from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from pathlib import Path

from vuln_mesh.adapters.base import BaseAdapter
from vuln_mesh.dashboard.state import EventType, PipelineEvent, PipelineTracker
from vuln_mesh.ingestion.loader import FileGraph
from vuln_mesh.ranker.scorer import RankedFile

from .hunt import Dimension, Finding, HuntAgent, LLMError, SynthAgent
from .verifier import VerifiedFinding, VerifierAgent

log = logging.getLogger(__name__)

# Surface threshold for spawning multi-dimensional agents
_THRESH_FULL = 0.55   # surface >= this → SURFACE + INFLUENCE + REACHABILITY
_THRESH_DUAL = 0.25   # surface >= this → SURFACE + INFLUENCE


def _select_dimensions(ranked: RankedFile) -> list[Dimension]:
    s = ranked.surface
    if s >= _THRESH_FULL:
        return [Dimension.SURFACE, Dimension.INFLUENCE, Dimension.REACHABILITY]
    if s >= _THRESH_DUAL:
        return [Dimension.SURFACE, Dimension.INFLUENCE]
    return [Dimension.TRIAGE]


def _group_subsystems(ranked_files: list[RankedFile]) -> list[list[RankedFile]]:
    """Return groups of 2+ files sharing a directory, where ≥1 file has surface≥0.3."""
    by_dir: dict[str, list[RankedFile]] = defaultdict(list)
    for rf in ranked_files:
        by_dir[str(Path(rf.node.path).parent)].append(rf)
    return [
        group for group in by_dir.values()
        if len(group) >= 2 and any(rf.surface >= 0.3 for rf in group)
    ]


def _agent_id(dimension: Dimension, path: str) -> str:
    return f"{dimension.value}:{path}"


def _corroborate(findings_by_dim: dict[str, list[Finding]]) -> list[Finding]:
    """Merge findings across dimensions. Same bug_class+line+file → increment corroboration."""
    merged: dict[str, Finding] = {}
    for dim_findings in findings_by_dim.values():
        for f in dim_findings:
            # Use file_path and require non-null lines to corroborate;
            # line_hint=None findings only corroborate by exact (bug_class, file, None)
            key = f"{f.bug_class}:{f.line_hint or 'none'}:{f.file_path}"
            if key in merged:
                merged[key].corroboration += 1
            else:
                merged[key] = f
    return list(merged.values())


def _build_neighborhood(path: str, graph: FileGraph | None, hops: int = 2) -> str:
    """Return a text summary of files within `hops` edges of `path` in the file graph."""
    if graph is None or not graph.edges:
        return ""
    adj: dict[str, set[str]] = defaultdict(set)
    for src, dst in graph.edges:
        adj[src].add(dst)
        adj[dst].add(src)

    visited: set[str] = {path}
    frontier: set[str] = {path}
    for _ in range(hops):
        next_frontier: set[str] = set()
        for node in frontier:
            for nb in adj.get(node, set()):
                if nb not in visited:
                    visited.add(nb)
                    next_frontier.add(nb)
        frontier = next_frontier
        if not frontier:
            break

    neighbors = visited - {path}
    if not neighbors:
        return ""
    lines = [f"- {nb}" for nb in sorted(neighbors)]
    return "\n".join(lines)


async def run_mesh(
    ranked_files: list[RankedFile],
    hunt_adapter: BaseAdapter,
    verifier_adapter: BaseAdapter,
    concurrency: int = 32,
    tracker: PipelineTracker | None = None,
    graph: FileGraph | None = None,
) -> list[VerifiedFinding]:
    file_sem = asyncio.Semaphore(concurrency)
    synth_sem = asyncio.Semaphore(max(concurrency // 4, 4))
    hunter = HuntAgent(hunt_adapter)
    verifier = VerifierAgent(verifier_adapter)
    synth = SynthAgent(verifier_adapter)  # SYNTH uses the smarter model

    async def _emit(type: EventType, data: dict) -> None:
        if tracker:
            await tracker.emit(PipelineEvent(type, data))

    # ── Per-dimension runner ────────────────────────────────────────────────
    async def _run_dimension(ranked: RankedFile, dim: Dimension) -> list[Finding]:
        agent_id = _agent_id(dim, ranked.node.path)
        await _emit(EventType.FILE_STARTED, {
            "path": ranked.node.path,
            "score": ranked.score,
            "surface": ranked.surface,
            "influence": ranked.influence,
            "reachability": ranked.reachability,
            "dimension": dim.value,
            "agent_id": agent_id,
        })
        try:
            neighborhood = _build_neighborhood(ranked.node.path, graph)
            findings = await hunter.run(ranked, neighborhood=neighborhood, dimension=dim)
        except LLMError as exc:
            await _emit(EventType.ERROR, {"message": f"[{dim.value}] {ranked.node.path}: {exc}"})
            await _emit(EventType.DISCARDED, {
                "path": ranked.node.path, "agent_id": agent_id,
                "dimension": dim.value, "reason": "LLM error",
            })
            return []
        if not findings:
            await _emit(EventType.DISCARDED, {
                "path": ranked.node.path, "agent_id": agent_id,
                "dimension": dim.value, "reason": "no findings",
            })
        return findings

    # ── Per-file multi-dimensional processing ───────────────────────────────
    async def _process_file(ranked: RankedFile) -> list[VerifiedFinding]:
        async with file_sem:
            dims = _select_dimensions(ranked)
            dim_tasks = [asyncio.create_task(_run_dimension(ranked, d)) for d in dims]
            dim_results = await asyncio.gather(*dim_tasks)

            findings_by_dim = {d.value: r for d, r in zip(dims, dim_results)}
            merged = _corroborate(findings_by_dim)

            if not merged:
                return []

            results = []
            for finding in merged:
                await _emit(EventType.FINDING, {
                    "path": finding.file_path,
                    "bug_class": finding.bug_class,
                    "description": finding.description,
                    "line_hint": finding.line_hint,
                    "dimension": finding.dimension,
                    "corroboration": finding.corroboration,
                })
                vf = await verifier.run(finding, ranked.node.content)
                if vf.verified:
                    await _emit(EventType.VERIFIED, {
                        "path": finding.file_path,
                        "bug_class": finding.bug_class,
                        "description": finding.description,
                        "line_hint": finding.line_hint,
                        "dimension": finding.dimension,
                        "corroboration": finding.corroboration,
                        "agent_id": _agent_id(Dimension(finding.dimension), finding.file_path),
                    })
                    results.append(vf)
                else:
                    await _emit(EventType.DISCARDED, {
                        "path": finding.file_path,
                        "agent_id": _agent_id(Dimension(finding.dimension), finding.file_path),
                        "dimension": finding.dimension,
                        "reason": "verifier rejected",
                        "bug_class": finding.bug_class,
                    })
            return results

    # ── Subsystem synthesis ─────────────────────────────────────────────────
    async def _process_subsystem(group: list[RankedFile]) -> list[VerifiedFinding]:
        async with synth_sem:
            label = Path(group[0].node.path).parent.name
            synth_path = f"[subsystem:{label}]"
            agent_id = f"synth:{synth_path}"
            await _emit(EventType.FILE_STARTED, {
                "path": synth_path,
                "score": max(rf.score for rf in group),
                "surface": max(rf.surface for rf in group),
                "influence": max(rf.influence for rf in group),
                "reachability": max(rf.reachability for rf in group),
                "dimension": Dimension.SYNTH.value,
                "agent_id": agent_id,
            })
            try:
                findings = await synth.run(group)
            except LLMError as exc:
                await _emit(EventType.ERROR, {"message": f"[synth:{label}] {exc}"})
                await _emit(EventType.DISCARDED, {
                    "path": synth_path, "agent_id": agent_id,
                    "dimension": Dimension.SYNTH.value, "reason": "LLM error",
                })
                return []
            if not findings:
                await _emit(EventType.DISCARDED, {
                    "path": synth_path, "agent_id": agent_id,
                    "dimension": Dimension.SYNTH.value, "reason": "no findings",
                })
                return []

            results = []
            for finding in findings:
                await _emit(EventType.FINDING, {
                    "path": synth_path,
                    "bug_class": finding.bug_class,
                    "description": finding.description,
                    "line_hint": finding.line_hint,
                    "dimension": Dimension.SYNTH.value,
                    "corroboration": 1,
                })
                # Concatenate ALL group files so verifier can reason about cross-file flows
                combined_content = "\n\n".join(
                    f"=== {rf.node.path} ===\n{rf.node.content}" for rf in group
                )
                vf = await verifier.run(finding, combined_content)
                if vf.verified:
                    await _emit(EventType.VERIFIED, {
                        "path": synth_path,
                        "bug_class": finding.bug_class,
                        "description": finding.description,
                        "line_hint": finding.line_hint,
                        "dimension": Dimension.SYNTH.value,
                        "corroboration": 1,
                        "agent_id": agent_id,
                    })
                    results.append(vf)
                else:
                    await _emit(EventType.DISCARDED, {
                        "path": synth_path, "agent_id": agent_id,
                        "dimension": Dimension.SYNTH.value, "reason": "verifier rejected",
                    })
            return results

    # ── Execute all file agents ─────────────────────────────────────────────
    file_tasks = [asyncio.create_task(_process_file(r)) for r in ranked_files]
    file_results = await asyncio.gather(*file_tasks)
    all_verified = [vf for batch in file_results for vf in batch]

    # ── Execute subsystem synthesis passes ──────────────────────────────────
    subsystems = _group_subsystems(ranked_files)
    if subsystems:
        log.info("Running %d subsystem synthesis passes", len(subsystems))
        synth_tasks = [asyncio.create_task(_process_subsystem(g)) for g in subsystems]
        synth_results = await asyncio.gather(*synth_tasks)
        all_verified.extend(vf for batch in synth_results for vf in batch)

    return all_verified
