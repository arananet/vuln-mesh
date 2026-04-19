from __future__ import annotations

import asyncio
import logging

from vuln_mesh.adapters.base import BaseAdapter
from vuln_mesh.dashboard.state import EventType, PipelineEvent, PipelineTracker
from vuln_mesh.ranker.scorer import RankedFile

from .hunt import HuntAgent, LLMError
from .verifier import VerifiedFinding, VerifierAgent

log = logging.getLogger(__name__)


async def run_mesh(
    ranked_files: list[RankedFile],
    hunt_adapter: BaseAdapter,
    verifier_adapter: BaseAdapter,
    concurrency: int = 32,
    tracker: PipelineTracker | None = None,
) -> list[VerifiedFinding]:
    sem = asyncio.Semaphore(concurrency)
    hunter = HuntAgent(hunt_adapter)
    verifier = VerifierAgent(verifier_adapter)

    async def _emit(type: EventType, data: dict) -> None:
        if tracker:
            await tracker.emit(PipelineEvent(type, data))

    async def _process(ranked: RankedFile) -> list[VerifiedFinding]:
        async with sem:
            await _emit(EventType.FILE_STARTED, {
                "path": ranked.node.path,
                "score": ranked.score,
            })

            try:
                findings = await hunter.run(ranked)
            except LLMError as exc:
                await _emit(EventType.ERROR, {"message": f"LLM error on {ranked.node.path}: {exc}"})
                await _emit(EventType.DISCARDED, {"path": ranked.node.path, "reason": "LLM error"})
                return []

            if not findings:
                await _emit(EventType.DISCARDED, {
                    "path": ranked.node.path,
                    "reason": "no findings",
                })
                return []

            results = []
            for finding in findings:
                await _emit(EventType.FINDING, {
                    "path": finding.file_path,
                    "bug_class": finding.bug_class,
                    "description": finding.description,
                    "line_hint": finding.line_hint,
                })

                vf = await verifier.run(finding, ranked.node.content)
                if vf.verified:
                    await _emit(EventType.VERIFIED, {
                        "path": finding.file_path,
                        "bug_class": finding.bug_class,
                        "description": finding.description,
                        "line_hint": finding.line_hint,
                    })
                    results.append(vf)
                else:
                    await _emit(EventType.DISCARDED, {
                        "path": finding.file_path,
                        "reason": "verifier rejected",
                        "bug_class": finding.bug_class,
                    })
                    log.info("Discarded by verifier: %s in %s", finding.bug_class, finding.file_path)

            return results

    tasks = [asyncio.create_task(_process(r)) for r in ranked_files]
    nested = await asyncio.gather(*tasks)
    return [vf for batch in nested for vf in batch]
