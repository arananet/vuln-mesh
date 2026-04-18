from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass

from vuln_mesh.ingestion.loader import FileGraph, FileNode

_UNSAFE_FUNCS = re.compile(
    r'\b(strcpy|strcat|sprintf|gets|scanf|memcpy|strncpy|strncat|snprintf'
    r'|vsprintf|vsnprintf|realpath|getwd|mktemp|tmpnam|tempnam)\s*\('
)

_W_UNSAFE = 0.5
_W_SIZE = 0.3
_W_DEPTH = 0.2


@dataclass
class RankedFile:
    node: FileNode
    score: float
    rationale: str


def _unsafe_density(node: FileNode) -> float:
    matches = len(_UNSAFE_FUNCS.findall(node.content))
    lines = max(node.content.count("\n"), 1)
    return matches / lines


def _bfs_depth(start: str, edges: list[tuple[str, str]]) -> dict[str, int]:
    adj: dict[str, list[str]] = {}
    for src, dst in edges:
        adj.setdefault(src, []).append(dst)
        adj.setdefault(dst, []).append(src)
    visited: dict[str, int] = {start: 0}
    q: deque[str] = deque([start])
    while q:
        node = q.popleft()
        for nb in adj.get(node, []):
            if nb not in visited:
                visited[nb] = visited[node] + 1
                q.append(nb)
    return visited


def rank(graph: FileGraph, top_n: int | None = None, min_score: float = 0.0) -> list[RankedFile]:
    if not graph.nodes:
        return []

    entry_points = [n.path for n in graph.nodes if n.is_entry_point]
    depth_map: dict[str, int] = {}
    for ep in entry_points:
        for path, depth in _bfs_depth(ep, graph.edges).items():
            depth_map[path] = min(depth_map.get(path, 9999), depth)

    raw: list[tuple[FileNode, float, float, float]] = []
    for node in graph.nodes:
        unsafe = _unsafe_density(node)
        size_kb = node.size_bytes / 1024
        depth = depth_map.get(node.path, 0)
        raw.append((node, unsafe, size_kb, depth))

    def _norm(values: list[float]) -> list[float]:
        lo, hi = min(values), max(values)
        if hi == lo:
            return [0.5] * len(values)
        return [(v - lo) / (hi - lo) for v in values]

    unsafe_norm = _norm([r[1] for r in raw])
    size_norm = _norm([r[2] for r in raw])
    # invert depth: closer to entry = higher score
    depth_inv = _norm([-r[3] for r in raw])

    results: list[RankedFile] = []
    for i, (node, unsafe_raw, size_raw, depth_raw) in enumerate(raw):
        score = (
            _W_UNSAFE * unsafe_norm[i]
            + _W_SIZE * size_norm[i]
            + _W_DEPTH * depth_inv[i]
        )
        rationale = (
            f"unsafe_density={unsafe_raw:.4f} size_kb={size_raw:.1f} "
            f"entry_depth={depth_raw}"
        )
        results.append(RankedFile(node=node, score=round(score, 4), rationale=rationale))

    results.sort(key=lambda r: r.score, reverse=True)
    results = [r for r in results if r.score >= min_score]
    if top_n is not None:
        results = results[:top_n]
    return results
