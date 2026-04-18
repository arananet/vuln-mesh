from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_CPP_EXTS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"}
_INCLUDE_RE = re.compile(r'#\s*include\s+["<]([^">]+)[">]')
_MAIN_RE = re.compile(r'\bint\s+main\s*\(')


class IngestionError(Exception):
    pass


@dataclass
class FileNode:
    path: str
    language: str
    content: str
    includes: list[str] = field(default_factory=list)
    is_entry_point: bool = False
    size_bytes: int = 0


@dataclass
class FileGraph:
    nodes: list[FileNode] = field(default_factory=list)
    edges: list[tuple[str, str]] = field(default_factory=list)


def _parse_includes(content: str) -> list[str]:
    return _INCLUDE_RE.findall(content)


def _detect_entry_point(content: str) -> bool:
    return bool(_MAIN_RE.search(content))


def ingest(source: str) -> FileGraph:
    root = Path(source)
    if not root.exists():
        raise IngestionError(f"Path does not exist: {source}")

    nodes: list[FileNode] = []
    path_index: dict[str, FileNode] = {}

    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in _CPP_EXTS:
            continue
        content = p.read_text(errors="replace")
        node = FileNode(
            path=str(p),
            language="c" if p.suffix.lower() in {".c", ".h"} else "cpp",
            content=content,
            includes=_parse_includes(content),
            is_entry_point=_detect_entry_point(content),
            size_bytes=p.stat().st_size,
        )
        nodes.append(node)
        path_index[p.name] = node

    graph = FileGraph(nodes=nodes)

    for node in nodes:
        for inc in node.includes:
            inc_name = Path(inc).name
            if inc_name in path_index:
                graph.edges.append((node.path, path_index[inc_name].path))

    return graph
