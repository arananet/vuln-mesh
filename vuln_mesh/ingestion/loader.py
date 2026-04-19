from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_LANG_MAP: dict[str, str] = {
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".py": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".java": "java",
}

_INCLUDE_RE = re.compile(r'#\s*include\s+["<]([^">]+)[">]')
_IMPORT_RE = re.compile(r'''(?:^|\n)\s*(?:import|from)\s+["']?([A-Za-z0-9_./\\-]+)''')
_REQUIRE_RE = re.compile(r'''require\s*\(\s*["']([^"']+)["']\s*\)''')
_MAIN_RE = re.compile(r'\bint\s+main\s*\(|\bif\s+__name__\s*==|\bfunc\s+main\s*\(|\bpublic\s+static\s+void\s+main\s*\(')


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


def _parse_imports(content: str, language: str) -> list[str]:
    if language in ("c", "cpp"):
        return _INCLUDE_RE.findall(content)
    if language in ("javascript", "typescript"):
        return _IMPORT_RE.findall(content) + _REQUIRE_RE.findall(content)
    return _IMPORT_RE.findall(content)


def _detect_entry_point(content: str) -> bool:
    return bool(_MAIN_RE.search(content))


def ingest(source: str) -> FileGraph:
    root = Path(source)
    if not root.exists():
        raise IngestionError(f"Path does not exist: {source}")

    nodes: list[FileNode] = []
    path_index: dict[str, FileNode] = {}

    for p in sorted(root.rglob("*")):
        lang = _LANG_MAP.get(p.suffix.lower())
        if not p.is_file() or lang is None:
            continue
        content = p.read_text(errors="replace")
        node = FileNode(
            path=str(p),
            language=lang,
            content=content,
            includes=_parse_imports(content, lang),
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
