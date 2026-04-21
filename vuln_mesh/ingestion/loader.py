from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

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
    ".as": "actionscript",
}

_INCLUDE_RE = re.compile(r'#\s*include\s+["<]([^">]+)[">]')
_IMPORT_RE = re.compile(r'''(?:^|\n)\s*(?:import|from)\s+["']?([A-Za-z0-9_./\\-]+)''')
_REQUIRE_RE = re.compile(r'''require\s*\(\s*["']([^"']+)["']\s*\)''')
_MAIN_RE = re.compile(
    r'\bint\s+main\s*\('             # C/C++
    r'|\bif\s+__name__\s*=='         # Python
    r'|\bfunc\s+main\s*\('           # Go
    r'|\bpublic\s+static\s+void\s+main\s*\('  # Java
)
_JS_ENTRY_RE = re.compile(
    r'(?:app|server)\.(listen|use)\s*\('    # Express/Node server
    r'|addEventListener\s*\(\s*["\'](?:DOMContentLoaded|load)["\']'  # Browser entry
    r'|process\.argv'                        # CLI scripts
    r'|export\s+default\s+function\s+App'    # React entry
)


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
    if language == "actionscript":
        return _IMPORT_RE.findall(content)
    return _IMPORT_RE.findall(content)


def _detect_entry_point(content: str, language: str) -> bool:
    if language in ("javascript", "typescript"):
        return bool(_MAIN_RE.search(content)) or bool(_JS_ENTRY_RE.search(content))
    return bool(_MAIN_RE.search(content))


def _resolve_include(inc: str, source_path: Path, path_index: dict[str, list[Path]]) -> Path | None:
    """Resolve an include/import relative to the including file first, then by basename."""
    # Try relative resolution from the including file's directory
    relative = source_path.parent / inc
    resolved = relative.resolve()
    if resolved.exists():
        return resolved

    # Fall back to basename lookup, but prefer unique matches
    inc_name = Path(inc).name
    candidates = path_index.get(inc_name, [])
    if len(candidates) == 1:
        return candidates[0]
    # Multiple candidates — ambiguous; return None to avoid wrong edges
    if len(candidates) > 1:
        log.debug("Ambiguous include %r from %s — %d candidates, skipping", inc, source_path, len(candidates))
        return None
    return None


def ingest(source: str) -> FileGraph:
    root = Path(source)
    if not root.exists():
        raise IngestionError(f"Path does not exist: {source}")

    nodes: list[FileNode] = []
    # Map basename → list of full Paths (handles duplicate basenames across directories)
    basename_index: dict[str, list[Path]] = {}
    path_to_node: dict[str, FileNode] = {}

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
            is_entry_point=_detect_entry_point(content, lang),
            size_bytes=p.stat().st_size,
        )
        nodes.append(node)
        basename_index.setdefault(p.name, []).append(p)
        path_to_node[str(p.resolve())] = node

    graph = FileGraph(nodes=nodes)

    for node in nodes:
        source_p = Path(node.path)
        for inc in node.includes:
            target = _resolve_include(inc, source_p, basename_index)
            if target is not None:
                target_key = str(target.resolve())
                if target_key in path_to_node:
                    graph.edges.append((node.path, path_to_node[target_key].path))

    return graph
