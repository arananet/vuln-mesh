from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum

from vuln_mesh.adapters.base import BaseAdapter
from vuln_mesh.ranker.scorer import RankedFile

log = logging.getLogger(__name__)


class Dimension(str, Enum):
    TRIAGE       = "triage"       # fast broad scan for low-surface files
    SURFACE      = "surface"      # direct vulnerabilities in this file's code
    INFLUENCE    = "influence"    # how callers can exploit this file's outputs
    REACHABILITY = "reachability" # attacker paths into this code
    SYNTH        = "synth"        # cross-file synthesis across a subsystem


_LANG_GUIDANCE: dict[str, str] = {
    "c":          "memory corruption, buffer overflows, use-after-free, double-free, format string bugs, integer overflows, command injection, race conditions",
    "cpp":        "memory corruption, buffer overflows, use-after-free, double-free, format string bugs, integer overflows, command injection, race conditions, type confusion",
    "python":     "command injection (os.system/subprocess), code execution (eval/exec), unsafe deserialization (pickle/yaml.load), path traversal, SQL injection, SSTI, insecure randomness",
    "javascript": "prototype pollution, XSS (innerHTML/document.write), command injection (child_process), path traversal, insecure eval, ReDoS, open redirect",
    "typescript": "prototype pollution, XSS (innerHTML/document.write), command injection (child_process), path traversal, insecure eval, ReDoS, open redirect",
    "go":         "command injection (exec.Command), path traversal, integer overflow, race conditions (data races), unsafe pointer arithmetic, SQL injection",
    "rust":       "unsafe block misuse, integer overflow, command injection, path traversal, race conditions across FFI boundaries",
    "php":        "SQL injection, command injection (exec/system/shell_exec), code injection (eval), path traversal, unserialize vulnerabilities, XSS",
    "ruby":       "command injection, code execution (eval/send), insecure deserialization (Marshal.load/YAML.load), SQL injection, path traversal",
    "java":       "command injection (Runtime.exec), SQL injection, insecure deserialization (ObjectInputStream), path traversal, XXE, SSRF",
}
_DEFAULT_GUIDANCE = "command injection, SQL injection, path traversal, insecure deserialization, code execution, authentication bypass"

_DIM_FOCUS: dict[Dimension, str] = {
    Dimension.TRIAGE: (
        "Quickly scan for any clear vulnerabilities. Flag anything suspicious, even if not certain."
    ),
    Dimension.SURFACE: (
        "Deep-dive into the file's own logic. Focus on: dangerous function calls, unchecked inputs, "
        "memory mismanagement, and logic errors within this file's functions."
    ),
    Dimension.INFLUENCE: (
        "This file's functions are called by other parts of the codebase. Assume every exported "
        "function receives attacker-controlled input. Find vulnerabilities that callers could trigger "
        "by passing malicious arguments or data."
    ),
    Dimension.REACHABILITY: (
        "Trace attacker-controlled data from external boundaries (HTTP params, file input, env vars, "
        "IPC) into this file. Find how attacker data reaches dangerous sinks. Map the full attack path."
    ),
    Dimension.SYNTH: (
        "These files form a subsystem. Analyze cross-file data flows: output of one file feeds into "
        "another's dangerous operation. Find vulnerabilities that only appear when files interact."
    ),
}

_JSON_FORMAT = """
Respond with a JSON array (and nothing else):
[
  {
    "line_hint": <int or null>,
    "bug_class": "<e.g. buffer-overflow, xss, sql-injection>",
    "description": "<precise description>",
    "exploit_input": "<concrete input that triggers the bug>"
  }
]
If you find no bugs, return: []
Be precise. Do not speculate. Only report bugs you can reason about concretely."""


def _hunt_system(language: str, dimension: Dimension = Dimension.TRIAGE) -> str:
    guidance = _LANG_GUIDANCE.get(language, _DEFAULT_GUIDANCE)
    focus = _DIM_FOCUS[dimension]
    return (
        f"You are a world-class vulnerability researcher analyzing {language} source code.\n"
        f"Analysis dimension: {dimension.value.upper()}\n\n"
        f"{focus}\n\n"
        f"Vulnerability classes to consider: {guidance}.\n"
        f"{_JSON_FORMAT}"
    )


@dataclass
class Finding:
    file_path: str
    line_hint: int | None
    bug_class: str
    description: str
    exploit_input: str
    confidence: float = 1.0
    dimension: str = Dimension.TRIAGE.value
    corroboration: int = 1  # how many dimensions flagged this


class LLMError(Exception):
    """Raised when the LLM call fails so callers can surface it to the dashboard."""


_JSON_ARRAY_RE = re.compile(r'\[[\s\S]*\]')


def _parse_llm_response(raw: str, path: str) -> list:
    if not raw or not raw.strip():
        log.debug("Empty LLM response for %s — treating as no findings", path)
        return []
    try:
        result = json.loads(raw)
        return result if isinstance(result, list) else []
    except json.JSONDecodeError:
        m = _JSON_ARRAY_RE.search(raw)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
        log.warning("Non-JSON LLM response for %s: %r", path, raw[:200])
        return []


class HuntAgent:
    def __init__(self, adapter: BaseAdapter) -> None:
        self.adapter = adapter

    async def run(
        self,
        ranked: RankedFile,
        neighborhood: str = "",
        dimension: Dimension = Dimension.TRIAGE,
    ) -> list[Finding]:
        content_block = f"=== FILE: {ranked.node.path} ===\n{ranked.node.content}"
        context = f"Ranker: surface={ranked.surface:.3f} influence={ranked.influence:.3f} reachability={ranked.reachability:.3f}\n\n"
        if neighborhood:
            context += f"Callgraph neighbors (2-hop):\n{neighborhood}\n\n"
        messages = [{"role": "user", "content": context + content_block}]

        try:
            raw = await self.adapter.complete(
                messages, _hunt_system(ranked.node.language, dimension), max_tokens=2048
            )
        except Exception as exc:
            log.warning("[%s] adapter failed for %s: %s", dimension.value, ranked.node.path, exc)
            raise LLMError(str(exc)) from exc

        items = _parse_llm_response(raw, ranked.node.path)[:5]  # cap at 5 per dimension
        return [
            Finding(
                file_path=ranked.node.path,
                line_hint=item.get("line_hint"),
                bug_class=item.get("bug_class", "unknown"),
                description=item.get("description", ""),
                exploit_input=item.get("exploit_input", ""),
                dimension=dimension.value,
            )
            for item in items
        ]


class SynthAgent:
    """Runs the SYNTH dimension across a group of related files."""

    def __init__(self, adapter: BaseAdapter) -> None:
        self.adapter = adapter

    async def run(self, files: list[RankedFile]) -> list[Finding]:
        blocks = "\n\n".join(
            f"=== FILE: {rf.node.path} (surface={rf.surface:.3f}) ===\n{rf.node.content[:3000]}"
            for rf in files
        )
        messages = [{"role": "user", "content": blocks}]
        # Use the language of the first file; all files in a subsystem share a language
        lang = files[0].node.language if files else "unknown"
        try:
            raw = await self.adapter.complete(
                messages, _hunt_system(lang, Dimension.SYNTH), max_tokens=2048
            )
        except Exception as exc:
            log.warning("[synth] adapter failed: %s", exc)
            raise LLMError(str(exc)) from exc

        items = _parse_llm_response(raw, files[0].node.path)
        return [
            Finding(
                file_path=item.get("file_path", files[0].node.path),
                line_hint=item.get("line_hint"),
                bug_class=item.get("bug_class", "unknown"),
                description=item.get("description", ""),
                exploit_input=item.get("exploit_input", ""),
                dimension=Dimension.SYNTH.value,
            )
            for item in items
        ]
