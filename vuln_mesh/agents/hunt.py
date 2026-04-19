from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from vuln_mesh.adapters.base import BaseAdapter
from vuln_mesh.ranker.scorer import RankedFile

log = logging.getLogger(__name__)

_LANG_GUIDANCE: dict[str, str] = {
    "c":   "memory corruption, buffer overflows, use-after-free, double-free, format string bugs, integer overflows, command injection, race conditions",
    "cpp": "memory corruption, buffer overflows, use-after-free, double-free, format string bugs, integer overflows, command injection, race conditions, type confusion",
    "python": "command injection (os.system/subprocess), code execution (eval/exec), unsafe deserialization (pickle/yaml.load), path traversal, SQL injection, SSTI, insecure randomness",
    "javascript": "prototype pollution, XSS (innerHTML/document.write), command injection (child_process), path traversal, insecure eval, ReDoS, open redirect",
    "typescript": "prototype pollution, XSS (innerHTML/document.write), command injection (child_process), path traversal, insecure eval, ReDoS, open redirect",
    "go":   "command injection (exec.Command), path traversal, integer overflow, race conditions (data races), unsafe pointer arithmetic, SQL injection",
    "rust": "unsafe block misuse, integer overflow, command injection, path traversal, race conditions across FFI boundaries",
    "php":  "SQL injection, command injection (exec/system/shell_exec), code injection (eval), path traversal, unserialize vulnerabilities, XSS",
    "ruby": "command injection, code execution (eval/send), insecure deserialization (Marshal.load/YAML.load), SQL injection, path traversal",
    "java": "command injection (Runtime.exec), SQL injection, insecure deserialization (ObjectInputStream), path traversal, XXE, SSRF",
}
_DEFAULT_GUIDANCE = "command injection, SQL injection, path traversal, insecure deserialization, code execution, authentication bypass"


def _hunt_system(language: str) -> str:
    guidance = _LANG_GUIDANCE.get(language, _DEFAULT_GUIDANCE)
    return f"""\
You are a world-class vulnerability researcher analyzing {language} source code.
Your job: find exploitable bugs — {guidance}.

For each finding respond with a JSON array (and nothing else) of objects:
[
  {{
    "line_hint": <int or null>,
    "bug_class": "<e.g. buffer-overflow>",
    "description": "<precise description of the vulnerability>",
    "exploit_input": "<concrete input string or byte sequence that triggers the bug>"
  }}
]

If you find no bugs, return an empty array: []
Be precise. Do not speculate. Only report bugs you can reason about concretely.
"""


@dataclass
class Finding:
    file_path: str
    line_hint: int | None
    bug_class: str
    description: str
    exploit_input: str
    confidence: float = 1.0


class LLMError(Exception):
    """Raised when the LLM call fails so callers can surface it to the dashboard."""


class HuntAgent:
    def __init__(self, adapter: BaseAdapter) -> None:
        self.adapter = adapter

    async def run(self, ranked: RankedFile, neighborhood: str = "") -> list[Finding]:
        content_block = f"=== FILE: {ranked.node.path} ===\n{ranked.node.content}"
        context = f"Ranker rationale: {ranked.rationale}\n\n"
        if neighborhood:
            context += f"Call graph neighbors (2-hop):\n{neighborhood}\n\n"
        messages = [{"role": "user", "content": context + content_block}]

        try:
            raw = await self.adapter.complete(messages, _hunt_system(ranked.node.language), max_tokens=2048)
            items = json.loads(raw)
        except Exception as exc:
            log.warning("Hunt agent failed for %s: %s", ranked.node.path, exc)
            raise LLMError(str(exc)) from exc

        findings = []
        for item in items:
            findings.append(Finding(
                file_path=ranked.node.path,
                line_hint=item.get("line_hint"),
                bug_class=item.get("bug_class", "unknown"),
                description=item.get("description", ""),
                exploit_input=item.get("exploit_input", ""),
            ))
        return findings
