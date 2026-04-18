from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from vuln_mesh.adapters.base import BaseAdapter
from vuln_mesh.ranker.scorer import RankedFile

log = logging.getLogger(__name__)

HUNT_SYSTEM = """\
You are a world-class vulnerability researcher analyzing C/C++ source code.
Your job: find exploitable bugs — memory corruption, integer overflows, use-after-free,
format string bugs, command injection, race conditions, logic errors.

For each finding respond with a JSON array (and nothing else) of objects:
[
  {
    "line_hint": <int or null>,
    "bug_class": "<e.g. buffer-overflow>",
    "description": "<precise description of the vulnerability>",
    "exploit_input": "<concrete input string or byte sequence that triggers the bug>"
  }
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
            raw = await self.adapter.complete(messages, HUNT_SYSTEM, max_tokens=2048)
            items = json.loads(raw)
        except Exception as exc:
            log.warning("Hunt agent failed for %s: %s", ranked.node.path, exc)
            return []

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
