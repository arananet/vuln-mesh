from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from vuln_mesh.adapters.base import BaseAdapter

from .hunt import Finding

log = logging.getLogger(__name__)

VERIFIER_SYSTEM = """\
You are a skeptical security researcher. You will be shown a claimed vulnerability finding
and the source code it references. Your job is to DISPROVE it.

Look for reasons the finding is wrong:
- Does the code path actually exist?
- Is the "exploit input" actually reachable?
- Is there implicit bounds checking the first analyst missed?
- Would the program crash before reaching the bug?

Respond with a JSON object (and nothing else):
{
  "verified": <true if the bug is real, false if you can disprove it>,
  "rationale": "<one paragraph explaining your conclusion>"
}

Be rigorous. Approve only what you cannot disprove.
"""


@dataclass
class VerifiedFinding:
    finding: Finding
    verified: bool
    verifier_rationale: str


class VerifierAgent:
    def __init__(self, adapter: BaseAdapter) -> None:
        self.adapter = adapter

    async def run(self, finding: Finding, file_content: str) -> VerifiedFinding:
        prompt = (
            f"=== CLAIMED FINDING ===\n"
            f"bug_class: {finding.bug_class}\n"
            f"description: {finding.description}\n"
            f"exploit_input: {finding.exploit_input}\n"
            f"line_hint: {finding.line_hint}\n\n"
            f"=== SOURCE FILE: {finding.file_path} ===\n"
            f"{file_content}"
        )
        messages = [{"role": "user", "content": prompt}]

        try:
            raw = await self.adapter.complete(messages, VERIFIER_SYSTEM, max_tokens=1024)
            data = json.loads(raw)
            return VerifiedFinding(
                finding=finding,
                verified=bool(data.get("verified", False)),
                verifier_rationale=data.get("rationale", ""),
            )
        except Exception as exc:
            log.warning("Verifier failed for %s: %s", finding.file_path, exc)
            # conservative: treat verifier failure as unverified
            return VerifiedFinding(finding=finding, verified=False, verifier_rationale=str(exc))
