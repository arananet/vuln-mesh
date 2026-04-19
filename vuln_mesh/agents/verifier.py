from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass

from vuln_mesh.adapters.base import BaseAdapter

from .hunt import Finding

log = logging.getLogger(__name__)

VERIFIER_SYSTEM = """\
You are a senior security engineer performing a second-pass review of a reported vulnerability.

Your job is to assess whether the finding is PLAUSIBLE and REALISTIC:
- Does the code pattern match the claimed vulnerability class?
- Is there a realistic path where attacker-controlled input reaches the dangerous operation?
- Would this be reportable in a real-world penetration test or bug bounty?

You do NOT need certainty. Confirm if the vulnerability is realistic and the code evidence
supports it. Only reject if the finding is clearly wrong — the code doesn't exist, the
operation is provably safe (e.g., fully sanitized, unreachable), or the bug class is
completely inapplicable to this language/context.

Respond with a JSON object (and nothing else):
{
  "verified": <true if plausible and realistic, false if clearly incorrect>,
  "rationale": "<one concise sentence explaining your decision>"
}
"""

_JSON_OBJ_RE = re.compile(r'\{[\s\S]*\}')


@dataclass
class VerifiedFinding:
    finding: Finding
    verified: bool
    verifier_rationale: str


class VerifierAgent:
    def __init__(self, adapter: BaseAdapter) -> None:
        self.adapter = adapter

    async def run(self, finding: Finding, file_content: str) -> VerifiedFinding:
        # Corroboration bypass: if 2+ independent dimensions found the same bug, confirm it
        if finding.corroboration >= 2:
            log.info("Auto-confirmed by corroboration (%d dims): %s", finding.corroboration, finding.bug_class)
            return VerifiedFinding(
                finding=finding,
                verified=True,
                verifier_rationale=f"Corroborated by {finding.corroboration} independent analysis dimensions.",
            )

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
            raw = await self.adapter.complete(messages, VERIFIER_SYSTEM, max_tokens=512)
            data = _parse_verifier_response(raw)
            return VerifiedFinding(
                finding=finding,
                verified=bool(data.get("verified", False)),
                verifier_rationale=data.get("rationale", ""),
            )
        except Exception as exc:
            log.warning("Verifier error for %s: %s — treating as unverified", finding.file_path, exc)
            return VerifiedFinding(finding=finding, verified=False, verifier_rationale=str(exc))


def _parse_verifier_response(raw: str) -> dict:
    if not raw or not raw.strip():
        return {}
    try:
        result = json.loads(raw)
        return result if isinstance(result, dict) else {}
    except json.JSONDecodeError:
        m = _JSON_OBJ_RE.search(raw)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
        log.warning("Non-JSON verifier response: %r", raw[:200])
        return {}
