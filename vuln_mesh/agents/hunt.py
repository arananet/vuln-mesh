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


# Language-specific guidance with OWASP/CWE references
_LANG_GUIDANCE: dict[str, str] = {
    "c": (
        "memory corruption (CWE-119), buffer overflows (CWE-120/CWE-121/CWE-122), "
        "use-after-free (CWE-416), double-free (CWE-415), format string bugs (CWE-134), "
        "integer overflows (CWE-190), command injection (CWE-78/OWASP A03), race conditions (CWE-362)"
    ),
    "cpp": (
        "memory corruption (CWE-119), buffer overflows (CWE-120/CWE-121/CWE-122), "
        "use-after-free (CWE-416), double-free (CWE-415), format string bugs (CWE-134), "
        "integer overflows (CWE-190), command injection (CWE-78/OWASP A03), race conditions (CWE-362), "
        "type confusion (CWE-843)"
    ),
    "python": (
        "command injection via os.system/subprocess (CWE-78/OWASP A03), "
        "code execution via eval/exec (CWE-94), unsafe deserialization via pickle/yaml.load (CWE-502/OWASP A08), "
        "path traversal (CWE-22/OWASP A01), SQL injection (CWE-89/OWASP A03), "
        "SSTI (CWE-1336), insecure randomness (CWE-330), "
        "SSRF (CWE-918/OWASP A10), broken access control (OWASP A01)"
    ),
    "javascript": (
        "prototype pollution (CWE-1321), XSS via innerHTML/document.write (CWE-79/OWASP A03), "
        "command injection via child_process (CWE-78/OWASP A03), path traversal (CWE-22/OWASP A01), "
        "insecure eval (CWE-94), ReDoS (CWE-1333), open redirect (CWE-601), "
        "insecure deserialization (CWE-502/OWASP A08), SSRF (CWE-918/OWASP A10), "
        "broken access control (OWASP A01), NoSQL injection (CWE-943)"
    ),
    "typescript": (
        "prototype pollution (CWE-1321), XSS via innerHTML/document.write (CWE-79/OWASP A03), "
        "command injection via child_process (CWE-78/OWASP A03), path traversal (CWE-22/OWASP A01), "
        "insecure eval (CWE-94), ReDoS (CWE-1333), open redirect (CWE-601), "
        "insecure deserialization (CWE-502/OWASP A08), SSRF (CWE-918/OWASP A10)"
    ),
    "go": (
        "command injection via exec.Command (CWE-78/OWASP A03), path traversal (CWE-22/OWASP A01), "
        "integer overflow (CWE-190), race conditions/data races (CWE-362), "
        "unsafe pointer arithmetic, SQL injection (CWE-89/OWASP A03)"
    ),
    "rust": (
        "unsafe block misuse (CWE-119), integer overflow (CWE-190), "
        "command injection (CWE-78/OWASP A03), path traversal (CWE-22/OWASP A01), "
        "race conditions across FFI boundaries (CWE-362)"
    ),
    "php": (
        "SQL injection (CWE-89/OWASP A03), command injection via exec/system/shell_exec (CWE-78/OWASP A03), "
        "code injection via eval (CWE-94), path traversal (CWE-22/OWASP A01), "
        "unserialize vulnerabilities (CWE-502/OWASP A08), XSS (CWE-79/OWASP A03)"
    ),
    "ruby": (
        "command injection (CWE-78/OWASP A03), code execution via eval/send (CWE-94), "
        "insecure deserialization via Marshal.load/YAML.load (CWE-502/OWASP A08), "
        "SQL injection (CWE-89/OWASP A03), path traversal (CWE-22/OWASP A01)"
    ),
    "java": (
        "command injection via Runtime.exec (CWE-78/OWASP A03), SQL injection (CWE-89/OWASP A03), "
        "insecure deserialization via ObjectInputStream (CWE-502/OWASP A08), "
        "path traversal (CWE-22/OWASP A01), XXE (CWE-611/OWASP A05), SSRF (CWE-918/OWASP A10)"
    ),
    "actionscript": (
        "cross-site scripting via ExternalInterface.call (CWE-79/OWASP A03), "
        "open redirect via navigateToURL (CWE-601), insecure cross-domain policy via Security.allowDomain (CWE-942), "
        "code injection via eval/loadVariables (CWE-94), SWF injection"
    ),
}
_DEFAULT_GUIDANCE = (
    "command injection (CWE-78/OWASP A03), SQL injection (CWE-89/OWASP A03), "
    "path traversal (CWE-22/OWASP A01), insecure deserialization (CWE-502/OWASP A08), "
    "code execution (CWE-94), authentication bypass (CWE-287/OWASP A07), "
    "SSRF (CWE-918/OWASP A10), broken access control (OWASP A01)"
)

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
    "cwe_id": "<e.g. CWE-79, CWE-89 — or null if unsure>",
    "owasp_category": "<e.g. A03:2021-Injection — or null if unsure>",
    "description": "<precise description>",
    "exploit_input": "<concrete input that triggers the bug>"
  }
]
If you find no bugs, return: []
Be precise. Do not speculate. Only report bugs you can reason about concretely.
Include CWE and OWASP references where applicable."""


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
    cwe_id: str | None = None
    owasp_category: str | None = None


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
                cwe_id=item.get("cwe_id"),
                owasp_category=item.get("owasp_category"),
            )
            for item in items
        ]


class SynthAgent:
    """Runs the SYNTH dimension across a group of related files."""

    MAX_FILE_CHARS = 3000

    def __init__(self, adapter: BaseAdapter) -> None:
        self.adapter = adapter

    async def run(self, files: list[RankedFile]) -> list[Finding]:
        parts: list[str] = []
        for rf in files:
            content = rf.node.content
            if len(content) > self.MAX_FILE_CHARS:
                log.warning(
                    "SynthAgent: truncating %s from %d to %d chars",
                    rf.node.path, len(content), self.MAX_FILE_CHARS,
                )
                content = content[:self.MAX_FILE_CHARS]
            parts.append(
                f"=== FILE: {rf.node.path} (surface={rf.surface:.3f}) ===\n{content}"
            )
        blocks = "\n\n".join(parts)
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
                cwe_id=item.get("cwe_id"),
                owasp_category=item.get("owasp_category"),
            )
            for item in items
        ]
