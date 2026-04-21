from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from vuln_mesh.oracle.runner import OracleResult, OracleStatus


def finding_hash(file_path: str, exploit_input: str) -> str:
    raw = f"{file_path}:{exploit_input}"
    return hashlib.sha256(raw.encode()).hexdigest()


def render_markdown(
    results: list[OracleResult],
    output_path: str | None = None,
    cvss_estimate: bool = True,
) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines: list[str] = []

    # Categorize results by status
    crashed = [r for r in results if r.status == OracleStatus.CRASHED]
    compile_errors = [r for r in results if r.status == OracleStatus.COMPILE_ERROR]
    skipped = [r for r in results if r.status == OracleStatus.SKIPPED]

    lines.append("# vuln-mesh Report")
    lines.append(f"\n**Generated:** {ts}  ")
    lines.append(f"**Total findings:** {len(results)}  ")
    lines.append(f"**Crash-confirmed:** {len(crashed)}  ")
    if compile_errors:
        lines.append(f"**Compile errors (verified but unbuildable):** {len(compile_errors)}  ")
    if skipped:
        lines.append(f"**Verified-only (non-compilable language):** {len(skipped)}  ")
    lines.append("")
    lines.append("---\n")

    if not results:
        lines.append("*No confirmed findings.*\n")
    else:
        # Compile errors section first — prominent warning
        if compile_errors:
            lines.append("## ⚠ Findings with Compile Errors\n")
            lines.append("> These findings were verified by the LLM agents but could not be compiled ")
            lines.append("> with ASan for ground-truth confirmation. They may still be real vulnerabilities.\n")
            for i, r in enumerate(compile_errors, 1):
                _render_finding(lines, r, f"CE-{i}", cvss_estimate, status_badge="COMPILE_ERROR")
            lines.append("---\n")

        # Verified-only (non-compilable) section
        if skipped:
            lines.append("## Verified Findings (Non-Compilable Languages)\n")
            lines.append("> These findings were verified by LLM agents. ASan oracle is not applicable ")
            lines.append("> for this language.\n")
            for i, r in enumerate(skipped, 1):
                _render_finding(lines, r, f"V-{i}", cvss_estimate, status_badge="VERIFIED")
            lines.append("---\n")

        # Crash-confirmed findings
        if crashed:
            lines.append("## Crash-Confirmed Findings\n")
            for i, r in enumerate(crashed, 1):
                _render_finding(lines, r, f"F-{i}", cvss_estimate, status_badge="CRASHED")

    report = "\n".join(lines)

    if output_path is None:
        output_path = f"vuln-mesh-report-{ts.replace(':', '-')}.md"
    Path(output_path).write_text(report)
    return report


def _render_finding(
    lines: list[str],
    r: OracleResult,
    label: str,
    cvss_estimate: bool,
    status_badge: str = "",
) -> None:
    f = r.finding.finding
    h = finding_hash(f.file_path, f.exploit_input)
    badge = f" `[{status_badge}]`" if status_badge else ""
    lines.append(f"### {label}: {f.bug_class}{badge}")
    lines.append(f"\n**File:** `{f.file_path}`  ")
    if f.line_hint:
        lines.append(f"**Line:** {f.line_hint}  ")
    lines.append(f"**ID:** `{h[:16]}`  ")
    if getattr(f, 'cwe_id', None):
        lines.append(f"**CWE:** {f.cwe_id}  ")
    if getattr(f, 'owasp_category', None):
        lines.append(f"**OWASP:** {f.owasp_category}  ")
    lines.append(f"\n#### Description\n\n{f.description}\n")
    lines.append(f"#### Exploit Input\n\n```\n{f.exploit_input}\n```\n")
    lines.append(f"#### Verifier Rationale\n\n{r.finding.verifier_rationale}\n")
    if r.output and r.status == OracleStatus.CRASHED:
        lines.append(f"#### ASan Output\n\n```\n{r.output[:1024]}\n```\n")
    elif r.output and r.status == OracleStatus.COMPILE_ERROR:
        lines.append(f"#### Compiler Error\n\n```\n{r.output[:1024]}\n```\n")
    if cvss_estimate:
        lines.append(_cvss_estimate_block(f.bug_class))
    lines.append("---\n")


def _cvss_estimate_block(bug_class: str) -> str:
    estimates: dict[str, str] = {
        "buffer-overflow": "CVSS 3.1 Base Score: ~8.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) — CWE-120",
        "use-after-free": "CVSS 3.1 Base Score: ~8.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H) — CWE-416",
        "integer-overflow": "CVSS 3.1 Base Score: ~7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) — CWE-190",
        "format-string": "CVSS 3.1 Base Score: ~9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) — CWE-134",
        "command-injection": "CVSS 3.1 Base Score: ~9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) — CWE-78",
        "sql-injection": "CVSS 3.1 Base Score: ~9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) — CWE-89",
        "xss": "CVSS 3.1 Base Score: ~6.1 (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N) — CWE-79",
        "path-traversal": "CVSS 3.1 Base Score: ~7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) — CWE-22",
        "prototype-pollution": "CVSS 3.1 Base Score: ~7.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L) — CWE-1321",
        "insecure-deserialization": "CVSS 3.1 Base Score: ~9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) — CWE-502",
        "ssrf": "CVSS 3.1 Base Score: ~7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) — CWE-918",
    }
    score = estimates.get(bug_class.lower(), "CVSS 3.1 Base Score: ~7.0 (heuristic estimate)")
    return f"#### CVSS Estimate\n\n> {score} *(LLM heuristic — not a formal assessment)*\n"
