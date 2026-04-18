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

    lines.append("# vuln-mesh Report")
    lines.append(f"\n**Generated:** {ts}  ")
    lines.append(f"**Confirmed findings:** {len(results)}\n")
    lines.append("---\n")

    if not results:
        lines.append("*No confirmed findings.*\n")
    else:
        for i, r in enumerate(results, 1):
            f = r.finding.finding
            h = finding_hash(f.file_path, f.exploit_input)
            lines.append(f"## Finding {i}: {f.bug_class}")
            lines.append(f"\n**File:** `{f.file_path}`  ")
            if f.line_hint:
                lines.append(f"**Line:** {f.line_hint}  ")
            lines.append(f"**ID:** `{h[:16]}`\n")
            lines.append(f"### Description\n\n{f.description}\n")
            lines.append(f"### Exploit Input\n\n```\n{f.exploit_input}\n```\n")
            lines.append(f"### Verifier Rationale\n\n{r.finding.verifier_rationale}\n")
            if r.output:
                lines.append(f"### ASan Output\n\n```\n{r.output[:1024]}\n```\n")
            if cvss_estimate:
                lines.append(_cvss_estimate_block(f.bug_class))
            lines.append("---\n")

    report = "\n".join(lines)

    if output_path is None:
        output_path = f"vuln-mesh-report-{ts.replace(':', '-')}.md"
    Path(output_path).write_text(report)
    return report


def _cvss_estimate_block(bug_class: str) -> str:
    estimates: dict[str, str] = {
        "buffer-overflow": "CVSS 3.1 Base Score: ~8.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
        "use-after-free": "CVSS 3.1 Base Score: ~8.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)",
        "integer-overflow": "CVSS 3.1 Base Score: ~7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)",
        "format-string": "CVSS 3.1 Base Score: ~9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
        "command-injection": "CVSS 3.1 Base Score: ~9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
    }
    score = estimates.get(bug_class.lower(), "CVSS 3.1 Base Score: ~7.0 (heuristic estimate)")
    return f"### CVSS Estimate\n\n> {score} *(LLM heuristic — not a formal assessment)*\n"
