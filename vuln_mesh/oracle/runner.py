from __future__ import annotations

import asyncio
import subprocess
import tempfile
from dataclasses import dataclass
from enum import Enum

from vuln_mesh.agents.verifier import VerifiedFinding

from .crash import compile_with_asan


class OracleStatus(str, Enum):
    CRASHED = "crashed"
    CLEAN = "clean"
    COMPILE_ERROR = "compile_error"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"  # non-compilable languages


@dataclass
class OracleResult:
    finding: VerifiedFinding
    status: OracleStatus
    output: str
    binary_path: str | None = None


# Languages where ASan oracle compilation is applicable
_COMPILABLE_LANGUAGES = {"c", "cpp"}


def run_oracle(vf: VerifiedFinding, timeout: int = 10) -> OracleResult:
    # Skip oracle for non-compilable languages — finding still ships as verified-only
    language = getattr(vf.finding, '_language', None)
    # Infer language from file extension if not set
    if language is None:
        ext = vf.finding.file_path.rsplit('.', 1)[-1].lower() if '.' in vf.finding.file_path else ''
        language = {"c": "c", "h": "c", "cpp": "cpp", "cc": "cpp", "cxx": "cpp"}.get(ext)

    if language not in _COMPILABLE_LANGUAGES:
        return OracleResult(
            finding=vf,
            status=OracleStatus.SKIPPED,
            output=f"Oracle skipped: ASan not applicable for {language or 'unknown'} files",
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        binary, stderr = compile_with_asan(vf.finding.file_path, tmpdir)
        if binary is None:
            return OracleResult(finding=vf, status=OracleStatus.COMPILE_ERROR, output=stderr or "")

        exploit = vf.finding.exploit_input.encode(errors="replace")
        try:
            result = subprocess.run(
                [binary],
                input=exploit,
                capture_output=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return OracleResult(finding=vf, status=OracleStatus.TIMEOUT, output="", binary_path=binary)

        combined = (result.stdout + result.stderr).decode(errors="replace")
        # ASan/crash indicators
        crashed = (
            result.returncode != 0
            and any(sig in combined for sig in ("ERROR: AddressSanitizer", "SIGSEGV", "Aborted", "runtime error"))
        ) or result.returncode < 0

        status = OracleStatus.CRASHED if crashed else OracleStatus.CLEAN
        return OracleResult(finding=vf, status=status, output=combined[:4096], binary_path=binary)


async def run_oracle_async(vf: VerifiedFinding, timeout: int = 10) -> OracleResult:
    """Async wrapper — runs oracle in a thread to avoid blocking the event loop."""
    return await asyncio.to_thread(run_oracle, vf, timeout)
