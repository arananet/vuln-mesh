from __future__ import annotations

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


@dataclass
class OracleResult:
    finding: VerifiedFinding
    status: OracleStatus
    output: str
    binary_path: str | None = None


def run_oracle(vf: VerifiedFinding, timeout: int = 10) -> OracleResult:
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
