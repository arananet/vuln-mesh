import shutil
import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock

from vuln_mesh.agents.hunt import Finding
from vuln_mesh.agents.verifier import VerifiedFinding
from vuln_mesh.oracle.crash import compile_with_asan
from vuln_mesh.oracle.runner import run_oracle, OracleStatus

FIXTURES = Path(__file__).parent / "fixtures" / "oracle"

pytestmark = pytest.mark.skipif(
    shutil.which("clang") is None and shutil.which("gcc") is None,
    reason="No C compiler available",
)


def _make_vf(file_path: str, exploit_input: str = "hello\n") -> VerifiedFinding:
    finding = Finding(
        file_path=file_path,
        line_hint=None,
        bug_class="buffer-overflow",
        description="test",
        exploit_input=exploit_input,
    )
    return VerifiedFinding(finding=finding, verified=True, verifier_rationale="confirmed")


def test_compile_with_asan_success():
    with tempfile.TemporaryDirectory() as tmpdir:
        binary, stderr = compile_with_asan(str(FIXTURES / "safe.c"), tmpdir)
    assert binary is not None
    assert stderr is None


def test_compile_with_asan_failure(tmp_path):
    broken = tmp_path / "broken.c"
    broken.write_text("this is not valid C code ;;;")
    with tempfile.TemporaryDirectory() as tmpdir:
        binary, stderr = compile_with_asan(str(broken), tmpdir)
    assert binary is None
    assert stderr


def test_oracle_safe_returns_clean():
    vf = _make_vf(str(FIXTURES / "safe.c"), "world\n")
    result = run_oracle(vf)
    assert result.status == OracleStatus.CLEAN


def test_oracle_crash_returns_crashed():
    # Feed more than 8 bytes to overflow the 8-byte buffer in crash.c
    exploit = "A" * 128 + "\n"
    vf = _make_vf(str(FIXTURES / "crash.c"), exploit)
    result = run_oracle(vf)
    assert result.status == OracleStatus.CRASHED


def test_oracle_compile_error():
    vf = _make_vf("/nonexistent/file.c", "x")
    result = run_oracle(vf)
    assert result.status == OracleStatus.COMPILE_ERROR


def test_oracle_timeout(tmp_path):
    inf_loop = tmp_path / "loop.c"
    inf_loop.write_text("int main(void){while(1){}return 0;}")
    vf = _make_vf(str(inf_loop), "")
    result = run_oracle(vf, timeout=1)
    assert result.status == OracleStatus.TIMEOUT
