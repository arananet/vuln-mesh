import hashlib
import tempfile
from pathlib import Path

from vuln_mesh.agents.hunt import Finding
from vuln_mesh.agents.verifier import VerifiedFinding
from vuln_mesh.oracle.runner import OracleResult, OracleStatus
from vuln_mesh.report.markdown import render_markdown, finding_hash


def _make_result(bug_class="buffer-overflow", file_path="vuln.c", exploit="AAAA") -> OracleResult:
    finding = Finding(file_path, 10, bug_class, "buffer overflows at line 10", exploit)
    vf = VerifiedFinding(finding=finding, verified=True, verifier_rationale="confirmed by verifier")
    return OracleResult(finding=vf, status=OracleStatus.CRASHED, output="ERROR: AddressSanitizer")


def test_render_markdown_creates_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = str(Path(tmpdir) / "report.md")
        render_markdown([_make_result()], output_path=out)
        assert Path(out).exists()


def test_render_markdown_contains_expected_sections():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = str(Path(tmpdir) / "report.md")
        report = render_markdown([_make_result()], output_path=out)
    assert "vuln.c" in report
    assert "buffer-overflow" in report
    assert "AAAA" in report


def test_render_markdown_empty_findings():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = str(Path(tmpdir) / "report.md")
        report = render_markdown([], output_path=out)
    assert "No confirmed findings" in report


def test_render_markdown_hash_present():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = str(Path(tmpdir) / "report.md")
        r = _make_result(file_path="vuln.c", exploit="AAAA")
        report = render_markdown([r], output_path=out)
    expected_hash = finding_hash("vuln.c", "AAAA")[:16]
    assert expected_hash in report


def test_render_markdown_cvss_present_when_enabled():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = str(Path(tmpdir) / "report.md")
        report = render_markdown([_make_result()], output_path=out, cvss_estimate=True)
    assert "CVSS" in report


def test_render_markdown_cvss_absent_when_disabled():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = str(Path(tmpdir) / "report.md")
        report = render_markdown([_make_result()], output_path=out, cvss_estimate=False)
    assert "CVSS" not in report


def test_finding_hash_deterministic():
    h1 = finding_hash("file.c", "exploit")
    h2 = finding_hash("file.c", "exploit")
    assert h1 == h2


def test_finding_hash_matches_sha256():
    raw = "file.c:exploit"
    expected = hashlib.sha256(raw.encode()).hexdigest()
    assert finding_hash("file.c", "exploit") == expected
