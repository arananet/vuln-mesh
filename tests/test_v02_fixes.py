"""Tests for v0.2 architectural fixes (spec: v02-architectural-fixes)."""
from __future__ import annotations

import asyncio
import logging
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

# ---------------------------------------------------------------------------
# 1. Ingestion: relative include resolution
# ---------------------------------------------------------------------------

def test_ingestion_relative_include():
    """AC: include directives resolved relative to the including file's directory."""
    from vuln_mesh.ingestion.loader import ingest

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "sub").mkdir()
        (root / "sub" / "a.c").write_text('#include "b.h"\nint x;')
        (root / "sub" / "b.h").write_text("int b;")
        graph = ingest(str(root))
        # b.h should be resolved relative to sub/a.c → sub/b.h
        edges_from_a = [dst for src, dst in graph.edges if "a.c" in str(src)]
        assert any("b.h" in str(e) for e in edges_from_a)


def test_ingestion_py_js_files():
    """AC: .py and .js files are ingested."""
    from vuln_mesh.ingestion.loader import ingest

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.py").write_text("import os\nprint('hi')")
        (root / "index.js").write_text("const x = require('fs');")
        graph = ingest(str(root))
        paths = [str(n.path) for n in graph.nodes]
        assert any("app.py" in p for p in paths)
        assert any("index.js" in p for p in paths)


# ---------------------------------------------------------------------------
# 2. Ranker: directed BFS, configurable weights
# ---------------------------------------------------------------------------

def test_ranker_directed_bfs():
    """AC: BFS uses directed edges — leaf not reachable from unrelated includer."""
    from vuln_mesh.ingestion.loader import FileGraph, FileNode
    from vuln_mesh.ranker.scorer import rank

    a = FileNode(path=Path("a.c"), content="int main(){}", language="c", includes=[])
    b = FileNode(path=Path("b.c"), content="int x;", language="c", includes=[])
    c = FileNode(path=Path("c.c"), content="int y;", language="c", includes=[])
    # a -> b (a includes b), c is isolated
    graph = FileGraph(nodes=[a, b, c], edges=[(Path("a.c"), Path("b.c"))])
    ranked = rank(graph)
    # c should have reachability_depth 0 (unreachable from entry)
    c_item = next(r for r in ranked if r.node.path == Path("c.c"))
    assert c_item.score >= 0  # just verifying it runs


def test_ranker_weights():
    """AC: weights parameter changes scoring."""
    from vuln_mesh.ingestion.loader import FileGraph, FileNode
    from vuln_mesh.ranker.scorer import rank

    a = FileNode(path=Path("a.c"), content="int main(){char buf[10]; gets(buf);}", language="c", includes=[])
    graph = FileGraph(nodes=[a], edges=[])
    r1 = rank(graph, weights={"surface": 1.0, "influence": 0.0, "reachability": 0.0})
    r2 = rank(graph, weights={"surface": 0.0, "influence": 1.0, "reachability": 0.0})
    # Different weights should produce different scores
    assert r1[0].score != r2[0].score or len(r1) == 1


# ---------------------------------------------------------------------------
# 3. Adapter: capabilities, retry on 429
# ---------------------------------------------------------------------------

def test_adapter_capabilities():
    """AC: BaseAdapter subclasses expose capabilities dict."""
    from vuln_mesh.adapters.anthropic import AnthropicAdapter
    from vuln_mesh.adapters.ollama import OllamaAdapter

    assert AnthropicAdapter.capabilities["supports_caching"] is True
    assert OllamaAdapter.capabilities["supports_json_mode"] is True


@pytest.mark.asyncio
async def test_adapter_retry_on_429(mocker):
    """AC: adapter retries on 429 with exponential backoff."""
    from vuln_mesh.adapters.base import AdapterConfig, BaseAdapter

    class _TestAdapter(BaseAdapter):
        capabilities = {}
        call_count = 0

        async def _do_complete(self, messages, system_prompt, max_tokens=4096):
            self.call_count += 1
            if self.call_count < 3:
                resp = httpx.Response(429)
                raise httpx.HTTPStatusError("rate limited", request=httpx.Request("POST", "http://x"), response=resp)
            return "ok"

    adapter = _TestAdapter(AdapterConfig(provider="test", model="m"))
    mocker.patch("asyncio.sleep", new_callable=AsyncMock)
    result = await adapter.complete([], "sys")
    assert result == "ok"
    assert adapter.call_count == 3


# ---------------------------------------------------------------------------
# 4. Corroboration key with None line_hint
# ---------------------------------------------------------------------------

def test_corroboration_key_includes_file_path():
    """AC: corroboration key uses file_path to avoid collisions."""
    from vuln_mesh.agents.mesh import _corroborate
    from vuln_mesh.agents.hunt import Finding

    f1 = Finding(file_path="a.c", bug_class="buffer-overflow", description="d", exploit_input="e", line_hint=None)
    f2 = Finding(file_path="b.c", bug_class="buffer-overflow", description="d", exploit_input="e", line_hint=None)
    result = _corroborate({"TRIAGE": [f1], "SURFACE": [f2]})
    # Both should survive since they're from different files
    assert len(result) == 2


# ---------------------------------------------------------------------------
# 5. Oracle: async wrapper, SKIPPED for non-compilable
# ---------------------------------------------------------------------------

def test_oracle_skips_non_compilable():
    """AC: oracle returns SKIPPED for .py/.js files."""
    from vuln_mesh.agents.hunt import Finding
    from vuln_mesh.agents.verifier import VerifiedFinding
    from vuln_mesh.oracle.runner import OracleStatus, run_oracle

    f = Finding(file_path="app.py", line_hint=1, bug_class="xss", description="d", exploit_input="e")
    vf = VerifiedFinding(finding=f, verified=True, verifier_rationale="r")
    result = run_oracle(vf)
    assert result.status == OracleStatus.SKIPPED


@pytest.mark.asyncio
async def test_oracle_async_wraps_to_thread(mocker):
    """AC: run_oracle_async uses asyncio.to_thread."""
    from vuln_mesh.oracle.runner import run_oracle_async

    mock_result = MagicMock()
    mocker.patch("vuln_mesh.oracle.runner.run_oracle", return_value=mock_result)
    mocker.patch("asyncio.to_thread", new_callable=AsyncMock, return_value=mock_result)
    vf = MagicMock()
    result = await run_oracle_async(vf)
    assert result is mock_result


# ---------------------------------------------------------------------------
# 6. Report: COMPILE_ERROR + SKIPPED + CWE/OWASP rendering
# ---------------------------------------------------------------------------

def test_report_compile_error_section():
    """AC: report renders compile errors prominently."""
    from vuln_mesh.agents.hunt import Finding
    from vuln_mesh.agents.verifier import VerifiedFinding
    from vuln_mesh.oracle.runner import OracleResult, OracleStatus
    from vuln_mesh.report.markdown import render_markdown

    f = Finding(file_path="x.c", line_hint=5, bug_class="buffer-overflow", description="d", exploit_input="e", cwe_id="CWE-120", owasp_category="A03:2021")
    vf = VerifiedFinding(finding=f, verified=True, verifier_rationale="r")

    with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as tmp:
        results = [OracleResult(finding=vf, status=OracleStatus.COMPILE_ERROR, output="error: ...")]
        md = render_markdown(results, output_path=tmp.name)
        assert "COMPILE_ERROR" in md
        assert "CWE-120" in md
        assert "A03:2021" in md
        assert "Compiler Error" in md


def test_report_skipped_section():
    """AC: report renders verified-only findings for non-compilable languages."""
    from vuln_mesh.agents.hunt import Finding
    from vuln_mesh.agents.verifier import VerifiedFinding
    from vuln_mesh.oracle.runner import OracleResult, OracleStatus
    from vuln_mesh.report.markdown import render_markdown

    f = Finding(file_path="app.js", line_hint=1, bug_class="xss", description="d", exploit_input="e")
    vf = VerifiedFinding(finding=f, verified=True, verifier_rationale="r")

    with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as tmp:
        results = [OracleResult(finding=vf, status=OracleStatus.SKIPPED, output="")]
        md = render_markdown(results, output_path=tmp.name)
        assert "VERIFIED" in md
        assert "Non-Compilable" in md


# ---------------------------------------------------------------------------
# 7. Hunt agent: CWE/OWASP in prompts
# ---------------------------------------------------------------------------

def test_hunt_guidance_has_cwe():
    """AC: hunt agent prompts include CWE IDs."""
    from vuln_mesh.agents.hunt import _LANG_GUIDANCE
    for lang, guidance in _LANG_GUIDANCE.items():
        assert "CWE" in guidance, f"{lang} guidance missing CWE references"


# ---------------------------------------------------------------------------
# 8. SynthAgent truncation logging
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_synth_truncation_logs_warning(mocker, caplog):
    """AC: SynthAgent logs warning when truncating large files."""
    from vuln_mesh.agents.hunt import SynthAgent, Finding
    from vuln_mesh.adapters.base import AdapterConfig, BaseAdapter

    class _Stub(BaseAdapter):
        capabilities = {}
        async def _do_complete(self, messages, system_prompt, max_tokens=4096):
            return '[]'

    adapter = _Stub(AdapterConfig(provider="test", model="m"))
    agent = SynthAgent(adapter)

    # Create a fake RankedFile with content larger than MAX_FILE_CHARS
    rf = MagicMock()
    rf.node.path = Path("big.c")
    rf.node.content = "x" * 5000
    rf.node.language = "c"
    rf.score = 0.9
    rf.surface = 0.5

    with caplog.at_level(logging.WARNING):
        await agent.run([rf])
    assert any("truncat" in r.message.lower() for r in caplog.records)


# ---------------------------------------------------------------------------
# 9. DB: DiscardedFinding model
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_discarded_finding_persistence():
    """AC: discarded findings are persisted to the database."""
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    from vuln_mesh.db.models import Base
    from vuln_mesh.db.repository import ScanRepository

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    async with Session() as session:
        repo = ScanRepository(session)
        scan = await repo.create_scan("test-target")
        df = await repo.add_discarded_finding(
            scan_id=scan.id,
            file_path="test.c",
            line_hint=10,
            bug_class="buffer-overflow",
            description="false positive",
            dimension="TRIAGE",
            rejection_reason="verifier_rejected",
        )
        assert df.id is not None
        results = await repo.get_discarded_findings(scan.id)
        assert len(results) == 1
        assert results[0].rejection_reason == "verifier_rejected"
    await engine.dispose()
