import json
import pytest
from unittest.mock import AsyncMock, MagicMock

from vuln_mesh.adapters.base import AdapterConfig, BaseAdapter
from vuln_mesh.agents.hunt import HuntAgent, Finding
from vuln_mesh.agents.verifier import VerifierAgent, VerifiedFinding
from vuln_mesh.agents.mesh import run_mesh
from vuln_mesh.ingestion.loader import FileNode
from vuln_mesh.ranker.scorer import RankedFile


def _make_ranked(path="test.c", content="void f(){strcpy(a,b);}") -> RankedFile:
    node = FileNode(path=path, language="c", content=content, size_bytes=len(content))
    return RankedFile(node=node, score=0.8, rationale="unsafe_density=0.5")


def _make_adapter(response: str) -> BaseAdapter:
    adapter = MagicMock(spec=BaseAdapter)
    adapter.complete = AsyncMock(return_value=response)
    return adapter


@pytest.mark.asyncio
async def test_hunt_agent_returns_findings():
    findings_json = json.dumps([{
        "line_hint": 3,
        "bug_class": "buffer-overflow",
        "description": "strcpy overflows dst",
        "exploit_input": "A" * 100,
    }])
    adapter = _make_adapter(findings_json)
    agent = HuntAgent(adapter)
    findings = await agent.run(_make_ranked())
    assert len(findings) == 1
    assert findings[0].bug_class == "buffer-overflow"
    assert findings[0].exploit_input == "A" * 100


@pytest.mark.asyncio
async def test_hunt_agent_empty_response():
    adapter = _make_adapter("[]")
    agent = HuntAgent(adapter)
    findings = await agent.run(_make_ranked())
    assert findings == []


@pytest.mark.asyncio
async def test_hunt_agent_adapter_exception_raises_llm_error():
    from vuln_mesh.agents.hunt import LLMError
    adapter = MagicMock(spec=BaseAdapter)
    adapter.complete = AsyncMock(side_effect=RuntimeError("network error"))
    agent = HuntAgent(adapter)
    with pytest.raises(LLMError, match="network error"):
        await agent.run(_make_ranked())


@pytest.mark.asyncio
async def test_verifier_agent_verified_true():
    response = json.dumps({"verified": True, "rationale": "The overflow is real."})
    adapter = _make_adapter(response)
    finding = Finding("f.c", 3, "buffer-overflow", "desc", "AAAA")
    vf = await VerifierAgent(adapter).run(finding, "char b[4]; strcpy(b, input);")
    assert vf.verified is True
    assert "real" in vf.verifier_rationale


@pytest.mark.asyncio
async def test_verifier_agent_verified_false():
    response = json.dumps({"verified": False, "rationale": "Bounds are checked upstream."})
    adapter = _make_adapter(response)
    finding = Finding("f.c", None, "buffer-overflow", "desc", "X")
    vf = await VerifierAgent(adapter).run(finding, "safe code")
    assert vf.verified is False


@pytest.mark.asyncio
async def test_verifier_adapter_exception_conservative():
    adapter = MagicMock(spec=BaseAdapter)
    adapter.complete = AsyncMock(side_effect=RuntimeError("timeout"))
    finding = Finding("f.c", None, "buffer-overflow", "desc", "X")
    vf = await VerifierAgent(adapter).run(finding, "code")
    assert vf.verified is False


@pytest.mark.asyncio
async def test_run_mesh_concurrency_cap():
    """Mesh should process all files and return only verified findings."""
    hunt_resp = json.dumps([{
        "line_hint": 1, "bug_class": "buffer-overflow",
        "description": "d", "exploit_input": "AAAA"
    }])
    verify_resp = json.dumps({"verified": True, "rationale": "confirmed"})

    hunt_adapter = _make_adapter(hunt_resp)
    verify_adapter = _make_adapter(verify_resp)

    ranked = [_make_ranked(f"file{i}.c") for i in range(5)]
    results = await run_mesh(ranked, hunt_adapter, verify_adapter, concurrency=2)
    assert len(results) == 5
    assert all(r.verified for r in results)


@pytest.mark.asyncio
async def test_run_mesh_filters_unverified():
    hunt_resp = json.dumps([{
        "line_hint": 1, "bug_class": "buffer-overflow",
        "description": "d", "exploit_input": "X"
    }])
    verify_resp = json.dumps({"verified": False, "rationale": "false positive"})

    ranked = [_make_ranked("f.c")]
    results = await run_mesh(
        ranked,
        _make_adapter(hunt_resp),
        _make_adapter(verify_resp),
    )
    assert results == []
