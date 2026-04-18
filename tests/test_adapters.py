import pytest
import respx
import httpx

from vuln_mesh.adapters.base import AdapterConfig
from vuln_mesh.adapters.factory import build_adapter
from vuln_mesh.adapters.anthropic import AnthropicAdapter
from vuln_mesh.adapters.ollama import OllamaAdapter


def _cfg(**kw) -> AdapterConfig:
    return AdapterConfig(provider="test", model="m", **kw)


def test_build_adapter_unknown_provider():
    with pytest.raises(ValueError, match="Unknown adapter provider"):
        build_adapter(AdapterConfig(provider="unknown", model="x"))


def test_build_adapter_anthropic():
    cfg = AdapterConfig(provider="anthropic", model="claude-sonnet-4-6", api_key="k")
    adapter = build_adapter(cfg)
    assert isinstance(adapter, AnthropicAdapter)


def test_build_adapter_ollama():
    cfg = AdapterConfig(provider="ollama", model="qwen2.5-coder:32b", base_url="http://localhost:11434")
    adapter = build_adapter(cfg)
    assert isinstance(adapter, OllamaAdapter)


@pytest.mark.asyncio
@respx.mock
async def test_anthropic_adapter_complete():
    cfg = AdapterConfig(provider="anthropic", model="claude-sonnet-4-6", api_key="test-key")
    adapter = AnthropicAdapter(cfg)

    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(200, json={
            "content": [{"type": "text", "text": "hello"}]
        })
    )
    result = await adapter.complete([{"role": "user", "content": "hi"}], "system", 100)
    assert result == "hello"


@pytest.mark.asyncio
@respx.mock
async def test_ollama_adapter_complete():
    cfg = AdapterConfig(provider="ollama", model="qwen2.5-coder:32b", base_url="http://localhost:11434")
    adapter = OllamaAdapter(cfg)

    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(200, json={
            "message": {"role": "assistant", "content": "found bug"}
        })
    )
    result = await adapter.complete([{"role": "user", "content": "analyze"}], "sys", 512)
    assert result == "found bug"


def test_adapter_config_defaults():
    cfg = AdapterConfig(provider="anthropic", model="claude-sonnet-4-6")
    assert cfg.max_tokens == 4096
    assert cfg.api_key == ""
    assert cfg.base_url == ""
