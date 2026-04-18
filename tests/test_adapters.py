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
async def test_anthropic_adapter_complete(mocker):
    cfg = AdapterConfig(provider="anthropic", model="claude-sonnet-4-6", api_key="test-key")
    adapter = AnthropicAdapter(cfg)

    # Mock the SDK client instead of the HTTP layer
    mock_response = mocker.MagicMock()
    mock_response.content = [mocker.MagicMock(text="hello")]
    adapter._client.messages.create = mocker.AsyncMock(return_value=mock_response)

    result = await adapter.complete([{"role": "user", "content": "hi"}], "system", 100)
    assert result == "hello"

    # Verify prompt caching was requested
    call_kwargs = adapter._client.messages.create.call_args.kwargs
    system_block = call_kwargs["system"][0]
    assert system_block["cache_control"] == {"type": "ephemeral"}


@pytest.mark.asyncio
async def test_anthropic_adapter_env_key(mocker):
    """Empty api_key passes None to SDK so it reads ANTHROPIC_API_KEY from env."""
    mocker.patch("vuln_mesh.adapters.anthropic.AsyncAnthropic")
    AnthropicAdapter(AdapterConfig(provider="anthropic", model="m", api_key=""))
    from vuln_mesh.adapters.anthropic import AsyncAnthropic
    AsyncAnthropic.assert_called_once_with(api_key=None)


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
