from __future__ import annotations

import pytest
import respx
import httpx

from vuln_mesh.adapters.base import AdapterConfig
from vuln_mesh.adapters.cloudflare import CloudflareAdapter
from vuln_mesh.adapters.factory import build_adapter


def _cfg(model="@cf/meta/llama-3.1-8b-instruct", api_key="tok") -> AdapterConfig:
    return AdapterConfig(provider="cloudflare", model=model, api_key=api_key)


def test_build_adapter_returns_cloudflare():
    adapter = build_adapter(_cfg())
    assert isinstance(adapter, CloudflareAdapter)


@pytest.mark.asyncio
@respx.mock
async def test_complete_returns_response_text():
    cfg = _cfg()
    adapter = CloudflareAdapter(cfg)
    adapter._account_id = "test-account"

    url = f"https://api.cloudflare.com/client/v4/accounts/test-account/ai/run/@cf/meta/llama-3.1-8b-instruct"
    respx.post(url).mock(return_value=httpx.Response(
        200,
        json={"success": True, "result": {"response": '["finding"]'}, "errors": []},
    ))

    result = await adapter.complete([{"role": "user", "content": "hi"}], "sys")
    assert result == '["finding"]'


@pytest.mark.asyncio
@respx.mock
async def test_complete_raises_on_api_error():
    cfg = _cfg()
    adapter = CloudflareAdapter(cfg)
    adapter._account_id = "test-account"

    url = f"https://api.cloudflare.com/client/v4/accounts/test-account/ai/run/@cf/meta/llama-3.1-8b-instruct"
    respx.post(url).mock(return_value=httpx.Response(
        200,
        json={"success": False, "result": None, "errors": [{"message": "bad token"}]},
    ))

    with pytest.raises(RuntimeError, match="bad token"):
        await adapter.complete([{"role": "user", "content": "hi"}], "sys")


@pytest.mark.asyncio
@respx.mock
async def test_complete_raises_on_http_error():
    cfg = _cfg()
    adapter = CloudflareAdapter(cfg)
    adapter._account_id = "test-account"

    url = f"https://api.cloudflare.com/client/v4/accounts/test-account/ai/run/@cf/meta/llama-3.1-8b-instruct"
    respx.post(url).mock(return_value=httpx.Response(401))

    with pytest.raises(httpx.HTTPStatusError):
        await adapter.complete([{"role": "user", "content": "hi"}], "sys")


def test_system_prompt_prepended_to_messages():
    """Cloudflare adapter must send system as first message in the array."""
    cfg = _cfg()
    adapter = CloudflareAdapter(cfg)
    adapter._account_id = "acct"

    captured: list[dict] = []

    async def _fake_post(url, headers, json, **_):
        captured.append(json)
        return httpx.Response(200, json={"success": True, "result": {"response": "[]"}})

    import respx as rx
    with rx.mock:
        url = f"https://api.cloudflare.com/client/v4/accounts/acct/ai/run/@cf/meta/llama-3.1-8b-instruct"
        rx.post(url).mock(side_effect=lambda req: httpx.Response(
            200, json={"success": True, "result": {"response": "[]"}}
        ))
        import asyncio
        asyncio.get_event_loop().run_until_complete(
            adapter.complete([{"role": "user", "content": "code"}], "system-prompt")
        )
