from __future__ import annotations

import os
import pytest
import respx
import httpx

from vuln_mesh.adapters.base import AdapterConfig
from vuln_mesh.adapters.cloudflare import CloudflareAdapter
from vuln_mesh.adapters.factory import build_adapter


def _make_adapter(model="@cf/meta/llama-3.1-8b-instruct", account_id="acct", token="tok") -> CloudflareAdapter:
    cfg = AdapterConfig(provider="cloudflare", model=model, api_key=token)
    adapter = CloudflareAdapter.__new__(CloudflareAdapter)
    adapter.config = cfg
    adapter._account_id = account_id
    adapter._token = token
    return adapter


def test_build_adapter_returns_cloudflare(monkeypatch):
    monkeypatch.setenv("CF_ACCOUNT_ID", "test-acct")
    monkeypatch.setenv("CF_API_TOKEN", "test-tok")
    cfg = AdapterConfig(provider="cloudflare", model="@cf/meta/llama-3.1-8b-instruct")
    adapter = build_adapter(cfg)
    assert isinstance(adapter, CloudflareAdapter)


def test_init_raises_if_account_id_missing(monkeypatch):
    monkeypatch.delenv("CF_ACCOUNT_ID", raising=False)
    monkeypatch.setenv("CF_API_TOKEN", "tok")
    cfg = AdapterConfig(provider="cloudflare", model="@cf/meta/llama-3.1-8b-instruct")
    with pytest.raises(RuntimeError, match="CF_ACCOUNT_ID"):
        CloudflareAdapter(cfg)


def test_init_raises_if_token_missing(monkeypatch):
    monkeypatch.setenv("CF_ACCOUNT_ID", "acct")
    monkeypatch.delenv("CF_API_TOKEN", raising=False)
    cfg = AdapterConfig(provider="cloudflare", model="@cf/meta/llama-3.1-8b-instruct", api_key="")
    with pytest.raises(RuntimeError, match="CF_API_TOKEN"):
        CloudflareAdapter(cfg)


@pytest.mark.asyncio
@respx.mock
async def test_complete_returns_response_text():
    adapter = _make_adapter()
    url = "https://api.cloudflare.com/client/v4/accounts/acct/ai/run/@cf/meta/llama-3.1-8b-instruct"
    respx.post(url).mock(return_value=httpx.Response(
        200, json={"success": True, "result": {"response": '["finding"]'}, "errors": []},
    ))
    result = await adapter.complete([{"role": "user", "content": "hi"}], "sys")
    assert result == '["finding"]'


@pytest.mark.asyncio
@respx.mock
async def test_complete_raises_on_api_error():
    adapter = _make_adapter()
    url = "https://api.cloudflare.com/client/v4/accounts/acct/ai/run/@cf/meta/llama-3.1-8b-instruct"
    respx.post(url).mock(return_value=httpx.Response(
        200, json={"success": False, "result": None, "errors": [{"message": "bad token"}]},
    ))
    with pytest.raises(RuntimeError, match="bad token"):
        await adapter.complete([{"role": "user", "content": "hi"}], "sys")


@pytest.mark.asyncio
@respx.mock
async def test_complete_raises_on_404_with_helpful_message():
    adapter = _make_adapter()
    url = "https://api.cloudflare.com/client/v4/accounts/acct/ai/run/@cf/meta/llama-3.1-8b-instruct"
    respx.post(url).mock(return_value=httpx.Response(404))
    with pytest.raises(RuntimeError, match="CF_ACCOUNT_ID"):
        await adapter.complete([{"role": "user", "content": "hi"}], "sys")


@pytest.mark.asyncio
@respx.mock
async def test_complete_raises_on_401():
    adapter = _make_adapter()
    url = "https://api.cloudflare.com/client/v4/accounts/acct/ai/run/@cf/meta/llama-3.1-8b-instruct"
    respx.post(url).mock(return_value=httpx.Response(401))
    with pytest.raises(httpx.HTTPStatusError):
        await adapter.complete([{"role": "user", "content": "hi"}], "sys")
