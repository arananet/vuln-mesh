from __future__ import annotations

import os

import httpx

from .base import AdapterConfig, BaseAdapter

_BASE = "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run/{model}"


class CloudflareAdapter(BaseAdapter):
    def __init__(self, config: AdapterConfig) -> None:
        super().__init__(config)
        self._account_id = os.environ.get("CF_ACCOUNT_ID", "")
        self._token = config.api_key or os.environ.get("CF_API_TOKEN", "")
        if not self._account_id:
            raise RuntimeError(
                "CF_ACCOUNT_ID environment variable is not set. "
                "Add it to your Railway service variables."
            )
        if not self._token:
            raise RuntimeError(
                "CF_API_TOKEN environment variable is not set. "
                "Add it to your Railway service variables."
            )

    def _url(self) -> str:
        return _BASE.format(account_id=self._account_id, model=self.config.model)

    async def complete(
        self,
        messages: list[dict],
        system: str,
        max_tokens: int | None = None,
    ) -> str:
        full_messages = [{"role": "system", "content": system}] + messages
        payload: dict = {"messages": full_messages}
        if max_tokens:
            payload["max_tokens"] = max_tokens
        headers = {"Authorization": f"Bearer {self._token}"}
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(self._url(), headers=headers, json=payload)
            if resp.status_code == 404:
                raise RuntimeError(
                    f"Cloudflare AI 404 — check CF_ACCOUNT_ID and model name '{self.config.model}'. "
                    f"URL: {self._url()}"
                )
            resp.raise_for_status()
            data = resp.json()
        if not data.get("success"):
            errors = data.get("errors", [])
            raise RuntimeError(f"Cloudflare AI error: {errors}")
        return data["result"]["response"]
