from __future__ import annotations

import httpx

from .base import AdapterConfig, BaseAdapter

_API_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"


class AnthropicAdapter(BaseAdapter):
    async def complete(
        self,
        messages: list[dict],
        system: str,
        max_tokens: int | None = None,
    ) -> str:
        payload = {
            "model": self.config.model,
            "max_tokens": max_tokens or self.config.max_tokens,
            "system": system,
            "messages": messages,
        }
        headers = {
            "x-api-key": self.config.api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(_API_URL, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        return data["content"][0]["text"]
