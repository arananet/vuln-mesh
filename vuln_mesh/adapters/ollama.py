from __future__ import annotations

import httpx

from .base import AdapterConfig, BaseAdapter


class OllamaAdapter(BaseAdapter):
    capabilities = {
        "supports_caching": False,
        "supports_json_mode": True,
    }

    def _url(self) -> str:
        base = self.config.base_url.rstrip("/")
        return f"{base}/api/chat"

    async def _do_complete(
        self,
        messages: list[dict],
        system: str,
        max_tokens: int | None = None,
    ) -> str:
        full_messages = [{"role": "system", "content": system}] + messages
        payload = {
            "model": self.config.model,
            "messages": full_messages,
            "stream": False,
            "options": {"num_predict": max_tokens or self.config.max_tokens},
        }
        async with httpx.AsyncClient(timeout=300) as client:
            resp = await client.post(self._url(), json=payload)
            resp.raise_for_status()
            data = resp.json()
        return data["message"]["content"]
