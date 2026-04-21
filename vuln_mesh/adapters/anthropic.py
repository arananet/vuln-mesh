from __future__ import annotations

from anthropic import AsyncAnthropic

from .base import AdapterConfig, BaseAdapter


class AnthropicAdapter(BaseAdapter):
    capabilities = {
        "supports_caching": True,
        "supports_json_mode": False,
    }

    def __init__(self, config: AdapterConfig) -> None:
        super().__init__(config)
        # api_key=None → SDK reads ANTHROPIC_API_KEY from env
        self._client = AsyncAnthropic(api_key=config.api_key or None)

    async def _do_complete(
        self,
        messages: list[dict],
        system: str,
        max_tokens: int | None = None,
    ) -> str:
        # Cache the system prompt — it's identical across all calls in a scan run
        response = await self._client.messages.create(
            model=self.config.model,
            max_tokens=max_tokens or self.config.max_tokens,
            system=[
                {
                    "type": "text",
                    "text": system,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=messages,
            extra_headers={"anthropic-beta": "prompt-caching-2024-07-31"},
        )
        return response.content[0].text
