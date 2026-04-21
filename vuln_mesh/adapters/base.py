from __future__ import annotations

import abc
import asyncio
import logging
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


@dataclass
class AdapterConfig:
    provider: str
    model: str
    base_url: str = ""
    api_key: str = ""
    max_tokens: int = 4096


class BaseAdapter(abc.ABC):
    # Override in subclasses to advertise provider-specific features
    capabilities: dict[str, bool] = {
        "supports_caching": False,
        "supports_json_mode": False,
    }

    def __init__(self, config: AdapterConfig) -> None:
        self.config = config

    @abc.abstractmethod
    async def _do_complete(
        self,
        messages: list[dict],
        system: str,
        max_tokens: int | None = None,
    ) -> str: ...

    async def complete(
        self,
        messages: list[dict],
        system: str,
        max_tokens: int | None = None,
        max_retries: int = 3,
    ) -> str:
        """Call _do_complete with exponential backoff retry on transient errors."""
        import httpx

        last_exc: Exception | None = None
        for attempt in range(max_retries):
            try:
                return await self._do_complete(messages, system, max_tokens)
            except (httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException) as exc:
                last_exc = exc
                status = getattr(getattr(exc, "response", None), "status_code", 0)
                # Only retry on transient errors: 429 (rate limit), 5xx (server error)
                if isinstance(exc, httpx.HTTPStatusError) and status < 429:
                    raise
                if attempt < max_retries - 1:
                    wait = 2 ** attempt
                    log.warning(
                        "Adapter %s attempt %d/%d failed (%s), retrying in %ds",
                        self.config.provider, attempt + 1, max_retries, exc, wait,
                    )
                    await asyncio.sleep(wait)
                else:
                    raise
        raise last_exc  # unreachable but satisfies type checker
