from __future__ import annotations

import abc
from dataclasses import dataclass


@dataclass
class AdapterConfig:
    provider: str
    model: str
    base_url: str = ""
    api_key: str = ""
    max_tokens: int = 4096


class BaseAdapter(abc.ABC):
    def __init__(self, config: AdapterConfig) -> None:
        self.config = config

    @abc.abstractmethod
    async def complete(
        self,
        messages: list[dict],
        system: str,
        max_tokens: int | None = None,
    ) -> str: ...
