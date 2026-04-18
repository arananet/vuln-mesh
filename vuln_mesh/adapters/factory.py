from __future__ import annotations

from .anthropic import AnthropicAdapter
from .base import AdapterConfig, BaseAdapter
from .ollama import OllamaAdapter

_REGISTRY: dict[str, type[BaseAdapter]] = {
    "anthropic": AnthropicAdapter,
    "ollama": OllamaAdapter,
}


def build_adapter(config: AdapterConfig) -> BaseAdapter:
    cls = _REGISTRY.get(config.provider)
    if cls is None:
        raise ValueError(
            f"Unknown adapter provider '{config.provider}'. "
            f"Available: {sorted(_REGISTRY)}"
        )
    return cls(config)
