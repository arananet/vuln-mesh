from __future__ import annotations

import json
import os

import httpx

from .base import AdapterConfig, BaseAdapter

# All inference goes through the shared AI Gateway (arananet-ai-gateway),
# never straight to the Workers AI REST API. The gateway's workers-ai
# endpoint returns the same native contract (success / result.response /
# errors) as the direct API, so only the URL and one header change.
_BASE = (
    "https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway}"
    "/workers-ai/{model}"
)
_DEFAULT_GATEWAY = "arananet-ai-gateway"


class CloudflareAdapter(BaseAdapter):
    capabilities = {
        "supports_caching": False,
        "supports_json_mode": False,
    }

    def __init__(self, config: AdapterConfig) -> None:
        super().__init__(config)
        # Defer env-var validation to complete() so tests that don't use
        # Cloudflare can still construct the adapter without crashing.
        self._account_id: str | None = None
        self._token: str | None = None

    def _ensure_credentials(self) -> None:
        if self._account_id is None:
            self._account_id = os.environ.get("CF_ACCOUNT_ID", "")
        if self._token is None:
            self._token = self.config.api_key or os.environ.get("CF_API_TOKEN", "")
        if not self._account_id:
            raise RuntimeError(
                "CF_ACCOUNT_ID environment variable is not set. "
                "Set it in your environment variables."
            )
        if not self._token:
            raise RuntimeError(
                "CF_API_TOKEN environment variable is not set. "
                "Set it in your environment variables."
            )

    def _gateway(self) -> str:
        return os.environ.get("CF_AI_GATEWAY", "") or _DEFAULT_GATEWAY

    def _url(self) -> str:
        return _BASE.format(
            account_id=self._account_id,
            gateway=self._gateway(),
            model=self.config.model,
        )

    def _metadata_header(self) -> str:
        # Per-app attribution in the gateway logs, same convention as the
        # other apps on the shared gateway.
        return json.dumps(
            {"app": "vuln-mesh", "env": os.environ.get("CF_AI_ENV", "") or "prod"}
        )

    async def _do_complete(
        self,
        messages: list[dict],
        system: str,
        max_tokens: int | None = None,
    ) -> str:
        self._ensure_credentials()
        full_messages = [{"role": "system", "content": system}] + messages
        payload: dict = {"messages": full_messages}
        if max_tokens:
            payload["max_tokens"] = max_tokens
        headers = {
            "Authorization": f"Bearer {self._token}",
            "cf-aig-metadata": self._metadata_header(),
        }
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(self._url(), headers=headers, json=payload)
            if resp.status_code == 404:
                raise RuntimeError(
                    f"Cloudflare AI Gateway 404: check CF_ACCOUNT_ID, the gateway "
                    f"'{self._gateway()}' and model name '{self.config.model}'. "
                    f"URL: {self._url()}"
                )
            resp.raise_for_status()
            data = resp.json()
        if not data.get("success"):
            errors = data.get("errors", [])
            raise RuntimeError(f"Cloudflare AI error: {errors}")
        return data["result"]["response"]
