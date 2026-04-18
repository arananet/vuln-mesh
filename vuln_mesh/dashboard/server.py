"""
Production ASGI entry point for Railway / uvicorn.

Run with:
    uvicorn vuln_mesh.dashboard.server:app --host 0.0.0.0 --port $PORT

To also launch a scan on startup (optional), set env vars:
    SCAN_TARGET=/path/to/source
    SCAN_CONFIG=config/default.yaml
"""
from __future__ import annotations

import asyncio
import logging
import os

from .app import create_app
from .state import PipelineTracker

log = logging.getLogger(__name__)

tracker = PipelineTracker()


def _build_scan_factory():
    """Return a coroutine factory for auto-scan on boot (SCAN_TARGET env var)."""
    target = os.environ.get("SCAN_TARGET", "")
    if not target:
        return None

    import yaml
    from vuln_mesh.cli import _run_scan

    config_path = os.environ.get("SCAN_CONFIG", "config/default.yaml")
    try:
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
    except FileNotFoundError:
        log.warning("SCAN_CONFIG not found: %s — scan disabled", config_path)
        return None

    def factory():
        return _run_scan(cfg, target, None, None, tracker)

    return factory


async def _scan_runner(source: str, config_path: str = "config/default.yaml") -> None:
    """On-demand scan runner called from POST /api/scan."""
    import yaml
    from vuln_mesh.cli import _run_scan

    try:
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
    except FileNotFoundError:
        log.warning("Config not found: %s — using defaults", config_path)
        cfg = {
            "ranker": {"top_n": 200, "min_score": 0.4},
            "agents": {"concurrency": 8, "model_profile": "triage", "verifier_profile": "verifier"},
            "adapters": {"triage": {"provider": "anthropic", "model": "claude-haiku-4-5-20251001"},
                         "verifier": {"provider": "anthropic", "model": "claude-sonnet-4-6"}},
        }

    await _run_scan(cfg, source, None, None, tracker)


app = create_app(tracker, scan_factory=_build_scan_factory(), scan_runner=_scan_runner)
