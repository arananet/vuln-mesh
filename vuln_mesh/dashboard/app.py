from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator, Callable, Coroutine, Any

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .state import PipelineEvent, PipelineTracker

log = logging.getLogger(__name__)

_STATIC = Path(__file__).parent / "static"


async def sse_stream(
    tracker: PipelineTracker,
    is_disconnected: Callable[[], Coroutine[Any, Any, bool]],
    heartbeat_interval: float = 1.0,
) -> AsyncIterator[str]:
    """Yield SSE-formatted strings. Extracted for unit testability."""
    q = tracker.subscribe()
    init = json.dumps({"type": "state", "stats": tracker.stats})
    yield f"data: {init}\n\n"
    try:
        while True:
            if await is_disconnected():
                break
            try:
                event: PipelineEvent = await asyncio.wait_for(q.get(), timeout=heartbeat_interval)
                payload = json.dumps({
                    "type": event.type,
                    "data": event.data,
                    "ts": event.timestamp,
                    "stats": tracker.stats,
                })
                yield f"data: {payload}\n\n"
            except asyncio.TimeoutError:
                yield ": heartbeat\n\n"
    finally:
        tracker.unsubscribe(q)


def create_app(
    tracker: PipelineTracker,
    scan_factory: Callable[[], Coroutine[Any, Any, None]] | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if scan_factory is not None:
            asyncio.create_task(scan_factory())
        yield

    app = FastAPI(title="vuln-mesh dashboard", lifespan=lifespan)

    @app.get("/")
    async def index():
        return FileResponse(_STATIC / "index.html")

    @app.get("/events")
    async def sse(request: Request):
        return StreamingResponse(
            sse_stream(tracker, request.is_disconnected),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")
    return app
