from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator, Callable, Coroutine, Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from vuln_mesh.db.models import Base
from vuln_mesh.db.repository import ScanRepository
from vuln_mesh.db.session import get_engine, get_session_factory

from .state import PipelineEvent, PipelineTracker

log = logging.getLogger(__name__)

_STATIC = Path(__file__).parent / "static"

# Paths that never require authentication (health probe + SPA assets)
_PUBLIC_PREFIXES = ("/api/health", "/static", "/")
_PUBLIC_EXACT = {"/", "/api/health"}


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
        # Create DB tables if connected
        engine = get_engine()
        if engine:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            log.info("Database tables ready")
        # Start scan background task if provided
        if scan_factory is not None:
            asyncio.create_task(scan_factory())
        yield
        if engine:
            await engine.dispose()

    app = FastAPI(title="vuln-mesh dashboard", lifespan=lifespan)

    # CORS — allow frontend domain (configurable via env var)
    origins_raw = os.environ.get("CORS_ORIGINS", "*")
    origins = [o.strip() for o in origins_raw.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # ── API key auth ───────────────────────────────────────────
    # Set API_SECRET_KEY to protect /events and /api/* endpoints.
    # When unset, all routes are open (local dev / first boot).
    # EventSource can't send headers, so /events also accepts ?token=<key>.
    @app.middleware("http")
    async def _require_auth(request: Request, call_next):
        secret = os.environ.get("API_SECRET_KEY", "")
        path = request.url.path
        if (
            not secret
            or path in _PUBLIC_EXACT
            or path.startswith("/static")
        ):
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        token_header = auth_header.removeprefix("Bearer ").strip() if auth_header.startswith("Bearer ") else ""
        token_query = request.query_params.get("token", "")

        if token_header == secret or token_query == secret:
            return await call_next(request)

        return JSONResponse({"detail": "Unauthorized"}, status_code=401)

    # ── Static / dashboard ─────────────────────────────────
    @app.get("/")
    async def index():
        return FileResponse(_STATIC / "index.html")

    # ── SSE stream ─────────────────────────────────────────
    @app.get("/events")
    async def sse(request: Request):
        return StreamingResponse(
            sse_stream(tracker, request.is_disconnected),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # ── Health ─────────────────────────────────────────────
    @app.get("/api/health")
    async def health():
        return {"status": "ok", "version": "0.1.0", "db": get_session_factory() is not None}

    # ── Scan history API ────────────────────────────────────
    @app.get("/api/scans")
    async def list_scans(limit: int = 20, offset: int = 0):
        factory = get_session_factory()
        if not factory:
            return []
        async with factory() as session:
            repo = ScanRepository(session)
            scans = await repo.list_scans(limit=limit, offset=offset)
            return [s.to_dict() for s in scans]

    @app.get("/api/scans/{scan_id}")
    async def get_scan(scan_id: str):
        factory = get_session_factory()
        if not factory:
            raise HTTPException(status_code=503, detail="Database not configured")
        async with factory() as session:
            repo = ScanRepository(session)
            scan = await repo.get_scan(scan_id)
            if not scan:
                raise HTTPException(status_code=404, detail="Scan not found")
            return scan.to_dict()

    @app.get("/api/scans/{scan_id}/findings")
    async def get_findings(scan_id: str):
        factory = get_session_factory()
        if not factory:
            return []
        async with factory() as session:
            repo = ScanRepository(session)
            findings = await repo.get_findings(scan_id)
            return [f.to_dict() for f in findings]

    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")
    return app
