from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator, Callable, Coroutine, Any

from pydantic import BaseModel

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

# Paths that never require a session token
_PUBLIC_EXACT = {"/", "/api/health", "/api/login"}


def _session_token() -> str:
    """Derive a bearer token from ADMIN_USER + ADMIN_PASS (stateless, no DB needed)."""
    import hashlib
    user = os.environ.get("ADMIN_USER", "admin")
    password = os.environ.get("ADMIN_PASS", "")
    return hashlib.sha256(f"{user}:{password}".encode()).hexdigest()


class _LoginBody(BaseModel):
    username: str = ""
    password: str = ""


class _ScanRequest(BaseModel):
    source: str
    output: str = ""          # report destination; empty = auto-named
    config: str = "config/default.yaml"
    github_token: str = ""


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
    scan_runner: Callable[[str, str], Coroutine[Any, Any, None]] | None = None,
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

    # ── Auth middleware ────────────────────────────────────────
    # Set ADMIN_PASS to enable auth. When empty, all routes are open
    # (useful for local dev). EventSource uses ?token= since browsers
    # cannot send custom headers on SSE connections.
    @app.middleware("http")
    async def _require_auth(request: Request, call_next):
        if not os.environ.get("ADMIN_PASS", ""):
            return await call_next(request)

        path = request.url.path
        if path in _PUBLIC_EXACT or path.startswith("/static"):
            return await call_next(request)

        token = _session_token()
        auth_header = request.headers.get("Authorization", "")
        token_header = auth_header.removeprefix("Bearer ").strip() if auth_header.startswith("Bearer ") else ""
        token_query = request.query_params.get("token", "")

        if token_header == token or token_query == token:
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

    # ── Login ──────────────────────────────────────────────
    @app.post("/api/login")
    async def login(body: _LoginBody):
        expected_user = os.environ.get("ADMIN_USER", "admin")
        expected_pass = os.environ.get("ADMIN_PASS", "")
        if not expected_pass:
            # Auth disabled — return a dummy token so the frontend still works
            return {"token": _session_token(), "auth_required": False}
        if body.username == expected_user and body.password == expected_pass:
            return {"token": _session_token(), "auth_required": True}
        return JSONResponse({"detail": "Invalid credentials"}, status_code=401)

    # ── On-demand scan trigger ─────────────────────────────
    _active_task: list[asyncio.Task] = []  # list so closure can mutate it

    @app.post("/api/scan")
    async def trigger_scan(body: _ScanRequest):
        from vuln_mesh.ingestion.git_clone import is_git_url
        if scan_runner is None:
            raise HTTPException(status_code=503, detail="Scan runner not configured")
        if not body.source or not body.source.strip():
            raise HTTPException(status_code=400, detail="source path is required")
        if not is_git_url(body.source) and not Path(body.source).exists():
            raise HTTPException(status_code=400, detail=f"Path not found: {body.source}")
        # Reject if a scan task is currently running
        if _active_task and not _active_task[0].done():
            raise HTTPException(status_code=409, detail="A scan is already running")
        task = asyncio.create_task(scan_runner(body.source, body.config, body.output or None, body.github_token or None))
        if _active_task:
            _active_task[0] = task
        else:
            _active_task.append(task)
        return {"status": "started", "source": body.source, "output": body.output or "(auto)"}

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
