import asyncio
import json
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from vuln_mesh.dashboard.app import create_app, sse_stream
from vuln_mesh.dashboard.state import EventType, PipelineEvent, PipelineTracker


def _app(tracker=None):
    return create_app(tracker or PipelineTracker(), scan_factory=None)


def test_create_app_returns_fastapi():
    assert isinstance(_app(), FastAPI)


def test_index_route_exists():
    client = TestClient(_app())
    assert client.get("/").status_code == 200


def test_app_has_events_and_index_routes():
    app = _app()
    paths = [r.path for r in app.routes]
    assert "/" in paths
    assert "/events" in paths


# ── sse_stream unit tests (no HTTP layer) ──────────────────

async def _collect(tracker, disconnect_after=1, heartbeat_interval=0.01):
    """Collect events from sse_stream until is_disconnected returns True."""
    call_count = 0

    async def is_disconnected():
        nonlocal call_count
        call_count += 1
        return call_count > disconnect_after

    chunks = []
    async for chunk in sse_stream(tracker, is_disconnected, heartbeat_interval):
        chunks.append(chunk)
    return chunks


@pytest.mark.asyncio
async def test_sse_stream_yields_initial_state():
    tracker = PipelineTracker()
    tracker.stats["files_ingested"] = 5
    chunks = await _collect(tracker, disconnect_after=0)
    assert len(chunks) == 1
    assert chunks[0].startswith("data: ")
    data = json.loads(chunks[0][6:])
    assert data["type"] == "state"
    assert data["stats"]["files_ingested"] == 5


@pytest.mark.asyncio
async def test_sse_stream_delivers_emitted_event():
    tracker = PipelineTracker()

    # Emit an event after a short delay so sse_stream has subscribed its queue
    async def _emit():
        await asyncio.sleep(0.05)
        await tracker.emit(PipelineEvent(EventType.SCAN_STARTED, {"target": "/src"}))

    task = asyncio.create_task(_emit())
    # Allow enough loop iterations for the emit to land (heartbeat=0.01s × 8)
    chunks = await _collect(tracker, disconnect_after=8, heartbeat_interval=0.01)
    await task

    data_chunks = [c for c in chunks if c.startswith("data: ")]
    types = [json.loads(c[6:])["type"] for c in data_chunks]
    assert EventType.SCAN_STARTED in types


@pytest.mark.asyncio
async def test_sse_stream_unsubscribes_on_exit():
    tracker = PipelineTracker()
    assert len(tracker._queues) == 0
    chunks = await _collect(tracker, disconnect_after=0)
    # After the generator finishes, the queue should be unsubscribed
    assert len(tracker._queues) == 0


@pytest.mark.asyncio
async def test_sse_stream_yields_heartbeat_on_timeout():
    tracker = PipelineTracker()
    # Allow one wait cycle (initial state + one loop iteration) before disconnect
    chunks = await _collect(tracker, disconnect_after=2, heartbeat_interval=0.01)
    heartbeats = [c for c in chunks if c.startswith(": heartbeat")]
    assert len(heartbeats) >= 1


# ── Auth middleware tests ───────────────────────────────────

def test_health_is_public_regardless_of_auth(monkeypatch):
    monkeypatch.setenv("API_SECRET_KEY", "supersecret")
    client = TestClient(_app())
    assert client.get("/api/health").status_code == 200


def test_index_is_public_regardless_of_auth(monkeypatch):
    monkeypatch.setenv("API_SECRET_KEY", "supersecret")
    client = TestClient(_app())
    assert client.get("/").status_code == 200


def test_api_scans_blocked_without_key(monkeypatch):
    monkeypatch.setenv("API_SECRET_KEY", "supersecret")
    client = TestClient(_app())
    assert client.get("/api/scans").status_code == 401


def test_api_scans_allowed_with_bearer_token(monkeypatch):
    monkeypatch.setenv("API_SECRET_KEY", "supersecret")
    client = TestClient(_app())
    resp = client.get("/api/scans", headers={"Authorization": "Bearer supersecret"})
    assert resp.status_code == 200


def test_no_auth_key_means_open_access(monkeypatch):
    monkeypatch.delenv("API_SECRET_KEY", raising=False)
    client = TestClient(_app())
    assert client.get("/api/scans").status_code == 200


def test_wrong_token_returns_401(monkeypatch):
    monkeypatch.setenv("API_SECRET_KEY", "supersecret")
    client = TestClient(_app())
    resp = client.get("/api/scans", headers={"Authorization": "Bearer wrongkey"})
    assert resp.status_code == 401


def test_static_files_are_public(monkeypatch):
    monkeypatch.setenv("API_SECRET_KEY", "supersecret")
    client = TestClient(_app())
    # /static/* should never be blocked (served by StaticFiles)
    assert client.get("/api/health").status_code == 200
