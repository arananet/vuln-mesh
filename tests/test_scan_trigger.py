import asyncio
import hashlib
import pytest
from fastapi.testclient import TestClient

from vuln_mesh.dashboard.app import create_app
from vuln_mesh.dashboard.state import PipelineTracker


def _token(user="admin", password="testpass"):
    return hashlib.sha256(f"{user}:{password}".encode()).hexdigest()


def _app_with_runner(runner=None):
    return create_app(PipelineTracker(), scan_factory=None, scan_runner=runner)


def test_scan_trigger_returns_503_when_no_runner():
    client = TestClient(_app_with_runner(runner=None))
    resp = client.post("/api/scan", json={"source": "/tmp"})
    assert resp.status_code == 503


def test_scan_trigger_returns_400_for_missing_source(tmp_path, monkeypatch):
    monkeypatch.delenv("ADMIN_PASS", raising=False)

    async def fake_runner(src, cfg, out=None): pass

    client = TestClient(_app_with_runner(runner=fake_runner))
    resp = client.post("/api/scan", json={"source": ""})
    assert resp.status_code == 400


def test_scan_trigger_returns_400_for_nonexistent_path(monkeypatch):
    monkeypatch.delenv("ADMIN_PASS", raising=False)

    async def fake_runner(src, cfg, out=None): pass

    client = TestClient(_app_with_runner(runner=fake_runner))
    resp = client.post("/api/scan", json={"source": "/nonexistent/path/xyz"})
    assert resp.status_code == 400


def test_scan_trigger_returns_200_for_valid_path(tmp_path, monkeypatch):
    monkeypatch.delenv("ADMIN_PASS", raising=False)

    async def fake_runner(src, cfg, out=None):
        await asyncio.sleep(10)  # stays "running" for the test

    client = TestClient(_app_with_runner(runner=fake_runner))
    resp = client.post("/api/scan", json={"source": str(tmp_path)})
    assert resp.status_code == 200
    assert resp.json()["status"] == "started"


def test_scan_trigger_returns_401_without_token(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_USER", "admin")
    monkeypatch.setenv("ADMIN_PASS", "testpass")

    async def fake_runner(src, cfg, out=None): pass

    client = TestClient(_app_with_runner(runner=fake_runner))
    resp = client.post("/api/scan", json={"source": str(tmp_path)})
    assert resp.status_code == 401


def test_scan_trigger_returns_409_when_scan_already_running(tmp_path, monkeypatch):
    monkeypatch.delenv("ADMIN_PASS", raising=False)

    async def fake_runner(src, cfg, out=None):
        await asyncio.sleep(10)  # stays running during both requests

    # Use context manager so both requests share the same event loop,
    # keeping the background task alive between calls.
    with TestClient(_app_with_runner(runner=fake_runner)) as client:
        client.post("/api/scan", json={"source": str(tmp_path)})
        resp = client.post("/api/scan", json={"source": str(tmp_path)})
    assert resp.status_code == 409
