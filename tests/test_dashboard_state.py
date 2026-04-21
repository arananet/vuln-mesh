import asyncio
import pytest

from vuln_mesh.dashboard.state import EventType, PipelineEvent, PipelineTracker


@pytest.mark.asyncio
async def test_emit_delivers_to_subscriber():
    tracker = PipelineTracker()
    q = tracker.subscribe()
    event = PipelineEvent(EventType.SCAN_STARTED, {"target": "/tmp/test"})
    await tracker.emit(event)
    received = q.get_nowait()
    assert received.type == EventType.SCAN_STARTED
    assert received.data["target"] == "/tmp/test"


@pytest.mark.asyncio
async def test_emit_delivers_to_multiple_subscribers():
    tracker = PipelineTracker()
    q1 = tracker.subscribe()
    q2 = tracker.subscribe()
    await tracker.emit(PipelineEvent(EventType.FINDING, {"bug_class": "buffer-overflow"}))
    assert q1.qsize() == 1
    assert q2.qsize() == 1


@pytest.mark.asyncio
async def test_full_queue_does_not_block():
    tracker = PipelineTracker()
    q = tracker.subscribe()
    # Fill the queue
    for _ in range(q.maxsize):
        q.put_nowait(PipelineEvent(EventType.FINDING, {}))
    # This should not raise or block
    await tracker.emit(PipelineEvent(EventType.FINDING, {"overflow": True}))
    assert q.full()


@pytest.mark.asyncio
async def test_unsubscribe_removes_queue():
    tracker = PipelineTracker()
    q = tracker.subscribe()
    tracker.unsubscribe(q)
    await tracker.emit(PipelineEvent(EventType.FINDING, {}))
    assert q.qsize() == 0  # not delivered after unsubscribe


@pytest.mark.asyncio
async def test_stats_update_scan_started():
    tracker = PipelineTracker()
    await tracker.emit(PipelineEvent(EventType.SCAN_STARTED, {"target": "/src"}))
    assert tracker.stats["target"] == "/src"
    assert tracker.stats["scan_started_at"] is not None


@pytest.mark.asyncio
async def test_stats_update_ingestion_complete():
    tracker = PipelineTracker()
    await tracker.emit(PipelineEvent(EventType.INGESTION_COMPLETE, {"count": 42}))
    assert tracker.stats["files_ingested"] == 42


@pytest.mark.asyncio
async def test_stats_update_ranking_complete():
    tracker = PipelineTracker()
    await tracker.emit(PipelineEvent(EventType.RANKING_COMPLETE, {"count": 20}))
    assert tracker.stats["files_ranked"] == 20


@pytest.mark.asyncio
async def test_stats_active_agents_increment_decrement():
    tracker = PipelineTracker()
    await tracker.emit(PipelineEvent(EventType.FILE_STARTED, {"path": "a.c"}))
    await tracker.emit(PipelineEvent(EventType.FILE_STARTED, {"path": "b.c"}))
    assert tracker.stats["active_agents"] == 2
    await tracker.emit(PipelineEvent(EventType.VERIFIED, {"path": "a.c", "bug_class": "bo"}))
    assert tracker.stats["active_agents"] == 1
    await tracker.emit(PipelineEvent(EventType.DISCARDED, {"path": "b.c"}))
    assert tracker.stats["active_agents"] == 0


@pytest.mark.asyncio
async def test_stats_findings_counters():
    tracker = PipelineTracker()
    await tracker.emit(PipelineEvent(EventType.FINDING, {}))
    await tracker.emit(PipelineEvent(EventType.FINDING, {}))
    assert tracker.stats["findings_raw"] == 2
    await tracker.emit(PipelineEvent(EventType.VERIFIED, {"path": "f.c", "bug_class": "bo"}))
    assert tracker.stats["findings_verified"] == 1


@pytest.mark.asyncio
async def test_stats_oracle_confirmed():
    tracker = PipelineTracker()
    await tracker.emit(PipelineEvent(EventType.ORACLE_RESULT, {"status": "crashed", "path": "f.c"}))
    assert tracker.stats["findings_confirmed"] == 1
    await tracker.emit(PipelineEvent(EventType.ORACLE_RESULT, {"status": "clean", "path": "g.c"}))
    assert tracker.stats["findings_confirmed"] == 1  # clean doesn't increment


@pytest.mark.asyncio
async def test_stats_oracle_skipped_counts_as_confirmed():
    tracker = PipelineTracker()
    await tracker.emit(PipelineEvent(EventType.ORACLE_RESULT, {"status": "skipped", "path": "app.js"}))
    assert tracker.stats["findings_confirmed"] == 1


@pytest.mark.asyncio
async def test_stats_oracle_compile_error_counts_as_confirmed():
    tracker = PipelineTracker()
    await tracker.emit(PipelineEvent(EventType.ORACLE_RESULT, {"status": "compile_error", "path": "x.c"}))
    assert tracker.stats["findings_confirmed"] == 1


@pytest.mark.asyncio
async def test_stats_scan_complete():
    tracker = PipelineTracker()
    await tracker.emit(PipelineEvent(EventType.FILE_STARTED, {"path": "x.c"}))
    await tracker.emit(PipelineEvent(EventType.SCAN_COMPLETE, {"confirmed": 0}))
    assert tracker.stats["scan_complete"] is True
    assert tracker.stats["active_agents"] == 0
