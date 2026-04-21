from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventType(str, Enum):
    SCAN_STARTED = "scan_started"
    INGESTION_COMPLETE = "ingestion_complete"
    RANKING_COMPLETE = "ranking_complete"
    FILE_STARTED = "file_started"
    FINDING = "finding"
    VERIFIED = "verified"
    DISCARDED = "discarded"
    ORACLE_RESULT = "oracle_result"
    SCAN_COMPLETE = "scan_complete"
    ERROR = "error"


@dataclass
class PipelineEvent:
    type: EventType
    data: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class PipelineTracker:
    """Broadcast event bus. Consumers call subscribe() to get a per-client Queue."""

    def __init__(self) -> None:
        self._queues: list[asyncio.Queue] = []
        self.stats: dict[str, Any] = {
            "files_ingested": 0,
            "files_ranked": 0,
            "active_agents": 0,
            "findings_raw": 0,
            "findings_verified": 0,
            "findings_confirmed": 0,
            "scan_started_at": None,
            "scan_complete": False,
            "target": "",
        }

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._queues.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        try:
            self._queues.remove(q)
        except ValueError:
            pass

    async def emit(self, event: PipelineEvent) -> None:
        self._update_stats(event)
        for q in list(self._queues):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass  # slow consumer — drop rather than block the pipeline

    def _update_stats(self, event: PipelineEvent) -> None:
        t = event.type
        if t == EventType.SCAN_STARTED:
            self.stats["scan_started_at"] = event.timestamp
            self.stats["target"] = event.data.get("target", "")
        elif t == EventType.INGESTION_COMPLETE:
            self.stats["files_ingested"] = event.data.get("count", 0)
        elif t == EventType.RANKING_COMPLETE:
            self.stats["files_ranked"] = event.data.get("count", 0)
        elif t == EventType.FILE_STARTED:
            self.stats["active_agents"] += 1
        elif t == EventType.FINDING:
            self.stats["findings_raw"] += 1
        elif t == EventType.VERIFIED:
            self.stats["findings_verified"] += 1
            self.stats["active_agents"] = max(0, self.stats["active_agents"] - 1)
        elif t == EventType.DISCARDED:
            self.stats["active_agents"] = max(0, self.stats["active_agents"] - 1)
        elif t == EventType.ORACLE_RESULT:
            if event.data.get("status") in ("crashed", "skipped", "compile_error"):
                self.stats["findings_confirmed"] += 1
        elif t == EventType.SCAN_COMPLETE:
            self.stats["scan_complete"] = True
            self.stats["active_agents"] = 0
