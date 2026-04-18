from __future__ import annotations

import uuid
from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class ScanRun(Base):
    __tablename__ = "scan_runs"

    # String(36) keeps us compatible with both SQLite (tests) and PostgreSQL
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target: Mapped[str] = mapped_column(String(1024))
    status: Mapped[str] = mapped_column(String(16), default="running")  # running | complete | error
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    files_ingested: Mapped[int] = mapped_column(Integer, default=0)
    files_ranked: Mapped[int] = mapped_column(Integer, default=0)
    findings_confirmed: Mapped[int] = mapped_column(Integer, default=0)

    findings: Mapped[list[Finding]] = relationship(back_populates="scan_run", lazy="select")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target": self.target,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "files_ingested": self.files_ingested,
            "files_ranked": self.files_ranked,
            "findings_confirmed": self.findings_confirmed,
        }


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_run_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_runs.id"))
    file_path: Mapped[str] = mapped_column(String(2048))
    line_hint: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bug_class: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text)
    exploit_input: Mapped[str] = mapped_column(Text)
    verifier_rationale: Mapped[str] = mapped_column(Text)
    oracle_output: Mapped[str] = mapped_column(Text)
    finding_hash: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    scan_run: Mapped[ScanRun] = relationship(back_populates="findings")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_run_id": self.scan_run_id,
            "file_path": self.file_path,
            "line_hint": self.line_hint,
            "bug_class": self.bug_class,
            "description": self.description,
            "exploit_input": self.exploit_input,
            "verifier_rationale": self.verifier_rationale,
            "oracle_output": self.oracle_output,
            "finding_hash": self.finding_hash,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
