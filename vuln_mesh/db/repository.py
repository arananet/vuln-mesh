from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Finding, ScanRun


class ScanRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_scan(self, target: str) -> ScanRun:
        scan = ScanRun(target=target, started_at=datetime.now(timezone.utc))
        self.session.add(scan)
        await self.session.commit()
        await self.session.refresh(scan)
        return scan

    async def complete_scan(
        self,
        scan_id: str,
        files_ingested: int,
        files_ranked: int,
        findings_confirmed: int,
    ) -> None:
        scan = await self.session.get(ScanRun, scan_id)
        if scan:
            scan.status = "complete"
            scan.completed_at = datetime.now(timezone.utc)
            scan.files_ingested = files_ingested
            scan.files_ranked = files_ranked
            scan.findings_confirmed = findings_confirmed
            await self.session.commit()

    async def fail_scan(self, scan_id: str) -> None:
        scan = await self.session.get(ScanRun, scan_id)
        if scan:
            scan.status = "error"
            scan.completed_at = datetime.now(timezone.utc)
            await self.session.commit()

    async def add_finding(
        self,
        scan_id: str,
        file_path: str,
        line_hint: int | None,
        bug_class: str,
        description: str,
        exploit_input: str,
        verifier_rationale: str,
        oracle_output: str,
        finding_hash: str,
    ) -> Finding:
        f = Finding(
            scan_run_id=scan_id,
            file_path=file_path,
            line_hint=line_hint,
            bug_class=bug_class,
            description=description,
            exploit_input=exploit_input,
            verifier_rationale=verifier_rationale,
            oracle_output=oracle_output,
            finding_hash=finding_hash,
            created_at=datetime.now(timezone.utc),
        )
        self.session.add(f)
        await self.session.commit()
        return f

    async def list_scans(self, limit: int = 20, offset: int = 0) -> list[ScanRun]:
        result = await self.session.execute(
            select(ScanRun).order_by(ScanRun.started_at.desc()).limit(limit).offset(offset)
        )
        return list(result.scalars().all())

    async def get_scan(self, scan_id: str) -> ScanRun | None:
        return await self.session.get(ScanRun, scan_id)

    async def get_findings(self, scan_id: str) -> list[Finding]:
        result = await self.session.execute(
            select(Finding).where(Finding.scan_run_id == scan_id)
        )
        return list(result.scalars().all())
