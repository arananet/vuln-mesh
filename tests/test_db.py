"""
DB repository tests — run against an in-memory SQLite database via aiosqlite.

SQLite doesn't support timezone-aware datetimes natively; the models use
DateTime(timezone=True) which SQLAlchemy strips to naive UTC for SQLite.
Tests stay agnostic to tzinfo presence.
"""
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from vuln_mesh.db.models import Base
from vuln_mesh.db.repository import ScanRepository
from vuln_mesh.db.session import _build_url, get_session_factory, reset_singletons


# ── Fixtures ───────────────────────────────────────────────

@pytest.fixture
async def session() -> AsyncSession:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest.fixture
def repo(session: AsyncSession) -> ScanRepository:
    return ScanRepository(session)


# ── _build_url ─────────────────────────────────────────────

def test_build_url_rewrites_postgres_prefix():
    assert _build_url("postgres://u:p@host/db") == "postgresql+asyncpg://u:p@host/db"


def test_build_url_rewrites_postgresql_prefix():
    assert _build_url("postgresql://u:p@host/db") == "postgresql+asyncpg://u:p@host/db"


def test_build_url_leaves_asyncpg_url_unchanged():
    url = "postgresql+asyncpg://u:p@host/db"
    assert _build_url(url) == url


# ── Session factory ────────────────────────────────────────

def test_get_session_factory_returns_none_without_env(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    reset_singletons()
    assert get_session_factory() is None
    reset_singletons()


# ── ScanRepository ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_scan_inserts_row(repo: ScanRepository):
    scan = await repo.create_scan("/src/target")
    assert scan.id is not None
    assert scan.target == "/src/target"
    assert scan.status == "running"
    assert scan.started_at is not None


@pytest.mark.asyncio
async def test_complete_scan_updates_status(repo: ScanRepository):
    scan = await repo.create_scan("/src")
    await repo.complete_scan(scan.id, files_ingested=10, files_ranked=5, findings_confirmed=2)
    updated = await repo.get_scan(scan.id)
    assert updated.status == "complete"
    assert updated.files_ingested == 10
    assert updated.files_ranked == 5
    assert updated.findings_confirmed == 2
    assert updated.completed_at is not None


@pytest.mark.asyncio
async def test_fail_scan_sets_error_status(repo: ScanRepository):
    scan = await repo.create_scan("/src")
    await repo.fail_scan(scan.id)
    updated = await repo.get_scan(scan.id)
    assert updated.status == "error"
    assert updated.completed_at is not None


@pytest.mark.asyncio
async def test_add_finding_links_to_scan(repo: ScanRepository):
    scan = await repo.create_scan("/src")
    finding = await repo.add_finding(
        scan_id=scan.id,
        file_path="/src/vuln.c",
        line_hint=42,
        bug_class="buffer_overflow",
        description="Classic stack smash",
        exploit_input="A" * 512,
        verifier_rationale="Confirmed unbounded strcpy",
        oracle_output="ASAN: heap-buffer-overflow",
        finding_hash="abc123",
    )
    assert finding.id is not None
    assert finding.scan_run_id == scan.id
    assert finding.bug_class == "buffer_overflow"
    assert finding.finding_hash == "abc123"


@pytest.mark.asyncio
async def test_list_scans_returns_ordered_by_started_at_desc(repo: ScanRepository):
    a = await repo.create_scan("/a")
    b = await repo.create_scan("/b")
    scans = await repo.list_scans()
    ids = [s.id for s in scans]
    assert ids.index(b.id) < ids.index(a.id)


@pytest.mark.asyncio
async def test_get_scan_returns_none_for_unknown_id(repo: ScanRepository):
    result = await repo.get_scan("does-not-exist")
    assert result is None


@pytest.mark.asyncio
async def test_get_findings_returns_findings_for_scan(repo: ScanRepository):
    scan = await repo.create_scan("/src")
    await repo.add_finding(scan.id, "/f.c", None, "uaf", "desc", "", "", "", "h1")
    await repo.add_finding(scan.id, "/g.c", None, "fsb", "desc", "", "", "", "h2")
    findings = await repo.get_findings(scan.id)
    assert len(findings) == 2
    hashes = {f.finding_hash for f in findings}
    assert hashes == {"h1", "h2"}


@pytest.mark.asyncio
async def test_get_findings_returns_empty_for_unknown_scan(repo: ScanRepository):
    findings = await repo.get_findings("no-such-scan")
    assert findings == []
