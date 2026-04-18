from __future__ import annotations

import os
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

_engine: AsyncEngine | None = None
_factory: async_sessionmaker[AsyncSession] | None = None


def _build_url(raw: str) -> str:
    """Normalise Railway / standard postgres URLs to asyncpg driver format."""
    for prefix in ("postgres://", "postgresql://"):
        if raw.startswith(prefix):
            return "postgresql+asyncpg://" + raw[len(prefix):]
    return raw  # already has driver prefix


def get_engine() -> AsyncEngine | None:
    global _engine
    if _engine is None:
        raw = os.environ.get("DATABASE_URL", "")
        if raw:
            _engine = create_async_engine(_build_url(raw), echo=False, pool_pre_ping=True)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession] | None:
    global _factory
    if _factory is None:
        engine = get_engine()
        if engine:
            _factory = async_sessionmaker(engine, expire_on_commit=False)
    return _factory


def reset_singletons() -> None:
    """Test helper — clears module-level singletons so tests can inject a custom engine."""
    global _engine, _factory
    _engine = None
    _factory = None
