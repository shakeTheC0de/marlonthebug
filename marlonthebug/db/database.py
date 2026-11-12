"""Async database bootstrap with SQLite-friendly defaults."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from marlonthebug.db.models import Base

logger = logging.getLogger("marlonthebug.db")


def sqlite_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path}"


class Database:
    def __init__(
        self,
        url: str,
        *,
        echo: bool = False,
        portable: bool = False,
    ) -> None:
        self.url = url
        self.portable = portable
        connect_args = {"check_same_thread": False, "timeout": 30}
        self.engine = create_async_engine(
            url,
            echo=echo,
            connect_args=connect_args if url.startswith("sqlite") else {},
        )
        self.session_factory = async_sessionmaker(
            self.engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )
        if url.startswith("sqlite"):
            event.listen(self.engine.sync_engine, "connect", self._configure_sqlite)

    def _configure_sqlite(self, dbapi_connection, _record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=30000")
        journal_mode = "DELETE" if self.portable else "WAL"
        cursor.execute(f"PRAGMA journal_mode={journal_mode}")
        cursor.close()

    async def init(self) -> None:
        try:
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        except Exception as exc:
            # Two local processes (panel + CLI) can race during first launch.
            if "already exists" not in str(exc).lower():
                raise
        logger.info("Database ready: %s", self.url)

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def close(self) -> None:
        await self.engine.dispose()

    async def ping(self) -> bool:
        try:
            async with self.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False
