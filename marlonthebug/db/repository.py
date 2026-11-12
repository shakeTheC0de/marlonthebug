"""Async repository pattern for database operations."""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from marlonthebug.db.models import (
    ExploitModel,
    FindingModel,
    ListenerModel,
    PivotModel,
    SessionModel,
    TargetModel,
    WorkspaceModel,
)

logger = logging.getLogger("marlonthebug.db")


class DatabaseRepository:
    def __init__(self, url: str = "sqlite+aiosqlite:///data/marlonthebug.db", echo: bool = False) -> None:
        self._engine = create_async_engine(url, echo=echo)
        self._session_factory = async_sessionmaker(
            self._engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )

    async def init(self) -> None:
        from marlonthebug.db.base import Base

        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database initialized")

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self._session_factory() as session:
            yield session

    async def close(self) -> None:
        await self._engine.dispose()

    async def create_workspace(self, name: str, **kwargs: object) -> WorkspaceModel:
        async with self.session() as s:
            ws = WorkspaceModel(name=name, **kwargs)
            s.add(ws)
            await s.commit()
            await s.refresh(ws)
            return ws

    async def get_workspace(self, workspace_id: str) -> WorkspaceModel | None:
        async with self.session() as s:
            return await s.get(WorkspaceModel, workspace_id)

    async def get_workspace_by_name(self, name: str) -> WorkspaceModel | None:
        async with self.session() as s:
            result = await s.execute(select(WorkspaceModel).where(WorkspaceModel.name == name))
            return result.scalar_one_or_none()

    async def list_workspaces(self) -> list[WorkspaceModel]:
        async with self.session() as s:
            result = await s.execute(select(WorkspaceModel).order_by(WorkspaceModel.created_at.desc()))
            return list(result.scalars().all())

    async def delete_workspace(self, workspace_id: str) -> bool:
        async with self.session() as s:
            ws = await s.get(WorkspaceModel, workspace_id)
            if not ws:
                return False
            await s.delete(ws)
            await s.commit()
            return True

    async def create_target(self, workspace_id: str, host: str, **kwargs: object) -> TargetModel:
        async with self.session() as s:
            target = TargetModel(workspace_id=workspace_id, host=host, **kwargs)
            s.add(target)
            await s.commit()
            await s.refresh(target)
            return target

    async def get_target(self, target_id: str) -> TargetModel | None:
        async with self.session() as s:
            return await s.get(TargetModel, target_id)

    async def get_targets_by_workspace(self, workspace_id: str) -> list[TargetModel]:
        async with self.session() as s:
            result = await s.execute(
                select(TargetModel).where(TargetModel.workspace_id == workspace_id)
            )
            return list(result.scalars().all())

    async def create_finding(self, **kwargs: object) -> FindingModel:
        async with self.session() as s:
            finding = FindingModel(**kwargs)
            s.add(finding)
            await s.commit()
            await s.refresh(finding)
            return finding

    async def get_findings_by_target(self, target_id: str) -> list[FindingModel]:
        async with self.session() as s:
            result = await s.execute(
                select(FindingModel).where(FindingModel.target_id == target_id).order_by(FindingModel.cvss_score.desc())
            )
            return list(result.scalars().all())

    async def get_findings_by_workspace(self, workspace_id: str) -> list[FindingModel]:
        async with self.session() as s:
            result = await s.execute(
                select(FindingModel)
                .join(TargetModel)
                .where(TargetModel.workspace_id == workspace_id)
                .order_by(FindingModel.cvss_score.desc())
            )
            return list(result.scalars().all())

    async def get_findings_by_severity(self, workspace_id: str, severity: str) -> list[FindingModel]:
        async with self.session() as s:
            result = await s.execute(
                select(FindingModel)
                .join(TargetModel)
                .where(
                    TargetModel.workspace_id == workspace_id,
                    FindingModel.severity == severity,
                )
                .order_by(FindingModel.cvss_score.desc())
            )
            return list(result.scalars().all())

    async def update_finding(self, finding_id: str, **kwargs: object) -> FindingModel | None:
        async with self.session() as s:
            finding = await s.get(FindingModel, finding_id)
            if not finding:
                return None
            for key, value in kwargs.items():
                setattr(finding, key, value)
            await s.commit()
            await s.refresh(finding)
            return finding

    async def create_exploit(self, **kwargs: object) -> ExploitModel:
        async with self.session() as s:
            exploit = ExploitModel(**kwargs)
            s.add(exploit)
            await s.commit()
            await s.refresh(exploit)
            return exploit

    async def create_listener(self, **kwargs: object) -> ListenerModel:
        async with self.session() as s:
            listener = ListenerModel(**kwargs)
            s.add(listener)
            await s.commit()
            await s.refresh(listener)
            return listener

    async def get_active_listeners(self) -> list[ListenerModel]:
        async with self.session() as s:
            result = await s.execute(
                select(ListenerModel).where(ListenerModel.status == "running")
            )
            return list(result.scalars().all())

    async def create_session(self, **kwargs: object) -> SessionModel:
        async with self.session() as s:
            session_obj = SessionModel(**kwargs)
            s.add(session_obj)
            await s.commit()
            await s.refresh(session_obj)
            return session_obj

    async def get_active_sessions(self) -> list[SessionModel]:
        async with self.session() as s:
            result = await s.execute(
                select(SessionModel).where(SessionModel.active == True)
            )
            return list(result.scalars().all())

    async def deactivate_session(self, session_id: str) -> SessionModel | None:
        from datetime import datetime, timezone

        async with self.session() as s:
            session_obj = await s.get(SessionModel, session_id)
            if not session_obj:
                return None
            session_obj.active = False
            session_obj.disconnected_at = datetime.now(timezone.utc)
            await s.commit()
            await s.refresh(session_obj)
            return session_obj

    async def create_pivot(self, **kwargs: object) -> PivotModel:
        async with self.session() as s:
            pivot = PivotModel(**kwargs)
            s.add(pivot)
            await s.commit()
            await s.refresh(pivot)
            return pivot

    async def get_targets_count(self, workspace_id: str) -> int:
        async with self.session() as s:
            result = await s.execute(
                select(TargetModel).where(TargetModel.workspace_id == workspace_id)
            )
            return len(list(result.scalars().all()))

    async def stats(self, workspace_id: str) -> dict[str, int]:
        async with self.session() as s:
            targets_result = await s.execute(
                select(TargetModel).where(TargetModel.workspace_id == workspace_id)
            )
            targets = list(targets_result.scalars().all())
            target_ids = [t.id for t in targets]

            findings_count = 0
            severity_counts: dict[str, int] = {}
            for tid in target_ids:
                result = await s.execute(select(FindingModel).where(FindingModel.target_id == tid))
                for f in result.scalars().all():
                    findings_count += 1
                    severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

            return {
                "targets": len(targets),
                "findings": findings_count,
                **severity_counts,
            }
