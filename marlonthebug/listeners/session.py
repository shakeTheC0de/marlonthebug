"""Exploitation session management — tracks active shells and provides I/O interface."""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

logger = logging.getLogger("marlonthebug.listeners")


@dataclass
class Session:
    id: str
    target: str = ""
    session_type: str = "shell"
    user: str = ""
    hostname: str = ""
    platform: str = ""
    connected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    disconnected_at: datetime | None = None
    active: bool = True
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    via: str = ""
    metadata: dict = field(default_factory=dict)


class SessionManager:
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return str(self._counter)

    def create(
        self,
        reader: asyncio.StreamReader | None = None,
        writer: asyncio.StreamWriter | None = None,
        target: str = "",
        session_type: str = "shell",
        via: str = "",
    ) -> Session:
        session = Session(
            id=self._next_id(),
            target=target,
            session_type=session_type,
            via=via,
            reader=reader,
            writer=writer,
        )
        self._sessions[session.id] = session
        logger.info("[Session] Created %s on %s (ID: %s)", session_type, target, session.id)
        return session

    def get(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)

    def list_active(self) -> list[Session]:
        return [s for s in self._sessions.values() if s.active]

    def deactivate(self, session_id: str) -> None:
        session = self._sessions.get(session_id)
        if session:
            session.active = False
            session.disconnected_at = datetime.now(UTC)
            if session.writer and not session.writer.is_closing():
                session.writer.close()
            logger.info("[Session] Closed %s", session_id)

    async def send(self, session_id: str, command: str) -> str | None:
        session = self._sessions.get(session_id)
        if not session or not session.active or not session.writer:
            return None

        try:
            session.writer.write((command + "\n").encode())
            await session.writer.drain()

            if session.reader:
                response = await asyncio.wait_for(session.reader.read(65536), timeout=10)
                return response.decode("utf-8", errors="replace")
            return None
        except Exception as e:
            logger.warning("Session %s send error: %s", session_id, e)
            return None

    async def close_all(self) -> None:
        for session in list(self._sessions.values()):
            self.deactivate(session.id)
        self._sessions.clear()
