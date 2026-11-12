"""Async event bus for inter-module communication."""

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable


class EventType(str, Enum):
    TARGET_DISCOVERED = "target:discovered"
    TARGET_UPDATED = "target:updated"
    FINDING_CREATED = "finding:created"
    FINDING_VERIFIED = "finding:verified"
    SCAN_STARTED = "scan:started"
    SCAN_COMPLETED = "scan:completed"
    SCAN_ERROR = "scan:error"
    PLUGIN_STARTED = "plugin:started"
    PLUGIN_COMPLETED = "plugin:completed"
    PLUGIN_ERROR = "plugin:error"
    EXPLOIT_STARTED = "exploit:started"
    EXPLOIT_SUCCESS = "exploit:success"
    EXPLOIT_FAILED = "exploit:failed"
    SESSION_OPENED = "session:opened"
    SESSION_CLOSED = "session:closed"
    LISTENER_STARTED = "listener:started"
    LISTENER_STOPPED = "listener:stopped"
    COLLABORATOR_CALLBACK = "collaborator:callback"
    WILD = "*"


@dataclass
class Event:
    type: EventType
    source: str
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


Handler = Callable[[Event], Awaitable[None]]


class EventBus:
    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = defaultdict(list)
        self._queue: asyncio.Queue[Event] = asyncio.Queue()
        self._running = False
        self._task: asyncio.Task[None] | None = None

    def subscribe(self, event_type: EventType | str, handler: Handler) -> None:
        key = event_type if isinstance(event_type, str) else event_type.value
        self._handlers[key].append(handler)

    def unsubscribe(self, event_type: EventType | str, handler: Handler) -> None:
        key = str(event_type)
        if handler in self._handlers[key]:
            self._handlers[key].remove(handler)

    async def emit(self, event: Event) -> None:
        await self._queue.put(event)

    async def emit_now(self, event: Event) -> None:
        await self._dispatch(event)

    async def _dispatch(self, event: Event) -> None:
        handlers = self._handlers.get(event.type.value, []) + self._handlers.get("*", [])

        async def handle(h: Handler) -> None:
            try:
                await h(event)
            except Exception:
                import logging

                logging.getLogger("marlonthebug").exception(
                    "Error in event handler %s for %s", h.__name__, event.type.value
                )

        results = await asyncio.gather(*(handle(h) for h in handlers), return_exceptions=True)

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._processor())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _processor(self) -> None:
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=0.5)
                await self._dispatch(event)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
