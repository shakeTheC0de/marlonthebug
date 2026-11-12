"""Per-scan application context shared by HTTP clients and plugins."""

from __future__ import annotations

import asyncio
import contextvars
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from marlonthebug.core.scope import ScopeConfig, ScopeGuard
from marlonthebug.http.rate import HostRateLimiter

logger = logging.getLogger("marlonthebug.context")

LogCallback = Callable[[str, str], Awaitable[None]]

_current_context: contextvars.ContextVar[ScanContext | None] = contextvars.ContextVar(
    "marlonthebug_scan_context", default=None
)


def get_scan_context() -> ScanContext | None:
    return _current_context.get()


def set_scan_context(context: ScanContext) -> contextvars.Token:
    return _current_context.set(context)


def reset_scan_context(token: contextvars.Token) -> None:
    _current_context.reset(token)


@dataclass
class RequestRecord:
    method: str
    url: str
    status: int
    length: int
    elapsed: float
    at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def as_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "length": self.length,
            "elapsed": round(self.elapsed, 3),
            "at": self.at.isoformat(),
        }


@dataclass
class ScanContext:
    scan_id: str
    workspace_id: str
    workspace_name: str
    scope: ScopeConfig
    http_client: httpx.AsyncClient
    rate_limiter: HostRateLimiter
    options: dict[str, Any] = field(default_factory=dict)
    endpoints: list[str] = field(default_factory=list)
    baseline: Any = None
    log_callback: LogCallback | None = None
    max_requests: int = 2500
    request_count: int = 0
    error_count: int = 0
    finding_count: int = 0
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    records: list[RequestRecord] = field(default_factory=list)
    should_stop: asyncio.Event = field(default_factory=asyncio.Event)
    discovered_hosts: set[str] = field(default_factory=set)

    @property
    def scope_guard(self) -> ScopeGuard:
        return ScopeGuard(self.scope)

    @property
    def elapsed(self) -> float:
        return (datetime.now(UTC) - self.started_at).total_seconds()

    @property
    def budget_exhausted(self) -> bool:
        return self.max_requests > 0 and self.request_count >= self.max_requests

    async def log(self, level: str, message: str) -> None:
        if self.log_callback:
            await self.log_callback(level, message)
        else:
            getattr(logger, level.lower(), logger.info)(message)

    async def record(
        self,
        method: str,
        url: str,
        status: int,
        length: int,
        elapsed: float,
    ) -> None:
        self.request_count += 1
        record = RequestRecord(method=method, url=url, status=status, length=length, elapsed=elapsed)
        self.records.append(record)
        if len(self.records) > 250:
            self.records = self.records[-250:]

    def cancel(self) -> None:
        self.should_stop.set()

    @classmethod
    async def create(
        cls,
        *,
        scan_id: str,
        workspace_id: str,
        workspace_name: str,
        scope: ScopeConfig,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        user_agent: str = "MarlonTheBug/2.0",
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        proxy: str | None = None,
        requests_per_second: float = 8.0,
        max_requests: int = 2500,
        options: dict[str, Any] | None = None,
        log_callback: LogCallback | None = None,
    ) -> ScanContext:
        request_headers = {"User-Agent": user_agent, "Accept": "*/*"}
        if headers:
            request_headers.update({str(k): str(v) for k, v in headers.items()})
        client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            verify=verify_ssl,
            follow_redirects=follow_redirects,
            max_redirects=max_redirects,
            headers=request_headers,
            cookies=cookies or {},
            proxy=proxy or None,
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        )
        return cls(
            scan_id=scan_id,
            workspace_id=workspace_id,
            workspace_name=workspace_name,
            scope=scope,
            http_client=client,
            rate_limiter=HostRateLimiter(requests_per_second),
            options=options or {},
            max_requests=max_requests,
            log_callback=log_callback,
        )

    async def close(self) -> None:
        await self.http_client.aclose()

    def stats(self) -> dict[str, Any]:
        return {
            "requests": self.request_count,
            "errors": self.error_count,
            "findings": self.finding_count,
            "duration": round(self.elapsed, 2),
            "started_at": self.started_at.isoformat(),
            "finished_at": datetime.now(UTC).isoformat(),
            "budget": self.max_requests,
        }


class Stopwatch:
    def __init__(self) -> None:
        self._start = time.monotonic()

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start
