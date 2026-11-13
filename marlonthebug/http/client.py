"""Async HTTP client with scope enforcement, shared scan connections and retries."""

from __future__ import annotations

import asyncio
import logging
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from marlonthebug.core.context import get_scan_context
from marlonthebug.core.scope import ScopeGuard, ScopeViolation
from marlonthebug.exploit.trace import get_trace

logger = logging.getLogger("marlonthebug.http")

USER_AGENTS = [
    "MarlonTheBug/2.0 (authorized security assessment)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class ScanBudgetExceeded(RuntimeError):  # noqa: N818
    """Raised when a scan reaches its configured request budget."""


@dataclass
class HttpResponse:
    status_code: int
    headers: dict[str, str]
    body: str
    content_length: int
    elapsed: float
    url: str
    redirect_chain: list[str] = field(default_factory=list)
    title: str = ""

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").lower()

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type or "<html" in self.body[:500].lower()

    @property
    def is_json(self) -> bool:
        return "json" in self.content_type or self.body.lstrip().startswith(("{", "["))

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


class AsyncHTTPClient:
    def __init__(
        self,
        timeout: float = 10.0,
        retries: int = 2,
        backoff: float = 1.5,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        user_agent: str | None = None,
        scope_guard: ScopeGuard | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> None:
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self._user_agent = user_agent
        self._scope_guard = scope_guard
        self._headers = headers or {}
        self._cookies = cookies or {}
        self._client: httpx.AsyncClient | None = None
        self._owns_client = True
        self._context = get_scan_context()
        if self._context:
            self._owns_client = False

    def random_user_agent(self) -> str:
        return self._user_agent or random.choice(USER_AGENTS)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._context:
            return self._context.http_client
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                verify=self.verify_ssl,
                follow_redirects=self.follow_redirects,
                max_redirects=self.max_redirects,
                headers={"User-Agent": self.random_user_agent(), **self._headers},
                cookies=self._cookies,
            )
        return self._client

    async def close(self) -> None:
        if self._owns_client and self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    def _check_scope(self, url: str) -> None:
        if self._context:
            self._context.scope_guard.require(url)
        elif self._scope_guard:
            parsed = urlparse(url)
            host = parsed.hostname or parsed.netloc.split(":")[0]
            if host and not self._scope_guard.check(host):
                raise ScopeViolation(f"Target out of scope: {host}")

    async def _request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
        self._check_scope(url)

        if self._context:
            if self._context.budget_exhausted:
                raise ScanBudgetExceeded(f"Request budget of {self._context.max_requests} exhausted")
            if self._context.should_stop.is_set():
                raise asyncio.CancelledError("Scan cancelled")
            await self._context.rate_limiter.acquire(url)

        client = await self._get_client()
        last_error: Exception | None = None

        for attempt in range(self.retries + 1):
            started = time.monotonic()
            trace = get_trace()
            trace_step = trace.start_request(method, url, kwargs) if trace else None
            try:
                response = await client.request(method, url, **kwargs)
                elapsed = time.monotonic() - started
                body = response.text
                match = _TITLE_RE.search(body)
                title = re.sub(r"\s+", " ", match.group(1)).strip()[:200] if match else ""
                result = HttpResponse(
                    status_code=response.status_code,
                    headers={key.lower(): value for key, value in response.headers.items()},
                    body=body,
                    content_length=len(response.content),
                    elapsed=elapsed,
                    url=str(response.url),
                    redirect_chain=[str(item.url) for item in response.history],
                    title=title,
                )
                if trace and trace_step is not None:
                    trace.finish_request(trace_step, result, elapsed)
                if self._context:
                    await self._context.record(
                        method, str(response.url), result.status_code, result.content_length, elapsed
                    )
                return result
            except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as exc:
                last_error = exc
                if trace and trace_step is not None:
                    trace.fail_request(trace_step, exc)
                if self._context:
                    self._context.error_count += 1
                if attempt < self.retries:
                    delay = self.backoff * (2**attempt) + random.uniform(0, 0.4)
                    logger.debug("Retrying %s in %.1fs: %s", url, delay, exc)
                    await asyncio.sleep(delay)

        raise RuntimeError(f"Request failed after {self.retries} retries: {last_error}")

    async def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
        return await self._request(method, url, **kwargs)

    async def get(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self._request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self._request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self._request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self._request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self._request("OPTIONS", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self._request("PATCH", url, **kwargs)

    async def probe(self, url: str) -> HttpResponse | None:
        try:
            return await self.head(url)
        except Exception:
            return None
