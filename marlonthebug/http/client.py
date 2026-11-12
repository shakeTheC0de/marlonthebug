"""Async HTTP client — httpx wrapper with retry, timeout, and session management."""

import asyncio
import logging
import random
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import httpx

from marlonthebug.core.scope import ScopeGuard

logger = logging.getLogger("marlonthebug.http")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
]


@dataclass
class HttpResponse:
    status_code: int
    headers: dict[str, str]
    body: str
    content_length: int
    elapsed: float
    url: str
    redirect_chain: list[str]
    title: str = ""


class AsyncHTTPClient:
    def __init__(
        self,
        timeout: float = 10.0,
        retries: int = 3,
        backoff: float = 2.0,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        user_agent: str | None = None,
        scope_guard: ScopeGuard | None = None,
    ) -> None:
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self._user_agent = user_agent
        self._scope_guard = scope_guard
        self._client: httpx.AsyncClient | None = None

    def random_user_agent(self) -> str:
        return self._user_agent or random.choice(USER_AGENTS)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            transport = httpx.AsyncHTTPTransport(retries=0)
            self._client = httpx.AsyncClient(
                transport=transport,
                timeout=httpx.Timeout(self.timeout),
                verify=self.verify_ssl,
                follow_redirects=self.follow_redirects,
                max_redirects=self.max_redirects,
                headers={"User-Agent": self.random_user_agent()},
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def _request(
        self,
        method: str,
        url: str,
        **kwargs: object,
    ) -> HttpResponse:
        if self._scope_guard:
            parsed = urlparse(url)
            target = parsed.hostname or parsed.netloc.split(":")[0]
            if target and not self._scope_guard.check(target):
                raise ValueError(f"Target {target} is out of scope")

        client = await self._get_client()
        last_error: Exception | None = None

        for attempt in range(self.retries + 1):
            try:
                response = await client.request(method, url, **kwargs)
                return HttpResponse(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=response.text,
                    content_length=len(response.content),
                    elapsed=response.elapsed.total_seconds(),
                    url=str(response.url),
                    redirect_chain=[str(h.url) for h in response.history],
                )
            except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as e:
                last_error = e
                if attempt < self.retries:
                    delay = self.backoff * (2 ** attempt) + random.uniform(0, 0.5)
                    logger.debug("Request to %s failed (attempt %d/%d), retrying in %.1fs: %s",
                                 url, attempt + 1, self.retries, delay, e)
                    await asyncio.sleep(delay)
                else:
                    raise

        raise RuntimeError(f"Request failed after {self.retries} retries: {last_error}")

    async def get(self, url: str, **kwargs: object) -> HttpResponse:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: object) -> HttpResponse:
        return await self._request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: object) -> HttpResponse:
        return await self._request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: object) -> HttpResponse:
        return await self._request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs: object) -> HttpResponse:
        return await self._request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: object) -> HttpResponse:
        return await self._request("OPTIONS", url, **kwargs)

    async def patch(self, url: str, **kwargs: object) -> HttpResponse:
        return await self._request("PATCH", url, **kwargs)

    async def probe(self, url: str) -> HttpResponse | None:
        try:
            client = await self._get_client()
            response = await client.head(url, follow_redirects=True)
            return HttpResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body="",
                content_length=0,
                elapsed=response.elapsed.total_seconds(),
                url=str(response.url),
                redirect_chain=[str(h.url) for h in response.history],
            )
        except Exception:
            return None
