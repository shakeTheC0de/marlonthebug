"""HTTP session pool — per-target cookie jars and connection reuse."""

import logging

import httpx

logger = logging.getLogger("marlonthebug.http")


class SessionPool:
    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        max_sessions: int = 50,
    ) -> None:
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.max_sessions = max_sessions
        self._sessions: dict[str, httpx.AsyncClient] = {}
        self._global_client: httpx.AsyncClient | None = None

    async def get_client(self, host: str, cookie_jar: httpx.Cookies | None = None) -> httpx.AsyncClient:
        if host not in self._sessions:
            if len(self._sessions) >= self.max_sessions:
                oldest = next(iter(self._sessions))
                await self._sessions[oldest].aclose()
                del self._sessions[oldest]

            self._sessions[host] = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                verify=self.verify_ssl,
                follow_redirects=self.follow_redirects,
                cookies=cookie_jar,
            )
        return self._sessions[host]

    async def get_global(self) -> httpx.AsyncClient:
        if self._global_client is None or self._global_client.is_closed:
            self._global_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                verify=self.verify_ssl,
                follow_redirects=self.follow_redirects,
            )
        return self._global_client

    async def set_cookies(self, host: str, cookies: dict[str, str]) -> None:
        client = await self.get_client(host)
        for name, value in cookies.items():
            client.cookies.set(name, value, domain=host)

    async def clear(self, host: str) -> None:
        if host in self._sessions:
            await self._sessions[host].aclose()
            del self._sessions[host]

    async def close_all(self) -> None:
        for _host, client in self._sessions.items():
            await client.aclose()
        self._sessions.clear()
        if self._global_client:
            await self._global_client.aclose()
            self._global_client = None
