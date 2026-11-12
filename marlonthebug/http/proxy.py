"""Proxy rotation — SOCKS5 and HTTP proxy support."""

import logging
import random
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("marlonthebug.http.proxy")


@dataclass
class Proxy:
    type: str
    host: str
    port: int
    username: str | None = None
    password: str | None = None

    @property
    def url(self) -> str:
        auth = f"{self.username}:{self.password}@" if self.username else ""
        return f"{self.type}://{auth}{self.host}:{self.port}"

    @property
    def httpx_url(self) -> str:
        return self.url if self.type.startswith("http") else f"http://{self.host}:{self.port}"


class ProxyManager:
    def __init__(self) -> None:
        self._proxies: list[Proxy] = []
        self._current_idx = -1
        self._enabled = False

    @property
    def enabled(self) -> bool:
        return self._enabled and len(self._proxies) > 0

    def add_proxy(self, proxy: Proxy) -> None:
        self._proxies.append(proxy)
        logger.debug("Added proxy: %s", proxy.url)

    def load_proxies(self, proxy_list: list[str], default_type: str = "http") -> None:
        for entry in proxy_list:
            try:
                proxy = self._parse(entry, default_type)
                if proxy:
                    self._proxies.append(proxy)
            except Exception as e:
                logger.warning("Invalid proxy entry '%s': %s", entry, e)

    @staticmethod
    def _parse(entry: str, default_type: str = "http") -> Proxy | None:
        entry = entry.strip()
        if not entry:
            return None

        parts = entry.split(":")
        if len(parts) == 2:
            return Proxy(type=default_type, host=parts[0], port=int(parts[1]))
        if len(parts) == 4:
            return Proxy(type=default_type, host=parts[0], port=int(parts[1]),
                         username=parts[2], password=parts[3])
        return None

    def next(self) -> Proxy | None:
        if not self._proxies:
            return None
        self._current_idx = (self._current_idx + 1) % len(self._proxies)
        return self._proxies[self._current_idx]

    def random(self) -> Proxy | None:
        if not self._proxies:
            return None
        return random.choice(self._proxies)

    def get_proxy_config(self) -> str | None:
        if not self.enabled:
            return None
        proxy = self.random()
        if proxy:
            return proxy.httpx_url if proxy.type == "http" else proxy.url
        return None
