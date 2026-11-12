"""Fuzzer engine — adaptive payload generation with response analysis."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, AsyncIterator, Callable

from marlonthebug.fuzzer.mutators import Mutator
from marlonthebug.fuzzer.generators import PayloadContext

if TYPE_CHECKING:
    from marlonthebug.http.client import AsyncHTTPClient, HttpResponse

logger = logging.getLogger("marlonthebug.fuzzer")


@dataclass
class FuzzResult:
    url: str
    payload: str
    status_code: int
    content_length: int
    response_time: float
    matched: bool
    match_reason: str = ""
    body_preview: str = ""


@dataclass
class FuzzerConfig:
    threads: int = 30
    delay: float = 0
    rate_limit: float = 0
    match_codes: list[int] = field(default_factory=lambda: [200, 201, 301, 302, 307, 403, 500])
    filter_codes: list[int] = field(default_factory=lambda: [404])
    match_length_threshold: int = 100
    recursion_depth: int = 2
    timeout: float = 10.0


class Fuzzer:
    def __init__(
        self,
        http_client: AsyncHTTPClient,
        config: FuzzerConfig | None = None,
    ) -> None:
        self.http = http_client
        self.config = config or FuzzerConfig()
        self.mutator = Mutator()
        self._semaphore = asyncio.Semaphore(self.config.threads)
        self._baseline: dict[str, int] = {}
        self._rate_limiter: float = 0

    async def establish_baseline(self, url: str, params: dict[str, str]) -> None:
        baseline = 0
        for _ in range(5):
            response = await self.http.get(url, params=params)
            baseline += response.content_length
            await asyncio.sleep(0.2)
        self._baseline[url] = baseline // 5
        logger.debug("Baseline length for %s: %d", url, self._baseline[url])

    async def fuzz_url(
        self,
        url: str,
        method: str = "GET",
        param: str | None = None,
        wordlist: list[str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> AsyncIterator[FuzzResult]:
        wordlist = wordlist or []
        baseline_len = self._baseline.get(url, 0)

        async def fuzz_single(payload: str) -> FuzzResult | None:
            async with self._semaphore:
                await self._rate_limit()
                start = time.monotonic()

                try:
                    if method == "GET" and param:
                        response = await self.http.get(url, params={param: payload}, headers=headers)
                    elif method == "POST" and param:
                        response = await self.http.post(url, data={param: payload}, headers=headers)
                    else:
                        response = await self.http.get(url, params={"q": payload}, headers=headers)

                    elapsed = time.monotonic() - start
                    matched, reason = self._analyze(response, baseline_len, elapsed, payload)

                    return FuzzResult(
                        url=url,
                        payload=payload,
                        status_code=response.status_code,
                        content_length=response.content_length,
                        response_time=elapsed,
                        matched=matched,
                        match_reason=reason,
                        body_preview=response.body[:200],
                    )
                except Exception as e:
                    logger.debug("Fuzz error for %s [%s]: %s", url, payload[:30], e)
                    return None

        tasks = [fuzz_single(payload) for payload in wordlist]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result and result.matched:
                yield result

    def fuzz_with_mutations(
        self,
        base_payload: str,
        count: int = 20,
    ) -> list[str]:
        return self.mutator.mutate(base_payload, count)

    async def _rate_limit(self) -> None:
        if self.config.rate_limit <= 0:
            return
        now = time.monotonic()
        if now - self._rate_limiter < (1.0 / self.config.rate_limit):
            await asyncio.sleep(1.0 / self.config.rate_limit)
        self._rate_limiter = time.monotonic()
        if self.config.delay > 0:
            await asyncio.sleep(self.config.delay)

    def _analyze(
        self,
        response: "HttpResponse",
        baseline_len: int,
        response_time: float,
        payload: str,
    ) -> tuple[bool, str]:
        if baseline_len > 0 and response.status_code not in self.config.filter_codes:
            if abs(response.content_length - baseline_len) > self.config.match_length_threshold:
                return True, f"Content length anomaly: {response.content_length} vs baseline {baseline_len}"

        if response.status_code in self.config.match_codes:
            body_lower = response.body.lower()
            error_indicators = [
                "error", "exception", "traceback", "warning",
                "sql", "syntax", "undefined", "stack trace",
                "fatal", "uncaught", "failed",
            ]
            for indicator in error_indicators:
                if indicator in body_lower:
                    return True, f"Body contains indicator: {indicator}"

        if response_time > 5.0:
            return True, f"Slow response: {response_time:.1f}s"

        return False, ""


class DictionaryFuzzer:
    def __init__(self, fuzzer: Fuzzer, wordlist_dir: str = "") -> None:
        self.fuzzer = fuzzer
        self._wordlists: dict[str, list[str]] = {}

    def load_wordlist(self, name: str, path: str) -> None:
        try:
            with open(path) as f:
                self._wordlists[name] = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            logger.warning("Wordlist not found: %s", path)

    def get_wordlist(self, name: str) -> list[str]:
        return self._wordlists.get(name, [])

    async def fuzz_directories(
        self,
        base_url: str,
        wordlist_name: str = "directories",
    ) -> AsyncIterator[FuzzResult]:
        wordlist = self.get_wordlist(wordlist_name)
        for payload in wordlist:
            url = f"{base_url.rstrip('/')}/{payload}"
            async for result in self.fuzzer.fuzz_url(url, param=None, wordlist=[payload]):
                yield result
