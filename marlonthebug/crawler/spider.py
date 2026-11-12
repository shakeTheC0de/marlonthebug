"""Intelligent async spider — crawling, sitemap parsing, endpoint extraction."""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse, parse_qs
from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup

if TYPE_CHECKING:
    from marlonthebug.http.client import AsyncHTTPClient

logger = logging.getLogger("marlonthebug.crawler")

JS_ENDPOINT_PATTERNS = [
    r'(?:"|\')(\/api\/[^"\'\s]+)(?:"|\')',
    r'(?:"|\')(\/v\d\/[^"\'\s]+)(?:"|\')',
    r'(?:fetch|axios|get|post|put|delete|patch)\s*\(\s*(?:"|\')([^"\'\s]+)(?:"|\')',
    r'path\s*:\s*(?:"|\')(\/[^"\'\s]+)(?:"|\')',
    r'(?:url|uri|href|src)\s*:\s*(?:"|\')(\/[^"\'\s]+)(?:"|\')',
]

SECRET_PATTERNS = [
    (r'(?i)(?:api[_-]?key|apikey|api_secret|secret[_-]?key)\s*[:=]\s*["\']([^"\'\s]{8,})["\']', "API Key"),
    (r'(?i)(?:token|access[_-]?token|auth[_-]?token)\s*[:=]\s*["\']([^"\'\s]{8,})["\']', "Access Token"),
    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']+?)["\']', "Password"),
    (r'(?i)(?:jwt|json[_-]?web[_-]?token|bearer)\s*[:=]\s*["\']([^"\'\s]{20,})["\']', "JWT Token"),
    (r'(?i)(?:aws[_-]?access[_-]?key[_-]?id|AKIA[A-Z0-9]{16})', "AWS Access Key"),
    (r'(?i)(?:github[_-]?token|gh[_-]?token|ghp_[A-Za-z0-9]{36,})', "GitHub Token"),
    (r'(?i)(?:private[_-]?key|rsa[_-]?private|dsa[_-]?private)', "Private Key"),
    (r'(?i)-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----', "Private Key Block"),
]


@dataclass
class CrawledPage:
    url: str
    status_code: int
    title: str
    links: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    js_endpoints: list[str] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body_preview: str = ""


class Crawler:
    def __init__(
        self,
        http_client: AsyncHTTPClient,
        max_depth: int = 5,
        max_pages: int = 1000,
        respect_robots: bool = True,
        follow_subdomains: bool = False,
        extract_js: bool = True,
        extract_api: bool = True,
        concurrency: int = 10,
    ) -> None:
        self.http = http_client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.respect_robots = respect_robots
        self.follow_subdomains = follow_subdomains
        self.extract_js = extract_js
        self.extract_api = extract_api
        self.concurrency = concurrency
        self._visited: set[str] = set()
        self._queued: set[str] = set()
        self._semaphore = asyncio.Semaphore(concurrency)
        self._robot_cache: dict[str, RobotFileParser | None] = {}
        self.results: list[CrawledPage] = []

    async def crawl(self, start_url: str) -> list[CrawledPage]:
        self.results = []
        self._visited.clear()
        self._queued.clear()

        queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        await queue.put((start_url, 0))
        self._queued.add(start_url)

        base_domain = urlparse(start_url).netloc

        async def worker() -> None:
            while True:
                try:
                    url, depth = await asyncio.wait_for(queue.get(), timeout=2)
                except asyncio.TimeoutError:
                    return

                try:
                    if url in self._visited or len(self.results) >= self.max_pages:
                        queue.task_done()
                        continue

                    self._visited.add(url)

                    if self.respect_robots and not await self._check_robots(url):
                        queue.task_done()
                        continue

                    async with self._semaphore:
                        page = await self._fetch(url)
                        if page:
                            self.results.append(page)

                            if depth < self.max_depth:
                                for link in page.links:
                                    if link not in self._visited and link not in self._queued:
                                        if not self.follow_subdomains:
                                            link_domain = urlparse(link).netloc
                                            if link_domain != base_domain:
                                                continue
                                        if len(self._queued) < self.max_pages * 2:
                                            self._queued.add(link)
                                            await queue.put((link, depth + 1))
                except Exception as e:
                    logger.debug("Crawler error for %s: %s", url, e)
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
        await asyncio.gather(*workers)

        logger.info("Crawler finished: %d pages visited", len(self.results))
        return self.results

    async def _fetch(self, url: str) -> CrawledPage | None:
        try:
            response = await self.http.get(url)
            soup = BeautifulSoup(response.body, "lxml")

            title = soup.title.string.strip() if soup.title else ""

            links: list[str] = []
            for a in soup.find_all("a", href=True):
                href = urljoin(url, a["href"])
                parsed = urlparse(href)
                if parsed.scheme in ("http", "https"):
                    links.append(href.split("#")[0])

            forms: list[dict] = []
            for form in soup.find_all("form"):
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    inputs.append({
                        "name": inp.get("name", ""),
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                    })
                forms.append({
                    "action": urljoin(url, form.get("action", "")),
                    "method": form.get("method", "GET").upper(),
                    "inputs": inputs,
                })

            js_endpoints: list[str] = []
            secrets: list[dict] = []

            if self.extract_js or self.extract_api:
                for script in soup.find_all("script", src=True):
                    js_endpoints.append(urljoin(url, script["src"]))

                for script in soup.find_all("script"):
                    if script.string:
                        content = script.string
                        for pattern in JS_ENDPOINT_PATTERNS:
                            for match in re.finditer(pattern, content):
                                ep = match.group(1)
                                if ep not in js_endpoints:
                                    js_endpoints.append(ep)

                        for pattern, label in SECRET_PATTERNS:
                            for match in re.finditer(pattern, content):
                                secrets.append({"type": label, "match": match.group(0)[:100]})

            return CrawledPage(
                url=url,
                status_code=response.status_code,
                title=title,
                links=links,
                forms=forms,
                js_endpoints=js_endpoints,
                secrets=secrets,
                headers=response.headers,
                body_preview=response.body[:500],
            )
        except Exception as e:
            logger.debug("Failed to fetch %s: %s", url, e)
            return None

    async def _check_robots(self, url: str) -> bool:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in self._robot_cache:
            rp = RobotFileParser()
            rp.set_url(f"{base}/robots.txt")
            try:
                rp.read()
                self._robot_cache[base] = rp
            except Exception:
                self._robot_cache[base] = None
                return True
        rp = self._robot_cache.get(base)
        if rp is None:
            return True
        return rp.can_fetch("*", url)
