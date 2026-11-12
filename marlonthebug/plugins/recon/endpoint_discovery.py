"""Hidden endpoint discovery — directory and file brute forcing."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, AsyncIterator

from marlonthebug.plugins.base import BasePlugin, Finding, Severity
from marlonthebug.http.client import AsyncHTTPClient

if TYPE_CHECKING:
    from marlonthebug.core.workspace import Workspace, TargetInfo

logger = logging.getLogger("marlonthebug.plugins.recon.endpoint_discovery")

DEFAULT_EXTENSIONS = ["php", "asp", "aspx", "jsp", "do", "action", "html", "htm", "js", "json",
                      "xml", "txt", "bak", "old", "swp", "sql", "zip", "tar", "gz", "log"]


class EndpointDiscoverer(BasePlugin):
    name = "endpoint_discovery"
    version = "1.0.0"
    description = "Discover hidden endpoints via directory and file brute forcing with response analysis"
    category = "recon"

    def __init__(self, options: dict | None = None) -> None:
        super().__init__(options)
        self._workspace: Workspace | None = None
        self._wordlist: list[str] = []

    async def setup(self, workspace: Workspace) -> None:
        self._workspace = workspace
        self._wordlist = self._load_wordlist()

    def _load_wordlist(self) -> list[str]:
        return [
            "admin", "login", "wp-admin", "administrator", "panel", "dashboard",
            "api", "v1", "v2", "graphql", "swagger", "docs", "status", "health",
            "config", "backup", "backups", "tmp", "temp", "test", "dev", "staging",
            "debug", "phpinfo", "info", "server-status", "console",
            ".git", ".env", ".svn", ".hg", ".DS_Store",
            "robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
            "upload", "uploads", "download", "files", "static", "assets",
            "wp-content", "wp-includes", "wp-json", "wp-login", "xmlrpc.php",
            "cgi-bin", "shell", "cmd",
            "vendor", "composer.json", "package.json", "yarn.lock", "Dockerfile",
        ]

    async def run(
        self,
        target: TargetInfo,
        options: dict | None = None,
    ) -> AsyncIterator[Finding]:
        from urllib.parse import urljoin

        extensions = self.options.get("extensions", DEFAULT_EXTENSIONS)
        threads = self.options.get("threads", 30)
        http = AsyncHTTPClient(timeout=8, retries=1)
        semaphore = asyncio.Semaphore(threads)

        async def check(path: str) -> Finding | None:
            async with semaphore:
                for scheme in ["https", "http"]:
                    url = f"{scheme}://{target.host}/{path}"
                    try:
                        response = await http.head(url)
                        if response.status_code not in (404, 400, 500):
                            return Finding(
                                plugin_name=self.name,
                                title=f"Endpoint discovered: {url}",
                                description=f"Found endpoint {url} returning HTTP {response.status_code}.",
                                severity=Severity.INFO,
                                cvss_score=0.0,
                                endpoint=url,
                                target_host=target.host,
                                category=self.category,
                                evidence={"url": url, "status_code": response.status_code},
                            )
                    except Exception:
                        continue
                return None

        priority_paths = [
            ".git/HEAD", ".env", ".env.backup", ".env.production",
            "robots.txt", "sitemap.xml", "admin", "login",
            "wp-admin", "wp-login.php", "xmlrpc.php",
            "phpmyadmin", "phpinfo.php", ".DS_Store",
        ]

        for path in priority_paths:
            result = await check(path)
            if result:
                yield result

        tasks = [check(item) for item in self._wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Finding):
                yield r

        for item in self._wordlist[:20]:
            for ext in extensions[:5]:
                result = await check(f"{item}.{ext}")
                if result:
                    yield result

        await http.close()
