"""Hidden endpoint discovery with soft-404 and content validation."""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo, Workspace

logger = logging.getLogger("marlonthebug.plugins.recon.endpoint_discovery")

DEFAULT_EXTENSIONS = ["php", "asp", "aspx", "jsp", "html", "json", "xml", "txt", "bak", "old", "zip", "log"]

# A generic 403 from the web server (cgi-bin, .htaccess) is not evidence of a
# sensitive resource. Only keep forbidden responses for paths that would be
# interesting if they exist.
INTERESTING_FORBIDDEN = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.backup",
    ".git/head",
    ".git/config",
    "server-status",
    "server-info",
    "phpinfo.php",
    "info.php",
    "backup",
    "backups",
    "config",
    "debug",
    "admin",
    "panel",
    "dashboard",
}

# Paths that are interesting only when their content matches the expected
# format.  This is what prevents SPA catch-all pages from becoming findings.
CONTENT_CHECKS: dict[str, tuple[str, ...]] = {
    ".git/HEAD": ("ref: refs/", "ref: refs/heads/"),
    ".env": ("=", "APP_", "DB_", "SECRET", "KEY"),
    ".env.local": ("=", "APP_", "DB_", "SECRET", "KEY"),
    ".env.production": ("=", "APP_", "DB_", "SECRET", "KEY"),
    ".env.backup": ("=", "APP_", "DB_", "SECRET", "KEY"),
    "robots.txt": ("user-agent:", "disallow:", "sitemap:"),
    "sitemap.xml": ("<urlset", "<sitemapindex"),
    "security.txt": ("contact:", "expires:"),
    "phpinfo.php": ("php version", "phpinfo()"),
    "info.php": ("php version", "phpinfo()"),
    "server-status": ("apache server status", "server status"),
    "server-info": ("apache server information", "server information"),
    "package.json": ('"name"', '"dependencies"', '"version"'),
    "composer.json": ('"require"', '"name"', '"autoload"'),
    "Dockerfile": ("from ", "run ", "cmd "),
    ".DS_Store": ("bud1", "\x00\x00\x00\x01bud1"),
}


class EndpointDiscoverer(BasePlugin):
    name = "endpoint_discovery"
    version = "2.0.0"
    description = "Descubre endpoints ocultos con baseline, validación de contenido y control de falsos positivos"
    category = "recon"
    beta = False

    WORDLIST = [
        "admin",
        "login",
        "panel",
        "dashboard",
        "api",
        "api/v1",
        "api/v2",
        "graphql",
        "swagger",
        "swagger-ui",
        "docs",
        "status",
        "health",
        "healthz",
        "config",
        "backup",
        "backups",
        "tmp",
        "test",
        "dev",
        "staging",
        "debug",
        "phpinfo.php",
        "info.php",
        "server-status",
        "server-info",
        ".git/HEAD",
        ".git/config",
        ".env",
        ".env.local",
        ".env.production",
        ".env.backup",
        ".svn/entries",
        ".hg/requires",
        ".DS_Store",
        "robots.txt",
        "sitemap.xml",
        "security.txt",
        ".well-known/security.txt",
        "upload",
        "uploads",
        "files",
        "download",
        "static",
        "assets",
        "wp-admin",
        "wp-login.php",
        "xmlrpc.php",
        "wp-json/wp/v2/users",
        "cgi-bin",
        "vendor",
        "composer.json",
        "package.json",
        "yarn.lock",
        "Dockerfile",
        "docker-compose.yml",
        ".htaccess",
        "web.config",
    ]

    async def setup(self, workspace: Workspace) -> None:
        self._workspace = workspace

    async def run(
        self,
        target: TargetInfo,
        options: dict | None = None,
    ) -> AsyncIterator[Finding]:
        options = options or {}
        base_url = str(options.get("base_url") or f"https://{target.host}").rstrip("/")
        baseline = options.get("baseline")
        http = AsyncHTTPClient(timeout=8, retries=1)
        semaphore = asyncio.Semaphore(8)
        extensions = self.options.get("extensions", DEFAULT_EXTENSIONS)
        seen: set[str] = set()

        async def check(path: str) -> Finding | None:
            path = path.lstrip("/")
            if path in seen:
                return None
            seen.add(path)
            async with semaphore:
                url = f"{base_url}/{path}"
                try:
                    response = await http.get(url)
                except Exception:
                    return None
                if response.status_code in (404, 410):
                    return None
                if baseline and baseline.looks_like_app_shell(response):
                    return None
                if response.status_code in (401, 403):
                    if baseline and baseline.is_soft_404(response):
                        return None
                    if not is_interesting_forbidden(path):
                        return None
                if not _content_is_valid(path, response.body, response.content_type):
                    return None
                snippet = re.sub(r"\s+", " ", response.body[:240]).strip()
                return Finding(
                    plugin_name=self.name,
                    title=f"Endpoint descubierto: /{path}",
                    description=(
                        f"El endpoint {url} responde HTTP {response.status_code} con contenido "
                        f"diferenciado del baseline y validación de formato correcta."
                    ),
                    severity=Severity.INFO,
                    cvss_score=0.0,
                    confidence=Confidence.HIGH,
                    endpoint=url,
                    target_host=target.host,
                    category=self.category,
                    evidence={
                        "status_code": response.status_code,
                        "content_type": response.content_type,
                        "content_length": response.content_length,
                        "snippet": snippet,
                        "validated": True,
                    },
                    remediation="Revisa si el recurso debe ser público. Restringe el acceso si contiene información interna.",
                    cwe="CWE-200",
                    owasp="A01:2021 Broken Access Control",
                )

        paths = list(dict.fromkeys(self.WORDLIST))
        for item in ("admin", "login", "api", "backup", "config"):
            for extension in extensions:
                paths.append(f"{item}.{extension}")

        tasks = [asyncio.create_task(check(path)) for path in paths]
        try:
            for task in asyncio.as_completed(tasks):
                result = await task
                if result:
                    yield result
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await http.close()


def is_interesting_forbidden(path: str) -> bool:
    return path.lstrip("/").lower() in INTERESTING_FORBIDDEN


def _content_is_valid(path: str, body: str, content_type: str) -> bool:
    path = path.lower()
    lowered = body.lower()
    checks = {key.lower(): value for key, value in CONTENT_CHECKS.items()}
    if path in checks:
        return any(marker.lower() in lowered for marker in checks[path])
    if path.endswith((".zip", ".tar", ".gz", ".bak", ".old")):
        return "html" not in content_type and len(body) > 32
    if path.endswith((".json",)):
        return body.lstrip().startswith(("{", "["))
    if path.endswith((".xml",)):
        return body.lstrip().startswith("<") and "html" not in content_type
    if path.endswith((".php", ".asp", ".aspx", ".jsp")):
        # A dynamic endpoint must return something other than a blank shell.
        return len(body.strip()) > 20 and "<html" not in body[:80].lower()
    if path in {"admin", "login", "panel", "dashboard"}:
        return len(body.strip()) > 20
    return len(body.strip()) > 20 and "not found" not in lowered[:300]


__all__ = ["CONTENT_CHECKS", "EndpointDiscoverer", "is_interesting_forbidden"]
