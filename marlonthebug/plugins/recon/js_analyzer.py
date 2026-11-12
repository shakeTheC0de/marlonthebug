"""JavaScript analyzer — extract endpoints, secrets, and parse sourcemaps."""

from __future__ import annotations

import json as json_mod
import logging
import re
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo, Workspace

logger = logging.getLogger("marlonthebug.plugins.recon.js_analyzer")

ENDPOINT_PATTERNS = [
    (r"['\"`](/api/[^'\"`\s]+)['\"`]", "API Endpoint"),
    (r"['\"`](/v\d/[^'\"`\s]+)['\"`]", "Versioned Endpoint"),
    (r"['\"`](/graphql[^'\"`\s]*)['\"`]", "GraphQL Endpoint"),
    (r"['\"`](/swagger[^'\"`\s]*)['\"`]", "Swagger Endpoint"),
    (r"['\"`](/oauth[^'\"`\s]*)['\"`]", "OAuth Endpoint"),
    (r"['\"`](https?://[^'\"`\s]+)['\"`]", "External URL"),
    (r"\.(get|post|put|delete|patch)\s*\(['\"`]([^'\"`\s]+)['\"`]", "AJAX Request"),
    (r"url\s*:\s*['\"`]([^'\"`\s]+)['\"`]", "URL Config"),
    (r"baseURL\s*:\s*['\"`]([^'\"`\s]+)['\"`]", "Base URL"),
    (r"path\s*:\s*['\"`](/[^'\"`\s]+)['\"`]", "Route Path"),
]

SECRET_PATTERNS_JS = [
    (r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "API Key in JS"),
    (r"(?i)(?:token|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "Token in JS"),
    (r"(?i)(?:secret|secret[_-]?key)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "Secret in JS"),
    (r"(?i)AKIA[0-9A-Z]{16}", "AWS Access Key in JS"),
    (r"(?i)ghp_[0-9a-zA-Z]{36,}", "GitHub Token in JS"),
    (r"(?i)sk-[a-zA-Z0-9]{32,}", "OpenAI/Stripe Key in JS"),
    (r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]+)['\"]", "Password in JS"),
    (r"(?i)(?:firebase|firebaseConfig)\s*[:=]\s*\{[^}]*apiKey\s*:\s*['\"]([^'\"]+)", "Firebase Config"),
    (r"(?i)-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "Private Key in JS"),
    (r'(?i)(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis)://[^\s\'"]+', "Database Connection String"),
]


class JSAnalyzer(BasePlugin):
    name = "js_analyzer"
    version = "1.0.0"
    description = "Extract endpoints, API keys, tokens, and secrets from JavaScript files"
    category = "recon"

    def __init__(self, options: dict | None = None) -> None:
        super().__init__(options)
        self._found_endpoints: set[str] = set()
        self._found_secrets: set[str] = set()

    async def setup(self, workspace: Workspace) -> None:
        self._found_endpoints.clear()
        self._found_secrets.clear()

    async def run(
        self,
        target: TargetInfo,
        options: dict | None = None,
    ) -> AsyncIterator[Finding]:
        http = AsyncHTTPClient(timeout=10, retries=2)
        try:
            for scheme in ["https", "http"]:
                try:
                    response = await http.get(f"{scheme}://{target.host}")
                    break
                except Exception:
                    continue
            else:
                return

            body = response.body
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(body, "lxml")
            script_urls: list[str] = []

            for script in soup.find_all("script", src=True):
                from urllib.parse import urljoin

                script_urls.append(urljoin(f"{scheme}://{target.host}", script["src"]))

            async for finding in self._analyze_inline(body, target.host):
                yield finding

            for script_url in script_urls[:20]:
                async for finding in self._analyze_script(script_url, target.host, http):
                    yield finding

            async for finding in self._analyze_sourcemaps(body, target.host, http):
                yield finding
        finally:
            await http.close()

    async def _analyze_inline(
        self,
        body: str,
        host: str,
    ) -> AsyncIterator[Finding]:
        for pattern, label in ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, body):
                value = match.group(1)
                if value not in self._found_endpoints:
                    self._found_endpoints.add(value)
                    yield Finding(
                        plugin_name=self.name,
                        title=f"JS endpoint found: {value}",
                        description=f"Discovered {label.lower()}: {value}",
                        severity=Severity.INFO,
                        cvss_score=0.0,
                        endpoint=value,
                        target_host=host,
                        category=self.category,
                        evidence={"type": label, "value": value, "source": "inline_script"},
                    )

        for pattern, label in SECRET_PATTERNS_JS:
            for match in re.finditer(pattern, body):
                value = match.group(0)
                if value not in self._found_secrets:
                    self._found_secrets.add(value)
                    yield Finding(
                        plugin_name=self.name,
                        title=f"Secret exposed in JS: {label}",
                        description=f"Found potential {label.lower()} in JavaScript: {value[:50]}...",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        endpoint=host,
                        target_host=host,
                        category=self.category,
                        evidence={"type": label, "match": value[:100], "source": "inline_script"},
                        remediation=f"Remove the {label.lower()} from client-side JavaScript. Use server-side environment variables instead.",
                    )

    async def _analyze_script(
        self,
        url: str,
        host: str,
        http: AsyncHTTPClient,
    ) -> AsyncIterator[Finding]:
        try:
            response = await http.get(url)
            for pattern, label in ENDPOINT_PATTERNS:
                for match in re.finditer(pattern, response.body):
                    value = match.group(1)
                    if value not in self._found_endpoints:
                        self._found_endpoints.add(value)
                        yield Finding(
                            plugin_name=self.name,
                            title=f"JS endpoint in {url}: {value}",
                            description=f"{label}: {value}",
                            severity=Severity.INFO,
                            cvss_score=0.0,
                            endpoint=value,
                            target_host=host,
                            category=self.category,
                            evidence={"type": label, "value": value, "script_url": url},
                        )
        except Exception as e:
            logger.debug("Failed to analyze %s: %s", url, e)

    async def _analyze_sourcemaps(
        self,
        body: str,
        host: str,
        http: AsyncHTTPClient,
    ) -> AsyncIterator[Finding]:
        sourcemap_urls = re.findall(r"//# sourceMappingURL=(.+)", body)
        for url in sourcemap_urls[:5]:
            try:
                response = await http.get(url)
                data = json_mod.loads(response.body)
                sources = data.get("sources", [])
                for source in sources[:10]:
                    yield Finding(
                        plugin_name=self.name,
                        title=f"Sourcemap source: {source}",
                        description=f"Original source file revealed via sourcemap: {source}",
                        severity=Severity.LOW,
                        cvss_score=3.5,
                        endpoint=url,
                        target_host=host,
                        category=self.category,
                        evidence={"sourcemap_url": url, "source_file": source},
                        remediation="Disable sourcemap generation in production builds.",
                    )
            except Exception:
                pass
