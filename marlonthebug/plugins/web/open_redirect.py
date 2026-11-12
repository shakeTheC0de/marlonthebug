"""Open Redirect detection."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo, Workspace

logger = logging.getLogger("marlonthebug.plugins.web.open_redirect")

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https:evil.com",
    "/\\evil.com",
    "https://evil.com%40target.com",
    "https://target.com.evil.com",
]

REDIRECT_PARAMS = [
    "url",
    "redirect",
    "link",
    "goto",
    "next",
    "continue",
    "return",
    "target",
    "referer",
    "redirect_uri",
    "redirect_url",
    "forward",
    "dest",
]


class OpenRedirectAuditor(BasePlugin):
    name = "open_redirect"
    version = "1.0.0"
    description = "Detect open redirect vulnerabilities in URL parameters"
    category = "web"

    async def setup(self, workspace: Workspace) -> None:
        self._workspace = workspace

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        http = AsyncHTTPClient(timeout=10, retries=1, follow_redirects=False)
        try:
            for scheme in ["https", "http"]:
                try:
                    resp = await http.get(f"{scheme}://{target.host}")
                    base_url = f"{scheme}://{target.host}"
                    break
                except Exception:
                    continue
            else:
                return

            from urllib.parse import urljoin

            from bs4 import BeautifulSoup

            soup = BeautifulSoup(resp.body, "lxml")
            test_urls: set[str] = set()

            for a in soup.find_all("a", href=True):
                href = urljoin(base_url, a["href"])
                parsed = urlparse(href)
                if parsed.netloc in (target.host, f"www.{target.host}") and parsed.query:
                    test_urls.add(href)

            for rp in REDIRECT_PARAMS:
                test_urls.add(f"{base_url}?{rp}=https://example.com")

            for url in list(test_urls)[:15]:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if not params:
                    continue

                for param_name in list(params.keys())[:10]:
                    param_lower = param_name.lower()
                    is_redirect = any(rp in param_lower for rp in REDIRECT_PARAMS)

                    if not is_redirect:
                        continue

                    for payload in REDIRECT_PAYLOADS[:3]:
                        test_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                        test_params[param_name] = payload
                        query_str = "&".join(f"{k}={v}" for k, v in test_params.items())
                        test_url = parsed._replace(query=query_str).geturl()

                        try:
                            response = await http.get(test_url)
                            location = response.headers.get("location", "")
                            if "evil.com" in location.lower() or payload in location:
                                yield self.create_finding(
                                    title=f"Open Redirect in '{param_name}'",
                                    description=f"Open redirect vulnerability in parameter '{param_name}'. "
                                    f"Redirects to external domain: {location}.",
                                    severity=Severity.MEDIUM,
                                    cvss_score=6.1,
                                    endpoint=url,
                                    target_host=target.host,
                                    evidence={
                                        "parameter": param_name,
                                        "payload": payload,
                                        "redirect_location": location,
                                    },
                                    remediation=(
                                        "1. Use a allowlist of permitted redirect URLs\n"
                                        "2. Use relative paths or named routes\n"
                                        "3. Validate the redirect URL against a known list\n"
                                        "4. Warn users before redirecting to external sites\n"
                                        "5. Use indirect references (IDs) instead of raw URLs"
                                    ),
                                )
                                break

                            if response.status_code in (301, 302, 307, 308):
                                location = response.headers.get("location", "")
                                if "evil.com" in location or "//evil" in location:
                                    yield self.create_finding(
                                        title=f"Open Redirect in '{param_name}'",
                                        description=f"HTTP {response.status_code} redirect to {location}.",
                                        severity=Severity.LOW if target.host in location else Severity.MEDIUM,
                                        cvss_score=5.5,
                                        endpoint=url,
                                        target_host=target.host,
                                        evidence={
                                            "parameter": param_name,
                                            "payload": payload,
                                            "status": response.status_code,
                                            "location": location,
                                        },
                                    )
                                    break
                        except Exception:
                            pass
        finally:
            await http.close()
