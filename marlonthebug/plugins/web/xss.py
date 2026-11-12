"""XSS detection — reflected and DOM-based cross-site scripting."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, AsyncIterator
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import Workspace, TargetInfo

logger = logging.getLogger("marlonthebug.plugins.web.xss")

XSS_PAYLOADS = [
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '\"><svg onload=alert(1)>',
    "'><svg onload=alert(1)>",
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<details open ontoggle=alert(1)>',
    '<body onload=alert(1)>',
]

CONTEXT_PATTERNS = [
    (r"<input[^>]+value=\"([^\"]*)\"", "html_attribute"),
    (r"<textarea[^>]*>([^<]*)</textarea>", "html_body"),
    (r"<script[^>]*>var\s+\w+\s*=\s*[\"']([^\"']*)[\"']", "js_string"),
    (r"<a[^>]+href=\"([^\"]*)\"", "href"),
]


class XSSAuditor(BasePlugin):
    name = "xss"
    version = "1.0.0"
    description = "Detect Cross-Site Scripting (XSS) vulnerabilities: reflected and DOM-based"
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
                    test_urls.add(href)

            for form in soup.find_all("form"):
                action = urljoin(base_url, form.get("action", ""))
                method = form.get("method", "GET").upper()
                if method == "GET":
                    inputs = [(inp.get("name", ""), inp.get("value", "")) for inp in form.find_all("input")]
                    if inputs:
                        params_str = "&".join(f"{n}={v or 'test'}" for n, v in inputs if n)
                        test_urls.add(f"{action}?{params_str}")

            if not test_urls:
                test_urls.add(base_url + "?q=test")

            for url in list(test_urls)[:15]:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if not params:
                    continue

                for param_name in list(params.keys())[:5]:
                    base_val = params.get(param_name, ["test"])[0]
                    reflector = base_url + "?test=" + base_url.replace("://", "XYZZY").upper()
                    if base_url + "?test=" not in reflector:
                        continue

                    for payload in XSS_PAYLOADS[:5]:
                        try:
                            test_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                            test_params[param_name] = payload
                            query_str = "&".join(f"{k}={v}" for k, v in test_params.items())
                            test_url = parsed._replace(query=query_str).geturl()
                            response = await http.get(test_url)

                            if payload in response.body:
                                contexts = []
                                for pattern, ctx in CONTEXT_PATTERNS:
                                    for match in re.finditer(pattern, response.body):
                                        if payload in match.group(0):
                                            contexts.append(ctx)

                                if contexts:
                                    yield self.create_finding(
                                        title=f"Reflected XSS in parameter '{param_name}'",
                                        description=f"Cross-Site Scripting vulnerability in parameter '{param_name}'. "
                                                    f"Payload reflected in contexts: {', '.join(contexts)}.",
                                        severity=Severity.HIGH,
                                        cvss_score=7.2,
                                        endpoint=url,
                                        target_host=target.host,
                                        evidence={
                                            "parameter": param_name,
                                            "payload": payload,
                                            "contexts": contexts,
                                            "url": test_url,
                                        },
                                        remediation=(
                                            "1. HTML-encode all user input before output\n"
                                            "2. Use Content-Security-Policy header\n"
                                            "3. Set HttpOnly and Secure flags on cookies\n"
                                            "4. Validate input against allowlists\n"
                                            "5. Use modern frameworks with auto-escaping (React, Vue, Angular)"
                                        ),
                                        waf_rules=[
                                            "SecRule ARGS \"(?i)<script\" \"id:2000,deny,status:403,msg:'XSS attempt'\"",
                                        ],
                                    )
                                    break
                        except Exception:
                            pass
        finally:
            await http.close()
