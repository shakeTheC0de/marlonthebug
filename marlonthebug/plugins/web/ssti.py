"""SSTI detection — Server-Side Template Injection."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, AsyncIterator
from urllib.parse import urlparse, parse_qs

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import Workspace, TargetInfo

logger = logging.getLogger("marlonthebug.plugins.web.ssti")

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("*{7*7}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${{7*7}}", "49"),
    ("{{'test'.upper()}}", "TEST"),
]

TEMPLATE_PARAMS = ["template", "view", "tpl", "page", "name", "email", "subject", "message", "content", "render"]


class SSTIAuditor(BasePlugin):
    name = "ssti"
    version = "1.0.0"
    description = "Detect Server-Side Template Injection (SSTI) in Jinja2, Twig, Freemarker, Velocity, ERB"
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

            from bs4 import BeautifulSoup
            from urllib.parse import urljoin

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

            for tp in TEMPLATE_PARAMS:
                test_urls.add(f"{base_url}?{tp}=test")

            for url in list(test_urls)[:15]:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if not params:
                    continue

                for param_name in list(params.keys())[:10]:
                    param_lower = param_name.lower()

                    for payload, expected_result in SSTI_PAYLOADS:
                        test_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                        test_params[param_name] = payload
                        query_str = "&".join(f"{k}={v}" for k, v in test_params.items())
                        test_url = parsed._replace(query=query_str).geturl()

                        try:
                            response = await http.get(test_url)
                            if expected_result in response.body:
                                yield self.create_finding(
                                    title=f"SSTI in '{param_name}' — evaluates {{7*7}} = 49",
                                    description=f"Server-Side Template Injection in parameter '{param_name}'. "
                                                f"Payload '{payload}' evaluated to '{expected_result}'.",
                                    severity=Severity.CRITICAL,
                                    cvss_score=9.8,
                                    endpoint=url,
                                    target_host=target.host,
                                    evidence={"parameter": param_name, "payload": payload,
                                               "expected": expected_result, "match": True},
                                    remediation=(
                                        "1. Never pass user input directly to template render functions\n"
                                        "2. Use a logic-less template engine (Mustache, Handlebars)\n"
                                        "3. Sandbox template evaluation\n"
                                        "4. Escape user input before inserting into templates\n"
                                        "5. Use allowlists for template variables"
                                    ),
                                )
                                break
                        except Exception:
                            pass
        finally:
            await http.close()
