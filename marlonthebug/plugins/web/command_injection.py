"""Command Injection detection — blind, time-based, and out-of-band."""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo, Workspace

logger = logging.getLogger("marlonthebug.plugins.web.command_injection")

CMD_PAYLOADS = [
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "&& id",
    "|| id",
    "| /usr/bin/id",
    "& id &",
]

TIME_PAYLOADS = [
    "; sleep 3",
    "| sleep 3",
    "`sleep 3`",
    "$(sleep 3)",
    "&& sleep 3",
]

CMD_PARAMS = ["cmd", "exec", "command", "run", "shell", "ping", "host", "ip", "address", "domain"]


class CommandInjectionAuditor(BasePlugin):
    name = "command_injection"
    version = "1.0.0"
    description = "Detect OS command injection vulnerabilities: blind, time-based, and output-based"
    category = "web"

    async def setup(self, workspace: Workspace) -> None:
        self._workspace = workspace

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        http = AsyncHTTPClient(timeout=15, retries=1)
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
                if parsed.netloc in (target.host, f"www.{target.host}"):
                    test_urls.add(href)

            for form in soup.find_all("form"):
                action = urljoin(base_url, form.get("action", ""))
                inputs = [(inp.get("name", ""), inp.get("value", "")) for inp in form.find_all("input")]
                if inputs:
                    params_str = "&".join(f"{n}={v or 'test'}" for n, v in inputs if n)
                    test_urls.add(f"{action}?{params_str}")

            for cp in CMD_PARAMS:
                test_urls.add(f"{base_url}?{cp}=test")

            for url in list(test_urls)[:15]:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if not params:
                    continue

                for param_name in list(params.keys())[:10]:
                    param_lower = param_name.lower()
                    is_cmd_param = any(cp in param_lower for cp in CMD_PARAMS)

                    if not is_cmd_param:
                        continue

                    baseline_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                    baseline_params[param_name] = "test"
                    query_str = "&".join(f"{k}={v}" for k, v in baseline_params.items())
                    baseline_url = parsed._replace(query=query_str).geturl()

                    try:
                        baseline = await http.get(baseline_url)
                    except Exception:
                        continue
                    baseline_body = baseline.body

                    for payload in CMD_PAYLOADS[:3]:
                        test_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                        test_params[param_name] = payload
                        query_str = "&".join(f"{k}={v}" for k, v in test_params.items())
                        test_url = parsed._replace(query=query_str).geturl()

                        try:
                            response = await http.get(test_url)
                            for indicator in ["uid=", "gid=", "groups="]:
                                if indicator in response.body and indicator not in baseline_body:
                                    yield self.create_finding(
                                        title=f"Command Injection in '{param_name}' — output visible",
                                        description=f"OS command injection in parameter '{param_name}'. "
                                        f"Payload '{payload}' returned {indicator}.",
                                        severity=Severity.CRITICAL,
                                        cvss_score=10.0,
                                        endpoint=url,
                                        target_host=target.host,
                                        evidence={
                                            "parameter": param_name,
                                            "payload": payload,
                                            "response_snippet": response.body[:300],
                                        },
                                        remediation=(
                                            "1. Never pass user input to system commands\n"
                                            "2. Use library calls instead of shell commands\n"
                                            "3. Escape or sanitize special characters: ; | & $ ( ) ` \\n"
                                            "4. Use allowlists for command parameters\n"
                                            "5. Run with minimal privileges (no root/sudo)"
                                        ),
                                    )
                                    break
                        except Exception:
                            pass

                    for time_payload in TIME_PAYLOADS[:2]:
                        start = time.monotonic()
                        test_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                        test_params[param_name] = time_payload
                        query_str = "&".join(f"{k}={v}" for k, v in test_params.items())
                        test_url = parsed._replace(query=query_str).geturl()

                        try:
                            await http.get(test_url)
                            elapsed = time.monotonic() - start
                            if elapsed > 2.0:
                                yield self.create_finding(
                                    title=f"Command Injection in '{param_name}' — time-based (blind)",
                                    description=f"Blind time-based command injection in parameter '{param_name}'. "
                                    f"Response took {elapsed:.1f}s with sleep payload.",
                                    severity=Severity.CRITICAL,
                                    cvss_score=9.5,
                                    endpoint=url,
                                    target_host=target.host,
                                    evidence={
                                        "parameter": param_name,
                                        "payload": time_payload,
                                        "response_time": elapsed,
                                    },
                                )
                        except Exception:
                            pass
        finally:
            await http.close()
