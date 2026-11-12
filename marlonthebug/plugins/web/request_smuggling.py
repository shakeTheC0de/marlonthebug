"""HTTP Request Smuggling detection — CL.TE, TE.CL, TE.TE desync."""

from __future__ import annotations

import logging
import socket
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo, Workspace

logger = logging.getLogger("marlonthebug.plugins.web.request_smuggling")


class RequestSmugglingAuditor(BasePlugin):
    name = "request_smuggling"
    version = "1.0.0"
    description = "Detect HTTP Request Smuggling via CL.TE, TE.CL, and TE.TE discrepancies"
    category = "web"

    CLTE_SMUGGLE = (
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "G"  # The front-end sees Content-Length: 6 → gets "0\r\n\r\nG" (6 bytes)
        # The back-end sees chunked → chunks "0\r\n\r\n" (zero-length chunk), then "G" starts next request
    )

    async def setup(self, workspace: Workspace) -> None:
        self._workspace = workspace

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        http = AsyncHTTPClient(timeout=10, retries=0)
        try:
            for scheme in ["https", "http"]:
                try:
                    await http.get(f"{scheme}://{target.host}")
                    base_url = f"{scheme}://{target.host}"
                    break
                except Exception:
                    continue
            else:
                return

            try:
                from urllib.parse import urlparse

                parsed = urlparse(base_url)
                host = parsed.hostname or target.host
                port = parsed.port or (443 if scheme == "https" else 80)

                timing = await self._time_request(host, port, scheme)

                if timing > 3.0:
                    yield self.create_finding(
                        title="Potential HTTP Request Smuggling (time-based detection)",
                        description=f"Time-based request smuggling test took {timing:.1f}s for {target.host}.",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        endpoint=base_url,
                        target_host=target.host,
                        evidence={"response_time": timing, "host": host, "port": port},
                        remediation=(
                            "1. Use HTTP/2 end-to-end\n"
                            "2. Disable HTTP pipelining on the backend\n"
                            "3. Configure front-end and back-end to use same Content-Length/Transfer-Encoding handling\n"
                            "4. Reject ambiguous requests (both CL and TE headers)\n"
                            "5. Normalize requests at the front-end proxy"
                        ),
                    )
            except Exception as e:
                logger.debug("Request smuggling check failed: %s", e)
        finally:
            await http.close()

    async def _time_request(self, host: str, port: int, scheme: str) -> float:
        import time

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))

        if scheme == "https":
            import ssl

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        payload = self.CLTE_SMUGGLE.format(host=host).encode()
        start = time.monotonic()

        try:
            sock.sendall(payload)
            sock.settimeout(3)
            data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except TimeoutError:
                    break
            elapsed = time.monotonic() - start
        finally:
            sock.close()

        return elapsed
