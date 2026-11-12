"""Web cache poisoning and cache deception heuristics."""

from __future__ import annotations

import logging
import secrets
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo

logger = logging.getLogger("marlonthebug.plugins.web.cache_poisoning")

CACHE_HEADERS = ("x-cache", "cf-cache-status", "age", "via", "x-cache-status", "cdn-cache")


class CachePoisoningAuditor(BasePlugin):
    name = "cache_poisoning"
    version = "1.0.0"
    description = "Prueba reflexión de cabeceras de proxy y presencia de caché compartida"
    category = "web"
    cwe = "CWE-444"
    owasp = "A05:2021 Security Misconfiguration"
    beta = True

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        options = options or {}
        base_url = str(options.get("base_url") or f"https://{target.host}").rstrip("/")
        endpoints = [base_url, *list(options.get("endpoints") or [])[:10]]
        http = AsyncHTTPClient(follow_redirects=False)
        canary = f"mtb-{secrets.token_hex(4)}.example"
        header_tests = {
            "X-Forwarded-Host": canary,
            "X-Forwarded-Scheme": "http",
            "X-Original-URL": f"/{canary}",
            "X-Rewrite-URL": f"/{canary}",
            "X-Host": canary,
        }
        tested: set[tuple[str, str]] = set()
        try:
            for url in list(dict.fromkeys(endpoints))[:8]:
                for header, value in header_tests.items():
                    if (url, header) in tested:
                        continue
                    tested.add((url, header))
                    try:
                        response = await http.get(url, headers={header: value})
                    except Exception:
                        continue
                    reflected = canary in response.body or canary in str(response.headers)
                    cached = any(response.header(name) for name in CACHE_HEADERS)
                    if header.startswith("X-Original") and response.status_code == 200:
                        reflected = True
                    if not reflected:
                        continue
                    yield self.create_finding(
                        title=f"Posible cache poisoning mediante {header}",
                        description=(
                            f"La cabecera {header} se refleja en la respuesta y hay indicios de caché compartida. "
                            "Si el proxy cachea la variante, un atacante podría envenenar contenido para otros usuarios."
                        ),
                        severity=Severity.MEDIUM if cached else Severity.LOW,
                        cvss_score=6.1 if cached else 3.7,
                        confidence=Confidence.MEDIUM if cached else Confidence.LOW,
                        cwe="CWE-444",
                        owasp="A05:2021 Security Misconfiguration",
                        endpoint=url,
                        target_host=target.host,
                        evidence={
                            "header": header,
                            "value": value,
                            "reflected": reflected,
                            "cache_headers": {
                                name: response.header(name) for name in CACHE_HEADERS if response.header(name)
                            },
                            "status": response.status_code,
                            "requires_manual_validation": True,
                        },
                        remediation=(
                            "Normaliza y valida cabeceras de proxy en el edge, no las incluyas en la clave de caché "
                            "sin allowlist y desactiva el cacheo de respuestas que reflejan entrada."
                        ),
                    )
        finally:
            await http.close()
