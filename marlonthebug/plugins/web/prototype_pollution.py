"""Prototype pollution heuristics — client-side sinks and reflected pollution."""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo

logger = logging.getLogger("marlonthebug.plugins.web.prototype_pollution")

SINKS = [
    (r"Object\.assign\s*\(", "Object.assign con fuente controlable"),
    (r"\$\.extend\s*\(\s*true", "jQuery.extend profundo"),
    (r"\b_\.merge\s*\(", "lodash.merge"),
    (r"\bmerge\s*\(\s*\{?\s*\.\.\.", "merge con spread"),
    (r"deepMerge\s*\(", "deepMerge"),
    (r"\[[^\]]+\]\s*=\s*[^=]", "asignación dinámica de propiedades"),
]
USER_INPUT = re.compile(r"(location\.(hash|search)|URLSearchParams|document\.cookie|postMessage)", re.IGNORECASE)
PAYLOADS = {
    "__proto__[mtb_polluted]": "mtb",
    "constructor[prototype][mtb_polluted]": "mtb",
    "mtb_polluted": "mtb",
}


class PrototypePollutionAuditor(BasePlugin):
    name = "prototype_pollution"
    version = "1.0.0"
    description = "Busca sinks de prototype pollution en JavaScript y reflejo de parámetros __proto__"
    category = "web"
    cwe = "CWE-1321"
    owasp = "A03:2021 Injection"
    beta = True

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        options = options or {}
        base_url = str(options.get("base_url") or f"https://{target.host}").rstrip("/")
        endpoints = list(options.get("endpoints") or [])
        http = AsyncHTTPClient()
        try:
            js_files = [url for url in endpoints if url.endswith(".js")][:12]
            if not js_files:
                try:
                    home = await http.get(base_url)
                    js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', home.body, re.IGNORECASE)[
                        :12
                    ]
                except Exception:
                    js_files = []
            reported = set()
            for raw_url in js_files:
                url = raw_url
                if not url.startswith("http"):
                    from urllib.parse import urljoin

                    url = urljoin(base_url + "/", url)
                try:
                    response = await http.get(url)
                except Exception:
                    continue
                if response.status_code != 200 or len(response.body) < 200:
                    continue
                for pattern, label in SINKS:
                    if not re.search(pattern, response.body):
                        continue
                    if not USER_INPUT.search(response.body):
                        continue
                    key = (url, label)
                    if key in reported:
                        continue
                    reported.add(key)
                    yield self.create_finding(
                        title=f"Posible sink de prototype pollution en {url.rsplit('/', 1)[-1]}",
                        description=(
                            f"El bundle {url} combina {label} con entrada controlable por el usuario "
                            "(location/URLSearchParams/cookies). Requiere revisión manual del flujo."
                        ),
                        severity=Severity.LOW,
                        cvss_score=3.7,
                        confidence=Confidence.LOW,
                        cwe="CWE-1321",
                        owasp="A03:2021 Injection",
                        endpoint=url,
                        target_host=target.host,
                        evidence={"sink": label, "bundle": url, "requires_manual_validation": True},
                        remediation=(
                            "Evita merges recursivos con objetos controlados por el usuario, usa Object.create(null), "
                            "bloquea __proto__/constructor/prototype y actualiza librerías vulnerables."
                        ),
                    )
                    break

            # Reflected pollution check on JSON endpoints.
            for url in [item for item in endpoints if "?" in item][:8]:
                parsed = urlparse(url)
                query = parse_qs(parsed.query)
                if not query:
                    continue
                for payload_key, value in PAYLOADS.items():
                    mutated = {name: values[0] for name, values in query.items()}
                    mutated[payload_key] = value
                    test_url = urlunparse(parsed._replace(query=urlencode(mutated)))
                    try:
                        response = await http.get(test_url)
                    except Exception:
                        continue
                    if not response.is_json or "mtb_polluted" not in response.body:
                        continue
                    yield self.create_finding(
                        title="Reflejo de parámetros de prototype pollution",
                        description=(
                            "El endpoint devuelve el parámetro __proto__/constructor en la respuesta JSON. "
                            "Puede indicar que el objeto se fusiona sin sanitizar; validar manualmente."
                        ),
                        severity=Severity.LOW,
                        cvss_score=3.7,
                        confidence=Confidence.LOW,
                        cwe="CWE-1321",
                        owasp="A03:2021 Injection",
                        endpoint=test_url,
                        target_host=target.host,
                        evidence={"payload": payload_key, "response_snippet": response.body[:300]},
                        remediation="Sanitiza claves peligrosas y evita merges recursivos de objetos no confiables.",
                    )
                    break
        finally:
            await http.close()
