"""SSTI detection with random arithmetic canaries and baseline comparison."""

from __future__ import annotations

import logging
import random
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo

logger = logging.getLogger("marlonthebug.plugins.web.ssti")

TEMPLATE_PARAMS = ["template", "view", "tpl", "page", "name", "email", "subject", "message", "content", "render"]

# Builders avoid static results like 49 that may already exist in the page.
SSTI_BUILDERS = [
    ("Jinja2/Twig", lambda a, b: f"{{{{{a}*{b}}}}}"),
    ("FreeMarker", lambda a, b: f"${{{a}*{b}}}"),
    ("ERB/Ruby", lambda a, b: f"<%= {a}*{b} %>"),
    ("Ruby interpolation", lambda a, b: f"#{{{a}*{b}}}"),
    ("Spring EL", lambda a, b: f"*{{{a}*{b}}}"),
]


class SSTIAuditor(BasePlugin):
    name = "ssti"
    version = "2.0.0"
    description = "Detecta SSTI con canarios aritméticos aleatorios y baseline"
    category = "web"
    cwe = "CWE-1336"
    owasp = "A03:2021 Injection"

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        options = options or {}
        base_url = str(options.get("base_url") or f"https://{target.host}").rstrip("/")
        endpoints = list(options.get("endpoints") or [])
        http = AsyncHTTPClient()
        reported: set[tuple[str, str]] = set()
        try:
            urls = [url for url in endpoints if "?" in url and "=" in url]
            for param in TEMPLATE_PARAMS:
                urls.append(f"{base_url}?{param}=test")
            for url in list(dict.fromkeys(urls))[:25]:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if not params:
                    continue
                try:
                    baseline = await http.get(url)
                except Exception:
                    continue
                for param in list(params.keys())[:6]:
                    if (url, param) in reported:
                        continue
                    a = random.randint(13, 97)
                    b = random.randint(13, 97)
                    expected = str(a * b)
                    if expected in baseline.body:
                        continue
                    for label, builder in SSTI_BUILDERS:
                        payload = builder(a, b)
                        test_params = {key: values[0] for key, values in params.items()}
                        test_params[param] = payload
                        test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                        try:
                            response = await http.get(test_url)
                        except Exception:
                            continue
                        if expected not in response.body:
                            continue
                        if payload in response.body:
                            # The server echoed the payload without evaluating it.
                            continue
                        reported.add((url, param))
                        yield self.create_finding(
                            title=f"SSTI en '{param}' — {label}",
                            description=(
                                f"El parámetro '{param}' evalúa expresiones de plantilla. "
                                f"El payload {payload!r} produjo {expected!r} y no fue reflejado literalmente."
                            ),
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            confidence=Confidence.HIGH,
                            cwe="CWE-1336",
                            owasp="A03:2021 Injection",
                            endpoint=url,
                            target_host=target.host,
                            evidence={
                                "parameter": param,
                                "payload": payload,
                                "expected": expected,
                                "engine": label,
                                "test_url": test_url,
                                "baseline_contains_result": False,
                                "response_snippet": response.body[:1500],
                                "random_canary": True,
                            },
                            remediation=(
                                "No pases entrada del usuario a motores de plantilla. Usa plantillas estáticas, "
                                "sandbox de evaluación y allowlists de variables."
                            ),
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection"
                            ],
                        )
                        break
        finally:
            await http.close()
