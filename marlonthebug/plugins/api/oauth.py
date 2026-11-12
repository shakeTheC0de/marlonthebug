"""OAuth 2.0 / OIDC checks — redirect URI, state and implicit flow."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo

logger = logging.getLogger("marlonthebug.plugins.api.oauth")

CANARY = "https://marlonthebug-canary.example/callback"
AUTH_MARKERS = (
    "/oauth",
    "/authorize",
    "/authorization",
    "/connect/authorize",
    "/auth?",
    "response_type=",
    "client_id=",
)


class OAuthAuditor(BasePlugin):
    name = "oauth"
    version = "2.0.0"
    description = "Revisa flujos OAuth/OIDC: redirect_uri, state, respuesta implícita y endpoints de autorización"
    category = "api"
    cwe = "CWE-601"
    owasp = "A01:2021 Broken Access Control"
    beta = True

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        options = options or {}
        base_url = str(options.get("base_url") or f"https://{target.host}").rstrip("/")
        endpoints = list(options.get("endpoints") or [])
        http = AsyncHTTPClient(follow_redirects=False)
        candidates = [url for url in endpoints if any(marker in url for marker in AUTH_MARKERS)]
        if not candidates:
            candidates = [f"{base_url}/oauth/authorize", f"{base_url}/authorize", f"{base_url}/auth"]
        tested: set[str] = set()
        try:
            for url in candidates[:15]:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if "client_id" not in params and "response_type" not in params:
                    continue
                key = parsed.netloc + parsed.path
                if key in tested:
                    continue
                tested.add(key)
                response_type = (params.get("response_type") or [""])[0]
                if response_type == "token":
                    yield self.create_finding(
                        title="OAuth con flujo implícito (response_type=token)",
                        description="El endpoint de autorización admite el flujo implícito, que expone access tokens en la URL y está desaconsejado.",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        confidence=Confidence.HIGH,
                        cwe="CWE-522",
                        owasp="A07:2021 Identification and Authentication Failures",
                        endpoint=url,
                        target_host=target.host,
                        evidence={"response_type": response_type},
                        remediation="Usa Authorization Code con PKCE y elimina el flujo implícito.",
                    )
                if not params.get("state"):
                    yield self.create_finding(
                        title="OAuth sin parámetro state",
                        description="La petición de autorización no incluye state, lo que facilita ataques CSRF sobre el flujo OAuth.",
                        severity=Severity.MEDIUM,
                        cvss_score=5.4,
                        confidence=Confidence.MEDIUM,
                        cwe="CWE-352",
                        owasp="A01:2021 Broken Access Control",
                        endpoint=url,
                        target_host=target.host,
                        evidence={"parameters": list(params.keys())},
                        remediation="Genera un state aleatorio por sesión y valídalo en el callback.",
                    )
                redirect = (params.get("redirect_uri") or [""])[0]
                if redirect:
                    mutated = {key: values[0] for key, values in params.items()}
                    mutated["redirect_uri"] = CANARY
                    test_url = urlunparse(parsed._replace(query=urlencode(mutated)))
                    try:
                        response = await http.get(test_url)
                    except Exception:
                        continue
                    location = response.headers.get("location", "")
                    if response.status_code in (301, 302, 303, 307, 308) and location.startswith(CANARY):
                        yield self.create_finding(
                            title="OAuth redirect_uri sin validación",
                            description=(
                                "El servidor de autorización redirige a un redirect_uri arbitrario. "
                                "Un atacante puede robar el código de autorización y tomar la cuenta."
                            ),
                            severity=Severity.CRITICAL,
                            cvss_score=9.1,
                            confidence=Confidence.HIGH,
                            cwe="CWE-601",
                            owasp="A01:2021 Broken Access Control",
                            endpoint=url,
                            target_host=target.host,
                            evidence={
                                "original_redirect_uri": redirect,
                                "tested_redirect_uri": CANARY,
                                "status": response.status_code,
                                "location": location[:300],
                            },
                            remediation="Valida redirect_uri contra una allowlist exacta por cliente y rechaza coincidencias por prefijo.",
                            references=["https://datatracker.ietf.org/doc/html/rfc9700"],
                        )
        finally:
            await http.close()
