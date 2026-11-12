"""Mass assignment checks for registration/profile APIs."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo

logger = logging.getLogger("marlonthebug.plugins.api.mass_assignment")

MARKERS = ("/register", "/signup", "/users", "/profile", "/account", "/me", "/api/v1/user")
EXTRA_FIELDS = {
    "is_admin": True,
    "role": "admin",
    "verified": True,
    "email_verified": True,
    "balance": 999999,
    "permissions": ["admin"],
}


class MassAssignmentAuditor(BasePlugin):
    name = "mass_assignment"
    version = "1.0.0"
    description = "Prueba asignación masiva de campos privilegiados en APIs de registro/perfil"
    category = "api"
    cwe = "CWE-915"
    owasp = "API3:2023 Broken Object Property Level Authorization"
    beta = True

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        options = options or {}
        base_url = str(options.get("base_url") or f"https://{target.host}").rstrip("/")
        endpoints = list(options.get("endpoints") or [])
        headers = dict(options.get("headers") or {})
        candidates = [url for url in endpoints if any(marker in url.lower() for marker in MARKERS)]
        if not candidates:
            candidates = [f"{base_url}/api/register", f"{base_url}/api/users", f"{base_url}/api/profile"]
        http = AsyncHTTPClient()
        try:
            for url in list(dict.fromkeys(candidates))[:6]:
                baseline_payload = {
                    "name": "Marlon TheBug",
                    "email": "mtb-audit@example.com",
                    "password": "Mtb-Audit-2026!",
                }
                try:
                    baseline = await http.post(
                        url, json=baseline_payload, headers={"Content-Type": "application/json", **headers}
                    )
                except Exception:
                    continue
                if baseline.status_code not in (200, 201):
                    continue
                try:
                    attack_payload = {**baseline_payload, **EXTRA_FIELDS}
                    response = await http.post(
                        url, json=attack_payload, headers={"Content-Type": "application/json", **headers}
                    )
                except Exception:
                    continue
                if not response.is_json:
                    continue
                try:
                    body = json.loads(response.body)
                except Exception:
                    continue
                reflected = _find_privileged_fields(body)
                if not reflected:
                    continue
                yield self.create_finding(
                    title="Posible mass assignment en endpoint de usuario",
                    description=(
                        f"El endpoint {url} acepta y refleja campos privilegiados enviados por el cliente "
                        f"({', '.join(reflected)}). Si persiste esos valores, un usuario podría elevar privilegios."
                    ),
                    severity=Severity.HIGH,
                    cvss_score=8.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    confidence=Confidence.MEDIUM,
                    cwe="CWE-915",
                    owasp="API3:2023 Broken Object Property Level Authorization",
                    endpoint=url,
                    target_host=target.host,
                    evidence={
                        "reflected_fields": reflected,
                        "status": response.status_code,
                        "sent_fields": list(EXTRA_FIELDS.keys()),
                        "requires_manual_validation": True,
                    },
                    remediation=(
                        "Usa DTOs o allowlists explícitas de campos aceptados y nunca asignes el cuerpo "
                        "completo de la petición al modelo de usuario."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"
                    ],
                )
        finally:
            await http.close()


def _find_privileged_fields(value, depth: int = 0) -> list[str]:
    found: list[str] = []
    if depth > 3:
        return found
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in EXTRA_FIELDS and item in (True, "admin", 999999, ["admin"]):
                found.append(key)
            found.extend(_find_privileged_fields(item, depth + 1))
    elif isinstance(value, list):
        for item in value[:5]:
            found.extend(_find_privileged_fields(item, depth + 1))
    return sorted(set(found))
