"""JWT security analysis — algorithm confusion, weak secrets and claim hygiene."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo

logger = logging.getLogger("marlonthebug.plugins.api.jwt")

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,}")
WEAK_SECRETS = [
    "secret",
    "password",
    "123456",
    "changeme",
    "jwt",
    "jwtsecret",
    "supersecret",
    "your-256-bit-secret",
    "secretkey",
    "mysecret",
    "admin",
    "test",
    "development",
    "key",
    "token",
    "marlonthebug",
    "default",
    "private",
    "shhhh",
]


class JWTAuditor(BasePlugin):
    name = "jwt"
    version = "2.0.0"
    description = "Analiza tokens JWT: alg none, secretos débiles, expiración y claims peligrosos"
    category = "api"
    cwe = "CWE-347"
    owasp = "A02:2021 Cryptographic Failures"
    beta = False

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        options = options or {}
        base_url = str(options.get("base_url") or f"https://{target.host}").rstrip("/")
        http = AsyncHTTPClient()
        tokens: dict[str, str] = {}
        try:
            for name, value in (options.get("cookies") or {}).items():
                if value.count(".") == 2 and value.startswith("eyJ"):
                    tokens[value] = f"cookie:{name}"
            for name, value in (options.get("headers") or {}).items():
                if name.lower() == "authorization":
                    for token in JWT_RE.findall(str(value)):
                        tokens[token] = "header:authorization"
            for url in [base_url, *list(options.get("endpoints") or [])[:20]]:
                try:
                    response = await http.get(url)
                except Exception:
                    continue
                for token in set(JWT_RE.findall(response.body)):
                    tokens[token] = url
                for name, value in response.headers.items():
                    if name.lower() in {"set-cookie", "authorization"}:
                        for token in JWT_RE.findall(value):
                            tokens[token] = f"response:{url}"
            for token, source in list(tokens.items())[:10]:
                async for finding in self._analyze(token, source, target):
                    yield finding
        finally:
            await http.close()

    async def _analyze(self, token: str, source: str, target: TargetInfo) -> AsyncIterator[Finding]:
        parts = token.split(".")
        if len(parts) != 3:
            return
        header = _decode(parts[0])
        payload = _decode(parts[1])
        if not isinstance(payload, dict) or "alg" not in header:
            return
        alg = str(header.get("alg", "")).lower()
        claims = {
            "header": header,
            "payload": {key: value for key, value in payload.items() if key.lower() not in {"password", "secret"}},
            "source": source,
        }

        if alg == "none":
            yield self.create_finding(
                title="JWT con algoritmo 'none'",
                description="El token declara alg=none, lo que permite modificar claims sin firma si el servidor lo acepta.",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                confidence=Confidence.HIGH,
                cwe="CWE-347",
                owasp="A02:2021 Cryptographic Failures",
                endpoint=source if "://" in source else f"https://{target.host}",
                target_host=target.host,
                evidence={**claims, "token_preview": token[:30] + "…"},
                remediation="Rechaza alg=none, fija el algoritmo esperado y valida la firma en cada petición.",
            )
            return

        if alg in {"hs256", "hs384", "hs512"}:
            digest = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}[alg]
            for secret in WEAK_SECRETS:
                expected = hmac.new(secret.encode(), f"{parts[0]}.{parts[1]}".encode(), digest).digest()
                if hmac.compare_digest(expected, _b64decode(parts[2])):
                    yield self.create_finding(
                        title="JWT firmado con un secreto débil",
                        description=f"El token se puede firmar con el secreto '{secret}', permitiendo falsificar identidad y claims.",
                        severity=Severity.CRITICAL,
                        cvss_score=9.1,
                        confidence=Confidence.HIGH,
                        cwe="CWE-798",
                        owasp="A02:2021 Cryptographic Failures",
                        endpoint=source if "://" in source else f"https://{target.host}",
                        target_host=target.host,
                        evidence={**claims, "weak_secret": secret},
                        remediation="Rota el secreto por una clave aleatoria de al menos 256 bits y gestiona los secretos fuera del código.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens"
                        ],
                    )
                    return

        if "exp" not in payload:
            yield self.create_finding(
                title="JWT sin expiración",
                description="El token no incluye el claim exp, por lo que puede reutilizarse indefinidamente si no hay otras revocaciones.",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                confidence=Confidence.HIGH,
                cwe="CWE-613",
                owasp="A07:2021 Identification and Authentication Failures",
                endpoint=source if "://" in source else f"https://{target.host}",
                target_host=target.host,
                evidence=claims,
                remediation="Incluye exp, iat y una rotación/revocación de tokens; usa refresh tokens de corta duración.",
            )

        kid = str(header.get("kid", ""))
        if kid and (any(char in kid for char in ("../", "/", "\\", "'", '"', "|")) or "http" in kid.lower()):
            yield self.create_finding(
                title="JWT con 'kid' potencialmente inyectable",
                description="El header kid contiene caracteres de ruta o consulta; si se usa para cargar claves puede permitir path traversal o inyección.",
                severity=Severity.MEDIUM,
                cvss_score=6.5,
                confidence=Confidence.MEDIUM,
                cwe="CWE-22",
                owasp="A02:2021 Cryptographic Failures",
                endpoint=source if "://" in source else f"https://{target.host}",
                target_host=target.host,
                evidence={**claims, "kid": kid},
                remediation="Valida kid contra una lista de claves conocidas y no lo uses directamente en rutas o consultas.",
            )

        if any(key in header for key in ("jku", "x5u")):
            yield self.create_finding(
                title="JWT con JWKS remoto controlable",
                description="El token incluye jku/x5u. Si el servidor acepta URLs arbitrarias, un atacante puede alojar su propia JWKS y firmar tokens.",
                severity=Severity.HIGH,
                cvss_score=8.1,
                confidence=Confidence.MEDIUM,
                cwe="CWE-918",
                owasp="A02:2021 Cryptographic Failures",
                endpoint=source if "://" in source else f"https://{target.host}",
                target_host=target.host,
                evidence={**claims, "jku": header.get("jku"), "x5u": header.get("x5u")},
                remediation="Restringe jku/x5u a dominios de confianza y valida la clave contra una allowlist.",
            )


def _decode(part: str) -> dict:
    try:
        padded = part + "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


def _b64decode(part: str) -> bytes:
    try:
        padded = part + "=" * (-len(part) % 4)
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return b""


def _snippet(value: str, length: int = 120) -> str:
    return value[:length] + ("…" if len(value) > length else "")
