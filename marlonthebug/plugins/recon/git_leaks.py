"""Git exposure detection with strict content validation.

An HTTP 200 is not evidence of an exposed repository.  The plugin only reports
when it can prove the response is a real Git object/configuration file and not
a SPA catch-all page.
"""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo

logger = logging.getLogger("marlonthebug.plugins.recon.git_leaks")

GIT_HEAD_RE = re.compile(r"^(ref:\s+refs/[^\n]+|[0-9a-f]{40})\s*$", re.MULTILINE)
GIT_CONFIG_RE = re.compile(r"\[core\]", re.IGNORECASE)
GIT_LOG_RE = re.compile(r"^[0-9a-f]{40} [0-9a-f]{40} .+ <.+> \d+ [+-]\d{4}", re.MULTILINE)
PACK_RE = re.compile(r"P pack-([0-9a-f]{40})\.pack")
SECRET_PATTERNS = [
    (r"(?i)AKIA[0-9A-Z]{16}", "AWS Access Key", Severity.HIGH, 8.0),
    (r"(?i)gh[pousr]_[A-Za-z0-9_]{36,}", "GitHub Token", Severity.CRITICAL, 9.0),
    (r"(?i)(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}", "Stripe API Key", Severity.CRITICAL, 9.0),
    (r"(?i)-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key", Severity.CRITICAL, 9.5),
    (r"(?i)(?:mongodb|postgres|mysql|redis)://[^\s\"'<>]+", "Database URI", Severity.CRITICAL, 9.0),
    (r"(?i)(?:api[_-]?key|apikey|secret)\s*=\s*['\"]?([^\s'\"]{8,})", "API Key in config", Severity.HIGH, 7.5),
]


class GitLeakDetector(BasePlugin):
    name = "git_leaks"
    version = "2.0.0"
    description = "Detecta .git expuesto y extrae metadatos solo tras validar el contenido real"
    category = "recon"

    GIT_PATHS = [
        ".git/HEAD",
        ".git/config",
        ".git/description",
        ".git/index",
        ".git/logs/HEAD",
        ".git/logs/refs/heads/master",
        ".git/logs/refs/heads/main",
        ".git/refs/heads/master",
        ".git/refs/heads/main",
        ".git/packed-refs",
        ".git/objects/info/packs",
    ]

    async def run(
        self,
        target: TargetInfo,
        options: dict | None = None,
    ) -> AsyncIterator[Finding]:
        options = options or {}
        base_url = str(options.get("base_url") or f"https://{target.host}").rstrip("/")
        baseline = options.get("baseline")
        http = AsyncHTTPClient(timeout=8, retries=1)
        try:
            head = await self._fetch_valid(http, f"{base_url}/.git/HEAD", GIT_HEAD_RE, baseline)
            if not head:
                return
            yield Finding(
                plugin_name=self.name,
                title=f"Repositorio Git expuesto en {target.host}",
                description=(
                    "El directorio .git es accesible públicamente y el archivo HEAD contiene una "
                    "referencia Git válida. Esto permite reconstruir código fuente, historial y secretos."
                ),
                severity=Severity.CRITICAL,
                cvss_score=9.0,
                confidence=Confidence.HIGH,
                endpoint=f"{base_url}/.git/HEAD",
                target_host=target.host,
                category=self.category,
                cwe="CWE-538",
                owasp="A05:2021 Security Misconfiguration",
                evidence={"validated": True, "head": head.body[:200]},
                remediation=(
                    "Bloquea el acceso a /.git en nginx/Apache, elimina el directorio del documento root "
                    "y rota cualquier secreto que pueda haber estado expuesto."
                ),
                references=["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"],
                waf_rules=[
                    "# nginx: bloquear .git",
                    "location ~ /\\.git { deny all; return 403; }",
                    "# Apache: bloquear .git",
                    '<DirectoryMatch "^/.*/\\.git/">',
                    "    Require all denied",
                    "</DirectoryMatch>",
                ],
            )

            config = await self._fetch_valid(http, f"{base_url}/.git/config", GIT_CONFIG_RE, baseline)
            if config:
                yield Finding(
                    plugin_name=self.name,
                    title=".git/config expuesto",
                    description="La configuración del repositorio Git es pública e incluye la sección [core].",
                    severity=Severity.HIGH,
                    cvss_score=8.5,
                    confidence=Confidence.HIGH,
                    endpoint=f"{base_url}/.git/config",
                    target_host=target.host,
                    category=self.category,
                    cwe="CWE-538",
                    owasp="A05:2021 Security Misconfiguration",
                    evidence={"file": ".git/config", "content": config.body[:1000]},
                    remediation="Bloquea .git y rota cualquier credencial o URL interna expuesta en la configuración.",
                )
                async for secret in self._secrets(config.body, target.host, f"{base_url}/.git/config"):
                    yield secret

            logs = await self._fetch_valid(http, f"{base_url}/.git/logs/HEAD", GIT_LOG_RE, baseline)
            if logs:
                yield Finding(
                    plugin_name=self.name,
                    title="Historial de referencias Git expuesto",
                    description="El archivo .git/logs/HEAD expone hashes y actividad del repositorio.",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    confidence=Confidence.HIGH,
                    endpoint=f"{base_url}/.git/logs/HEAD",
                    target_host=target.host,
                    category=self.category,
                    cwe="CWE-538",
                    evidence={"lines": logs.body.splitlines()[:10]},
                    remediation="Bloquea .git/ completo en el servidor web.",
                )

            if self.options.get("check_commits", False):
                packs = await self._fetch_valid(http, f"{base_url}/.git/objects/info/packs", PACK_RE, baseline)
                if packs:
                    for pack_hash in PACK_RE.findall(packs.body)[:3]:
                        yield Finding(
                            plugin_name=self.name,
                            title=f"Pack file de Git expuesto: {pack_hash[:8]}",
                            description="Un pack file del repositorio es descargable y puede contener el historial completo.",
                            severity=Severity.HIGH,
                            cvss_score=8.0,
                            confidence=Confidence.HIGH,
                            endpoint=f"{base_url}/.git/objects/pack/pack-{pack_hash}.pack",
                            target_host=target.host,
                            category=self.category,
                            evidence={"pack": f"pack-{pack_hash}.pack"},
                            remediation="Bloquea .git y asume compromiso del código fuente.",
                        )
        finally:
            await http.close()

    async def _fetch_valid(self, http, url: str, pattern: re.Pattern, baseline):
        try:
            response = await http.get(url)
        except Exception:
            return None
        if response.status_code != 200 or not response.body:
            return None
        if baseline and baseline.looks_like_app_shell(response):
            return None
        if not pattern.search(response.body):
            return None
        return response

    async def _secrets(self, content: str, host: str, endpoint: str) -> AsyncIterator[Finding]:
        seen: set[str] = set()
        for pattern, name, severity, score in SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                value = match.group(0)
                if value in seen:
                    continue
                seen.add(value)
                yield Finding(
                    plugin_name=self.name,
                    title=f"{name} expuesto en .git/config",
                    description=f"Se ha encontrado un {name} en la configuración pública del repositorio.",
                    severity=severity,
                    cvss_score=score,
                    confidence=Confidence.HIGH,
                    endpoint=endpoint,
                    target_host=host,
                    category=self.category,
                    cwe="CWE-798",
                    owasp="A07:2021 Identification and Authentication Failures",
                    evidence={"type": name, "match": value[:120]},
                    remediation=f"Rota el {name.lower()} inmediatamente y elimina el secreto del historial.",
                )
