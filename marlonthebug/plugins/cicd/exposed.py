"""CI/CD configuration exposure checks."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo

logger = logging.getLogger("marlonthebug.plugins.cicd.exposed")

CHECKS = [
    (".gitlab-ci.yml", ("stages:", "script:", "job"), "GitLab CI"),
    (".github/workflows/ci.yml", ("on:", "jobs:", "steps:"), "GitHub Actions"),
    (".github/workflows/main.yml", ("on:", "jobs:", "steps:"), "GitHub Actions"),
    ("Jenkinsfile", ("pipeline {", "agent any", "stages {"), "Jenkins"),
    (".travis.yml", ("language:", "script:", "jobs:"), "Travis CI"),
    ("azure-pipelines.yml", ("trigger:", "pool:", "steps:"), "Azure Pipelines"),
    ("bitbucket-pipelines.yml", ("pipelines:", "image:", "step:"), "Bitbucket Pipelines"),
    ("docker-compose.yml", ("services:", "image:", "volumes:"), "Docker Compose"),
    ("Dockerfile", ("from ", "run ", "cmd "), "Dockerfile"),
]


class CICDExposureAuditor(BasePlugin):
    name = "cicd_exposed"
    version = "1.0.0"
    description = "Detecta pipelines y manifiestos de CI/CD públicos con posibles secretos o rutas internas"
    category = "cicd"
    cwe = "CWE-538"
    owasp = "A05:2021 Security Misconfiguration"
    beta = True

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        options = options or {}
        base_url = str(options.get("base_url") or f"https://{target.host}").rstrip("/")
        baseline = options.get("baseline")
        http = AsyncHTTPClient()
        try:
            for path, markers, product in CHECKS:
                url = f"{base_url}/{path}"
                try:
                    response = await http.get(url)
                except Exception:
                    continue
                if response.status_code != 200:
                    continue
                if baseline and baseline.looks_like_app_shell(response):
                    continue
                body = response.body.lower()
                if not any(marker in body for marker in markers):
                    continue
                yield self.create_finding(
                    title=f"Configuración de {product} expuesta: {path}",
                    description=(
                        f"El archivo {path} es público y contiene la definición de un pipeline de {product}. "
                        "Puede revelar nombres de entornos, imágenes internas, comandos de despliegue y "
                        "referencias a secretos."
                    ),
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    confidence=Confidence.HIGH,
                    cwe="CWE-538",
                    owasp="A05:2021 Security Misconfiguration",
                    endpoint=url,
                    target_host=target.host,
                    evidence={
                        "file": path,
                        "product": product,
                        "content_type": response.content_type,
                        "snippet": response.body[:500],
                    },
                    remediation=(
                        "Elimina los archivos de pipeline del directorio público, bloquea su acceso, "
                        "sirve solo artefactos compilados y rota cualquier secreto referenciado."
                    ),
                )
        finally:
            await http.close()
