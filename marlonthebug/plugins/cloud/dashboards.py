"""Exposed cloud dashboards and orchestration APIs."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo

logger = logging.getLogger("marlonthebug.plugins.cloud.dashboards")

CHECKS = [
    ("/grafana/login", ("grafana",), "Grafana", "dashboard"),
    ("/kibana", ("kibana",), "Kibana", "dashboard"),
    ("/app/kibana", ("kibana",), "Kibana", "dashboard"),
    ("/jenkins/login", ("jenkins",), "Jenkins", "CI/CD"),
    ("/api/v1/namespaces", ('"kind":"namespacelist"', '"kind": "namespacelist"'), "Kubernetes API", "cluster"),
    ("/version", ('"apiversion"', '"api_version"', '"version"'), "Docker Engine API", "container"),
    ("/actuator/env", ('"propertysources"', '"activeprofiles"'), "Spring Actuator", "application"),
]


class CloudDashboardAuditor(BasePlugin):
    name = "cloud_dashboards"
    version = "1.0.0"
    description = "Detecta dashboards y APIs de cloud/contenedores expuestos sin autenticación"
    category = "cloud"
    cwe = "CWE-306"
    owasp = "A05:2021 Security Misconfiguration"
    beta = True

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        options = options or {}
        base_url = str(options.get("base_url") or f"https://{target.host}").rstrip("/")
        baseline = options.get("baseline")
        http = AsyncHTTPClient()
        try:
            for path, markers, product, kind in CHECKS:
                url = f"{base_url}{path}"
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
                    title=f"{product} expuesto sin autenticación",
                    description=(
                        f"El servicio {product} ({kind}) responde en {url} con contenido identificable "
                        "y sin una redirección de autenticación. Puede exponer datos, configuración o "
                        "capacidades de administración."
                    ),
                    severity=Severity.HIGH if kind in {"cluster", "container"} else Severity.MEDIUM,
                    cvss_score=8.2 if kind in {"cluster", "container"} else 6.5,
                    confidence=Confidence.MEDIUM,
                    cwe="CWE-306",
                    owasp="A05:2021 Security Misconfiguration",
                    endpoint=url,
                    target_host=target.host,
                    evidence={
                        "product": product,
                        "kind": kind,
                        "status": response.status_code,
                        "content_type": response.content_type,
                        "snippet": response.body[:300],
                        "requires_manual_validation": True,
                    },
                    remediation=(
                        "Restringe el acceso por red o VPN, exige autenticación fuerte y MFA, "
                        "y no expongas APIs de administración a Internet."
                    ),
                )
        finally:
            await http.close()
