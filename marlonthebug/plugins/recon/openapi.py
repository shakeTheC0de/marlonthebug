"""Exposed OpenAPI/Swagger specification discovery.

A public API specification is valuable reconnaissance: it enumerates routes,
authentication schemes and request models. The plugin reports the exposure and
adds every documented path to the scan context so the rest of the assessment
can target real endpoints instead of guessing.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo, Workspace

logger = logging.getLogger("marlonthebug.plugins.recon.openapi")

SPEC_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api/docs-json",
    "/api/docs-json/",
    "/api/v3/api-docs",
    "/v3/api-docs",
    "/api/docs/swagger.json",
    "/docs/swagger.json",
)


class OpenAPIDiscovery(BasePlugin):
    name = "openapi"
    version = "1.0.0"
    description = "Detecta especificaciones OpenAPI/Swagger expuestas y extrae sus endpoints"
    category = "recon"
    beta = False

    async def setup(self, workspace: Workspace) -> None:
        self._workspace = workspace

    async def run(
        self,
        target: TargetInfo,
        options: dict | None = None,
    ) -> AsyncIterator[Finding]:
        options = options or {}
        base_url = str(options.get("base_url") or f"https://{target.host}").rstrip("/")
        http = AsyncHTTPClient(timeout=12, retries=1, verify_ssl=True)
        try:
            for spec_path in SPEC_PATHS:
                url = urljoin(base_url + "/", spec_path.lstrip("/"))
                try:
                    response = await http.get(url)
                except Exception as exc:
                    logger.debug("OpenAPI probe failed for %s: %s", url, exc)
                    continue
                if response.status_code != 200:
                    continue
                if "json" not in response.content_type:
                    continue
                try:
                    spec = json.loads(response.body)
                except (TypeError, ValueError):
                    continue
                if not isinstance(spec, dict) or not (spec.get("openapi") or spec.get("swagger")):
                    continue
                paths = spec.get("paths")
                if not isinstance(paths, dict) or not paths:
                    continue

                documented: list[str] = []
                for path, _item in paths.items():
                    if not isinstance(path, str) or not path.startswith("/"):
                        continue
                    documented.append(path)
                    if self._context is not None:
                        full_url = urljoin(base_url + "/", path.lstrip("/"))
                        if full_url not in self._context.endpoints:
                            self._context.endpoints.append(full_url)
                if not documented:
                    continue

                title = str(spec.get("info", {}).get("title", "API"))
                version = str(spec.get("info", {}).get("version", ""))
                schemes = sorted((spec.get("components", {}).get("securitySchemes") or {}).keys())
                public_operations = 0
                for item in paths.values():
                    if not isinstance(item, dict):
                        continue
                    for operation in item.values():
                        if isinstance(operation, dict) and not operation.get("security"):
                            public_operations += 1
                description = (
                    f"La especificación OpenAPI de {title} está accesible públicamente en {url}. "
                    f"Documenta {len(documented)} rutas y {len(schemes)} esquema(s) de autenticación. "
                    "Puede revelar rutas internas, modelos de datos y parámetros no previstos para clientes externos."
                )
                yield Finding(
                    plugin_name=self.name,
                    title=f"Especificación OpenAPI expuesta: {spec_path}",
                    description=description,
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    confidence=Confidence.HIGH,
                    endpoint=url,
                    target_host=target.host,
                    category=self.category,
                    cwe="CWE-200",
                    owasp="A05:2021 Security Misconfiguration",
                    evidence={
                        "spec_url": url,
                        "title": title,
                        "version": version,
                        "path_count": len(documented),
                        "paths": documented[:200],
                        "security_schemes": schemes,
                        "public_operations": public_operations,
                    },
                    remediation=(
                        "Restringe /api/docs y la especificación OpenAPI a redes internas, "
                        "elimínalos en producción o protégelos con autenticación."
                    ),
                    references=["https://owasp.org/www-project-api-security/"],
                )
                return
        finally:
            await http.close()
