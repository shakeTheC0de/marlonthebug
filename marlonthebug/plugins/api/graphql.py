"""GraphQL introspection and endpoint exposure checks."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo

logger = logging.getLogger("marlonthebug.plugins.api.graphql")

INTROSPECTION = {"query": "{ __schema { queryType { name } types { name kind } } }"}


class GraphQLAuditor(BasePlugin):
    name = "graphql"
    version = "2.0.0"
    description = "Detecta GraphQL expuesto e introspección habilitada"
    category = "api"
    cwe = "CWE-200"
    owasp = "API8:2023 Security Misconfiguration"

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        options = options or {}
        base_url = str(options.get("base_url") or f"https://{target.host}").rstrip("/")
        endpoints = list(options.get("endpoints") or [])
        candidates = [url for url in endpoints if "graphql" in url.lower() or "graphiql" in url.lower()]
        candidates += [f"{base_url}/graphql", f"{base_url}/api/graphql", f"{base_url}/v1/graphql"]
        http = AsyncHTTPClient()
        tested: set[str] = set()
        try:
            for url in list(dict.fromkeys(candidates))[:8]:
                if url in tested:
                    continue
                tested.add(url)
                try:
                    response = await http.post(
                        url,
                        json=INTROSPECTION,
                        headers={"Content-Type": "application/json", "Accept": "application/json"},
                    )
                except Exception:
                    continue
                if response.status_code != 200 or "__schema" not in response.body:
                    continue
                if "<html" in response.body[:200].lower():
                    continue
                yield self.create_finding(
                    title="GraphQL con introspección habilitada",
                    description=(
                        f"El endpoint GraphQL {url} acepta consultas de introspección y expone el esquema "
                        "completo (tipos, queries, mutations y campos). Facilita el mapeo de la API."
                    ),
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    confidence=Confidence.HIGH,
                    cwe="CWE-200",
                    owasp="API8:2023 Security Misconfiguration",
                    endpoint=url,
                    target_host=target.host,
                    evidence={
                        "status": response.status_code,
                        "introspection": True,
                        "schema_snippet": response.body[:600],
                    },
                    remediation=(
                        "Deshabilita la introspección en producción, aplica profundidad y complejidad máximas, "
                        "y exige autenticación/autorización por campo."
                    ),
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
                )
        finally:
            await http.close()
