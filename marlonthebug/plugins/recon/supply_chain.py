"""Supply-chain exposure — public manifests and OSV dependency matching."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo

logger = logging.getLogger("marlonthebug.plugins.recon.supply_chain")


class SupplyChainAuditor(BasePlugin):
    name = "supply_chain"
    version = "1.0.0"
    description = "Detecta manifiestos públicos y correlaciona dependencias con OSV"
    category = "recon"
    cwe = "CWE-1104"
    owasp = "A06:2021 Vulnerable and Outdated Components"
    beta = True

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        options = options or {}
        base_url = str(options.get("base_url") or f"https://{target.host}").rstrip("/")
        baseline = options.get("baseline")
        intel = options.get("intel")
        http = AsyncHTTPClient()
        manifests = {
            "package.json": "npm",
            "composer.json": "Packagist",
            "requirements.txt": "PyPI",
        }
        try:
            for path, ecosystem in manifests.items():
                try:
                    response = await http.get(f"{base_url}/{path}")
                except Exception:
                    continue
                if response.status_code != 200 or len(response.body) < 15:
                    continue
                if baseline and baseline.looks_like_app_shell(response):
                    continue
                dependencies = self._parse_manifest(path, response.body)
                if not dependencies:
                    continue
                url = f"{base_url}/{path}"
                yield self.create_finding(
                    title=f"Manifiesto de dependencias expuesto: {path}",
                    description=(
                        f"El archivo {path} es público y revela {len(dependencies)} dependencias y versiones. "
                        "Facilita la búsqueda de componentes vulnerables y ataques de supply chain."
                    ),
                    severity=Severity.LOW,
                    cvss_score=3.7,
                    confidence=Confidence.HIGH,
                    cwe="CWE-200",
                    owasp="A05:2021 Security Misconfiguration",
                    endpoint=url,
                    target_host=target.host,
                    evidence={"manifest": path, "dependencies": dependencies[:40]},
                    remediation=(
                        "Elimina los manifiestos del directorio público, bloquea su acceso en el servidor "
                        "y sirve solo los artefactos compilados necesarios."
                    ),
                )
                if intel is None:
                    continue
                for name, version in dependencies[:15]:
                    if not version:
                        continue
                    try:
                        vulns = await intel.lookup_osv(ecosystem, name, version)
                    except Exception:
                        continue
                    for vuln in vulns[:2]:
                        score = float(vuln.get("score") or 0)
                        severity = Severity.CRITICAL if score >= 9 else Severity.HIGH if score >= 7 else Severity.MEDIUM
                        kev = False
                        epss = 0.0
                        for alias in [vuln.get("id", ""), *list(vuln.get("aliases", []))]:
                            if not alias:
                                continue
                            cached = await intel.repository.get_cve(alias)
                            if cached:
                                kev = kev or cached.kev
                                epss = max(epss, cached.epss)
                        yield self.create_finding(
                            title=f"Dependencia vulnerable: {name}@{version} ({vuln.get('id', 'OSV')})",
                            description=(
                                f"OSV identifica {vuln.get('id', 'una vulnerabilidad')} en {name}@{version}. "
                                f"{vuln.get('summary', '')}"
                            ),
                            severity=severity,
                            cvss_score=score,
                            confidence=Confidence.HIGH,
                            cwe="CWE-1104",
                            owasp="A06:2021 Vulnerable and Outdated Components",
                            endpoint=url,
                            target_host=target.host,
                            evidence={
                                "package": name,
                                "version": version,
                                "osv_id": vuln.get("id"),
                                "aliases": vuln.get("aliases", []),
                                "summary": vuln.get("summary", ""),
                                "references": vuln.get("references", [])[:10],
                            },
                            remediation=f"Actualiza {name} a una versión corregida y revisa el aviso de OSV.",
                            references=[ref for ref in vuln.get("references", [])[:5] if ref],
                            kev=kev,
                            epss=epss,
                        )
        finally:
            await http.close()

    @staticmethod
    def _parse_manifest(path: str, body: str) -> list[tuple[str, str]]:
        dependencies: list[tuple[str, str]] = []
        if path.endswith(".json"):
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                return []
            for section in ("dependencies", "devDependencies", "require"):
                for name, version in (data.get(section) or {}).items():
                    cleaned = re.sub(r"^[~^>=<\s]+", "", str(version)).split(" ")[0]
                    dependencies.append((name, cleaned))
        elif path == "requirements.txt":
            for raw_line in body.splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(r"([A-Za-z0-9_.-]+)\s*[=<>~!]+\s*([0-9][\w.]*)", line)
                if match:
                    dependencies.append((match.group(1), match.group(2)))
        return dependencies
