"""BOLA/IDOR heuristic testing for authenticated API endpoints."""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from marlonthebug.http.baseline import similarity
from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo

logger = logging.getLogger("marlonthebug.plugins.api.bola")

ID_PARAMS = {"id", "user_id", "userid", "account_id", "account", "order_id", "invoice_id", "customer_id", "uid"}


class BOLAAuditor(BasePlugin):
    name = "bola"
    version = "2.0.0"
    description = "Prueba BOLA/IDOR en endpoints autenticados con identificadores numéricos"
    category = "api"
    cwe = "CWE-639"
    owasp = "A01:2021 Broken Access Control"
    beta = True

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        options = options or {}
        headers = dict(options.get("headers") or {})
        cookies = dict(options.get("cookies") or {})
        if not headers.get("Authorization") and not headers.get("authorization") and not cookies:
            return
        base_url = str(options.get("base_url") or f"https://{target.host}").rstrip("/")
        endpoints = list(options.get("endpoints") or [])
        http = AsyncHTTPClient()
        tested: set[str] = set()
        try:
            for url in self._candidates(base_url, endpoints)[:12]:
                parsed = urlparse(url)
                query = parse_qs(parsed.query)
                target_value = None
                target_param = None
                for name, values in query.items():
                    if name.lower() in ID_PARAMS and values and values[0].isdigit():
                        target_param, target_value = name, values[0]
                        break
                if target_param is None:
                    match = re.search(r"/(\d{1,10})(?:/|$)", parsed.path)
                    if not match:
                        continue
                    target_value = match.group(1)
                if target_value is None:
                    continue
                key = parsed.netloc + parsed.path + str(target_param)
                if key in tested:
                    continue
                tested.add(key)
                baseline = await self._get(http, url)
                if not baseline or baseline.status_code != 200:
                    continue
                if not baseline.is_json:
                    continue
                for delta in (1, -1):
                    mutated_value = str(max(1, int(target_value) + delta))
                    if target_param:
                        mutated_query = {name: values[:] for name, values in query.items()}
                        mutated_query[target_param] = [mutated_value]
                        test_url = urlunparse(parsed._replace(query=urlencode(mutated_query, doseq=True)))
                    else:
                        test_url = urlunparse(
                            parsed._replace(path=parsed.path.replace(f"/{target_value}", f"/{mutated_value}", 1))
                        )
                    response = await self._get(http, test_url)
                    if not response or response.status_code != 200 or not response.is_json:
                        continue
                    if any(
                        marker in response.body.lower()[:500]
                        for marker in ("forbidden", "unauthorized", "login", "access denied")
                    ):
                        continue
                    body_similarity = similarity(baseline.body, response.body)
                    if body_similarity < 0.65:
                        continue
                    if len(response.body) < 40:
                        continue
                    yield self.create_finding(
                        title=f"Posible BOLA/IDOR en {parsed.path}",
                        description=(
                            f"Un usuario autenticado puede cambiar el identificador {target_value!r} por "
                            f"{mutated_value!r} y seguir recibiendo datos con HTTP 200 y estructura similar. "
                            "Requiere validación manual para confirmar que el objeto pertenece a otro usuario."
                        ),
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                        confidence=Confidence.LOW,
                        cwe="CWE-639",
                        owasp="A01:2021 Broken Access Control",
                        endpoint=url,
                        target_host=target.host,
                        evidence={
                            "parameter": target_param or "path_id",
                            "original_id": target_value,
                            "tested_id": mutated_value,
                            "status": response.status_code,
                            "similarity": round(body_similarity, 3),
                            "requires_manual_validation": True,
                        },
                        remediation=(
                            "Aplica autorización a nivel de objeto en cada endpoint, no solo a nivel de ruta. "
                            "Comprueba que el recurso pertenece al usuario autenticado antes de devolverlo."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
                        ],
                    )
                    break
        finally:
            await http.close()

    async def _get(self, http: AsyncHTTPClient, url: str):
        try:
            return await http.get(url)
        except Exception:
            return None

    def _candidates(self, base_url: str, endpoints: list[str]) -> list[str]:
        result = []
        for url in endpoints:
            parsed = urlparse(url)
            if parsed.netloc.lower() != urlparse(base_url).netloc.lower():
                continue
            query = parse_qs(parsed.query)
            if any(
                name.lower() in ID_PARAMS and values and values[0].isdigit() for name, values in query.items()
            ) or re.search(r"/\d{1,10}(?:/|$)", parsed.path):
                result.append(url)
        return list(dict.fromkeys(result))
