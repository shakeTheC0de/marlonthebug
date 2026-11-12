"""SQL injection detection with baseline comparison and repeated validation."""

from __future__ import annotations

import logging
import re
import statistics
import time
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from marlonthebug.http.baseline import similarity
from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo

logger = logging.getLogger("marlonthebug.plugins.web.sqli")

ERROR_PATTERNS = [
    (r"(?i)SQL syntax.*MySQL", "MySQL"),
    (r"(?i)Warning.*mysql_.*", "MySQL"),
    (r"(?i)PostgreSQL.*ERROR", "PostgreSQL"),
    (r"(?i)Warning.*\Wpg_\S+", "PostgreSQL"),
    (r"(?i)Driver.*SQL[\-\s]*Server", "MSSQL"),
    (r"(?i)OLE DB.*SQL Server", "MSSQL"),
    (r"(?i)ORA-[0-9]{4,5}", "Oracle"),
    (r"(?i)SQLite.*error", "SQLite"),
    (r"(?i)unclosed quotation mark", "Generic SQL"),
    (r"(?i)quoted string not properly terminated", "Generic SQL"),
    (r"(?i)You have an error in your SQL", "MySQL"),
]

ERROR_PAYLOADS = ["'", '"', "' OR '1'='1", "1'", "1 AND 1=1"]
BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    (" AND 1=1", " AND 1=2"),
    ('" AND "1"="1', '" AND "1"="2'),
]
TIME_PAYLOADS = [
    "' OR SLEEP(5)-- -",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)-- -",
]


class SQLiAuditor(BasePlugin):
    name = "sqli"
    version = "2.0.0"
    description = "Detección de inyección SQL con baseline, repetición y validación temporal"
    category = "web"
    cwe = "CWE-89"
    owasp = "A03:2021 Injection"

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        options = options or {}
        base_url = str(options.get("base_url") or f"https://{target.host}").rstrip("/")
        baseline = options.get("baseline")
        endpoints = list(options.get("endpoints") or [])
        http = AsyncHTTPClient()
        reported: set[str] = set()
        try:
            urls = await self._candidate_urls(http, base_url, endpoints)
            for url in urls[:25]:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if not params:
                    continue
                for param in list(params.keys())[:4]:
                    if param in reported:
                        continue
                    try:
                        original = params[param][0]
                        base_response = await http.get(url)
                        if baseline and baseline.looks_like_app_shell(base_response):
                            continue
                        # Measure normal variance to avoid dynamic-page false positives.
                        second = await http.get(url)
                        noise_delta = abs(base_response.content_length - second.content_length)
                        noise_similarity = similarity(base_response.body, second.body)

                        finding = await self._error_based(
                            http, url, parsed, params, param, original, base_response, baseline, target
                        )
                        if finding:
                            reported.add(param)
                            yield finding
                            continue

                        finding = await self._boolean_based(
                            http,
                            url,
                            parsed,
                            params,
                            param,
                            original,
                            noise_delta,
                            noise_similarity,
                            baseline,
                            target,
                        )
                        if finding:
                            reported.add(param)
                            yield finding
                            continue

                        finding = await self._time_based(http, url, parsed, params, param, original, baseline, target)
                        if finding:
                            reported.add(param)
                            yield finding
                    except Exception as exc:
                        logger.debug("SQLi test failed for %s/%s: %s", url, param, exc)
        finally:
            await http.close()

    async def _candidate_urls(self, http: AsyncHTTPClient, base_url: str, endpoints: list[str]) -> list[str]:
        urls = [url for url in endpoints if "?" in url and "=" in url]
        try:
            home = await http.get(base_url)
            soup = BeautifulSoup(home.body, "lxml")
            for anchor in soup.find_all("a", href=True):
                candidate = urljoin(base_url, anchor["href"])
                if "?" in candidate and "=" in candidate and _same_host(candidate, base_url):
                    urls.append(candidate)
            for form in soup.find_all("form"):
                if form.get("method", "get").lower() != "get":
                    continue
                action = urljoin(base_url, form.get("action", ""))
                inputs = [item.get("name") for item in form.find_all("input") if item.get("name")]
                if inputs:
                    query = urlencode(dict.fromkeys(inputs, "1"))
                    urls.append(f"{action}?{query}")
        except Exception:
            pass
        deduped = []
        seen = set()
        for url in urls:
            normalized = url.split("#")[0]
            if normalized not in seen:
                seen.add(normalized)
                deduped.append(normalized)
        return deduped

    async def _error_based(self, http, url, parsed, params, param, original, base_response, baseline, target):
        for payload in ERROR_PAYLOADS:
            test_params = {key: values[0] for key, values in params.items()}
            test_params[param] = f"{original}{payload}"
            test_url = _replace_query(url, test_params)
            try:
                response = await http.get(test_url)
            except Exception:
                continue
            if baseline and baseline.looks_like_app_shell(response):
                continue
            for pattern, db_type in ERROR_PATTERNS:
                if re.search(pattern, response.body) and not re.search(pattern, base_response.body):
                    return self.create_finding(
                        title=f"Inyección SQL (error-based) en '{param}' [{db_type}]",
                        description=(
                            f"El parámetro '{param}' provoca un error del motor {db_type} al inyectar "
                            f"un payload SQL. El error no aparecía en la respuesta baseline."
                        ),
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        confidence=Confidence.HIGH,
                        cwe="CWE-89",
                        owasp="A03:2021 Injection",
                        endpoint=url,
                        target_host=target.host,
                        evidence={
                            "parameter": param,
                            "payload": payload,
                            "db_type": db_type,
                            "url": test_url,
                            "error_snippet": _snippet(response.body, pattern),
                        },
                        remediation=(
                            "Usa consultas parametrizadas (prepared statements) y valida el tipo de dato. "
                            "Aplica mínimo privilegio a la cuenta de base de datos y revisa los logs del motor."
                        ),
                        references=["https://owasp.org/Top10/A03_2021-Injection/"],
                        waf_rules=[
                            'SecRule ARGS "(?i)(\\bselect\\b|\\bunion\\b|\\bsleep\\b|\\bbenchmark\\b)" '
                            "\"id:1001,deny,status:403,msg:'SQLi attempt'\"",
                        ],
                    )
        return None

    async def _boolean_based(
        self, http, url, parsed, params, param, original, noise_delta, noise_similarity, baseline, target
    ):
        for true_payload, false_payload in BOOLEAN_PAIRS:
            true_params = {key: values[0] for key, values in params.items()}
            false_params = dict(true_params)
            true_params[param] = f"{original}{true_payload}"
            false_params[param] = f"{original}{false_payload}"
            try:
                true_response = await http.get(_replace_query(url, true_params))
                false_response = await http.get(_replace_query(url, false_params))
            except Exception:
                continue
            if baseline and (
                baseline.looks_like_app_shell(true_response) or baseline.looks_like_app_shell(false_response)
            ):
                continue
            delta = abs(true_response.content_length - false_response.content_length)
            body_similarity = similarity(true_response.body, false_response.body)
            significant = delta > max(40, noise_delta * 3) or body_similarity < max(0.9, noise_similarity - 0.12)
            if not significant:
                continue
            # Confirm with a second pair to avoid transient dynamic content.
            try:
                confirm_true = await http.get(_replace_query(url, true_params))
                confirm_false = await http.get(_replace_query(url, false_params))
            except Exception:
                continue
            confirm_delta = abs(confirm_true.content_length - confirm_false.content_length)
            if confirm_delta < max(30, noise_delta * 2):
                continue
            return self.create_finding(
                title=f"Inyección SQL booleana en '{param}'",
                description=(
                    f"El parámetro '{param}' devuelve respuestas sistemáticamente distintas entre "
                    f"condiciones verdaderas y falsas, con una variación superior al ruido del baseline."
                ),
                severity=Severity.HIGH,
                cvss_score=8.6,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                confidence=Confidence.MEDIUM,
                cwe="CWE-89",
                owasp="A03:2021 Injection",
                endpoint=url,
                target_host=target.host,
                evidence={
                    "parameter": param,
                    "true_payload": true_payload,
                    "false_payload": false_payload,
                    "delta": delta,
                    "noise_delta": noise_delta,
                    "similarity": round(body_similarity, 3),
                    "confirmed": True,
                },
                remediation="Usa consultas parametrizadas y evita concatenar entrada del usuario en SQL.",
                references=["https://owasp.org/Top10/A03_2021-Injection/"],
            )
        return None

    async def _time_based(self, http, url, parsed, params, param, original, baseline, target):
        timings = []
        for _ in range(2):
            try:
                started = time.monotonic()
                response = await http.get(url)
                timings.append(time.monotonic() - started)
                if baseline and baseline.looks_like_app_shell(response):
                    return None
            except Exception:
                return None
        average = statistics.mean(timings) if timings else 0.3
        for payload in TIME_PAYLOADS:
            test_params = {key: values[0] for key, values in params.items()}
            test_params[param] = f"{original}{payload}"
            test_url = _replace_query(url, test_params)
            try:
                started = time.monotonic()
                await http.get(test_url)
                elapsed = time.monotonic() - started
            except Exception:
                continue
            if elapsed < average + 4.2:
                continue
            # Confirm the delay with a second request.
            try:
                started = time.monotonic()
                await http.get(test_url)
                confirm = time.monotonic() - started
            except Exception:
                continue
            if confirm < average + 3.5:
                continue
            return self.create_finding(
                title=f"Inyección SQL time-based en '{param}'",
                description=(
                    f"El parámetro '{param}' introduce un retraso reproducible de {confirm:.1f}s "
                    f"frente a un baseline de {average:.2f}s."
                ),
                severity=Severity.CRITICAL,
                cvss_score=9.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
                confidence=Confidence.HIGH,
                cwe="CWE-89",
                owasp="A03:2021 Injection",
                endpoint=url,
                target_host=target.host,
                evidence={
                    "parameter": param,
                    "payload": payload,
                    "baseline_seconds": round(average, 2),
                    "delayed_seconds": round(confirm, 2),
                    "confirmed": True,
                },
                remediation="Usa consultas parametrizadas y limita el tiempo de ejecución de las consultas.",
                references=["https://owasp.org/Top10/A03_2021-Injection/"],
            )
        return None


def _replace_query(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def _same_host(candidate: str, base_url: str) -> bool:
    return urlparse(candidate).netloc.lower() == urlparse(base_url).netloc.lower()


def _snippet(body: str, pattern: str) -> str:
    match = re.search(pattern, body)
    if not match:
        return body[:300]
    start = max(0, match.start() - 80)
    return body[start : match.end() + 160]
