"""Reflected XSS detection with context validation and baseline comparison."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from marlonthebug.http.baseline import similarity
from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo

logger = logging.getLogger("marlonthebug.plugins.web.xss")

PAYLOADS = [
    "<svg onload=alert(1)>",
    '"><svg onload=alert(1)>',
    "'><svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
]


class XSSAuditor(BasePlugin):
    name = "xss"
    version = "2.0.0"
    description = "Detección de XSS reflejado con validación de contexto y baseline"
    category = "web"
    cwe = "CWE-79"
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
            for url in urls[:30]:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if not params:
                    continue
                for param in list(params.keys())[:5]:
                    if param in reported:
                        continue
                    try:
                        base_response = await http.get(url)
                        if baseline and baseline.looks_like_app_shell(base_response):
                            continue
                        second = await http.get(url)
                        noise = similarity(base_response.body, second.body)
                        for payload in PAYLOADS:
                            test_params = {key: values[0] for key, values in params.items()}
                            test_params[param] = payload
                            test_url = _replace_query(url, test_params)
                            response = await http.get(test_url)
                            if baseline and baseline.looks_like_app_shell(response):
                                continue
                            if payload not in response.body:
                                continue
                            if "&lt;svg" in response.body.lower() or "&lt;img" in response.body.lower():
                                continue
                            context = _reflection_context(response.body, payload)
                            if context is None:
                                continue
                            if similarity(base_response.body, response.body) > 0.995:
                                continue
                            reported.add(param)
                            yield self.create_finding(
                                title=f"XSS reflejado en el parámetro '{param}'",
                                description=(
                                    f"El parámetro '{param}' refleja el payload sin codificar en contexto "
                                    f"{context}. La respuesta cambia respecto al baseline y el navegador "
                                    f"interpretaría el HTML inyectado."
                                ),
                                severity=Severity.HIGH,
                                cvss_score=7.2,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                confidence=Confidence.HIGH,
                                cwe="CWE-79",
                                owasp="A03:2021 Injection",
                                endpoint=url,
                                target_host=target.host,
                                evidence={
                                    "parameter": param,
                                    "payload": payload,
                                    "context": context,
                                    "url": test_url,
                                    "baseline_similarity": round(noise, 3),
                                    "reflected": True,
                                },
                                remediation=(
                                    "Codifica la salida según el contexto (HTML, atributo, JavaScript), "
                                    "aplica una CSP restrictiva y evita insertar entrada del usuario con innerHTML."
                                ),
                                references=[
                                    "https://owasp.org/www-community/attacks/xss/",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                                ],
                                waf_rules=[
                                    'SecRule ARGS "(?i)(<script|<svg|onerror=|onload=)" '
                                    "\"id:2001,deny,status:403,msg:'XSS attempt'\"",
                                ],
                            )
                            break
                    except Exception as exc:
                        logger.debug("XSS test failed for %s/%s: %s", url, param, exc)
        finally:
            await http.close()

    async def _candidate_urls(self, http: AsyncHTTPClient, base_url: str, endpoints: list[str]) -> list[str]:
        urls = [url for url in endpoints if "?" in url and "=" in url]
        try:
            home = await http.get(base_url)
            soup = BeautifulSoup(home.body, "lxml")
            for anchor in soup.find_all("a", href=True):
                candidate = urljoin(base_url, anchor["href"])
                if "?" in candidate and "=" in candidate and urlparse(candidate).netloc == urlparse(base_url).netloc:
                    urls.append(candidate)
            for form in soup.find_all("form"):
                if form.get("method", "get").lower() != "get":
                    continue
                action = urljoin(base_url, form.get("action", ""))
                names = [item.get("name") for item in form.find_all("input") if item.get("name")]
                if names:
                    urls.append(f"{action}?{urlencode(dict.fromkeys(names, 'test'))}")
        except Exception:
            pass
        seen = set()
        result = []
        for url in urls:
            normalized = url.split("#")[0]
            if normalized not in seen:
                seen.add(normalized)
                result.append(normalized)
        return result


def _replace_query(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def _reflection_context(body: str, payload: str) -> str | None:
    index = body.find(payload)
    if index < 0:
        return None
    before = body[max(0, index - 160) : index].lower()
    after = body[index + len(payload) : index + len(payload) + 80].lower()
    if "<script" in before and "</script" not in before:
        return "javascript"
    if "<textarea" in before and "</textarea" not in before:
        return "html_body"
    if before.rfind("<") > before.rfind(">"):
        return "html_attribute"
    if any(marker in before for marker in ("<div", "<p", "<span", "<body", "<td", "<li", "<h1")):
        return "html_body"
    if "<" in payload and ">" in payload and after:
        return "html_body"
    return None
