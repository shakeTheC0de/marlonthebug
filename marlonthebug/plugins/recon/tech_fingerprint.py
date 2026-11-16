"""Technology fingerprinting with version extraction for CVE correlation."""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.http.errors import is_edge_error
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo, Workspace

logger = logging.getLogger("marlonthebug.plugins.recon.tech_fingerprint")

TECH_SIGNATURES: list[dict] = [
    {"name": "nginx", "headers": {"server": r"(?i)nginx"}, "category": "Web Server"},
    {"name": "Apache", "headers": {"server": r"(?i)apache"}, "category": "Web Server"},
    {"name": "IIS", "headers": {"server": r"(?i)microsoft-iis"}, "category": "Web Server"},
    {"name": "Caddy", "headers": {"server": r"(?i)caddy"}, "category": "Web Server"},
    {"name": "Cloudflare", "headers": {"cf-ray": r".+", "server": r"(?i)cloudflare"}, "category": "CDN"},
    {"name": "AWS CloudFront", "headers": {"x-cache": r"(?i)hit from cloudfront"}, "category": "CDN"},
    {"name": "Akamai", "headers": {"server": r"(?i)akamai"}, "category": "CDN"},
    {
        "name": "React",
        "html": [r"react\.js", r"react-dom", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"],
        "js": [r"react@([\d.]+)"],
        "category": "JavaScript Framework",
    },
    {"name": "Vue.js", "html": [r"vue\.js", r"__vue__"], "js": [r"vue@([\d.]+)"], "category": "JavaScript Framework"},
    {
        "name": "Angular",
        "html": [r'ng-version="([\d.]+)"', r"angular\.js"],
        "js": [r"angular@([\d.]+)"],
        "category": "JavaScript Framework",
    },
    {"name": "jQuery", "html": [r"jquery[.\-]([\d.]+)"], "js": [r"jquery@([\d.]+)"], "category": "JavaScript Library"},
    {"name": "Bootstrap", "html": [r"bootstrap[.\-]([\d.]+)", r"bootstrap@([\d.]+)"], "category": "CSS Framework"},
    {"name": "Tailwind CSS", "html": [r"tailwindcss", r"tailwind\.css"], "category": "CSS Framework"},
    {
        "name": "Next.js",
        "html": [r"__NEXT_DATA__", r"/_next/static"],
        "headers": {"x-powered-by": r"(?i)next\.js"},
        "category": "Framework",
    },
    {"name": "Nuxt.js", "html": [r"__NUXT__", r"/_nuxt/"], "category": "Framework"},
    {
        "name": "WordPress",
        "html": [r"wp-content", r"wp-includes"],
        "meta": {"generator": r"(?i)wordpress\s*([\d.]+)?"},
        "category": "CMS",
    },
    {
        "name": "Drupal",
        "html": [r"drupal\.js", r"sites/all/"],
        "headers": {"x-generator": r"(?i)drupal\s*([\d.]*)?"},
        "category": "CMS",
    },
    {"name": "Joomla", "html": [r"joomla!", r"/media/system/js/"], "category": "CMS"},
    {"name": "Laravel", "headers": {"set-cookie": r"laravel_session"}, "html": [r"laravel"], "category": "Framework"},
    {
        "name": "Django",
        "html": [r"csrfmiddlewaretoken", r"django"],
        "headers": {"x-frame-options": r"SAMEORIGIN"},
        "category": "Framework",
    },
    {
        "name": "Ruby on Rails",
        "headers": {"x-powered-by": r"(?i)phusion passenger"},
        "html": [r"rails"],
        "category": "Framework",
    },
    {"name": "Express.js", "headers": {"x-powered-by": r"(?i)express"}, "category": "Framework"},
    {"name": "Flask", "headers": {"server": r"(?i)werkzeug(?:/([\d.]+))?"}, "category": "Framework"},
    {"name": "PHP", "headers": {"x-powered-by": r"(?i)php/([\d.]+)"}, "html": [r"\.php"], "category": "Language"},
    {
        "name": "ASP.NET",
        "headers": {"x-powered-by": r"(?i)asp\.net", "x-aspnet-version": r"([\d.]+)"},
        "html": [r"__VIEWSTATE", r"__EVENTVALIDATION"],
        "category": "Framework",
    },
    {
        "name": "Java",
        "headers": {"x-powered-by": r"(?i)(servlet|jsp|jsf)"},
        "html": [r"\.jsp", r"\.do"],
        "category": "Language",
    },
    {"name": "Node.js", "headers": {"x-powered-by": r"(?i)node\.js"}, "category": "Runtime"},
    {"name": "GraphQL", "html": [r"graphql", r"graphiql", r"__graphql"], "category": "API"},
    {"name": "Swagger", "html": [r"swagger", r"swagger-ui"], "category": "API Documentation"},
    {
        "name": "Google Analytics",
        "html": [r"google-analytics\.com", r"gtag"],
        "js": [r"UA-\d+-\d+", r"G-[A-Z0-9]+"],
        "category": "Analytics",
    },
    {"name": "Stripe", "html": [r"js\.stripe\.com", r"stripe\.js"], "category": "Payment"},
    {
        "name": "Firebase",
        "html": [r"firebase\.js", r"firebase-app"],
        "js": [r"firebase@([\d.]+)"],
        "category": "Backend as a Service",
    },
]

_VERSION_RE = re.compile(r"(?<![\w.-])(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)")


def _extract_version(text: str, pattern: str = "") -> str:
    if not text:
        return ""
    if pattern:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            for group in match.groups():
                if group:
                    return group.strip()
    match = _VERSION_RE.search(text)
    return match.group(1) if match else ""


class TechFingerprinter(BasePlugin):
    name = "tech_fingerprint"
    version = "2.0.0"
    description = "Detecta tecnologías y versiones para correlacionar CVEs"
    category = "recon"

    async def setup(self, workspace: Workspace) -> None:
        self._workspace = workspace

    async def run(
        self,
        target: TargetInfo,
        options: dict | None = None,
    ) -> AsyncIterator[Finding]:
        options = options or {}
        base_url = str(options.get("base_url") or f"https://{target.host}").rstrip("/")
        http = AsyncHTTPClient(timeout=10, verify_ssl=True)
        try:
            try:
                response = await http.get(base_url)
            except Exception:
                return
            if is_edge_error(response):
                return
            detected = self._analyze(response.body, response.headers)
            technologies = [self._label(item) for item in detected]
            if self._workspace:
                target.technologies = technologies
                target.metadata["tech_details"] = detected
                target.metadata["server"] = response.headers.get("server", "")
            for tech in detected:
                yield Finding(
                    plugin_name=self.name,
                    title=f"Tecnología detectada: {self._label(tech)}",
                    description=f"Detectado {self._label(tech)} ({tech['category']}) en {target.host}.",
                    severity=Severity.INFO,
                    cvss_score=0.0,
                    confidence=Confidence.HIGH,
                    endpoint=base_url,
                    target_host=target.host,
                    category=self.category,
                    cwe="CWE-200",
                    owasp="A05:2021 Security Misconfiguration",
                    evidence={
                        "technology": tech["name"],
                        "version": tech.get("version", ""),
                        "category": tech["category"],
                        "match_type": tech.get("match_type", "unknown"),
                        "match_value": tech.get("match_value", "")[:200],
                    },
                )
            server = response.headers.get("server", "")
            if server:
                yield Finding(
                    plugin_name=self.name,
                    title=f"Cabecera Server expuesta: {server}",
                    description="La cabecera Server revela el servidor y su versión. Reduce la información expuesta.",
                    severity=Severity.LOW,
                    cvss_score=2.6,
                    confidence=Confidence.HIGH,
                    endpoint=base_url,
                    target_host=target.host,
                    category=self.category,
                    cwe="CWE-200",
                    owasp="A05:2021 Security Misconfiguration",
                    evidence={"server_header": server},
                    remediation="Configura el servidor para ocultar la versión en la cabecera Server.",
                )
        finally:
            await http.close()

    @staticmethod
    def _label(tech: dict) -> str:
        return f"{tech['name']} {tech['version']}".strip() if tech.get("version") else tech["name"]

    def _analyze(self, body: str, headers: dict[str, str]) -> list[dict]:
        detected: list[dict] = []
        body_lower = body.lower()
        meta_tags = dict(
            re.findall(r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']*)["\']', body, re.IGNORECASE)
        )

        for sig in TECH_SIGNATURES:
            match = None
            for key, pattern in (sig.get("headers") or {}).items():
                value = headers.get(key, "")
                if value and re.search(pattern, value, re.IGNORECASE):
                    match = {
                        "match_type": f"header:{key}",
                        "match_value": value[:120],
                        "version": _extract_version(value, pattern),
                    }
                    break
            if not match:
                for key, pattern in (sig.get("meta") or {}).items():
                    value = meta_tags.get(key, "")
                    if value and re.search(pattern, value, re.IGNORECASE):
                        match = {
                            "match_type": f"meta:{key}",
                            "match_value": value[:120],
                            "version": _extract_version(value, pattern),
                        }
                        break
            if not match:
                for pattern in sig.get("html", []):
                    found = re.search(pattern, body_lower, re.IGNORECASE)
                    if found:
                        match = {
                            "match_type": "html",
                            "match_value": pattern,
                            "version": next((group for group in found.groups() if group), ""),
                        }
                        break
            if not match:
                for pattern in sig.get("js", []):
                    found = re.search(pattern, body, re.IGNORECASE)
                    if found:
                        match = {
                            "match_type": "js",
                            "match_value": pattern,
                            "version": next((group for group in found.groups() if group), ""),
                        }
                        break
            if not match:
                continue
            if any(item["name"] == sig["name"] for item in detected):
                continue
            detected.append(
                {
                    "name": sig["name"],
                    "category": sig["category"],
                    "version": match["version"],
                    "match_type": match["match_type"],
                    "match_value": match["match_value"],
                }
            )
        return detected
