"""Technology fingerprinting — Wappalyzer-like detection via headers, HTML, JS."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, AsyncIterator

from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import Workspace, TargetInfo

logger = logging.getLogger("marlonthebug.plugins.recon.tech_fingerprint")

TECH_SIGNATURES: list[dict] = [
    {"name": "nginx", "headers": {"server": r"(?i)nginx"}, "category": "Web Server"},
    {"name": "Apache", "headers": {"server": r"(?i)apache"}, "category": "Web Server"},
    {"name": "Cloudflare", "headers": {"cf-ray": r".+", "server": r"(?i)cloudflare"}, "category": "CDN"},
    {"name": "AWS CloudFront", "headers": {"x-cache": r"(?i)hit from cloudfront"}, "category": "CDN"},
    {"name": "React", "html": [r'react\.js', r'react-dom', r'__REACT_DEVTOOLS_GLOBAL_HOOK__'], "js": [r'react@[\d.]+'], "category": "JavaScript Framework"},
    {"name": "Vue.js", "html": [r'vue\.js', r'vue@[\d.]+', r'__vue__'], "category": "JavaScript Framework"},
    {"name": "Angular", "html": [r'ng-version', r'angular\.js', r'angular@[\d.]+'], "category": "JavaScript Framework"},
    {"name": "jQuery", "html": [r'jquery[.\-][\d.]+'], "js": [r'jquery@[\d.]+'], "category": "JavaScript Library"},
    {"name": "Bootstrap", "html": [r'bootstrap\.css', r'bootstrap\.js', r'bootstrap@[\d.]+'], "category": "CSS Framework"},
    {"name": "Tailwind CSS", "html": [r'tailwindcss', r'tailwind\.css'], "category": "CSS Framework"},
    {"name": "Next.js", "html": [r'__NEXT_DATA__', r'/_next/static'], "headers": {"x-powered-by": r"(?i)next\.js"}, "category": "Framework"},
    {"name": "Nuxt.js", "html": [r'__NUXT__', r'/_nuxt/'], "category": "Framework"},
    {"name": "WordPress", "html": [r'wp-content', r'wp-includes', r'wordpress'], "headers": {"x-powered-by": r"(?i)wordpress"}, "meta": {"generator": r"(?i)wordpress"}, "category": "CMS"},
    {"name": "Drupal", "html": [r'drupal\.js', r'sites/all/'], "headers": {"x-generator": r"(?i)drupal"}, "category": "CMS"},
    {"name": "Joomla", "html": [r'joomla!', r'/media/system/js/'], "category": "CMS"},
    {"name": "Laravel", "headers": {"set-cookie": r"laravel_session"}, "html": [r'laravel'], "category": "Framework"},
    {"name": "Django", "html": [r'csrfmiddlewaretoken', r'django'], "headers": {"x-frame-options": r"SAMEORIGIN"}, "category": "Framework"},
    {"name": "Ruby on Rails", "headers": {"x-powered-by": r"(?i)phusion passenger"}, "html": [r'rails'], "category": "Framework"},
    {"name": "Express.js", "headers": {"x-powered-by": r"(?i)express"}, "category": "Framework"},
    {"name": "Flask", "headers": {"server": r"(?i)werkzeug"}, "category": "Framework"},
    {"name": "PHP", "headers": {"x-powered-by": r"(?i)php"}, "html": [r'\.php'], "category": "Language"},
    {"name": "ASP.NET", "headers": {"x-powered-by": r"(?i)asp\.net", "x-aspnet-version": r".+"}, "html": [r'__VIEWSTATE', r'__EVENTVALIDATION'], "category": "Framework"},
    {"name": "Java", "headers": {"x-powered-by": r"(?i)(servlet|jsp|jsf)"}, "html": [r'\.jsp', r'\.do'], "category": "Language"},
    {"name": "Node.js", "headers": {"x-powered-by": r"(?i)node\.js"}, "category": "Runtime"},
    {"name": "GraphQL", "html": [r'graphql', r'graphiql', r'__graphql'], "category": "API"},
    {"name": "Swagger", "html": [r'swagger', r'swagger-ui'], "category": "API Documentation"},
    {"name": "Google Analytics", "html": [r'google-analytics\.com', r'gtag'], "js": [r'UA-\d+-\d+', r'G-[A-Z0-9]+'], "category": "Analytics"},
    {"name": "Google Tag Manager", "html": [r'googletagmanager\.com'], "category": "Analytics"},
    {"name": "Stripe", "html": [r'js\.stripe\.com', r'stripe\.js'], "category": "Payment"},
    {"name": "Firebase", "html": [r'firebase\.js', r'firebase-app'], "js": [r'firebase@[\d.]+'], "category": "Backend as a Service"},
    {"name": "PostgreSQL", "html": [r'pg_query', r'pg_'], "category": "Database"},
    {"name": "MySQL", "html": [r'mysql_query', r'mysql_'], "category": "Database"},
    {"name": "MongoDB", "html": [r'mongodb', r'mongo'], "category": "Database"},
]


class TechFingerprinter(BasePlugin):
    name = "tech_fingerprint"
    version = "1.0.0"
    description = "Detect technology stack via HTTP headers, HTML, JavaScript, and meta tags"
    category = "recon"

    def __init__(self, options: dict | None = None) -> None:
        super().__init__(options)
        self._workspace: Workspace | None = None

    async def setup(self, workspace: Workspace) -> None:
        self._workspace = workspace

    async def run(
        self,
        target: TargetInfo,
        options: dict | None = None,
    ) -> AsyncIterator[Finding]:
        from marlonthebug.http.client import AsyncHTTPClient

        http = AsyncHTTPClient(timeout=10, verify_ssl=True)
        try:
            scheme = "https"
            try:
                response = await http.get(f"https://{target.host}")
            except Exception:
                try:
                    response = await http.get(f"http://{target.host}")
                    scheme = "http"
                except Exception as e:
                    yield Finding(
                        plugin_name=self.name,
                        title=f"Could not connect to {target.host}",
                        description=str(e),
                        severity=Severity.INFO,
                        cvss_score=0.0,
                        endpoint=target.host,
                        target_host=target.host,
                        category=self.category,
                    )
                    return

            body = response.body
            headers = response.headers

            detected = self._analyze(body, headers)
            technologies = [t["name"] for t in detected]

            if self._workspace:
                target.technologies = technologies
                target.metadata["tech_details"] = detected

            for tech in detected:
                yield Finding(
                    plugin_name=self.name,
                    title=f"Technology detected: {tech['name']}",
                    description=f"Detected {tech['name']} ({tech['category']}) on {target.host}.",
                    severity=Severity.INFO,
                    cvss_score=0.0,
                    endpoint=f"{scheme}://{target.host}",
                    target_host=target.host,
                    category=self.category,
                    evidence={
                        "technology": tech["name"],
                        "category": tech["category"],
                        "match_type": tech.get("match_type", "unknown"),
                        "match_value": tech.get("match_value", ""),
                    },
                )

            server = headers.get("server", "")
            if server:
                yield Finding(
                    plugin_name=self.name,
                    title=f"Server header: {server}",
                    description=f"Server header reveals: {server}. Consider hiding this information.",
                    severity=Severity.LOW,
                    cvss_score=3.0,
                    endpoint=f"{scheme}://{target.host}",
                    target_host=target.host,
                    category=self.category,
                    evidence={"server_header": server},
                    remediation="Configure your web server to hide or obscure the Server header.",
                )
        finally:
            await http.close()

    def _analyze(self, body: str, headers: dict[str, str]) -> list[dict]:
        detected: list[dict] = []
        body_lower = body.lower()

        for sig in TECH_SIGNATURES:
            for match_type, patterns in [
                ("header", sig.get("headers", {})),
                ("meta", sig.get("meta", {})),
            ]:
                if isinstance(patterns, dict):
                    for key, pattern in patterns.items():
                        value = headers.get(key, "")
                        if value and re.search(pattern, value):
                            detected.append({
                                "name": sig["name"],
                                "category": sig["category"],
                                "match_type": f"header:{key}",
                                "match_value": value[:100],
                            })
                            break
                if any(d["name"] == sig["name"] for d in detected):
                    break

            if any(d["name"] == sig["name"] for d in detected):
                continue

            for pattern in sig.get("html", []):
                if re.search(pattern, body_lower):
                    detected.append({
                        "name": sig["name"],
                        "category": sig["category"],
                        "match_type": "html",
                        "match_value": pattern,
                    })
                    break

            if any(d["name"] == sig["name"] for d in detected):
                continue

            for pattern in sig.get("js", []):
                if re.search(pattern, body):
                    detected.append({
                        "name": sig["name"],
                        "category": sig["category"],
                        "match_type": "js",
                        "match_value": pattern,
                    })
                    break

        return detected
