"""Security header analyzer — CSP, HSTS, CORS, cookie flags, and more."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("marlonthebug.utils.headers")


@dataclass
class HeaderAnalysis:
    headers_present: dict[str, str] = field(default_factory=dict)
    missing_headers: list[str] = field(default_factory=list)
    csp_analysis: dict[str, Any] = field(default_factory=dict)
    cookie_analysis: list[dict[str, Any]] = field(default_factory=list)
    cors_analysis: dict[str, Any] = field(default_factory=dict)
    score: int = 0
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "strict-transport-security": "Strict-Transport-Security",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "x-xss-protection": "X-XSS-Protection",
    "x-permitted-cross-domain-policies": "X-Permitted-Cross-Domain-Policies",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
    "cross-origin-embedder-policy": "Cross-Origin-Embedder-Policy",
}

HEADER_WEIGHTS = {
    "content-security-policy": 25,
    "strict-transport-security": 20,
    "x-frame-options": 15,
    "x-content-type-options": 10,
    "referrer-policy": 10,
    "permissions-policy": 5,
    "x-xss-protection": 5,
    "cross-origin-opener-policy": 5,
    "cross-origin-resource-policy": 5,
}

MAX_SCORE = sum(HEADER_WEIGHTS.values())


def analyze_headers(headers: dict[str, str], cookies: dict[str, str] | None = None) -> HeaderAnalysis:
    analysis = HeaderAnalysis()
    cookies = cookies or {}

    headers_lower = {k.lower(): v for k, v in headers.items()}

    for key, header_name in SECURITY_HEADERS.items():
        value = headers_lower.get(key)
        if value:
            analysis.headers_present[header_name] = value
            analysis.score += HEADER_WEIGHTS.get(key, 0)
        else:
            analysis.missing_headers.append(header_name)
            analysis.issues.append(f"Missing security header: {header_name}")
            analysis.recommendations.append(f"Add the {header_name} header.")

    csp = headers_lower.get("content-security-policy", "")
    if csp:
        analysis.csp_analysis = analyze_csp(csp)
        for issue in analysis.csp_analysis.get("issues", []):
            analysis.issues.append(f"CSP: {issue}")

    cookie_analysis = analyze_cookies(cookies, headers_lower)
    analysis.cookie_analysis = cookie_analysis
    for issue in cookie_analysis:
        analysis.issues.append(f"Cookie {issue['name']}: {issue['issue']}")
        analysis.recommendations.append(
            f"Set {', '.join(issue['missing_flags'])} flags on cookie '{issue['name']}'."
        )

    cors_analysis = analyze_cors(headers_lower)
    analysis.cors_analysis = cors_analysis
    for issue in cors_analysis.get("issues", []):
        analysis.issues.append(f"CORS: {issue}")

    return analysis


def analyze_csp(csp_header: str) -> dict[str, Any]:
    issues: list[str] = []
    directives: dict[str, str] = {}

    for part in csp_header.split(";"):
        part = part.strip()
        if " " in part:
            key, values = part.split(" ", 1)
            directives[key.strip()] = values.strip()
        elif part:
            directives[part] = ""

    unsafe_keywords = ["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'"]
    for directive, value in directives.items():
        if directive in ("script-src", "style-src", "default-src"):
            if any(uk in value for uk in unsafe_keywords):
                issues.append(f"{directive} contains unsafe directive (unsafe-inline/unsafe-eval)")

    if "object-src" not in directives and "default-src" not in directives:
        issues.append("Missing object-src directive")
    if "base-uri" not in directives:
        issues.append("Missing base-uri directive")

    return {
        "directives": directives,
        "issues": issues,
        "safe": len(issues) == 0,
    }


def analyze_cookies(
    cookies: dict[str, str],
    headers: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    headers = headers or {}

    set_cookie_headers = [
        v for k, v in headers.items() if k.lower() == "set-cookie"
    ]

    if set_cookie_headers:
        for sc in set_cookie_headers:
            parts = [p.strip() for p in sc.split(";")]
            if parts:
                name = parts[0].split("=", 1)[0]
                attrs = {p.split("=", 1)[0].lower() for p in parts[1:]}
                missing = []

                if "httponly" not in attrs:
                    missing.append("HttpOnly")
                if "secure" not in attrs:
                    missing.append("Secure")
                if "samesite" not in attrs:
                    missing.append("SameSite")

                if missing:
                    results.append({
                        "name": name,
                        "issue": f"Missing flags: {', '.join(missing)}",
                        "missing_flags": missing,
                    })
        return results

    for name in cookies:
        results.append({
            "name": name,
            "issue": "Cookie set without security flags (cannot verify)",
            "missing_flags": ["HttpOnly", "Secure", "SameSite"],
        })
    return results


def analyze_cors(headers: dict[str, str]) -> dict[str, Any]:
    issues: list[str] = []

    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")

    if acao == "*":
        if acac.lower() == "true":
            issues.append("Access-Control-Allow-Origin is '*' with credentials enabled — this is dangerous!")
        else:
            issues.append("Access-Control-Allow-Origin is '*' — allows any origin.")
    elif acao:
        if "null" in acao:
            issues.append("Access-Control-Allow-Origin includes 'null' — vulnerable to sandboxed origins.")

    allowed_methods = headers.get("access-control-allow-methods", "")
    allowed_headers = headers.get("access-control-allow-headers", "")
    if allowed_methods and "PUT" in allowed_methods or "DELETE" in allowed_methods or "PATCH" in allowed_methods:
        issues.append("CORS allows unsafe HTTP methods.")

    return {
        "allow_origin": acao,
        "allow_credentials": acac,
        "issues": issues,
        "safe": len(issues) == 0,
    }
