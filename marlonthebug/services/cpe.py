"""CPE 2.3 mapping for technology versions detected during reconnaissance.

NVD accepts a ``virtualMatchString`` CPE, which is far more precise than a
keyword search: ``nginx 1.24.0`` becomes
``cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*`` and only CVEs whose vulnerable
configuration matches that product/version are returned.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# Detected technology name -> (CPE vendor, CPE product).
CPE_PRODUCTS: dict[str, tuple[str, str]] = {
    "nginx": ("nginx", "nginx"),
    "apache": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"),
    "apache http server": ("apache", "http_server"),
    "iis": ("microsoft", "internet_information_services"),
    "microsoft iis": ("microsoft", "internet_information_services"),
    "caddy": ("caddyserver", "caddy"),
    "react": ("facebook", "react"),
    "vue.js": ("vuejs", "vue"),
    "vue": ("vuejs", "vue"),
    "angular": ("google", "angular"),
    "jquery": ("jquery", "jquery"),
    "bootstrap": ("getbootstrap", "bootstrap"),
    "next.js": ("vercel", "next.js"),
    "nextjs": ("vercel", "next.js"),
    "nuxt.js": ("nuxt", "nuxt"),
    "nuxt": ("nuxt", "nuxt"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "laravel": ("laravel", "laravel"),
    "django": ("djangoproject", "django"),
    "ruby on rails": ("rubyonrails", "rails"),
    "express.js": ("expressjs", "express"),
    "express": ("expressjs", "express"),
    "flask": ("palletsprojects", "flask"),
    "php": ("php", "php"),
    "asp.net": ("microsoft", "asp.net_core"),
    "node.js": ("nodejs", "node.js"),
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
}

_VERSION_RE = re.compile(r"^[vV]?(\d+(?:\.\d+){0,4}(?:[-+][A-Za-z0-9._-]+)?)")
_VERSION_SEARCH = re.compile(r"(?<![\w.-])(\d+(?:\.\d+){0,4}(?:[-+][A-Za-z0-9._-]+)?)")
_LABEL_RE = re.compile(r"^(?P<name>.+?)\s+(?P<version>[vV]?\d[\w.+-]*)$")


@dataclass(frozen=True, slots=True)
class TechCPE:
    name: str
    version: str
    cpe: str
    match_type: str = "cpe"


def normalize_version(value: str) -> str:
    """Keep the numeric version and a simple pre-release suffix.

    ``Apache/2.4.58 (Ubuntu)`` -> ``2.4.58``
    ``v18.2.0`` -> ``18.2.0``
    ``1.24.0-ubuntu`` -> ``1.24.0-ubuntu``
    """
    cleaned = (value or "").strip()
    if not cleaned:
        return ""
    match = _VERSION_RE.match(cleaned) or _VERSION_SEARCH.search(cleaned)
    if not match:
        return ""
    version = match.group(1).rstrip(".-+")
    # CPE 2.3 components cannot contain whitespace or unescaped wildcards.
    if any(char.isspace() for char in version):
        return ""
    return version


def cpe_for(name: str, version: str) -> str:
    product = CPE_PRODUCTS.get(name.strip().lower())
    normalized = normalize_version(version)
    if not product or not normalized:
        return ""
    vendor, item = product
    return f"cpe:2.3:a:{vendor}:{item}:{normalized}:*:*:*:*:*:*:*"


def from_tech_details(details: list[Any] | None) -> list[TechCPE]:
    if not details:
        return []
    rows: list[TechCPE] = []
    seen: set[str] = set()
    for detail in details:
        if not isinstance(detail, dict):
            continue
        name = str(detail.get("name", ""))
        version = normalize_version(str(detail.get("version", "")))
        cpe = cpe_for(name, version)
        if not cpe or cpe in seen:
            continue
        seen.add(cpe)
        rows.append(TechCPE(name=name, version=version, cpe=cpe, match_type="cpe"))
    return rows


def from_technologies(labels: list[str] | None) -> list[TechCPE]:
    if not labels:
        return []
    rows: list[TechCPE] = []
    seen: set[str] = set()
    for label in labels:
        match = _LABEL_RE.match(str(label).strip())
        if not match:
            continue
        name = match.group("name").strip()
        version = normalize_version(match.group("version"))
        cpe = cpe_for(name, version)
        if not cpe or cpe in seen:
            continue
        seen.add(cpe)
        rows.append(TechCPE(name=name, version=version, cpe=cpe, match_type="cpe"))
    return rows
