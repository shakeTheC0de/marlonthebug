"""Typed application settings with portable defaults."""

from __future__ import annotations

import contextlib
import copy
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from marlonthebug.paths import AppPaths, resource_path


class GeneralSettings(BaseModel):
    threads: int = 20
    timeout: float = 10.0
    retries: int = 2
    backoff: float = 1.5
    verify_ssl: bool = True
    follow_redirects: bool = True
    max_redirects: int = 5
    user_agent: str = "MarlonTheBug/2.0 (authorized security assessment)"


class ScopeSettings(BaseModel):
    require_confirmation: bool = True
    allow_exploitation: bool = False
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_ip_ranges: list[str] = Field(default_factory=list)
    excluded: list[str] = Field(default_factory=list)


class ProxySettings(BaseModel):
    enabled: bool = False
    http: str | None = None
    https: str | None = None
    socks: str | None = None


class HeaderSettings(BaseModel):
    accept_language: str = "es-ES,es;q=0.9,en;q=0.8"


class TLSSettings(BaseModel):
    verify: bool = True
    ca_bundle: str | None = None


class HTTPSettings(BaseModel):
    proxy: ProxySettings = Field(default_factory=ProxySettings)
    headers: HeaderSettings = Field(default_factory=HeaderSettings)
    tls: TLSSettings = Field(default_factory=TLSSettings)


class CrawlerSettings(BaseModel):
    max_depth: int = 3
    max_pages: int = 200
    respect_robots_txt: bool = True
    follow_subdomains: bool = False
    extract_js: bool = True
    extract_api_endpoints: bool = True


class ScanSettings(BaseModel):
    requests_per_second: float = 8.0
    max_requests: int = 2500
    verify_findings: bool = True
    deduplicate: bool = True
    default_profile: str = "standard"


class ExploitationSettings(BaseModel):
    confirm_before_payload: bool = True
    confirm_before_listener: bool = True
    max_concurrent_sessions: int = 5
    auto_cleanup: bool = True
    log_all_actions: bool = True
    default_listener_port: int = 4444


class PanelSettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8765
    open_browser: bool = True
    auth: bool = True
    page_size: int = 50


class IntelSettings(BaseModel):
    auto_sync: bool = True
    sync_interval_hours: int = 24
    offline: bool = False
    request_timeout: float = 30.0
    nvd_api_key: str = ""
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    epss_url: str = "https://api.first.org/data/v1/epss"
    osv_url: str = "https://api.osv.dev/v1"
    nvd_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class ReportSettings(BaseModel):
    language: str = "es"
    template: str = "full"
    classification: str = "CONFIDENCIAL"
    company: str = "MarlonTheBug"
    include_evidence: bool = True
    include_remediation: bool = True
    include_waf_rules: bool = True


class LoggingSettings(BaseModel):
    level: str = "INFO"
    format: str = "{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}"
    rotation: str = "10 MB"
    retention: str = "30 days"
    file: str | None = None
    console: bool = True


class AppSettings(BaseModel):
    general: GeneralSettings = Field(default_factory=GeneralSettings)
    scope: ScopeSettings = Field(default_factory=ScopeSettings)
    http: HTTPSettings = Field(default_factory=HTTPSettings)
    crawler: CrawlerSettings = Field(default_factory=CrawlerSettings)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    exploitation: ExploitationSettings = Field(default_factory=ExploitationSettings)
    panel: PanelSettings = Field(default_factory=PanelSettings)
    intel: IntelSettings = Field(default_factory=IntelSettings)
    reports: ReportSettings = Field(default_factory=ReportSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

    model_config = {"extra": "ignore"}


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return data if isinstance(data, dict) else {}
    except (OSError, yaml.YAMLError):
        return {}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _env_overrides() -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    if value := os.environ.get("MARLONTHEBUG_HOST"):
        overrides.setdefault("panel", {})["host"] = value
    if value := os.environ.get("MARLONTHEBUG_PORT"):
        with contextlib.suppress(ValueError):
            overrides.setdefault("panel", {})["port"] = int(value)
    if os.environ.get("MARLONTHEBUG_OFFLINE", "").lower() in {"1", "true", "yes"}:
        overrides.setdefault("intel", {})["offline"] = True
    if value := os.environ.get("NVD_API_KEY"):
        overrides.setdefault("intel", {})["nvd_api_key"] = value
    return overrides


def load_settings(
    paths: AppPaths,
    overrides: dict[str, Any] | None = None,
) -> AppSettings:
    """Merge bundled defaults, the user's config and explicit overrides."""
    defaults = _read_yaml(resource_path("resources", "default_config.yaml"))
    user = _read_yaml(paths.config_file)
    merged = _deep_merge(defaults, user)
    if overrides:
        merged = _deep_merge(merged, overrides)
    merged = _deep_merge(merged, _env_overrides())
    return AppSettings.model_validate(merged)


def write_default_config(paths: AppPaths) -> Path:
    """Create a user config file on first launch without overwriting it."""
    if not paths.config_file.exists():
        defaults = _read_yaml(resource_path("resources", "default_config.yaml"))
        paths.config_file.parent.mkdir(parents=True, exist_ok=True)
        paths.config_file.write_text(
            yaml.safe_dump(defaults, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
    return paths.config_file


def save_settings(settings: AppSettings, paths: AppPaths) -> Path:
    paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(
        yaml.safe_dump(settings.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return paths.config_file
