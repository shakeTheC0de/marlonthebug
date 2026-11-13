"""FastAPI dependencies and shared template helpers."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlencode

from fastapi import Request
from fastapi.templating import Jinja2Templates

from marlonthebug.db.repository import Repository
from marlonthebug.paths import AppPaths
from marlonthebug.plugins.registry import PluginRegistry
from marlonthebug.services.exploitation import ExploitationService
from marlonthebug.services.intel import IntelService
from marlonthebug.services.reports import ReportService
from marlonthebug.services.scanner import ScanManager
from marlonthebug.settings import AppSettings
from marlonthebug.tools.service import ToolService
from marlonthebug.web.security import PanelAuth


def get_repo(request: Request) -> Repository:
    return request.app.state.repo


def get_settings(request: Request) -> AppSettings:
    return request.app.state.settings


def get_paths(request: Request) -> AppPaths:
    return request.app.state.paths


def get_scans(request: Request) -> ScanManager:
    return request.app.state.scan_manager


def get_intel(request: Request) -> IntelService:
    return request.app.state.intel


def get_reports(request: Request) -> ReportService:
    return request.app.state.report_service


def get_exploitation(request: Request) -> ExploitationService:
    return request.app.state.exploitation


def get_tools(request: Request) -> ToolService:
    return request.app.state.tools


def get_templates(request: Request) -> Jinja2Templates:
    return request.app.state.templates


def get_auth(request: Request) -> PanelAuth:
    return request.app.state.auth


async def render(request: Request, template: str, status_code: int = 200, **context: Any):
    repository = get_repo(request)
    workspaces = await repository.list_workspaces()
    workspace_id = context.get("workspace_id") or request.query_params.get("workspace")
    current = next((item for item in workspaces if item.id == workspace_id), None)
    if current is None and workspaces:
        current = workspaces[0]
    context.setdefault("workspaces", workspaces)
    context.setdefault("current_workspace", current)
    context.setdefault("workspace_id", current.id if current else "")
    context.setdefault("csrf", getattr(request.state, "csrf", ""))
    context.setdefault("nav", "")
    context.setdefault("flash_ok", request.query_params.get("ok"))
    context.setdefault("flash_err", request.query_params.get("err"))
    context.setdefault("request", request)
    context.setdefault("app_version", request.app.version)
    context.setdefault("current_path", request.url.path)
    return get_templates(request).TemplateResponse(
        request=request,
        name=template,
        context=context,
        status_code=status_code,
    )


def split_values(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip() for item in re.split(r"[,;\n]+", raw) if item.strip()]


def parse_headers(raw: str | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw_line in (raw or "").splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip():
            headers[key.strip()] = value.strip()
    return headers


def parse_cookies(raw: str | None) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for chunk in (raw or "").replace("\n", ";").split(";"):
        if "=" not in chunk:
            continue
        key, value = chunk.split("=", 1)
        if key.strip():
            cookies[key.strip()] = value.strip()
    return cookies


def plugin_groups(request: Request) -> dict[str, list[dict[str, Any]]]:
    cached = getattr(request.app.state, "plugin_groups", None)
    if cached is not None:
        return cached
    registry = PluginRegistry()
    registry.discover()
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for key, instance in registry._instances.items():
        groups[instance.category].append(
            {
                "key": key,
                "name": instance.name,
                "description": instance.description,
                "category": instance.category,
                "version": instance.version,
                "beta": getattr(instance, "beta", False),
            }
        )
    for items in groups.values():
        items.sort(key=lambda item: item["name"])
    result = dict(groups)
    request.app.state.plugin_groups = result
    return result


def query_string(request: Request, **updates: Any) -> str:
    params: dict[str, Any] = dict(request.query_params)
    for key, value in updates.items():
        if value is None:
            params.pop(key, None)
        elif isinstance(value, list):
            params.pop(key, None)
            params[key] = value
        else:
            params[key] = str(value)
    return urlencode(params, doseq=True)
