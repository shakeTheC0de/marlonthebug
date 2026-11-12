"""Jinja filters shared by the panel templates."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

SEVERITY_ES = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Media",
    "low": "Baja",
    "info": "Informativa",
}
STATUS_ES = {
    "open": "Abierto",
    "confirmed": "Confirmado",
    "false_positive": "Falso positivo",
    "accepted": "Riesgo aceptado",
    "remediated": "Remediado",
}
CONFIDENCE_ES = {"high": "Alta", "medium": "Media", "low": "Baja"}
SCAN_STATUS_ES = {
    "pending": "Pendiente",
    "running": "En curso",
    "completed": "Completado",
    "failed": "Fallido",
    "cancelled": "Cancelado",
    "interrupted": "Interrumpido",
}


def datetimefmt(value: Any, fmt: str = "%d/%m/%Y %H:%M") -> str:
    if not value:
        return "—"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.strftime(fmt)
    return str(value)


def relative_time(value: Any) -> str:
    if not value:
        return "—"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    if not isinstance(value, datetime):
        return str(value)
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    delta = datetime.now(UTC) - value
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return "hace unos segundos"
    if seconds < 3600:
        return f"hace {seconds // 60} min"
    if seconds < 86400:
        return f"hace {seconds // 3600} h"
    return f"hace {seconds // 86400} d"


def severity_label(value: str) -> str:
    return SEVERITY_ES.get(value, value)


def status_label(value: str) -> str:
    return STATUS_ES.get(value, value)


def confidence_label(value: str) -> str:
    return CONFIDENCE_ES.get(value, value)


def scan_status_label(value: str) -> str:
    return SCAN_STATUS_ES.get(value, value)


def filesize(value: int | None) -> str:
    if not value:
        return "0 B"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} GB"


def json_pretty(value: Any, indent: int = 2) -> str:
    try:
        return json.dumps(value, indent=indent, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def host_of(value: str) -> str:
    if not value:
        return ""
    try:
        return urlparse(value).hostname or value
    except ValueError:
        return value


def truncate(value: str, length: int = 80) -> str:
    if not value:
        return ""
    return value if len(value) <= length else value[: length - 1] + "…"


def cvss_class(value: float | None) -> str:
    score = float(value or 0)
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def percent(value: float | None, total: float | None) -> int:
    if not total:
        return 0
    return min(100, int((float(value or 0) / float(total)) * 100))
