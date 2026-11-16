"""Shared detection of edge/CDN error pages that are not real application content."""

from __future__ import annotations

from typing import Any

EDGE_ERROR_STATUS = {520, 521, 522, 523, 524, 525, 526, 530}
EDGE_ERROR_MARKERS = (
    "ssl handshake failed",
    "origin is unreachable",
    "web server is down",
    "cloudflare",
    "error 525",
    "error 526",
    "error 523",
    "errorcode_525",
    "5xx-error-landing",
    "cloudflare-5xx-errors",
    "cf-error-details",
)


def is_edge_error(response: Any) -> bool:
    if getattr(response, "status_code", 0) in EDGE_ERROR_STATUS:
        return True
    body = str(getattr(response, "body", "") or "").lower()
    return any(marker in body for marker in EDGE_ERROR_MARKERS)
