"""Response baselines and soft-404 detection.

Modern applications frequently answer every path with the same SPA shell and
HTTP 200.  Treating that as a finding is the fastest way to lose credibility,
so every discovery plugin compares responses against randomly generated paths
before reporting anything.
"""

from __future__ import annotations

import difflib
import re
import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from marlonthebug.http.client import AsyncHTTPClient, HttpResponse


_WHITESPACE_RE = re.compile(r"\s+")
_RANDOM_TOKEN_RE = re.compile(r"[a-f0-9]{8,}", re.IGNORECASE)


def normalize_body(body: str, limit: int = 4000) -> str:
    text = body[:limit].lower()
    text = _RANDOM_TOKEN_RE.sub("#", text)
    return _WHITESPACE_RE.sub(" ", text).strip()


def similarity(left: str, right: str) -> float:
    a = normalize_body(left)
    b = normalize_body(right)
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


@dataclass
class BaselineSample:
    url: str
    status_code: int
    length: int
    body: str
    title: str
    content_type: str


@dataclass
class BaselineProbe:
    base_url: str
    samples: list[BaselineSample] = field(default_factory=list)
    catch_all: bool = False

    @property
    def primary(self) -> BaselineSample | None:
        return self.samples[0] if self.samples else None

    def is_soft_404(self, response: HttpResponse) -> bool:
        """Return True when a response is indistinguishable from a random path."""
        if not self.samples:
            return False
        if response.status_code in (404, 410):
            return True
        for sample in self.samples:
            if response.status_code != sample.status_code:
                continue
            length_delta = abs(response.content_length - sample.length)
            tolerance = max(64, int(sample.length * 0.08))
            if length_delta <= tolerance and similarity(response.body, sample.body) >= 0.92:
                return True
        return False

    def looks_like_app_shell(self, response: HttpResponse) -> bool:
        if self.is_soft_404(response):
            return True
        if self.catch_all and self.primary:
            return (
                response.status_code == self.primary.status_code
                and similarity(response.body, self.primary.body) >= 0.85
            )
        return False


async def build_baseline(
    http: AsyncHTTPClient,
    base_url: str,
    extra_paths: list[str] | None = None,
) -> BaselineProbe:
    token = secrets.token_hex(8)
    paths = extra_paths or [
        f"/__mtb_{token}",
        f"/__mtb_{token}.html",
        f"/__mtb_{token}/",
        f"/api/__mtb_{token}",
        f"/.well-known/__mtb_{token}",
    ]
    samples: list[BaselineSample] = []
    for path in paths:
        try:
            response = await http.get(f"{base_url.rstrip('/')}{path}")
        except Exception:
            continue
        samples.append(
            BaselineSample(
                url=str(response.url),
                status_code=response.status_code,
                length=response.content_length,
                body=response.body,
                title=response.title,
                content_type=response.headers.get("content-type", ""),
            )
        )

    probe = BaselineProbe(base_url=base_url, samples=samples)
    if len(samples) >= 2:
        statuses = {sample.status_code for sample in samples}
        bodies = {normalize_body(sample.body) for sample in samples}
        lengths = [sample.length for sample in samples]
        same_status = len(statuses) == 1
        same_body = len(bodies) == 1
        close_length = max(lengths) - min(lengths) <= max(64, int(max(lengths) * 0.08))
        probe.catch_all = bool(same_status and (same_body or close_length))
    return probe
