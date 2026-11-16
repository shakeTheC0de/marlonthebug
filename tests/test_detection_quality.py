"""Detection-quality tests for noisy heuristics."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from marlonthebug.http.errors import is_edge_error
from marlonthebug.plugins.recon.endpoint_discovery import is_interesting_forbidden
from marlonthebug.plugins.web import cache_poisoning
from marlonthebug.plugins.web.prototype_pollution import has_proto_sink


class _Response:
    def __init__(self, body: str, headers: dict[str, str] | None = None) -> None:
        self.body = body
        self.headers = headers or {}
        self.status_code = 200

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


def _run_plugin(monkeypatch: pytest.MonkeyPatch, response_body: str) -> list:
    class FakeHTTP:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def get(self, url: str, headers: dict[str, str] | None = None) -> _Response:
            value = next(iter((headers or {}).values()), "")
            return _Response(response_body.replace("CANARY", value), {"cf-cache-status": "MISS"})

        async def close(self) -> None:
            return None

    monkeypatch.setattr(cache_poisoning, "AsyncHTTPClient", FakeHTTP)
    plugin = cache_poisoning.CachePoisoningAuditor()
    target = SimpleNamespace(host="example.com")
    findings: list = []

    async def collect() -> None:
        async for finding in plugin.run(target, {"base_url": "https://example.com"}):
            findings.append(finding)

    asyncio.run(collect())
    return findings


def test_cache_poisoning_ignores_cache_miss_without_reflection(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _run_plugin(monkeypatch, "<html>normal</html>") == []


def test_cache_poisoning_reports_reflected_header(monkeypatch: pytest.MonkeyPatch) -> None:
    findings = _run_plugin(monkeypatch, "<html>CANARY</html>")
    assert findings
    assert all(finding.evidence["reflected"] is True for finding in findings)
    assert all(finding.evidence["cache_headers"]["cf-cache-status"] == "MISS" for finding in findings)


def test_prototype_pollution_requires_explicit_proto_key() -> None:
    generic_bundle = "const q = location.search; obj[key] = value;"
    assert has_proto_sink(generic_bundle) is False
    vulnerable_bundle = "Object.assign(target, JSON.parse(location.hash)); // __proto__"
    assert has_proto_sink(vulnerable_bundle) is True


def test_edge_error_detection_ignores_cloudflare_error_pages() -> None:
    assert is_edge_error(SimpleNamespace(status_code=200, body="errorcode_525 landing"))
    assert is_edge_error(SimpleNamespace(status_code=525, body=""))
    assert not is_edge_error(SimpleNamespace(status_code=200, body="<html>real app</html>"))


def test_generic_forbidden_paths_are_not_reported() -> None:
    assert is_interesting_forbidden(".env") is True
    assert is_interesting_forbidden(".git/HEAD") is True
    assert is_interesting_forbidden("cgi-bin") is False
    assert is_interesting_forbidden(".htaccess") is False


def test_guided_playbooks_cover_findings_without_modules() -> None:
    from marlonthebug.services.playbooks import playbook_for

    assert playbook_for("openapi")["kind"] == "guided"
    assert playbook_for("auth_bypass")["kind"] == "self_tested"
    assert playbook_for("request_smuggling")["kind"] == "manual"
    assert playbook_for("unknown-plugin") is None


def test_rce_post_exploitation_replaces_only_the_command() -> None:
    from marlonthebug.exploit.webapp.rce_exploit import _replace_command

    assert _replace_command("; id", "hostname") == "; hostname"
    assert _replace_command("| id", "uname -a") == "| uname -a"
    assert _replace_command("$(id)", "hostname") == "$(hostname)"
    assert _replace_command("`id`", "hostname") == "`hostname`"
