"""Tests for the 2.0 persistence, panel, reporting and detection layers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from marlonthebug.core.scope import ScopeConfig
from marlonthebug.core.workspace import TargetInfo
from marlonthebug.db.database import Database, sqlite_url
from marlonthebug.db.repository import Repository, finding_fingerprint
from marlonthebug.exploit.registry import ExploitRegistry
from marlonthebug.http.baseline import BaselineProbe, BaselineSample, similarity
from marlonthebug.paths import AppPaths
from marlonthebug.plugins.api.jwt import JWTAuditor
from marlonthebug.plugins.recon.endpoint_discovery import _content_is_valid
from marlonthebug.plugins.recon.supply_chain import SupplyChainAuditor
from marlonthebug.services.exploitation import ExploitationService, ExploitBlocked
from marlonthebug.services.intel import IntelService
from marlonthebug.services.reports import ReportRequest, ReportService
from marlonthebug.services.scanner import ScanManager
from marlonthebug.settings import load_settings
from marlonthebug.tools.catalog import tools_for_plugin
from marlonthebug.tools.docker_runner import docker_url
from marlonthebug.web.app import create_app


@pytest.fixture
def app_paths(tmp_path: Path) -> AppPaths:
    paths = AppPaths.resolve(data_dir=tmp_path / "data", portable=True)
    paths.ensure()
    return paths


async def _database(paths: AppPaths) -> tuple[Database, Repository]:
    database = Database(sqlite_url(paths.db_path), portable=True)
    await database.init()
    return database, Repository(database)


def test_paths_are_portable(tmp_path: Path) -> None:
    paths = AppPaths.resolve(data_dir=tmp_path / "portable", portable=True)
    paths.ensure()
    assert paths.db_path.exists() is False
    assert paths.db_path.parent == tmp_path / "portable"
    assert paths.reports_dir.exists()
    assert paths.logs_dir.exists()
    assert paths.token_path.parent == tmp_path / "portable"


def test_scope_is_fail_closed() -> None:
    scope = ScopeConfig(allowed_domains=["example.com", "*.example.com"])
    assert scope.is_domain_allowed("example.com")
    assert scope.is_domain_allowed("api.example.com")
    assert not scope.is_domain_allowed("evil.com")
    empty = ScopeConfig()
    assert not empty.is_domain_allowed("example.com")


def test_scope_accepts_ip_with_port() -> None:
    scope = ScopeConfig(allowed_ip_ranges=["127.0.0.1"])
    assert scope.is_url_allowed("http://127.0.0.1:8080/path")


def test_baseline_rejects_catch_all() -> None:
    sample = BaselineSample(
        url="https://example.com/__mtb",
        status_code=200,
        length=100,
        body="<html><body>SPA shell</body></html>",
        title="SPA",
        content_type="text/html",
    )
    probe = BaselineProbe(base_url="https://example.com", samples=[sample], catch_all=True)

    class FakeResponse:
        status_code = 200
        content_length = 100
        body = "<html><body>SPA shell</body></html>"

    assert probe.is_soft_404(FakeResponse())  # type: ignore[arg-type]
    assert probe.looks_like_app_shell(FakeResponse())  # type: ignore[arg-type]
    assert similarity("hello world", "hello world") == 1.0


def test_endpoint_content_validation() -> None:
    assert _content_is_valid(".git/HEAD", "ref: refs/heads/main\n", "text/plain")
    assert not _content_is_valid(".git/HEAD", "<html><body>SPA</body></html>", "text/html")
    assert _content_is_valid("robots.txt", "User-agent: *\nDisallow: /admin\n", "text/plain")
    assert not _content_is_valid("robots.txt", "<html>not found</html>", "text/html")
    assert _content_is_valid("package.json", '{"name":"demo","version":"1.0.0"}', "application/json")


async def test_repository_deduplicates_findings(app_paths: AppPaths) -> None:
    database, repo = await _database(app_paths)
    try:
        workspace = await repo.create_workspace("demo", client_name="Acme")
        target = await repo.add_target(workspace.id, "example.com")
        data = {
            "workspace_id": workspace.id,
            "target_id": target.id,
            "plugin_name": "sqli",
            "category": "web",
            "title": "SQL Injection en id",
            "description": "test",
            "severity": "critical",
            "endpoint": "https://example.com/item?id=1",
            "target_host": "example.com",
            "evidence": {"parameter": "id"},
            "fingerprint": finding_fingerprint(
                "sqli", "SQL Injection en id", "https://example.com/item?id=1", "example.com", "id"
            ),
        }
        first, created = await repo.upsert_finding(data)
        second, created_again = await repo.upsert_finding(data)
        assert created is True
        assert created_again is False
        assert first.id == second.id
        findings, total = await repo.list_findings(workspace_id=workspace.id)
        assert total == 1
        assert findings[0].severity == "critical"
    finally:
        await database.close()


async def test_report_generation_html(app_paths: AppPaths) -> None:
    database, repo = await _database(app_paths)
    try:
        settings = load_settings(app_paths)
        workspace = await repo.create_workspace("demo", client_name="Acme S.L.")
        target = await repo.add_target(workspace.id, "example.com")
        scan = await repo.create_scan(workspace.id, ["example.com"], ["web"], profile="standard")
        await repo.upsert_finding(
            {
                "workspace_id": workspace.id,
                "scan_run_id": scan.id,
                "target_id": target.id,
                "plugin_name": "xss",
                "category": "web",
                "title": "XSS reflejado en q",
                "description": "El parámetro q se refleja sin codificar.",
                "severity": "high",
                "confidence": "high",
                "cvss_score": 7.2,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "endpoint": "https://example.com/search?q=test",
                "target_host": "example.com",
                "evidence": {"parameter": "q", "payload": "<svg onload=alert(1)>"},
                "remediation": "Codifica la salida.",
                "references": [{"url": "https://owasp.org/www-community/attacks/xss/"}],
                "fingerprint": finding_fingerprint(
                    "xss", "XSS reflejado en q", "https://example.com/search?q=test", "example.com", "q"
                ),
            }
        )
        service = ReportService(repo, settings, app_paths)
        report = await service.generate(
            ReportRequest(
                workspace_id=workspace.id,
                scan_run_id=scan.id,
                format="html",
                template="full",
                language="es",
                client_name="Acme S.L.",
            )
        )
        path = Path(report.path)
        assert path.exists()
        html = path.read_text(encoding="utf-8")
        assert "XSS reflejado en q" in html
        assert "Acme S.L." in html
        assert "CVSS" in html
    finally:
        await database.close()


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


async def test_jwt_alg_none_detection() -> None:
    token = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': '1'})}."
    findings = [
        finding async for finding in JWTAuditor()._analyze(token, "cookie:session", TargetInfo(host="example.com"))
    ]
    assert findings
    assert findings[0].severity.value == "critical"
    assert "none" in findings[0].title.lower()


async def test_jwt_weak_secret_detection() -> None:
    header = _b64({"alg": "HS256", "typ": "JWT"})
    payload = _b64({"sub": "1", "exp": 9999999999})
    signature = (
        base64.urlsafe_b64encode(hmac.new(b"secret", f"{header}.{payload}".encode(), hashlib.sha256).digest())
        .rstrip(b"=")
        .decode()
    )
    token = f"{header}.{payload}.{signature}"
    findings = [
        finding
        async for finding in JWTAuditor()._analyze(token, "header:authorization", TargetInfo(host="example.com"))
    ]
    assert any("secreto débil" in finding.title for finding in findings)


def test_supply_chain_manifest_parser() -> None:
    dependencies = SupplyChainAuditor._parse_manifest(
        "package.json",
        json.dumps({"dependencies": {"lodash": "^4.17.20", "react": "18.2.0"}}),
    )
    assert ("lodash", "4.17.20") in dependencies
    assert ("react", "18.2.0") in dependencies


def test_panel_auth_and_csrf(app_paths: AppPaths) -> None:
    settings = load_settings(app_paths)
    settings.intel.auto_sync = False
    app = create_app(app_paths, settings, auth_enabled=True)
    with TestClient(app) as client:
        assert client.get("/login").status_code == 200
        token = app.state.auth.token
        response = client.post("/login", data={"token": token, "next": "/"}, follow_redirects=False)
        assert response.status_code == 303
        page = client.get("/workspaces")
        assert page.status_code == 200
        match = re.search(r'name="csrf" value="([^"]+)"', page.text)
        assert match
        csrf = match.group(1)
        created = client.post("/workspaces", data={"name": "auth-demo", "csrf": csrf}, follow_redirects=False)
        assert created.status_code == 303
        rejected = client.post("/workspaces", data={"name": "auth-demo-2"}, follow_redirects=False)
        assert rejected.status_code == 403


def test_panel_pages_render(app_paths: AppPaths) -> None:
    settings = load_settings(app_paths)
    settings.intel.auto_sync = False
    app = create_app(app_paths, settings, auth_enabled=False)
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        response = client.post("/workspaces", data={"name": "web-test", "client_name": "Acme"}, follow_redirects=False)
        assert response.status_code == 303
        assert client.get("/workspaces").status_code == 200
        assert client.get("/scans/new").status_code == 200
        assert client.get("/findings").status_code == 200
        assert client.get("/reports/new").status_code == 200
        assert client.get("/intel").status_code == 200
        assert client.get("/settings").status_code == 200
        assert client.get("/api/workspaces").status_code == 200


async def test_scan_pipeline_against_local_server(app_paths: AppPaths) -> None:
    shell = b"<html><head><title>Demo</title></head><body><a href='/search?q=test'>Search</a></body></html>"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args) -> None:
            return

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            if parsed.path == "/search":
                value = query.get("q", [""])[0]
                body = (
                    b"SQL syntax error MySQL"
                    if "'" in value
                    else f"<html><body>{value}<svg onload=alert(1)></body></html>".encode()
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if parsed.path == "/.git/HEAD":
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(shell)))
            self.end_headers()
            self.wfile.write(shell)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    host = f"127.0.0.1:{server.server_address[1]}"
    database, repo = await _database(app_paths)
    try:
        settings = load_settings(app_paths)
        settings.intel.offline = True
        settings.scan.requests_per_second = 40
        workspace = await repo.create_workspace("scan-test")
        target = await repo.add_target(workspace.id, host)
        scan = await repo.create_scan(
            workspace.id,
            [target.host],
            ["recon", "web"],
            modules=[
                "recon/tech_fingerprint",
                "recon/endpoint_discovery",
                "recon/git_leaks",
                "web/sqli",
                "web/xss",
            ],
            profile="safe",
            options={"max_requests": 400},
        )
        manager = ScanManager(repo, settings, IntelService(repo, settings, app_paths))
        await manager.start(scan.id)
        await manager.tasks[scan.id]
        findings, _ = await repo.list_findings(workspace_id=workspace.id, page_size=100)
        plugins = {finding.plugin_name for finding in findings}
        assert "sqli" in plugins
        assert "xss" in plugins
        assert "git_leaks" not in plugins
        assert not any(finding.endpoint.endswith("/.env") for finding in findings)
        stored_scan = await repo.get_scan(scan.id)
        assert stored_scan is not None
        assert stored_scan.status == "completed"
    finally:
        await database.close()
        server.shutdown()


def test_exploit_registry_maps_findings() -> None:
    registry = ExploitRegistry()
    registry.discover()
    assert registry.for_plugin("sqli")
    assert registry.for_plugin("xss")
    assert registry.for_plugin("lfi_rfi")
    assert not registry.for_plugin("tech_fingerprint")


def test_tool_catalog_and_docker_url() -> None:
    sqli_tools = {tool.key for tool in tools_for_plugin("sqli")}
    assert {"sqlmap", "nuclei"}.issubset(sqli_tools)
    assert "nuclei" in {tool.key for tool in tools_for_plugin("xss")}
    assert tools_for_plugin("secret_finder") == []
    assert docker_url("http://127.0.0.1:8080/app?q=1") == "http://host.docker.internal:8080/app?q=1"
    assert docker_url("https://example.com") == "https://example.com"


async def test_exploitation_requires_workspace_flag(app_paths: AppPaths) -> None:
    database, repo = await _database(app_paths)
    try:
        settings = load_settings(app_paths)
        workspace = await repo.create_workspace("exploit-blocked", allow_exploitation=False)
        target = await repo.add_target(workspace.id, "example.com")
        finding, _ = await repo.upsert_finding(
            {
                "workspace_id": workspace.id,
                "target_id": target.id,
                "plugin_name": "xss",
                "category": "web",
                "title": "XSS de prueba",
                "description": "test",
                "severity": "high",
                "endpoint": "https://example.com/?q=test",
                "target_host": "example.com",
                "evidence": {"parameter": "q"},
                "fingerprint": finding_fingerprint(
                    "xss", "XSS de prueba", "https://example.com/?q=test", "example.com", "q"
                ),
            }
        )
        service = ExploitationService(repo, settings, app_paths)
        with pytest.raises(ExploitBlocked):
            await service.run(finding.id, "webapp/xss_exploit", "EXPLOTAR")
    finally:
        await database.close()
