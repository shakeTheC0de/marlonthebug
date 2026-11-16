"""Tests for the portable Docker stack, tool backends and backups."""

from __future__ import annotations

import io
import json
import sqlite3
import tarfile
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from marlonthebug.paths import AppPaths
from marlonthebug.services.backup import BackupError, create_backup, restore_backup
from marlonthebug.settings import AppSettings, ToolSettings, load_settings
from marlonthebug.tools import runner_api
from marlonthebug.tools.catalog import TOOLS, build_command
from marlonthebug.tools.local_runner import LocalToolRunner
from marlonthebug.tools.remote_runner import RemoteToolRunner
from marlonthebug.tools.runner_api import ToolValidationError, validate_run_request
from marlonthebug.tools.runner_factory import build_tool_runner
from marlonthebug.tools.service import ToolService


class _FakeTarget:
    host = "127.0.0.1"


class _FakeFinding:
    endpoint = "http://127.0.0.1:8000/item?id=1"
    target = _FakeTarget()
    plugin_name = "sqli"


@pytest.fixture
def app_paths(tmp_path: Path) -> AppPaths:
    paths = AppPaths.resolve(data_dir=tmp_path / "data", portable=True)
    paths.ensure()
    return paths


@pytest.fixture(autouse=True)
def reset_runner_semaphore() -> None:
    runner_api.app.state.tool_semaphore = None
    yield
    runner_api.app.state.tool_semaphore = None


def test_catalog_commands_pass_runner_validation() -> None:
    finding = _FakeFinding()
    for tool in TOOLS.values():
        target, args = build_command(tool, finding)
        request = validate_run_request(
            {
                "tool": tool.key,
                "args": args,
                "target": target,
                "timeout": 120,
            }
        )
        assert request.tool == tool.key
        assert request.args == args


def test_runner_rejects_dangerous_arguments() -> None:
    target = "http://127.0.0.1:8000/item?id=1"
    with pytest.raises(ToolValidationError):
        validate_run_request(
            {
                "tool": "sqlmap",
                "args": ["sqlmap", "-u", target, "--batch", "--os-shell"],
                "target": target,
                "timeout": 60,
            }
        )
    with pytest.raises(ToolValidationError):
        validate_run_request(
            {
                "tool": "commix",
                "args": ["commix", f"--url={target}", "--batch", "--os-cmd=rm -rf /"],
                "target": target,
                "timeout": 60,
            }
        )
    with pytest.raises(ToolValidationError):
        validate_run_request(
            {
                "tool": "nmap",
                "args": ["nmap", "-Pn", "--script", "vulners", "127.0.0.1"],
                "target": "127.0.0.1",
                "timeout": 60,
            }
        )
    with pytest.raises(ToolValidationError):
        validate_run_request(
            {
                "tool": "nmap",
                "args": ["nmap", "-Pn", "evil.example"],
                "target": "127.0.0.1",
                "timeout": 60,
            }
        )


def test_runner_timeout_and_tool_allowlist() -> None:
    target = "http://127.0.0.1:8000/item?id=1"
    with pytest.raises(ToolValidationError):
        validate_run_request({"tool": "bash", "args": ["bash", "-c", "id"], "target": target, "timeout": 30})
    with pytest.raises(ToolValidationError):
        validate_run_request(
            {
                "tool": "sqlmap",
                "args": ["sqlmap", "-u", target],
                "target": target,
                "timeout": 9999,
            }
        )


def test_runner_accepts_host_port_and_uppercase_scheme() -> None:
    host_port = validate_run_request(
        {
            "tool": "nmap",
            "args": ["nmap", "-Pn", "-sV", "--top-ports", "100", "example.com:8080"],
            "target": "example.com:8080",
            "timeout": 60,
        }
    )
    assert host_port.target == "example.com:8080"
    uppercase = validate_run_request(
        {
            "tool": "whatweb",
            "args": ["whatweb", "HTTP://example.com/", "--no-errors"],
            "target": "HTTP://example.com/",
            "timeout": 60,
        }
    )
    assert uppercase.tool == "whatweb"


def test_runner_api_auth_and_health(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MTB_TOOLS_TOKEN", "secret")
    client = TestClient(runner_api.app)
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert "sqlmap" in health.json()["tools"]

    payload = {
        "tool": "sqlmap",
        "args": ["sqlmap", "-u", "http://127.0.0.1:8000/item?id=1", "--batch"],
        "target": "http://127.0.0.1:8000/item?id=1",
        "timeout": 60,
    }
    assert client.post("/run", json=payload).status_code == 401
    assert client.post("/run", json=payload, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert (
        client.post(
            "/run",
            json={"tool": "bash", "args": ["bash", "-c", "id"], "target": "http://127.0.0.1", "timeout": 60},
            headers={"Authorization": "Bearer secret"},
        ).status_code
        == 422
    )


def test_runner_api_executes_validated_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MTB_TOOLS_TOKEN", "secret")

    async def fake_execute(request: runner_api.RunRequest) -> dict[str, Any]:
        assert request.tool == "sqlmap"
        return {
            "tool": request.tool,
            "command": request.command,
            "output": "Parameter: id (GET)\nit is vulnerable",
            "error": "",
            "returncode": 0,
            "duration": 0.1,
            "timed_out": False,
            "truncated": False,
        }

    monkeypatch.setattr(runner_api, "execute_tool", fake_execute)
    client = TestClient(runner_api.app)
    payload = {
        "tool": "sqlmap",
        "args": ["sqlmap", "-u", "http://127.0.0.1:8000/item?id=1", "--batch"],
        "target": "http://127.0.0.1:8000/item?id=1",
        "timeout": 60,
    }
    response = client.post("/run", json=payload, headers={"Authorization": "Bearer secret"})
    assert response.status_code == 200
    assert "vulnerable" in response.json()["output"]
    assert response.json()["command"] == payload["args"]

    too_large = client.post(
        "/run",
        content=b"x" * (runner_api.MAX_BODY_BYTES + 1),
        headers={"Authorization": "Bearer secret", "Content-Type": "application/json"},
    )
    assert too_large.status_code == 413


async def test_remote_runner_maps_health_and_result() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/healthz":
            return httpx.Response(200, json={"status": "ok", "version": "2.0.0", "tools": ["sqlmap", "nuclei"]})
        if request.url.path == "/run":
            payload = json.loads(request.content)
            assert payload["tool"] == "sqlmap"
            return httpx.Response(
                200,
                json={
                    "tool": "sqlmap",
                    "command": payload["args"],
                    "output": "Parameter: id (GET)\nit is vulnerable",
                    "error": "",
                    "returncode": 0,
                    "duration": 1.25,
                    "timed_out": False,
                    "truncated": False,
                },
            )
        return httpx.Response(404)

    settings = ToolSettings(
        backend="remote",
        remote_url="http://runner",
        remote_token="secret",
        timeout=60,
    )
    runner = RemoteToolRunner(settings, transport=httpx.MockTransport(handler))
    status = await runner.status()
    assert status["available"] is True
    assert status["backend"] == "remote"
    result = await runner.run(
        "sqlmap",
        ["sqlmap", "-u", "http://127.0.0.1:8000/item?id=1", "--batch"],
        "http://127.0.0.1:8000/item?id=1",
    )
    assert result.success is True
    assert result.evidence["backend"] == "remote"
    assert result.evidence["returncode"] == 0
    assert "vulnerable" in result.output


async def test_remote_runner_reports_unreachable_and_auth_errors() -> None:
    settings = ToolSettings(backend="remote", remote_url="http://runner", remote_token="secret")

    def unreachable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    runner = RemoteToolRunner(settings, transport=httpx.MockTransport(unreachable))
    status = await runner.status()
    assert status["available"] is False
    assert "no disponible" in status["reason"]
    result = await runner.run("nmap", ["nmap", "-Pn", "127.0.0.1"], "127.0.0.1")
    assert result.success is False
    assert "No se pudo contactar" in result.error

    def unauthorized(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "Token inválido o ausente"})

    runner = RemoteToolRunner(settings, transport=httpx.MockTransport(unauthorized))
    result = await runner.run("nmap", ["nmap", "-Pn", "127.0.0.1"], "127.0.0.1")
    assert result.success is False
    assert "Token inválido" in result.error


async def test_local_runner_status() -> None:
    runner = LocalToolRunner(ToolSettings(backend="local"))
    status = await runner.status()
    assert status["backend"] == "local"
    assert "sqlmap" in status["tools"]


def test_tool_service_rebuilds_runner(app_paths: AppPaths) -> None:
    settings = AppSettings()
    settings.tools.backend = "remote"
    service = ToolService(None, settings, app_paths)  # type: ignore[arg-type]
    assert isinstance(service.runner, RemoteToolRunner)
    settings.tools.backend = "local"
    service.configure(settings)
    assert isinstance(service.runner, LocalToolRunner)
    settings.tools.backend = "docker"
    assert build_tool_runner(settings.tools).backend == "docker"


def test_settings_environment_overrides(app_paths: AppPaths, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MTB_PANEL_PORT", "9999")
    monkeypatch.setenv("MTB_TOOLS_BACKEND", "remote")
    monkeypatch.setenv("MTB_TOOLS_URL", "http://runner:8080")
    monkeypatch.setenv("MTB_TOOLS_TOKEN", "secret")
    monkeypatch.setenv("MTB_TOOLS_TIMEOUT", "240")
    settings = load_settings(app_paths)
    assert settings.panel.port == 9999
    assert settings.tools.backend == "remote"
    assert settings.tools.remote_url == "http://runner:8080"
    assert settings.tools.remote_token == "secret"
    assert settings.tools.timeout == 240

    monkeypatch.setenv("MTB_TOOLS_BACKEND", "not-a-backend")
    assert load_settings(app_paths).tools.backend == "docker"


def test_app_paths_honors_mtb_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "mtb-data"
    monkeypatch.setenv("MTB_DATA_DIR", str(target))
    paths = AppPaths.resolve()
    assert paths.root == target.resolve()
    assert paths.config_dir == paths.root / "config"


def test_backup_roundtrip(app_paths: AppPaths, tmp_path: Path) -> None:
    connection = sqlite3.connect(app_paths.db_path)
    connection.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY, name TEXT)")
    connection.execute("INSERT INTO sample (name) VALUES ('before')")
    connection.commit()
    connection.close()
    (app_paths.config_dir / "config.yaml").write_text("panel:\n  port: 8765\n", encoding="utf-8")
    report = app_paths.reports_dir / "report.txt"
    report.write_text("informe", encoding="utf-8")
    (app_paths.feeds_dir / "kev.json").write_text("{}", encoding="utf-8")
    app_paths.token_path.write_text("token", encoding="utf-8")
    (app_paths.logs_dir / "app.log").write_text("log", encoding="utf-8")

    archive = create_backup(app_paths, tmp_path / "backup.tar.gz", include_logs=True)
    assert archive.exists()
    assert tarfile.is_tarfile(archive)

    app_paths.db_path.unlink()
    report.unlink()
    app_paths.token_path.unlink()
    stats = restore_backup(archive, app_paths, force=True)
    assert stats["files"] >= 4
    assert report.read_text(encoding="utf-8") == "informe"
    assert app_paths.token_path.read_text(encoding="utf-8") == "token"
    connection = sqlite3.connect(app_paths.db_path)
    try:
        assert connection.execute("SELECT name FROM sample").fetchone()[0] == "before"
    finally:
        connection.close()

    with pytest.raises(BackupError):
        create_backup(app_paths, tmp_path / "backup.tar.gz")
    with pytest.raises(BackupError):
        restore_backup(archive, app_paths)


def test_restore_rejects_path_traversal(app_paths: AppPaths, tmp_path: Path) -> None:
    archive_path = tmp_path / "evil.tar.gz"
    payload = b"owned"
    with tarfile.open(archive_path, "w:gz") as archive:
        info = tarfile.TarInfo("../evil.txt")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    with pytest.raises(BackupError):
        restore_backup(archive_path, app_paths, force=True)
    assert not (tmp_path / "evil.txt").exists()


def test_compose_stack_is_socketless_and_local_only() -> None:
    compose_text = Path("docker-compose.yml").read_text(encoding="utf-8")
    compose = yaml.safe_load(compose_text)
    assert set(compose["services"]) == {"panel", "tools-runner"}
    panel = compose["services"]["panel"]
    runner = compose["services"]["tools-runner"]
    assert str(panel["ports"][0]).startswith("127.0.0.1:")
    assert "ports" not in runner
    assert runner["expose"] == ["8080"]
    assert "/var/run/docker.sock" not in compose_text
    assert panel["read_only"] is True
    assert runner["read_only"] is True
    assert panel["cap_drop"] == ["ALL"]
    assert runner["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in panel["security_opt"]
    assert "no-new-privileges:true" in runner["security_opt"]
    assert "remote" in str(panel["environment"]["MTB_TOOLS_BACKEND"])
    assert "MTB_TOOLS_TOKEN" in runner["environment"]

    panel_dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    tools_dockerfile = Path("Dockerfile.tools").read_text(encoding="utf-8")
    assert '"--data-dir", "/data"' in panel_dockerfile
    assert "docker.sock" not in panel_dockerfile
    assert "runner_api" in tools_dockerfile
    assert "marlonthebug.tools.runner_api" in tools_dockerfile
