"""Tests for CPE correlation, feed freshness and signed bundles."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from marlonthebug.cli.app import cli
from marlonthebug.paths import AppPaths
from marlonthebug.services.cpe import cpe_for, from_tech_details, from_technologies, normalize_version
from marlonthebug.services.intel import IntelService
from marlonthebug.services.signing import (
    SigningError,
    generate_keypair,
    public_key_fingerprint,
    sign_bundle,
    verify_bundle,
)
from marlonthebug.settings import AppSettings, load_settings


class FakeRepository:
    def __init__(self, feed: Any | None = None) -> None:
        self.feed = feed
        self.replaced: tuple[str, list[dict[str, Any]]] | None = None
        self.search_calls = 0
        self.search_result: list[Any] = []
        self.feed_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.cves: list[dict[str, Any]] = []

    async def get_feed(self, name: str) -> Any | None:
        return self.feed

    async def replace_asset_intel(self, target_id: str, rows: list[dict[str, Any]]) -> int:
        self.replaced = (target_id, rows)
        return len(rows)

    async def search_cves(self, query: str, limit: int = 10) -> list[Any]:
        self.search_calls += 1
        return self.search_result

    async def upsert_feed(self, *args: Any, **kwargs: Any) -> Any:
        self.feed_calls.append((args, kwargs))
        return self.feed

    async def bulk_upsert_cves(self, rows: list[dict[str, Any]]) -> None:
        self.cves.extend(rows)

    async def list_feeds(self) -> list[Any]:
        return [self.feed] if self.feed else []

    async def intel_stats(self) -> dict[str, int]:
        return {"total": 1, "kev": 0, "epss": 0, "nvd": 1}


@pytest.fixture
def app_paths(tmp_path: Path) -> AppPaths:
    paths = AppPaths.resolve(data_dir=tmp_path / "data", portable=True)
    paths.ensure()
    return paths


@pytest.fixture
def settings() -> AppSettings:
    return AppSettings()


def test_cpe_mapping_normalizes_versions() -> None:
    assert normalize_version("Apache/2.4.58 (Ubuntu)") == "2.4.58"
    assert normalize_version("v18.2.0") == "18.2.0"
    assert normalize_version("1.24.0-ubuntu") == "1.24.0-ubuntu"
    assert normalize_version("no version") == ""
    assert cpe_for("nginx", "1.24.0") == "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
    assert cpe_for("Apache", "2.4.58") == "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"
    assert cpe_for("React", "18.2.0") == "cpe:2.3:a:facebook:react:18.2.0:*:*:*:*:*:*:*"
    assert cpe_for("Unknown", "1.2.3") == ""


def test_cpe_extraction_deduplicates() -> None:
    details = [
        {"name": "nginx", "version": "1.24.0"},
        {"name": "nginx", "version": "1.24.0"},
        {"name": "WordPress", "version": "6.4.2"},
        {"name": "jQuery", "version": ""},
    ]
    rows = from_tech_details(details)
    assert [row.cpe for row in rows] == [
        "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*",
    ]
    labels = from_technologies(["nginx 1.24.0", "WordPress 6.4.2", "jQuery"])
    assert len(labels) == 2


async def test_match_target_uses_cpe_without_keyword_noise(app_paths: AppPaths, settings: AppSettings) -> None:
    repository = FakeRepository()
    service = IntelService(repository, settings, app_paths)  # type: ignore[arg-type]
    calls: list[str] = []

    async def fake_lookup(cpe: str, limit: int = 100) -> list[dict[str, Any]]:
        calls.append(cpe)
        return [{"cve_id": "CVE-2024-0001", "cvss_score": 9.8}]

    service.lookup_cpe = fake_lookup  # type: ignore[method-assign]
    target = SimpleNamespace(
        id="target-1",
        technologies=["nginx 1.24.0"],
        metadata_={"tech_details": [{"name": "nginx", "version": "1.24.0"}]},
    )
    rows = await service.match_target(target)  # type: ignore[arg-type]
    assert len(rows) == 1
    assert rows[0]["match_type"] == "cpe"
    assert rows[0]["confidence"] == "high"
    assert repository.search_calls == 0
    assert calls == ["cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"]
    assert repository.replaced == ("target-1", rows)

    async def empty_lookup(cpe: str, limit: int = 100) -> list[dict[str, Any]]:
        return []

    service.lookup_cpe = empty_lookup  # type: ignore[method-assign]
    rows = await service.match_target(target)  # type: ignore[arg-type]
    assert rows == []
    assert repository.search_calls == 0


async def test_match_target_falls_back_when_nvd_is_unreachable(app_paths: AppPaths, settings: AppSettings) -> None:
    repository = FakeRepository()
    repository.search_result = [SimpleNamespace(cve_id="CVE-2020-0001", source="nvd")]
    service = IntelService(repository, settings, app_paths)  # type: ignore[arg-type]

    async def failed_lookup(cpe: str, limit: int = 100) -> None:
        return None

    service.lookup_cpe = failed_lookup  # type: ignore[method-assign]
    target = SimpleNamespace(
        id="target-2",
        technologies=["nginx 1.24.0"],
        metadata_={"tech_details": [{"name": "nginx", "version": "1.24.0"}]},
    )
    rows = await service.match_target(target)  # type: ignore[arg-type]
    assert rows[0]["match_type"] == "keyword"
    assert rows[0]["confidence"] == "low"
    assert repository.search_calls == 1


async def test_lookup_cpe_parses_nvd_and_caches(httpx_mock: Any, app_paths: AppPaths, settings: AppSettings) -> None:
    repository = FakeRepository()
    service = IntelService(repository, settings, app_paths)  # type: ignore[arg-type]
    cpe = "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
    httpx_mock.add_response(
        json={
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1234",
                        "descriptions": [{"lang": "en", "value": "nginx issue"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 9.8,
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                        "baseSeverity": "CRITICAL",
                                    }
                                }
                            ]
                        },
                        "references": [{"url": "https://example.com/advisory"}],
                        "weaknesses": [{"description": [{"value": "CWE-787"}]}],
                    }
                }
            ]
        }
    )
    rows = await service.lookup_cpe(cpe)
    assert rows is not None
    assert rows[0]["cve_id"] == "CVE-2024-1234"
    assert rows[0]["cvss_score"] == 9.8
    assert repository.cves[0]["cve_id"] == "CVE-2024-1234"
    request = httpx_mock.get_request()
    assert request.url.params["virtualMatchString"] == cpe
    assert request.url.params["resultsPerPage"] == "100"

    rows_again = await service.lookup_cpe(cpe)
    assert rows_again == rows
    assert len(httpx_mock.get_requests()) == 1


async def test_summary_marks_stale_feeds(app_paths: AppPaths, settings: AppSettings) -> None:
    feed = SimpleNamespace(
        name="cisa-kev",
        source="https://example.com/kev.json",
        status="ok",
        count=10,
        error="",
        last_sync=datetime.now(UTC) - timedelta(days=2),
        metadata_={"etag": '"v1"'},
    )
    service = IntelService(FakeRepository(feed), settings, app_paths)  # type: ignore[arg-type]
    summary = await service.summary()
    assert summary["feeds"][0]["stale"] is True
    assert summary["feeds"][0]["next_sync"] is not None
    assert summary["feeds"][0]["metadata"]["etag"] == '"v1"'


async def test_sync_kev_uses_conditional_headers(httpx_mock: Any, app_paths: AppPaths, settings: AppSettings) -> None:
    feed = SimpleNamespace(
        name="cisa-kev",
        count=7,
        last_sync=datetime.now(UTC),
        metadata_={"etag": '"v1"', "last_modified": "Wed, 01 Jan 2025 00:00:00 GMT"},
    )
    repository = FakeRepository(feed)
    service = IntelService(repository, settings, app_paths)  # type: ignore[arg-type]
    httpx_mock.add_response(url=settings.intel.kev_url, status_code=304)
    result = await service.sync_kev()
    assert result == {"status": "not_modified", "count": 7}
    request = httpx_mock.get_request()
    assert request.headers["if-none-match"] == '"v1"'
    assert request.headers["if-modified-since"] == "Wed, 01 Jan 2025 00:00:00 GMT"
    assert repository.feed_calls[-1][0][0] == "cisa-kev"
    assert repository.feed_calls[-1][1]["metadata"] == feed.metadata_


def test_signing_roundtrip_and_tamper(tmp_path: Path) -> None:
    private_key = tmp_path / "signing.pem"
    public_key = tmp_path / "signing.pub"
    generate_keypair(private_key, public_key)
    assert private_key.stat().st_mode & 0o777 == 0o600
    assert len(public_key_fingerprint(public_key)) == 64

    bundle = tmp_path / "intel.json"
    bundle.write_text('{"cves": []}', encoding="utf-8")
    signature = sign_bundle(bundle, private_key)
    assert signature.name == "intel.json.sig"
    verify_bundle(bundle, signature, public_key)

    bundle.write_text('{"cves": [{"cve_id": "CVE-2024-0001"}]}', encoding="utf-8")
    with pytest.raises(SigningError):
        verify_bundle(bundle, signature, public_key)

    with pytest.raises(SigningError):
        generate_keypair(private_key, public_key)


def test_cli_keygen_sign_and_verify(tmp_path: Path) -> None:
    private_key = tmp_path / "key.pem"
    public_key = tmp_path / "key.pub"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["intel", "keygen", "--private", str(private_key), "--public", str(public_key)],
    )
    assert result.exit_code == 0, result.output
    assert private_key.exists() and public_key.exists()

    bundle = tmp_path / "bundle.json"
    bundle.write_text('{"cves": []}', encoding="utf-8")
    signature = sign_bundle(bundle, private_key)
    verify = runner.invoke(
        cli,
        ["intel", "verify", str(bundle), "--public-key", str(public_key), "--signature", str(signature)],
    )
    assert verify.exit_code == 0, verify.output

    bundle.write_text('{"cves": [{"cve_id": "CVE-2024-0002"}]}', encoding="utf-8")
    invalid = runner.invoke(
        cli,
        ["intel", "verify", str(bundle), "--public-key", str(public_key), "--signature", str(signature)],
    )
    assert invalid.exit_code == 1


def test_signing_key_is_used_from_environment(
    app_paths: AppPaths, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    public_key = tmp_path / "key.pub"
    monkeypatch.setenv("MTB_BUNDLE_PUBLIC_KEY", str(public_key))
    monkeypatch.setenv("MTB_REQUIRE_BUNDLE_SIGNATURE", "1")
    loaded = load_settings(app_paths)
    assert loaded.intel.signing_public_key == str(public_key)
    assert loaded.intel.require_bundle_signature is True
