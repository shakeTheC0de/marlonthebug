"""Vulnerability intelligence: CISA KEV, EPSS, OSV and NVD with offline cache."""

from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from marlonthebug import __version__
from marlonthebug.db.models import CveModel, TargetModel
from marlonthebug.db.repository import Repository
from marlonthebug.paths import AppPaths
from marlonthebug.services.cpe import from_tech_details, from_technologies
from marlonthebug.settings import AppSettings

logger = logging.getLogger("marlonthebug.intel")

OSV_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "go": "Go",
    "crates.io": "crates.io",
    "nuget": "NuGet",
    "rubygems": "RubyGems",
    "packagist": "Packagist",
}


class IntelService:
    def __init__(self, repository: Repository, settings: AppSettings, paths: AppPaths) -> None:
        self.repository = repository
        self.settings = settings
        self.paths = paths
        self.headers = {"User-Agent": "MarlonTheBug/2.0 vulnerability-intel"}
        self._cpe_cache: dict[str, list[dict[str, Any]] | None] = {}

    async def sync_all(self, force: bool = False) -> dict[str, Any]:
        if self.settings.intel.offline and not force:
            return {"status": "offline", "message": "Modo offline activo; no se descargan feeds."}
        results: dict[str, Any] = {}
        results["kev"] = await self.sync_kev()
        results["epss"] = await self.sync_epss()
        results["enriched_findings"] = await self.enrich_findings()
        return results

    async def enrich_findings(self, limit: int = 5000) -> int:
        """Re-evaluate KEV/EPSS for findings that reference a CVE."""
        from sqlalchemy import select

        from marlonthebug.db.models import FindingModel

        updated = 0
        async with self.repository.db.session() as session:
            result = await session.execute(select(FindingModel).limit(limit))
            findings = list(result.scalars().all())
        for finding in findings:
            text = " ".join(
                [
                    finding.title or "",
                    finding.description or "",
                    json.dumps(finding.evidence or {}, ensure_ascii=False, default=str),
                    json.dumps(finding.references or [], ensure_ascii=False, default=str),
                ]
            )
            cve_ids = {match.upper() for match in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)}
            if not cve_ids:
                continue
            kev = finding.kev
            epss = finding.epss
            for cve_id in cve_ids:
                cached = await self.repository.get_cve(cve_id)
                if cached:
                    kev = kev or cached.kev
                    epss = max(epss, cached.epss)
            if kev != finding.kev or epss > finding.epss:
                await self.repository.update_finding(finding.id, kev=kev, epss=epss)
                updated += 1
        return updated

    async def sync_kev(self) -> dict[str, Any]:
        url = self.settings.intel.kev_url
        feed = await self.repository.get_feed("cisa-kev")
        cached = feed.metadata_ if feed and isinstance(feed.metadata_, dict) else {}
        headers = {**self.headers, **self._conditional_headers(cached)}
        try:
            async with httpx.AsyncClient(
                timeout=self.settings.intel.request_timeout,
                headers=headers,
                follow_redirects=True,
            ) as client:
                response = await client.get(url)
            if response.status_code == 304:
                await self.repository.upsert_feed(
                    "cisa-kev",
                    url,
                    "not_modified",
                    feed.count if feed else 0,
                    metadata=cached,
                )
                return {"status": "not_modified", "count": feed.count if feed else 0}
            response.raise_for_status()
            payload = response.json()
            rows = []
            for item in payload.get("vulnerabilities", []):
                cve_id = item.get("cveID", "").strip()
                if not cve_id:
                    continue
                rows.append(
                    {
                        "cve_id": cve_id,
                        "title": item.get("vulnerabilityName", ""),
                        "description": item.get("shortDescription", ""),
                        "kev": True,
                        "kev_due_date": item.get("dueDate", ""),
                        "published": item.get("dateAdded", ""),
                        "references": [
                            {
                                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                            }
                        ],
                        "affected": [
                            {
                                "vendor": item.get("vendorProject", ""),
                                "product": item.get("product", ""),
                                "ransomware": item.get("knownRansomwareCampaignUse", "Unknown"),
                                "required_action": item.get("requiredAction", ""),
                                "notes": item.get("notes", ""),
                            }
                        ],
                        "source": "cisa-kev",
                        "severity": "high",
                    }
                )
            await self.repository.bulk_upsert_cves(rows)
            metadata = {
                "catalog_version": payload.get("catalogVersion", ""),
                **self._response_validators(response),
            }
            await self.repository.upsert_feed("cisa-kev", url, "ok", len(rows), metadata=metadata)
            logger.info("KEV synced: %d entries", len(rows))
            return {"status": "ok", "count": len(rows)}
        except Exception as exc:
            logger.warning("KEV sync failed: %s", exc)
            await self.repository.upsert_feed("cisa-kev", url, "error", 0, error=str(exc), metadata=cached)
            return {"status": "error", "error": str(exc)}

    async def sync_epss(self) -> dict[str, Any]:
        """Download the daily EPSS CSV and update the CVEs we already track."""
        url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
        feed = await self.repository.get_feed("epss")
        cached = feed.metadata_ if feed and isinstance(feed.metadata_, dict) else {}
        headers = {**self.headers, **self._conditional_headers(cached)}
        try:
            known = await self._known_cve_ids()
            if not known:
                await self.repository.upsert_feed("epss", url, "skipped", 0, metadata={"reason": "no CVEs cached"})
                return {"status": "skipped", "reason": "No hay CVEs en caché; sincroniza KEV primero."}
            rows: list[dict[str, Any]] = []
            async with httpx.AsyncClient(
                timeout=max(60.0, self.settings.intel.request_timeout),
                headers=headers,
                follow_redirects=True,
            ) as client:
                response = await client.get(url)
            if response.status_code == 304:
                await self.repository.upsert_feed(
                    "epss",
                    url,
                    "not_modified",
                    feed.count if feed else 0,
                    metadata=cached,
                )
                return {"status": "not_modified", "count": feed.count if feed else 0}
            response.raise_for_status()
            raw = gzip.decompress(response.content)
            for line in io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8", errors="ignore"):
                if line.startswith("#") or line.startswith("cve,"):
                    continue
                parts = next(csv.reader([line.strip()]))
                if len(parts) < 3:
                    continue
                cve_id, epss, percentile = parts[0], parts[1], parts[2]
                if cve_id in known:
                    try:
                        rows.append(
                            {
                                "cve_id": cve_id,
                                "epss": float(epss),
                                "epss_percentile": float(percentile),
                            }
                        )
                    except ValueError:
                        continue
            await self.repository.bulk_upsert_cves(rows)
            await self.repository.upsert_feed(
                "epss",
                url,
                "ok",
                len(rows),
                metadata=self._response_validators(response),
            )
            logger.info("EPSS synced: %d scores", len(rows))
            return {"status": "ok", "count": len(rows)}
        except Exception as exc:
            logger.warning("EPSS sync failed: %s", exc)
            await self.repository.upsert_feed("epss", url, "error", 0, error=str(exc), metadata=cached)
            return {"status": "error", "error": str(exc)}

    @staticmethod
    def _conditional_headers(metadata: dict[str, Any]) -> dict[str, str]:
        headers: dict[str, str] = {}
        if etag := metadata.get("etag"):
            headers["If-None-Match"] = str(etag)
        if modified := metadata.get("last_modified"):
            headers["If-Modified-Since"] = str(modified)
        return headers

    @staticmethod
    def _response_validators(response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        if etag := response.headers.get("etag"):
            metadata["etag"] = etag
        if modified := response.headers.get("last-modified"):
            metadata["last_modified"] = modified
        return metadata

    async def _known_cve_ids(self) -> set[str]:
        async with self.repository.db.session() as session:
            from sqlalchemy import select

            result = await session.execute(select(CveModel.cve_id))
            return {str(row[0]) for row in result.all()}

    async def sync_nvd_cve(self, cve_id: str, force: bool = False) -> CveModel | None:
        if not force:
            cached = await self.repository.get_cve(cve_id)
            if cached and cached.source == "nvd":
                return cached
        url = self.settings.intel.nvd_url
        headers = dict(self.headers)
        if self.settings.intel.nvd_api_key:
            headers["apiKey"] = self.settings.intel.nvd_api_key
        try:
            async with httpx.AsyncClient(
                timeout=self.settings.intel.request_timeout,
                headers=headers,
                follow_redirects=True,
            ) as client:
                response = await client.get(url, params={"cveId": cve_id})
                response.raise_for_status()
                payload = response.json()
            vulnerabilities = payload.get("vulnerabilities", [])
            if not vulnerabilities:
                return None
            cve = vulnerabilities[0]["cve"]
            data = self._parse_nvd(cve)
            await self.repository.bulk_upsert_cves([data])
            await self.repository.upsert_feed("nvd", url, "ok", 1)
            return await self.repository.get_cve(cve_id)
        except Exception as exc:
            logger.warning("NVD lookup failed for %s: %s", cve_id, exc)
            await self.repository.upsert_feed("nvd", url, "error", 0, error=str(exc))
            return None

    def _parse_nvd(self, cve: dict[str, Any]) -> dict[str, Any]:
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        description = next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        score = 0.0
        vector = ""
        severity = "unknown"
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                primary = entries[0]
                data = primary.get("cvssData", {})
                score = float(data.get("baseScore", 0.0))
                vector = data.get("vectorString", "")
                severity = str(data.get("baseSeverity", primary.get("baseSeverity", "unknown"))).lower()
                break
        weaknesses = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                value = desc.get("value", "")
                if value.startswith("CWE-"):
                    weaknesses.append(value)
        references = [ref.get("url", "") for ref in cve.get("references", []) if ref.get("url")]
        return {
            "cve_id": cve_id,
            "title": description[:200],
            "description": description,
            "cvss_score": score,
            "cvss_vector": vector,
            "severity": severity,
            "published": cve.get("published", ""),
            "modified": cve.get("lastModified", ""),
            "cwe": sorted(set(weaknesses)),
            "references": [{"url": url} for url in references[:30]],
            "source": "nvd",
        }

    async def lookup_osv(self, ecosystem: str, package: str, version: str) -> list[dict[str, Any]]:
        url = f"{self.settings.intel.osv_url.rstrip('/')}/query"
        payload = {
            "package": {"ecosystem": OSV_ECOSYSTEMS.get(ecosystem.lower(), ecosystem), "name": package},
            "version": version,
        }
        try:
            async with httpx.AsyncClient(
                timeout=self.settings.intel.request_timeout,
                headers=self.headers,
                follow_redirects=True,
            ) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
            results = []
            for vuln in data.get("vulns", []):
                severity = "medium"
                score = 0.0
                for item in vuln.get("severity", []):
                    if item.get("type") == "CVSS_V3":
                        vector = item.get("score", "")
                        try:
                            from cvss import CVSS3

                            parsed = CVSS3(vector)
                            score = parsed.scores()[0]
                            severity = parsed.severities()[0].lower()
                        except Exception:
                            pass
                results.append(
                    {
                        "id": vuln.get("id", ""),
                        "aliases": vuln.get("aliases", []),
                        "summary": vuln.get("summary", ""),
                        "details": vuln.get("details", ""),
                        "severity": severity,
                        "score": score,
                        "references": [ref.get("url", "") for ref in vuln.get("references", [])],
                    }
                )
            await self.repository.upsert_feed("osv", url, "ok", len(results))
            return results
        except Exception as exc:
            logger.warning("OSV lookup failed for %s/%s: %s", package, version, exc)
            await self.repository.upsert_feed("osv", url, "error", 0, error=str(exc))
            return []

    async def match_target(self, target: TargetModel) -> list[dict[str, Any]]:
        """Correlate detected technologies with CVEs through CPE and NVD.

        Exact product/version matches are high confidence. If no version can be
        mapped to a CPE, the previous keyword search is kept as a low-confidence
        fallback. A version with no matching CVE produces no noise.
        """
        details = target.metadata_.get("tech_details") if isinstance(target.metadata_, dict) else None
        candidates = from_tech_details(details if isinstance(details, list) else None)
        if not candidates:
            candidates = from_technologies(list(target.technologies or []))

        rows: dict[tuple[str, str, str], dict[str, Any]] = {}
        cpe_ok = not self.settings.intel.offline
        if not self.settings.intel.offline:
            for candidate in candidates[: max(1, self.settings.intel.max_cpe_lookups)]:
                cves = await self.lookup_cpe(candidate.cpe)
                if cves is None:
                    # A timeout or rate limit means the remaining lookups would
                    # only add latency. Fall back to the local keyword index.
                    cpe_ok = False
                    break
                for cve in cves:
                    cve_id = str(cve.get("cve_id", ""))
                    if not cve_id:
                        continue
                    key = (candidate.name.lower(), candidate.version, cve_id)
                    rows[key] = {
                        "product": candidate.name,
                        "version": candidate.version,
                        "cve_id": cve_id,
                        "match_type": candidate.match_type,
                        "confidence": "high",
                        "source": "nvd",
                    }

        if not candidates or not cpe_ok:
            for technology in target.technologies or []:
                product, version = _split_technology(str(technology))
                if not product:
                    continue
                matches = await self.repository.search_cves(product, limit=10)
                for match in matches:
                    if not match.cve_id:
                        continue
                    key = (product, version, match.cve_id)
                    rows.setdefault(
                        key,
                        {
                            "product": product,
                            "version": version,
                            "cve_id": match.cve_id,
                            "match_type": "keyword",
                            "confidence": "low",
                            "source": match.source or "nvd",
                        },
                    )

        await self.repository.replace_asset_intel(target.id, list(rows.values()))
        return list(rows.values())

    async def lookup_cpe(self, cpe: str, limit: int = 100) -> list[dict[str, Any]] | None:
        """Query NVD by CPE 2.3 and cache the resulting CVEs.

        Returns ``None`` when the lookup could not be performed (network, rate
        limit, invalid response), which lets the caller fall back to the local
        keyword index. An empty list means NVD answered but found no CVEs.
        """
        if cpe in self._cpe_cache:
            return self._cpe_cache[cpe]
        url = self.settings.intel.nvd_url
        headers = dict(self.headers)
        if self.settings.intel.nvd_api_key:
            headers["apiKey"] = self.settings.intel.nvd_api_key
        params: dict[str, str | int] = {
            "virtualMatchString": cpe,
            "resultsPerPage": max(1, min(limit, 2000)),
        }
        try:
            async with httpx.AsyncClient(
                timeout=min(self.settings.intel.request_timeout, self.settings.intel.cpe_timeout),
                headers=headers,
                follow_redirects=True,
            ) as client:
                response = await client.get(url, params=params)
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:
            logger.warning("NVD CPE lookup failed for %s: %s", cpe, exc)
            await self.repository.upsert_feed(
                "nvd-cpe",
                url,
                "error",
                0,
                error=str(exc),
                metadata={"cpe": cpe},
            )
            self._remember_cpe(cpe, None)
            return None

        rows: list[dict[str, Any]] = []
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {})
            if not cve.get("id"):
                continue
            rows.append(self._parse_nvd(cve))
        if rows:
            await self.repository.bulk_upsert_cves(rows)
        await self.repository.upsert_feed(
            "nvd-cpe",
            url,
            "ok",
            len(rows),
            metadata={"cpe": cpe},
        )
        self._remember_cpe(cpe, rows)
        return rows

    def _remember_cpe(self, cpe: str, rows: list[dict[str, Any]] | None) -> None:
        if len(self._cpe_cache) > 256:
            self._cpe_cache.clear()
        self._cpe_cache[cpe] = rows

    async def summary(self) -> dict[str, Any]:
        feeds = await self.repository.list_feeds()
        stats = await self.repository.intel_stats()
        now = datetime.now(UTC)
        interval = max(1, self.settings.intel.sync_interval_hours)
        feed_rows = []
        for feed in feeds:
            last_sync = feed.last_sync
            if last_sync is not None and last_sync.tzinfo is None:
                last_sync = last_sync.replace(tzinfo=UTC)
            next_sync = last_sync + timedelta(hours=interval) if last_sync else None
            feed_rows.append(
                {
                    "name": feed.name,
                    "source": feed.source,
                    "status": feed.status,
                    "count": feed.count,
                    "error": feed.error,
                    "last_sync": last_sync,
                    "next_sync": next_sync,
                    "stale": bool(next_sync and now > next_sync),
                    "metadata": feed.metadata_ or {},
                }
            )
        return {
            "feeds": feed_rows,
            "stats": stats,
            "offline": self.settings.intel.offline,
            "sync_interval_hours": interval,
        }

    async def auto_sync_if_needed(self) -> None:
        if self.settings.intel.offline:
            return
        feed = await self.repository.get_feed("cisa-kev")
        if feed and feed.last_sync:
            last_sync = feed.last_sync
            if last_sync.tzinfo is None:
                last_sync = last_sync.replace(tzinfo=UTC)
            age = datetime.now(UTC) - last_sync
            if age < timedelta(hours=self.settings.intel.sync_interval_hours):
                return
        await self.sync_all()

    async def export_bundle(self, path: Path | None = None) -> Path:
        path = path or (self.paths.feeds_dir / "intel-bundle.json")
        async with self.repository.db.session() as session:
            from sqlalchemy import select

            result = await session.execute(select(CveModel))
            cves = list(result.scalars().all())
        payload = {
            "schema": "marlonthebug-intel-bundle/1",
            "app_version": __version__,
            "generated_at": datetime.now(UTC).isoformat(),
            "count": len(cves),
            "cves": [
                {
                    "cve_id": cve.cve_id,
                    "title": cve.title,
                    "description": cve.description,
                    "cvss_score": cve.cvss_score,
                    "cvss_vector": cve.cvss_vector,
                    "severity": cve.severity,
                    "published": cve.published,
                    "modified": cve.modified,
                    "kev": cve.kev,
                    "kev_due_date": cve.kev_due_date,
                    "epss": cve.epss,
                    "epss_percentile": cve.epss_percentile,
                    "cwe": cve.cwe,
                    "references": cve.references,
                    "affected": cve.affected,
                    "source": cve.source,
                }
                for cve in cves
            ],
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    async def import_bundle(self, path: Path) -> int:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("El bundle debe ser un objeto JSON")
        rows = payload.get("cves", [])
        if not isinstance(rows, list):
            raise ValueError("El campo cves debe ser una lista")
        if len(rows) > 200_000:
            raise ValueError("El bundle contiene demasiadas CVEs")
        if not all(isinstance(row, dict) and row.get("cve_id") for row in rows):
            raise ValueError("Cada CVE del bundle debe incluir cve_id")
        await self.repository.bulk_upsert_cves(rows)
        await self.repository.upsert_feed(
            "bundle",
            str(path),
            "ok",
            len(rows),
            metadata={"schema": payload.get("schema", ""), "generated_at": payload.get("generated_at", "")},
        )
        return len(rows)


def _split_technology(value: str) -> tuple[str, str]:
    cleaned = value.strip()
    if not cleaned:
        return "", ""
    parts = cleaned.replace("/", " ").split()
    if len(parts) >= 2 and any(char.isdigit() for char in parts[1]):
        return parts[0].lower(), parts[1]
    return cleaned.lower(), ""
