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

from marlonthebug.db.models import CveModel, TargetModel
from marlonthebug.db.repository import Repository
from marlonthebug.paths import AppPaths
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
        try:
            async with httpx.AsyncClient(
                timeout=self.settings.intel.request_timeout,
                headers=self.headers,
                follow_redirects=True,
            ) as client:
                response = await client.get(url)
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
                            }
                        ],
                        "source": "cisa-kev",
                        "severity": "high",
                    }
                )
            await self.repository.bulk_upsert_cves(rows)
            await self.repository.upsert_feed(
                "cisa-kev",
                url,
                "ok",
                len(rows),
                metadata={"catalog_version": payload.get("catalogVersion", "")},
            )
            logger.info("KEV synced: %d entries", len(rows))
            return {"status": "ok", "count": len(rows)}
        except Exception as exc:
            logger.warning("KEV sync failed: %s", exc)
            await self.repository.upsert_feed("cisa-kev", url, "error", 0, error=str(exc))
            return {"status": "error", "error": str(exc)}

    async def sync_epss(self) -> dict[str, Any]:
        """Download the daily EPSS CSV and update the CVEs we already track."""
        url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
        try:
            known = await self._known_cve_ids()
            if not known:
                await self.repository.upsert_feed("epss", url, "skipped", 0, metadata={"reason": "no CVEs cached"})
                return {"status": "skipped", "reason": "No hay CVEs en caché; sincroniza KEV primero."}
            rows: list[dict[str, Any]] = []
            async with httpx.AsyncClient(
                timeout=max(60.0, self.settings.intel.request_timeout),
                headers=self.headers,
                follow_redirects=True,
            ) as client:
                response = await client.get(url)
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
            await self.repository.upsert_feed("epss", url, "ok", len(rows))
            logger.info("EPSS synced: %d scores", len(rows))
            return {"status": "ok", "count": len(rows)}
        except Exception as exc:
            logger.warning("EPSS sync failed: %s", exc)
            await self.repository.upsert_feed("epss", url, "error", 0, error=str(exc))
            return {"status": "error", "error": str(exc)}

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
        rows: list[dict[str, Any]] = []
        for technology in target.technologies or []:
            product, version = _split_technology(str(technology))
            if not product:
                continue
            cves = await self.repository.search_cves(product, limit=10)
            for cve in cves:
                if cve.cve_id:
                    rows.append(
                        {
                            "product": product,
                            "version": version,
                            "cve_id": cve.cve_id,
                            "match_type": "keyword",
                            "confidence": "low",
                            "source": cve.source or "nvd",
                        }
                    )
        await self.repository.replace_asset_intel(target.id, rows)
        return rows

    async def summary(self) -> dict[str, Any]:
        feeds = await self.repository.list_feeds()
        stats = await self.repository.intel_stats()
        return {
            "feeds": feeds,
            "stats": stats,
            "offline": self.settings.intel.offline,
        }

    async def auto_sync_if_needed(self) -> None:
        if self.settings.intel.offline:
            return
        feed = await self.repository.get_feed("cisa-kev")
        if feed and feed.last_sync:
            age = datetime.now(UTC) - feed.last_sync.replace(tzinfo=UTC)
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
        rows = payload.get("cves", [])
        await self.repository.bulk_upsert_cves(rows)
        await self.repository.upsert_feed("bundle", str(path), "ok", len(rows))
        return len(rows)


def _split_technology(value: str) -> tuple[str, str]:
    cleaned = value.strip()
    if not cleaned:
        return "", ""
    parts = cleaned.replace("/", " ").split()
    if len(parts) >= 2 and any(char.isdigit() for char in parts[1]):
        return parts[0].lower(), parts[1]
    return cleaned.lower(), ""
