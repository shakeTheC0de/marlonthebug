"""Scan orchestration with live progress, shared HTTP context and persistence."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

from marlonthebug.core.context import ScanContext, reset_scan_context, set_scan_context
from marlonthebug.core.scope import scope_from_workspace
from marlonthebug.crawler.spider import Crawler
from marlonthebug.db.repository import Repository
from marlonthebug.http.baseline import BaselineProbe, build_baseline
from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Confidence, Finding, Severity
from marlonthebug.plugins.registry import PluginRegistry
from marlonthebug.services.workspaces import target_info, workspace_from_model
from marlonthebug.settings import AppSettings

logger = logging.getLogger("marlonthebug.scanner")

PROFILES: dict[str, dict[str, Any]] = {
    "safe": {"max_pages": 40, "requests_per_second": 2.0, "max_requests": 600, "max_depth": 2},
    "standard": {"max_pages": 200, "requests_per_second": 8.0, "max_requests": 2500, "max_depth": 3},
    "deep": {"max_pages": 800, "requests_per_second": 12.0, "max_requests": 10000, "max_depth": 5},
}


class ScanManager:
    def __init__(self, repository: Repository, settings: AppSettings, intel: Any = None) -> None:
        self.repository = repository
        self.settings = settings
        self.intel = intel
        self.tasks: dict[str, asyncio.Task] = {}
        self.contexts: dict[str, ScanContext] = {}
        self.logs: dict[str, list[dict[str, Any]]] = {}
        self.subscribers: dict[str, set[asyncio.Queue]] = {}

    def is_running(self, scan_id: str) -> bool:
        task = self.tasks.get(scan_id)
        return bool(task and not task.done())

    async def start(self, scan_id: str) -> None:
        if self.is_running(scan_id):
            return
        task = asyncio.create_task(self._run(scan_id), name=f"scan-{scan_id}")
        self.tasks[scan_id] = task

    async def cancel(self, scan_id: str) -> bool:
        context = self.contexts.get(scan_id)
        if context:
            context.cancel()
        task = self.tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
            return True
        return False

    async def shutdown(self) -> None:
        for task in list(self.tasks.values()):
            if not task.done():
                task.cancel()
        for task in list(self.tasks.values()):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        self.subscribers.setdefault(scan_id, set()).add(queue)
        return queue

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        subscribers = self.subscribers.get(scan_id)
        if subscribers:
            subscribers.discard(queue)
            if not subscribers:
                self.subscribers.pop(scan_id, None)

    def get_logs(self, scan_id: str) -> list[dict[str, Any]]:
        return list(self.logs.get(scan_id, []))

    def _publish(self, scan_id: str, event: dict[str, Any]) -> None:
        for queue in list(self.subscribers.get(scan_id, set())):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                with contextlib.suppress(asyncio.QueueEmpty):
                    queue.get_nowait()
                with contextlib.suppress(asyncio.QueueFull):
                    queue.put_nowait(event)

    async def _log(self, scan_id: str, level: str, message: str) -> None:
        entry = {
            "time": datetime.now(UTC).strftime("%H:%M:%S"),
            "level": level.upper(),
            "message": message,
        }
        self.logs.setdefault(scan_id, []).append(entry)
        if len(self.logs[scan_id]) > 1000:
            self.logs[scan_id] = self.logs[scan_id][-1000:]
        self._publish(scan_id, {"type": "log", **entry})
        logger.info("[scan %s] %s: %s", scan_id[:8], level.upper(), message)

    async def _run(self, scan_id: str) -> None:
        scan = await self.repository.get_scan(scan_id, with_workspace=True)
        if not scan or not scan.workspace:
            logger.error("Scan %s not found", scan_id)
            return
        workspace = scan.workspace

        profile = PROFILES.get(scan.profile, PROFILES["standard"])
        options = {**profile, **(scan.options or {})}
        scope = scope_from_workspace(
            workspace.scope or {},
            allow_exploitation=workspace.allow_exploitation,
            require_confirmation=workspace.require_confirmation,
        )
        headers = dict(options.get("headers") or {})
        cookies = dict(options.get("cookies") or {})
        proxy = options.get("proxy") or None
        user_agent = options.get("user_agent") or self.settings.general.user_agent

        context = await ScanContext.create(
            scan_id=scan_id,
            workspace_id=workspace.id,
            workspace_name=workspace.name,
            scope=scope,
            timeout=float(options.get("timeout", self.settings.general.timeout)),
            verify_ssl=bool(options.get("verify_ssl", self.settings.general.verify_ssl)),
            follow_redirects=bool(options.get("follow_redirects", self.settings.general.follow_redirects)),
            max_redirects=int(options.get("max_redirects", self.settings.general.max_redirects)),
            user_agent=user_agent,
            headers=headers,
            cookies=cookies,
            proxy=proxy,
            requests_per_second=float(options.get("requests_per_second", self.settings.scan.requests_per_second)),
            max_requests=int(options.get("max_requests", self.settings.scan.max_requests)),
            options=options,
            log_callback=lambda level, message: self._log(scan_id, level, message),
        )
        self.contexts[scan_id] = context
        token = set_scan_context(context)

        await self.repository.update_scan(
            scan_id,
            status="running",
            started_at=datetime.now(UTC),
            logs=[],
        )
        self.logs.setdefault(scan_id, [])
        await self._log(scan_id, "info", f"Análisis iniciado en {workspace.name}")
        await self._log(
            scan_id,
            "info",
            f"Perfil {scan.profile} · {len(scan.targets)} objetivo(s) · {', '.join(scan.categories) or 'todos'}",
        )

        try:
            workspace_model = workspace_from_model(workspace)
            target_map = {target.host: target for target in workspace.targets}
            targets = [target_map[host] for host in scan.targets if host in target_map]
            if not targets:
                targets = list(workspace.targets)
            if not targets:
                raise RuntimeError("El workspace no tiene objetivos para analizar")

            plugins = self._select_plugins(scan.categories, scan.modules)
            if not plugins:
                raise RuntimeError("No hay módulos disponibles para las categorías seleccionadas")
            await self._log(scan_id, "info", f"Módulos cargados: {len(plugins)}")

            total_steps = max(1, len(targets) * 2 + len(targets) * len(plugins))
            done_steps = 0

            for host in [item.host for item in targets]:
                if context.should_stop.is_set():
                    break
                target = target_map.get(host)
                if not target:
                    continue
                target_id = target.id
                info = target_info(target)
                base_url, _ = await self._resolve_base_url(context, host)
                await self._log(scan_id, "info", f"[{host}] objetivo accesible en {base_url}")
                done_steps += 1
                self._publish(
                    scan_id,
                    {
                        "type": "progress",
                        "done": done_steps,
                        "total": total_steps,
                        "message": f"Analizando {host}",
                    },
                )

                baseline = await self._baseline(context, base_url)
                context.baseline = baseline
                await self._log(
                    scan_id,
                    "info",
                    f"[{host}] baseline: {'catch-all detectado' if baseline.catch_all else 'sin catch-all'}",
                )

                endpoints = await self._crawl(context, base_url)
                done_steps += 1
                await self._log(
                    scan_id,
                    "info",
                    f"[{host}] {len(endpoints)} endpoints descubiertos",
                )

                plugin_options = {
                    **options,
                    "base_url": base_url,
                    "endpoints": endpoints,
                    "baseline": baseline,
                    "headers": headers,
                    "cookies": cookies,
                    "target_id": target_id,
                    "intel": self.intel,
                }

                semaphore = asyncio.Semaphore(max(1, min(self.settings.general.threads, 10)))

                async def run_plugin(
                    plugin_class: type[BasePlugin],
                    _semaphore: asyncio.Semaphore = semaphore,
                    _info: Any = info,
                    _options: dict = plugin_options,
                    _target_id: str = target_id,
                    _host: str = host,
                    _workspace_id: str = workspace.id,
                ) -> None:
                    nonlocal done_steps
                    async with _semaphore:
                        if context.should_stop.is_set():
                            return
                        instance = plugin_class()
                        instance._context = context
                        try:
                            await instance.setup(workspace_model)
                            async for finding in instance.run(_info, _options):
                                await self._persist_finding(scan_id, _workspace_id, _target_id, _host, finding)
                                context.finding_count += 1
                                self._publish(
                                    scan_id,
                                    {
                                        "type": "finding",
                                        "finding": serialize_finding(finding),
                                    },
                                )
                            await instance.teardown()
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            context.error_count += 1
                            await self._log(
                                scan_id,
                                "error",
                                f"[{_host}] {instance.category}/{instance.name}: {exc}",
                            )
                        finally:
                            done_steps += 1
                            self._publish(
                                scan_id,
                                {
                                    "type": "progress",
                                    "done": done_steps,
                                    "total": total_steps,
                                    "message": f"{instance.category}/{instance.name} · {_host}",
                                },
                            )

                await asyncio.gather(*(run_plugin(cls) for cls in plugins))
                await self.repository.add_target(
                    workspace.id,
                    host,
                    technologies=info.technologies,
                    metadata=info.metadata,
                )
                for discovered in sorted(context.discovered_hosts):
                    if discovered != host:
                        await self.repository.add_target(workspace.id, discovered)

            if context.should_stop.is_set():
                status = "cancelled"
                await self._log(scan_id, "warning", "Análisis cancelado por el usuario")
            else:
                status = "completed"
                await self._log(scan_id, "success", "Análisis completado")

            stats = context.stats()
            stats.update(
                {
                    "plugins": len(plugins),
                    "targets": len(targets),
                    "created_findings": context.finding_count,
                }
            )
            await self.repository.update_scan(
                scan_id,
                status=status,
                finished_at=datetime.now(UTC),
                stats=stats,
                logs=self.logs.get(scan_id, [])[-500:],
            )
            await self.repository.log_action(
                "scan.complete",
                target=workspace.name,
                detail={"scan_id": scan_id, "status": status, **stats},
            )
            self._publish(scan_id, {"type": "done", "status": status, "stats": stats})

        except asyncio.CancelledError:
            await self.repository.update_scan(
                scan_id,
                status="cancelled",
                finished_at=datetime.now(UTC),
                stats=context.stats(),
                logs=self.logs.get(scan_id, [])[-500:],
            )
            await self._log(scan_id, "warning", "Análisis cancelado")
            self._publish(scan_id, {"type": "done", "status": "cancelled", "stats": context.stats()})
            raise
        except Exception as exc:
            logger.exception("Scan %s failed", scan_id)
            await self.repository.update_scan(
                scan_id,
                status="failed",
                error=str(exc),
                finished_at=datetime.now(UTC),
                stats=context.stats(),
                logs=self.logs.get(scan_id, [])[-500:],
            )
            await self._log(scan_id, "error", f"Error fatal: {exc}")
            self._publish(scan_id, {"type": "done", "status": "failed", "error": str(exc)})
        finally:
            reset_scan_context(token)
            await context.close()
            self.contexts.pop(scan_id, None)

    def _select_plugins(self, categories: list[str], modules: list[str]) -> list[type[BasePlugin]]:
        registry = PluginRegistry()
        registry.discover()
        selected: list[type[BasePlugin]] = []
        wanted_modules = set(modules or [])
        wanted_categories = set(categories or [])
        for key, plugin in registry._instances.items():
            if wanted_modules and key not in wanted_modules:
                continue
            if not wanted_modules and wanted_categories and plugin.category not in wanted_categories:
                continue
            selected.append(plugin.__class__)
        selected.sort(key=lambda item: (item.category != "recon", item.category, item.name))
        return selected

    async def _resolve_base_url(self, context: ScanContext, host: str) -> tuple[str, Any]:
        http = AsyncHTTPClient(timeout=min(8.0, self.settings.general.timeout))
        for scheme in ("https", "http"):
            try:
                response = await http.get(f"{scheme}://{host}")
                if response.status_code < 500:
                    return f"{scheme}://{host}", response
            except Exception:
                continue
        return f"https://{host}", None

    async def _baseline(self, context: ScanContext, base_url: str) -> BaselineProbe:
        http = AsyncHTTPClient()
        try:
            return await build_baseline(http, base_url)
        except Exception as exc:
            await context.log("warning", f"No se pudo construir el baseline: {exc}")
            return BaselineProbe(base_url=base_url)

    async def _crawl(self, context: ScanContext, base_url: str) -> list[str]:
        profile = context.options
        http = AsyncHTTPClient()
        crawler = Crawler(
            http,
            max_depth=int(profile.get("max_depth", 3)),
            max_pages=int(profile.get("max_pages", 200)),
            respect_robots=bool(profile.get("respect_robots_txt", True)),
            follow_subdomains=False,
            extract_js=True,
            extract_api=True,
            concurrency=10,
        )
        endpoints: set[str] = {base_url}
        try:
            pages = await crawler.crawl(base_url)
            for page in pages:
                endpoints.add(page.url)
                endpoints.update(page.js_endpoints)
                for link in page.links[:100]:
                    endpoints.add(link)
            context.endpoints = sorted(endpoints)
        except Exception as exc:
            await context.log("warning", f"Error en crawler: {exc}")
        return context.endpoints

    async def _persist_finding(
        self,
        scan_id: str,
        workspace_id: str,
        target_id: str,
        host: str,
        finding: Finding,
    ) -> None:
        kev = finding.kev
        epss = finding.epss
        payload_text = json.dumps(finding.to_dict(), ensure_ascii=False, default=str)
        for cve_id in set(re.findall(r"CVE-\d{4}-\d{4,7}", payload_text, re.IGNORECASE)):
            cached = await self.repository.get_cve(cve_id.upper())
            if cached:
                kev = kev or cached.kev
                epss = max(epss, cached.epss)
        data = {
            "workspace_id": workspace_id,
            "scan_run_id": scan_id,
            "target_id": target_id,
            "plugin_name": finding.plugin_name,
            "category": finding.category,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "status": finding.status,
            "cvss_score": finding.cvss_score,
            "cvss_vector": finding.cvss_vector,
            "cwe": finding.cwe,
            "owasp": finding.owasp,
            "endpoint": finding.endpoint,
            "target_host": finding.target_host or host,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "references": finding.references,
            "waf_rules": finding.waf_rules,
            "intel": finding.intel,
            "notes": finding.notes,
            "verified": finding.verified,
            "kev": kev,
            "epss": epss,
            "fingerprint": finding.fingerprint,
        }
        await self.repository.upsert_finding(data)


def serialize_finding(finding: Finding) -> dict[str, Any]:
    return {
        "title": finding.title,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "endpoint": finding.endpoint,
        "target": finding.target_host,
        "plugin": finding.plugin_name,
        "cvss": finding.cvss_score,
    }


__all__ = ["PROFILES", "Confidence", "ScanManager", "Severity", "serialize_finding"]
