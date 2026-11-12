"""FastAPI application factory for the MarlonTheBug panel."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

from marlonthebug import __version__
from marlonthebug.db.database import Database, sqlite_url
from marlonthebug.db.repository import Repository
from marlonthebug.paths import AppPaths, resource_path
from marlonthebug.services.intel import IntelService
from marlonthebug.services.reports import ReportService
from marlonthebug.services.scanner import ScanManager
from marlonthebug.settings import AppSettings, load_settings, write_default_config
from marlonthebug.web import filters
from marlonthebug.web.routes import router
from marlonthebug.web.security import PanelAuth, safe_next

logger = logging.getLogger("marlonthebug.web")

PUBLIC_PATHS = {"/login", "/healthz", "/favicon.ico"}


def create_app(
    paths: AppPaths | None = None,
    settings: AppSettings | None = None,
    auth_enabled: bool | None = None,
) -> FastAPI:
    paths = paths or AppPaths.resolve()
    paths.ensure()
    settings = settings or load_settings(paths)
    write_default_config(paths)
    if auth_enabled is not None:
        settings.panel.auth = auth_enabled

    database = Database(sqlite_url(paths.db_path), portable=paths.portable)
    repository = Repository(database)
    intel = IntelService(repository, settings, paths)
    scan_manager = ScanManager(repository, settings, intel)
    report_service = ReportService(repository, settings, paths)
    auth = PanelAuth(paths, enabled=settings.panel.auth)

    templates = Jinja2Templates(directory=str(resource_path("web", "templates")))
    templates.env.filters.update(
        {
            "datetimefmt": filters.datetimefmt,
            "relative_time": filters.relative_time,
            "severity_label": filters.severity_label,
            "status_label": filters.status_label,
            "confidence_label": filters.confidence_label,
            "scan_status_label": filters.scan_status_label,
            "filesize": filters.filesize,
            "json_pretty": filters.json_pretty,
            "host_of": filters.host_of,
            "truncate": filters.truncate,
            "cvss_class": filters.cvss_class,
            "percent": filters.percent,
        }
    )
    templates.env.globals.update(
        {
            "app_name": "MarlonTheBug",
            "app_version": __version__,
            "severity_order": ["critical", "high", "medium", "low", "info"],
            "status_order": ["open", "confirmed", "false_positive", "accepted", "remediated"],
            "category_labels": {
                "recon": "Reconocimiento",
                "web": "Web",
                "api": "API",
                "auth": "Autenticación",
                "cloud": "Cloud",
                "llm": "IA / LLM",
                "general": "General",
            },
            "now": datetime.now(UTC),
        }
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await database.init()
        interrupted = await repository.mark_interrupted_scans()
        if interrupted:
            logger.warning("Marked %d interrupted scans", interrupted)
        intel_task: asyncio.Task | None = None
        if settings.intel.auto_sync and not settings.intel.offline:
            intel_task = asyncio.create_task(intel.auto_sync_if_needed())
        logger.info("Panel ready at http://%s:%s", settings.panel.host, settings.panel.port)
        try:
            yield
        finally:
            if intel_task and not intel_task.done():
                intel_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await intel_task
            await scan_manager.shutdown()
            await database.close()

    app = FastAPI(
        title="MarlonTheBug",
        version=__version__,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    app.state.paths = paths
    app.state.settings = settings
    app.state.database = database
    app.state.repo = repository
    app.state.scan_manager = scan_manager
    app.state.intel = intel
    app.state.report_service = report_service
    app.state.auth = auth
    app.state.templates = templates
    app.state.intel_syncing = False
    app.state.intel_task = None

    class SecurityMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            path = request.url.path
            token = request.query_params.get("token")
            if token and auth.enabled:
                if hmac_compare(token, auth.token):
                    response = RedirectResponse(
                        url=str(request.url.remove_query_params("token")),
                        status_code=303,
                    )
                    auth.login(response)
                    return response
                return JSONResponse({"detail": "Token inválido"}, status_code=401)

            if (
                auth.enabled
                and path not in PUBLIC_PATHS
                and not path.startswith("/static")
                and not auth.is_authenticated(request)
            ):
                if path.startswith("/api/"):
                    return JSONResponse({"detail": "No autenticado"}, status_code=401)
                next_url = request.url.path
                if request.url.query:
                    next_url += f"?{request.url.query}"
                return RedirectResponse(f"/login?next={safe_next(next_url)}", status_code=303)

            request.state.csrf = auth.csrf_token()
            response = await call_next(request)
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
            response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
            response.headers.setdefault("Referrer-Policy", "no-referrer")
            response.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                "script-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'",
            )
            return response

    app.add_middleware(SecurityMiddleware)

    @app.exception_handler(404)
    async def not_found(request: Request, exc):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "Not found"}, status_code=404)
        from marlonthebug.web.deps import render

        return await render(request, "error.html", status_code=404, code=404, message="Página no encontrada")

    @app.exception_handler(500)
    async def server_error(request: Request, exc):
        logger.exception("Unhandled panel error: %s", exc)
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "Internal server error"}, status_code=500)
        from marlonthebug.web.deps import render

        return await render(
            request,
            "error.html",
            status_code=500,
            code=500,
            message="Error interno del panel. Revisa los logs.",
        )

    app.include_router(router)
    app.mount(
        "/static",
        StaticFiles(directory=str(resource_path("web", "static"))),
        name="static",
    )

    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        return {
            "status": "ok" if await database.ping() else "degraded",
            "version": __version__,
        }

    return app


def hmac_compare(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)
