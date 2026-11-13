"""HTTP routes for the MarlonTheBug panel and JSON API."""

from __future__ import annotations

import asyncio
import contextlib
import csv
import io
import json
import math
from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)

from marlonthebug.db.models import ScanRunModel
from marlonthebug.services.evidence import to_markdown
from marlonthebug.services.exploitation import ExploitBlocked
from marlonthebug.services.reports import ReportRequest
from marlonthebug.services.scanner import PROFILES
from marlonthebug.settings import save_settings
from marlonthebug.web import serializers
from marlonthebug.web.deps import (
    get_auth,
    get_exploitation,
    get_intel,
    get_paths,
    get_repo,
    get_reports,
    get_scans,
    get_settings,
    get_tools,
    parse_cookies,
    parse_headers,
    plugin_groups,
    query_string,
    render,
    split_values,
)
from marlonthebug.web.security import safe_next

router = APIRouter()

SEVERITIES = ["critical", "high", "medium", "low", "info"]
STATUSES = ["open", "confirmed", "false_positive", "accepted", "remediated"]
CATEGORIES = ["recon", "web", "api", "auth", "cloud", "cicd", "llm"]


def require_csrf(request: Request, form) -> None:
    token = str(form.get("csrf") or request.headers.get("x-csrf-token") or "")
    if not get_auth(request).check_csrf(request, token):
        raise HTTPException(status_code=403, detail="Token CSRF inválido")


def redirect_with(url: str, **params) -> RedirectResponse:
    from urllib.parse import urlencode

    clean = {key: value for key, value in params.items() if value}
    if clean:
        url = f"{url}?{urlencode(clean)}"
    return RedirectResponse(url, status_code=303)


def host_from_target(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        return (parsed.netloc or "").lower()
    return value.split("/")[0].lower()


async def get_scan_or_404(request: Request, scan_id: str) -> ScanRunModel:
    scan = await get_repo(request).get_scan(scan_id, with_workspace=True)
    if not scan:
        raise HTTPException(status_code=404, detail="Análisis no encontrado")
    return scan


# ── Authentication ─────────────────────────────────────────


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = "/"):
    auth = get_auth(request)
    if auth.is_authenticated(request):
        return RedirectResponse("/", status_code=303)
    return await render(request, "login.html", next_url=safe_next(next), error=None)


@router.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    token = str(form.get("token", "")).strip()
    next_url = safe_next(str(form.get("next", "/")))
    auth = get_auth(request)
    import hmac

    if hmac.compare_digest(token, auth.token):
        response = RedirectResponse(next_url, status_code=303)
        auth.login(response)
        return response
    return await render(
        request,
        "login.html",
        next_url=next_url,
        error="Token incorrecto. Copia el token del archivo indicado o de la consola.",
    )


@router.post("/logout")
async def logout(request: Request):
    form = await request.form()
    require_csrf(request, form)
    response = RedirectResponse("/login", status_code=303)
    get_auth(request).logout(response)
    return response


# ── Dashboard ─────────────────────────────────────────────


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    repo = get_repo(request)
    workspaces = await repo.list_workspaces()
    workspace_id = request.query_params.get("workspace") or (workspaces[0].id if workspaces else None)
    stats = (
        await repo.dashboard_stats(workspace_id)
        if workspace_id
        else {
            "severity": {},
            "statuses": {},
            "categories": {},
            "plugins": [],
            "total": 0,
            "kev": 0,
            "assets": 0,
            "scans": 0,
            "reports": 0,
            "recent_findings": [],
            "trend": [],
        }
    )
    recent_scans = await repo.list_scans(workspace_id, limit=5) if workspace_id else []
    intel_summary = await get_intel(request).summary()
    return await render(
        request,
        "dashboard.html",
        nav="dashboard",
        workspace_id=workspace_id,
        stats=stats,
        recent_scans=recent_scans,
        intel_summary=intel_summary,
    )


# ── Workspaces ────────────────────────────────────────────


@router.get("/workspaces", response_class=HTMLResponse)
async def workspaces_page(request: Request):
    repo = get_repo(request)
    workspaces = await repo.list_workspaces()
    cards = []
    for workspace in workspaces:
        stats = await repo.dashboard_stats(workspace.id)
        cards.append({"workspace": workspace, "stats": stats})
    return await render(request, "workspaces.html", nav="workspaces", workspace_cards=cards)


@router.post("/workspaces")
async def create_workspace(request: Request):
    form = await request.form()
    require_csrf(request, form)
    name = str(form.get("name", "")).strip()
    if not name:
        return redirect_with("/workspaces", err="El nombre del proyecto es obligatorio")
    repo = get_repo(request)
    if await repo.get_workspace_by_name(name):
        return redirect_with("/workspaces", err="Ya existe un proyecto con ese nombre")
    workspace = await repo.create_workspace(
        name=name,
        client_name=str(form.get("client_name", "")).strip(),
        description=str(form.get("description", "")).strip(),
        allow_exploitation=bool(form.get("allow_exploitation")),
        require_confirmation=not bool(form.get("skip_confirmation")),
    )
    await repo.log_action("workspace.create", target=name, detail={"workspace_id": workspace.id})
    return redirect_with(f"/workspaces/{workspace.id}", ok="Proyecto creado")


@router.get("/workspaces/{workspace_id}", response_class=HTMLResponse)
async def workspace_detail(request: Request, workspace_id: str):
    repo = get_repo(request)
    workspace = await repo.get_workspace(workspace_id)
    if not workspace:
        raise HTTPException(404, "Workspace no encontrado")
    stats = await repo.dashboard_stats(workspace.id)
    scans = await repo.list_scans(workspace.id, limit=10)
    findings, _ = await repo.list_findings(workspace_id=workspace.id, page_size=10, sort="recent")
    return await render(
        request,
        "workspace_detail.html",
        nav="workspaces",
        workspace=workspace,
        workspace_id=workspace.id,
        stats=stats,
        scans=scans,
        findings=findings,
    )


@router.post("/workspaces/{workspace_id}/scope")
async def update_workspace_scope(request: Request, workspace_id: str):
    form = await request.form()
    require_csrf(request, form)
    repo = get_repo(request)
    workspace = await repo.get_workspace(workspace_id)
    if not workspace:
        raise HTTPException(404, "Workspace no encontrado")
    scope = dict(workspace.scope or {})
    scope["allowed_domains"] = split_values(str(form.get("allowed_domains", "")))
    scope["allowed_ip_ranges"] = split_values(str(form.get("allowed_ip_ranges", "")))
    scope["excluded"] = split_values(str(form.get("excluded", "")))
    await repo.update_workspace(
        workspace_id,
        scope=scope,
        allow_exploitation=bool(form.get("allow_exploitation")),
        require_confirmation=not bool(form.get("skip_confirmation")),
    )
    await repo.log_action(
        "workspace.scope.update",
        target=workspace.name,
        detail={"scope": scope, "allow_exploitation": bool(form.get("allow_exploitation"))},
    )
    return redirect_with(f"/workspaces/{workspace_id}", ok="Alcance actualizado")


@router.post("/workspaces/{workspace_id}/targets")
async def add_target(request: Request, workspace_id: str):
    form = await request.form()
    require_csrf(request, form)
    repo = get_repo(request)
    workspace = await repo.get_workspace(workspace_id)
    if not workspace:
        raise HTTPException(404, "Workspace no encontrado")
    hosts = split_values(str(form.get("targets", "")))
    hosts = [host_from_target(host) for host in hosts]
    hosts = [host for host in hosts if host]
    if not hosts:
        return redirect_with(f"/workspaces/{workspace_id}", err="Indica al menos un dominio o IP")
    for host in hosts:
        await repo.add_target(workspace_id, host)
    await repo.log_action("target.add", target=workspace.name, detail={"hosts": hosts})
    return redirect_with(f"/workspaces/{workspace_id}", ok=f"{len(hosts)} objetivo(s) añadido(s)")


@router.post("/workspaces/{workspace_id}/delete")
async def delete_workspace(request: Request, workspace_id: str):
    form = await request.form()
    require_csrf(request, form)
    repo = get_repo(request)
    workspace = await repo.get_workspace(workspace_id)
    if workspace:
        await repo.delete_workspace(workspace_id)
        await repo.log_action("workspace.delete", target=workspace.name)
    return redirect_with("/workspaces", ok="Proyecto eliminado")


# ── Scans ─────────────────────────────────────────────────


@router.get("/scans", response_class=HTMLResponse)
async def scans_page(request: Request):
    repo = get_repo(request)
    workspace_id = request.query_params.get("workspace") or None
    scans = await repo.list_scans(workspace_id, limit=100)
    return await render(
        request,
        "scans.html",
        nav="scans",
        workspace_id=workspace_id,
        scans=scans,
        running={scan.id: get_scans(request).is_running(scan.id) for scan in scans},
    )


@router.get("/scans/new", response_class=HTMLResponse)
async def new_scan_page(request: Request):
    repo = get_repo(request)
    workspaces = await repo.list_workspaces()
    workspace_id = request.query_params.get("workspace") or (workspaces[0].id if workspaces else "")
    workspace = await repo.get_workspace(workspace_id) if workspace_id else None
    return await render(
        request,
        "scan_new.html",
        nav="scans",
        workspace_id=workspace_id,
        workspace=workspace,
        profiles=PROFILES,
        plugin_groups=plugin_groups(request),
        categories=CATEGORIES,
        settings=get_settings(request),
    )


@router.post("/scans")
async def create_scan(request: Request):
    form = await request.form()
    require_csrf(request, form)
    repo = get_repo(request)
    workspace_id = str(form.get("workspace_id", ""))
    workspace = await repo.get_workspace(workspace_id)
    if not workspace:
        return redirect_with("/scans/new", err="Selecciona un proyecto válido")
    if not form.get("authorized"):
        return redirect_with(
            f"/scans/new?workspace={workspace_id}",
            err="Debes confirmar que tienes autorización para analizar los objetivos",
        )

    hosts = [host_from_target(item) for item in form.getlist("targets")]
    hosts += [host_from_target(item) for item in split_values(str(form.get("targets_text", "")))]
    hosts = sorted({host for host in hosts if host})
    if not hosts:
        return redirect_with(f"/scans/new?workspace={workspace_id}", err="Selecciona o añade al menos un objetivo")
    for host in hosts:
        await repo.add_target(workspace.id, host)

    modules = [str(item) for item in form.getlist("modules")]
    categories = (
        [str(item) for item in form.getlist("categories")]
        if not modules
        else sorted({item.split("/")[0] for item in modules})
    )
    if not categories:
        categories = ["recon", "web"]
    profile = str(form.get("profile", "standard"))
    if profile not in PROFILES:
        profile = "standard"

    options = {
        "headers": parse_headers(str(form.get("headers", ""))),
        "cookies": parse_cookies(str(form.get("cookies", ""))),
        "requests_per_second": float(form.get("requests_per_second") or 0) or None,
        "max_requests": int(form.get("max_requests") or 0) or None,
        "follow_redirects": bool(form.get("follow_redirects")),
        "verify_ssl": bool(form.get("verify_ssl")),
        "timeout": float(form.get("timeout") or 0) or None,
        "max_pages": int(form.get("max_pages") or 0) or None,
        "max_depth": int(form.get("max_depth") or 0) or None,
    }
    options = {key: value for key, value in options.items() if value is not None}
    scan = await repo.create_scan(
        workspace_id=workspace.id,
        targets=hosts,
        categories=categories,
        modules=modules,
        profile=profile,
        options=options,
        created_by="panel",
    )
    await repo.log_action(
        "scan.start",
        target=workspace.name,
        detail={"scan_id": scan.id, "targets": hosts, "categories": categories, "profile": profile},
    )
    await get_scans(request).start(scan.id)
    return redirect_with(f"/scans/{scan.id}", ok="Análisis iniciado")


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: str):
    scan = await get_scan_or_404(request, scan_id)
    repo = get_repo(request)
    all_findings = await repo.list_all_findings(scan.workspace_id, limit=5000)
    findings = [
        finding for finding in all_findings if finding.scan_run_id == scan.id or scan.id in (finding.occurrences or [])
    ]
    logs = get_scans(request).get_logs(scan.id) or list(scan.logs or [])
    stats = dict(scan.stats or {})
    stats.setdefault("findings", len(findings))
    return await render(
        request,
        "scan_detail.html",
        nav="scans",
        workspace_id=scan.workspace_id,
        scan=scan,
        findings=findings,
        logs=logs,
        stats=stats,
        is_running=get_scans(request).is_running(scan.id),
    )


@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(request: Request, scan_id: str):
    form = await request.form()
    require_csrf(request, form)
    scan = await get_scan_or_404(request, scan_id)
    await get_scans(request).cancel(scan_id)
    await get_repo(request).log_action(
        "scan.cancel", target=scan.workspace.name if scan.workspace else "", detail={"scan_id": scan_id}
    )
    return redirect_with(f"/scans/{scan_id}", ok="Cancelación solicitada")


@router.get("/scans/{scan_id}/stream")
async def scan_stream(request: Request, scan_id: str):
    scan = await get_scan_or_404(request, scan_id)
    manager = get_scans(request)
    initial = manager.get_logs(scan.id) or list(scan.logs or [])
    queue = manager.subscribe(scan.id)

    def sse(payload: dict) -> str:
        return f"data: {json.dumps(payload, ensure_ascii=False, default=str)}\n\n"

    async def generator():
        try:
            for entry in initial[-200:]:
                yield sse({"type": "log", **entry})
            if not manager.is_running(scan.id):
                yield sse({"type": "done", "status": scan.status, "stats": scan.stats or {}})
                return
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                except TimeoutError:
                    yield ": ping\n\n"
                    continue
                yield sse(event)
                if event.get("type") == "done":
                    break
        finally:
            manager.unsubscribe(scan.id, queue)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Findings ──────────────────────────────────────────────


@router.get("/findings", response_class=HTMLResponse)
async def findings_page(request: Request):
    repo = get_repo(request)
    workspace_id = request.query_params.get("workspace") or None
    severities = request.query_params.getlist("severity") or None
    statuses = request.query_params.getlist("status") or None
    categories = request.query_params.getlist("category") or None
    search = request.query_params.get("q") or None
    kev = request.query_params.get("kev") == "1"
    sort = request.query_params.get("sort", "severity")
    try:
        page = max(1, int(request.query_params.get("page", "1")))
    except ValueError:
        page = 1
    page_size = get_settings(request).panel.page_size
    findings, total = await repo.list_findings(
        workspace_id=workspace_id,
        severities=severities,
        statuses=statuses,
        categories=categories,
        search=search,
        kev_only=kev,
        page=page,
        page_size=page_size,
        sort=sort,
    )
    total_pages = max(1, math.ceil(total / page_size))
    return await render(
        request,
        "findings.html",
        nav="findings",
        workspace_id=workspace_id,
        findings=findings,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        severities=severities or [],
        statuses_filter=statuses or [],
        categories=categories or [],
        query=search or "",
        kev=kev,
        sort=sort,
        page_url=lambda **kwargs: query_string(request, **kwargs),
        severities_available=SEVERITIES,
        statuses_available=STATUSES,
        categories_available=CATEGORIES,
    )


@router.get("/findings/export")
async def export_findings(request: Request):
    repo = get_repo(request)
    workspace_id = request.query_params.get("workspace") or None
    findings = await repo.list_all_findings(workspace_id, limit=5000)
    output = io.StringIO()
    output.write("\ufeff")
    writer = csv.writer(output)
    writer.writerow(
        [
            "ID",
            "Severidad",
            "Estado",
            "Título",
            "Categoría",
            "Plugin",
            "Objetivo",
            "Endpoint",
            "CVSS",
            "CWE",
            "OWASP",
            "KEV",
            "EPSS",
            "Confianza",
            "Primera vez",
            "Última vez",
        ]
    )
    for finding in findings:
        writer.writerow(
            [
                finding.id,
                finding.severity,
                finding.status,
                finding.title,
                finding.category,
                finding.plugin_name,
                finding.target_host,
                finding.endpoint,
                finding.cvss_score,
                finding.cwe,
                finding.owasp,
                "Sí" if finding.kev else "No",
                finding.epss,
                finding.confidence,
                finding.first_seen,
                finding.last_seen,
            ]
        )
    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="hallazgos-marlonthebug.csv"'},
    )


@router.get("/findings/{finding_id}", response_class=HTMLResponse)
async def finding_detail(request: Request, finding_id: str):
    repo = get_repo(request)
    finding = await repo.get_finding(finding_id)
    if not finding:
        raise HTTPException(404, "Hallazgo no encontrado")
    modules = await get_exploitation(request).available_modules(finding)
    exploit_runs = await repo.list_exploit_runs(finding_id=finding.id, limit=10)
    tool_modules = get_tools(request).available_tools(finding)
    docker_status = await get_tools(request).status() if tool_modules else {"available": False}
    return await render(
        request,
        "finding_detail.html",
        nav="findings",
        workspace_id=finding.workspace_id,
        finding=finding,
        statuses_available=STATUSES,
        exploit_modules=modules,
        exploit_runs=exploit_runs,
        tool_modules=tool_modules,
        docker_status=docker_status,
        allow_exploitation=bool(finding.workspace and finding.workspace.allow_exploitation),
    )


@router.post("/findings/{finding_id}/status")
async def update_finding_status(request: Request, finding_id: str):
    form = await request.form()
    require_csrf(request, form)
    repo = get_repo(request)
    finding = await repo.get_finding(finding_id)
    if not finding:
        raise HTTPException(404, "Hallazgo no encontrado")
    status = str(form.get("status", finding.status))
    if status not in STATUSES:
        return redirect_with(f"/findings/{finding_id}", err="Estado no válido")
    notes = str(form.get("notes", ""))
    await repo.update_finding(finding_id, status=status, notes=notes)
    await repo.log_action(
        "finding.status",
        target=finding.target_host,
        detail={"finding_id": finding_id, "status": status},
    )
    return redirect_with(f"/findings/{finding_id}", ok="Hallazgo actualizado")


@router.post("/findings/{finding_id}/delete")
async def delete_finding(request: Request, finding_id: str):
    form = await request.form()
    require_csrf(request, form)
    repo = get_repo(request)
    finding = await repo.get_finding(finding_id)
    if finding:
        await repo.delete_finding(finding_id)
        await repo.log_action("finding.delete", target=finding.target_host, detail={"finding_id": finding_id})
    return redirect_with("/findings", ok="Hallazgo eliminado")


# ── Exploitation ───────────────────────────────────────────


@router.get("/exploits", response_class=HTMLResponse)
async def exploits_page(request: Request):
    repo = get_repo(request)
    workspace_id = request.query_params.get("workspace") or None
    if not workspace_id:
        workspaces = await repo.list_workspaces()
        workspace_id = workspaces[0].id if workspaces else None
    exploitable = await get_exploitation(request).list_exploitable(workspace_id) if workspace_id else []
    runs = await repo.list_exploit_runs(workspace_id, limit=50)
    docker_status = await get_tools(request).status()
    return await render(
        request,
        "exploits.html",
        nav="exploits",
        workspace_id=workspace_id,
        exploitable=exploitable,
        runs=runs,
        docker_status=docker_status,
        tool_image=get_settings(request).tools.docker_image,
    )


@router.get("/exploits/{run_id}", response_class=HTMLResponse)
async def exploit_detail(request: Request, run_id: str):
    run = await get_repo(request).get_exploit_run(run_id)
    if not run:
        raise HTTPException(404, "Ejecución de explotación no encontrada")
    return await render(
        request,
        "exploit_detail.html",
        nav="exploits",
        workspace_id=run.workspace_id,
        run=run,
    )


@router.get("/exploits/{run_id}/evidence.md")
async def exploit_evidence_markdown(request: Request, run_id: str):
    run = await get_repo(request).get_exploit_run(run_id)
    if not run:
        raise HTTPException(404, "Ejecución de explotación no encontrada")
    content = to_markdown(run)
    return Response(
        content=content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="evidencia-{run.id[:8]}.md"'},
    )


@router.get("/exploits/{run_id}/evidence.json")
async def exploit_evidence_json(request: Request, run_id: str):
    run = await get_repo(request).get_exploit_run(run_id)
    if not run:
        raise HTTPException(404, "Ejecución de explotación no encontrada")
    return JSONResponse(
        {
            "id": run.id,
            "module": run.module_name,
            "status": run.status,
            "risk": run.risk,
            "payload": run.payload,
            "output": run.output,
            "error": run.error,
            "evidence": run.evidence,
            "operator": run.operator,
            "started_at": serializers.iso(run.started_at),
            "finished_at": serializers.iso(run.finished_at),
        }
    )


@router.post("/findings/{finding_id}/exploit")
async def run_exploit(request: Request, finding_id: str):
    form = await request.form()
    require_csrf(request, form)
    module_key = str(form.get("module", ""))
    confirm_text = str(form.get("confirm_text", ""))
    try:
        run = await get_exploitation(request).run(
            finding_id=finding_id,
            module_key=module_key,
            confirm_text=confirm_text,
            operator="panel",
        )
    except ExploitBlocked as exc:
        return redirect_with(f"/findings/{finding_id}", err=str(exc))
    if run.status == "success":
        return redirect_with(f"/exploits/{run.id}", ok="Explotación confirmada y evidenciada")
    if run.status == "not_applicable":
        return redirect_with(f"/exploits/{run.id}", err="El módulo no encontró condiciones para explotar")
    return redirect_with(f"/exploits/{run.id}", err="La explotación no pudo confirmarse")


@router.post("/findings/{finding_id}/tool")
async def run_tool(request: Request, finding_id: str):
    form = await request.form()
    require_csrf(request, form)
    tool_key = str(form.get("tool", ""))
    confirm_text = str(form.get("confirm_text", ""))
    try:
        run = await get_tools(request).run(
            finding_id=finding_id,
            tool_key=tool_key,
            confirm_text=confirm_text,
            operator="panel",
        )
    except ExploitBlocked as exc:
        return redirect_with(f"/findings/{finding_id}", err=str(exc))
    if run.status == "success":
        return redirect_with(f"/exploits/{run.id}", ok="Herramienta ejecutada y evidencia guardada")
    return redirect_with(f"/exploits/{run.id}", err="La herramienta no confirmó el hallazgo; revisa la salida")


# ── Assets ────────────────────────────────────────────────


@router.get("/assets", response_class=HTMLResponse)
async def assets_page(request: Request):
    repo = get_repo(request)
    workspace_id = request.query_params.get("workspace") or None
    if not workspace_id:
        workspaces = await repo.list_workspaces()
        workspace_id = workspaces[0].id if workspaces else None
    assets = await repo.list_assets(workspace_id) if workspace_id else []
    return await render(request, "assets.html", nav="assets", workspace_id=workspace_id, assets=assets)


@router.get("/assets/{target_id}", response_class=HTMLResponse)
async def asset_detail(request: Request, target_id: str):
    repo = get_repo(request)
    target = await repo.get_target(target_id)
    if not target:
        raise HTTPException(404, "Activo no encontrado")
    findings = await repo.list_findings_for_target(target.id)
    intel = await repo.list_asset_intel(target.id)
    return await render(
        request,
        "asset_detail.html",
        nav="assets",
        workspace_id=target.workspace_id,
        target=target,
        findings=findings,
        intel=intel,
    )


@router.post("/assets/{target_id}/intel")
async def match_asset_intel(request: Request, target_id: str):
    form = await request.form()
    require_csrf(request, form)
    repo = get_repo(request)
    target = await repo.get_target(target_id)
    if not target:
        raise HTTPException(404, "Activo no encontrado")
    rows = await get_intel(request).match_target(target)
    await repo.log_action("intel.match", target=target.host, detail={"matches": len(rows)})
    return redirect_with(f"/assets/{target_id}", ok=f"{len(rows)} coincidencias locales de CVE")


# ── Reports ───────────────────────────────────────────────


@router.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    repo = get_repo(request)
    workspace_id = request.query_params.get("workspace") or None
    reports = await repo.list_reports(workspace_id)
    return await render(request, "reports.html", nav="reports", workspace_id=workspace_id, reports=reports)


@router.get("/reports/new", response_class=HTMLResponse)
async def new_report_page(request: Request):
    repo = get_repo(request)
    workspaces = await repo.list_workspaces()
    workspace_id = request.query_params.get("workspace") or (workspaces[0].id if workspaces else "")
    scans = await repo.list_scans(workspace_id, limit=50) if workspace_id else []
    settings = get_settings(request)
    return await render(
        request,
        "report_new.html",
        nav="reports",
        workspace_id=workspace_id,
        scans=scans,
        report_defaults=settings.reports,
        selected_scan_id=request.query_params.get("scan", ""),
    )


@router.post("/reports")
async def create_report(request: Request):
    form = await request.form()
    require_csrf(request, form)
    workspace_id = str(form.get("workspace_id", ""))
    repo = get_repo(request)
    workspace = await repo.get_workspace(workspace_id)
    if not workspace:
        return redirect_with("/reports/new", err="Selecciona un proyecto válido")
    report_request = ReportRequest(
        workspace_id=workspace.id,
        scan_run_id=str(form.get("scan_run_id", "")) or None,
        template=str(form.get("template", "full")),
        language=str(form.get("language", "es")),
        format=str(form.get("format", "pdf")),
        classification=str(form.get("classification", "CONFIDENCIAL")),
        company=str(form.get("company", "MarlonTheBug")),
        client_name=str(form.get("client_name", "")),
        title=str(form.get("title", "")),
        include_evidence=bool(form.get("include_evidence")),
        include_remediation=bool(form.get("include_remediation")),
        include_waf_rules=bool(form.get("include_waf_rules")),
    )
    try:
        report = await get_reports(request).generate(report_request)
    except Exception as exc:
        return redirect_with("/reports/new", err=f"No se pudo generar el informe: {exc}")
    message = "Informe generado"
    if report.options.get("pdf_fallback"):
        message = "Informe generado en HTML; instala Playwright o WeasyPrint para PDF"
    return redirect_with(f"/reports/{report.id}", ok=message)


@router.get("/reports/{report_id}", response_class=HTMLResponse)
async def report_detail(request: Request, report_id: str):
    report = await get_repo(request).get_report(report_id)
    if not report:
        raise HTTPException(404, "Informe no encontrado")
    exists = Path(report.path).exists()
    return await render(
        request,
        "report_detail.html",
        nav="reports",
        workspace_id=report.workspace_id,
        report=report,
        exists=exists,
    )


@router.get("/reports/{report_id}/download")
async def download_report(request: Request, report_id: str):
    report = await get_repo(request).get_report(report_id)
    if not report or not Path(report.path).exists():
        raise HTTPException(404, "Archivo de informe no encontrado")
    media = {
        "pdf": "application/pdf",
        "html": "text/html; charset=utf-8",
        "markdown": "text/markdown; charset=utf-8",
        "json": "application/json",
    }.get(report.format, "application/octet-stream")
    return FileResponse(report.path, media_type=media, filename=report.filename)


@router.get("/reports/{report_id}/preview")
async def preview_report(request: Request, report_id: str):
    report = await get_repo(request).get_report(report_id)
    if not report or not Path(report.path).exists():
        raise HTTPException(404, "Archivo de informe no encontrado")
    if report.format == "pdf":
        return FileResponse(report.path, media_type="application/pdf", headers={"Content-Disposition": "inline"})
    if report.format in {"html", "markdown"}:
        path = Path(report.path)
        if report.format == "markdown":
            import markdown as md

            content = md.markdown(path.read_text(encoding="utf-8"), extensions=["tables", "fenced_code"])
        else:
            content = path.read_text(encoding="utf-8")
        return HTMLResponse(content)
    raise HTTPException(404, "Vista previa no disponible")


@router.post("/reports/{report_id}/delete")
async def delete_report(request: Request, report_id: str):
    form = await request.form()
    require_csrf(request, form)
    repo = get_repo(request)
    report = await repo.get_report(report_id)
    if report:
        path = Path(report.path)
        if path.exists() and path.is_file():
            path.unlink(missing_ok=True)
        await repo.delete_report(report_id)
        await repo.log_action("report.delete", detail={"report_id": report_id})
    return redirect_with("/reports", ok="Informe eliminado")


# ── Intelligence ──────────────────────────────────────────


@router.get("/intel", response_class=HTMLResponse)
async def intel_page(request: Request):
    intel = get_intel(request)
    summary = await intel.summary()
    kev = await get_repo(request).list_kev(30)
    query = request.query_params.get("q", "")
    results = await get_repo(request).search_cves(query, 30) if query else []
    return await render(
        request,
        "intel.html",
        nav="intel",
        summary=summary,
        kev=kev,
        query=query,
        results=results,
        syncing=getattr(request.app.state, "intel_syncing", False),
    )


@router.post("/intel/sync")
async def sync_intel(request: Request):
    form = await request.form()
    require_csrf(request, form)
    app = request.app
    if getattr(app.state, "intel_syncing", False):
        return redirect_with("/intel", ok="Ya hay una sincronización en curso")
    intel = get_intel(request)

    async def run_sync() -> None:
        app.state.intel_syncing = True
        try:
            await intel.sync_all()
        finally:
            app.state.intel_syncing = False

    app.state.intel_task = asyncio.create_task(run_sync())
    return redirect_with("/intel", ok="Sincronización iniciada en segundo plano")


@router.get("/intel/search", response_class=HTMLResponse)
async def intel_search(request: Request, q: str = ""):
    results = await get_repo(request).search_cves(q, 50) if q else []
    summary = await get_intel(request).summary()
    return await render(
        request,
        "intel.html",
        nav="intel",
        summary=summary,
        kev=await get_repo(request).list_kev(30),
        query=q,
        results=results,
        syncing=getattr(request.app.state, "intel_syncing", False),
    )


@router.post("/intel/export")
async def export_intel(request: Request):
    form = await request.form()
    require_csrf(request, form)
    path = await get_intel(request).export_bundle()
    return FileResponse(
        path,
        media_type="application/json",
        filename="marlonthebug-intel-bundle.json",
    )


@router.post("/intel/import")
async def import_intel(request: Request, file: UploadFile = File(...)):
    form = await request.form()
    require_csrf(request, form)
    content = await file.read()
    if len(content) > 50 * 1024 * 1024:
        return redirect_with("/intel", err="El bundle supera el límite de 50 MB")
    path = get_paths(request).feeds_dir / "imported-intel.json"
    path.write_bytes(content)
    try:
        count = await get_intel(request).import_bundle(path)
    except Exception as exc:
        return redirect_with("/intel", err=f"Bundle inválido: {exc}")
    return redirect_with("/intel", ok=f"{count} CVEs importadas")


# ── Settings ──────────────────────────────────────────────


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    repo = get_repo(request)
    settings = get_settings(request)
    audit = await repo.list_audit(50)
    feeds = await repo.list_feeds()
    plugin_count = sum(len(items) for items in plugin_groups(request).values())
    docker_status = await get_tools(request).status()
    return await render(
        request,
        "settings.html",
        nav="settings",
        settings=settings,
        paths=get_paths(request),
        audit=audit,
        feeds=feeds,
        plugin_count=plugin_count,
        docker_status=docker_status,
    )


@router.post("/settings")
async def update_settings(request: Request):
    form = await request.form()
    require_csrf(request, form)
    settings = get_settings(request)
    settings.reports.language = str(form.get("language", settings.reports.language))
    settings.reports.company = str(form.get("company", settings.reports.company))
    settings.reports.classification = str(form.get("classification", settings.reports.classification))
    settings.intel.auto_sync = bool(form.get("auto_sync"))
    settings.intel.offline = bool(form.get("offline"))
    with contextlib.suppress(ValueError):
        settings.intel.sync_interval_hours = max(1, int(form.get("sync_interval_hours", 24)))
    with contextlib.suppress(ValueError):
        settings.panel.page_size = max(10, min(200, int(form.get("page_size", 50))))
    with contextlib.suppress(ValueError):
        settings.scan.requests_per_second = max(0.5, float(form.get("requests_per_second", 8)))
        settings.scan.max_requests = max(100, int(form.get("max_requests", 2500)))
    settings.tools.enabled = bool(form.get("tools_enabled"))
    settings.tools.docker_image = str(form.get("docker_image", settings.tools.docker_image)).strip()
    settings.tools.network = str(form.get("docker_network", settings.tools.network))
    with contextlib.suppress(ValueError):
        settings.tools.timeout = max(30, min(900, int(form.get("tool_timeout", 180))))
    save_settings(settings, get_paths(request))
    await get_repo(request).log_action("settings.update", detail={"by": "panel"})
    return redirect_with("/settings", ok="Configuración guardada")


# ── JSON API ──────────────────────────────────────────────


@router.get("/api/stats")
async def api_stats(request: Request):
    workspace_id = request.query_params.get("workspace") or None
    return await get_repo(request).dashboard_stats(workspace_id)


@router.get("/api/workspaces")
async def api_workspaces(request: Request):
    workspaces = await get_repo(request).list_workspaces()
    return [serializers.workspace_dict(item) for item in workspaces]


@router.get("/api/findings")
async def api_findings(request: Request):
    repo = get_repo(request)
    page = max(1, int(request.query_params.get("page", "1")))
    page_size = min(200, max(1, int(request.query_params.get("page_size", "50"))))
    findings, total = await repo.list_findings(
        workspace_id=request.query_params.get("workspace") or None,
        severities=request.query_params.getlist("severity") or None,
        statuses=request.query_params.getlist("status") or None,
        categories=request.query_params.getlist("category") or None,
        search=request.query_params.get("q") or None,
        kev_only=request.query_params.get("kev") == "1",
        page=page,
        page_size=page_size,
        sort=request.query_params.get("sort", "severity"),
    )
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [serializers.finding_dict(item) for item in findings],
    }


@router.get("/api/findings/{finding_id}")
async def api_finding(request: Request, finding_id: str):
    finding = await get_repo(request).get_finding(finding_id)
    if not finding:
        raise HTTPException(404, "Hallazgo no encontrado")
    return serializers.finding_dict(finding, include_evidence=True)


@router.get("/api/scans")
async def api_scans(request: Request):
    scans = await get_repo(request).list_scans(request.query_params.get("workspace") or None, limit=100)
    return [serializers.scan_dict(item) for item in scans]


@router.get("/api/scans/{scan_id}")
async def api_scan(request: Request, scan_id: str):
    scan = await get_scan_or_404(request, scan_id)
    return serializers.scan_dict(scan)


@router.get("/api/intel/summary")
async def api_intel(request: Request):
    summary = await get_intel(request).summary()
    return {
        "offline": summary["offline"],
        "stats": summary["stats"],
        "feeds": [
            {
                "name": feed.name,
                "status": feed.status,
                "count": feed.count,
                "last_sync": serializers.iso(feed.last_sync),
                "error": feed.error,
            }
            for feed in summary["feeds"]
        ],
    }


@router.get("/api/cves")
async def api_cves(request: Request):
    query = request.query_params.get("q", "")
    results = await get_repo(request).search_cves(query, 50) if query else []
    return [serializers.cve_dict(item) for item in results]
