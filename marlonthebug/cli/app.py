"""Command-line interface for MarlonTheBug 2.0."""

from __future__ import annotations

import asyncio
import shutil
import threading
import webbrowser
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from marlonthebug import __version__
from marlonthebug.db.database import Database, sqlite_url
from marlonthebug.db.repository import Repository
from marlonthebug.paths import AppPaths
from marlonthebug.services.intel import IntelService
from marlonthebug.services.reports import ReportRequest, ReportService
from marlonthebug.services.scanner import PROFILES, ScanManager
from marlonthebug.settings import load_settings, write_default_config
from marlonthebug.utils.logging import setup_logging

cli = typer.Typer(
    name="marlonthebug",
    help="MarlonTheBug — plataforma de auditoría y reporting de seguridad.",
    no_args_is_help=True,
    add_completion=False,
)
workspace_app = typer.Typer(help="Gestión de proyectos", no_args_is_help=True)
scan_app = typer.Typer(help="Ejecución de análisis", no_args_is_help=True)
report_app = typer.Typer(help="Generación de informes", no_args_is_help=True)
intel_app = typer.Typer(help="Inteligencia de vulnerabilidades", no_args_is_help=True)
legacy_app = typer.Typer(help="Importación de datos de versiones anteriores", no_args_is_help=True)
exploit_app = typer.Typer(help="Explotación controlada", no_args_is_help=True)
tools_app = typer.Typer(help="Herramientas reales de seguridad", no_args_is_help=True)
cli.add_typer(workspace_app, name="workspace")
cli.add_typer(scan_app, name="scan")
cli.add_typer(report_app, name="report")
cli.add_typer(intel_app, name="intel")
cli.add_typer(legacy_app, name="legacy")
cli.add_typer(exploit_app, name="exploit")
cli.add_typer(tools_app, name="tools")

console = Console()


def _paths(data_dir: str | None = None, portable: bool = False) -> AppPaths:
    paths = AppPaths.resolve(data_dir=data_dir, portable=portable)
    paths.ensure()
    write_default_config(paths)
    return paths


def _settings(paths: AppPaths, offline: bool = False):
    return load_settings(paths, overrides={"intel": {"offline": True}} if offline else None)


async def _repo(paths: AppPaths) -> tuple[Database, Repository]:
    database = Database(sqlite_url(paths.db_path), portable=paths.portable)
    await database.init()
    return database, Repository(database)


def _resolve_workspace(repository: Repository, name: str | None):
    async def resolve():
        if name:
            workspace = await repository.get_workspace_by_name(name)
            if workspace:
                return workspace
            return await repository.get_workspace(name)
        workspaces = await repository.list_workspaces()
        return workspaces[0] if workspaces else None

    return resolve()


@cli.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", is_flag=True, help="Mostrar versión"),
) -> None:
    if version:
        typer.echo(f"MarlonTheBug v{__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


@cli.command()
def panel(
    host: str | None = typer.Option(None, "--host", help="Host de escucha (por defecto 127.0.0.1)"),
    port: int | None = typer.Option(None, "--port", help="Puerto del panel (por defecto 8765)"),
    no_browser: bool = typer.Option(False, "--no-browser", help="No abrir el navegador"),
    no_auth: bool = typer.Option(False, "--no-auth", help="Desactivar token local (no recomendado)"),
    data_dir: str | None = typer.Option(None, "--data-dir", help="Directorio de datos"),
    portable: bool = typer.Option(False, "--portable", help="Guardar todo en ./data"),
    offline: bool = typer.Option(False, "--offline", help="No descargar feeds de inteligencia"),
) -> None:
    """Arranca el panel web local."""
    import uvicorn

    from marlonthebug.web.app import create_app

    paths = _paths(data_dir, portable)
    overrides: dict[str, dict[str, object]] = {}
    if host:
        overrides.setdefault("panel", {})["host"] = host
    if port:
        overrides.setdefault("panel", {})["port"] = port
    settings = load_settings(paths, overrides=overrides or None)
    settings.intel.offline = offline
    host = host or settings.panel.host
    port = port or settings.panel.port
    setup_logging(
        level=settings.logging.level,
        log_file=paths.logs_dir / "marlonthebug.log",
        rotation=settings.logging.rotation,
        retention=settings.logging.retention,
    )
    app = create_app(paths, settings, auth_enabled=not no_auth)
    token = app.state.auth.token if app.state.auth.enabled else ""
    browser_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    url = f"http://{browser_host}:{port}/"
    if token:
        url += f"?token={token}"

    console.print(
        Panel.fit(
            f"[bold cyan]MarlonTheBug[/bold cyan] v{__version__}\n"
            f"Panel: [link]{url}[/link]\n"
            f"Datos: [dim]{paths.root}[/dim]\n"
            f"Config: [dim]{paths.config_file}[/dim]",
            title="Servidor local",
            border_style="cyan",
        )
    )
    if host not in {"127.0.0.1", "localhost", "::1"} and no_auth:
        console.print("[bold red]Aviso:[/bold red] estás exponiendo el panel sin autenticación.")
    if not no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host=host, port=port, log_config=None)


@cli.command("serve", hidden=True)
def serve_alias(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8765, "--port"),
    no_browser: bool = typer.Option(False, "--no-browser"),
    no_auth: bool = typer.Option(False, "--no-auth"),
    data_dir: str | None = typer.Option(None, "--data-dir"),
    portable: bool = typer.Option(False, "--portable"),
    offline: bool = typer.Option(False, "--offline"),
) -> None:
    panel(host, port, no_browser, no_auth, data_dir, portable, offline)


@workspace_app.command("create")
def workspace_create(
    name: str = typer.Option(..., "--name", "-n"),
    client: str = typer.Option("", "--client"),
    description: str = typer.Option("", "--description", "-d"),
    data_dir: str | None = typer.Option(None, "--data-dir"),
) -> None:
    """Crea un proyecto."""

    async def run() -> None:
        paths = _paths(data_dir)
        database, repository = await _repo(paths)
        try:
            if await repository.get_workspace_by_name(name):
                console.print(f"[red]Ya existe un proyecto llamado {name}[/red]")
                raise typer.Exit(1)
            workspace = await repository.create_workspace(name, client_name=client, description=description)
            await repository.log_action("workspace.create", target=name, detail={"workspace_id": workspace.id})
            console.print(f"[green]Proyecto creado:[/green] {workspace.name} ({workspace.id})")
        finally:
            await database.close()

    asyncio.run(run())


@workspace_app.command("list")
def workspace_list(data_dir: str | None = typer.Option(None, "--data-dir")) -> None:
    """Lista proyectos."""

    async def run() -> None:
        paths = _paths(data_dir)
        database, repository = await _repo(paths)
        try:
            workspaces = await repository.list_workspaces()
            table = Table(title="Proyectos")
            table.add_column("Nombre")
            table.add_column("Cliente")
            table.add_column("Activos")
            table.add_column("Creado")
            for workspace in workspaces:
                table.add_row(
                    workspace.name,
                    workspace.client_name or "—",
                    str(len(workspace.targets or [])),
                    workspace.created_at.strftime("%Y-%m-%d"),
                )
            console.print(table if workspaces else "No hay proyectos.")
        finally:
            await database.close()

    asyncio.run(run())


@workspace_app.command("add")
def workspace_add(
    name: str = typer.Option(..., "--name", "-n"),
    domains: str = typer.Option("", "--domains"),
    ips: str = typer.Option("", "--ips"),
    data_dir: str | None = typer.Option(None, "--data-dir"),
) -> None:
    """Añade dominios o IPs al alcance de un proyecto."""

    async def run() -> None:
        paths = _paths(data_dir)
        database, repository = await _repo(paths)
        try:
            workspace = await repository.get_workspace_by_name(name)
            if not workspace:
                console.print(f"[red]Proyecto no encontrado: {name}[/red]")
                raise typer.Exit(1)
            hosts = [host.strip() for host in domains.split(",") if host.strip()]
            hosts += [ip.strip() for ip in ips.split(",") if ip.strip()]
            for host in hosts:
                await repository.add_target(workspace.id, host)
            await repository.log_action("target.add", target=name, detail={"hosts": hosts})
            console.print(f"[green]Añadidos {len(hosts)} objetivos a {name}[/green]")
        finally:
            await database.close()

    asyncio.run(run())


@workspace_app.command("info")
def workspace_info(
    name: str = typer.Option(..., "--name", "-n"),
    data_dir: str | None = typer.Option(None, "--data-dir"),
) -> None:
    """Muestra el detalle de un proyecto."""

    async def run() -> None:
        paths = _paths(data_dir)
        database, repository = await _repo(paths)
        try:
            workspace = await repository.get_workspace_by_name(name)
            if not workspace:
                console.print(f"[red]Proyecto no encontrado: {name}[/red]")
                raise typer.Exit(1)
            stats = await repository.dashboard_stats(workspace.id)
            console.print(f"[bold]{workspace.name}[/bold] · {workspace.client_name or 'sin cliente'}")
            console.print(
                f"Activos: {len(workspace.targets or [])} · Hallazgos: {stats['total']} · Análisis: {stats['scans']}"
            )
            console.print(f"Alcance: {workspace.scope}")
        finally:
            await database.close()

    asyncio.run(run())


@workspace_app.command("delete")
def workspace_delete(
    name: str = typer.Option(..., "--name", "-n"),
    yes: bool = typer.Option(False, "--yes", "-y"),
    data_dir: str | None = typer.Option(None, "--data-dir"),
) -> None:
    """Elimina un proyecto y todos sus datos."""
    if not yes and not typer.confirm(f"¿Eliminar el proyecto {name} y todos sus datos?"):
        raise typer.Exit()
    asyncio.run(_delete_workspace(name, data_dir))


async def _delete_workspace(name: str, data_dir: str | None) -> None:
    paths = _paths(data_dir)
    database, repository = await _repo(paths)
    try:
        workspace = await repository.get_workspace_by_name(name)
        if workspace:
            await repository.delete_workspace(workspace.id)
            console.print(f"[green]Proyecto eliminado:[/green] {name}")
        else:
            console.print(f"[red]Proyecto no encontrado: {name}[/red]")
    finally:
        await database.close()


@scan_app.command("run")
def scan_run(
    workspace_name: str = typer.Option(..., "--workspace", "-w", help="Nombre del proyecto"),
    targets: str = typer.Option("", "--targets", "-t", help="Objetivos separados por coma"),
    categories: str = typer.Option("recon,web", "--categories", "-c"),
    modules: str = typer.Option("", "--modules", "-m", help="Módulos category/name separados por coma"),
    profile: str = typer.Option("standard", "--profile", "-p"),
    authorized: bool = typer.Option(False, "--authorized", help="Confirmo que tengo autorización"),
    data_dir: str | None = typer.Option(None, "--data-dir"),
) -> None:
    """Ejecuta un análisis desde la terminal."""
    if not authorized:
        console.print("[red]Debes confirmar autorización con --authorized[/red]")
        raise typer.Exit(1)
    if profile not in PROFILES:
        console.print(f"[red]Perfil no válido. Usa: {', '.join(PROFILES)}[/red]")
        raise typer.Exit(1)
    asyncio.run(_run_scan(workspace_name, targets, categories, modules, profile, data_dir))


async def _run_scan(
    workspace_name: str,
    targets: str,
    categories: str,
    modules: str,
    profile: str,
    data_dir: str | None,
) -> None:
    paths = _paths(data_dir)
    settings = load_settings(paths)
    setup_logging(settings.logging.level, paths.logs_dir / "marlonthebug.log")
    database, repository = await _repo(paths)
    try:
        workspace = await repository.get_workspace_by_name(workspace_name)
        if not workspace:
            console.print(f"[red]Proyecto no encontrado: {workspace_name}[/red]")
            raise typer.Exit(1)
        host_list = [item.strip() for item in targets.split(",") if item.strip()]
        if not host_list:
            host_list = [target.host for target in workspace.targets]
        if not host_list:
            console.print("[red]El proyecto no tiene objetivos. Usa --targets o añade activos.[/red]")
            raise typer.Exit(1)
        for host in host_list:
            await repository.add_target(workspace.id, host)
        category_list = [item.strip() for item in categories.split(",") if item.strip()]
        module_list = [item.strip() for item in modules.split(",") if item.strip()]
        scan = await repository.create_scan(
            workspace.id,
            host_list,
            category_list,
            modules=module_list,
            profile=profile,
            created_by="cli",
        )
        manager = ScanManager(repository, settings, IntelService(repository, settings, paths))
        await manager.start(scan.id)
        task = manager.tasks[scan.id]
        printed = 0
        while not task.done():
            logs = manager.get_logs(scan.id)
            for entry in logs[printed:]:
                console.print(f"[dim]{entry['time']}[/dim] [{entry['level'].lower()}]{entry['message']}[/]")
            printed = len(logs)
            await asyncio.sleep(0.6)
        await task
        for entry in manager.get_logs(scan.id)[printed:]:
            console.print(f"[dim]{entry['time']}[/dim] [{entry['level'].lower()}]{entry['message']}[/]")
        findings, total = await repository.list_findings(workspace_id=workspace.id, page_size=20, sort="severity")
        console.print(f"\n[green]Análisis completado:[/green] {total} hallazgos en el proyecto")
        table = Table(title="Últimos hallazgos")
        table.add_column("Severidad")
        table.add_column("Título")
        table.add_column("Objetivo")
        for finding in findings[:10]:
            table.add_row(finding.severity, finding.title, finding.target_host)
        if findings:
            console.print(table)
    finally:
        await database.close()


@report_app.command("generate")
def report_generate(
    workspace_name: str = typer.Option(..., "--workspace", "-w"),
    scan_id: str = typer.Option("", "--scan", help="ID de análisis concreto"),
    format: str = typer.Option("pdf", "--format", "-f", help="pdf, html, markdown o json"),
    template: str = typer.Option("full", "--template", help="full, executive o technical"),
    language: str = typer.Option("es", "--language", help="es o en"),
    output: str | None = typer.Option(None, "--output", "-o"),
    data_dir: str | None = typer.Option(None, "--data-dir"),
) -> None:
    """Genera un informe desde la base de datos."""
    asyncio.run(_generate_report(workspace_name, scan_id, format, template, language, output, data_dir))


async def _generate_report(
    workspace_name: str,
    scan_id: str,
    fmt: str,
    template: str,
    language: str,
    output: str | None,
    data_dir: str | None,
) -> None:
    paths = _paths(data_dir)
    settings = load_settings(paths)
    setup_logging(settings.logging.level, paths.logs_dir / "marlonthebug.log")
    database, repository = await _repo(paths)
    try:
        workspace = await repository.get_workspace_by_name(workspace_name)
        if not workspace:
            console.print(f"[red]Proyecto no encontrado: {workspace_name}[/red]")
            raise typer.Exit(1)
        service = ReportService(repository, settings, paths)
        report = await service.generate(
            ReportRequest(
                workspace_id=workspace.id,
                scan_run_id=scan_id or None,
                format=fmt,
                template=template,
                language=language,
                classification=settings.reports.classification,
                company=settings.reports.company,
                client_name=workspace.client_name,
            )
        )
        console.print(f"[green]Informe generado:[/green] {report.path}")
        if output:
            target = Path(output).expanduser()
            shutil.copy2(report.path, target)
            console.print(f"[green]Copiado a:[/green] {target}")
    finally:
        await database.close()


@intel_app.command("sync")
def intel_sync(data_dir: str | None = typer.Option(None, "--data-dir")) -> None:
    """Sincroniza KEV y EPSS."""
    asyncio.run(_intel_sync(data_dir))


async def _intel_sync(data_dir: str | None) -> None:
    paths = _paths(data_dir)
    settings = load_settings(paths)
    database, repository = await _repo(paths)
    try:
        service = IntelService(repository, settings, paths)
        result = await service.sync_all()
        console.print(result)
    finally:
        await database.close()


@intel_app.command("status")
def intel_status(data_dir: str | None = typer.Option(None, "--data-dir")) -> None:
    """Muestra el estado de los feeds."""

    async def run() -> None:
        paths = _paths(data_dir)
        database, repository = await _repo(paths)
        try:
            feeds = await repository.list_feeds()
            stats = await repository.intel_stats()
            table = Table(title="Inteligencia")
            table.add_column("Feed")
            table.add_column("Estado")
            table.add_column("Registros")
            table.add_column("Última sync")
            for feed in feeds:
                table.add_row(
                    feed.name,
                    feed.status,
                    str(feed.count),
                    feed.last_sync.strftime("%Y-%m-%d %H:%M") if feed.last_sync else "nunca",
                )
            console.print(table)
            console.print(f"CVEs: {stats['total']} · KEV: {stats['kev']} · EPSS: {stats['epss']}")
        finally:
            await database.close()

    asyncio.run(run())


@intel_app.command("search")
def intel_search(
    query: str = typer.Argument(...),
    data_dir: str | None = typer.Option(None, "--data-dir"),
) -> None:
    """Busca una CVE en la caché local."""

    async def run() -> None:
        paths = _paths(data_dir)
        database, repository = await _repo(paths)
        try:
            results = await repository.search_cves(query, 30)
            table = Table(title=f"Resultados para {query}")
            table.add_column("CVE")
            table.add_column("CVSS")
            table.add_column("KEV")
            table.add_column("Descripción")
            for cve in results:
                table.add_row(cve.cve_id, f"{cve.cvss_score:.1f}", "sí" if cve.kev else "no", cve.description[:90])
            console.print(table if results else "Sin resultados.")
        finally:
            await database.close()

    asyncio.run(run())


@intel_app.command("export")
def intel_export(
    output: str | None = typer.Option(None, "--output", "-o"),
    sign_key: str | None = typer.Option(None, "--sign-key", help="Clave privada Ed25519 para firmar el bundle"),
    data_dir: str | None = typer.Option(None, "--data-dir"),
) -> None:
    """Exporta un bundle de inteligencia para entornos air-gapped."""
    asyncio.run(_intel_export(output, sign_key, data_dir))


async def _intel_export(output: str | None, sign_key: str | None, data_dir: str | None) -> None:
    from marlonthebug.services.signing import SigningError, sign_bundle

    paths = _paths(data_dir)
    settings = load_settings(paths)
    database, repository = await _repo(paths)
    try:
        service = IntelService(repository, settings, paths)
        path = await service.export_bundle(Path(output).expanduser() if output else None)
        console.print(f"[green]Bundle exportado:[/green] {path}")
        if sign_key:
            try:
                signature = sign_bundle(path, Path(sign_key))
            except SigningError as exc:
                console.print(f"[red]No se pudo firmar:[/red] {exc}")
                raise typer.Exit(1) from exc
            console.print(f"[green]Firma Ed25519:[/green] {signature}")
    finally:
        await database.close()


@intel_app.command("import")
def intel_import(
    path: str = typer.Argument(...),
    signature: str | None = typer.Option(None, "--signature", help="Firma .sig del bundle"),
    public_key: str | None = typer.Option(None, "--public-key", help="Clave pública Ed25519"),
    data_dir: str | None = typer.Option(None, "--data-dir"),
) -> None:
    """Importa un bundle de inteligencia (y verifica su firma si se indica)."""
    asyncio.run(_intel_import(path, signature, public_key, data_dir))


async def _intel_import(
    path: str,
    signature: str | None,
    public_key: str | None,
    data_dir: str | None,
) -> None:
    from marlonthebug.services.signing import SigningError, verify_bundle

    paths = _paths(data_dir)
    settings = load_settings(paths)
    bundle_path = Path(path).expanduser()
    key_path = Path(public_key).expanduser() if public_key else None
    signature_path = Path(signature).expanduser() if signature else None
    if settings.intel.require_bundle_signature or signature or key_path:
        if key_path is None and settings.intel.signing_public_key:
            key_path = Path(settings.intel.signing_public_key).expanduser()
        if key_path is None:
            console.print("[red]Falta la clave pública Ed25519 (--public-key).[/red]")
            raise typer.Exit(1)
        if signature_path is None:
            signature_path = bundle_path.with_name(bundle_path.name + ".sig")
        try:
            verify_bundle(bundle_path, signature_path, key_path)
        except SigningError as exc:
            console.print(f"[red]Firma inválida:[/red] {exc}")
            raise typer.Exit(1) from exc
        console.print(f"[green]Firma válida:[/green] {signature_path}")

    database, repository = await _repo(paths)
    try:
        service = IntelService(repository, settings, paths)
        count = await service.import_bundle(bundle_path)
        console.print(f"[green]{count} CVEs importadas[/green]")
    finally:
        await database.close()


@intel_app.command("keygen")
def intel_keygen(
    private_key: str = typer.Option("mtb-intel-signing.pem", "--private", help="Ruta de la clave privada"),
    public_key: str = typer.Option("mtb-intel-signing.pub", "--public", help="Ruta de la clave pública"),
    force: bool = typer.Option(False, "--force", help="Sobrescribir claves existentes"),
) -> None:
    """Genera un par de claves Ed25519 para firmar bundles."""
    from marlonthebug.services.signing import SigningError, generate_keypair, public_key_fingerprint

    try:
        private_path, public_path = generate_keypair(Path(private_key), Path(public_key), force=force)
    except SigningError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    console.print(f"[green]Clave privada:[/green] {private_path} [dim](0600)[/dim]")
    console.print(f"[green]Clave pública:[/green] {public_path}")
    console.print(f"[dim]Huella SHA-256: {public_key_fingerprint(public_path)}[/dim]")


@intel_app.command("verify")
def intel_verify(
    path: str = typer.Argument(..., help="Bundle a verificar"),
    public_key: str = typer.Option(..., "--public-key", help="Clave pública Ed25519"),
    signature: str | None = typer.Option(None, "--signature", help="Firma .sig (por defecto bundle.sig)"),
) -> None:
    """Verifica la firma Ed25519 de un bundle."""
    from marlonthebug.services.signing import SigningError, verify_bundle

    bundle_path = Path(path).expanduser()
    signature_path = Path(signature).expanduser() if signature else bundle_path.with_name(bundle_path.name + ".sig")
    try:
        verify_bundle(bundle_path, signature_path, Path(public_key).expanduser())
    except SigningError as exc:
        console.print(f"[red]Firma inválida:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Firma válida:[/green] {signature_path}")


@exploit_app.command("list")
def exploit_list(
    workspace_name: str = typer.Option(..., "--workspace", "-w"),
    data_dir: str | None = typer.Option(None, "--data-dir"),
) -> None:
    """Lista hallazgos con módulos de explotación disponibles."""

    async def run() -> None:
        from marlonthebug.services.exploitation import ExploitationService

        paths = _paths(data_dir)
        settings = load_settings(paths)
        database, repository = await _repo(paths)
        try:
            workspace = await repository.get_workspace_by_name(workspace_name)
            if not workspace:
                console.print(f"[red]Proyecto no encontrado: {workspace_name}[/red]")
                raise typer.Exit(1)
            service = ExploitationService(repository, settings, paths)
            rows = await service.list_exploitable(workspace.id)
            table = Table(title=f"Explotables · {workspace.name}")
            table.add_column("ID")
            table.add_column("Severidad")
            table.add_column("Hallazgo")
            table.add_column("Módulos")
            for finding, modules in rows:
                table.add_row(
                    finding.id[:8],
                    finding.severity,
                    finding.title[:70],
                    ", ".join(module["key"] for module in modules),
                )
            console.print(table if rows else "No hay hallazgos explotables.")
        finally:
            await database.close()

    asyncio.run(run())


@exploit_app.command("run")
def exploit_run(
    finding_id: str = typer.Option(..., "--finding", "-f", help="ID del hallazgo"),
    module: str = typer.Option(..., "--module", "-m", help="category/name del módulo"),
    confirm_text: str = typer.Option(..., "--confirm-text", help="Escribe EXPLOTAR"),
    data_dir: str | None = typer.Option(None, "--data-dir"),
) -> None:
    """Ejecuta una explotación controlada y muestra la evidencia."""
    asyncio.run(_exploit_run(finding_id, module, confirm_text, data_dir))


async def _exploit_run(
    finding_id: str,
    module: str,
    confirm_text: str,
    data_dir: str | None,
) -> None:
    from marlonthebug.services.exploitation import ExploitationService, ExploitBlocked

    paths = _paths(data_dir)
    settings = load_settings(paths)
    database, repository = await _repo(paths)
    try:
        service = ExploitationService(repository, settings, paths)
        try:
            run = await service.run(finding_id, module, confirm_text, operator="cli")
        except ExploitBlocked as exc:
            console.print(f"[red]Bloqueado:[/red] {exc}")
            raise typer.Exit(1) from exc
        console.print(f"[bold]Estado:[/bold] {run.status}")
        console.print(run.output or run.error or "Sin salida")
        if run.evidence:
            console.print(run.evidence)
    finally:
        await database.close()


@tools_app.command("status")
def tools_status(data_dir: str | None = typer.Option(None, "--data-dir")) -> None:
    """Muestra el estado del backend de herramientas."""
    asyncio.run(_tools_status(data_dir))


async def _tools_status(data_dir: str | None) -> None:
    from marlonthebug.tools.service import ToolService

    paths = _paths(data_dir)
    settings = load_settings(paths)
    database, repository = await _repo(paths)
    try:
        service = ToolService(repository, settings, paths)
        status = await service.status()
        console.print(status)
    finally:
        await database.close()


@tools_app.command("build")
def tools_build(
    image: str | None = typer.Option(None, "--image", help="Imagen a construir"),
    data_dir: str | None = typer.Option(None, "--data-dir"),
) -> None:
    """Construye la imagen Docker con Kali (solo backend docker)."""
    paths = _paths(data_dir)
    settings = load_settings(paths)
    if image:
        settings.tools.docker_image = image
    from marlonthebug.tools.service import ToolService

    service = ToolService(None, settings, paths)  # type: ignore[arg-type]
    console.print(f"[*] Construyendo {settings.tools.docker_image}…")
    code, output = service.build_image_sync()
    console.print(output)
    if code == 0:
        console.print(f"[green]Imagen lista:[/green] {settings.tools.docker_image}")
    else:
        console.print(f"[red]La construcción falló con código {code}[/red]")
        raise typer.Exit(code)


@tools_app.command("run")
def tools_run(
    finding_id: str = typer.Option(..., "--finding", "-f"),
    tool: str = typer.Option(..., "--tool", "-t", help="sqlmap, nuclei, commix, whatweb, nikto, nmap"),
    confirm_text: str = typer.Option(..., "--confirm-text", help="Escribe EXPLOTAR"),
    data_dir: str | None = typer.Option(None, "--data-dir"),
) -> None:
    """Ejecuta una herramienta real contra un hallazgo."""
    asyncio.run(_tools_run(finding_id, tool, confirm_text, data_dir))


async def _tools_run(finding_id: str, tool: str, confirm_text: str, data_dir: str | None) -> None:
    from marlonthebug.services.exploitation import ExploitBlocked
    from marlonthebug.tools.service import ToolService

    paths = _paths(data_dir)
    settings = load_settings(paths)
    database, repository = await _repo(paths)
    try:
        service = ToolService(repository, settings, paths)
        try:
            run = await service.run(finding_id, tool, confirm_text, operator="cli")
        except ExploitBlocked as exc:
            console.print(f"[red]Bloqueado:[/red] {exc}")
            raise typer.Exit(1) from exc
        console.print(f"[bold]Estado:[/bold] {run.status}")
        console.print(run.output[:8000] or run.error or "Sin salida")
    finally:
        await database.close()


@tools_app.command("runner")
def tools_runner(
    host: str = typer.Option("0.0.0.0", "--host", help="Host de escucha del runner"),
    port: int = typer.Option(8080, "--port", help="Puerto del runner"),
) -> None:
    """Arranca el servicio tools-runner (uso interno o desarrollo)."""
    import os

    from marlonthebug.tools.runner_api import serve

    if not os.environ.get("MTB_TOOLS_TOKEN"):
        console.print("[red]Define MTB_TOOLS_TOKEN antes de arrancar el tools-runner.[/red]")
        raise typer.Exit(1)
    console.print(f"[cyan]tools-runner[/cyan] escuchando en http://{host}:{port}")
    serve(host, port)


@cli.command("backup")
def backup_command(
    output: str | None = typer.Option(None, "--output", "-o", help="Archivo .tar.gz de destino"),
    include_logs: bool = typer.Option(False, "--include-logs", help="Incluir logs en el backup"),
    data_dir: str | None = typer.Option(None, "--data-dir"),
) -> None:
    """Empaqueta la base de datos, informes y configuración en un .tar.gz."""
    from marlonthebug.services.backup import BackupError, create_backup

    paths = _paths(data_dir)
    try:
        target = create_backup(
            paths,
            Path(output).expanduser() if output else None,
            include_logs=include_logs,
        )
    except BackupError as exc:
        console.print(f"[red]No se pudo crear el backup:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Backup creado:[/green] {target}")
    console.print("[dim]Incluye la base de datos, informes, configuración y el token del panel.[/dim]")


@cli.command("restore")
def restore_command(
    archive: str = typer.Argument(..., help="Archivo .tar.gz creado por marlonthebug backup"),
    force: bool = typer.Option(False, "--force", help="Sobrescribir los datos existentes"),
    yes: bool = typer.Option(False, "--yes", "-y", help="No pedir confirmación"),
    data_dir: str | None = typer.Option(None, "--data-dir"),
) -> None:
    """Restaura un backup en el directorio de datos."""
    from marlonthebug.services.backup import BackupError, restore_backup

    paths = AppPaths.resolve(data_dir=data_dir)
    if not yes and not typer.confirm(f"¿Restaurar {archive} en {paths.root}?"):
        raise typer.Exit()
    try:
        stats = restore_backup(Path(archive), paths, force=force)
    except BackupError as exc:
        console.print(f"[red]No se pudo restaurar:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Restauración completada:[/green] {stats['files']} archivos en {paths.root}")
    console.print("[dim]Arranca el panel de nuevo para aplicar los datos restaurados.[/dim]")


@cli.command("console")
def console_tui() -> None:
    """Abre la consola TUI clásica (requiere el extra tui)."""
    try:
        from marlonthebug.cli.console import ConsoleApp
    except ImportError:
        console.print("[red]La TUI requiere instalar:[/red] uv sync --extra tui")
        raise typer.Exit(1) from None
    ConsoleApp().run()


@legacy_app.command("import")
def legacy_import(
    reports: str = typer.Option("reports", "--reports", "-r", help="Directorio con informes JSON 1.x"),
    data_dir: str | None = typer.Option(None, "--data-dir"),
) -> None:
    """Importa informes JSON antiguos al panel 2.0."""
    asyncio.run(_legacy_import(reports, data_dir))


async def _legacy_import(reports: str, data_dir: str | None) -> None:
    from marlonthebug.services.legacy import import_reports

    paths = _paths(data_dir)
    database, repository = await _repo(paths)
    try:
        stats = await import_reports(repository, Path(reports).expanduser())
        console.print(
            f"[green]Importación completada:[/green] "
            f"{stats['reports']} informes, {stats['workspaces']} proyectos, {stats['findings']} hallazgos"
        )
        if stats["skipped"]:
            console.print(f"[yellow]{stats['skipped']} archivos omitidos[/yellow]")
    finally:
        await database.close()


@cli.command("config")
def config_command(data_dir: str | None = typer.Option(None, "--data-dir")) -> None:
    """Muestra la configuración efectiva."""
    paths = _paths(data_dir)
    settings = load_settings(paths)
    console.print(f"Datos: {paths.root}")
    console.print(f"Config: {paths.config_file}")
    console.print(settings.model_dump(mode="json"))
