"""CLI command groups and entry points for MarlonTheBug."""

from pathlib import Path

import typer

from marlonthebug import __version__

cli = typer.Typer(
    name="marlonthebug",
    help="MarlonTheBug — Offensive Security Auditing & Exploitation Platform",
    no_args_is_help=True,
)

workspace_app = typer.Typer(help="Workspace management", no_args_is_help=True)
cli.add_typer(workspace_app, name="workspace")

recon_app = typer.Typer(help="Reconnaissance operations", no_args_is_help=True)
cli.add_typer(recon_app, name="recon")

audit_app = typer.Typer(help="Security auditing", no_args_is_help=True)
cli.add_typer(audit_app, name="audit")

exploit_app = typer.Typer(help="Exploitation", no_args_is_help=True)
cli.add_typer(exploit_app, name="exploit")

sessions_app = typer.Typer(help="Session management", no_args_is_help=True)
cli.add_typer(sessions_app, name="sessions")

report_app = typer.Typer(help="Reporting", no_args_is_help=True)
cli.add_typer(report_app, name="report")

listener_app = typer.Typer(help="Listener management", no_args_is_help=True)
cli.add_typer(listener_app, name="listeners")


@cli.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show version"),
) -> None:
    if version:
        typer.echo(f"MarlonTheBug v{__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


# ── Workspace commands ────────────────────────────────────

@workspace_app.command()
def create(
    name: str = typer.Option(..., "--name", "-n", help="Workspace name"),
    description: str = typer.Option("", "--description", "-d", help="Description"),
) -> None:
    """Create a new workspace."""
    from marlonthebug.core.workspace import WorkspaceManager

    mgr = WorkspaceManager(base_dir=Path("workspaces"))
    ws = mgr.create(name)
    typer.echo(f"[+] Created workspace: {ws.name}")


@workspace_app.command()
def switch(
    name: str = typer.Option(..., "--name", "-n", help="Workspace name"),
) -> None:
    """Switch to an existing workspace."""
    from marlonthebug.core.workspace import WorkspaceManager

    mgr = WorkspaceManager(base_dir=Path("workspaces"))
    ws = mgr.switch(name)
    typer.echo(f"[+] Switched to workspace: {ws.name}")
    typer.echo(f"    Targets: {len(ws.targets)}")


@workspace_app.command()
def add(
    domains: str = typer.Option("", "--domains", help="Comma-separated domains"),
    ips: str = typer.Option("", "--ips", help="Comma-separated IPs or CIDR ranges"),
) -> None:
    """Add targets to the current workspace."""
    from marlonthebug.core.workspace import WorkspaceManager

    mgr = WorkspaceManager(base_dir=Path("workspaces"))
    ws = mgr.current
    if not ws:
        typer.echo("[!] No active workspace. Create or switch to one first.")
        raise typer.Exit(1)

    domain_list = [d.strip() for d in domains.split(",") if d.strip()]
    ip_list = [i.strip() for i in ips.split(",") if i.strip()]

    mgr.add_targets(domains=domain_list, ips=ip_list)
    typer.echo(f"[+] Added targets to workspace: {ws.name}")
    typer.echo(f"    Domains: {domain_list}")
    typer.echo(f"    IPs/CIDRs: {ip_list}")


@workspace_app.command()
def info() -> None:
    """Show current workspace info."""
    from marlonthebug.core.workspace import WorkspaceManager

    mgr = WorkspaceManager(base_dir=Path("workspaces"))
    ws = mgr.current
    if not ws:
        typer.echo("[!] No active workspace.")
        raise typer.Exit(1)

    typer.echo(f"Workspace: {ws.name}")
    typer.echo(f"Created:   {ws.created_at}")
    typer.echo(f"Updated:   {ws.updated_at}")
    typer.echo(f"Targets:   {len(ws.targets)}")
    typer.echo(f"Scope:")
    typer.echo(f"  Domains:   {ws.scope.allowed_domains}")
    typer.echo(f"  IP Ranges: {ws.scope.allowed_ip_ranges}")
    typer.echo(f"  Excluded:  {ws.scope.excluded}")
    typer.echo(f"  Exploitation: {'ON' if ws.scope.allow_exploitation else 'OFF'}")


@workspace_app.command()
def list() -> None:
    """List all workspaces."""
    from marlonthebug.core.workspace import WorkspaceManager

    mgr = WorkspaceManager(base_dir=Path("workspaces"))
    workspaces = mgr.list_workspaces()
    if not workspaces:
        typer.echo("No workspaces found.")
        return
    for name in workspaces:
        marker = "*" if mgr.current and mgr.current.name == name else " "
        typer.echo(f"  [{marker}] {name}")


@workspace_app.command()
def delete(
    name: str = typer.Option(..., "--name", "-n", help="Workspace name"),
) -> None:
    """Delete a workspace."""
    from marlonthebug.core.workspace import WorkspaceManager

    mgr = WorkspaceManager(base_dir=Path("workspaces"))
    confirm = typer.confirm(f"Delete workspace '{name}'? This cannot be undone.")
    if confirm:
        mgr.delete(name)
        typer.echo(f"[+] Deleted workspace: {name}")


# ── Recon commands ────────────────────────────────────────

@recon_app.command()
def run(
    plugin: str = typer.Option("", "--plugin", "-p", help="Specific plugin to run"),
) -> None:
    """Run reconnaissance against workspace targets."""
    from collections import Counter

    from marlonthebug.core.engine import Engine
    from marlonthebug.core.workspace import WorkspaceManager

    mgr = WorkspaceManager(base_dir=Path("workspaces"))
    ws = mgr.current
    if not ws:
        typer.echo("[!] No active workspace.")
        raise typer.Exit(1)

    engine = Engine()
    typer.echo(f"[*] Running recon on workspace: {ws.name}")

    async def _run() -> None:
        await engine.start()
        targets = [ws.targets[t] for t in ws.targets]
        findings = await engine.run_recon(targets)
        await engine.stop()

        typer.echo(f"\n[+] Recon complete: {len(findings)} findings\n")

        by_severity: Counter[str] = Counter()
        by_plugin: Counter[str] = Counter()
        for f in findings:
            by_severity[f.severity.value] += 1
            by_plugin[f.plugin_name] += 1

        if by_severity:
            typer.echo("  Severity breakdown:")
            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev in by_severity:
                    badge = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}.get(sev, "")
                    typer.echo(f"    {badge} {sev.upper():8s} {by_severity[sev]}")

        typer.echo(f"\n  Plugin breakdown:")
        for name, count in by_plugin.most_common():
            typer.echo(f"    {name:25s} {count}")

        # Show top targets
        count = 0
        for host, t in ws.targets.items():
            if count >= 10:
                break
            techs = ", ".join(t.technologies[:5]) or "none"
            typer.echo(f"    {host:40s} type={t.type:<10s} tech={techs}")
            count += 1

        from pathlib import Path
        from marlonthebug.output.reports import ReportGenerator
        rgen = ReportGenerator(output_dir=Path("reports"))
        path = rgen.generate_json(findings, workspace_name=ws.name)
        typer.echo(f"\n[+] Report saved: {path}")

        ws.save()

    import asyncio
    asyncio.run(_run())


# ── Audit commands ────────────────────────────────────────

@audit_app.command()
def run(
    category: str = typer.Option("web", "--category", "-c", help="Audit category (web, api, auth)"),
) -> None:
    """Run security audit against workspace targets."""
    from collections import Counter
    from pathlib import Path

    from marlonthebug.core.engine import Engine
    from marlonthebug.core.workspace import WorkspaceManager

    mgr = WorkspaceManager(base_dir=Path("workspaces"))
    ws = mgr.current
    if not ws:
        typer.echo("[!] No active workspace.")
        raise typer.Exit(1)

    engine = Engine()
    typer.echo(f"[*] Running {category} audit on workspace: {ws.name}")

    async def _run() -> None:
        await engine.start()
        targets = [ws.targets[t] for t in ws.targets]
        findings = await engine.run_audit(targets, categories=[category])
        await engine.stop()

        typer.echo(f"\n[+] Audit complete: {len(findings)} findings\n")

        by_severity: Counter[str] = Counter()
        by_plugin: Counter[str] = Counter()
        for f in findings:
            by_severity[f.severity.value] += 1
            by_plugin[f.plugin_name] += 1

        if by_severity:
            typer.echo("  Severity breakdown:")
            badges = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}
            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev in by_severity:
                    typer.echo(f"    {badges.get(sev, '')} {sev.upper():8s} {by_severity[sev]}")

        typer.echo(f"\n  Plugin breakdown:")
        for name, count in by_plugin.most_common():
            typer.echo(f"    {name:28s} {count}")

        if findings:
            typer.echo(f"\n  Top findings:")
            sorted_findings = sorted(findings, key=lambda f: f.cvss_score, reverse=True)
            for f in sorted_findings[:10]:
                sev_badge = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}
                badge = sev_badge.get(f.severity.value, "")
                typer.echo(f"    {badge} [{f.severity.value.upper():8s}] {f.title}")
                if f.endpoint:
                    typer.echo(f"       Endpoint: {f.endpoint}")
                if f.evidence:
                    ev_short = str(f.evidence)[:120]
                    typer.echo(f"       Evidence: {ev_short}")

        from marlonthebug.output.reports import ReportGenerator
        rgen = ReportGenerator(output_dir=Path("reports"))
        path = rgen.generate_json(findings, workspace_name=ws.name)
        typer.echo(f"\n[+] Report saved: {path}")

    import asyncio
    asyncio.run(_run())


# ── Listener commands ─────────────────────────────────────

@listener_app.command()
def start(
    listener_type: str = typer.Option("tcp", "--type", "-t", help="Listener type: tcp, http, dns"),
    port: int = typer.Option(4444, "--port", "-p", help="Port to listen on"),
    host: str = typer.Option("0.0.0.0", "--host", "-H", help="Host to bind to"),
) -> None:
    """Start a listener for reverse connections."""
    typer.echo(f"[+] Starting {listener_type} listener on {host}:{port}")
    typer.echo("[*] Implement listener server logic here")


# ── Session commands ──────────────────────────────────────

@sessions_app.command()
def list() -> None:
    """List active exploitation sessions."""
    typer.echo("No active sessions.")


@sessions_app.command()
def interact(
    session_id: str = typer.Option(..., "--id", "-i", help="Session ID to interact with"),
) -> None:
    """Interact with an active session."""
    typer.echo(f"[*] Interacting with session: {session_id}")


# ── Report commands ───────────────────────────────────────

@report_app.command()
def generate(
    format: str = typer.Option("json", "--format", "-f", help="Output format: json, markdown, html, pdf"),
    output: str = typer.Option("", "--output", "-o", help="Output file path"),
) -> None:
    """Generate a report from workspace findings."""
    typer.echo(f"[*] Generating {format} report...")


@cli.command()
def console() -> None:
    """Launch the interactive TUI console."""
    from marlonthebug.cli.console import ConsoleApp

    ConsoleApp().run()
