"""Interactive Textual TUI console for MarlonTheBug."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import ClassVar

from rich.console import RenderableType
from rich.markdown import Markdown
from rich.table import Table
from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.reactive import reactive
from textual.widgets import Button, Header, Input, Label, Static

logger = logging.getLogger("marlonthebug.console")

BANNER = r"""
   __  ___          __             _______  __    ___           __
  /  |/  /__ _____ / /__  ___    /_  __/ / / /   / _ )__ _____/ /
 / /|_/ / _ `/ __/ / _ \/ _ \    / / / /_/ /   / _  / // / _ / _ \
/_/  /_/\_,_/_/ /_/\___/_//_/   /_/  \__,_/   /____/\_,_/\_,_/_.__/
"""


class OutputPanel(VerticalScroll):
    DEFAULT_CSS = """
    OutputPanel {
        border: solid $primary;
        height: 1fr;
    }
    """

    def clear(self) -> None:
        self.remove_children()

    def write(self, content: RenderableType) -> None:
        self.mount(Static(content))
        self.scroll_end(animate=False)


class InputBar(Horizontal):
    DEFAULT_CSS = """
    InputBar {
        height: 3;
        dock: bottom;
    }
    InputBar > Input {
        width: 1fr;
    }
    """

    def compose(self) -> ComposeResult:
        yield Input(placeholder="marlonthebug> ", id="command-input")
        yield Button("Send", id="send-button")


class ConsoleApp(App):
    TITLE = "MarlonTheBug"
    SUB_TITLE = "Offensive Security Auditing & Exploitation Platform"
    BINDINGS: ClassVar[list] = [
        ("ctrl+c", "quit", "Quit"),
        ("ctrl+l", "clear", "Clear"),
        ("ctrl+h", "help", "Help"),
        ("tab", "autocomplete", "Autocomplete"),
    ]

    CSS = """
    Screen {
        layout: vertical;
    }

    #output-panel {
        height: 1fr;
        overflow-y: auto;
    }

    #status-bar {
        height: 1;
        dock: bottom;
        background: $primary;
        color: $text;
        padding: 0 1;
    }

    ListView {
        height: auto;
        max-height: 20;
    }

    Button {
        min-width: 8;
    }

    Label {
        padding: 1 2;
    }
    """

    context: reactive[str] = reactive("")
    workspace_name: reactive[str] = reactive("")

    def __init__(self) -> None:
        super().__init__()
        self._command_buffer: list[str] = []
        self._history_index = -1
        self._in_module_context = False

    def compose(self) -> ComposeResult:
        yield Header()
        yield OutputPanel(id="output-panel")
        yield InputBar()
        yield Label("No workspace loaded.", id="status-bar")

    def on_mount(self) -> None:
        output = self.query_one("#output-panel", OutputPanel)
        output.write(Markdown(f"```\n{BANNER}\n```"))
        output.write(Text("v1.0.0 — Type 'help' for available commands.\n", style="dim"))
        output.write(Text(""))

        try:
            from marlonthebug.core.workspace import WorkspaceManager

            mgr = WorkspaceManager(base_dir=Path("workspaces"))
            ws = mgr.current
            if ws:
                self.workspace_name = ws.name
                self.context = ws.name
                self._update_status()
        except Exception:
            pass

    def _update_status(self) -> None:
        status = self.query_one("#status-bar", Label)
        text = f"Workspace: {self.workspace_name or 'none'}"
        if self.context:
            text += f" | Context: {self.context}"
        status.update(text)

    @on(Button.Pressed, "#send-button")
    async def handle_send(self) -> None:
        await self._process_input()

    @on(Input.Submitted, "#command-input")
    async def handle_submit(self) -> None:
        await self._process_input()

    async def _process_input(self) -> None:
        cmd_input = self.query_one("#command-input", Input)
        command = cmd_input.value.strip()
        if not command:
            return

        cmd_input.value = ""
        self._command_buffer.append(command)
        self._history_index = len(self._command_buffer)

        output = self.query_one("#output-panel", OutputPanel)
        output.write(Text(f"\nmarlonthebug> {command}", style="bold green"))
        await self._execute(command, output)

    async def _execute(self, command: str, output: OutputPanel) -> None:
        parts = command.lower().split()
        if not parts:
            return

        cmd = parts[0]
        args = parts[1:]

        if cmd == "help":
            await self._cmd_help(output)
        elif cmd == "clear":
            output.clear()
        elif cmd == "workspace":
            await self._cmd_workspace(args, output)
        elif cmd == "use":
            await self._cmd_use(args, output)
        elif cmd == "info":
            await self._cmd_info(output)
        elif cmd == "set":
            await self._cmd_set(args, output)
        elif cmd == "run":
            await self._cmd_run(output)
        elif cmd == "sessions":
            await self._cmd_sessions(output)
        elif cmd == "listeners":
            await self._cmd_listeners(output)
        elif cmd == "report":
            await self._cmd_report(args, output)
        elif cmd == "back":
            await self._cmd_back(output)
        elif cmd == "exit" or cmd == "quit":
            self.exit()
        else:
            output.write(Text(f"[!] Unknown command: {cmd} (type 'help' for commands)", style="yellow"))

    async def _cmd_help(self, output: OutputPanel) -> None:
        help_table = Table(title="MarlonTheBug Commands")
        help_table.add_column("Command", style="cyan")
        help_table.add_column("Description")

        commands = [
            ("workspace create <name>", "Create a new workspace"),
            ("workspace switch <name>", "Switch to workspace"),
            ("workspace add <targets>", "Add domains/IPs to scope"),
            ("workspace info", "Show current workspace info"),
            ("workspace list", "List all workspaces"),
            ("workspace delete <name>", "Delete a workspace"),
            ("use <category>/<module>", "Load a plugin module"),
            ("use exploit/<module>", "Load an exploit module"),
            ("info", "Show current module info"),
            ("set <option> <value>", "Set module option"),
            ("run", "Execute current module"),
            ("listeners start", "Start a listener"),
            ("listeners stop", "Stop a listener"),
            ("sessions", "List active sessions"),
            ("sessions -i <id>", "Interact with session"),
            ("report generate", "Generate audit report"),
            ("back", "Return from module context"),
            ("clear", "Clear console"),
            ("exit / quit", "Exit MarlonTheBug"),
        ]
        for cmd, desc in commands:
            help_table.add_row(cmd, desc)
        output.write(help_table)

    async def _cmd_workspace(self, args: list[str], output: OutputPanel) -> None:
        if not args:
            output.write(Text("[!] Usage: workspace <create|switch|add|info|list|delete> [args]", style="yellow"))
            return

        sub = args[0]
        try:
            from marlonthebug.core.workspace import WorkspaceManager

            mgr = WorkspaceManager(base_dir=Path("workspaces"))

            if sub == "create" and len(args) > 1:
                ws = mgr.create(args[1])
                self.workspace_name = ws.name
                self.context = ws.name
                self._update_status()
                output.write(Text(f"[+] Created workspace: {ws.name}", style="green"))
            elif sub == "switch" and len(args) > 1:
                ws = mgr.switch(args[1])
                self.workspace_name = ws.name
                self.context = ws.name
                self._update_status()
                output.write(Text(f"[+] Switched to workspace: {ws.name} ({len(ws.targets)} targets)", style="green"))
            elif sub == "add":
                pass
            elif sub == "info":
                ws = mgr.current
                if ws:
                    info_table = Table(title=f"Workspace: {ws.name}")
                    info_table.add_column("Property")
                    info_table.add_column("Value")
                    info_table.add_row("Targets", str(len(ws.targets)))
                    info_table.add_row("Domains", ", ".join(ws.scope.allowed_domains) or "none")
                    info_table.add_row("IP Ranges", ", ".join(ws.scope.allowed_ip_ranges) or "none")
                    info_table.add_row("Exploitation", "ON" if ws.scope.allow_exploitation else "OFF")
                    output.write(info_table)
                else:
                    output.write(Text("[!] No active workspace.", style="yellow"))
            elif sub == "list":
                workspaces = mgr.list_workspaces()
                if workspaces:
                    for name in workspaces:
                        marker = " *" if mgr.current and mgr.current.name == name else "  "
                        output.write(Text(f"{marker} {name}"))
                else:
                    output.write(Text("No workspaces found.", style="dim"))
            elif sub == "delete" and len(args) > 1:
                mgr.delete(args[1])
                output.write(Text(f"[+] Deleted workspace: {args[1]}", style="green"))
            else:
                output.write(Text("[!] Unknown workspace subcommand.", style="yellow"))
        except Exception as e:
            output.write(Text(f"[!] Error: {e}", style="red"))

    async def _cmd_use(self, args: list[str], output: OutputPanel) -> None:
        if not args:
            output.write(Text("[!] Usage: use <category>/<module>", style="yellow"))
            return
        module_name = args[0]
        self.context = module_name
        self._in_module_context = True
        self._update_status()
        output.write(Text(f"[*] Loaded module: {module_name}", style="cyan"))
        output.write(Text("[*] Type 'info' for module details, 'run' to execute, 'back' to return.", style="dim"))

    async def _cmd_info(self, output: OutputPanel) -> None:
        if not self._in_module_context:
            output.write(Text("[!] No module loaded. Use: use <category>/<module>", style="yellow"))
            return
        output.write(Text(f"[*] Module: {self.context}\n[*] No additional info available.", style="cyan"))

    async def _cmd_set(self, args: list[str], output: OutputPanel) -> None:
        if len(args) < 2:
            output.write(Text("[!] Usage: set <option> <value>", style="yellow"))
            return
        output.write(Text(f"[*] SET {args[0]} => {args[1]}", style="cyan"))

    async def _cmd_run(self, output: OutputPanel) -> None:
        if not self._in_module_context:
            output.write(Text("[!] No module loaded. Use: use <category>/<module>", style="yellow"))
            return
        output.write(Text(f"[*] Running {self.context}...", style="yellow"))
        output.write(Text("[+] Module execution would start here.", style="dim"))

    async def _cmd_back(self, output: OutputPanel) -> None:
        self._in_module_context = False
        self.context = self.workspace_name
        self._update_status()
        output.write(Text("[*] Returned to workspace context.", style="dim"))

    async def _cmd_sessions(self, output: OutputPanel) -> None:
        table = Table(title="Active Sessions")
        table.add_column("ID")
        table.add_column("Target")
        table.add_column("Type")
        table.add_column("User")
        table.add_column("Hostname")
        table.add_row("-", "-", "-", "-", "-")
        output.write(table)

    async def _cmd_listeners(self, output: OutputPanel) -> None:
        table = Table(title="Active Listeners")
        table.add_column("ID")
        table.add_column("Type")
        table.add_column("Host")
        table.add_column("Port")
        table.add_column("Status")
        table.add_row("-", "-", "-", "-", "-")
        output.write(table)

    async def _cmd_report(self, args: list[str], output: OutputPanel) -> None:
        output.write(Text("[*] Report generation would be triggered here.", style="dim"))

    def action_clear(self) -> None:
        self.query_one("#output-panel", OutputPanel).clear()

    def action_help(self) -> None:
        self.query_one("#command-input", Input).value = "help"
