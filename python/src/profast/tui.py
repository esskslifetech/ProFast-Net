"""``profast watch``: a full-screen dashboard for a terminal.

The dashboard is deliberately read-only. Everything it shows comes from the
same JSON-RPC surface the GUI uses, so a dashboard can never do something the
GUI cannot, and neither can do anything the daemon has not agreed to.
"""

from __future__ import annotations

import sys
import time
from typing import Any

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import Service
from .render import bans_table, events_table, human_seconds, services_table

REFRESH_SECONDS = 1.5
SCAN_EVERY_SECONDS = 20.0


# --------------------------------------------------------------------- keyboard


class Keyboard:
    """Non-blocking single-key reader; degraded gracefully when not a tty."""

    def __init__(self) -> None:
        self.enabled = False
        self._fd: int | None = None
        self._saved: Any = None
        try:
            if sys.platform == "win32":
                import msvcrt  # noqa: F401

                self.enabled = bool(sys.stdin and sys.stdin.isatty())
            else:
                import termios
                import tty

                self._fd = sys.stdin.fileno()
                if not sys.stdin.isatty():
                    return
                self._saved = termios.tcgetattr(self._fd)
                tty.setcbreak(self._fd)
                self.enabled = True
        except Exception:  # noqa: BLE001 - a terminal we cannot drive is not fatal
            self.enabled = False

    def poll(self) -> str:
        if not self.enabled:
            return ""
        try:
            if sys.platform == "win32":
                import msvcrt

                if not msvcrt.kbhit():
                    return ""
                return msvcrt.getwch()
            import select

            ready, _, _ = select.select([sys.stdin], [], [], 0)
            if not ready:
                return ""
            return sys.stdin.read(1)
        except Exception:  # noqa: BLE001
            return ""

    def restore(self) -> None:
        if self._saved is None or self._fd is None:
            return
        try:
            import termios

            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._saved)
        except Exception:  # noqa: BLE001
            pass


# -------------------------------------------------------------------- dashboard


class Dashboard:
    """Holds the last known state and paints it."""

    def __init__(self, backend: Any, mode: str, show_services: bool = True) -> None:
        self.backend = backend
        self.mode = mode
        self.show_services = show_services
        self.status: dict[str, Any] = {}
        self.services: list[Service] = []
        self.events: list[dict[str, Any]] = []
        self.bans: list[dict[str, Any]] = []
        self.error = ""
        self.paused = False
        self._next_scan = 0.0

    # --------------------------------------------------------------- data pull
    def refresh(self, force_scan: bool = False) -> None:
        now = time.monotonic()
        want_scan = self.show_services and (force_scan or now >= self._next_scan)

        try:
            self.status = self.backend.call("core.status") or {}
            self.events = self.backend.call("core.events", {"limit": 40}) or []
            self.bans = self.backend.call("defense.bans") or []
            if want_scan:
                rows = self.backend.call("scan.services", {"min_risk": 0, "refresh": force_scan})
                self.services = _to_services(rows or [])
                self._next_scan = now + SCAN_EVERY_SECONDS
            self.error = ""
        except Exception as exc:  # noqa: BLE001 - the dashboards must never crash
            self.error = f"{type(exc).__name__}: {exc}"

    # ------------------------------------------------------------------ painting
    def render(self) -> Layout:
        root = Layout()
        root.split_column(
            Layout(self._header(), name="header", size=3),
            Layout(name="body"),
            Layout(self._footer(), name="footer", size=3),
        )
        root["body"].split_row(
            Layout(name="left", ratio=2, minimum_size=34),
            Layout(name="right", ratio=3, minimum_size=40),
        )
        root["left"].split_column(
            Layout(self._identity(), name="identity"),
            Layout(self._defense(), name="defense"),
        )
        root["right"].split_column(
            Layout(self._services() if self.show_services else self._bans(), name="services"),
            Layout(events_table(self.events, title="events"), name="events"),
        )
        return root

    def _header(self) -> Panel:
        mirage = self.status.get("mirage", {})
        address = mirage.get("virtual_address", "-")
        port = mirage.get("port", "-")
        rotating = human_seconds(mirage.get("next_rotation_s", 0))
        focus = self.status.get("focus")
        focus_text = f"[green]focus {focus['target']}[/]" if focus else "[dim]no focus window[/]"

        title = Text.assemble(
            ("ProFast-Net ", "bold"),
            (str(self.status.get("version", "?")), "cyan"),
            ("  ", ""),
            (f"{address}:{port}", "bold cyan"),
            (f"  rotates in {rotating}", "dim"),
            ("  ·  ", "dim"),
            (self.mode, "magenta"),
            ("  ·  ", "dim"),
        )
        title.append_text(Text.from_markup(focus_text))
        if self.paused:
            title.append_text(Text("  PAUSED", style="bold yellow"))
        return Panel(title, border_style="cyan", height=3)

    def _identity(self) -> Panel:
        mirage = self.status.get("mirage", {})
        table = Table(box=None, show_header=False, padding=(0, 1))
        table.add_column("field", style="dim", no_wrap=True)
        table.add_column("value")

        table.add_row("node", f"{mirage.get('node_name', '?')} (id {mirage.get('node_id', '?')})")
        table.add_row("epoch", str(mirage.get("epoch", "?")))
        table.add_row("window", f"{mirage.get('epoch_seconds', '?')}s")
        table.add_row("peers", str(mirage.get("peers", 0)))
        table.add_row("spa replay", str(mirage.get("replay_cache", 0)))
        table.add_row("kernel tier", str(self.status.get("kernel_tier", "")))
        table.add_row(
            "privileges",
            "[green]elevated[/]" if self.status.get("elevated") else "[yellow]user[/]",
        )
        return Panel(table, title="identity", border_style="blue", height=11)

    def _defense(self) -> Panel:
        defense = self.status.get("defense", {})
        firewall_state = self.status.get("firewall", {})
        table = Table(box=None, show_header=False, padding=(0, 1))
        table.add_column("field", style="dim", no_wrap=True)
        table.add_column("value")

        table.add_row("bans", str(defense.get("active_bans", 0)))
        table.add_row("tracked", str(defense.get("tracked", 0)))
        table.add_row("tarpit", "on" if defense.get("tarpit") else "off")
        table.add_row("auto-ban", "on" if defense.get("auto_ban") else "off")
        table.add_row("backend", str(firewall_state.get("backend", "?")))
        table.add_row(
            "inbound",
            "[red]default-deny[/]" if firewall_state.get("block_inbound") else "permissive",
        )
        if self.bans:
            latest = self.bans[0]
            table.add_row("latest", f"{latest.get('ip', '')} {latest.get('reason', '')}")
        return Panel(table, title="defence", border_style="red", height=11)

    def _services(self) -> Any:
        if self.error:
            return Panel(self.error, title="services", border_style="yellow")
        if not self.services:
            return Panel(
                "[dim]no listening services in scope[/]", title="services", border_style="dim"
            )
        ordered = sorted(self.services, key=lambda svc: -svc.risk)[:14]
        return services_table(ordered, title=f"listening services ({len(self.services)})")

    def _bans(self) -> Any:
        if not self.bans:
            return Panel("[dim]no active bans[/]", title="bans", border_style="dim")
        return bans_table(self.bans[:12])

    def _footer(self) -> Panel:
        if self.error:
            body = Text(self.error, style="red")
        else:
            body = Text.from_markup(
                "[dim]q quit   space pause   r rescan   e events[/]"
                f"   [dim]uptime {human_seconds(self.status.get('uptime_s', 0))}[/]"
            )
        return Panel(body, border_style="red" if self.error else "dim", height=3)


def _to_services(rows: list[dict[str, Any]]) -> list[Service]:
    return [
        Service(
            pid=int(row.get("pid", 0)),
            process=str(row.get("process", "")),
            port=int(row.get("port", 0)),
            protocol=str(row.get("protocol", "")),
            address=str(row.get("address", "")),
            path=str(row.get("path", "")),
            public=bool(row.get("public")),
            system=bool(row.get("system")),
            risk=int(row.get("risk", 0)),
            level=str(row.get("level", "low")),
            reasons=list(row.get("reasons", [])),
        )
        for row in rows
    ]


# ------------------------------------------------------------------------- entry


def run_dashboard(args: Any, console: Console | None = None) -> int:
    """Run until the operator quits. Returns a process exit code."""
    from .cli import open_backend  # imported late to avoid a circular import

    console = console or Console()
    interval = float(getattr(args, "interval", REFRESH_SECONDS) or REFRESH_SECONDS)
    show_services = not bool(getattr(args, "no_services", False))

    backend, mode = open_backend(args)
    dashboard = Dashboard(backend, mode, show_services=show_services)
    keyboard = Keyboard()

    try:
        dashboard.refresh(force_scan=True)
        with Live(
            dashboard.render(),
            console=console,
            screen=True,
            auto_refresh=False,
            transient=False,
        ) as live:
            last = 0.0
            while True:
                key = keyboard.poll().lower()

                if key in ("q", "\x03", "\x1b"):
                    break
                if key == " ":
                    dashboard.paused = not dashboard.paused
                if key == "r":
                    dashboard.refresh(force_scan=True)
                if key == "e":
                    dashboard.show_services = not dashboard.show_services

                now = time.monotonic()
                if not dashboard.paused and (now - last) >= interval:
                    dashboard.refresh()
                    last = now

                live.update(dashboard.render(), refresh=True)
                time.sleep(0.15)
    except KeyboardInterrupt:
        return 0
    finally:
        keyboard.restore()
        backend.close()

    return 0


def render_snapshot(args: Any, console: Console | None = None) -> int:
    """One frame, no alternate screen. Handy for scripts and for CI smoke tests."""
    from .cli import open_backend

    console = console or Console()
    show_services = not bool(getattr(args, "no_services", False))
    backend, mode = open_backend(args)
    try:
        dashboard = Dashboard(backend, mode, show_services=show_services)
        dashboard.refresh(force_scan=True)
        console.print(dashboard._header())
        console.print(
            Group(
                dashboard._identity(),
                dashboard._defense(),
                dashboard._services() if show_services else dashboard._bans(),
                events_table(dashboard.events, title="events"),
            )
        )
    finally:
        backend.close()
    return 0
