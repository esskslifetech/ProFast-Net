"""Every table ProFast renders, in one place so the CLI and the dashboard agree."""

from __future__ import annotations

from typing import Any

from rich import box
from rich.table import Table

from .models import Service

LEVEL_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
}

ACTION_STYLE = {
    "allow": "green",
    "tarpit": "yellow",
    "drop": "red",
}


def human_seconds(value: float | int) -> str:
    seconds = max(0, int(value))
    if seconds < 60:
        return f"{seconds}s"
    minutes, rest = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {rest:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


def risk_badge(level: str, score: int) -> str:
    return f"[{LEVEL_STYLE.get(level, 'dim')}]{level:<8} {score:>3}[/]"


def services_table(services: list[Service], title: str = "Listening services") -> Table:
    table = Table(title=title, box=box.SIMPLE_HEAD)
    table.add_column("Risk", justify="left", no_wrap=True)
    table.add_column("Port", justify="right")
    table.add_column("Proto")
    table.add_column("Binding", no_wrap=True)
    table.add_column("Process", no_wrap=True)
    table.add_column("PID", justify="right")
    table.add_column("Why", overflow="fold", min_width=28)

    for svc in services:
        table.add_row(
            risk_badge(svc.level, svc.risk),
            str(svc.port),
            svc.protocol.upper(),
            "all interfaces" if svc.public else svc.address,
            svc.process or "unknown",
            str(svc.pid or "-"),
            "; ".join(svc.reasons),
        )
    return table


def status_table(status: dict[str, Any]) -> Table:
    mirage = status.get("mirage", {})
    firewall = status.get("firewall", {})
    defense = status.get("defense", {})

    table = Table(box=box.SIMPLE, show_header=False, expand=False)
    table.add_column("field", style="dim")
    table.add_column("value")

    table.add_row("version", f"{status.get('version')} (protocol {status.get('protocol')})")
    table.add_row("platform", f"{status.get('os')}/{status.get('arch')}")
    table.add_row(
        "privileges",
        "[green]elevated[/]" if status.get("elevated") else "[yellow]user (limited)[/]",
    )
    table.add_row("kernel tier", str(status.get("kernel_tier", "")))
    table.add_row("uptime", human_seconds(status.get("uptime_s", 0)))
    table.add_row("", "")
    table.add_row("node", f"{mirage.get('node_name')} (id {mirage.get('node_id')})")
    table.add_row("virtual address", f"[bold cyan]{mirage.get('virtual_address')}[/]")
    table.add_row("hopping port", f"[bold cyan]{mirage.get('port')}[/]")
    table.add_row(
        "epoch",
        f"{mirage.get('epoch')} (every {mirage.get('epoch_seconds')}s, "
        f"next in {human_seconds(mirage.get('next_rotation_s', 0))})",
    )
    table.add_row("authorized peers", str(mirage.get("peers", 0)))
    table.add_row("replay cache", str(mirage.get("replay_cache", 0)))
    table.add_row("", "")
    table.add_row("firewall", f"{firewall.get('backend')} / block={firewall.get('block_inbound')}")
    table.add_row(
        "defense",
        f"{defense.get('active_bans', 0)} active ban(s), tarpit={defense.get('tarpit')}",
    )
    return table


def bans_table(bans: list[dict[str, Any]]) -> Table:
    table = Table(title="Active bans", box=box.SIMPLE_HEAD)
    table.add_column("Address")
    table.add_column("Reason")
    table.add_column("Level", justify="right")
    table.add_column("Hits", justify="right")
    table.add_column("Expires")

    for ban in bans:
        table.add_row(
            ban.get("ip", ""),
            ban.get("reason", ""),
            str(ban.get("level", 0)),
            str(ban.get("hits", 0)),
            str(ban.get("expires_at", ""))[:19],
        )
    return table


def events_table(events: list[dict[str, Any]], title: str = "Recent events") -> Table:
    table = Table(title=title, box=box.SIMPLE_HEAD, expand=True)
    table.add_column("When", style="dim", no_wrap=True)
    table.add_column("Area", style="cyan", no_wrap=True)
    table.add_column("Detail", overflow="fold")

    for event in events:
        table.add_row(
            str(event.get("at", ""))[11:19] or str(event.get("at", "")),
            str(event.get("kind", "")),
            str(event.get("detail", "")),
        )
    return table
