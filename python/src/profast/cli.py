"""Command line interface: the human entry point to ProFast-Net."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from . import __version__, config, firewall, native, rpc
from .errors import CONSENT_REQUIRED, ELEVATION_REQUIRED, UNAVAILABLE, RpcError
from .models import Service
from .render import (
    bans_table,
    human_seconds,
    services_table,
    status_table,
)

console = Console()


# --------------------------------------------------------------------- backend


class EmbeddedBackend:
    """Runs the engine in-process when no daemon is available."""

    def __init__(self) -> None:
        from .engine import Engine

        cfg, _created = config.load()
        self._engine = Engine(cfg)
        self.info = {"version": __version__, "mode": "embedded"}

    def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        return self._engine.handle(method, dict(params or {}))

    def close(self) -> None:
        return None

    def __enter__(self) -> EmbeddedBackend:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def open_backend(args: argparse.Namespace) -> tuple[Any, str]:
    if args.embedded:
        return EmbeddedBackend(), "embedded"

    try:
        client = rpc.Client().connect()
        return client, "daemon"
    except RpcError as exc:
        if args.daemon:
            raise
        console.print(
            f"[dim]daemon not available ({exc.message}); running in embedded mode "
            "(state does not persist between commands)[/]"
        )
        return EmbeddedBackend(), "embedded"


def call(args: argparse.Namespace, method: str, params: dict[str, Any] | None = None) -> Any:
    backend, _mode = open_backend(args)
    try:
        return backend.call(method, params)
    finally:
        backend.close()


def emit(args: argparse.Namespace, payload: Any, renderer: Any = None) -> None:
    if args.json:
        console.print_json(json.dumps(payload, default=str))
        return
    if renderer is not None:
        console.print(renderer)
    elif isinstance(payload, str):
        console.print(payload)
    else:
        console.print_json(json.dumps(payload, default=str))


# --------------------------------------------------------------------- helpers


def require_elevation(action: str) -> bool:
    if firewall.elevated():
        return True
    console.print(
        Panel(
            f"[yellow]{action} needs administrator/root privileges.[/]\n"
            "Re-run this command from an elevated terminal.",
            title="elevation required",
            border_style="yellow",
        )
    )
    return False


def risky_to_services(rows: list[dict[str, Any]]) -> list[Service]:
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


def terminated_with_consent(args: argparse.Namespace, services: list[Service]) -> None:
    """Ask the user, obtain a bound token, then terminate. Never the other way."""
    targets = [svc for svc in services if svc.pid > 4]
    pids = sorted({svc.pid for svc in targets})
    if not pids:
        console.print("[yellow]nothing to terminate: no user-owned processes selected[/]")
        return

    names = ", ".join(sorted({svc.process or f"pid {svc.pid}" for svc in targets}))
    console.print(services_table(targets, title="About to terminate"))
    console.print(
        f"[bold]This will stop {len(pids)} process(es):[/] {names}\n"
        "[dim]Unsaved work in those applications will be lost.[/]"
    )

    if not Confirm.ask("Terminate these processes now?", default=False):
        console.print("[dim]cancelled, nothing was changed[/]")
        return

    token_targets = [f"pid:{pid}" for pid in pids]
    grant = call(
        args,
        "consent.request",
        {
            "action": "services.terminate",
            "summary": f"terminate {len(pids)} listening service(s)",
            "targets": token_targets,
        },
    )
    console.print(f"[dim]confirmation valid until {grant['expires'][11:19]} UTC[/]")

    result = call(
        args,
        "services.terminate",
        {"pids": pids, "token": grant["token"], "force": bool(getattr(args, "force", False))},
    )

    if result.get("terminated"):
        console.print(f"[green]terminated:[/] {', '.join(str(p) for p in result['terminated'])}")
    for failure in result.get("failed", []):
        console.print(f"[red]failed pid {failure['pid']}:[/] {failure['error']}")


# -------------------------------------------------------------------- commands


def cmd_status(args: argparse.Namespace) -> int:
    status = call(args, "core.status")
    if args.json:
        console.print_json(json.dumps(status, default=str))
        return 0

    mirage = status.get("mirage", {})
    header = Panel.fit(
        f"[bold]ProFast-Net[/] {status.get('version')}\n"
        f"[cyan]{mirage.get('virtual_address')}[/]:[cyan]{mirage.get('port')}[/] "
        f"rotates in {human_seconds(mirage.get('next_rotation_s', 0))}",
        border_style="cyan",
    )
    console.print(header)
    console.print(status_table(status))

    focus = status.get("focus")
    if focus:
        console.print(
            Panel(
                f"[green]{focus['target']}[/] until {str(focus['ends_at'])[11:19]} UTC\n"
                f"priority boosted={focus.get('boosted')} "
                f"eco-qos relaxed={focus.get('eco_qos_relaxed')}",
                title="focus",
                border_style="green",
            )
        )
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    from .tui import render_snapshot, run_dashboard

    if getattr(args, "snapshot", False):
        return render_snapshot(args, console)
    return run_dashboard(args, console)


def cmd_scan(args: argparse.Namespace) -> int:
    payload = call(
        args, "scan.services", {"min_risk": args.min_risk, "refresh": args.refresh}
    )
    services = risky_to_services(payload)

    if args.json:
        console.print_json(json.dumps(payload, default=str))
    elif not services:
        console.print("[green]no listening services matched the filter[/]")
    else:
        console.print(
            services_table(
                services if args.all else services[: args.limit],
                title=f"{len(services)} listening service(s)",
            )
        )

    if args.kill:
        candidates = [svc for svc in services if svc.risk >= 55]
        if not candidates:
            console.print("[green]nothing high-risk to terminate[/]")
            return 0
        terminated_with_consent(args, candidates)
    return 0


def cmd_focus(args: argparse.Namespace) -> int:
    if args.focus_action == "status":
        session = call(args, "focus.status")
        if not session:
            console.print("[dim]no focus session is running[/]")
        else:
            console.print_json(json.dumps(session, default=str))
        return 0

    if args.focus_action == "stop":
        session = call(args, "focus.stop")
        console.print(f"[green]focus stopped[/] (was {session['target']})")
        return 0

    if not args.target:
        console.print("[red]focus start needs an application path or --pid[/]")
        return 2

    pid = args.pid
    if pid == 0 and args.target and Path(args.target).suffix == ".exe":
        pid = find_pid_for_path(args.target)

    session = call(
        args,
        "focus.start",
        {"target": args.target, "pid": pid, "duration_s": int(args.minutes * 60)},
    )
    console.print(
        Panel(
            f"[green]focusing[/] {session['target']}\n"
            f"window: {human_seconds(args.minutes * 60)}\n"
            f"priority boosted: {session.get('boosted')}   "
            f"eco-qos relaxed: {session.get('eco_qos_relaxed')}",
            title="focus",
            border_style="green",
        )
    )
    for line in session.get("applied", []):
        console.print(f"  [green]+[/] {line}")
    for line in session.get("skipped", []):
        console.print(f"  [yellow]~[/] {line}")
    for line in session.get("errors", []):
        console.print(f"  [red]![/] {line}")
    return 0


def find_pid_for_path(path: str) -> int:
    try:
        import psutil
    except ImportError:
        return 0

    wanted = Path(path).name.lower()
    best = 0
    for proc in psutil.process_iter(["pid", "name"]):
        if (proc.info.get("name") or "").lower() == wanted:
            best = max(best, int(proc.info["pid"]))
    return best


def cmd_firewall(args: argparse.Namespace) -> int:
    if args.firewall_action == "status":
        payload = call(args, "firewall.status")
        if args.json:
            console.print_json(json.dumps(payload, default=str))
        elif not payload.get("rules"):
            console.print("[dim]no ProFast rules installed[/]")
        else:
            table = Table(title=f"firewall rules ({payload.get('backend')})", show_lines=False)
            table.add_column("rule")
            for rule in payload["rules"]:
                table.add_row(json.dumps(rule) if isinstance(rule, dict) else str(rule))
            console.print(table)
        return 0

    if args.firewall_action == "reset":
        if not require_elevation("Removing firewall rules"):
            return 3
        report = call(args, "firewall.reset")
        console.print(f"[green]reset:[/] {', '.join(report.get('applied', [])) or 'nothing to do'}")
        return 0

    params = {
        "block_inbound": args.block,
        "allow_ports": args.allow_port or [],
        "dry_run": args.firewall_action == "plan" or args.dry_run,
    }

    if args.firewall_action == "plan" or args.dry_run:
        plan = call(args, "firewall.plan", params)
        console.print(f"[bold]backend:[/] {plan['backend']}  [bold]rules:[/] {len(plan['rules'])}")
        for line in plan.get("preview", []) or plan.get("script", "").splitlines():
            console.print(f"  [cyan]{line}[/]")
        return 0

    if not require_elevation("Applying firewall rules"):
        return 3
    report = call(args, "firewall.apply", params)
    console.print(
        f"[green]applied[/] {len(report.get('applied', []))} rule(s) on {report.get('backend')}"
    )
    for line in report.get("errors", []):
        console.print(f"  [red]![/] {line}")
    return 0


def cmd_defend(args: argparse.Namespace) -> int:
    if args.defend_action == "status":
        emit(args, call(args, "defense.status"))
        return 0
    if args.defend_action == "bans":
        bans = call(args, "defense.bans")
        if args.json:
            console.print_json(json.dumps(bans, default=str))
        elif not bans:
            console.print("[green]no active bans[/]")
        else:
            console.print(bans_table(bans))
        return 0
    if args.defend_action == "ban":
        ban = call(args, "defense.ban", {"ip": args.ip, "reason": args.reason})
        console.print(f"[red]banned[/] {ban['ip']} until {ban['expires_at'][:19]} UTC")
        return 0
    if args.defend_action == "unban":
        result = call(args, "defense.unban", {"ip": args.ip})
        style = "green" if result.get("unbanned") else "yellow"
        console.print(f"[{style}]unbanned={result.get('unbanned')}[/] {args.ip}")
        return 0
    return 2


def cmd_mirage(args: argparse.Namespace) -> int:
    if args.mirage_action == "peers":
        peers = call(args, "mirage.peers")
        if args.json:
            console.print_json(json.dumps(peers, default=str))
        elif not peers:
            console.print("[dim]no authorized peers yet[/]")
        else:
            table = Table(title="authorized peers", box=None)
            for column in ("node", "source", "epoch", "virtual address", "last seen"):
                table.add_column(column)
            for peer in peers:
                table.add_row(
                    str(peer.get("node_id")),
                    str(peer.get("source")),
                    str(peer.get("epoch")),
                    str(peer.get("virtual_address")),
                    str(peer.get("last_seen"))[11:19],
                )
            console.print(table)
        return 0

    if args.mirage_action == "rotate":
        locator = call(args, "mirage.rotate")
        console.print(
            f"[green]locator refrehed[/] {locator['virtual_address']}:{locator['port']} "
            f"(epoch {locator['epoch']})"
        )
        return 0

    if args.mirage_action == "spa":
        token = call(args, "mirage.spa", {"node_id": args.node_id})
        if args.json:
            console.print_json(json.dumps(token, default=str))
            return 0
        console.print(
            Panel(
                f"token:  [bold]{token['token']}[/]\n"
                f"peer:   {token['virtual_address']}:{token['port']}\n"
                f"valid:  {human_seconds(token['expires_in_s'])} (epoch {token['epoch']})\n\n"
                "[dim]The peer sends this as a single UDP datagram, then connects to the "
                "derived port. The token is single-use.[/]",
                title="single packet authorization",
                border_style="cyan",
            )
        )
        return 0

    if args.mirage_action == "accept":
        result = call(args, "mirage.accept", {"token": args.token, "source": args.source})
        if args.json:
            emit(args, result)
            return 0
        console.print(f"[green]accepted[/] node {result['node_id']} at {result['virtual_address']}")
        return 0

    emit(args, call(args, "mirage.status"))
    return 0


def backend_tool() -> str:
    """The host program the active firewall backend needs.

    ``sys.platform`` is ``win32``, not ``windows``; keying a mapping on the
    human-readable backend name silently returns the fallback on Windows.
    """
    if sys.platform == "win32":
        return "powershell"
    if sys.platform == "darwin":
        return "pfctl"
    return "nft"


def cmd_doctor(args: argparse.Namespace) -> int:
    checks: list[tuple[str, bool, str]] = []

    checks.append(("python", sys.version_info >= (3, 10), sys.version.split()[0]))

    try:
        import psutil

        checks.append(("psutil", True, psutil.__version__))
    except ImportError:
        checks.append(("psutil", False, "not installed (pip install psutil)"))

    native_path = native.find_native()
    checks.append(
        (
            "native bridge",
            native_path is not None,
            str(native_path) if native_path else "not built (scripts/build.ps1)",
        )
    )

    elevated = firewall.elevated()
    checks.append(("elevation", elevated, "administrator" if elevated else "user"))

    tool = backend_tool()
    backend_present = shutil.which(tool)
    checks.append(
        ("firewall backend", bool(backend_present), backend_present or f"{tool} not found")
    )

    endpoint = rpc.read_endpoint()
    if endpoint is None:
        checks.append(("daemon", False, "not running"))
    else:
        # The endpoint file outlives a daemon that was killed outright, so
        # report the daemon only when the authenticated handshake succeeds.
        probe = rpc.Client()
        try:
            probe.connect()
            checks.append(("daemon", True, str(endpoint.get("address"))))
        except RpcError as exc:
            checks.append(("daemon", False, f"stale endpoint: {exc}"))
        finally:
            probe.close()

    cfg, created = config.load()
    secret_ok = True
    try:
        cfg.secret()
    except ValueError:
        secret_ok = False
    suffix = " (new)" if created else ""
    checks.append(("configuration", secret_ok, f"{config.config_path()}{suffix}"))

    table = Table(box=None, title="environment")
    table.add_column("check")
    table.add_column("state")
    table.add_column("detail", style="dim")
    for name, ok, detail in checks:
        table.add_row(name, "[green]ok[/]" if ok else "[red]missing[/]", detail)
    console.print(table)
    return 0 if all(ok for _, ok, _ in checks) else 1


def cmd_config(args: argparse.Namespace) -> int:
    if args.config_action == "path":
        console.print(str(config.config_path()))
        return 0
    if args.config_action == "init":
        cfg = config.defaults()
        path = config.save(cfg)
        console.print(f"[green]wrote[/] {path}")
        return 0

    cfg, created = config.load()
    payload = cfg.to_dict()
    if args.json:
        console.print_json(json.dumps(payload, default=str))
        return 0
    if created:
        console.print(f"[dim]created {config.config_path()}[/]")
    payload["mirage"]["secret_hex"] = "***redacted***"
    console.print_json(json.dumps(payload))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .daemon import main as daemon_main

    argv: list[str] = []
    if args.no_firewall:
        argv.append("--no-firewall")
    return daemon_main(argv)


def cmd_gui(args: argparse.Namespace) -> int:
    try:
        from .gui.app import run
    except ImportError as exc:
        console.print(
            Panel(
                f"[red]The GUI needs PySide6.[/]\n\n"
                f"Install it with:\n  [bold]pip install 'profast-net[gui]'[/]\n\n"
                f"[dim]{exc}[/]",
                title="GUI unavailable",
                border_style="red",
            )
        )
        return 1
    return run(force_embedded=bool(args.embedded))


# ---------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="profast",
        description="ProFast-Net: concentrate the link, rotate the identity, defend the host.",
    )
    parser.add_argument("--json", action="store_true", help="machine readable output")
    parser.add_argument("--daemon", action="store_true", help="require a running daemon")
    parser.add_argument("--embedded", action="store_true", help="run the engine in-process")
    parser.add_argument("--force", action="store_true", help="force-kill where supported")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="one screen overview").set_defaults(func=cmd_status)

    watch_parser = sub.add_parser("watch", help="live dashboard")
    watch_parser.add_argument(
        "--interval", type=float, default=1.5, help="refresh period in seconds"
    )
    watch_parser.add_argument("--snapshot", action="store_true", help="print one frame and exit")
    watch_parser.add_argument(
        "--no-services", action="store_true", help="skip the listening-service scan"
    )
    watch_parser.set_defaults(func=cmd_watch)

    sub.add_parser("doctor", help="check the local environment").set_defaults(func=cmd_doctor)

    scan_parser = sub.add_parser("scan", help="inventory listening services and score risk")
    scan_parser.add_argument("--all", action="store_true", help="do not truncate the table")
    scan_parser.add_argument("--limit", type=int, default=25)
    scan_parser.add_argument("--min-risk", type=int, default=0)
    scan_parser.add_argument("--refresh", action="store_true", help="bypass the cache")
    scan_parser.add_argument(
        "--kill", action="store_true", help="offer to terminate high-risk services (asks first)"
    )
    scan_parser.set_defaults(func=cmd_scan)

    focus_parser = sub.add_parser("focus", help="concentrate the link on one task")
    focus_sub = focus_parser.add_subparsers(dest="focus_action", required=True)
    focus_start = focus_sub.add_parser("start", help="start a focus window")
    focus_start.add_argument("target", nargs="?", default="", help="application path")
    focus_start.add_argument("--pid", type=int, default=0)
    focus_start.add_argument("--minutes", type=float, default=60.0)
    focus_sub.add_parser("stop", help="stop and revert")
    focus_sub.add_parser("status", help="show the active window")
    focus_parser.set_defaults(func=cmd_focus, target="", pid=0, minutes=60.0)

    firewall_parser = sub.add_parser("firewall", help="inspect or change the inbound posture")
    firewall_sub = firewall_parser.add_subparsers(dest="firewall_action", required=True)
    for name, help_text in (
        ("plan", "print the rules without touching the host"),
        ("apply", "install the rules"),
        ("reset", "remove every ProFast rule"),
        ("status", "show installed rules"),
    ):
        child = firewall_sub.add_parser(name, help=help_text)
        child.add_argument("--block", action="store_true", help="default-deny inbound")
        child.add_argument("--allow-port", type=int, action="append", default=[])
        child.add_argument("--dry-run", action="store_true")
    firewall_parser.set_defaults(func=cmd_firewall, block=False, allow_port=[], dry_run=False)

    defend_parser = sub.add_parser("defend", help="ban list and manual actions")
    defend_sub = defend_parser.add_subparsers(dest="defend_action", required=True)
    defend_sub.add_parser("status")
    defend_sub.add_parser("bans")
    ban_parser = defend_sub.add_parser("ban")
    ban_parser.add_argument("ip")
    ban_parser.add_argument("--reason", default="manual ban")
    unban_parser = defend_sub.add_parser("unban")
    unban_parser.add_argument("ip")
    defend_parser.set_defaults(func=cmd_defend, ip="", reason="manual ban")

    mirage_parser = sub.add_parser("mirage", help="rotating identity controls")
    mirage_sub = mirage_parser.add_subparsers(dest="mirage_action", required=True)
    mirage_sub.add_parser("status")
    mirage_sub.add_parser("rotate")
    mirage_sub.add_parser("peers")
    spa_parser = mirage_sub.add_parser("spa", help="mint a single packet authorization token")
    spa_parser.add_argument("--node-id", type=int, default=0)
    accept_parser = mirage_sub.add_parser("accept", help="validate a received token")
    accept_parser.add_argument("token")
    accept_parser.add_argument("--source", default="127.0.0.1")
    mirage_parser.set_defaults(func=cmd_mirage, node_id=0, token="", source="127.0.0.1")

    config_parser = sub.add_parser("config", help="configuration file")
    config_sub = config_parser.add_subparsers(dest="config_action", required=True)
    config_sub.add_parser("show")
    config_sub.add_parser("path")
    config_sub.add_parser("init")
    config_parser.set_defaults(func=cmd_config)

    serve_parser = sub.add_parser("serve", help="run the reference daemon (Python)")
    serve_parser.add_argument("--no-firewall", action="store_true")
    serve_parser.set_defaults(func=cmd_serve)

    sub.add_parser("gui", help="open the desktop dashboard").set_defaults(func=cmd_gui)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return int(args.func(args))
    except RpcError as exc:
        if exc.code == CONSENT_REQUIRED:
            console.print(f"[yellow]confirmation required:[/] {exc.message}")
        elif exc.code == ELEVATION_REQUIRED:
            console.print(f"[yellow]elevation required:[/] {exc.message}")
        elif exc.code == UNAVAILABLE:
            console.print(f"[red]unavailable:[/] {exc.message}")
        else:
            console.print(f"[red]error:[/] {exc.message}")
        return 1
    except KeyboardInterrupt:
        console.print("\n[dim]interrupted[/]")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
