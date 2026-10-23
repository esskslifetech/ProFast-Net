"""Host firewall rendering and application.

On Windows the rules are installed through the Windows Firewall cmdlets, which
sit directly on top of the Windows Filtering Platform. Linux uses nftables and
macOS uses pf anchors. The kernel callout driver in ``native/windows/driver``
can take over later without changing this rule model.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .models import Report

PREFIX = "ProFast/"
PF_ANCHOR = "com.profast"
NFT_TABLE = "profast"

MIRAGE_NAME = PREFIX + "Mirage"
SPA_NAME = PREFIX + "SPA"
BLOCK_NAME = PREFIX + "BlockInbound"


@dataclass
class Rule:
    name: str
    action: str  # allow | block
    protocol: str  # tcp | udp | any
    ports: list[int] = field(default_factory=list)
    remote: str = "any"

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "direction": "in",
            "action": self.action,
            "protocol": self.protocol,
            "ports": self.ports,
            "remote": self.remote,
        }


@dataclass
class Plan:
    backend: str
    rules: list[Rule]
    preview: list[str] = field(default_factory=list)
    payload: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "backend": self.backend,
            "rules": [rule.to_dict() for rule in self.rules],
            "preview": self.preview,
            "script": self.payload,
        }


def backend_name() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "pf"
    return "nft"


def elevated() -> bool:
    if sys.platform == "win32":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False


def build_plan(
    block_inbound: bool,
    allow_lan: bool,
    allow_ports: list[int],
    mirage_port: int = 0,
    spa_port: int = 0,
) -> Plan:
    if sys.platform == "win32":
        return _plan_windows(block_inbound, allow_lan, allow_ports, mirage_port, spa_port)
    if sys.platform == "darwin":
        return _plan_darwin(block_inbound, allow_lan, allow_ports, mirage_port, spa_port)
    return _plan_linux(block_inbound, allow_lan, allow_ports, mirage_port, spa_port)


def _plan_windows(block, allow_lan, allow_ports, mirage_port, spa_port) -> Plan:
    rules: list[Rule] = []
    preview = ["Remove-NetFirewallRule -DisplayName 'ProFast/*'"]

    if mirage_port:
        remote = "LocalSubnet" if allow_lan else "any"
        rules.append(Rule(MIRAGE_NAME, "allow", "tcp", [mirage_port], remote))
        rules.append(Rule(SPA_NAME, "allow", "udp", [spa_port or mirage_port], remote))
        preview.append(
            f"New-NetFirewallRule '{MIRAGE_NAME}' allow tcp/{mirage_port} from {remote}"
        )
        preview.append(f"New-NetFirewallRule '{SPA_NAME}' allow udp/{spa_port or mirage_port}")

    for port in allow_ports:
        name = f"{PREFIX}Port-{port}"
        rules.append(Rule(name, "allow", "tcp", [port], "any"))
        preview.append(f"New-NetFirewallRule '{name}' allow tcp/{port}")

    if block:
        rules.append(Rule(BLOCK_NAME, "block", "any", [], "any"))
        preview.append(f"New-NetFirewallRule '{BLOCK_NAME}' block inbound any")

    return Plan("windows", rules, preview)


def _plan_linux(block, allow_lan, allow_ports, mirage_port, spa_port) -> Plan:
    rules = [Rule("established", "allow", "any"), Rule("loopback", "allow", "any")]
    lines = [
        f"add table inet {NFT_TABLE}",
        f"flush table inet {NFT_TABLE}",
        f"add chain inet {NFT_TABLE} input {{ type filter hook input "
        f"priority filter; policy accept; }}",
        f"add rule inet {NFT_TABLE} input iif lo accept",
        f"add rule inet {NFT_TABLE} input ct state established,related accept",
    ]

    if mirage_port:
        rules.append(Rule(MIRAGE_NAME, "allow", "tcp", [mirage_port]))
        lines.append(f"add rule inet {NFT_TABLE} input tcp dport {mirage_port} accept")
        lines.append(f"add rule inet {NFT_TABLE} input udp dport {spa_port or mirage_port} accept")

    for port in allow_ports:
        rules.append(Rule(f"{PREFIX}Port-{port}", "allow", "tcp", [port]))
        lines.append(f"add rule inet {NFT_TABLE} input tcp dport {port} accept")

    if block:
        rules.append(Rule(BLOCK_NAME, "block", "any"))
        lines.append(f"add rule inet {NFT_TABLE} input udp dport {{ 67, 68, 546, 547 }} accept")
        lines.append(
            f"add rule inet {NFT_TABLE} input icmp type "
            "{ destination-unreachable, time-exceeded } accept"
        )
        lines.append(f"add rule inet {NFT_TABLE} input counter drop")

    return Plan("nft", rules, lines, "\n".join(lines) + "\n")


def _plan_darwin(block, allow_lan, allow_ports, mirage_port, spa_port) -> Plan:
    rules: list[Rule] = []
    lines = [
        "pass out quick all",
        "pass in quick proto udp from any to any port 67",
        "pass in quick proto udp from any to any port 68",
    ]

    if mirage_port:
        rules.append(Rule(MIRAGE_NAME, "allow", "tcp", [mirage_port]))
        lines.append(f"pass in quick proto tcp from any to any port {mirage_port}")
        lines.append(f"pass in quick proto udp from any to any port {spa_port or mirage_port}")

    for port in allow_ports:
        rules.append(Rule(f"{PREFIX}Port-{port}", "allow", "tcp", [port]))
        lines.append(f"pass in quick proto tcp from any to any port {port}")

    if block:
        rules.append(Rule(BLOCK_NAME, "block", "any"))
        lines.append("block drop in quick proto { tcp udp } from any to any")

    return Plan("pf", rules, lines, "\n".join(lines) + "\n")


def apply(plan: Plan) -> Report:
    try:
        if plan.backend == "windows":
            return _apply_windows(plan)
        if plan.backend == "nft":
            return _apply_linux(plan)
        if plan.backend == "pf":
            return _apply_darwin(plan)
    except (OSError, subprocess.SubprocessError) as exc:
        return Report(plan.backend, errors=[str(exc)])
    return Report(plan.backend, errors=[f"unknown backend {plan.backend}"])


def _run(argv: list[str], stdin: str | None = None) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)

    output = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode == 0, output.strip()


def _powershell(script: str) -> tuple[bool, str]:
    return _run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ]
    )


def _ps_rule(rule: Rule) -> str:
    parts = [
        f"New-NetFirewallRule -DisplayName '{rule.name}'",
        "-Direction Inbound",
        f"-Action {'Allow' if rule.action == 'allow' else 'Block'}",
        "-Profile Any",
        "-Enabled True",
    ]
    if rule.protocol != "any":
        parts.append(f"-Protocol {rule.protocol.upper()}")
    if rule.ports:
        parts.append("-LocalPort " + ",".join(str(p) for p in rule.ports))
    if rule.remote != "any":
        parts.append(f"-RemoteAddress {rule.remote}")
    parts.append("-ErrorAction Stop")
    return " ".join(parts)


def _apply_windows(plan: Plan) -> Report:
    report = Report("windows")
    script = ["Remove-NetFirewallRule -DisplayName 'ProFast/*' -ErrorAction SilentlyContinue"]
    script.extend(_ps_rule(rule) for rule in plan.rules)

    ok, output = _powershell("; ".join(script))
    if not ok:
        report.skipped.append("Windows Firewall cmdlets unavailable")
        return _apply_windows_netsh(plan, report)

    report.applied = [rule.name for rule in plan.rules]
    if output:
        report.errors.append(output)
    return report


def _apply_windows_netsh(plan: Plan, report: Report) -> Report:
    """Fallback for systems without the NetSecurity module."""
    if not shutil.which("netsh"):
        report.errors.append("neither New-NetFirewallRule nor netsh is available")
        return report

    if not elevated():
        report.errors.append("administrator rights are required to change firewall rules")
        return report

    for rule in plan.rules:
        argv = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule.name}",
            "dir=in",
            f"action={rule.action}",
            f"protocol={rule.protocol}",
        ]
        if rule.ports:
            argv.append("localport=" + ",".join(str(p) for p in rule.ports))
        if rule.remote != "any":
            argv.append(f"remoteip={rule.remote}")

        ok, output = _run(argv)
        if ok:
            report.applied.append(rule.name)
        else:
            report.errors.append(f"{rule.name}: {output}")
    return report


def _apply_linux(plan: Plan) -> Report:
    report = Report("nft")
    if not shutil.which("nft"):
        report.errors.append("nft is not installed (install nftables)")
        return report

    ok, output = _run(["nft", "-f", "-"], stdin=plan.payload)
    if ok:
        report.applied.append(f"inet {NFT_TABLE} table installed")
    else:
        report.errors.append(output or "nft rejected the plan")
    return report


def _apply_darwin(plan: Plan) -> Report:
    report = Report("pf")
    if not shutil.which("pfctl"):
        report.errors.append("pfctl is not available")
        return report

    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as handle:
        handle.write(plan.payload)
        path = Path(handle.name)

    try:
        _run(["pfctl", "-e"])  # already enabled is not an error
        ok, output = _run(["pfctl", "-a", PF_ANCHOR, "-f", str(path)])
        if ok:
            report.applied.append(f"pf anchor {PF_ANCHOR} loaded")
        else:
            report.errors.append(output or "pfctl rejected the plan")
    finally:
        path.unlink(missing_ok=True)
    return report


def reset() -> Report:
    """Remove every rule ProFast owns."""
    if sys.platform == "win32":
        ok, output = _powershell(
            "Remove-NetFirewallRule -DisplayName 'ProFast/*' -ErrorAction SilentlyContinue"
        )
        if ok:
            return Report("windows", applied=["all ProFast rules removed"])
        return Report("windows", errors=[output or "removal failed"])

    if sys.platform == "darwin":
        ok, output = _run(["pfctl", "-a", PF_ANCHOR, "-F", "rules"])
        if ok:
            return Report("pf", applied=["pf anchor flushed"])
        return Report("pf", errors=[output or "pfctl failed"])

    ok, output = _run(["nft", "delete", "table", "inet", NFT_TABLE])
    if ok:
        return Report("nft", applied=[f"inet {NFT_TABLE} removed"])
    if "No such file" in output:
        return Report("nft", skipped=["no ProFast table present"])
    return Report("nft", errors=[output or "nft failed"])


def status() -> list[dict[str, object]]:
    """Return the rules ProFast currently owns, as reported by the OS."""
    if sys.platform == "win32":
        ok, output = _powershell(
            "Get-NetFirewallRule -DisplayName 'ProFast/*' | "
            "Select-Object DisplayName,Enabled,Direction,Action | ConvertTo-Json -Compress"
        )
        if not ok or not output:
            return []
        import json

        try:
            parsed = json.loads(output)
        except ValueError:
            return []
        return parsed if isinstance(parsed, list) else [parsed]

    if sys.platform == "darwin":
        ok, output = _run(["pfctl", "-a", PF_ANCHOR, "-sr"])
        return [{"rule": line} for line in output.splitlines()] if ok and output else []

    ok, output = _run(["nft", "list", "table", "inet", NFT_TABLE])
    return [{"rule": line} for line in output.splitlines()] if ok and output else []
