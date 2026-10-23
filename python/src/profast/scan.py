"""Listening-service inventory and risk scoring.

Uses psutil so one implementation covers Windows, Linux and macOS. The risk
table is kept identical to ``core/internal/scan/risk.go``.
"""

from __future__ import annotations

import socket
from dataclasses import replace

from .models import Service

# port -> (score, reason)
PORT_PROFILES: dict[int, tuple[int, str]] = {
    21: (70, "FTP carries credentials in clear text"),
    23: (90, "Telnet is unencrypted remote shell access"),
    25: (40, "SMTP relay exposed to the network"),
    69: (50, "TFTP has no authentication"),
    135: (65, "MSRPC endpoint mapper is a classic lateral movement target"),
    137: (55, "NetBIOS name service leaks host information"),
    139: (75, "NetBIOS session service exposes SMB"),
    445: (85, "SMB file sharing exposed to the LAN"),
    512: (70, "rexec allows unauthenticated remote execution"),
    513: (65, "rlogin trusts the source host"),
    514: (60, "rsh/rlogind family, legacy and unsafe"),
    1433: (70, "SQL Server reachable from the network"),
    1521: (60, "Oracle listener exposed"),
    1900: (35, "SSDP/UPnP discovery answers arbitrary probes"),
    2049: (60, "NFS export exposed"),
    3306: (65, "MySQL reachable from the network"),
    3389: (80, "RDP is the most attacked Windows service"),
    5432: (55, "PostgreSQL reachable from the network"),
    5900: (75, "VNC often runs without a password"),
    5985: (70, "WinRM over HTTP accepts remote management"),
    5986: (50, "WinRM over HTTPS exposed"),
    6379: (85, "Redis has no authentication by default"),
    8080: (30, "HTTP proxy or dev server exposed"),
    9200: (70, "Elasticsearch has no authentication by default"),
    11211: (60, "memcached amplifies traffic and leaks data"),
    27017: (80, "MongoDB historically allows anonymous access"),
}

RISKY_PATH_FRAGMENTS = (
    "\\temp\\",
    "\\tmp\\",
    "/tmp/",
    "\\downloads\\",
    "/downloads/",
    "\\appdata\\local\\temp",
)

SYSTEM_PROCESSES = {
    "system",
    "svchost",
    "lsass",
    "services",
    "wininit",
    "smss",
    "csrss",
    "kernel_task",
    "launchd",
    "systemd",
    "init",
    "root",
}


def is_public(address: str) -> bool:
    return address in {"", "*", "0.0.0.0", "::", "[::]", "any", "Any"}


def score(service: Service) -> tuple[int, str, list[str]]:
    value = 5
    reasons: list[str] = []

    profile = PORT_PROFILES.get(service.port)
    if profile:
        value, reason = profile
        reasons.append(reason)
    elif service.port < 1024:
        value = 25
        reasons.append(f"privileged port {service.port} is bound")

    if service.public:
        value += 20
        reasons.append("listening on every interface, not just loopback")
    elif service.address in {"127.0.0.1", "::1"}:
        value -= 10

    if service.system:
        value += 10
        reasons.append("runs as a system account, so a compromise is total")

    lowered = service.path.lower()
    if any(fragment in lowered for fragment in RISKY_PATH_FRAGMENTS if lowered):
        value += 15
        reasons.append("binary executed from a temporary or download folder")

    if service.protocol == "udp" and service.public:
        value += 5
        reasons.append("UDP service is spoofable and amplifies probes")

    value = max(0, min(100, value))
    if not reasons:
        reasons.append("no known exposure signature")
    return value, level(value), reasons


def level(value: int) -> str:
    if value >= 80:
        return "critical"
    if value >= 55:
        return "high"
    if value >= 30:
        return "medium"
    return "low"


def list_services() -> list[Service]:
    """Enumerate every listening TCP/UDP socket, worst first."""
    try:
        import psutil
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise RuntimeError("psutil is required for service scanning") from exc

    process_cache: dict[int, tuple[str, str]] = {}
    seen: dict[tuple[str, int, int], int] = {}
    services: list[Service] = []

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied as exc:
        raise RuntimeError("insufficient privileges to enumerate sockets") from exc

    for conn in connections:
        if not conn.laddr:
            continue

        is_tcp = conn.type == socket.SOCK_STREAM
        if is_tcp and conn.status != psutil.CONN_LISTEN:
            continue
        if not is_tcp and conn.status not in {psutil.CONN_NONE, ""}:
            continue

        address, port = conn.laddr[0], conn.laddr[1]
        pid = conn.pid or 0
        name, path = process_cache.get(pid, ("unknown", ""))

        if pid and pid not in process_cache:
            try:
                proc = psutil.Process(pid)
                name = proc.name()
                path = proc.exe() or ""
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                name, path = f"pid {pid}", ""
            process_cache[pid] = (name, path)

        key = ("tcp" if is_tcp else "udp", port, pid)
        candidate = Service(
            pid=pid,
            process=name,
            port=port,
            protocol="tcp" if is_tcp else "udp",
            address=address,
            path=path,
            public=is_public(address),
            system=name.lower() in SYSTEM_PROCESSES,
        )

        if key in seen:
            index = seen[key]
            if candidate.public and not services[index].public:
                services[index] = replace(services[index], address=address, public=True)
            continue

        seen[key] = len(services)
        services.append(candidate)

    for index, service in enumerate(services):
        value, label, reasons = score(service)
        services[index] = replace(service, risk=value, level=label, reasons=reasons)

    services.sort(key=lambda svc: (-svc.risk, svc.port))
    return services


def risky(services: list[Service], minimum: int = 55) -> list[Service]:
    return [svc for svc in services if svc.risk >= minimum]
