"""Reference implementation of the daemon method surface.

The Go daemon and this module answer exactly the same JSON-RPC methods, which
is what lets the CLI and the GUI stay language-agnostic. When no Go binary is
installed, ``profast serve`` runs this engine instead.
"""

from __future__ import annotations

import os
import platform
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from . import defense as defense_mod
from . import firewall, mirage, native, scan
from .config import Config
from .consent import ConsentError, Expired, Mismatch
from .consent import Store as ConsentStore
from .errors import (
    CONSENT_REQUIRED,
    ELEVATION_REQUIRED,
    INTERNAL_ERROR,
    INVALID_PARAMS,
    METHOD_NOT_FOUND,
    UNAVAILABLE,
    RpcError,
)
from .focus import Manager as FocusManager
from .version import PROTOCOL_VERSION, VERSION

# How long the firewall rule list is reused; reading it starts a process (see
# _firewall_rules). Rules only change through apply and reset, which drop it.
FIREWALL_TTL = timedelta(seconds=15)


class Engine:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._secret = config.secret()
        self._lock = threading.RLock()
        self._started = datetime.now(timezone.utc)
        self._peers: dict[int, dict[str, Any]] = {}
        self._events: list[dict[str, Any]] = []
        self._replay = mirage.ReplayCache(4096)
        self._consent = ConsentStore(90)
        self._focus = FocusManager(config.focus)
        self._defense = defense_mod.Engine(
            defense_mod.Config(
                enabled=config.defense.enabled,
                auto_ban=config.defense.auto_ban,
                threshold=config.defense.ban_threshold,
                window=timedelta(seconds=config.defense.window_seconds),
                scan_threshold=config.defense.scan_threshold,
                initial_ttl=timedelta(minutes=config.defense.initial_ban_min),
                max_ttl=timedelta(hours=config.defense.max_ban_hours),
                max_bans=config.defense.max_bans,
                tarpit=config.defense.tarpit,
            )
        )
        self._scan_cache: list[scan.Service] = []
        self._scan_at: datetime | None = None
        self._firewall_cache: list[dict[str, object]] = []
        self._firewall_at: datetime | None = None

    # ------------------------------------------------------------- internals
    def locator(self) -> tuple[int, str, int, float]:
        now = time.time()
        epoch = mirage.epoch(now, self.config.mirage.epoch_seconds)
        address, port = mirage.derive(self._secret, self.config.mirage.node_id, epoch)
        return epoch, address, port, now

    def record(self, kind: str, detail: str) -> None:
        with self._lock:
            self._events.append(
                {
                    "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "kind": kind,
                    "detail": detail,
                }
            )
            if len(self._events) > 256:
                self._events = self._events[-256:]

    def events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return list(reversed(self._events[-limit:]))

    def status(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        epoch, address, port, stamp = self.locator()

        with self._lock:
            peers = len(self._peers)
            scanned = len(self._scan_cache)

        remaining = int(mirage.until_boundary(stamp, self.config.mirage.epoch_seconds))

        return {
            "version": VERSION,
            "protocol": PROTOCOL_VERSION,
            "os": platform.system().lower(),
            "arch": platform.machine().lower(),
            "pid": os.getpid(),
            "uptime_s": int((now - self._started).total_seconds()),
            "elevated": firewall.elevated(),
            "kernel_tier": _kernel_tier(),
            "mirage": {
                "enabled": self.config.mirage.enabled,
                "node_id": self.config.mirage.node_id,
                "node_name": self.config.mirage.node_name,
                "epoch": epoch,
                "epoch_seconds": self.config.mirage.epoch_seconds,
                "virtual_address": address,
                "port": port,
                "next_rotation_s": remaining,
                "peers": peers,
                "replay_cache": len(self._replay),
                "identity_model": "rotating-virtual-locator",
            },
            "focus": self._focus.status(),
            "defense": self._defense.stats(),
            "firewall": {
                "enabled": self.config.firewall.enabled,
                "block_inbound": self.config.firewall.block_inbound,
                "allow_lan": self.config.firewall.allow_lan,
                "backend": firewall.backend_name(),
                "applied": len(self._firewall_rules()),
                "errors": [],
            },
            "scan": {"services": scanned, "cached_at": _iso(self._scan_at)},
        }

    def capabilities(self) -> dict[str, Any]:
        features = [
            "focus.dscp",
            "focus.process-priority",
            "scan.services",
            "scan.risk",
            "defense.escalating-bans",
            "firewall.os-native",
            "mirage.rotating-locator",
            "mirage.spa",
        ]
        if platform.system() == "Windows":
            features.append("focus.eco-qos-relax")

        env = native.environment()
        return {
            **env,
            "firewall_backend": firewall.backend_name(),
            "kernel_tier": _kernel_tier(),
            "features": features,
        }

    # ---------------------------------------------------------------- methods
    def handle(self, method: str, params: dict[str, Any] | None) -> Any:
        params = params or {}
        handler = getattr(self, "_m_" + method.replace(".", "_"), None)
        if handler is None:
            raise RpcError(METHOD_NOT_FOUND, f"unknown method {method!r}")
        try:
            return handler(params)
        except RpcError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise RpcError(INVALID_PARAMS, str(exc)) from exc

    # core -------------------------------------------------------------------
    def _m_core_ping(self, _params: dict[str, Any]) -> dict[str, Any]:
        return {"ok": True, "version": VERSION, "protocol": PROTOCOL_VERSION}

    def _m_core_status(self, _params: dict[str, Any]) -> dict[str, Any]:
        return self.status()

    def _m_core_capabilities(self, _params: dict[str, Any]) -> dict[str, Any]:
        return self.capabilities()

    def _m_core_config(self, _params: dict[str, Any]) -> dict[str, Any]:
        return self.config.to_dict()

    def _m_core_events(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        return self.events(int(params.get("limit", 50)))

    # mirage -----------------------------------------------------------------
    def _m_mirage_status(self, _params: dict[str, Any]) -> dict[str, Any]:
        return self.status()["mirage"]

    def _m_mirage_rotate(self, _params: dict[str, Any]) -> dict[str, Any]:
        epoch, address, port, _ = self.locator()
        self.record("mirage", f"locator refreshed for epoch {epoch}")
        return {"epoch": epoch, "virtual_address": address, "port": port}

    def _m_mirage_peers(self, _params: dict[str, Any]) -> list[dict[str, Any]]:
        with self._lock:
            return sorted(self._peers.values(), key=lambda p: p["last_seen"], reverse=True)

    def _m_mirage_spa(self, params: dict[str, Any]) -> dict[str, Any]:
        node_id = int(params.get("node_id") or self.config.mirage.node_id)
        nonce_hex = params.get("nonce_hex") or ""
        nonce = bytes.fromhex(nonce_hex) if nonce_hex else None
        if nonce is not None and len(nonce) != 16:
            raise ValueError("nonce_hex must be 16 bytes")

        # The locator belongs to the node the token is minted for, which is not
        # necessarily this host: a peer mints a token for its own node id.
        stamp = time.time()
        epoch_value = mirage.epoch(stamp, self.config.mirage.epoch_seconds)
        address, port = mirage.derive(self._secret, node_id, epoch_value)
        _, token, _ = mirage.mint(self._secret, node_id, epoch_value, nonce)
        return {
            "token": token,
            "node_id": node_id,
            "epoch": epoch_value,
            "virtual_address": address,
            "port": port,
            "expires_in_s": int(mirage.until_boundary(stamp, self.config.mirage.epoch_seconds)),
        }

    def _m_mirage_accept(self, params: dict[str, Any]) -> dict[str, Any]:
        token = str(params.get("token", ""))
        source = str(params.get("source", ""))
        now = time.time()

        try:
            node_id, token_epoch = mirage.verify(
                self._secret, token, now, self.config.mirage.epoch_seconds
            )
        except mirage.MirageError as exc:
            _, _, port, _ = self.locator()
            decision = self._defense.observe(source, port)
            self.record("mirage", f"rejected SPA from {source}: {exc} ({decision.action})")
            raise RpcError(UNAVAILABLE, f"single packet authorization rejected: {exc}") from exc

        raw = mirage.decode_token(token)
        if self._replay.check(raw):
            self.record("mirage", f"replay attempt from {source}")
            raise RpcError(UNAVAILABLE, "token already used")

        address, port = mirage.derive(self._secret, node_id, token_epoch)
        with self._lock:
            self._peers[node_id] = {
                "node_id": node_id,
                "source": source,
                "epoch": token_epoch,
                "virtual_address": address,
                "last_seen": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }

        _ = raw
        self.record("mirage", f"peer {node_id} authorized from {source}")
        return {
            "accepted": True,
            "node_id": node_id,
            "epoch": token_epoch,
            "virtual_address": address,
            "port": port,
            "source": source,
        }

    # focus ------------------------------------------------------------------
    def _m_focus_start(self, params: dict[str, Any]) -> dict[str, Any]:
        session = self._focus.start(
            target=str(params.get("target", "")),
            pid=int(params.get("pid", 0) or 0),
            duration_s=int(params.get("duration_s", 0) or 0),
        )
        self.record("focus", f"started for {session.target}")
        return session.to_dict()

    def _m_focus_stop(self, _params: dict[str, Any]) -> dict[str, Any]:
        try:
            session = self._focus.stop()
        except RuntimeError as exc:
            raise RpcError(UNAVAILABLE, str(exc)) from exc
        self.record("focus", "stopped, policies reverted")
        return session.to_dict()

    def _m_focus_status(self, _params: dict[str, Any]) -> dict[str, Any] | None:
        return self._focus.status()

    # scan -------------------------------------------------------------------
    def _m_scan_services(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        services = self._services(refresh=bool(params.get("refresh", False)))
        minimum = int(params.get("min_risk", 0) or 0)
        limit = int(params.get("limit", 0) or 0)

        selected = [svc for svc in services if svc.risk >= minimum]
        if limit > 0:
            selected = selected[:limit]
        return [svc.to_dict() for svc in selected]

    def _m_scan_risky(self, _params: dict[str, Any]) -> list[dict[str, Any]]:
        return [svc.to_dict() for svc in scan.risky(self._services(refresh=False))]

    def _services(self, refresh: bool) -> list[scan.Service]:
        with self._lock:
            cached, cached_at = self._scan_cache, self._scan_at
        if (
            not refresh
            and cached
            and cached_at is not None
            and (datetime.now(timezone.utc) - cached_at) < timedelta(seconds=45)
        ):
            return cached

        try:
            services = scan.list_services()
        except RuntimeError as exc:
            raise RpcError(UNAVAILABLE, str(exc)) from exc

        with self._lock:
            self._scan_cache = services
            self._scan_at = datetime.now(timezone.utc)
        return services

    # consent ----------------------------------------------------------------
    def _m_consent_request(self, params: dict[str, Any]) -> dict[str, Any]:
        action = str(params.get("action", ""))
        if not action:
            raise ValueError("action is required")
        grant = self._consent.issue(
            action=action,
            summary=str(params.get("summary", "")),
            targets=[str(t) for t in params.get("targets", [])],
        )
        self.record("consent", f"requested: {action}")
        return grant.to_dict()

    def _m_consent_pending(self, _params: dict[str, Any]) -> list[dict[str, Any]]:
        return [grant.to_dict() for grant in self._consent.pending()]

    def _m_consent_revoke(self, params: dict[str, Any]) -> dict[str, Any]:
        self._consent.revoke(str(params.get("token", "")))
        return {"revoked": True}

    # services ---------------------------------------------------------------
    def _m_services_terminate(self, params: dict[str, Any]) -> dict[str, Any]:
        pids = [int(pid) for pid in params.get("pids", [])]
        if not pids:
            raise ValueError("pids is required")
        if len(pids) > 64:
            raise ValueError("at most 64 processes per request")

        for pid in pids:
            if pid <= 4 or pid == os.getpid():
                raise ValueError(f"refusing to terminate pid {pid}")

        targets = sorted(f"pid:{pid}" for pid in pids)
        try:
            self._consent.redeem(str(params.get("token", "")), "services.terminate", targets)
        except Expired as exc:
            raise RpcError(CONSENT_REQUIRED, "confirmation expired, ask the user again") from exc
        except Mismatch as exc:
            raise RpcError(CONSENT_REQUIRED, str(exc)) from exc
        except ConsentError as exc:
            raise RpcError(
                CONSENT_REQUIRED, "a user confirmation is required before terminating processes"
            ) from exc

        terminated, failed = self._kill(pids, force=bool(params.get("force", False)))
        self.record("services", f"terminated {len(terminated)}, failed {len(failed)}")
        return {"ok": not failed, "terminated": terminated, "failed": failed}

    @staticmethod
    def _kill(pids: list[int], force: bool) -> tuple[list[int], list[dict[str, Any]]]:
        import psutil

        terminated: list[int] = []
        failed: list[dict[str, Any]] = []

        for pid in pids:
            try:
                proc = psutil.Process(pid)
                proc.kill() if force else proc.terminate()
                try:
                    proc.wait(timeout=3)
                except psutil.TimeoutExpired:
                    proc.kill()
                terminated.append(pid)
            except (psutil.Error, OSError) as exc:
                failed.append({"pid": pid, "error": str(exc)})
        return terminated, failed

    # firewall ---------------------------------------------------------------
    def _firewall_plan(self, params: dict[str, Any]) -> firewall.Plan:
        epoch, _address, port, _stamp = self.locator()
        block = bool(params.get("block_inbound", self.config.firewall.block_inbound))
        allow_lan = bool(params.get("allow_lan", self.config.firewall.allow_lan))
        ports = [int(p) for p in params.get("allow_ports", self.config.firewall.allow_ports)]
        return firewall.build_plan(block, allow_lan, ports, port, port)

    def _m_firewall_plan(self, params: dict[str, Any]) -> dict[str, Any]:
        _ = params.get("block_inbound")
        return self._firewall_plan(params).to_dict()

    def _m_firewall_apply(self, params: dict[str, Any]) -> dict[str, Any]:
        plan = self._firewall_plan(params)
        if params.get("dry_run"):
            return {**plan.to_dict(), "dry_run": True}

        report = firewall.apply(plan)
        # Even a partial failure may have written some rules.
        self._forget_firewall()
        self.record(
            "firewall", f"{len(report.applied)} applied, {len(report.errors)} error(s)"
        )
        if report.errors:
            code = ELEVATION_REQUIRED if not firewall.elevated() else INTERNAL_ERROR
            raise RpcError(code, "; ".join(report.errors))
        return report.to_dict()

    def _m_firewall_reset(self, _params: dict[str, Any]) -> dict[str, Any]:
        report = firewall.reset()
        self._forget_firewall()
        self.record("firewall", "all ProFast rules removed")
        return report.to_dict()

    def _firewall_rules(self) -> list[dict[str, object]]:
        """Rules the OS reports for us, reused for a short while.

        Asking the OS starts a PowerShell process on Windows, which takes
        seconds; the window polls every second, so the answer is kept and only
        re-read once it is stale. Everything that changes the rules drops it.
        """
        with self._lock:
            cached, cached_at = self._firewall_cache, self._firewall_at
        if cached_at is not None and (datetime.now(timezone.utc) - cached_at) < FIREWALL_TTL:
            return cached

        # Not under the lock: the probe takes seconds and the same lock guards
        # the peer table and the event log, which must stay usable meanwhile.
        rules = firewall.status()

        with self._lock:
            self._firewall_cache = rules
            self._firewall_at = datetime.now(timezone.utc)
        return rules

    def _forget_firewall(self) -> None:
        with self._lock:
            self._firewall_at = None

    def _m_firewall_status(self, _params: dict[str, Any]) -> dict[str, Any]:
        return {"backend": firewall.backend_name(), "rules": self._firewall_rules()}

    # defense ----------------------------------------------------------------
    def _m_defense_status(self, _params: dict[str, Any]) -> dict[str, Any]:
        return self._defense.stats()

    def _m_defense_bans(self, _params: dict[str, Any]) -> list[dict[str, Any]]:
        return [ban.to_dict() for ban in self._defense.bans()]

    def _m_defense_ban(self, params: dict[str, Any]) -> dict[str, Any]:
        source = defense_mod.normalize_ip(str(params.get("ip", "")))
        reason = str(params.get("reason") or "manual ban")
        ban = self._defense.ban(source, reason)
        self.record("defense", f"banned {source}: {reason}")
        return ban.to_dict()

    def _m_defense_unban(self, params: dict[str, Any]) -> dict[str, Any]:
        source = defense_mod.normalize_ip(str(params.get("ip", "")))
        removed = self._defense.unban(source)
        self.record("defense", f"unbanned {source}")
        return {"unbanned": removed}

    def _m_defense_observe(self, params: dict[str, Any]) -> dict[str, Any]:
        source = defense_mod.normalize_ip(str(params.get("source", "")))
        decision = self._defense.observe(source, int(params.get("port", 0) or 0))
        return decision.to_dict()

    # housekeeping -----------------------------------------------------------
    def tick(self) -> bool:
        """Expire focus sessions. Returns True when a session was closed."""
        if self._focus.tick():
            self.record("focus", "session window elapsed, policies reverted")
            return True
        return False


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat(timespec="seconds") if moment else None


def _kernel_tier() -> str:
    system = platform.system()
    if system == "Windows":
        return "wfp (user-mode filters active, callout driver optional)"
    if system == "Darwin":
        return "pf + network-extension (entitlement required for the extension)"
    return "nftables + xdp (libbpf loader optional)"
