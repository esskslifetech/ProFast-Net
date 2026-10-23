"""Reactive defence: scan detection, escalating bans, tarpitting.

Mirrors ``core/internal/defense``. This module never sends a packet of its
own: "forceful defence" means the host refuses, throttles and remembers, not
that it retaliates.
"""

from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .models import Ban


@dataclass
class Config:
    enabled: bool = True
    auto_ban: bool = True
    threshold: int = 40
    window: timedelta = timedelta(seconds=10)
    scan_threshold: int = 20
    initial_ttl: timedelta = timedelta(minutes=5)
    max_ttl: timedelta = timedelta(hours=24)
    max_bans: int = 4096
    tarpit: bool = True


@dataclass
class Decision:
    action: str
    reason: str
    ban_seconds: int = 0

    def to_dict(self) -> dict[str, object]:
        return {"action": self.action, "reason": self.reason, "ban_seconds": self.ban_seconds}


@dataclass
class _State:
    attempts: list[datetime] = field(default_factory=list)
    ports: set[int] = field(default_factory=set)
    level: int = 0


class Engine:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()
        self._lock = threading.Lock()
        self._states: dict[str, _State] = {}
        self._bans: dict[str, Ban] = {}
        self._events: list[dict[str, object]] = []

    # ---------------------------------------------------------------- observe
    def observe(self, source: str, port: int, now: datetime | None = None) -> Decision:
        if not self.config.enabled:
            return Decision("allow", "defense disabled")

        now = now or datetime.now(timezone.utc)
        with self._lock:
            ban = self._bans.get(source)
            if ban and now < ban.expires_at:
                ban.hits += 1
                remaining = int((ban.expires_at - now).total_seconds())
                return Decision("drop", f"source is banned: {ban.reason}", remaining)
            if ban:
                del self._bans[source]

            state = self._states.setdefault(source, _State())
            cutoff = now - self.config.window
            state.attempts = [stamp for stamp in state.attempts if stamp > cutoff]
            state.attempts.append(now)
            state.ports.add(port)

            if not self.config.auto_ban:
                return Decision("allow", "monitor only")

            if len(state.ports) >= self.config.scan_threshold:
                seconds = self._ban_locked(source, "port scan", now)
                state.ports.clear()
                return Decision("drop", "port scan detected", seconds)

            if len(state.attempts) >= self.config.threshold:
                seconds = self._ban_locked(source, "connection flood", now)
                return Decision("drop", "connection flood detected", seconds)

            if self.config.tarpit and len(state.attempts) >= self.config.threshold // 2:
                return Decision("tarpit", "throttling probe rate")

            return Decision("allow", "within policy")

    # ------------------------------------------------------------------- bans
    def ban(self, source: str, reason: str, now: datetime | None = None) -> Ban:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            self._ban_locked(source, reason, now)
            return self._bans[source]

    def unban(self, source: str) -> bool:
        with self._lock:
            existed = self._bans.pop(source, None) is not None
            self._states.pop(source, None)
            return existed

    def blocked(self, source: str, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            ban = self._bans.get(source)
            return bool(ban and now < ban.expires_at)

    def bans(self, now: datetime | None = None) -> list[Ban]:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            for ip in [ip for ip, ban in self._bans.items() if now >= ban.expires_at]:
                del self._bans[ip]
            return sorted(self._bans.values(), key=lambda b: b.banned_at, reverse=True)

    def _ban_locked(self, source: str, reason: str, now: datetime) -> int:
        state = self._states.setdefault(source, _State())
        ttl = self.config.initial_ttl
        for _ in range(state.level):
            ttl *= 2
            if ttl >= self.config.max_ttl:
                ttl = self.config.max_ttl
                break

        if len(self._bans) >= self.config.max_bans:
            oldest = min(self._bans, key=lambda ip: self._bans[ip].banned_at)
            del self._bans[oldest]

        self._bans[source] = Ban(
            ip=source,
            reason=reason,
            banned_at=now,
            expires_at=now + ttl,
            level=state.level,
        )
        state.level += 1
        self._event("ban", source, reason)
        return int(ttl.total_seconds())

    # ----------------------------------------------------------------- events
    def _event(self, kind: str, source: str, detail: str) -> None:
        self._events.append(
            {
                "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "kind": kind,
                "source": source,
                "detail": detail,
            }
        )
        if len(self._events) > 512:
            self._events = self._events[-512:]

    def events(self, limit: int = 50) -> list[dict[str, object]]:
        with self._lock:
            return list(reversed(self._events[-limit:]))

    def stats(self, now: datetime | None = None) -> dict[str, object]:
        active = len(self.bans(now))
        with self._lock:
            tracked = len(self._states)
        return {
            "enabled": self.config.enabled,
            "auto_ban": self.config.auto_ban,
            "active_bans": active,
            "tracked": tracked,
            "tarpit": self.config.tarpit,
        }


def normalize_ip(value: str) -> str:
    """Accept ``1.2.3.4``, ``1.2.3.4:80`` and ``[::1]:80``."""
    candidate = value.strip()
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]
    elif candidate.count(":") == 1:
        candidate = candidate.split(":", 1)[0]

    address = ipaddress.ip_address(candidate)
    return str(address)
