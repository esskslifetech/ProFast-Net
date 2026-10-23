"""Shared data shapes. Keeping them in one module keeps the CLI, the GUI and
the daemon speaking about the same objects."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat(timespec="seconds") if moment else None


@dataclass
class Service:
    pid: int
    process: str
    port: int
    protocol: str
    address: str
    path: str = ""
    public: bool = False
    system: bool = False
    risk: int = 0
    level: str = "low"
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Grant:
    token: str
    action: str
    targets: list[str]
    summary: str
    issued: datetime
    expires: datetime

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["issued"] = _iso(self.issued)
        data["expires"] = _iso(self.expires)
        return data


@dataclass
class Ban:
    ip: str
    reason: str
    banned_at: datetime
    expires_at: datetime
    level: int = 0
    hits: int = 0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["banned_at"] = _iso(self.banned_at)
        data["expires_at"] = _iso(self.expires_at)
        return data


@dataclass
class Peer:
    node_id: int
    source: str
    epoch: int
    virtual_address: str
    last_seen: datetime

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["last_seen"] = _iso(self.last_seen)
        return data


@dataclass
class FocusSession:
    target: str
    started: datetime
    ends_at: datetime
    pid: int = 0
    boosted: bool = False
    eco_qos_relaxed: bool = False
    background_caps: bool = False
    applied: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["started"] = _iso(self.started)
        data["ends_at"] = _iso(self.ends_at)
        return data


@dataclass
class Report:
    backend: str
    applied: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
