"""Configuration shared byte-for-byte with the Go daemon.

Both implementations read the same ``config.json``. The schema lives here, in
Python, because this is the side a user edits by hand.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import struct
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

APP_DIR = "ProFast-Net"


def config_dir() -> Path:
    """Mirror Go's os.UserConfigDir()."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming")
        return Path(base) / APP_DIR
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_DIR
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / APP_DIR


def runtime_dir() -> Path:
    """Mirror the Go daemon's short, per-user runtime directory."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")
        return Path(base) / APP_DIR
    user = os.environ.get("USER") or "user"
    import tempfile

    return Path(tempfile.gettempdir()) / f"profast-{user}"


def config_path() -> Path:
    return config_dir() / "config.json"


def endpoint_path() -> Path:
    return runtime_dir() / "endpoint.json"


def state_path() -> Path:
    return runtime_dir() / "state.json"


@dataclass
class MirageConfig:
    enabled: bool = True
    interface: str = "auto"
    node_name: str = ""
    node_id: int = 0
    secret_hex: str = ""
    epoch_seconds: int = 10
    peer_port: int = 0


@dataclass
class FocusConfig:
    target_path: str = ""
    boost_priority: bool = True
    disable_eco_qos: bool = True
    default_duration_s: int = 3600
    throttle_others: bool = True
    background_dscp: int = 8


@dataclass
class DefenseConfig:
    enabled: bool = True
    auto_ban: bool = True
    ban_threshold: int = 40
    window_seconds: int = 10
    scan_threshold: int = 20
    initial_ban_min: int = 5
    max_ban_hours: int = 24
    max_bans: int = 4096
    tarpit: bool = True


@dataclass
class FirewallConfig:
    enabled: bool = True
    allow_lan: bool = True
    block_inbound: bool = False
    allow_ports: list[int] = field(default_factory=list)


@dataclass
class Config:
    version: int = 1
    mirage: MirageConfig = field(default_factory=MirageConfig)
    focus: FocusConfig = field(default_factory=FocusConfig)
    defense: DefenseConfig = field(default_factory=DefenseConfig)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    log_level: str = "info"

    def secret(self) -> bytes:
        raw = bytes.fromhex(self.mirage.secret_hex.strip())
        if len(raw) != 32:
            raise ValueError(f"mirage secret must be 32 bytes, got {len(raw)}")
        return raw

    def clamp(self) -> None:
        self.mirage.epoch_seconds = min(300, max(2, self.mirage.epoch_seconds))
        self.focus.default_duration_s = max(1, self.focus.default_duration_s)
        self.defense.ban_threshold = max(1, self.defense.ban_threshold)
        self.defense.window_seconds = max(1, self.defense.window_seconds)
        self.defense.max_bans = max(16, self.defense.max_bans)
        self.firewall.allow_ports = sorted({int(p) for p in self.firewall.allow_ports})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Config:
        cfg = cls()
        cfg.version = int(raw.get("version", cfg.version))
        cfg.log_level = str(raw.get("log_level", cfg.log_level))
        for section_name in ("mirage", "focus", "defense", "firewall"):
            section = getattr(cfg, section_name)
            for key, value in (raw.get(section_name) or {}).items():
                if hasattr(section, key):
                    setattr(section, key, value)
        return cfg


def defaults() -> Config:
    hostname = os.uname().nodename if hasattr(os, "uname") else os.environ.get("COMPUTERNAME", "")
    hostname = hostname or "profast-node"
    node_id = struct.unpack(">I", hashlib.sha256(hostname.encode()).digest()[:4])[0]

    return Config(
        mirage=MirageConfig(
            node_name=hostname,
            node_id=node_id,
            secret_hex=secrets.token_bytes(32).hex(),
        )
    )


def load(path: Path | None = None) -> tuple[Config, bool]:
    """Load the configuration, creating a default one when absent."""
    target = Path(path) if path else config_path()
    if not target.exists():
        cfg = defaults()
        save(cfg, target)
        return cfg, True

    raw = json.loads(target.read_text(encoding="utf-8"))
    cfg = Config.from_dict(raw)
    cfg.clamp()
    return cfg, False


def save(cfg: Config, path: Path | None = None) -> Path:
    target = Path(path) if path else config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(cfg.to_dict(), indent=2) + "\n", encoding="utf-8")
    try:
        target.chmod(0o600)
    except OSError:  # Windows ACLs are not POSIX bits
        pass
    return target
