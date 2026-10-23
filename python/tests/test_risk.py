"""Risk scoring and reactive defence.

The scoring table is shared with ``core/internal/scan/risk.go``; these cases are
the ones that decide whether the CLI offers to terminate a service at all.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from profast import defense, scan
from profast.models import Service


def _service(**overrides: object) -> Service:
    base = {
        "pid": 100,
        "process": "app",
        "port": 50000,
        "protocol": "tcp",
        "address": "127.0.0.1",
    }
    base.update(overrides)
    return Service(**base)  # type: ignore[arg-type]


def _scored(*services: Service) -> list[Service]:
    """Apply the same scoring `list_services` does, without touching the host."""
    result = []
    for service in services:
        value, label, reasons = scan.score(service)
        result.append(
            Service(
                pid=service.pid,
                process=service.process,
                port=service.port,
                protocol=service.protocol,
                address=service.address,
                path=service.path,
                public=service.public,
                system=service.system,
                risk=value,
                level=label,
                reasons=reasons,
            )
        )
    return sorted(result, key=lambda svc: (-svc.risk, svc.port))


# --------------------------------------------------------------------- scoring


def test_telnet_on_every_interface_is_critical() -> None:
    value, level, reasons = scan.score(
        _service(port=23, address="0.0.0.0", public=True, process="telnetd")
    )
    assert value == 100
    assert level == "critical"
    assert any("Telnet" in reason for reason in reasons)


def test_loopback_dev_server_scores_lower_than_exposed_one() -> None:
    local, _, _ = scan.score(_service(port=8080))
    exposed, _, _ = scan.score(_service(port=8080, address="0.0.0.0", public=True))
    assert exposed > local
    assert exposed - local == 30


def test_unknown_low_port_is_flagged_but_not_critical() -> None:
    value, level, reasons = scan.score(_service(port=600))
    assert 0 < value < 55
    assert level in {"low", "medium"}
    assert any("privileged port" in reason for reason in reasons)


def test_system_flag_and_temp_path_add_weight() -> None:
    exposed = {"port": 9000, "address": "0.0.0.0", "public": True}
    plain, _, _ = scan.score(_service(**exposed))
    system, _, _ = scan.score(_service(**exposed, system=True))
    temp, _, _ = scan.score(_service(**exposed, path="C:\\Users\\bob\\Downloads\\tool.exe"))
    assert system == plain + 10
    assert temp == plain + 15


def test_public_udp_is_penalised_once_more() -> None:
    exposed = {"port": 9001, "address": "0.0.0.0", "public": True}
    tcp, _, _ = scan.score(_service(**exposed))
    udp, _, _ = scan.score(_service(**exposed, protocol="udp"))
    assert udp == tcp + 5


def test_every_service_gets_at_least_one_reason() -> None:
    _, _, reasons = scan.score(_service())
    assert reasons


@pytest.mark.parametrize(
    ("value", "expected"),
    [(0, "low"), (29, "low"), (30, "medium"), (54, "medium"), (55, "high"), (79, "high"),
     (80, "critical"), (100, "critical")],
)
def test_level_thresholds(value: int, expected: str) -> None:
    assert scan.level(value) == expected


def test_risky_filter_uses_the_high_threshold() -> None:
    services = _scored(
        _service(port=23, address="0.0.0.0", public=True),
        _service(port=8080),
    )
    assert [svc.port for svc in scan.risky(services)] == [23]
    assert [svc.port for svc in scan.risky(services, minimum=0)] == [23, 8080]


def test_public_binding_detection() -> None:
    for address in ("0.0.0.0", "::", "*", ""):
        assert scan.is_public(address) is True
    for address in ("127.0.0.1", "::1", "192.168.1.4"):
        assert scan.is_public(address) is False


# --------------------------------------------------------------------- defence


def _defense(**overrides: object) -> defense.Engine:
    settings = {
        "threshold": 5,
        "window": timedelta(seconds=10),
        "scan_threshold": 3,
        "initial_ttl": timedelta(minutes=1),
        "max_ttl": timedelta(hours=1),
        "tarpit": True,
        "auto_ban": True,
    }
    settings.update(overrides)
    return defense.Engine(defense.Config(**settings))  # type: ignore[arg-type]


def test_first_contact_is_allowed() -> None:
    decision = _defense().observe("203.0.113.5", 443)
    assert decision.action == "allow"


def test_repeated_probes_are_tarpitted_before_being_banned() -> None:
    engine = _defense()
    assert engine.observe("203.0.113.5", 443).action == "allow"
    assert engine.observe("203.0.113.5", 443).action == "tarpit"


def test_connection_flood_gets_banned() -> None:
    engine = _defense()
    for _ in range(5):
        decision = engine.observe("203.0.113.6", 443)
    assert decision.action == "drop"
    assert decision.reason == "connection flood detected"
    assert decision.ban_seconds == 60
    assert engine.blocked("203.0.113.6") is True


def test_port_scan_is_detected_by_fan_out() -> None:
    engine = _defense()
    for port in (21, 22, 23):
        decision = engine.observe("203.0.113.7", port)
    assert decision.action == "drop"
    assert decision.reason == "port scan detected"
    assert [ban.ip for ban in engine.bans()] == ["203.0.113.7"]


def test_bans_escalate_up_to_the_ceiling() -> None:
    engine = _defense()
    first = engine.ban("198.51.100.9", "manual")
    second = engine.ban("198.51.100.9", "manual")
    assert first.level == 0
    assert second.level == 1
    assert (second.expires_at - second.banned_at) == 2 * (first.expires_at - first.banned_at)

    for _ in range(10):
        latest = engine.ban("198.51.100.9", "manual")
    assert (latest.expires_at - latest.banned_at) == timedelta(hours=1)


def test_an_active_ban_counts_hits_and_drops() -> None:
    engine = _defense()
    engine.ban("198.51.100.10", "manual")
    decision = engine.observe("198.51.100.10", 443)
    assert decision.action == "drop"
    assert engine.bans()[0].hits == 1


def test_unban_clears_state() -> None:
    engine = _defense()
    engine.ban("198.51.100.11", "manual")
    assert engine.unban("198.51.100.11") is True
    assert engine.unban("198.51.100.11") is False
    assert engine.observe("198.51.100.11", 443).action == "allow"


def test_disabled_defence_allows_everything() -> None:
    engine = _defense(enabled=False)
    for _ in range(50):
        assert engine.observe("203.0.113.8", 443).action == "allow"
    assert engine.bans() == []


def test_monitor_only_never_bans() -> None:
    engine = _defense(auto_ban=False)
    for port in range(20000, 20020):
        assert engine.observe("203.0.113.9", port).action == "allow"
    assert engine.bans() == []


def test_stats_report_the_shape_the_dashboard_expects() -> None:
    engine = _defense()
    engine.ban("198.51.100.12", "manual")
    stats = engine.stats()
    assert stats["active_bans"] == 1
    assert stats["tarpit"] is True
    assert stats["enabled"] is True
    assert set(stats) == {"enabled", "auto_ban", "active_bans", "tracked", "tarpit"}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("203.0.113.5", "203.0.113.5"),
        ("203.0.113.5:443", "203.0.113.5"),
        (" 198.51.100.7 ", "198.51.100.7"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("2001:db8::2", "2001:db8::2"),
    ],
)
def test_normalize_ip_accepts_endpoint_forms(raw: str, expected: str) -> None:
    assert defense.normalize_ip(raw) == expected


def test_normalize_ip_rejects_nonsense() -> None:
    with pytest.raises(ValueError):
        defense.normalize_ip("not-an-address")
