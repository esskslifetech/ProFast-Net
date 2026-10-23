"""The engine's firewall probe cache.

``firewall.status()`` shells out to the OS - on Windows it starts PowerShell -
which takes seconds, while the window asks for status every second. The engine
therefore keeps the answer for a short while, and everything that edits the
rules has to drop it.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from profast import config
from profast import engine as engine_module
from profast.engine import Engine


@pytest.fixture
def eng() -> Engine:
    return Engine(config.defaults())


@pytest.fixture
def probe(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Records how often the OS is really asked for the rule list."""
    calls: list[int] = []

    def status() -> list[dict[str, object]]:
        calls.append(1)
        return [{"DisplayName": f"ProFast/rule{index}"} for index in range(len(calls))]

    monkeypatch.setattr(engine_module.firewall, "status", status)
    return calls


def test_status_asks_the_os_once(eng: Engine, probe: list[int]) -> None:
    first = eng.status()
    second = eng.status()
    third = eng.status()

    assert len(probe) == 1
    assert first["firewall"]["applied"] == 1
    assert second["firewall"]["applied"] == 1
    assert third["firewall"]["applied"] == 1


def test_empty_rule_list_is_cached_too(eng: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
    # "No rules" is a real answer. Keying the cache on a non-empty list would
    # re-probe the OS on every poll for exactly the unconfigured case.
    calls: list[int] = []

    def status() -> list[dict[str, object]]:
        calls.append(1)
        return []

    monkeypatch.setattr(engine_module.firewall, "status", status)

    assert eng.status()["firewall"]["applied"] == 0
    assert eng.status()["firewall"]["applied"] == 0
    assert len(calls) == 1


def test_the_status_method_shares_the_cache(eng: Engine, probe: list[int]) -> None:
    eng.status()
    payload = eng._m_firewall_status({})

    assert len(probe) == 1
    assert [rule["DisplayName"] for rule in payload["rules"]] == ["ProFast/rule0"]


def test_forgetting_forces_a_new_probe(eng: Engine, probe: list[int]) -> None:
    eng.status()
    eng._forget_firewall()

    assert eng.status()["firewall"]["applied"] == 2
    assert len(probe) == 2


def test_apply_drops_the_cache(
    eng: Engine, probe: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    report = SimpleNamespace(applied=["a"], skipped=[], errors=[], to_dict=dict)
    monkeypatch.setattr(engine_module.firewall, "apply", lambda _plan: report)

    eng.status()
    eng._m_firewall_apply({})
    eng.status()

    # The count has to reflect what was just written, not the pre-apply answer.
    assert len(probe) == 2


def test_reset_drops_the_cache(
    eng: Engine, probe: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    report = SimpleNamespace(applied=[], skipped=[], errors=[], to_dict=dict)
    monkeypatch.setattr(engine_module.firewall, "reset", lambda: report)

    eng.status()
    eng._m_firewall_reset({})
    eng.status()

    assert len(probe) == 2
