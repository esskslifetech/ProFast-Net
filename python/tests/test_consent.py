"""Confirmation tokens: the mechanism that makes "ask the user first" enforceable."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from profast import consent


def _store(ttl: int = 90) -> consent.Store:
    return consent.Store(ttl)


def test_redeem_consumes_the_token() -> None:
    store = _store()
    grant = store.issue("services.terminate", "terminate 2 services", ["pid:10", "pid:11"])
    store.redeem(grant.token, "services.terminate", ["pid:11", "pid:10"])

    with pytest.raises(consent.UnknownToken):
        store.redeem(grant.token, "services.terminate", ["pid:10", "pid:11"])


def test_target_order_and_case_do_not_matter() -> None:
    store = _store()
    grant = store.issue("services.terminate", "one", ["PID:42", "pid:7"])
    store.redeem(grant.token, "services.terminate", ["pid:7", "pid:42"])


def test_a_different_target_set_is_refused() -> None:
    store = _store()
    grant = store.issue("services.terminate", "one", ["pid:42"])

    with pytest.raises(consent.Mismatch):
        store.redeem(grant.token, "services.terminate", ["pid:42", "pid:43"])


def test_a_different_action_is_refused() -> None:
    store = _store()
    grant = store.issue("services.terminate", "one", ["pid:42"])

    with pytest.raises(consent.Mismatch):
        store.redeem(grant.token, "firewall.apply", ["pid:42"])


def test_an_unknown_token_is_refused() -> None:
    store = _store()
    with pytest.raises(consent.UnknownToken):
        store.redeem("00" * 16, "services.terminate", [])


def test_an_expired_token_is_refused_and_still_consumed() -> None:
    store = _store(5)
    grant = store.issue("services.terminate", "one", ["pid:42"])
    store._entries[grant.token].grant.expires = datetime.now(timezone.utc) - timedelta(seconds=1)

    with pytest.raises(consent.Expired):
        store.redeem(grant.token, "services.terminate", ["pid:42"])

    with pytest.raises(consent.UnknownToken):
        store.redeem(grant.token, "services.terminate", ["pid:42"])


def test_revoke_removes_a_pending_grant() -> None:
    store = _store()
    grant = store.issue("services.terminate", "one", ["pid:42"])
    assert len(store.pending()) == 1

    store.revoke(grant.token)
    assert store.pending() == []

    with pytest.raises(consent.UnknownToken):
        store.redeem(grant.token, "services.terminate", ["pid:42"])


def test_tokens_are_unique_and_time_boxed() -> None:
    store = _store()
    first = store.issue("services.terminate", "one", ["pid:42"])
    second = store.issue("services.terminate", "one", ["pid:42"])

    assert first.token != second.token
    assert 60 <= (first.expires - first.issued).total_seconds() <= 120
    assert len(first.token) == 32


def test_fingerprint_is_stable() -> None:
    assert consent.fingerprint(["B", "a"]) == consent.fingerprint(["a", "b"])
    assert consent.fingerprint([]) == consent.fingerprint([])
    assert consent.fingerprint(["a"]) != consent.fingerprint(["a", "b"])
