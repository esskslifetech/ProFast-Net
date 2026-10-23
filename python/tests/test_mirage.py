"""Known-answer tests for the rotating identity.

The vectors here are the contract between C++, Go and Python. ``pfbench
selftest`` prints exactly these values, so if any implementation drifts the
suite fails on the same numbers a developer can reproduce with the native tool.
"""

from __future__ import annotations

import pytest

from profast import mirage

SECRET = bytes(range(32))
NONCE = bytes(range(16))

# Produced by `pfbench selftest` and pinned by native/tests/native_tests.cpp.
NODE_ID = 1
EPOCH = 1000
ADDRESS = "fd41:ae7d:9004:782d:a2d2:c2ca:7166:0e99"
PORT = 35239
TOKEN = "AAAAAQAAAAAAAAPoAAECAwQFBgcICQoLDA0OD_xKMVWkDMvZK13nmJsm1YE"
RAW_HEX = (
    "0000000100000000000003e8000102030405060708090a0b0c0d0e0f"
    "fc4a3155a40ccbd92b5de7989b26d581"
)


def test_derive_matches_the_native_vector() -> None:
    address, port = mirage.derive(SECRET, NODE_ID, EPOCH)
    assert address == ADDRESS
    assert port == PORT


def test_derivation_is_a_pure_function_of_epoch() -> None:
    first = mirage.derive(SECRET, NODE_ID, EPOCH)
    second = mirage.derive(SECRET, NODE_ID, EPOCH)
    third = mirage.derive(SECRET, NODE_ID, EPOCH + 1)
    assert first == second
    assert first != third


def test_address_stays_inside_the_ula_prefix() -> None:
    for node in (0, 1, 7, 2**32 - 1):
        for step in range(8):
            address, port = mirage.derive(SECRET, node, EPOCH + step)
            assert address.startswith("fd")
            assert len(address.split(":")) == 8
            assert mirage.PORT_BASE <= port < mirage.PORT_BASE + mirage.PORT_SPAN


def test_secret_length_is_enforced() -> None:
    with pytest.raises(ValueError):
        mirage.derive(b"short", NODE_ID, EPOCH)


def test_mint_matches_the_native_vector() -> None:
    raw, encoded, nonce = mirage.mint(SECRET, NODE_ID, EPOCH, NONCE)
    assert nonce == NONCE
    assert encoded == TOKEN
    assert raw.hex() == RAW_HEX
    assert len(encoded) == 59  # 44 raw bytes -> 59 unpadded base64url characters


def test_mint_uses_a_fresh_nonce_by_default() -> None:
    _, first, _ = mirage.mint(SECRET, NODE_ID, EPOCH)
    _, second, _ = mirage.mint(SECRET, NODE_ID, EPOCH)
    assert first != second


def test_verify_returns_the_node_and_epoch() -> None:
    now = EPOCH * 10 + 4
    node_id, token_epoch = mirage.verify(SECRET, TOKEN, now, 10)
    assert (node_id, token_epoch) == (NODE_ID, EPOCH)


def test_verify_tolerates_one_epoch_of_skew() -> None:
    one_ahead = (EPOCH + 1) * 10 + 1
    one_behind = (EPOCH - 1) * 10 + 9
    assert mirage.verify(SECRET, TOKEN, one_ahead, 10)[1] == EPOCH
    assert mirage.verify(SECRET, TOKEN, one_behind, 10)[1] == EPOCH


def test_verify_rejects_stale_and_future_tokens() -> None:
    with pytest.raises(mirage.ClockError):
        mirage.verify(SECRET, TOKEN, (EPOCH + 3) * 10, 10)
    with pytest.raises(mirage.ClockError):
        mirage.verify(SECRET, TOKEN, (EPOCH - 3) * 10, 10)


def test_verify_rejects_a_foreign_secret() -> None:
    other = bytes(reversed(range(32)))
    with pytest.raises(mirage.AuthError):
        mirage.verify(other, TOKEN, EPOCH * 10, 10)


def test_verify_rejects_a_tampered_body() -> None:
    raw = bytearray(bytes.fromhex(RAW_HEX))
    raw[5] ^= 0x01
    tampered = __import__("base64").urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
    with pytest.raises(mirage.AuthError):
        mirage.verify(SECRET, tampered, EPOCH * 10, 10)


@pytest.mark.parametrize("token", ["", "not base64!", "AAAA", "a" * 58])
def test_verify_rejects_structurally_bad_tokens(token: str) -> None:
    with pytest.raises(mirage.TokenError):
        mirage.verify(SECRET, token, EPOCH * 10, 10)


def test_replay_cache_remembers_a_token_once() -> None:
    raw, _, _ = mirage.mint(SECRET, NODE_ID, EPOCH, NONCE)
    cache = mirage.ReplayCache(64)
    assert cache.check(raw) is False
    assert cache.check(raw) is True
    assert len(cache) == 1


def test_replay_cache_is_bounded() -> None:
    cache = mirage.ReplayCache(16)
    for index in range(40):
        cache.check(mirage.mint(SECRET, NODE_ID, EPOCH, index.to_bytes(16, "big"))[0])
    assert len(cache) == 16


def test_epoch_helpers() -> None:
    assert mirage.epoch(0, 10) == 0
    assert mirage.epoch(9.99, 10) == 0
    assert mirage.epoch(10, 10) == 1
    assert mirage.until_boundary(0, 10) == 10
    assert mirage.until_boundary(9.5, 10) == pytest.approx(0.5)
    assert mirage.until_boundary(11, 10) == 9.0
