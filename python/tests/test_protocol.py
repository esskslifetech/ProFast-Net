"""The control protocol: handshake, error codes, consent enforcement.

These tests start a real daemon on a real socket (loopback TCP on Windows, a
unix socket elsewhere) and talk to it with the same client the CLI and GUI use.
"""

from __future__ import annotations

import json
import secrets
import threading
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest

from profast import config, daemon, errors, native, rpc
from profast.engine import Engine
from profast.errors import RpcError
from profast.version import PROTOCOL_VERSION, VERSION

# ------------------------------------------------------------------------ daemon


@pytest.fixture()
def running(tmp_path: Path) -> Iterator[SimpleNamespace]:
    settings = config.defaults()
    engine = Engine(settings)

    endpoint = tmp_path / "endpoint.json"
    server, advertised = daemon._make_server(endpoint)
    network, address = advertised.split("://", 1)
    token = secrets.token_hex(32)

    server.engine = engine  # type: ignore[attr-defined]
    server.token = token  # type: ignore[attr-defined]
    daemon._write_endpoint(endpoint, network, address, token)

    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
    )
    thread.start()
    try:
        yield SimpleNamespace(
            endpoint=endpoint, address=address, network=network, token=token, engine=engine
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        endpoint.unlink(missing_ok=True)


def _client(running: SimpleNamespace) -> rpc.Client:
    return rpc.Client(endpoint_path=running.endpoint).connect()


def test_handshake_reports_the_protocol_version(running: SimpleNamespace) -> None:
    with _client(running) as client:
        assert client.info["protocol"] == PROTOCOL_VERSION
        assert client.info["version"] == VERSION

        pong = client.ping()
        assert pong["ok"] is True
        assert pong["protocol"] == PROTOCOL_VERSION


def test_status_has_the_sections_the_ui_reads(running: SimpleNamespace) -> None:
    with _client(running) as client:
        status = client.call("core.status")

    assert status["version"] == VERSION
    assert {"mirage", "focus", "defense", "firewall", "scan"} <= set(status)
    assert len(status["mirage"]["virtual_address"].split(":")) == 8
    assert status["mirage"]["port"] >= 20000


def test_unknown_method_returns_method_not_found(running: SimpleNamespace) -> None:
    with _client(running) as client:
        with pytest.raises(RpcError) as info:
            client.call("core.does_not_exist")
    assert info.value.code == errors.METHOD_NOT_FOUND


def test_termination_without_a_token_is_refused(running: SimpleNamespace) -> None:
    with _client(running) as client:
        with pytest.raises(RpcError) as info:
            client.call("services.terminate", {"pids": [4242]})
    assert info.value.code == errors.CONSENT_REQUIRED


def test_consent_is_bound_to_the_exact_process_set(running: SimpleNamespace) -> None:
    with _client(running) as client:
        grant = client.call(
            "consent.request",
            {"action": "services.terminate", "summary": "test", "targets": ["pid:4242"]},
        )
        assert len(grant["token"]) == 32
        assert grant["targets"] == ["pid:4242"]

        with pytest.raises(RpcError) as info:
            client.call(
                "services.terminate",
                {"pids": [4242, 4243], "token": grant["token"]},
            )
    assert info.value.code == errors.CONSENT_REQUIRED


def test_privileged_pids_are_refused_before_consent(running: SimpleNamespace) -> None:
    with _client(running) as client:
        with pytest.raises(RpcError) as info:
            client.call("services.terminate", {"pids": [4]})
    assert info.value.code == errors.INVALID_PARAMS


def test_a_bad_control_token_is_rejected(running: SimpleNamespace, tmp_path: Path) -> None:
    forged = tmp_path / "forged.json"
    forged.write_text(
        json.dumps(
            {
                "network": running.network,
                "address": running.address,
                "token": "0" * 64,
                "pid": 1,
                "version": VERSION,
                "protocol": PROTOCOL_VERSION,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(RpcError) as info:
        rpc.Client(endpoint_path=forged).connect()
    assert info.value.code == errors.UNAUTHORIZED


def test_consent_requests_are_recorded_as_events(running: SimpleNamespace) -> None:
    with _client(running) as client:
        client.call(
            "consent.request",
            {"action": "services.terminate", "summary": "test", "targets": ["pid:99"]},
        )
        events = client.call("core.events", {"limit": 10})

    assert any(event["kind"] == "consent" for event in events)


def test_mirage_accept_rejects_a_forged_token(running: SimpleNamespace) -> None:
    with _client(running) as client:
        with pytest.raises(RpcError) as info:
            client.call("mirage.accept", {"token": "A" * 59, "source": "203.0.113.9"})
    assert info.value.code == errors.UNAVAILABLE


def test_mirage_spa_round_trip(running: SimpleNamespace) -> None:
    with _client(running) as client:
        minted = client.call("mirage.spa", {"node_id": 7})
        accepted = client.call(
            "mirage.accept", {"token": minted["token"], "source": "127.0.0.1"}
        )
        peers = client.call("mirage.peers")

        with pytest.raises(RpcError):
            client.call("mirage.accept", {"token": minted["token"], "source": "127.0.0.1"})

    assert accepted["node_id"] == 7
    assert accepted["virtual_address"] == minted["virtual_address"]
    assert [peer["node_id"] for peer in peers] == [7]


def test_capabilities_lists_the_feature_surface(running: SimpleNamespace) -> None:
    with _client(running) as client:
        capabilities = client.call("core.capabilities")

    features = set(capabilities["features"])
    assert {"mirage.rotating-locator", "mirage.spa", "scan.risk"} <= features
    assert capabilities["firewall_backend"] in {"windows", "nft", "pf"}

# ----------------------------------------------------------------- engine shape


def test_engine_reports_the_same_contract_locally() -> None:
    engine = Engine(config.defaults())
    status = engine.status()

    assert status["protocol"] == PROTOCOL_VERSION
    assert status["mirage"]["identity_model"] == "rotating-virtual-locator"
    assert status["focus"] is None
    assert engine.handle("core.ping", {})["ok"] is True


def test_focus_status_is_empty_before_a_session() -> None:
    engine = Engine(config.defaults())
    assert engine.handle("focus.status", {}) is None


def test_stopping_an_idle_focus_session_is_an_error() -> None:
    engine = Engine(config.defaults())
    with pytest.raises(RpcError) as info:
        engine.handle("focus.stop", {})
    assert info.value.code == errors.UNAVAILABLE


# ------------------------------------------------------------------ error codes


def test_error_codes_are_stable() -> None:
    assert errors.PARSE_ERROR == -32700
    assert errors.INVALID_REQUEST == -32600
    assert errors.METHOD_NOT_FOUND == -32601
    assert errors.INVALID_PARAMS == -32602
    assert errors.INTERNAL_ERROR == -32603
    assert errors.CONSENT_REQUIRED == -32001
    assert errors.UNAUTHORIZED == -32002
    assert errors.UNAVAILABLE == -32003
    assert errors.ELEVATION_REQUIRED == -32004


# ------------------------------------------------------------------- DSCP bridge


@pytest.mark.parametrize(
    ("text", "value"),
    [("ef", 46), ("EF", 46), ("cs1", 8), ("background", 8), ("af41", 34), ("0", 0), ("63", 63)],
)
def test_dscp_names_parse(text: str, value: int) -> None:
    assert native.parse_dscp(text) == value


@pytest.mark.parametrize("text", ["ef2", "-1", "64", "urgent"])
def test_dscp_rejects_nonsense(text: str) -> None:
    with pytest.raises(ValueError):
        native.parse_dscp(text)


# ------------------------------------------------------------------ config file


def test_configuration_round_trips(tmp_path: Path) -> None:
    target = tmp_path / "config.json"
    original = config.defaults()

    config.save(original, target)
    loaded, created = config.load(target)

    assert created is False
    assert loaded.mirage.node_id == original.mirage.node_id
    assert loaded.secret() == original.secret()
    assert loaded.mirage.epoch_seconds == original.mirage.epoch_seconds


def test_configuration_is_clamped_on_load(tmp_path: Path) -> None:
    target = tmp_path / "config.json"
    raw = config.defaults().to_dict()
    raw["mirage"]["epoch_seconds"] = 10_000
    raw["defense"]["ban_threshold"] = -5
    target.write_text(json.dumps(raw), encoding="utf-8")

    loaded, _created = config.load(target)
    assert loaded.mirage.epoch_seconds == 300
    assert loaded.defense.ban_threshold >= 1


def test_a_missing_secret_is_reported() -> None:
    settings = config.defaults()
    settings.mirage.secret_hex = "abcd"
    with pytest.raises(ValueError):
        settings.secret()
