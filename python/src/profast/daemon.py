"""Reference ProFast-Net daemon.

This is the Python twin of ``core/cmd/profastd``: same endpoint file, same
handshake, same JSON-RPC methods. Use it when the Go binary is not built, or as
the debugging counterpart when comparing behaviour across implementations.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import secrets
import signal
import socketserver
import sys
import threading
from pathlib import Path
from typing import Any

from . import config
from .engine import Engine
from .errors import (
    INTERNAL_ERROR,
    INVALID_REQUEST,
    PARSE_ERROR,
    UNAUTHORIZED,
    RpcError,
)
from .version import PROTOCOL_VERSION, VERSION


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        first = self.rfile.readline()
        if not first:
            return
        try:
            hello = json.loads(first)
        except ValueError:
            self._write({"jsonrpc": "2.0", "error": _error(PARSE_ERROR, "malformed handshake")})
            return

        if not hmac.compare_digest(str(hello.get("pf_auth", "")), self.server.token):  # type: ignore[attr-defined]
            self._write(
                {
                    "jsonrpc": "2.0",
                    "id": hello.get("id"),
                    "error": _error(UNAUTHORIZED, "invalid control token"),
                }
            )
            return

        self._write(
            {
                "jsonrpc": "2.0",
                "id": hello.get("id"),
                "result": {"ok": True, "version": VERSION, "protocol": PROTOCOL_VERSION},
            }
        )

        for raw in self.rfile:
            if not raw.strip():
                continue
            try:
                request = json.loads(raw)
            except ValueError:
                self._write({"jsonrpc": "2.0", "error": _error(PARSE_ERROR, "malformed JSON")})
                continue

            response = self._dispatch(request)
            if request.get("id") is not None:
                self._write(response)

    def _dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        request_id = request.get("id")
        method = request.get("method")
        if not isinstance(method, str) or not method:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": _error(INVALID_REQUEST, "missing method"),
            }

        params = request.get("params") or {}
        if not isinstance(params, dict):
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": _error(INVALID_REQUEST, "params must be an object"),
            }

        try:
            result = self.server.engine.handle(method, params)  # type: ignore[attr-defined]
        except RpcError as exc:
            return {"jsonrpc": "2.0", "id": request_id, "error": exc.to_dict()}
        except Exception as exc:  # noqa: BLE001 - the daemon must never die on a call
            return {"jsonrpc": "2.0", "id": request_id, "error": _error(INTERNAL_ERROR, str(exc))}

        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _write(self, payload: dict[str, Any]) -> None:
        try:
            self.wfile.write(json.dumps(payload).encode("utf-8") + b"\n")
            self.wfile.flush()
        except OSError:
            pass


def _error(code: int, message: str) -> dict[str, Any]:
    return {"code": code, "message": message}


def _make_server(endpoint_path: Path) -> tuple[socketserver.BaseServer, str]:
    endpoint_path.parent.mkdir(parents=True, exist_ok=True)

    if os.name == "nt":
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
        server.daemon_threads = True
        host, port = server.server_address[:2]
        address = f"{host}:{port}"
        network = "tcp"
    else:
        socket_path = endpoint_path.parent / "daemon.sock"
        if socket_path.exists():
            socket_path.unlink()
        thread_server = socketserver.ThreadingUnixStreamServer
        server = thread_server(str(socket_path), _Handler)
        server.daemon_threads = True
        os.chmod(socket_path, 0o600)
        address = str(socket_path)
        network = "unix"

    return server, f"{network}://{address}"


def _write_endpoint(path: Path, network: str, address: str, token: str) -> None:
    payload = {
        "network": network,
        "address": address,
        "token": token,
        "pid": os.getpid(),
        "version": VERSION,
        "protocol": PROTOCOL_VERSION,
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    try:
        tmp.chmod(0o600)
    except OSError:
        pass
    tmp.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="profastd-py", description="ProFast-Net reference daemon (Python)"
    )
    parser.add_argument("--config", type=Path, help="path to config.json")
    parser.add_argument("--endpoint", type=Path, help="path to the IPC endpoint file")
    parser.add_argument(
        "--no-firewall", action="store_true", help="never touch host firewall rules"
    )
    args = parser.parse_args(argv)

    cfg, created = config.load(args.config)
    if args.no_firewall:
        cfg.firewall.enabled = False
    if created:
        print(f"created default configuration at {config.config_path()}", file=sys.stderr)

    engine = Engine(cfg)
    endpoint_path = args.endpoint or config.endpoint_path()

    server, advertised = _make_server(endpoint_path)
    network, address = advertised.split("://", 1)

    token = secrets.token_hex(32)
    server.engine = engine  # type: ignore[attr-defined]
    server.token = token  # type: ignore[attr-defined]

    _write_endpoint(endpoint_path, network, address, token)

    stop = threading.Event()

    def _shutdown(signum: int, _frame: object) -> None:
        print(f"signal {signum} received, shutting down", file=sys.stderr)
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _shutdown)
        except (ValueError, OSError):  # not on the main thread, or unsupported
            pass

    def _ticker() -> None:
        while not stop.wait(1.0):
            try:
                engine.tick()
            except Exception as exc:  # noqa: BLE001
                print(f"tick failed: {exc}", file=sys.stderr)

    threading.Thread(target=_ticker, daemon=True).start()

    print(
        f"profastd-py {VERSION} ready on {advertised}\n"
        f"  endpoint: {endpoint_path}\n"
        f"  node: {cfg.mirage.node_name} ({cfg.mirage.node_id})\n"
        f"  elevated: {engine.status()['elevated']}",
        file=sys.stderr,
    )

    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        endpoint_path.unlink(missing_ok=True)
        if network == "unix":
            Path(address).unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
