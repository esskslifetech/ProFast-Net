"""JSON-RPC client used by the CLI, the dashboard and the GUI."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

from . import config
from .errors import INTERNAL_ERROR, UNAVAILABLE, RpcError


def read_endpoint(path: Path | None = None) -> dict[str, Any] | None:
    target = Path(path) if path else config.endpoint_path()
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def daemon_available(path: Path | None = None) -> bool:
    return read_endpoint(path) is not None


class Client:
    """One connection, one handshake, many calls."""

    def __init__(self, endpoint_path: Path | None = None, timeout: float = 15.0) -> None:
        self.endpoint_path = Path(endpoint_path) if endpoint_path else config.endpoint_path()
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._file: Any = None
        self._id = 0
        self.info: dict[str, Any] = {}

    # ------------------------------------------------------------- lifecycle
    def connect(self) -> Client:
        endpoint = read_endpoint(self.endpoint_path)
        if endpoint is None:
            raise RpcError(UNAVAILABLE, "no daemon endpoint found; start one with `profast serve`")

        try:
            if endpoint.get("network") == "unix":
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect(endpoint["address"])
            else:
                host, port = str(endpoint["address"]).rsplit(":", 1)
                sock = socket.create_connection((host, int(port)), timeout=self.timeout)
        except OSError as exc:
            raise RpcError(UNAVAILABLE, f"daemon is not reachable: {exc}") from exc

        self._sock = sock
        self._file = sock.makefile("rwb")

        reply = self._exchange(
            {"jsonrpc": "2.0", "id": 0, "method": "auth", "pf_auth": endpoint.get("token", "")}
        )
        if "error" in reply:
            self.close()
            raise RpcError(
                reply["error"].get("code", UNAVAILABLE),
                reply["error"].get("message", "handshake rejected"),
            )
        self.info = reply.get("result", {})
        return self

    def close(self) -> None:
        if self._file is not None:
            try:
                self._file.close()
            except OSError:
                pass
            self._file = None
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def __enter__(self) -> Client:
        return self.connect()

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ calls
    def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        if self._sock is None:
            self.connect()

        self._id += 1
        request: dict[str, Any] = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params:
            request["params"] = params

        reply = self._exchange(request)
        if "error" in reply:
            error = reply["error"]
            raise RpcError(error.get("code", INTERNAL_ERROR), error.get("message", "call failed"))
        return reply.get("result")

    def ping(self) -> dict[str, Any]:
        return self.call("core.ping")

    # ---------------------------------------------------------------- private
    def _exchange(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._file is None:
            raise RpcError(UNAVAILABLE, "client is not connected")
        try:
            self._file.write(json.dumps(payload).encode("utf-8") + b"\n")
            self._file.flush()
            line = self._file.readline()
        except OSError as exc:
            raise RpcError(UNAVAILABLE, f"connection lost: {exc}") from exc

        if not line:
            raise RpcError(UNAVAILABLE, "daemon closed the connection")
        try:
            return json.loads(line)
        except ValueError as exc:
            raise RpcError(INTERNAL_ERROR, "daemon sent malformed JSON") from exc
