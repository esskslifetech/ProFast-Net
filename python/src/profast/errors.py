"""JSON-RPC error codes shared by the engine, the daemon and the client."""

from __future__ import annotations

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
CONSENT_REQUIRED = -32001
UNAUTHORIZED = -32002
UNAVAILABLE = -32003
ELEVATION_REQUIRED = -32004


class RpcError(Exception):
    """An error that carries a JSON-RPC code across the wire."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def to_dict(self) -> dict[str, object]:
        return {"code": self.code, "message": self.message}
