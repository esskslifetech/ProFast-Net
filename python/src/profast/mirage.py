"""The rotating virtual identity.

Wire format and derivation are shared with ``core/internal/mirage`` and
``native/src/mirage.cpp``. Any change here must be mirrored in both, and the
vectors in ``tests/test_mirage.py`` will fail loudly if they drift.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from collections import OrderedDict

LABEL = b"profast-mirage-v1"
SPA_LABEL = b"profast-spa-v1"
TOKEN_LEN = 44
PORT_BASE = 20000
PORT_SPAN = 40000


class MirageError(Exception):
    """Base class for every identity failure."""


class AuthError(MirageError):
    """The token MAC did not verify."""


class ClockError(MirageError):
    """The token epoch is outside the accepted window."""


class TokenError(MirageError):
    """The token is structurally invalid."""


def epoch(now: float, seconds: int) -> int:
    return int(now) // max(1, seconds)


def until_boundary(now: float, seconds: int) -> float:
    span = max(1, seconds)
    return span - (now % span)


def _key(secret: bytes, node_id: int) -> bytes:
    return hmac.new(secret, LABEL + struct.pack(">I", node_id), hashlib.sha256).digest()


def format_v6(raw: bytes) -> str:
    return ":".join(f"{raw[i] << 8 | raw[i + 1]:04x}" for i in range(0, 16, 2))


def derive(secret: bytes, node_id: int, epoch_value: int) -> tuple[str, int]:
    """Return the locator (address, port) for one node and epoch."""
    if len(secret) != 32:
        raise ValueError(f"mirage secret must be 32 bytes, got {len(secret)}")

    material = hmac.new(
        _key(secret, node_id), struct.pack(">Q", epoch_value), hashlib.sha256
    ).digest()

    raw = bytearray(16)
    raw[0] = 0xFD  # fd00::/8 unique local address space
    raw[1:] = material[:15]

    port = PORT_BASE + struct.unpack(">H", material[15:17])[0] % PORT_SPAN
    return format_v6(bytes(raw)), port


def mint(
    secret: bytes, node_id: int, epoch_value: int, nonce: bytes | None = None
) -> tuple[bytes, str, bytes]:
    """Build a Single Packet Authorization token."""
    nonce = nonce if nonce is not None else secrets.token_bytes(16)
    if len(nonce) != 16:
        raise ValueError("nonce must be 16 bytes")

    body = struct.pack(">IQ", node_id, epoch_value) + nonce
    mac = hmac.new(_key(secret, node_id), SPA_LABEL + body, hashlib.sha256).digest()[:16]
    token = body + mac
    return token, base64.urlsafe_b64encode(token).rstrip(b"=").decode("ascii"), nonce


def decode_token(encoded: str) -> bytes:
    padding = "=" * (-len(encoded) % 4)
    try:
        raw = base64.urlsafe_b64decode(encoded + padding)
    except (ValueError, TypeError) as exc:
        raise TokenError("token is not base64url") from exc
    if len(raw) != TOKEN_LEN:
        raise TokenError(f"token must be {TOKEN_LEN} bytes, got {len(raw)}")
    return raw


def verify(
    secret: bytes, encoded: str, now: float, epoch_seconds: int
) -> tuple[int, int]:
    """Validate a token. Accepts one epoch of skew in either direction."""
    raw = decode_token(encoded)
    node_id, token_epoch = struct.unpack(">IQ", raw[:12])
    body, mac = raw[:28], raw[28:]

    expected = hmac.new(_key(secret, node_id), SPA_LABEL + body, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(expected, mac):
        raise AuthError("single packet authorization failed")

    current = epoch(now, epoch_seconds)
    if token_epoch + 1 < current or token_epoch > current + 1:
        raise ClockError("token epoch outside the accepted window")

    return node_id, token_epoch


class ReplayCache:
    """Fixed-capacity cache of accepted (node, nonce) pairs."""

    def __init__(self, capacity: int = 4096) -> None:
        self.capacity = max(16, capacity)
        self._seen: OrderedDict[tuple[int, bytes], None] = OrderedDict()

    def check(self, token: bytes) -> bool:
        """Return True when the token was already used."""
        if len(token) < 28:
            return True
        node_id = struct.unpack(">I", token[:4])[0]
        key = (node_id, token[12:28])
        if key in self._seen:
            return True

        self._seen[key] = None
        while len(self._seen) > self.capacity:
            self._seen.popitem(last=False)
        return False

    def __len__(self) -> int:
        return len(self._seen)
