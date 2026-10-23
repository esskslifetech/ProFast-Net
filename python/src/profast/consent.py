"""Confirmation tokens for destructive actions.

Mirrors ``core/internal/consent``. The daemon refuses to terminate anything
without a token that was issued for the exact same process set and has not
expired or been redeemed.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .models import Grant


class ConsentError(Exception):
    """Base class for confirmation failures."""


class UnknownToken(ConsentError):
    pass


class Expired(ConsentError):
    pass


class Mismatch(ConsentError):
    pass


def fingerprint(targets: Iterable[str]) -> str:
    normalised = sorted(str(t).strip().lower() for t in targets)
    return hashlib.sha256("\x00".join(normalised).encode()).hexdigest()


@dataclass
class _Entry:
    grant: Grant
    print: str


class Store:
    """Pending confirmations. Never persisted: a restart invalidates them."""

    def __init__(self, ttl_seconds: int = 90) -> None:
        self.ttl = timedelta(seconds=max(5, ttl_seconds))
        self._lock = threading.Lock()
        self._entries: dict[str, _Entry] = {}

    def issue(self, action: str, summary: str, targets: list[str]) -> Grant:
        now = datetime.now(timezone.utc)
        grant = Grant(
            token=secrets.token_hex(16),
            action=action,
            targets=list(targets),
            summary=summary,
            issued=now,
            expires=now + self.ttl,
        )
        with self._lock:
            self._entries[grant.token] = _Entry(grant=grant, print=fingerprint(targets))
            self._prune(now)
        return grant

    def redeem(self, token: str, action: str, targets: list[str]) -> None:
        with self._lock:
            entry = self._entries.pop(token, None)
        if entry is None:
            raise UnknownToken("unknown or already used confirmation token")
        if datetime.now(timezone.utc) > entry.grant.expires:
            raise Expired("confirmation expired, ask the user again")
        if entry.grant.action != action:
            raise Mismatch("confirmation was issued for a different action")
        if entry.print != fingerprint(targets):
            raise Mismatch("confirmation was issued for a different target set")

    def revoke(self, token: str) -> None:
        with self._lock:
            self._entries.pop(token, None)

    def pending(self) -> list[Grant]:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._prune(now)
            return [entry.grant for entry in self._entries.values()]

    def _prune(self, now: datetime) -> None:
        for token in [t for t, e in self._entries.items() if now > e.grant.expires]:
            del self._entries[token]
