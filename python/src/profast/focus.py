"""Focus mode: concentrate the link on one task."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

from . import native
from .config import FocusConfig
from .models import FocusSession, Report


class Manager:
    """Owns the single active focus session."""

    def __init__(self, cfg: FocusConfig) -> None:
        self.cfg = cfg
        self._lock = threading.Lock()
        self._session: FocusSession | None = None

    def start(self, target: str, pid: int = 0, duration_s: int = 0) -> FocusSession:
        if not target and pid <= 0:
            raise ValueError("focus requires an application path or a pid")

        with self._lock:
            if self._session is not None:
                raise RuntimeError("a focus session is already running; stop it first")

        seconds = duration_s if duration_s > 0 else self.cfg.default_duration_s
        report = native.apply_focus(
            app_path=target,
            dscp=46,
            background_dscp=self.cfg.background_dscp,
            throttle_others=self.cfg.throttle_others,
        )

        now = datetime.now(timezone.utc)
        session = FocusSession(
            target=target,
            pid=pid,
            started=now,
            ends_at=now + timedelta(seconds=seconds),
            background_caps=self.cfg.throttle_others,
            applied=list(report.applied),
            skipped=list(report.skipped),
            errors=list(report.errors),
        )

        if pid > 0:
            if self.cfg.boost_priority:
                ok, detail = native.set_priority(pid, 2)
                if ok:
                    session.boosted = True
                else:
                    session.skipped.append(f"process priority: {detail}")
            if self.cfg.disable_eco_qos:
                ok, detail = native.set_power_throttling(pid, True)
                if ok:
                    session.eco_qos_relaxed = True
                elif "Windows" not in detail:
                    session.skipped.append(f"power throttling: {detail}")

        with self._lock:
            self._session = session
        return session

    def stop(self) -> FocusSession:
        with self._lock:
            session = self._session
            self._session = None
        if session is None:
            raise RuntimeError("no focus session is running")

        report: Report = native.revert()
        session.applied.extend(report.applied)
        session.errors.extend(report.errors)

        if session.pid > 0:
            native.set_priority(session.pid, 0)
            native.set_power_throttling(session.pid, False)
        return session

    def status(self) -> dict[str, object] | None:
        with self._lock:
            return self._session.to_dict() if self._session else None

    def expired(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            return self._session is not None and now > self._session.ends_at

    def tick(self) -> bool:
        """Stop the session when its window has elapsed. Returns True if stopped."""
        if not self.expired():
            return False
        try:
            self.stop()
        except RuntimeError:
            return False
        return True
