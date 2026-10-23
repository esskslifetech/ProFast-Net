"""Asynchronous JSON-RPC bridge for the GUI.

Every backend call is blocking (a socket round-trip, or a process scan), so the
window never calls the backend directly. A single worker thread owns the
connection and results are delivered back to the GUI thread by signal.
"""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QThread, Signal

JOB_TIMEOUT = 30.0


class _Worker(QThread):
    done = Signal(int, object)
    failed = Signal(int, str)

    def __init__(self, backend: Any) -> None:
        super().__init__()
        self._backend = backend
        self._jobs: queue.Queue[tuple[int, Any, dict[str, Any]]] = queue.Queue()
        self._stop = threading.Event()

    def submit(self, job_id: int, target: Any, params: dict[str, Any] | None = None) -> None:
        self._jobs.put((job_id, target, dict(params or {})))

    def stop(self) -> None:
        self._stop.set()
        self._jobs.put((-1, None, {}))

    def run(self) -> None:  # noqa: D102 - QThread entry point
        while not self._stop.is_set():
            try:
                job_id, target, params = self._jobs.get(timeout=0.2)
            except queue.Empty:
                continue
            if job_id < 0:
                break
            try:
                if callable(target):
                    value = target(self._backend)
                else:
                    value = self._backend.call(str(target), params)
            except Exception as exc:  # noqa: BLE001 - surfaced in the UI
                self.failed.emit(job_id, f"{exc}")
                continue
            self.done.emit(job_id, value)


class Bridge(QObject):
    """Request/response plumbing with tags instead of futures.

    ``request("status", "core.status")`` eventually emits ``result("status", …)``
    or ``failed("status", "…")``. Pages connect once and filter on the tag.
    """

    result = Signal(str, object)
    failed = Signal(str, str)
    connection_lost = Signal(str)

    def __init__(self, backend: Any, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.backend = backend
        self._worker = _Worker(backend)
        self._tags: dict[int, str] = {}
        self._lock = threading.Lock()
        self._next_id = 1
        self._worker.done.connect(self._on_done)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    # ------------------------------------------------------------------ submit
    def request(self, tag: str, method: str, params: dict[str, Any] | None = None) -> None:
        self._enqueue(tag, method, params)

    def task(self, tag: str, fn: Callable[[Any], Any]) -> None:
        """Run an arbitrary callable against the backend inside the worker."""
        self._enqueue(tag, fn, None)

    def _enqueue(self, tag: str, target: Any, params: dict[str, Any] | None) -> None:
        with self._lock:
            job_id = self._next_id
            self._next_id += 1
            self._tags[job_id] = tag
        self._worker.submit(job_id, target, params)

    # ------------------------------------------------------------------ results
    def _on_done(self, job_id: int, value: object) -> None:
        tag = self._pop(job_id)
        if tag:
            self.result.emit(tag, value)

    def _on_failed(self, job_id: int, message: str) -> None:
        tag = self._pop(job_id)
        if tag:
            self.failed.emit(tag, message)

    def _pop(self, job_id: int) -> str:
        with self._lock:
            return self._tags.pop(job_id, "")

    # ---------------------------------------------------------------- lifecycle
    def close(self) -> None:
        self._worker.stop()
        self._worker.wait(3000)
        close = getattr(self.backend, "close", None)
        if callable(close):
            close()
