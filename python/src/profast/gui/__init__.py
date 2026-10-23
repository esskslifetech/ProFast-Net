"""PySide6 desktop dashboard.

Imported lazily by ``profast gui`` so that the CLI keeps working on machines
without Qt. Nothing in this package is imported at CLI start-up.
"""

from __future__ import annotations

__all__ = ["run"]


def run(argv: list[str] | None = None) -> int:
    from .app import run as _run

    return _run(argv)
