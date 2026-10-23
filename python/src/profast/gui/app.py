"""Desktop dashboard: ``profast gui``.

The window is a thin shell over the same JSON-RPC surface as the CLI. It
prefers a running daemon and falls back to an in-process engine so the GUI is
useful on a machine that has never run ``profast serve``.
"""

from __future__ import annotations

import sys
from datetime import datetime
from typing import Any

from PySide6.QtCore import QTimer
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .. import config, rpc
from ..engine import Engine
from ..errors import RpcError
from ..version import VERSION
from . import elevate
from .bridge import Bridge
from .pages import (
    DefensePage,
    FirewallPage,
    FocusPage,
    MiragePage,
    OverviewPage,
    ServicesPage,
)
from .theme import PALETTE, apply_theme

POLL_MS = 1000


class Embedded:
    """Keeps the engine alive in-process, and ticks it like the daemon does."""

    def __init__(self) -> None:
        cfg, _created = config.load()
        self._engine = Engine(cfg)

    def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        return self._engine.handle(method, dict(params or {}))

    def tick(self) -> bool:
        return self._engine.tick()

    def close(self) -> None:
        return None


def open_backend(force_embedded: bool = False) -> tuple[Any, str]:
    """Attach to the daemon when one answers, otherwise keep the engine here.

    ``force_embedded`` is what the elevated re-launch asks for: it must not
    attach to a daemon that is still running without the new rights.
    """
    if not force_embedded:
        try:
            return rpc.Client().connect(), "daemon"
        except RpcError:
            pass
    return Embedded(), "embedded"


class MainWindow(QMainWindow):
    def __init__(self, backend: Any, mode: str) -> None:
        super().__init__()
        self.mode = mode
        self.status: dict[str, Any] = {}
        self._status_pending = False

        self.setWindowTitle(f"ProFast-Net {VERSION}")
        self.resize(1180, 760)

        self.bridge = Bridge(backend, self)
        self.bridge.result.connect(self._on_result)
        self.bridge.failed.connect(self._on_failed)

        root = QWidget()
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._build_sidebar())

        self.stack = QStackedWidget()
        self.pages = [
            OverviewPage(self.bridge),
            FocusPage(self.bridge),
            ServicesPage(self.bridge),
            DefensePage(self.bridge),
            MiragePage(self.bridge),
            FirewallPage(self.bridge),
        ]
        for page in self.pages:
            self.stack.addWidget(page)
        layout.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        self.status_label = QLabel("connecting")
        self.statusBar().addWidget(self.status_label)
        self.identity_label = QLabel("")
        self.statusBar().addPermanentWidget(self.identity_label)

        self.nav_buttons[0].setChecked(True)
        self.stack.setCurrentIndex(0)

        for index in range(len(self.pages)):
            shortcut = QShortcut(QKeySequence(f"Ctrl+{index + 1}"), self)
            shortcut.activated.connect(lambda i=index: self._show(i))
        QShortcut(QKeySequence("F5"), self).activated.connect(self._poll)

        self.timer = QTimer(self)
        self.timer.setInterval(POLL_MS)
        self.timer.timeout.connect(self._poll)
        self.timer.start()

        self._poll()
        self.pages[0].refresh()
        self._paint_elevation()

    # -------------------------------------------------------------------- chrome
    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(196)
        column = QVBoxLayout(sidebar)
        column.setContentsMargins(0, 0, 0, 12)
        column.setSpacing(0)

        brand = QLabel("ProFast-Net")
        brand.setObjectName("Brand")
        column.addWidget(brand)
        subtitle = QLabel("focus · rotate · defend")
        subtitle.setObjectName("BrandSub")
        column.addWidget(subtitle)

        self.nav_buttons: list[QPushButton] = []
        group = QButtonGroup(self)
        group.setExclusive(True)
        for index, label in enumerate(
            ("Overview", "Focus", "Services", "Defence", "Identity", "Firewall")
        ):
            button = QPushButton(f"  {label}")
            button.setObjectName("Nav")
            button.setCheckable(True)
            button.clicked.connect(lambda _checked=False, i=index: self._show(i))
            group.addButton(button)
            column.addWidget(button)
            self.nav_buttons.append(button)

        column.addStretch(1)
        # Two lines: the full wording does not fit a 196px sidebar on one.
        self.elevate_button = QPushButton("Ask for Administrative\nPermissions")
        self.elevate_button.setObjectName("Elevate")
        self.elevate_button.setVisible(elevate.supported())
        self.elevate_button.clicked.connect(self._ask_for_admin)
        column.addWidget(self.elevate_button)

        footer = QLabel(f"v{VERSION} · {self.mode}")
        footer.setObjectName("BrandSub")
        column.addWidget(footer)
        return sidebar

    def _show(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        self.nav_buttons[index].setChecked(True)
        page = self.pages[index]
        page.refresh()
        if self.status:
            page.apply_status(self.status)

    # ------------------------------------------------------------------- polling
    def _poll(self) -> None:
        if self._status_pending:
            return
        self._status_pending = True
        self.bridge.request("status", "core.status")
        self.bridge.request("events", "core.events", {"limit": 40})
        self.bridge.task("tick", lambda backend: getattr(backend, "tick", lambda: False)())

    def _on_result(self, tag: str, payload: object) -> None:
        if tag == "status":
            self._status_pending = False
            self.status = dict(payload or {})  # type: ignore[arg-type]
            self._paint_status()
            return
        if tag == "events":
            self.pages[0].apply_events(list(payload or []))  # type: ignore[arg-type]
            return

    def _on_failed(self, tag: str, message: str) -> None:
        if tag == "status":
            self._status_pending = False
            self.status_label.setText(f"daemon error: {message}")
            self.status_label.setStyleSheet(f"color: {PALETTE['bad']};")

    def _paint_status(self) -> None:
        mirage = self.status.get("mirage", {})
        address = f"{mirage.get('virtual_address', '-')}:{mirage.get('port', '-')}"
        stamp = datetime.now().strftime("%H:%M:%S")
        elevated = "elevated" if self.status.get("elevated") else "user"
        self.status_label.setText(
            f"{self.mode} · {elevated} · {self.status.get('kernel_tier', '')} · updated {stamp}"
        )
        self.status_label.setStyleSheet(f"color: {PALETTE['muted']};")
        self.identity_label.setText(address)
        self._paint_elevation()

        page = self.pages[self.stack.currentIndex()]
        page.apply_status(self.status)

    def _paint_elevation(self) -> None:
        # Already holding the rights: the control has nothing left to ask for.
        if self._has_admin():
            self.elevate_button.setEnabled(False)
            self.elevate_button.setToolTip("Already running with administrator rights.")
            return
        self.elevate_button.setEnabled(True)
        self.elevate_button.setToolTip(
            "Restart ProFast-Net with administrator rights so firewall rules, QoS "
            "policies and service termination are permitted."
        )

    def _has_admin(self) -> bool:
        """Whether the process that runs the engine holds administrator rights."""
        if "elevated" in self.status:
            return bool(self.status["elevated"])
        # Nothing reported yet. Only an in-process engine follows this window's
        # token; a daemon keeps its own, whatever this window was started with.
        return self.mode == "embedded" and elevate.is_elevated()

    def _ask_for_admin(self) -> None:
        """Re-launch elevated. A process cannot promote itself, so this starts a
        second copy with a fresh UAC token and closes this one."""
        if self._has_admin():
            return

        intro = (
            "Windows will ask you to confirm. This window closes and reopens with "
            "administrator rights, which lets ProFast-Net install firewall rules, set "
            "QoS policies and stop services."
        )
        if self.mode == "daemon":
            intro += (
                "\n\nThis window is served by a daemon without administrator rights. "
                "Privileges belong to the process that runs the engine, so that daemon "
                "is stopped and the elevated window runs the engine itself."
            )

        box = QMessageBox(self)
        box.setWindowTitle("Ask for Administrative Permissions")
        box.setIcon(QMessageBox.Icon.Question)
        box.setText(intro)
        ask = box.addButton("Ask for permission", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() is not ask:
            return

        # --embedded wins over a daemon that is still alive during the handover.
        ok, message = elevate.relaunch(sys.argv, extra=["--embedded"])
        if not ok:
            self.status_label.setText(message)
            self.status_label.setStyleSheet(f"color: {PALETTE['bad']};")
            return
        if self.mode == "daemon":
            stopped, detail = elevate.stop_daemon()
            if not stopped:
                QMessageBox.warning(self, "Daemon still running", detail)
        self.close()

    # ------------------------------------------------------------------- shutdown
    def closeEvent(self, event: object) -> None:  # noqa: N802 - Qt naming
        self.timer.stop()
        self.bridge.close()
        super().closeEvent(event)  # type: ignore[arg-type]


def run(argv: list[str] | None = None, force_embedded: bool = False) -> int:
    application = QApplication.instance() or QApplication(argv or sys.argv)
    application.setApplicationName("ProFast-Net")
    application.setApplicationDisplayName("ProFast-Net")
    apply_theme(application)

    backend, mode = open_backend(force_embedded)
    window = MainWindow(backend, mode)
    window.show()
    return int(application.exec())


if __name__ == "__main__":
    raise SystemExit(run())
