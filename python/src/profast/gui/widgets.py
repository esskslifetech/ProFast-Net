"""Reusable Qt widgets for the ProFast dashboard."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..models import Service
from .theme import PALETTE, level_color


def title(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("PageTitle")
    return label


def hint(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("PageHint")
    label.setWordWrap(True)
    return label


def button_row(*widgets: QWidget) -> QWidget:
    holder = QWidget()
    layout = QHBoxLayout(holder)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(8)
    for widget in widgets:
        layout.addWidget(widget)
    layout.addStretch(1)
    return holder


class Card(QFrame):
    """A titled panel. Subclasses or callers fill ``body``."""

    def __init__(self, heading: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 14, 16, 16)
        outer.setSpacing(8)

        self.heading = QLabel(heading.upper())
        self.heading.setObjectName("CardTitle")
        # A Preferred label absorbs the card's spare vertical space and then
        # centres its own text, which floats the title into the middle of the
        # card. Pin it to its hint height instead.
        self.heading.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        outer.addWidget(self.heading)

        self.body = QVBoxLayout()
        self.body.setSpacing(6)
        outer.addLayout(self.body)


class StatTile(Card):
    """A single number with a caption, for the top of the overview."""

    def __init__(
        self, caption: str, value: str = "-", footnote: str = "", compact: bool = False
    ) -> None:
        super().__init__(caption)
        self._value = QLabel(value)
        # A 42-character IPv6 locator needs the smaller monospace face.
        self._value.setObjectName("CardValueMono" if compact else "CardValue")
        self._value.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._footnote = QLabel(footnote)
        self._footnote.setObjectName("CardHint")
        self._footnote.setWordWrap(True)

        self.body.addWidget(self._value)
        self.body.addWidget(self._footnote)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_value(self, value: str, footnote: str | None = None, color: str | None = None) -> None:
        self._value.setText(value)
        self._value.setStyleSheet(f"color: {color};" if color else "")
        if footnote is not None:
            self._footnote.setText(footnote)


class MonoLabel(QLabel):
    def __init__(self, text: str = "") -> None:
        super().__init__(text)
        self.setObjectName("Mono")
        self.setTextInteractionFlags(Qt.TextSelectableByMouse)


class KeyValueList(QWidget):
    """Two-column read-out that grows rows on demand and keeps keys aligned."""

    def __init__(self) -> None:
        super().__init__()
        self._form = QFormLayout(self)
        self._form.setContentsMargins(0, 0, 0, 0)
        self._form.setSpacing(6)
        self._values: dict[str, QLabel] = {}

    def update_rows(self, data: dict[str, Any]) -> None:
        for name, value in data.items():
            label = self._values.get(name)
            if label is None:
                key = QLabel(name)
                key.setStyleSheet(f"color: {PALETTE['muted']};")
                label = QLabel("")
                label.setWordWrap(True)
                label.setTextInteractionFlags(Qt.TextSelectableByMouse)
                self._form.addRow(key, label)
                self._values[name] = label
            label.setText(str(value))


class ServiceTable(QTableWidget):
    COLUMNS = ("Risk", "Port", "Proto", "Binding", "Process", "PID", "Why")

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(0, len(self.COLUMNS), parent)
        self.setHorizontalHeaderLabels(self.COLUMNS)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setAlternatingRowColors(False)
        self.setShowGrid(False)

        header = self.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)

        self._services: list[Service] = []

    def load(self, services: Iterable[Service]) -> None:
        self._services = sorted(list(services), key=lambda svc: -svc.risk)
        self.setRowCount(len(self._services))
        for row, svc in enumerate(self._services):
            badge = QTableWidgetItem(f"{svc.level:<8} {svc.risk:>3}")
            badge.setForeground(QColor(level_color(svc.level)))
            badge.setData(Qt.ItemDataRole.UserRole, svc.pid)

            binding = "all interfaces" if svc.public else svc.address
            cells = (
                badge,
                QTableWidgetItem(str(svc.port)),
                QTableWidgetItem(svc.protocol.upper()),
                QTableWidgetItem(binding),
                QTableWidgetItem(svc.process or "unknown"),
                QTableWidgetItem(str(svc.pid or "-")),
                QTableWidgetItem("; ".join(svc.reasons)),
            )
            for column, cell in enumerate(cells):
                if column != 0:
                    cell.setForeground(QColor(PALETTE["text"]))
                self.setItem(row, column, cell)
            if svc.system:
                for column in range(len(self.COLUMNS)):
                    item = self.item(row, column)
                    if item is not None:
                        item.setToolTip("system process: blocked from termination")

    def services(self) -> list[Service]:
        return self._services

    def selected_services(self) -> list[Service]:
        rows = sorted({index.row() for index in self.selectedIndexes()})
        return [self._services[row] for row in rows if 0 <= row < len(self._services)]


class EventFeed(QListWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWordWrap(True)
        self.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)

    def load(self, events: Iterable[dict[str, Any]]) -> None:
        self.clear()
        for event in events:
            stamp = str(event.get("at", ""))[11:19]
            kind = str(event.get("kind", ""))
            detail = str(event.get("detail", ""))
            item = QListWidgetItem(f"{stamp}  {kind:<9}  {detail}")
            item.setForeground(QColor(PALETTE["muted"]))
            self.addItem(item)


class ConsentDialog(QDialog):
    """The GUI equivalent of the CLI confirmation prompt.

    The dialog returns ``Accepted`` only when the operator both selects the
    processes and ticks the acknowledgement; the daemon then still requires a
    fresh consent token before anything is terminated.
    """

    def __init__(self, services: list[Service], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Confirm termination")
        self.setMinimumWidth(560)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        heading = QLabel("Stop these listening services?")
        heading.setObjectName("PageTitle")
        layout.addWidget(heading)

        lines = QVBoxLayout()
        for svc in services:
            label = QLabel(
                f"• {svc.process or 'unknown'} (pid {svc.pid}) — port {svc.port}/{svc.protocol}"
            )
            label.setWordWrap(True)
            lines.addWidget(label)
        layout.addLayout(lines)

        warning = QLabel(
            "Unsaved work in these applications will be lost. The request is sent to the "
            "daemon with a single-use confirmation token that expires in 90 seconds."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet(f"color: {PALETTE['warn']};")
        layout.addWidget(warning)

        self._ack = QCheckBox("I understand and want to terminate these processes")
        layout.addWidget(self._ack)

        buttons = QDialogButtonBox()
        self._ok = buttons.addButton("Terminate", QDialogButtonBox.ButtonRole.AcceptRole)
        self._ok.setObjectName("Danger")
        self._ok.setEnabled(False)
        cancel = buttons.addButton("Cancel", QDialogButtonBox.ButtonRole.RejectRole)
        cancel.setObjectName("")
        layout.addWidget(buttons)

        self._ack.toggled.connect(self._ok.setEnabled)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
