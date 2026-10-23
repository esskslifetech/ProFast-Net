"""Colours and the stylesheet for the desktop dashboard.

One dark palette, defined once. Widgets never hard-code a colour; they ask for
a role name so the whole window can be re-themed in a single place.
"""

from __future__ import annotations

PALETTE = {
    "bg": "#0b0f14",
    "bg_alt": "#111823",
    "panel": "#141c27",
    "panel_alt": "#1a2431",
    "border": "#243243",
    "text": "#dbe4ee",
    "muted": "#7d8fa3",
    "accent": "#22d3ee",
    "accent_dim": "#0e7490",
    "good": "#34d399",
    "warn": "#fbbf24",
    "bad": "#f87171",
    "critical": "#fb7185",
}

LEVEL_COLORS = {
    "critical": PALETTE["critical"],
    "high": PALETTE["bad"],
    "medium": PALETTE["warn"],
    "low": PALETTE["muted"],
}

STYLESHEET = """
/* No fill on the universal selector: a QWidget background also paints every
   QLabel and bare layout holder with the page colour, which punches dark
   rectangles through the rounded cards. Only top-level surfaces are filled. */
QWidget {
    color: %(text)s;
    font-family: "Segoe UI", "Inter", "Helvetica Neue", Arial, sans-serif;
    font-size: 13px;
}
QMainWindow, QDialog { background-color: %(bg)s; }
QLabel, QCheckBox { background: transparent; }

QWidget#Sidebar {
    background-color: %(bg_alt)s;
    border-right: 1px solid %(border)s;
}
QLabel#Brand {
    color: %(accent)s;
    font-size: 17px;
    font-weight: 700;
    padding: 18px 16px 4px 16px;
}
QLabel#BrandSub {
    color: %(muted)s;
    font-size: 11px;
    padding: 0 16px 16px 16px;
}

QPushButton#Nav {
    background: transparent;
    border: none;
    border-left: 3px solid transparent;
    padding: 9px 14px;
    text-align: left;
    color: %(muted)s;
}
QPushButton#Nav:hover { color: %(text)s; background-color: %(panel)s; }
QPushButton#Nav:checked {
    color: %(text)s;
    border-left: 3px solid %(accent)s;
    background-color: %(panel)s;
    font-weight: 600;
}

QFrame#Card {
    background-color: %(panel)s;
    border: 1px solid %(border)s;
    border-radius: 10px;
}
QLabel#CardTitle {
    color: %(muted)s;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1px;
}
QLabel#CardValue {
    color: %(text)s;
    font-size: 22px;
    font-weight: 700;
}
QLabel#CardValueMono {
    font-family: "Cascadia Mono", "Consolas", "SF Mono", monospace;
    color: %(text)s;
    font-size: 14px;
    font-weight: 600;
}
QLabel#CardHint { color: %(muted)s; font-size: 11px; }
QLabel#Mono {
    font-family: "Cascadia Mono", "Consolas", "SF Mono", monospace;
    color: %(accent)s;
    font-size: 15px;
}
QLabel#PageTitle { font-size: 20px; font-weight: 700; }
QLabel#PageHint { color: %(muted)s; }

QPushButton {
    background-color: %(panel_alt)s;
    border: 1px solid %(border)s;
    border-radius: 6px;
    padding: 7px 14px;
}
QPushButton:hover { border-color: %(accent_dim)s; }
QPushButton:disabled { color: %(muted)s; border-color: %(border)s; }
QPushButton#Primary {
    background-color: %(accent_dim)s;
    border-color: %(accent)s;
    color: #04171d;
    font-weight: 600;
}
QPushButton#Primary:hover { background-color: %(accent)s; }
QPushButton#Danger {
    background-color: #7f1d1d;
    border-color: %(bad)s;
    color: #fee2e2;
    font-weight: 600;
}
QPushButton#Danger:hover { background-color: #991b1b; }
QPushButton#Elevate {
    background-color: %(panel_alt)s;
    border: 1px solid %(accent_dim)s;
    color: %(accent)s;
    font-size: 11px;
    font-weight: 600;
    padding: 9px 8px;
    margin: 0 12px 10px 12px;
    border-radius: 6px;
}
QPushButton#Elevate:hover { background-color: %(panel)s; border-color: %(accent)s; }
QPushButton#Elevate:disabled {
    background: transparent;
    color: %(muted)s;
    border-color: %(border)s;
}

QLineEdit, QSpinBox, QComboBox, QPlainTextEdit, QListWidget, QTableWidget {
    background-color: %(panel)s;
    border: 1px solid %(border)s;
    border-radius: 6px;
    selection-background-color: %(accent_dim)s;
    selection-color: %(text)s;
}
QLineEdit, QSpinBox, QComboBox { padding: 6px 8px; }
QPlainTextEdit { font-family: "Cascadia Mono", "Consolas", monospace; font-size: 12px; }

QTableWidget { gridline-color: %(border)s; }
QTableWidget::item { padding: 5px 6px; }
QTableWidget::item:selected { background-color: %(panel_alt)s; color: %(text)s; }
QHeaderView::section {
    background-color: %(bg_alt)s;
    color: %(muted)s;
    border: none;
    border-bottom: 1px solid %(border)s;
    padding: 6px;
    font-weight: 600;
}

QListWidget { border: none; }
QListWidget::item { padding: 7px 4px; border-bottom: 1px solid %(border)s; }

QCheckBox { spacing: 8px; }
QStatusBar { background-color: %(bg_alt)s; color: %(muted)s; border-top: 1px solid %(border)s; }
QToolTip {
    background-color: %(panel_alt)s;
    color: %(text)s;
    border: 1px solid %(border)s;
    padding: 4px;
}
QSplitter::handle { background-color: %(border)s; }
"""


def stylesheet() -> str:
    return STYLESHEET % PALETTE


def level_color(level: str) -> str:
    return LEVEL_COLORS.get(level, PALETTE["muted"])


def apply_theme(app: object) -> None:
    """Apply the palette to a QApplication (duck-typed to keep the import lazy)."""
    app.setStyleSheet(stylesheet())  # type: ignore[attr-defined]
