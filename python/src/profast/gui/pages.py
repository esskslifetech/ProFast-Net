"""The six dashboard pages. Each page is a passive view: it asks the bridge for
data and renders what comes back. No page talks to the operating system.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..models import Service
from ..render import human_seconds
from .bridge import Bridge
from .theme import PALETTE
from .widgets import (
    Card,
    ConsentDialog,
    EventFeed,
    KeyValueList,
    MonoLabel,
    ServiceTable,
    StatTile,
    button_row,
    hint,
    title,
)


def _item(text: Any) -> QTableWidgetItem:
    item = QTableWidgetItem("" if text is None else str(text))
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    return item


class Page(QWidget):
    """Common plumbing: an inline error banner and tag-routed result handling."""

    def __init__(self, bridge: Bridge, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.bridge = bridge
        self._handlers: dict[str, Callable[[Any], None]] = {}
        self._errors: dict[str, Callable[[str], None]] = {}

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(24, 20, 24, 20)
        self.layout.setSpacing(14)

        self.banner = QLabel("")
        self.banner.setWordWrap(True)
        self.banner.setStyleSheet(
            f"background-color: #3f1d1d; color: {PALETTE['bad']}; "
            "border: 1px solid #7f1d1d; border-radius: 6px; padding: 8px;"
        )
        self.banner.hide()
        self.layout.addWidget(self.banner)

        bridge.result.connect(self._route_result)
        bridge.failed.connect(self._route_error)

    def on(self, tag: str, handler: Callable[[Any], None]) -> None:
        self._handlers[tag] = handler

    def on_error(self, tag: str, handler: Callable[[str], None]) -> None:
        self._errors[tag] = handler

    def _route_result(self, tag: str, payload: object) -> None:
        handler = self._handlers.get(tag)
        if handler is not None:
            self.banner.hide()
            handler(payload)

    def _route_error(self, tag: str, message: str) -> None:
        handler = self._errors.get(tag)
        if handler is not None:
            handler(message)
            return
        if tag in self._handlers:
            self.show_error(message)

    def show_error(self, message: str) -> None:
        self.notice(message, PALETTE["bad"], background="#3f1d1d", border="#7f1d1d")

    def notice(
        self,
        message: str,
        color: str,
        background: str = "#0f2b23",
        border: str = "#14532d",
    ) -> None:
        self.banner.setStyleSheet(
            f"background-color: {background}; color: {color}; "
            f"border: 1px solid {border}; border-radius: 6px; padding: 8px;"
        )
        self.banner.setText(message)
        self.banner.show()

    def refresh(self) -> None:  # noqa: D102 - pages override where they have data to pull
        return None

    def apply_status(self, status: dict[str, Any]) -> None:  # noqa: D102
        return None

    def apply_events(self, events: list[dict[str, Any]]) -> None:  # noqa: D102
        return None


# ------------------------------------------------------------------------- overview


class OverviewPage(Page):
    def __init__(self, bridge: Bridge) -> None:
        super().__init__(bridge)
        self.layout.addWidget(title("Overview"))
        self.layout.addWidget(
            hint(
                "The address and port below are derived from this node's secret and the current "
                "epoch. Authorized peers can compute the same values; everyone else sees a host "
                "that keeps moving."
            )
        )

        tiles = QHBoxLayout()
        tiles.setSpacing(12)
        # A 39-character IPv6 locator needs the compact face plus three shares
        # of the row; the three short tiles read fine at a single share each.
        self.address = StatTile("virtual address", "-", compact=True)
        self.port = StatTile("hopping port", "-")
        self.rotation = StatTile("next rotation", "-")
        self.bans = StatTile("active bans", "0")
        tiles.addWidget(self.address, 3)
        for tile in (self.port, self.rotation, self.bans):
            tiles.addWidget(tile, 1)
        self.layout.addLayout(tiles)

        lower = QHBoxLayout()
        lower.setSpacing(12)

        self.details = Card("node")
        self.kv = KeyValueList()
        self.details.body.addWidget(self.kv)
        lower.addWidget(self.details, 1)

        self.feed = Card("recent events")
        self.events = EventFeed()
        self.feed.body.addWidget(self.events)
        lower.addWidget(self.feed, 1)
        self.layout.addLayout(lower, 1)

    def apply_status(self, status: dict[str, Any]) -> None:
        mirage = status.get("mirage", {})
        defense = status.get("defense", {})
        focus = status.get("focus")
        firewall_state = status.get("firewall", {})

        self.address.set_value(str(mirage.get("virtual_address", "-")))
        self.port.set_value(str(mirage.get("port", "-")))
        self.rotation.set_value(
            human_seconds(mirage.get("next_rotation_s", 0)),
            f"epoch {mirage.get('epoch', '?')} · {mirage.get('epoch_seconds', '?')}s window",
        )
        self.bans.set_value(
            str(defense.get("active_bans", 0)),
            f"{defense.get('tracked', 0)} source(s) tracked",
            PALETTE["bad"] if defense.get("active_bans") else None,
        )

        self.kv.update_rows(
            {
                "version": f"{status.get('version')} (protocol {status.get('protocol')})",
                "platform": f"{status.get('os')}/{status.get('arch')}",
                "uptime": human_seconds(status.get("uptime_s", 0)),
                "privileges": "elevated" if status.get("elevated") else "user (limited)",
                "kernel tier": status.get("kernel_tier", ""),
                "firewall": f"{firewall_state.get('backend')} · "
                f"block={firewall_state.get('block_inbound')} · "
                f"{firewall_state.get('applied', 0)} rule(s)",
                "focus": f"{focus['target']} until {str(focus['ends_at'])[11:19]} UTC"
                if focus
                else "idle",
            }
        )

    def apply_events(self, events: list[dict[str, Any]]) -> None:
        self.events.load(events)


# ---------------------------------------------------------------------------- focus


class FocusPage(Page):
    def __init__(self, bridge: Bridge) -> None:
        super().__init__(bridge)
        self.layout.addWidget(title("Focus"))
        self.layout.addWidget(
            hint(
                "Focus raises this application's scheduling priority and relaxes Windows power "
                "throttling for the length of the window. Marked traffic is tagged DSCP 46 (EF); "
                "everything else can be tagged as background. Policies revert when the window "
                "closes or you press Stop."
            )
        )

        form = Card("session")
        self.target = QLineEdit()
        self.target.setPlaceholderText("path to the application, or use --pid from the CLI")
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)

        self.pid = QSpinBox()
        self.pid.setRange(0, 2_147_483_647)
        self.pid.setPrefix("pid ")

        self.minutes = QSpinBox()
        self.minutes.setRange(1, 480)
        self.minutes.setValue(60)
        self.minutes.setSuffix(" min")

        row = QHBoxLayout()
        row.addWidget(self.target, 3)
        row.addWidget(browse)
        row.addWidget(self.pid)
        row.addWidget(self.minutes)
        form.body.addLayout(row)

        self.start_button = QPushButton("Start focus")
        self.start_button.setObjectName("Primary")
        self.start_button.clicked.connect(self._start)
        self.stop_button = QPushButton("Stop and revert")
        self.stop_button.clicked.connect(self._stop)
        form.body.addWidget(button_row(self.start_button, self.stop_button))
        self.layout.addWidget(form)

        status_card = Card("active window")
        self.session = KeyValueList()
        status_card.body.addWidget(self.session)
        self.layout.addWidget(status_card, 1)

        self.on("focus.start", self._show_session)
        self.on("focus.stop", self._show_stopped)
        self.on("focus.status", self._show_session)

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select the application to focus")
        if path:
            self.target.setText(path)

    def _start(self) -> None:
        self.banner.hide()
        self.bridge.request(
            "focus.start",
            "focus.start",
            {
                "target": self.target.text().strip(),
                "pid": int(self.pid.value()),
                "duration_s": int(self.minutes.value() * 60),
            },
        )

    def _stop(self) -> None:
        self.bridge.request("focus.stop", "focus.stop")

    def _show_session(self, payload: object) -> None:
        if not payload:
            self.session.update_rows({"state": "no focus session is running"})
            return
        data = dict(payload)  # type: ignore[arg-type]
        self.session.update_rows(
            {
                "target": data.get("target", ""),
                "window": human_seconds(
                    _seconds_between(data.get("started", ""), data.get("ends_at", ""))
                ),
                "ends at": str(data.get("ends_at", ""))[11:19] + " UTC",
                "priority boosted": data.get("boosted"),
                "eco-qos relaxed": data.get("eco_qos_relaxed"),
                "applied": ", ".join(data.get("applied", [])) or "nothing",
                "skipped": ", ".join(data.get("skipped", [])) or "nothing",
                "errors": ", ".join(data.get("errors", [])) or "none",
            }
        )

    def _show_stopped(self, payload: object) -> None:
        data = dict(payload) if payload else {}  # type: ignore[arg-type]
        self.session.update_rows(
            {"state": "stopped", "was": data.get("target", ""), "policies": "reverted"}
        )

    def refresh(self) -> None:
        self.bridge.request("focus.status", "focus.status")


def _seconds_between(start: str, end: str) -> int:
    from datetime import datetime

    try:
        begin = datetime.fromisoformat(str(start))
        finish = datetime.fromisoformat(str(end))
    except ValueError:
        return 0
    return max(0, int((finish - begin).total_seconds()))


# ------------------------------------------------------------------------- services


class ServicesPage(Page):
    def __init__(self, bridge: Bridge) -> None:
        super().__init__(bridge)
        self.layout.addWidget(title("Services"))
        self.layout.addWidget(
            hint(
                "Every listening socket is scored by exposure, port class and process age. "
                "Termination is never automatic: the dialog below asks first, then the daemon "
                "requires a single-use token bound to exactly the selected pids."
            )
        )

        controls = QHBoxLayout()
        self.minimum = QSpinBox()
        self.minimum.setRange(0, 100)
        self.minimum.setPrefix("min risk ")
        rescan = QPushButton("Rescan")
        rescan.clicked.connect(lambda: self._load(refresh=True))
        self.terminate = QPushButton("Terminate selected…")
        self.terminate.setObjectName("Danger")
        self.terminate.clicked.connect(self._terminate)
        controls.addWidget(self.minimum)
        controls.addWidget(rescan)
        controls.addStretch(1)
        controls.addWidget(self.terminate)
        self.layout.addLayout(controls)

        self.table = ServiceTable()
        self.layout.addWidget(self.table, 1)

        self.on("scan.services", self._loaded)
        self.on("services.terminate", self._terminated)

    def _load(self, refresh: bool = False) -> None:
        self.bridge.request(
            "scan.services",
            "scan.services",
            {"min_risk": int(self.minimum.value()), "refresh": refresh},
        )

    def _loaded(self, payload: object) -> None:
        rows = list(payload or [])  # type: ignore[arg-type]
        self.table.load(
            Service(
                pid=int(row.get("pid", 0)),
                process=str(row.get("process", "")),
                port=int(row.get("port", 0)),
                protocol=str(row.get("protocol", "")),
                address=str(row.get("address", "")),
                path=str(row.get("path", "")),
                public=bool(row.get("public")),
                system=bool(row.get("system")),
                risk=int(row.get("risk", 0)),
                level=str(row.get("level", "low")),
                reasons=list(row.get("reasons", [])),
            )
            for row in rows
        )

    def _terminate(self) -> None:
        chosen = [svc for svc in self.table.selected_services() if svc.pid > 4 and not svc.system]
        if not chosen:
            self.show_error("select at least one non-system service first")
            return

        dialog = ConsentDialog(chosen, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        pids = sorted({svc.pid for svc in chosen})

        def flow(backend: Any) -> Any:
            targets = [f"pid:{pid}" for pid in pids]
            grant = backend.call(
                "consent.request",
                {
                    "action": "services.terminate",
                    "summary": f"terminate {len(pids)} listening service(s)",
                    "targets": targets,
                },
            )
            return backend.call("services.terminate", {"pids": pids, "token": grant["token"]})

        self.bridge.task("services.terminate", flow)

    def _terminated(self, payload: object) -> None:
        data = dict(payload or {})  # type: ignore[arg-type]
        done = data.get("terminated", [])
        failed = data.get("failed", [])
        message = f"terminated {len(done)} process(es)"
        if failed:
            detail = ", ".join(f"{item['pid']} ({item['error']})" for item in failed)
            message += f"; failed: {detail}"
        self.notice(message, PALETTE["good"] if not failed else PALETTE["warn"])
        self._load(refresh=True)

    def refresh(self) -> None:
        self._load()


# -------------------------------------------------------------------------- defense


class DefensePage(Page):
    COLUMNS = ("Address", "Reason", "Level", "Hits", "Expires")

    def __init__(self, bridge: Bridge) -> None:
        super().__init__(bridge)
        self.layout.addWidget(title("Defence"))
        self.layout.addWidget(
            hint(
                "Defence never sends a packet of its own. It observes, throttles and remembers: "
                "repeated probes are tarpitted, port scans are banned, and repeat offenders get "
                "an exponentially longer ban up to the configured ceiling."
            )
        )

        tiles = QHBoxLayout()
        tiles.setSpacing(12)
        self.active = StatTile("active bans")
        self.tracked = StatTile("sources tracked")
        self.tarpit = StatTile("tarpit")
        self.auto = StatTile("auto-ban")
        for tile in (self.active, self.tracked, self.tarpit, self.auto):
            tiles.addWidget(tile)
        self.layout.addLayout(tiles)

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.layout.addWidget(self.table, 1)

        controls = QHBoxLayout()
        self.ip = QLineEdit()
        self.ip.setPlaceholderText("address to ban, e.g. 203.0.113.9")
        self.reason = QLineEdit()
        self.reason.setPlaceholderText("reason")
        ban = QPushButton("Ban")
        ban.setObjectName("Danger")
        ban.clicked.connect(self._ban)
        unban = QPushButton("Unban selected")
        unban.clicked.connect(self._unban)
        controls.addWidget(self.ip, 2)
        controls.addWidget(self.reason, 2)
        controls.addWidget(ban)
        controls.addWidget(unban)
        self.layout.addLayout(controls)

        self.on("defense.bans", self._loaded)
        self.on("defense.ban", lambda _payload: self.refresh())
        self.on("defense.unban", lambda _payload: self.refresh())

    def _loaded(self, payload: object) -> None:
        bans = list(payload or [])  # type: ignore[arg-type]
        self.table.setRowCount(len(bans))
        for row, ban in enumerate(bans):
            cells = (
                ban.get("ip", ""),
                ban.get("reason", ""),
                ban.get("level", 0),
                ban.get("hits", 0),
                str(ban.get("expires_at", ""))[:19],
            )
            for column, value in enumerate(cells):
                self.table.setItem(row, column, _item(value))

    def _ban(self) -> None:
        if not self.ip.text().strip():
            self.show_error("enter an address to ban")
            return
        self.bridge.request(
            "defense.ban",
            "defense.ban",
            {"ip": self.ip.text().strip(), "reason": self.reason.text().strip() or "manual ban"},
        )

    def _unban(self) -> None:
        rows = sorted({index.row() for index in self.table.selectedIndexes()})
        if not rows:
            self.show_error("select a ban first")
            return
        for row in rows:
            address = self.table.item(row, 0)
            if address is not None:
                self.bridge.request("defense.unban", "defense.unban", {"ip": address.text()})

    def apply_status(self, status: dict[str, Any]) -> None:
        defense = status.get("defense", {})
        self.active.set_value(str(defense.get("active_bans", 0)))
        self.tracked.set_value(str(defense.get("tracked", 0)))
        self.tarpit.set_value("on" if defense.get("tarpit") else "off")
        self.auto.set_value("on" if defense.get("auto_ban") else "off")

    def refresh(self) -> None:
        self.bridge.request("defense.bans", "defense.bans")


# --------------------------------------------------------------------------- mirage


class MiragePage(Page):
    COLUMNS = ("Node", "Source", "Epoch", "Virtual address", "Last seen")

    def __init__(self, bridge: Bridge) -> None:
        super().__init__(bridge)
        self.layout.addWidget(title("Identity"))
        self.layout.addWidget(
            hint(
                "The locator is a moving target: address and port are HMAC-derived per epoch from "
                "the cluster secret. Peers prove themselves with a single packet authorization "
                "token; a replayed token is rejected before the handshake starts."
            )
        )

        top = Card("current locator")
        self.address = MonoLabel("-")
        self.detail = QLabel("")
        self.detail.setStyleSheet(f"color: {PALETTE['muted']};")
        top.body.addWidget(self.address)
        top.body.addWidget(self.detail)

        self.node = QSpinBox()
        self.node.setRange(1, 2_147_483_647)
        self.node.setValue(1)
        mint = QPushButton("Mint SPA token")
        mint.setObjectName("Primary")
        mint.clicked.connect(self._mint)
        top.body.addWidget(button_row(QLabel("peer node id"), self.node, mint))
        self.layout.addWidget(top)

        accept = Card("accept a token")
        self.token = QLineEdit()
        self.token.setPlaceholderText("paste a 59 character token")
        self.source = QLineEdit()
        self.source.setPlaceholderText("source address (optional)")
        accept_button = QPushButton("Validate")
        accept_button.clicked.connect(self._accept)
        row = QHBoxLayout()
        row.addWidget(self.token, 3)
        row.addWidget(self.source, 2)
        row.addWidget(accept_button)
        accept.body.addLayout(row)
        self.layout.addWidget(accept)

        peers = Card("authorized peers")
        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        peers.body.addWidget(self.table)
        self.layout.addWidget(peers, 1)

        self.on("mirage.spa", self._minted)
        self.on("mirage.accept", self._accepted)
        self.on("mirage.peers", self._peers_loaded)
        self.on("mirage.rotate", lambda _payload: self.refresh())

    def _mint(self) -> None:
        self.bridge.request("mirage.spa", "mirage.spa", {"node_id": int(self.node.value())})

    def _minted(self, payload: object) -> None:
        token = dict(payload or {})  # type: ignore[arg-type]
        dialog = TokenDialog(
            str(token.get("token", "")),
            f"valid for {human_seconds(token.get('expires_in_s', 0))} "
            f"(epoch {token.get('epoch')}) — single use",
            self,
        )
        dialog.exec()

    def _accept(self) -> None:
        self.bridge.request(
            "mirage.accept",
            "mirage.accept",
            {"token": self.token.text().strip(), "source": self.source.text().strip()},
        )

    def _accepted(self, payload: object) -> None:
        data = dict(payload or {})  # type: ignore[arg-type]
        self.notice(
            f"accepted node {data.get('node_id')} from {data.get('source')} — "
            f"locator {data.get('virtual_address')}:{data.get('port')}",
            PALETTE["good"],
        )
        self.token.clear()
        self.refresh()

    def _peers_loaded(self, payload: object) -> None:
        peers = list(payload or [])  # type: ignore[arg-type]
        self.table.setRowCount(len(peers))
        for row, peer in enumerate(peers):
            cells = (
                peer.get("node_id"),
                peer.get("source"),
                peer.get("epoch"),
                peer.get("virtual_address"),
                str(peer.get("last_seen", ""))[11:19],
            )
            for column, value in enumerate(cells):
                self.table.setItem(row, column, _item(value))

    def apply_status(self, status: dict[str, Any]) -> None:
        mirage = status.get("mirage", {})
        self.address.setText(f"{mirage.get('virtual_address', '-')}:{mirage.get('port', '-')}")
        self.detail.setText(
            f"epoch {mirage.get('epoch', '?')} · rotates in "
            f"{human_seconds(mirage.get('next_rotation_s', 0))} · "
            f"{mirage.get('peers', 0)} authorized peer(s) · "
            f"replay cache {mirage.get('replay_cache', 0)}"
        )

    def refresh(self) -> None:
        self.bridge.request("mirage.peers", "mirage.peers")


class TokenDialog(QDialog):
    def __init__(self, token: str, note: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Single packet authorization token")
        self.setMinimumWidth(620)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        heading = QLabel("Send this token as one UDP datagram")
        heading.setObjectName("PageTitle")
        layout.addWidget(heading)

        field = QPlainTextEdit(token)
        field.setReadOnly(True)
        field.setFixedHeight(64)
        layout.addWidget(field)

        caption = QLabel(note)
        caption.setWordWrap(True)
        caption.setStyleSheet(f"color: {PALETTE['muted']};")
        layout.addWidget(caption)

        buttons = QDialogButtonBox()
        copy = buttons.addButton("Copy", QDialogButtonBox.ButtonRole.ActionRole)
        copy.clicked.connect(lambda: self._copy(token))
        close = buttons.addButton("Close", QDialogButtonBox.ButtonRole.AcceptRole)
        close.setObjectName("Primary")
        layout.addWidget(buttons)
        buttons.accepted.connect(self.accept)
        self._note = caption

    def _copy(self, token: str) -> None:
        from PySide6.QtWidgets import QApplication

        QApplication.clipboard().setText(token)
        self._note.setText("copied to the clipboard")


# ------------------------------------------------------------------------ firewall


class FirewallPage(Page):
    def __init__(self, bridge: Bridge) -> None:
        super().__init__(bridge)
        self.layout.addWidget(title("Firewall"))
        self.layout.addWidget(
            hint(
                "Rules are rendered for the host backend: the Windows Filtering Platform through "
                "the NetSecurity cmdlets (netsh fallback), nftables on Linux, and a pf anchor on "
                "macOS. Applying rules needs elevation: use Ask for Administrative Permissions in "
                "the sidebar. DHCP and ICMP control messages are always preserved so the link "
                "never strands itself."
            )
        )

        options = Card("posture")
        self.block = QCheckBox("Default-deny inbound (keeps DHCP and ICMP control traffic)")
        self.lan = QCheckBox("Allow the mirage port from the local subnet only")
        self.lan.setChecked(True)
        self.ports = QLineEdit()
        self.ports.setPlaceholderText("extra inbound tcp ports to allow, e.g. 22, 443")
        options.body.addWidget(self.block)
        options.body.addWidget(self.lan)
        options.body.addWidget(self.ports)

        self.plan_button = QPushButton("Preview")
        self.plan_button.clicked.connect(self._plan)
        self.apply_button = QPushButton("Apply")
        self.apply_button.setObjectName("Primary")
        self.apply_button.clicked.connect(self._apply)
        self.reset_button = QPushButton("Remove all ProFast rules")
        self.reset_button.setObjectName("Danger")
        self.reset_button.clicked.connect(self._reset)
        options.body.addWidget(button_row(self.plan_button, self.apply_button, self.reset_button))
        self.layout.addWidget(options)

        preview = Card("plan")
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setPlaceholderText("press Preview to render the rules for this host")
        preview.body.addWidget(self.preview)
        self.layout.addWidget(preview, 1)

        self.on("firewall.plan", self._show_plan)
        self.on("firewall.apply", self._show_report)
        self.on("firewall.reset", self._show_report)

    def _params(self) -> dict[str, Any]:
        ports = []
        for chunk in self.ports.text().replace(";", ",").split(","):
            chunk = chunk.strip()
            if chunk.isdigit():
                ports.append(int(chunk))
        return {
            "block_inbound": self.block.isChecked(),
            "allow_lan": self.lan.isChecked(),
            "allow_ports": ports,
        }

    def _plan(self) -> None:
        self.bridge.request("firewall.plan", "firewall.plan", self._params())

    def _apply(self) -> None:
        self.bridge.request("firewall.apply", "firewall.apply", self._params())

    def _reset(self) -> None:
        self.bridge.request("firewall.reset", "firewall.reset")

    def _show_plan(self, payload: object) -> None:
        data = dict(payload or {})  # type: ignore[arg-type]
        lines = [f"# backend: {data.get('backend')}"]
        lines.extend(str(line) for line in data.get("preview", []))
        script = str(data.get("script") or "")
        if script:
            lines.append("")
            lines.append("# rendered script")
            lines.extend(script.splitlines())
        self.preview.setPlainText("\n".join(lines))

    def _show_report(self, payload: object) -> None:
        data = dict(payload or {})  # type: ignore[arg-type]
        lines = [f"backend: {data.get('backend')}", ""]
        for label in ("applied", "skipped", "errors"):
            entries = data.get(label) or []
            if entries:
                lines.append(f"{label}:")
                lines.extend(f"  {entry}" for entry in entries)
        self.preview.setPlainText("\n".join(lines))
        self.bridge.request("firewall.status", "firewall.status")
