"""
Small building blocks shared by every page, so the pages look like one
application rather than eight: cards, stat tiles, status chips, a real on/off
switch, and an empty-state message for tables that have nothing to show.
"""
from PyQt6.QtCore import QEvent, QObject, QPropertyAnimation, QRectF, Qt, pyqtProperty
from PyQt6.QtGui import QColor, QPainter
from PyQt6.QtWidgets import (
    QAbstractButton, QAbstractItemView, QFrame, QHBoxLayout, QHeaderView,
    QLabel, QSizePolicy, QTableWidget, QVBoxLayout, QWidget,
)

from maze.gui.theme import THREAT_COLORS


def card(title: str = "") -> tuple[QFrame, QVBoxLayout, QLabel]:
    """A surface with an optional small caps title. Returns (frame, body, title)."""
    frame = QFrame()
    frame.setObjectName("card")
    body = QVBoxLayout(frame)
    body.setContentsMargins(16, 14, 16, 14)
    body.setSpacing(10)
    lbl = QLabel(title.upper())
    lbl.setObjectName("card_title")
    body.addWidget(lbl)
    return frame, body, lbl


def chip(text: str = "", color: str = "") -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("chip")
    set_chip(lbl, text, color)
    return lbl


def set_chip(lbl: QLabel, text: str, color: str) -> None:
    """A rounded status label tinted with ``color`` (any #rrggbb)."""
    lbl.setText(text)
    c = QColor(color or "#8b919a")
    lbl.setStyleSheet(
        f"color: {c.name()}; background-color: rgba({c.red()}, {c.green()}, "
        f"{c.blue()}, 38); border-radius: 9px; padding: 2px 9px; "
        f"font-size: 11px; font-weight: 600;")
    lbl.setVisible(bool(text))


class StatTile(QFrame):
    """A number with a caption, optionally clickable (navigates somewhere)."""

    def __init__(self, on_click=None, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self._on_click = on_click
        if on_click:
            self.setCursor(Qt.CursorShape.PointingHandCursor)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(2)
        self.value = QLabel("0")
        self.value.setObjectName("stat_value")
        self.label = QLabel("")
        self.label.setObjectName("stat_label")
        lay.addWidget(self.value)
        lay.addWidget(self.label)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set(self, value, color: str = "") -> None:
        self.value.setText(str(value))
        self.value.setStyleSheet(f"color: {color};" if color else "")

    def mouseReleaseEvent(self, event) -> None:
        if self._on_click and event.button() == Qt.MouseButton.LeftButton:
            self._on_click()
        super().mouseReleaseEvent(event)


class ToggleSwitch(QAbstractButton):
    """An on/off switch. The old toggle was a button labelled with a circle
    glyph that many fonts do not have, so it read as the letter "O"."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedSize(42, 24)
        self._pos = 0.0
        self._anim = QPropertyAnimation(self, b"knob", self)
        self._anim.setDuration(120)
        self.toggled.connect(self._animate)
        self._busy = False

    def _get_knob(self) -> float:
        return self._pos

    def _set_knob(self, value: float) -> None:
        self._pos = value
        self.update()

    knob = pyqtProperty(float, _get_knob, _set_knob)

    def _animate(self, checked: bool) -> None:
        self._anim.stop()
        self._anim.setStartValue(self._pos)
        self._anim.setEndValue(1.0 if checked else 0.0)
        self._anim.start()

    def set_state(self, checked: bool) -> None:
        """Reflect a state without emitting clicked (and without animating)."""
        self.blockSignals(True)
        self.setChecked(checked)
        self.blockSignals(False)
        self._anim.stop()
        self._pos = 1.0 if checked else 0.0
        self.update()

    def set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.setEnabled(not busy)
        self.update()

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        on = QColor(THREAT_COLORS["safe"])
        off = QColor(self.palette().mid().color())
        off.setAlpha(150)
        track = QColor(on) if self._pos > 0.5 else off
        if not self.isEnabled():
            track.setAlpha(90)
        if self._busy:
            track = QColor(THREAT_COLORS["suspicious"])
        r = QRectF(0, 0, self.width(), self.height())
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(track)
        p.drawRoundedRect(r, r.height() / 2, r.height() / 2)
        d = r.height() - 6
        x = 3 + self._pos * (r.width() - d - 6)
        p.setBrush(QColor("#ffffff"))
        p.drawEllipse(QRectF(x, 3, d, d))
        p.end()


class _EmptyOverlay(QObject):
    """Shows a centred message over a table's viewport while it has no rows."""

    def __init__(self, table: QTableWidget, text: str):
        super().__init__(table)
        self._table = table
        self.label = QLabel(text, table.viewport())
        self.label.setObjectName("empty_state")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setWordWrap(True)
        self.label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        table.viewport().installEventFilter(self)
        model = table.model()
        model.rowsInserted.connect(self.sync)
        model.rowsRemoved.connect(self.sync)
        model.modelReset.connect(self.sync)
        self.sync()

    def eventFilter(self, obj, event) -> bool:
        if event.type() in (QEvent.Type.Resize, QEvent.Type.Show):
            self.label.setGeometry(self._table.viewport().rect())
        return False

    def sync(self, *_args) -> None:
        try:
            visible = any(not self._table.isRowHidden(r)
                          for r in range(self._table.rowCount()))
            self.label.setGeometry(self._table.viewport().rect())
            self.label.setVisible(not visible)
        except RuntimeError:
            pass        # the model outlived its table during teardown


def attach_empty_state(table: QTableWidget, text: str) -> _EmptyOverlay:
    """Give ``table`` a message for when it is empty. Keep the returned object
    to change the text later (``.label.setText``) or after filtering
    (``.sync()``)."""
    return _EmptyOverlay(table, text)


def setup_table(table: QTableWidget, stretch: int, fit: tuple = (),
                fixed: dict | None = None) -> None:
    """Uniform table chrome. ``stretch`` takes the slack, columns in ``fit``
    size to their content (so "DANGEROUS" or a PID is never cut to "DANGE…"),
    ``fixed`` maps column → width."""
    table.verticalHeader().setVisible(False)
    table.verticalHeader().setDefaultSectionSize(34)
    table.setShowGrid(False)
    table.setAlternatingRowColors(True)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setWordWrap(False)
    header = table.horizontalHeader()
    header.setStretchLastSection(False)
    header.setHighlightSections(False)
    header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
    for col in range(table.columnCount()):
        header.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
    for col in fit:
        header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
    for col, width in (fixed or {}).items():
        header.setSectionResizeMode(col, QHeaderView.ResizeMode.Fixed)
        table.setColumnWidth(col, width)
    header.setSectionResizeMode(stretch, QHeaderView.ResizeMode.Stretch)


def row_layout(*widgets, stretch_after: int | None = None,
               spacing: int = 8) -> QHBoxLayout:
    """A horizontal row; a stretch is inserted after index ``stretch_after``."""
    lay = QHBoxLayout()
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(spacing)
    for i, w in enumerate(widgets):
        if isinstance(w, QWidget):
            lay.addWidget(w)
        else:
            lay.addLayout(w)
        if stretch_after is not None and i == stretch_after:
            lay.addStretch()
    return lay
