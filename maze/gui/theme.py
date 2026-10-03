"""
Application stylesheet.

Every widget class the interface uses is styled here, for both themes. The
previous sheet left text inputs, text panes, group boxes, check boxes and spin
boxes to the system palette, so on a light desktop theme the dark window came
out with white text boxes and black-on-black labels — and its "dim" text colour
(#3a3a3a on #0a0a0a) was below any readable contrast in the first place.
"""

from pathlib import Path

_BASE = """
* {{
    font-family: "Inter", "Noto Sans", "Segoe UI", sans-serif;
}}

QWidget {{
    font-size: 13px;
    color: {text};
    background-color: transparent;
    selection-background-color: {accent_soft};
    selection-color: {text};
}}

QMainWindow, QDialog, QMessageBox, QInputDialog {{
    background-color: {bg};
}}

QWidget#content, QStackedWidget#pages, QStackedWidget#pages > QWidget {{
    background-color: {bg};
}}

QToolTip {{
    background-color: {elevated};
    color: {text};
    border: 1px solid {border2};
    padding: 6px 8px;
    border-radius: 6px;
}}

/* ── window chrome ─────────────────────────────────────────────── */

QFrame#sidebar {{
    background-color: {sidebar};
    border: none;
    border-right: 1px solid {border};
}}

QLabel#logo {{
    color: {text};
    font-size: 14px;
    font-weight: 700;
    letter-spacing: 3px;
}}

QLabel#logo_sub {{
    color: {text_dim};
    font-size: 11px;
}}

QPushButton#nav {{
    background: transparent;
    border: none;
    border-radius: 8px;
    color: {text_mid};
    text-align: left;
    padding: 9px 12px;
    font-size: 13px;
}}

QPushButton#nav:hover {{
    background-color: {elevated};
    color: {text};
}}

QPushButton#nav:checked {{
    background-color: {accent_soft};
    color: {text};
    font-weight: 600;
}}

QLabel#nav_badge {{
    background-color: {danger};
    color: #ffffff;
    border-radius: 8px;
    padding: 1px 6px;
    font-size: 11px;
    font-weight: 700;
}}

QWidget#topbar {{
    background-color: {bg};
    border-bottom: 1px solid {border};
}}

QLabel#page_title {{
    color: {text};
    font-size: 18px;
    font-weight: 700;
}}

QLabel#page_subtitle {{
    color: {text_mid};
    font-size: 12px;
}}

QPushButton#win_btn, QPushButton#win_close {{
    background: transparent;
    border: none;
    border-radius: 0;
    color: {text_mid};
    font-size: 14px;
    padding: 0;
    min-width: 44px;
    min-height: 40px;
}}

QPushButton#win_btn:hover {{
    background-color: {elevated};
    color: {text};
}}

QPushButton#win_close:hover {{
    background-color: #c42b1c;
    color: #ffffff;
}}

/* ── cards and text ────────────────────────────────────────────── */

QFrame#card {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: 10px;
}}

QFrame#hero {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: 12px;
}}

QLabel#card_title, QLabel#section_title {{
    color: {text_dim};
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
}}

QLabel#card_key {{
    color: {text_mid};
    font-size: 12px;
}}

QLabel#card_value {{
    color: {text};
    font-size: 13px;
}}

QLabel#muted {{
    color: {text_mid};
    font-size: 12px;
}}

QLabel#stat_value {{
    color: {text};
    font-size: 26px;
    font-weight: 700;
}}

QLabel#stat_label {{
    color: {text_mid};
    font-size: 12px;
}}

QLabel#empty_state {{
    color: {text_dim};
    font-size: 13px;
    padding: 24px;
}}

QLabel#chip {{
    border-radius: 9px;
    padding: 2px 9px;
    font-size: 11px;
    font-weight: 600;
}}

QFrame[frameShape="4"], QFrame[frameShape="5"] {{
    color: {border};
    background: {border};
    border: none;
    max-height: 1px;
}}

/* ── inputs ────────────────────────────────────────────────────── */

QLineEdit, QSpinBox, QPlainTextEdit, QTextEdit {{
    background-color: {input_bg};
    color: {text};
    border: 1px solid {border2};
    border-radius: 7px;
    padding: 5px 9px;
}}

QLineEdit:focus, QSpinBox:focus {{
    border-color: {accent};
}}

QLineEdit:disabled, QSpinBox:disabled {{
    color: {text_dim};
}}

QTextEdit, QPlainTextEdit {{
    padding: 8px 10px;
    font-family: "JetBrains Mono", "Fira Code", "DejaVu Sans Mono", monospace;
    font-size: 12px;
}}

QTextEdit#detail, QPlainTextEdit#detail {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: 10px;
}}

QSpinBox::up-button, QSpinBox::down-button {{
    width: 16px;
    border: none;
    background: transparent;
}}

QComboBox {{
    background-color: {input_bg};
    color: {text};
    border: 1px solid {border2};
    border-radius: 7px;
    padding: 5px 10px;
    min-width: 120px;
}}

QComboBox:hover {{
    border-color: {text_dim};
}}

QComboBox::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: right center;
    width: 22px;
    border: none;
}}

QComboBox QAbstractItemView {{
    background-color: {elevated};
    color: {text};
    border: 1px solid {border2};
    selection-background-color: {accent_soft};
    selection-color: {text};
    outline: none;
    padding: 4px;
}}

QCheckBox {{
    spacing: 9px;
    color: {text};
}}

QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 1px solid {border2};
    background-color: {input_bg};
}}

QCheckBox::indicator:checked {{
    background-color: {accent};
    border-color: {accent};
    image: url({check_icon});
}}

QCheckBox:disabled {{
    color: {text_dim};
}}

/* ── buttons ───────────────────────────────────────────────────── */

QPushButton {{
    background-color: {elevated};
    color: {text};
    border: 1px solid {border2};
    border-radius: 7px;
    padding: 6px 14px;
    min-height: 18px;
}}

QPushButton:hover {{
    border-color: {text_dim};
}}

QPushButton:pressed {{
    background-color: {surface};
}}

QPushButton:disabled {{
    color: {text_dim};
    border-color: {border};
}}

QPushButton:checked {{
    background-color: {accent_soft};
    border-color: {accent};
}}

QPushButton#primary {{
    background-color: {accent};
    border-color: {accent};
    color: #ffffff;
    font-weight: 600;
}}

QPushButton#primary:hover {{
    background-color: {accent_hover};
    border-color: {accent_hover};
}}

QPushButton#primary:disabled {{
    background-color: {elevated};
    border-color: {border};
    color: {text_dim};
}}

QPushButton#danger:disabled {{
    color: {text_dim};
}}

QPushButton#danger {{
    color: {danger};
}}

QPushButton#danger:hover {{
    border-color: {danger};
}}

QPushButton#link {{
    background: transparent;
    border: none;
    color: {accent};
    padding: 2px 4px;
}}

QPushButton#link:hover {{
    text-decoration: underline;
}}

/* ── tables ────────────────────────────────────────────────────── */

QTableWidget, QTableView, QListWidget {{
    background-color: {surface};
    alternate-background-color: {alt_row};
    border: 1px solid {border};
    border-radius: 10px;
    gridline-color: transparent;
    color: {text};
    selection-background-color: {accent_soft};
    selection-color: {text};
    outline: none;
}}

QListWidget::item {{
    padding: 5px 8px;
    border-radius: 5px;
}}

QListWidget::item:selected {{
    background-color: {accent_soft};
    color: {text};
}}

QTableWidget::item, QTableView::item {{
    padding: 4px 10px;
    border: none;
}}

QHeaderView {{
    background-color: transparent;
    border: none;
}}

QHeaderView::section {{
    background-color: {surface};
    color: {text_mid};
    padding: 8px 10px;
    border: none;
    border-bottom: 1px solid {border};
    font-size: 11px;
    font-weight: 700;
}}

QTableCornerButton::section {{
    background-color: {surface};
    border: none;
}}

/* ── group boxes (settings) ────────────────────────────────────── */

QGroupBox {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: 10px;
    margin-top: 26px;
    padding: 14px 16px 16px 16px;
    font-weight: 700;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 4px;
    top: 0px;
    padding: 0 4px 6px 4px;
    color: {text};
    font-size: 13px;
}}

/* ── scrolling ─────────────────────────────────────────────────── */

QScrollArea {{
    background-color: transparent;
    border: none;
}}

QScrollArea > QWidget > QWidget {{
    background-color: transparent;
}}

QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 2px;
}}

QScrollBar::handle:vertical {{
    background: {scrollbar};
    border-radius: 3px;
    min-height: 30px;
}}

QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
    margin: 2px;
}}

QScrollBar::handle:horizontal {{
    background: {scrollbar};
    border-radius: 3px;
    min-width: 30px;
}}

QScrollBar::add-line, QScrollBar::sub-line,
QScrollBar::add-page, QScrollBar::sub-page {{
    width: 0; height: 0;
    background: none;
}}

QSplitter::handle {{
    background-color: transparent;
}}

QMenu {{
    background-color: {elevated};
    color: {text};
    border: 1px solid {border2};
    border-radius: 8px;
    padding: 5px;
}}

QMenu::item {{
    padding: 6px 22px 6px 12px;
    border-radius: 5px;
}}

QMenu::item:selected {{
    background-color: {accent_soft};
}}

QMenu::item:disabled {{
    color: {text_dim};
}}

QMenu::separator {{
    height: 1px;
    background: {border2};
    margin: 4px 6px;
}}
"""

# OLED dark: true black background so unlit pixels stay off, with surfaces
# only a step above it and hairline borders doing the separating.
_DARK = {
    "bg":           "#000000",
    "sidebar":      "#000000",
    "surface":      "#0a0a0a",
    "alt_row":      "#0d0d0d",
    "elevated":     "#141414",
    "input_bg":     "#050505",
    "border":       "#1a1a1a",
    "border2":      "#262626",
    "text":         "#ededed",
    "text_mid":     "#9a9a9a",
    "text_dim":     "#6a6a6a",
    "scrollbar":    "#2a2a2a",
    "accent":       "#4f8cff",
    "accent_hover": "#6a9dff",
    "accent_soft":  "#0f1a33",
    "danger":       "#ff5a3c",
}

_LIGHT = {
    "bg":           "#f4f5f7",
    "sidebar":      "#eceef1",
    "surface":      "#ffffff",
    "alt_row":      "#f8f9fb",
    "elevated":     "#f0f2f5",
    "input_bg":     "#ffffff",
    "border":       "#e1e4e8",
    "border2":      "#d0d4da",
    "text":         "#16191d",
    "text_mid":     "#5a616b",
    "text_dim":     "#8b919a",
    "scrollbar":    "#c9cdd3",
    "accent":       "#2f6bff",
    "accent_hover": "#4a7fff",
    "accent_soft":  "#dfe8ff",
    "danger":       "#d93a1a",
}


def palette(theme: str) -> dict:
    """The colour tokens for ``theme``, for widgets that paint themselves."""
    return _DARK if theme == "dark" else _LIGHT


_CHECK_ICON = (Path(__file__).parent / "assets" / "check.svg").as_posix()


def get_stylesheet(theme: str) -> str:
    return _BASE.format(check_icon=_CHECK_ICON, **palette(theme))


THREAT_COLORS = {
    "safe":       "#22c55e",
    "suspicious": "#f5a524",
    "dangerous":  "#ff4d2e",
}
