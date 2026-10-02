from pathlib import Path
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtCore import Qt

_LOGO_PATH = Path(__file__).parent.parent.parent / "MAZE.png"
# Pre-rendered by tools/make_logo.py; 16-32 carry the heavier small mark.
_LOGO_DIR = Path(__file__).parent / "logo"
_LOGO_SIZES = (16, 22, 24, 32, 48, 64, 128, 256, 512)


def create_app_icon(size: int = 64) -> QIcon:
    """The app icon with every rendered size, so the tray and the window
    manager each pick their own instead of scaling one bitmap. `size` only
    matters for the fallbacks below."""
    icon = QIcon()
    for s in _LOGO_SIZES:
        p = _LOGO_DIR / f"maze-guard-{s}.png"
        if p.exists():
            icon.addFile(str(p))
    if not icon.isNull():
        return icon

    if _LOGO_PATH.exists():
        pixmap = QPixmap(str(_LOGO_PATH))
        if not pixmap.isNull():
            return QIcon(pixmap.scaled(size, size, Qt.AspectRatioMode.KeepAspectRatio,
                                       Qt.TransformationMode.SmoothTransformation))

    # Fallback: plain text icon if PNG is missing
    from PyQt6.QtGui import QPainter, QColor, QFont
    pixmap = QPixmap(size, size)
    pixmap.fill(QColor("#0a0a0a"))
    p = QPainter(pixmap)
    p.setPen(QColor("#f0f0f0"))
    font = QFont("sans-serif", size // 5, QFont.Weight.Bold)
    p.setFont(font)
    p.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "M")
    p.end()
    return QIcon(pixmap)
