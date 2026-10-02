#!/usr/bin/env python3
"""Generate the Maze Guard logo set: a G built from maze walls.

Drawn on the Maze family icon grid shared with Maze AI, Qlam and Maze Connect:
1024 canvas, black tile edge to edge with corner radius 224, the mark inside
212..812. The G is a single maze wall with the lit spark at its centre. At
16-32 px the spark is dropped and the G drawn at double weight, so it stays
legible in the tray.

    python3 tools/make_logo.py

Outputs:
  maze/gui/logo/maze-guard.svg           app icon (48 px and up)
  maze/gui/logo/maze-guard-small.svg     reduced mark (16-32 px)
  maze/gui/logo/maze-guard-<size>.png    16 22 24 32 48 64 128 256 512
  MAZE.png                               1024 master, used by the installers
  maze-guard-logo.png                    the same 1024 logo, for the README and outside use

PNG rendering needs rsvg-convert (librsvg).
"""
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOGO = ROOT / "maze" / "gui" / "logo"

WHITE = "#F4F4F6"
TILE_RX = 224

OUTER = "M812 380 V212 H212 V812 H812 V512 H620"     # the G
OUTER_SMALL = "M800 372 V224 H224 V800 H800 V512 H600"

SMALL_SIZES = (16, 22, 24, 32)
LARGE_SIZES = (48, 64, 128, 256, 512)


def _wall(d: str, width: int, opacity: float = 1.0) -> str:
    op = f' stroke-opacity="{opacity}"' if opacity != 1 else ""
    return (f'<path d="{d}" fill="none" stroke="{WHITE}" stroke-width="{width}" '
            f'stroke-linecap="square" stroke-linejoin="miter"{op}/>')


def _spark(cx: int, cy: int, s: int) -> str:
    k = round(s * 0.12, 2)
    return (f'<path fill="#fff" d="M{cx} {cy - s} C{cx + k} {cy - k} {cx + k} {cy - k} {cx + s} {cy} '
            f'C{cx + k} {cy + k} {cx + k} {cy + k} {cx} {cy + s} C{cx - k} {cy + k} {cx - k} {cy + k} {cx - s} {cy} '
            f'C{cx - k} {cy - k} {cx - k} {cy - k} {cx} {cy - s}Z"/>')


def _svg(body: str, defs: str = "") -> str:
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">'
            f'<title>Maze Guard</title>{defs}'
            f'<rect width="1024" height="1024" rx="{TILE_RX}" fill="#000"/>{body}</svg>\n')


GLOW = ('<defs><radialGradient id="glow" cx=".5" cy=".5" r=".5">'
        '<stop offset="0" stop-color="#fff" stop-opacity=".42"/>'
        '<stop offset=".45" stop-color="#fff" stop-opacity=".09"/>'
        '<stop offset="1" stop-color="#fff" stop-opacity="0"/></radialGradient></defs>')


def app_icon() -> str:
    return _svg('<circle cx="512" cy="512" r="180" fill="url(#glow)"/>'
                + _wall(OUTER, 52) + _spark(512, 512, 72), GLOW)


def small_icon() -> str:
    return _svg(_wall(OUTER_SMALL, 92))


def _render(src: Path, dst: Path, size: int) -> None:
    subprocess.run(["rsvg-convert", "-w", str(size), "-h", str(size), str(src), "-o", str(dst)], check=True)


def main() -> None:
    LOGO.mkdir(parents=True, exist_ok=True)
    big, small = LOGO / "maze-guard.svg", LOGO / "maze-guard-small.svg"
    big.write_text(app_icon())
    small.write_text(small_icon())
    for size in SMALL_SIZES:
        _render(small, LOGO / f"maze-guard-{size}.png", size)
    for size in LARGE_SIZES:
        _render(big, LOGO / f"maze-guard-{size}.png", size)
    _render(big, ROOT / "MAZE.png", 1024)
    _render(big, ROOT / "maze-guard-logo.png", 1024)
    print(f"logo set written to {LOGO} and {ROOT / 'MAZE.png'}")


if __name__ == "__main__":
    main()
