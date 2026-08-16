#!/usr/bin/env python3
import sys


def _usage() -> None:
    print(
        "Maze Guard — public WiFi security monitor\n"
        "\n"
        "  maze-guard                 start the interface\n"
        "  maze-guard --background    start hidden in the system tray\n"
        "  maze-guard --doctor        check that every feature works here\n"
        "  maze-guard --version       print the version\n"
    )


if __name__ == "__main__":
    if "--help" in sys.argv or "-h" in sys.argv:
        _usage()
    elif "--version" in sys.argv:
        from maze import __version__
        print(f"maze-guard {__version__}")
    elif "--doctor" in sys.argv:
        # Deliberately reachable without the GUI: the most likely reason to run
        # this is that the GUI is showing something unbelievable.
        from maze.utils.doctor import main as doctor
        sys.exit(doctor())
    else:
        from maze.gui.app import run
        run()
