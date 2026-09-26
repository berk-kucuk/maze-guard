"""
The GUI must drive a PyQt6 event loop.

qasync chooses its Qt binding when it is imported. Imported before PyQt6 on a
machine that also has PyQt5 (common: other Qt apps pull it in), it bound to
PyQt5 and the app hung invisibly — no window, no tray icon, and the stuck
process kept the single-instance socket so every later launch exited silently.
Nothing in the unit tests noticed, because nothing started the loop.

Each case runs in a FRESH interpreter: the binding is decided once per process,
and this test process may already have imported either binding.

    ./venv/bin/python -m unittest discover -s tests -v
"""
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_PROBE = r"""
import asyncio, sys
import maze.gui.app                       # the real import order of the GUI
import qasync
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication
print("binding", qasync.QtModuleName)
app = QApplication.instance() or QApplication(sys.argv)
loop = qasync.QEventLoop(app)
asyncio.set_event_loop(loop)
fired = []
QTimer.singleShot(0, lambda: fired.append(1))
async def boot():
    await asyncio.sleep(0.05)
    return "ran"
with loop:
    print("coroutine", loop.run_until_complete(asyncio.wait_for(boot(), 5)))
print("qt-timer", bool(fired))
"""


def _have(mod: str) -> bool:
    return subprocess.run([sys.executable, "-c", f"import {mod}"],
                          capture_output=True).returncode == 0


@unittest.skipUnless(_have("PyQt6.QtWidgets") and _have("qasync"), "PyQt6/qasync not installed")
class QtBindingTests(unittest.TestCase):
    def _probe(self, **env_over):
        env = dict(os.environ, QT_QPA_PLATFORM="offscreen", PYTHONPATH=str(ROOT),
                   MAZE_GUARD_LOG_FILE="")    # never write the real ~/.config/maze/maze.log
        env.pop("QT_API", None)
        env.update(env_over)
        r = subprocess.run([sys.executable, "-B", "-c", _PROBE], cwd=ROOT, env=env,
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        return dict(line.split(" ", 1) for line in r.stdout.splitlines() if " " in line)

    def test_qasync_binds_pyqt6_and_the_loop_runs(self):
        out = self._probe()
        self.assertEqual(out.get("binding"), "PyQt6")
        self.assertEqual(out.get("coroutine"), "ran")
        self.assertEqual(out.get("qt-timer"), "True")

    @unittest.skipUnless(_have("PyQt5.QtCore"), "PyQt5 not installed")
    def test_a_foreign_qt_api_setting_cannot_rebind_it(self):
        # A desktop that exports QT_API=pyqt5 for some other program must not
        # break Maze Guard.
        self.assertEqual(self._probe(QT_API="pyqt5").get("binding"), "PyQt6")


if __name__ == "__main__":
    unittest.main()
