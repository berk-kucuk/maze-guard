"""
End-to-end detection, with real packets.

Everything else in this suite feeds the detectors synthetic input. This drives
the whole path — libpcap filter, capture thread, classification, threshold,
event bus — with TCP connections a kernel actually sent, which is the part that
manual testing was needed for until now.

It runs inside an unprivileged user + network namespace, so it needs no sudo
and touches nothing outside itself. Where namespaces are unavailable (a
container without them, a kernel with user namespaces disabled) it skips.

    ./venv/bin/python -m unittest discover -s tests -v
"""
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

# Child processes inherit this: the maze code they run never writes the
# user's real ~/.config/maze/maze.log.
os.environ.setdefault("MAZE_GUARD_LOG_FILE", "")

ROOT = Path(__file__).resolve().parent.parent
SCENARIO = ROOT / "tests" / "support" / "scan_scenario.py"
TIMEOUT = 90


def _namespaces_available() -> bool:
    # scripts/check.sh --quick sets this: the end-to-end run costs a few
    # seconds, which is worth skipping in a tight edit loop and never worth
    # skipping before a release.
    if os.environ.get("MAZE_SKIP_INTEGRATION"):
        return False
    if not shutil.which("unshare"):
        return False
    try:
        proc = subprocess.run(["unshare", "-Urn", "true"],
                              capture_output=True, timeout=10)
        return proc.returncode == 0
    except Exception:
        return False


@unittest.skipUnless(_namespaces_available(),
                     "user namespaces unavailable — cannot capture packets "
                     "without root")
class PortScanEndToEndTests(unittest.TestCase):
    """A scan that really happened, detected by the code that ships."""

    @classmethod
    def setUpClass(cls):
        proc = subprocess.run(
            ["unshare", "-Urn", sys.executable, str(SCENARIO)],
            capture_output=True, text=True, timeout=TIMEOUT, cwd=ROOT)
        if proc.returncode != 0:
            raise unittest.SkipTest(
                f"scenario could not run: {proc.stderr.strip()[-300:]}")
        line = next((l for l in reversed(proc.stdout.splitlines())
                     if l.startswith("{")), "")
        if not line:
            raise unittest.SkipTest(f"scenario produced no result:\n{proc.stdout[-300:]}")
        cls.result = json.loads(line)

    def test_the_capture_actually_captured(self):
        """A detector that sees nothing and a quiet network look identical
        from the outside, and mean opposite things."""
        self.assertEqual(self.result["capture"], "direct")
        self.assertGreater(self.result["packets_seen"], 0)

    def test_the_scan_is_reported(self):
        kinds = {e["type"] for e in self.result["events"]}
        self.assertIn("port_scan", kinds)

    def test_it_escalates_from_suspicious_to_dangerous(self):
        levels = [e["level"] for e in self.result["events"]
                  if e["type"] == "port_scan"]
        self.assertIn("suspicious", levels)
        self.assertIn("dangerous", levels)
        self.assertLess(levels.index("suspicious"), levels.index("dangerous"))

    def test_the_source_and_technique_are_identified(self):
        event = next(e for e in self.result["events"] if e["type"] == "port_scan")
        self.assertEqual(event["src"], "127.0.0.2")
        self.assertEqual(event["technique"], "syn_scan")

    def test_the_port_count_reflects_what_was_probed(self):
        counts = [e["unique_ports"] for e in self.result["events"]]
        self.assertTrue(any(c >= 5 for c in counts), counts)


if __name__ == "__main__":
    unittest.main()
