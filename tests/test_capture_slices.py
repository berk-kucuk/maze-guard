"""
Tests for how long a capture slice lives and what ends it.

The capture used to be rebuilt every 60 seconds, which put the interface in and
out of promiscuous mode about 600 times in an evening. That is waste on a wired
NIC and a hazard on a USB WiFi adapter, where standing a capture back up is the
path in which rt2x00usb and friends mishandle a device that vanished — and an
external adapter is the normal way to get monitor mode, so it is what a lot of
this audience runs.

What matters in these tests is that the two properties hold together: the
capture is not torn down while the link is unchanged, and it leaves immediately
when the link really moves.

    ./venv/bin/python -m unittest discover -s tests -v
"""
import os
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("MAZE_GUARD_LOG_FILE", "")  # never write the real ~/.config/maze/maze.log
from maze import helper                                    # noqa: E402


class TestSliceLength(unittest.TestCase):

    def test_slice_is_long_enough_to_stop_churning(self):
        """Ten minutes, not one: the old value is what caused the churn."""
        self.assertGreaterEqual(helper._SLICE_SECONDS, 600)


class TestInterfaceChangeDetector(unittest.TestCase):

    def _detector(self, resolves_to, current="enp42s0"):
        patch = unittest.mock.patch.object(helper, "_resolve_iface",
                                           return_value=resolves_to)
        patch.start()
        self.addCleanup(patch.stop)
        return helper._iface_change_detector(current)

    def test_unchanged_link_never_ends_the_capture(self):
        stop = self._detector("enp42s0")
        self.assertFalse(any(stop(None) for _ in range(50)))

    def test_moved_link_ends_the_capture(self):
        stop = self._detector("wlan0")
        self.assertTrue(stop(None))

    def test_resolution_is_cached_between_packets(self):
        """Called once per packet, so it cannot resolve the link every time."""
        calls = []

        def counting(_current):
            calls.append(1)
            return "enp42s0"

        with unittest.mock.patch.object(helper, "_resolve_iface",
                                        side_effect=counting):
            stop = helper._iface_change_detector("enp42s0")
            for _ in range(1000):
                stop(None)
        self.assertEqual(len(calls), 1)

    def test_a_failing_lookup_keeps_capturing(self):
        """Losing the capture is worse than noticing a switch late."""
        with unittest.mock.patch.object(helper, "_resolve_iface",
                                        side_effect=RuntimeError("boom")):
            stop = helper._iface_change_detector("enp42s0")
            self.assertFalse(stop(None))

    def test_empty_resolution_is_not_a_change(self):
        """`_resolve_iface` returning nothing means "could not tell"."""
        stop = self._detector("")
        self.assertFalse(stop(None))


if __name__ == "__main__":
    unittest.main()
