"""
Tests for reading our own drop-rule hits back out of the kernel log.

The sample lines are real ones, taken from a session where a phone running
nmap was auto-blocked and kept probing for another ninety minutes.

    ./venv/bin/python -m unittest discover -s tests -v
"""
import os
import sys
import unittest
import unittest.mock
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("MAZE_GUARD_LOG_FILE", "")  # never write the real ~/.config/maze/maze.log
from maze.protection import block_log                      # noqa: E402

MDNS = ("2026-08-22T21:53:39+0300 msi kernel: MAZE-BLOCKIN=enp42s0 OUT= "
        "MAC=01:00:5e:00:00:fb:da:38:63:d3:27:c6:08:00 SRC=192.168.0.28 "
        "DST=224.0.0.251 LEN=472 TOS=0x00 PREC=0x00 TTL=255 ID=22346 DF "
        "PROTO=UDP SPT=5353 DPT=5353 LEN=452")
SCAN = ("2026-08-22T23:23:27+0300 msi kernel: MAZE-BLOCKIN=enp42s0 OUT= "
        "MAC=aa:bb SRC=192.168.0.28 DST=192.168.0.42 LEN=44 TOS=0x00 "
        "PROTO=TCP SPT=51000 DPT=1720 WINDOW=1024 RES=0x00 SYN URGP=0")
OTHER = ("2026-08-22T23:24:00+0300 msi kernel: MAZE-BLOCKIN=enp42s0 OUT= "
         "MAC=aa:bb SRC=192.168.0.99 DST=192.168.0.42 LEN=44 PROTO=TCP "
         "SPT=4000 DPT=22 SYN URGP=0")
NOISE = "2026-08-22T23:24:01+0300 msi kernel: r8169 enp42s0: link up"


class ParseTests(unittest.TestCase):
    def test_one_record_per_source(self):
        out = block_log.parse([MDNS, SCAN, OTHER, NOISE])
        self.assertEqual(set(out), {"192.168.0.28", "192.168.0.99"})
        self.assertEqual(out["192.168.0.28"].packets, 2)

    def test_ports_and_protocols_are_collected(self):
        rec = block_log.parse([MDNS, SCAN])["192.168.0.28"]
        self.assertEqual(rec.ports, {5353, 1720})
        self.assertEqual(rec.protocols, {"UDP", "TCP"})

    def test_the_window_is_the_first_and_last_packet(self):
        rec = block_log.parse([SCAN, MDNS])["192.168.0.28"]
        self.assertEqual(rec.first.hour, 21)
        self.assertEqual(rec.last.hour, 23)

    def test_unrelated_kernel_chatter_is_ignored(self):
        self.assertEqual(block_log.parse([NOISE]), {})

    def test_a_watermark_prevents_double_counting(self):
        """journalctl's --since is inclusive to the second, so a poller that
        did not filter would count the boundary second twice."""
        after = datetime.fromisoformat("2026-08-22T22:00:00")
        out = block_log.parse([MDNS, SCAN], after=after)
        self.assertEqual(out["192.168.0.28"].packets, 1)
        self.assertEqual(out["192.168.0.28"].ports, {1720})

    def test_lines_without_a_timestamp_are_dropped_when_filtering(self):
        undated = "kernel: MAZE-BLOCKIN=x SRC=192.168.0.28 DST=y PROTO=TCP DPT=80"
        self.assertEqual(block_log.parse([undated]) != {}, True)
        self.assertEqual(block_log.parse([undated], after=datetime.now()), {})


class ReadTests(unittest.TestCase):
    def _run(self, returncode=0, stdout="", raises=None):
        result = unittest.mock.Mock(returncode=returncode, stdout=stdout,
                                    stderr="")
        patch = unittest.mock.patch(
            "subprocess.run",
            side_effect=raises if raises else None,
            return_value=result)
        return patch

    def test_an_unreadable_journal_is_empty_not_an_exception(self):
        with self._run(returncode=1, stdout=""):
            self.assertEqual(block_log.read_sync(), {})

    def test_a_missing_journalctl_is_survivable(self):
        with self._run(raises=FileNotFoundError("journalctl")):
            self.assertEqual(block_log.read_sync(), {})

    def test_the_query_is_scoped_to_our_own_prefix(self):
        with self._run(stdout=SCAN) as run:
            block_log.read_sync(since="-5m")
        args = run.call_args[0][0]
        self.assertIn("--grep", args)
        self.assertIn("MAZE-", args)
        self.assertIn("-k", args)
        self.assertEqual(args[args.index("--since") + 1], "-5m")


if __name__ == "__main__":
    unittest.main()
