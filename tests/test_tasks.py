"""MG4: background tasks are kept alive and their failures are logged."""
from __future__ import annotations

import asyncio
import gc
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from maze.core import tasks  # noqa: E402


class SpawnTests(unittest.IsolatedAsyncioTestCase):
    async def test_survives_garbage_collection(self):
        done = asyncio.Event()
        before = tasks.running()

        async def work():
            await asyncio.sleep(0.05)
            done.set()
        tasks.spawn(work())          # no reference kept by the caller
        gc.collect()
        await asyncio.wait_for(done.wait(), 2)
        await asyncio.sleep(0)
        self.assertEqual(tasks.running(), before, "a finished task was kept")

    async def test_failure_is_logged_not_lost(self):
        async def boom():
            raise RuntimeError("block failed")
        with mock.patch.object(tasks.log, "error") as err:
            t = tasks.spawn(boom())
            with self.assertRaises(RuntimeError):
                await t
            await asyncio.sleep(0)
        self.assertTrue(err.called)

    def test_no_bare_create_task_left(self):
        import re
        root = Path(__file__).resolve().parents[1] / "maze"
        for f in root.rglob("*.py"):
            for n, line in enumerate(f.read_text().splitlines(), 1):
                if re.match(r"\s*asyncio\.(create_task|ensure_future)\(", line):
                    self.fail(f"{f}:{n}: a task nobody keeps: {line.strip()}")
