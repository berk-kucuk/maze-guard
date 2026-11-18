"""Fire-and-forget tasks that are neither lost nor silent (audit MG4).

asyncio keeps only a weak reference to a running task: one started with
create_task()/ensure_future() and not stored anywhere can be garbage-collected
part way through — a block that never reaches the firewall, a monitor loop
that just stops. And an exception in such a task is reported, if at all,
only when the task object is collected. spawn() keeps a strong reference
until the task is done and logs whatever it raised.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from typing import Any

from maze.utils.logger import log

_running: set[asyncio.Future] = set()


def _done(task: asyncio.Future) -> None:
    _running.discard(task)
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        log.error("background task failed: %r", exc, exc_info=exc)


def spawn(aw: Awaitable[Any]) -> asyncio.Future:
    """asyncio.ensure_future(aw), kept alive until it finishes."""
    task = asyncio.ensure_future(aw)
    _running.add(task)
    task.add_done_callback(_done)
    return task


def running() -> int:
    """How many spawned tasks are still alive (for tests)."""
    return len(_running)
