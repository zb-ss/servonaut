"""Helpers for CLI questions asked while an asyncio event loop is running."""
from __future__ import annotations

import signal
from collections.abc import Iterator
from contextlib import contextmanager


@contextmanager
def ctrl_c_interrupts() -> Iterator[None]:
    """Make Ctrl-C raise KeyboardInterrupt while a prompt waits for input.

    A question asked from inside ``asyncio.run`` would otherwise get
    asyncio's handler, which (from Python 3.11) only cancels the running
    task: ``input()`` keeps waiting, and the next Enter is taken as an
    answer, so a question that defaults to "yes" goes ahead after Ctrl-C.
    Python's default handler raises at the prompt instead. The previous
    handler is restored afterwards.
    """
    try:
        previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    except ValueError:
        # Not the main thread: asyncio.run installed no handler there either.
        yield
        return
    try:
        yield
    finally:
        if previous is not None:
            signal.signal(signal.SIGINT, previous)
