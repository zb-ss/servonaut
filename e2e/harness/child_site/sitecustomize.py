"""Install the e2e guards in a child process, or stop the child.

The suite puts this directory first on ``PYTHONPATH`` for every Python
process it starts, so the guards are active before the child imports anything
else. Settings come from the ``SERVONAUT_E2E_*`` environment variables. Once
armed, the child reports itself in ``SERVONAUT_E2E_ARMED_LOG``; module
constants and the Hetzner and OVH client libraries are then pointed at the
local fakes, and an owner watchdog ends the child once the process that owns
the run, or the run's root, is gone. ``child_guard.py`` does all of it (see
there for the details).

Python's ``site`` module ignores errors raised here, which would let a child
run unguarded. Any failure therefore ends the process at once (exit 70).
"""

import os
import sys

# A guarded child never writes bytecode: what it imports lives in the
# toolchain and the checkout, outside the test root. The environment says so
# too, but a child can arm through an install's start-up hook while running
# under ``python -E``, which ignores PYTHONDONTWRITEBYTECODE. This line runs
# before the guard's own imports.
sys.dont_write_bytecode = True

_CHILD_GUARD_MODULE = "_servonaut_e2e_child_guard"
_EXIT_UNGUARDED = 70


def _load_child_guard():
    import importlib.util

    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "child_guard.py"
    )
    spec = importlib.util.spec_from_file_location(_CHILD_GUARD_MODULE, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load the e2e guard from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[_CHILD_GUARD_MODULE] = module
    spec.loader.exec_module(module)
    return module


try:
    _load_child_guard().arm()
except BaseException as exc:  # noqa: BLE001 - any failure must stop the child
    try:
        sys.stderr.write(f"e2e guard could not be installed; stopping this process: {exc!r}\n")
        sys.stderr.flush()
    finally:
        os._exit(_EXIT_UNGUARDED)
