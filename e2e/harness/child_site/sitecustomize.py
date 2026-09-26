"""Install the e2e guards in a child process, or stop the child.

The suite puts this directory first on ``PYTHONPATH`` for every Python
process it starts, so the guards are active before the child imports anything
else. Settings come from the ``SERVONAUT_E2E_*`` environment variables. Once
armed, the child reports itself in ``SERVONAUT_E2E_ARMED_LOG``.

Python's ``site`` module ignores errors raised here, which would let a child
run unguarded. Any failure therefore ends the process at once (exit 70).
"""

import os
import sys

_MODULE_NAME = "_servonaut_e2e_netguard"
_EXIT_UNGUARDED = 70


def _install() -> None:
    import importlib.util

    module = sys.modules.get(_MODULE_NAME)
    if module is None:
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "netguard.py"
        )
        spec = importlib.util.spec_from_file_location(_MODULE_NAME, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load the e2e guard from {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[_MODULE_NAME] = module
        spec.loader.exec_module(module)
    module.install_from_environment()


try:
    _install()
except BaseException as exc:  # noqa: BLE001 - any failure must stop the child
    try:
        sys.stderr.write(f"e2e guard could not be installed; stopping this process: {exc!r}\n")
        sys.stderr.flush()
    finally:
        os._exit(_EXIT_UNGUARDED)
