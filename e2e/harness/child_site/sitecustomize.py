"""Install the e2e guards in a child process, or stop the child.

The suite puts this directory first on ``PYTHONPATH`` for every Python
process it starts, so the guards are active before the child imports anything
else. Settings come from the ``SERVONAUT_E2E_*`` environment variables. Once
armed, the child reports itself in ``SERVONAUT_E2E_ARMED_LOG``.

``SERVONAUT_E2E_REDIRECTS`` (JSON, ``{"module": {"ATTRIBUTE": value}}``)
points endpoints that the application only defines as module constants at
the suite's local fakes: each attribute is replaced as soon as its module has
been imported. A redirect whose attribute no longer exists stops the child,
so a renamed constant cannot silently send a child back to the real service
(the network guard would refuse it anyway).

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

_MODULE_NAME = "_servonaut_e2e_netguard"
_ENV_REDIRECTS = "SERVONAUT_E2E_REDIRECTS"
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


class _RedirectingLoader:
    """Runs the real loader, then replaces the redirected attributes."""

    def __init__(self, loader, attributes):
        self._loader = loader
        self._attributes = attributes

    def create_module(self, spec):
        return self._loader.create_module(spec)

    def exec_module(self, module):
        self._loader.exec_module(module)
        for name, value in self._attributes.items():
            if not hasattr(module, name):
                sys.stderr.write(
                    f"e2e redirect target {module.__name__}.{name} does not exist; "
                    "stopping this process\n"
                )
                sys.stderr.flush()
                os._exit(_EXIT_UNGUARDED)
            setattr(module, name, value)

    def __getattr__(self, name):
        return getattr(self._loader, name)


class _RedirectFinder:
    """Meta path finder that wraps the loader of each redirected module."""

    def __init__(self, redirects):
        self._redirects = redirects

    def find_spec(self, fullname, path, target=None):
        attributes = self._redirects.get(fullname)
        if attributes is None:
            return None
        for finder in sys.meta_path:
            if finder is self or not hasattr(finder, "find_spec"):
                continue
            spec = finder.find_spec(fullname, path, target)
            if spec is not None and spec.loader is not None:
                spec.loader = _RedirectingLoader(spec.loader, attributes)
                return spec
        return None


def _install_redirects() -> None:
    raw = os.environ.get(_ENV_REDIRECTS)
    if not raw:
        return
    import json

    redirects = json.loads(raw)
    if not isinstance(redirects, dict) or not all(
        isinstance(attributes, dict) for attributes in redirects.values()
    ):
        raise ValueError(f"{_ENV_REDIRECTS} must map module names to attribute objects")
    sys.meta_path.insert(0, _RedirectFinder(redirects))


try:
    _install()
    _install_redirects()
except BaseException as exc:  # noqa: BLE001 - any failure must stop the child
    try:
        sys.stderr.write(f"e2e guard could not be installed; stopping this process: {exc!r}\n")
        sys.stderr.flush()
    finally:
        os._exit(_EXIT_UNGUARDED)
