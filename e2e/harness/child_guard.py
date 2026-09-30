"""Arm the e2e guards in the current process from its environment.

Standard library only, and without side effects on import: this file is
loaded by path, never imported as part of the ``e2e`` package.
``child_site/sitecustomize.py`` calls :func:`arm` in every Python child the
suite starts; the local QA sandbox's in-process TUI host
(``e2e/sandbox/tpmcp_host.py``) calls it to put itself inside a sandbox.

:func:`arm` installs the network, filesystem and program guards from the
``SERVONAUT_E2E_*`` variables (see ``netguard.py``) and reports the process
in ``SERVONAUT_E2E_ARMED_LOG``. It then applies two kinds of redirects:

``SERVONAUT_E2E_REDIRECTS`` (JSON, ``{"module": {"ATTRIBUTE": value}}``)
points endpoints that the application only defines as module constants at
the suite's local fakes: each attribute is replaced as soon as its module has
been imported (at once, for a module imported before arming). A redirect
whose attribute no longer exists stops the process, so a renamed constant
cannot silently send it back to the real service (the network guard would
refuse it anyway).

``SERVONAUT_E2E_PROVIDER_REDIRECTS`` points the Hetzner and OVH client
libraries at the local fakes (see ``provider_redirects.py``).

With ``watch_owner`` (the default) a daemon thread ends the process
(exit 75) once the process that owns the run, or the run's root directory,
is gone. Fixture teardown normally stops children; the watchdog covers a run
that was killed before teardown, including detached children such as a
background relay listener.
"""

import os
import sys
import threading
import time

GUARD_MODULE = "_servonaut_e2e_netguard"
ENV_REDIRECTS = "SERVONAUT_E2E_REDIRECTS"
ENV_PROVIDER_REDIRECTS = "SERVONAUT_E2E_PROVIDER_REDIRECTS"
ENV_OWNER_PID = "SERVONAUT_E2E_OWNER_PID"
ENV_OWNER_ROOT = "SERVONAUT_E2E_OWNER_ROOT"
EXIT_UNGUARDED = 70
EXIT_ORPHANED = 75
_WATCH_SECONDS = 0.25
_HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))


def process_identity(pid):
    """(state, start time) of *pid* from /proc, or None when it is gone.

    The start time tells a reused PID apart from the original process.
    Also None where there is no /proc (see :func:`owner_alive`).
    """
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii", errors="replace") as handle:
            fields = handle.read().rsplit(")", 1)[1].split()
    except (OSError, IndexError):
        return None
    return fields[0], fields[19]


def owner_alive(pid, identity, root=""):
    """True while *pid* is still the process *identity* describes and *root* exists.

    Without /proc, a live *pid* is the best available answer.
    """
    if root and not os.path.isdir(root):
        return False
    if not os.path.exists("/proc/self/stat"):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            pass
        return True
    current = process_identity(pid)
    return (
        identity is not None
        and current is not None
        and current[0] not in ("Z", "X")
        and current[1] == identity[1]
    )


def _load_by_path(name, filename):
    import importlib.util

    path = os.path.join(_HARNESS_DIR, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _install_guard():
    module = sys.modules.get(GUARD_MODULE)
    if module is None:
        module = _load_by_path(GUARD_MODULE, "netguard.py")
    module.install_from_environment()


def _start_owner_watchdog():
    raw_pid = os.environ.get(ENV_OWNER_PID, "")
    if not raw_pid.isdigit() or int(raw_pid) == os.getpid():
        return
    pid = int(raw_pid)
    root = os.environ.get(ENV_OWNER_ROOT, "")
    identity = process_identity(pid)

    def watch():
        while owner_alive(pid, identity, root):
            time.sleep(_WATCH_SECONDS)
        try:
            sys.stderr.write("e2e: the test run that started this process is gone; stopping\n")
            sys.stderr.flush()
        finally:
            os._exit(EXIT_ORPHANED)

    threading.Thread(target=watch, name="e2e-owner-watchdog", daemon=True).start()


def _redirect_providers():
    """Point the Hetzner/OVH client libraries at the fakes, when asked to."""
    if not os.environ.get(ENV_PROVIDER_REDIRECTS):
        return
    module = _load_by_path("_servonaut_e2e_provider_redirects", "provider_redirects.py")
    module.apply_from_environment()


def _set_attributes(module, attributes):
    for name, value in attributes.items():
        if not hasattr(module, name):
            sys.stderr.write(
                f"e2e redirect target {module.__name__}.{name} does not exist; "
                "stopping this process\n"
            )
            sys.stderr.flush()
            os._exit(EXIT_UNGUARDED)
        setattr(module, name, value)


class _RedirectingLoader:
    """Runs the real loader, then replaces the redirected attributes."""

    def __init__(self, loader, attributes):
        self._loader = loader
        self._attributes = attributes

    def create_module(self, spec):
        return self._loader.create_module(spec)

    def exec_module(self, module):
        self._loader.exec_module(module)
        _set_attributes(module, self._attributes)

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


def _install_redirects():
    raw = os.environ.get(ENV_REDIRECTS)
    if not raw:
        return
    import json

    redirects = json.loads(raw)
    if not isinstance(redirects, dict) or not all(
        isinstance(attributes, dict) for attributes in redirects.values()
    ):
        raise ValueError(f"{ENV_REDIRECTS} must map module names to attribute objects")
    # Arming again (a long-lived host) replaces the previous redirects.
    sys.meta_path[:] = [
        finder for finder in sys.meta_path if type(finder).__name__ != _RedirectFinder.__name__
    ]
    sys.meta_path.insert(0, _RedirectFinder(redirects))
    for name, attributes in redirects.items():
        if name in sys.modules:
            _set_attributes(sys.modules[name], attributes)


def arm(*, watch_owner=True):
    """Install the guards and apply the redirects named in the environment."""
    # The process never writes bytecode: what it imports lives in the
    # toolchain and the checkout, outside the sandbox.
    sys.dont_write_bytecode = True
    _install_guard()
    if watch_owner:
        _start_owner_watchdog()
    _install_redirects()
    _redirect_providers()
