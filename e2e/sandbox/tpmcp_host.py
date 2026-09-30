"""Run the QA sandbox's TUI inside a textual-pilot-mcp server.

``tpmcp_spec.py`` (160x50) and ``tpmcp_spec_narrow.py`` (100x30) load this
file by path and call :func:`make_spec`. textual-pilot-mcp imports a spec
once, when its server starts, in its own interpreter and virtual
environment, and runs the app in that process at every ``launch``. So at
import time nothing here touches a Servonaut checkout (only the standard
library, textual-pilot-mcp and the sibling ``state.py``); everything else
happens at ``launch``:

1. ``HOME`` resolves through the per-user pointer to the live sandbox's
   ``state.json`` (a clear error when no sandbox runs).
2. The process environment is REPLACED by the sandbox's child environment,
   so nothing of the server's own environment (cloud credentials, tokens,
   proxies) reaches the app.
3. The harness's own ``child_guard.arm()`` from the checkout that started the
   sandbox installs the network, filesystem and program guards and the
   module redirects every sandbox child gets (without the owner watchdog:
   ending this process would end the MCP server).
4. Package metadata for ``servonaut`` (the version the app shows and its
   install details) is answered from the sandbox's interpreter, as its
   children read it, not from this server's own install.
5. That checkout's ``src`` goes first on ``sys.path``, and only then is
   ``servonaut.app`` imported; the app must come from there.

Several Servonaut modules bind paths under ``HOME`` when first imported, and
a process imports a module once. A later ``launch`` therefore needs a sandbox
with the same home (restarting the same checkout's sandbox keeps its path);
anything else fails loudly and asks for a server restart.

Snapshots go to ``${XDG_STATE_HOME:-~/.local/state}/servonaut-qa/captures/``
(the one place outside the sandbox this process may write).
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import os
import sys
import tempfile
import time
import types
from pathlib import Path
from typing import Any

from textual_pilot_mcp import AppSpec

_HERE = Path(__file__).resolve().parent
_STATE_MODULE = "_servonaut_qa_state"
_CHILD_GUARD_MODULE = "_servonaut_e2e_child_guard"
_GUARD_MODULE = "_servonaut_e2e_netguard"
_SERVER_ENV_MODULE = "_servonaut_qa_server_env"
# The checkout holding this spec: the install the fix for missing SDKs names.
_CHECKOUT = _HERE.parent.parent
# Client libraries the sandbox's fakes stand in for; the app lists no Hetzner
# or OVH servers without them.
_PROVIDER_SDKS = ("hcloud", "ovh")
# Import-time locations that must lie in the sandbox home (see
# e2e/harness/canary.py for the full list the suite checks).
_HOME_BOUND = ("servonaut.config.manager", "CONFIG_DIR")


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _server_env() -> dict:
    """The environment the server was started with (for the per-user paths).

    Kept in a module of its own: the first launch replaces ``os.environ``,
    and a ``reload`` of the spec runs this file again.
    """
    holder = sys.modules.get(_SERVER_ENV_MODULE)
    if holder is None:
        holder = types.ModuleType(_SERVER_ENV_MODULE)
        holder.env = dict(os.environ)
        sys.modules[_SERVER_ENV_MODULE] = holder
    return holder.env


_state = _load(_STATE_MODULE, _HERE / "state.py")
_SERVER_ENV = _server_env()


class SandboxLaunchError(RuntimeError):
    """The app cannot be launched in the sandbox (the message says what to do)."""


def _disarm_guard() -> None:
    """Lift the filesystem and program guards a previous launch installed.

    The pointer lives outside the sandbox; the next launch arms them again.
    """
    guard = sys.modules.get(_GUARD_MODULE)
    if guard is not None:
        guard.disarm_filesystem_and_spawns()


def _live_state() -> dict:
    _disarm_guard()
    try:
        return _state.load_live_state(_SERVER_ENV)
    except _state.SandboxUnavailable as exc:
        raise SandboxLaunchError(str(exc)) from None


class SandboxHome(os.PathLike):
    """``AppSpec.home_dir`` that resolves to the live sandbox's home at launch."""

    _qa_sandbox_home = True

    def __fspath__(self) -> str:
        return _live_state()["sandbox"]["home"]

    def __eq__(self, other: object) -> bool:
        # A reloaded spec builds a new instance of a new class: same setting.
        return getattr(other, "_qa_sandbox_home", False)

    def __hash__(self) -> int:
        return hash("qa-sandbox-home")

    def __repr__(self) -> str:
        return f"<the live QA sandbox's home, read at launch from {_state.pointer_path(_SERVER_ENV)}>"


def _check_provider_sdks() -> None:
    missing = [module for module in _PROVIDER_SDKS if importlib.util.find_spec(module) is None]
    if missing:
        raise SandboxLaunchError(
            f"this MCP server's Python ({sys.executable}) lacks {', '.join(missing)}, which "
            "the sandbox's Hetzner and OVH servers need. For a pipx install of "
            "textual-pilot-mcp, run: "
            f'pipx inject textual-pilot-mcp -e "{_CHECKOUT}[hetzner,ovh]" --force '
            "and restart the MCP server."
        )


def _check_loaded_servonaut(current: dict) -> None:
    """A second launch must match what this process imported the first time."""
    module = sys.modules.get("servonaut")
    if module is None:
        return
    src = Path(current["src_dir"])
    home = Path(current["sandbox"]["home"])
    loaded_from = Path(module.__file__ or "").resolve()
    bound_module = sys.modules.get(_HOME_BOUND[0])
    bound = Path(getattr(bound_module, _HOME_BOUND[1], "")) if bound_module else None
    if src not in loaded_from.parents or (bound is not None and home not in bound.parents):
        raise SandboxLaunchError(
            f"this MCP server already runs Servonaut from {loaded_from.parent} with its home "
            f"paths bound to {bound.parent if bound else 'unknown'}; the live sandbox uses "
            f"{src} and {home}. Restart the MCP server to use this sandbox."
        )


class _SandboxDistributionFinder(importlib.metadata.DistributionFinder):
    """Answers for the ``servonaut`` distribution with the sandbox's own.

    The app reads its version and install details from package metadata.
    This interpreter has its own (often older) install; the sandbox's
    children read the one of the interpreter that started the sandbox, and
    so must the app hosted here, or it would show another version and offer
    an update to the one the local package index serves.
    """

    def __init__(self, dist_info: str) -> None:
        self._distribution = importlib.metadata.PathDistribution(Path(dist_info))

    def find_spec(self, *args: Any, **kwargs: Any) -> None:
        return None

    def find_distributions(self, context: Any = None) -> list:
        name = getattr(context, "name", None)
        if name and name.replace("-", "_").lower() == "servonaut":
            return [self._distribution]
        return []


def _use_sandbox_distribution(current: dict) -> None:
    sys.meta_path[:] = [
        finder for finder in sys.meta_path
        if type(finder).__name__ != _SandboxDistributionFinder.__name__
    ]
    if current.get("distribution"):
        sys.meta_path.insert(0, _SandboxDistributionFinder(current["distribution"]))


def _enter_sandbox(current: dict, captures: Path) -> None:
    """Replace the environment, arm the guards, put the checkout's src first."""
    env = dict(current["env"])
    captures.mkdir(parents=True, exist_ok=True)
    readable = [str(captures), current.get("distribution") or ""]
    env["SERVONAUT_E2E_ALLOWED_DIRS"] = os.pathsep.join(
        filter(None, [env.get("SERVONAUT_E2E_ALLOWED_DIRS", ""), *readable])
    )
    env["SERVONAUT_E2E_WRITE_ROOTS"] = os.pathsep.join(
        filter(None, [env.get("SERVONAUT_E2E_WRITE_ROOTS", ""), str(captures)])
    )
    os.environ.clear()
    os.environ.update(env)
    os.chdir(current["sandbox"]["base"])  # where the sandbox's children start
    tempfile.tempdir = None  # re-read TMPDIR
    if hasattr(time, "tzset"):
        time.tzset()
    guard_file = Path(current["repo_root"]) / "e2e" / "harness" / "child_guard.py"
    child_guard = sys.modules.get(_CHILD_GUARD_MODULE)
    if child_guard is None or Path(child_guard.__file__).resolve() != guard_file.resolve():
        child_guard = _load(_CHILD_GUARD_MODULE, guard_file)
    child_guard.arm(watch_owner=False)
    _use_sandbox_distribution(current)
    src = current["src_dir"]
    if sys.path[:1] != [src]:
        sys.path.insert(0, src)


def _verify_source(current: dict) -> None:
    import servonaut

    src = Path(current["src_dir"]).resolve()
    loaded_from = Path(servonaut.__file__ or "").resolve()
    if src not in loaded_from.parents:
        raise SandboxLaunchError(
            f"servonaut was imported from {loaded_from.parent}, not from the sandbox's "
            f"checkout {src}; restart the MCP server"
        )


def make_spec(size: tuple[int, int]) -> AppSpec:
    """The AppSpec of the sandbox's TUI at *size* (columns, rows)."""
    captures = _state.captures_dir(_SERVER_ENV) / f"{size[0]}x{size[1]}"

    def build_app() -> Any:
        current = _live_state()
        _check_provider_sdks()
        _check_loaded_servonaut(current)
        _enter_sandbox(current, captures)
        _verify_source(current)
        from servonaut.app import ServonautApp
        from servonaut.runtime import detect_runtime

        return ServonautApp(runtime_layout=detect_runtime())

    return AppSpec(
        factory=build_app,
        size=size,
        home_dir=SandboxHome(),
        output_dir=captures,
        title_template="Servonaut QA — {scene}",
    )
