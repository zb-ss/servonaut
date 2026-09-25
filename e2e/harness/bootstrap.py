"""Hermetic environment for the end-to-end suite.

:func:`bootstrap` runs from the first lines of ``e2e/conftest.py``, before
any ``servonaut`` import. It creates a private test root, replaces the
process environment with an allowlist that points every home, cache, temp,
cloud and API location inside that root, and installs the network and
filesystem guards. :func:`build_env` produces the same kind of environment
for child processes (CLI, MCP server), each with its own home.

Nothing here reads or copies the developer's environment beyond locating the
real home directory, which is only used to *protect* it.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Mapping, Optional

HARNESS_DIR = Path(__file__).resolve().parent
E2E_DIR = HARNESS_DIR.parent
REPO_ROOT = E2E_DIR.parent
SRC_DIR = REPO_ROOT / "src"
CHILD_SITE_DIR = HARNESS_DIR / "child_site"

# Optional user settings, read from the invoking environment.
ENV_ROOT_BASE = "SERVONAUT_E2E_ROOT"  # directory to create test roots in
ENV_KEEP = "SERVONAUT_E2E_KEEP"  # "1" keeps the test root for inspection
ENV_ARTIFACTS = "SERVONAUT_E2E_ARTIFACTS"  # where failure artifacts go
# Set for every child: the run's pytest process and test root. A child stops
# itself once either is gone (child_site/sitecustomize.py).
ENV_OWNER_PID = "SERVONAUT_E2E_OWNER_PID"
ENV_OWNER_ROOT = "SERVONAUT_E2E_OWNER_ROOT"
# Internal: lets xdist workers create their roots next to the controller's.
_ENV_BASE_TMP = "SERVONAUT_E2E_BASE_TMP"

GUARD_MODULE = "_servonaut_e2e_netguard"

# Port 9 (discard) on loopback: nothing listens, so any request that was not
# pointed at a fake is refused at once instead of reaching a real service.
DEAD_HTTPS_URL = "https://127.0.0.1:9"
DEAD_HTTP_URL = "http://127.0.0.1:9"
# A neutral account name for every process (some code reads the login name).
SANDBOX_USER = "e2e-user"
ARTIFACTS_MARKER = ".servonaut-e2e-artifacts"

# Variables carried from the invoking environment into the test process so
# pytest-xdist workers (which inherit it) see the same settings.
_CARRIED_VARIABLES = (
    ENV_ROOT_BASE,
    ENV_KEEP,
    ENV_ARTIFACTS,
    "PYTEST_XDIST_WORKER",
    "PYTEST_XDIST_WORKER_COUNT",
    "PYTEST_XDIST_TESTRUNUID",
    "PYTEST_ADDOPTS",
)


class HermeticityError(RuntimeError):
    """The suite cannot guarantee isolation, so it refuses to run."""


@dataclass(frozen=True)
class Sandbox:
    """One isolated set of home, temp and XDG directories."""

    base: Path

    @property
    def home(self) -> Path:
        return self.base / "home"

    @property
    def tmp(self) -> Path:
        return self.base / "tmp"

    def xdg(self, kind: str) -> Path:
        return self.base / "xdg" / kind

    def create(self) -> "Sandbox":
        for path in (
            self.home,
            self.tmp,
            self.xdg("config"),
            self.xdg("cache"),
            self.xdg("data"),
            self.xdg("state"),
            self.xdg("runtime"),
        ):
            path.mkdir(parents=True, exist_ok=True)
        self.xdg("runtime").chmod(0o700)
        return self

    def reset_home(self) -> None:
        """Empty the home directory (the directory itself is kept)."""
        if self.home.exists():
            shutil.rmtree(self.home)
        self.home.mkdir(parents=True)


@dataclass(frozen=True)
class E2EContext:
    """Everything the fixtures need to know about this process's test root."""

    root: Path
    worker: str
    sandbox: Sandbox  # the in-process sandbox (TUI journeys share it)
    ca_cert: Path
    server_cert: Path
    server_key: Path
    protected_dirs: tuple[str, ...]
    allowed_dirs: tuple[str, ...]
    write_roots: tuple[str, ...]
    artifacts_dir: Path
    keep_root: bool

    @property
    def tests_dir(self) -> Path:
        return self.root / "tests"

    @property
    def default_shims(self) -> Path:
        return self.root / "shims-default"


_CONTEXT: Optional[E2EContext] = None


def context() -> E2EContext:
    """Return the context created by :func:`bootstrap`."""
    if _CONTEXT is None:
        raise HermeticityError("e2e bootstrap has not run in this process")
    return _CONTEXT


def is_within(path: "str | os.PathLike[str]", root: "str | os.PathLike[str]") -> bool:
    """True when *path* is *root* or lies below it, after resolving symlinks."""
    return load_guard().within(os.path.realpath(path), os.path.realpath(root))


def load_guard() -> ModuleType:
    """Return the shared guard module (also loaded by child_site/sitecustomize)."""
    module = sys.modules.get(GUARD_MODULE)
    if module is None:
        spec = importlib.util.spec_from_file_location(GUARD_MODULE, HARNESS_DIR / "netguard.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[GUARD_MODULE] = module
        spec.loader.exec_module(module)
    return module


def _real_home_dirs(original_env: Mapping[str, str]) -> tuple[str, ...]:
    """The developer's real home directories, which the suite must never touch.

    A pytest-xdist worker inherits the controller's hermetic environment, so
    its ``HOME`` is already a sandbox; it takes the protected list the
    controller computed instead.
    """
    candidates: list[str] = []
    inherited = original_env.get("SERVONAUT_E2E_PROTECTED_DIRS", "")
    if inherited:
        candidates.extend(p for p in inherited.split(os.pathsep) if p)
    elif original_env.get("HOME"):
        candidates.append(original_env["HOME"])
    try:
        import pwd

        candidates.append(pwd.getpwuid(os.getuid()).pw_dir)
    except (ImportError, KeyError):
        pass
    out: list[str] = []
    for candidate in candidates:
        path = os.path.realpath(candidate)
        if path != os.sep and path not in out:
            out.append(path)
    return tuple(out)


def _assert_servonaut_not_imported() -> None:
    loaded = sorted(
        name for name in sys.modules if name == "servonaut" or name.startswith("servonaut.")
    )
    if loaded:
        raise HermeticityError(
            "servonaut was imported before the e2e bootstrap "
            f"({', '.join(loaded[:3])}...). Run `python -m pytest e2e` in its own "
            "process, not together with tests/."
        )


# ---------------------------------------------------------------------------
# Child environments
# ---------------------------------------------------------------------------


def _home_env(sandbox: Sandbox) -> dict[str, str]:
    """Home, temp and locale: everything points inside *sandbox*."""
    return {
        "HOME": str(sandbox.home),
        "USERPROFILE": str(sandbox.home),
        "USER": SANDBOX_USER,
        "LOGNAME": SANDBOX_USER,
        "USERNAME": SANDBOX_USER,
        "XDG_CONFIG_HOME": str(sandbox.xdg("config")),
        "XDG_CACHE_HOME": str(sandbox.xdg("cache")),
        "XDG_DATA_HOME": str(sandbox.xdg("data")),
        "XDG_STATE_HOME": str(sandbox.xdg("state")),
        "XDG_RUNTIME_DIR": str(sandbox.xdg("runtime")),
        "TMPDIR": str(sandbox.tmp),
        "TMP": str(sandbox.tmp),
        "TEMP": str(sandbox.tmp),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "TERM": "xterm-256color",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
        "TEXTUAL_ANIMATIONS": "none",
    }


def _tool_env(shim_dir: Path) -> dict[str, str]:
    """``PATH`` holds the fake tools alone; Python children load the guard."""
    return {
        "PATH": str(shim_dir),
        "PYTHONPATH": os.pathsep.join([str(CHILD_SITE_DIR), str(SRC_DIR)]),
        "BROWSER": str(shim_dir / "browser"),
        "EDITOR": str(shim_dir / "editor"),
        "VISUAL": str(shim_dir / "editor"),
    }


def _service_env(home: Path, ca_cert: Path) -> dict[str, str]:
    """Cloud SDKs and Servonaut endpoints: fake credentials, refused endpoints.

    There are deliberately no proxy variables: a proxy would turn a request
    to a real host into a loopback connection the socket guard cannot see.
    """
    return {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_CONFIG_FILE": str(home / ".aws" / "config"),
        "AWS_SHARED_CREDENTIALS_FILE": str(home / ".aws" / "credentials"),
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_MAX_ATTEMPTS": "1",
        "AWS_RETRY_MODE": "standard",
        "AWS_ENDPOINT_URL": DEAD_HTTP_URL,
        "PYTHON_KEYRING_BACKEND": "keyring.backends.null.Keyring",
        "SERVONAUT_API_URL": DEAD_HTTPS_URL,
        "SERVONAUT_MCP_URL": DEAD_HTTPS_URL,
        # Only the suite's own CA is trusted.
        "SSL_CERT_FILE": str(ca_cert),
    }


def _guard_env(
    ctx: E2EContext, shim_dir: Path, guard_log: Path, armed_log: Path
) -> dict[str, str]:
    """Settings for the guard every Python child installs (child_site)."""
    return {
        "SERVONAUT_E2E_GUARD_LOG": str(guard_log),
        "SERVONAUT_E2E_ARMED_LOG": str(armed_log),
        "SERVONAUT_E2E_PROTECTED_DIRS": os.pathsep.join(ctx.protected_dirs),
        "SERVONAUT_E2E_ALLOWED_DIRS": os.pathsep.join(ctx.allowed_dirs),
        # Children may write inside the test root only.
        "SERVONAUT_E2E_WRITE_ROOTS": str(ctx.root),
        "SERVONAUT_E2E_SPAWN_DIRS": str(shim_dir),
        ENV_OWNER_PID: str(os.getpid()),
        ENV_OWNER_ROOT: str(ctx.root),
    }


def build_env(
    sandbox: Sandbox,
    *,
    shim_dir: Path,
    guard_log: Path,
    armed_log: Path,
    extra: Optional[Mapping[str, str]] = None,
) -> dict[str, str]:
    """Return a complete environment for a process living in *sandbox*.

    Starts from nothing: only the variables listed in the helpers above exist.
    """
    ctx = context()
    env = {
        **_home_env(sandbox),
        **_tool_env(shim_dir),
        **_service_env(sandbox.home, ctx.ca_cert),
        **_guard_env(ctx, shim_dir, guard_log, armed_log),
    }
    if extra:
        env.update(extra)
    return env


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------


def _artifacts_dir(original_env: Mapping[str, str], protected: tuple[str, ...]) -> Path:
    """Where failure artifacts go; never a directory holding the checkout or a home."""
    configured = original_env.get(ENV_ARTIFACTS)
    path = Path(configured).resolve() if configured else REPO_ROOT / "e2e-artifacts"
    for guarded in (*protected, str(REPO_ROOT)):
        if is_within(guarded, path):
            raise HermeticityError(
                f"{ENV_ARTIFACTS} must not be (or contain) the checkout or a home "
                f"directory; got {path}"
            )
    return path


def _lift_inherited_guard() -> None:
    """Disarm a guard inherited from the pytest-xdist controller.

    A worker inherits the controller's environment, so child_site already
    armed the guard with the controller's roots. This process needs its own
    root first; :func:`bootstrap` re-arms the guard afterwards.
    """
    if GUARD_MODULE in sys.modules:
        sys.modules[GUARD_MODULE].disarm_filesystem_and_spawns()


def _make_context(
    root: Path,
    worker: str,
    original_env: Mapping[str, str],
    protected: tuple[str, ...],
    artifacts_dir: Path,
) -> E2EContext:
    from e2e.harness.fake_cloud import tls

    material = tls.generate(root / "tls")
    return E2EContext(
        root=root,
        worker=worker,
        sandbox=Sandbox(root / "proc").create(),
        ca_cert=material.ca_cert,
        server_cert=material.server_cert,
        server_key=material.server_key,
        protected_dirs=protected,
        allowed_dirs=(str(root), str(REPO_ROOT), str(artifacts_dir)),
        # The test process may also write pytest's cache and the failure
        # artifacts; nothing else outside the test root.
        write_roots=(
            str(root),
            str(artifacts_dir),
            str(REPO_ROOT / ".pytest_cache"),
            str(REPO_ROOT / "pytest-cache-files-") + "*",
        ),
        artifacts_dir=artifacts_dir,
        keep_root=original_env.get(ENV_KEEP) == "1",
    )


def _apply_environment(ctx: E2EContext, original_env: Mapping[str, str], base: str) -> None:
    ctx.default_shims.mkdir()
    env = build_env(
        ctx.sandbox,
        shim_dir=ctx.default_shims,
        guard_log=ctx.root / "guard-default.jsonl",
        armed_log=ctx.root / "armed-default.jsonl",
    )
    for name in _CARRIED_VARIABLES:
        if name in original_env:
            env[name] = original_env[name]
    env[_ENV_BASE_TMP] = base
    os.environ.clear()
    os.environ.update(env)
    tempfile.tempdir = None  # re-read TMPDIR
    # Bytecode caches would be written next to the sources, outside the root.
    sys.dont_write_bytecode = True


def bootstrap() -> E2EContext:
    """Create the test root, apply the hermetic environment, arm the guards."""
    global _CONTEXT
    if _CONTEXT is not None:
        return _CONTEXT
    _assert_servonaut_not_imported()
    original_env = dict(os.environ)
    _lift_inherited_guard()
    worker = original_env.get("PYTEST_XDIST_WORKER", "main")
    # Validate the settings before anything is created on disk.
    protected = _real_home_dirs(original_env)
    artifacts_dir = _artifacts_dir(original_env, protected)
    base = (
        original_env.get(ENV_ROOT_BASE)
        or original_env.get(_ENV_BASE_TMP)
        or tempfile.gettempdir()
    )
    Path(base).mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix=f"servonaut-e2e-{worker}-", dir=base)).resolve()
    _CONTEXT = _make_context(root, worker, original_env, protected, artifacts_dir)
    _apply_environment(_CONTEXT, original_env, base)
    load_guard().install(
        log_path=None,
        protected=_CONTEXT.protected_dirs,
        allowed=_CONTEXT.allowed_dirs,
        write_roots=_CONTEXT.write_roots,
        spawn_dirs=[str(_CONTEXT.default_shims)],
    )
    return _CONTEXT


def teardown() -> None:
    """Remove the test root unless ``SERVONAUT_E2E_KEEP=1``."""
    ctx = _CONTEXT
    if ctx is None or ctx.keep_root:
        return
    try:
        shutil.rmtree(ctx.root)
    except OSError as exc:
        sys.stderr.write(f"e2e: could not remove the test root {ctx.root}: {exc}\n")
