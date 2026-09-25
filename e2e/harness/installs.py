"""Install Servonaut the way users do, inside the test root and offline.

- :func:`session_wheels` builds the checkout with ``python -m build``, as the
  publish workflow does, using the build backend already installed in this
  environment (``--no-isolation``), so nothing is downloaded. The checkout is
  built as the next patch release, above every published release (between
  releases it carries the latest one's version), and once more as the release
  after that, to update to. Under pytest-xdist the controller builds them once
  for all workers (:func:`prebuild_for_workers`).
- :class:`VenvInstall` is ``pip install servonaut`` into a fresh venv;
  :class:`PipxInstall` is ``pipx install servonaut`` with ``PIPX_HOME`` and
  ``PIPX_BIN_DIR`` under the journey. Both install Servonaut from FakeCloud's
  package index, which serves the wheels a journey offers.
- Dependencies come from this test environment. Every install sees a
  read-only *overlay* of its site-packages (symlinks, without Servonaut and
  pip), appended after the install's own site-packages, so pip finds each
  requirement already satisfied and never looks one up.
- Every Python process of an install arms the e2e guard. Direct children get
  it through ``PYTHONPATH``. Every venv, ours or pipx's, is created without
  pip and gets the start-up hook before anything runs in it; pip is added
  afterwards (``venv`` itself would run ``ensurepip`` without ``PYTHONPATH``).
  pipx drops ``PYTHONPATH`` too, so it runs Python through a wrapper
  (``PIPX_DEFAULT_PYTHON``) that arms the guard and creates venvs that way.
  The hook is a ``.pth`` file, which a ``sitecustomize`` module shipped by
  some Linux distributions cannot shadow.
- The update check reads FakeCloud's JSON document through
  ``SERVONAUT_PYPI_URL``, which the ``fake_cloud`` fixture sets. Releases
  from before that variable existed read a module constant, so for those the
  hook applies the same URL to it.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shlex
import shutil
import sys
import sysconfig
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from e2e.harness.bootstrap import (
    CHILD_SITE_DIR,
    E2E_DIR,
    ENV_PREBUILT_WHEELS,
    REPO_ROOT,
    E2EContext,
    Sandbox,
    build_env,
    is_within,
    load_guard,
)
from e2e.harness.processes import ChildLog, CliResult, run_cli
from e2e.tools import fetch_previous_release as fetcher

HOOK_MODULE = "_servonaut_e2e_site"
# The app's own override for the update check's package-index URL.
ENV_PYPI_URL = "SERVONAUT_PYPI_URL"
PIPX_VENV_NAME = "servonaut"
PACKAGED_JOURNEYS = E2E_DIR / "journeys" / "packaged"
WHEELS_MANIFEST = "wheels.json"
BUILD_MODULES = ("build", "hatchling")
BUILD_TIMEOUT_SECONDS = 180.0
INSTALL_TIMEOUT_SECONDS = 180.0

# Kept out of the overlay: the app must come from the install alone, and
# each install has its own pip. ``.pth`` files would not run from the
# overlay anyway (it is a plain path entry, not a site directory).
_OVERLAY_EXCLUDED = re.compile(
    r"^(servonaut([-_.].*)?|_servonaut.*|__editable__.*"
    r"|pip|pip-.*\.dist-info|__pycache__|.*\.pth)$",
    re.IGNORECASE,
)
# The source files a wheel build needs (see [tool.hatch.build] in pyproject),
# and the ignore rules the build applies to them.
_BUILD_INPUTS = ("pyproject.toml", "README.md", "LICENSE", ".gitignore", "src")

_HOOK_SOURCE = '''\
"""Start-up hook for Servonaut installs in the e2e suite (test root only).

Arms the e2e guard, exposes the test environment's packages (the overlay)
after this install's own, and, in releases older than the ${env_url}
override, points the update check at the URL it names.
"""

import os
import sys

_GUARD_SITE = {guard_site!r}
_OVERLAY = {overlay!r}
_UPDATE_MODULE = "servonaut.services.update_service"


class _PackageIndexRedirect:
    """Set ``PYPI_URL`` in releases whose update service has no override."""

    def find_spec(self, name, path, target=None):
        url = os.environ.get({env_url!r})
        if name != _UPDATE_MODULE or not url:
            return None
        from importlib.machinery import PathFinder

        spec = PathFinder.find_spec(name, path)
        if spec is None or spec.loader is None:
            return spec
        execute = spec.loader.exec_module

        def exec_module(module):
            execute(module)
            if not hasattr(module, "PYPI_URL_ENV"):
                module.PYPI_URL = url

        spec.loader.exec_module = exec_module
        return spec


if _OVERLAY not in sys.path:
    sys.path.append(_OVERLAY)
if "_servonaut_e2e_netguard" not in sys.modules:
    import runpy

    runpy.run_path(_GUARD_SITE, run_name="_servonaut_e2e_guard_site")
if not any(isinstance(f, _PackageIndexRedirect) for f in sys.meta_path):
    sys.meta_path.insert(0, _PackageIndexRedirect())
'''


def environment_site_dirs() -> list[Path]:
    """This interpreter's site-packages directories (the overlay's source)."""
    paths = sysconfig.get_paths()
    out: list[Path] = []
    for key in ("purelib", "platlib"):
        path = Path(paths[key]).resolve()
        if path not in out:
            out.append(path)
    return out


def build_overlay(destination: Path) -> Path:
    """Link every package of this environment, except Servonaut and pip."""
    destination.mkdir(parents=True)
    for site_dir in environment_site_dirs():
        for entry in sorted(site_dir.iterdir()):
            link = destination / entry.name
            if _OVERLAY_EXCLUDED.match(entry.name) or link.exists():
                continue
            link.symlink_to(entry)
    return destination


# The Python pipx runs. pipx drops PYTHONPATH from its children, so this
# arms the guard itself. A venv is created without pip and hooked before
# anything runs in it; then pip is added by ensurepip, armed (venv would run
# ensurepip without PYTHONPATH, before the hook exists).
_PIPX_PYTHON_SOURCE = """\
PYTHONPATH={child_site}
export PYTHONPATH
if [ "$1" != "-m" ] || [ "$2" != "venv" ]; then
    exec {python} "$@"
fi
shift 2
with_pip=yes
for target do
    if [ "$target" = "--without-pip" ]; then with_pip=; fi
done
{python} -m venv --without-pip "$@" || exit $?
{python} {add_hook} "$target" || exit $?
if [ -n "$with_pip" ]; then
    exec "$target/bin/python" -m ensurepip --upgrade --default-pip
fi
"""

_ADD_HOOK_SOURCE = """\
\"\"\"Copy the e2e start-up hook into the venv named on the command line.\"\"\"

import shutil
import sys
import sysconfig
from pathlib import Path

target = sys.argv[1]
scheme = "venv" if "venv" in sysconfig.get_scheme_names() else "posix_prefix"
site = Path(sysconfig.get_path("purelib", scheme, vars={{"base": target, "platbase": target}}))
for source in Path({template!r}).iterdir():
    shutil.copyfile(source, site / source.name)
"""


def venv_site_packages(venv: Path) -> Path:
    """The site-packages directory of a venv made by this interpreter."""
    scheme = "venv" if "venv" in sysconfig.get_scheme_names() else "posix_prefix"
    paths = {"base": str(venv), "platbase": str(venv)}
    return Path(sysconfig.get_path("purelib", scheme, vars=paths))


def write_hook(site_packages: Path, overlay: Path) -> None:
    """Put the start-up hook into *site_packages*: a module and the ``.pth``
    line that runs it in every process of that venv."""
    source = _HOOK_SOURCE.format(
        guard_site=str(CHILD_SITE_DIR / "sitecustomize.py"),
        overlay=str(overlay),
        env_url=ENV_PYPI_URL,
    )
    (site_packages / f"{HOOK_MODULE}.py").write_text(source, encoding="utf-8")
    (site_packages / f"{HOOK_MODULE}.pth").write_text(f"import {HOOK_MODULE}\n", encoding="utf-8")


def has_hook(venv: Path) -> bool:
    return (venv_site_packages(venv) / f"{HOOK_MODULE}.pth").is_file()


def copy_sources(destination: Path, *, version: Optional[str] = None) -> Path:
    """Copy the build inputs of the checkout, optionally with another version."""
    destination.mkdir(parents=True)
    for name in _BUILD_INPUTS:
        source = REPO_ROOT / name
        if source.is_dir():
            ignore = shutil.ignore_patterns("__pycache__")
            shutil.copytree(source, destination / name, ignore=ignore)
        else:
            shutil.copy2(source, destination / name)
    if version is not None:
        _set_version(destination / "pyproject.toml", r'^(version\s*=\s*")[^"]+(")', version)
        _set_version(
            destination / "src" / "servonaut" / "__init__.py",
            r"^(__version__\s*=\s*['\"])[^'\"]+(['\"])",
            version,
        )
    return destination


def _set_version(path: Path, pattern: str, version: str) -> None:
    text, count = re.subn(
        pattern, rf"\g<1>{version}\g<2>", path.read_text(encoding="utf-8"), count=1, flags=re.M
    )
    if count != 1:
        raise RuntimeError(f"no version to replace in {path}")
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Running tools
# ---------------------------------------------------------------------------


@dataclass
class ToolRunner:
    """Runs guarded child processes with one environment recipe."""

    env_for: Callable[[Sandbox], dict[str, str]]
    armed_log: Path
    log: Optional[ChildLog] = None

    def run(
        self,
        sandbox: Sandbox,
        argv: Iterable[str],
        *,
        timeout: float = 60.0,
        stdin: Optional[str] = None,
    ) -> CliResult:
        return run_cli(
            list(argv),
            env=self.env_for(sandbox),
            cwd=sandbox.base,
            armed_log=self.armed_log,
            stdin=stdin,
            timeout=timeout,
            log=self.log,
        )

    def make_venv(self, sandbox: Sandbox, path: Path, overlay: Path) -> None:
        """``python -m venv`` with this interpreter, hooked before pip is added.

        venv runs ensurepip without ``PYTHONPATH``, so it would run unguarded;
        here pip is added afterwards, by a process the hook arms.
        """
        self._must_pass(sandbox, [sys.executable, "-m", "venv", "--without-pip", str(path)])
        write_hook(venv_site_packages(path), overlay)
        python = str(path / "bin" / "python")
        self._must_pass(sandbox, [python, "-m", "ensurepip", "--upgrade", "--default-pip"])

    def _must_pass(self, sandbox: Sandbox, argv: list[str]) -> None:
        result = self.run(sandbox, argv, timeout=INSTALL_TIMEOUT_SECONDS)
        if result.returncode != 0:
            raise RuntimeError(f"{argv[1:3]} failed:\n{result.describe()}")


def build_wheel(
    runner: ToolRunner, sandbox: Sandbox, source: Path, outdir: Path, *, sdist: bool = True
) -> Path:
    """Build *source* offline; with *sdist* the wheel is built from the sdist, as CI does."""
    argv = [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(outdir)]
    if not sdist:
        argv.append("--wheel")
    result = runner.run(sandbox, [*argv, str(source)], timeout=BUILD_TIMEOUT_SECONDS)
    if result.returncode != 0:
        raise RuntimeError("building the wheel failed:\n" + result.describe())
    wheels = sorted(outdir.glob("servonaut-*-py3-none-any.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected one wheel in {outdir}, found {wheels}")
    return wheels[0]


def wheel_versions(checkout: str) -> tuple[str, str]:
    """The versions the checkout is built as: the next patch release, and the
    release after it (for the update journeys)."""
    major, minor, micro = fetcher.version_key(checkout)[:3]
    return f"{major}.{minor}.{micro + 1}", f"{major}.{minor}.{micro + 2}"


def _session_runner(ctx: E2EContext, directory: Path) -> tuple[ToolRunner, Sandbox, Path]:
    """A runner for builds outside any journey, and its guard log."""
    sandbox = Sandbox(directory / "sandbox").create()
    guard_log = directory / "guard.jsonl"
    armed_log = directory / "armed.jsonl"

    def env_for(box: Sandbox) -> dict[str, str]:
        extra = {"PYTHONPATH": str(CHILD_SITE_DIR)}
        return build_env(
            box, shim_dir=ctx.default_shims, guard_log=guard_log, armed_log=armed_log, extra=extra
        )

    return ToolRunner(env_for, armed_log), sandbox, guard_log


def build_session_wheels(ctx: E2EContext, directory: Path) -> dict[str, Path]:
    """Build the checkout as both versions (see :func:`wheel_versions`)."""
    runner, sandbox, guard_log = _session_runner(ctx, directory)
    wheels = {}
    versions = wheel_versions(fetcher.checkout_version())
    # The published package is built from the sdist; the later one only needs a wheel.
    for name, version, sdist in (("current", versions[0], True), ("newer", versions[1], False)):
        source = copy_sources(directory / name / "src", version=version)
        wheels[name] = build_wheel(runner, sandbox, source, directory / name / "dist", sdist=sdist)
    escapes = load_guard().read_log(guard_log)
    if escapes:
        raise RuntimeError(f"building the wheels tried to leave the sandbox: {escapes}")
    manifest = {name: str(path) for name, path in wheels.items()}
    (directory / WHEELS_MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
    return wheels


def session_wheels(ctx: E2EContext, directory: Path) -> dict[str, Path]:
    """This test process's wheels: copies of the controller's, or built here."""
    prebuilt = os.environ.get(ENV_PREBUILT_WHEELS)
    readable = prebuilt and not load_guard().is_protected(os.path.realpath(prebuilt))
    if ctx.worker == "main" or not readable:
        return build_session_wheels(ctx, directory)
    recorded = json.loads((Path(prebuilt) / WHEELS_MANIFEST).read_text(encoding="utf-8"))
    wheels = {}
    for name, path in recorded.items():
        copy = directory / name / Path(path).name
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, copy)
        wheels[name] = copy
    return wheels


def _selects_packaged_journeys(config: Any) -> bool:
    base = Path(config.invocation_params.dir)
    for arg in config.args:
        path = (base / arg.split("::", 1)[0]).resolve()
        if is_within(path, PACKAGED_JOURNEYS) or is_within(PACKAGED_JOURNEYS, path):
            return True
    return False


def prebuild_for_workers(config: Any, ctx: E2EContext) -> None:
    """In the pytest-xdist controller: build the wheels once for all workers.

    Runs before the workers start; they find the wheels through
    ``ENV_PREBUILT_WHEELS``. If the build fails here, each worker builds for
    itself and reports the failure with its journeys.
    """
    if ctx.worker != "main" or not config.pluginmanager.has_plugin("dsession"):
        return
    if not _selects_packaged_journeys(config):
        return
    if any(importlib.util.find_spec(name) is None for name in BUILD_MODULES):
        return
    directory = ctx.root / "packaged-prebuilt"
    try:
        build_session_wheels(ctx, directory)
    except (RuntimeError, OSError) as exc:
        sys.stderr.write(f"e2e: building the wheels for the workers failed: {exc}\n")
        return
    os.environ[ENV_PREBUILT_WHEELS] = str(directory)


# ---------------------------------------------------------------------------
# Installs
# ---------------------------------------------------------------------------


@dataclass
class _Install:
    """Something that provides the ``servonaut`` console script."""

    runner: ToolRunner

    @property
    def console(self) -> Path:
        raise NotImplementedError

    def run(
        self, sandbox: Sandbox, *args: str, timeout: float = 60.0, stdin: Optional[str] = None
    ) -> CliResult:
        """Run the installed ``servonaut`` with *args*."""
        return self.runner.run(sandbox, [str(self.console), *args], timeout=timeout, stdin=stdin)


@dataclass
class VenvInstall(_Install):
    """A venv the user created and ran ``pip install servonaut`` in."""

    path: Path

    @property
    def bin_dir(self) -> Path:
        return self.path / "bin"

    @property
    def python(self) -> Path:
        return self.bin_dir / "python"

    @property
    def console(self) -> Path:
        return self.bin_dir / "servonaut"

    def create(self, sandbox: Sandbox, overlay: Path) -> "VenvInstall":
        self.runner.make_venv(sandbox, self.path, overlay)
        return self

    def pip(self, sandbox: Sandbox, *args: str) -> CliResult:
        argv = [str(self.python), "-m", "pip", *args]
        return self.runner.run(sandbox, argv, timeout=INSTALL_TIMEOUT_SECONDS)


@dataclass
class PipxInstall(_Install):
    """``pipx install servonaut`` with every pipx directory under the journey."""

    home: Path
    bin_dir: Path
    tools_dir: Path
    overlay: Path

    @property
    def console(self) -> Path:
        return self.bin_dir / "servonaut"

    @property
    def venv(self) -> Path:
        return self.home / "venvs" / PIPX_VENV_NAME

    @property
    def python(self) -> Path:
        return self.venv / "bin" / "python"

    @property
    def wrapper(self) -> Path:
        """``pipx`` on the app's PATH: this interpreter's pipx module."""
        return self.tools_dir / "pipx"

    @property
    def python_wrapper(self) -> Path:
        """The Python pipx runs (``PIPX_DEFAULT_PYTHON``)."""
        return self.tools_dir / "pipx-python"

    def env(self) -> dict[str, str]:
        return {
            "PIPX_HOME": str(self.home),
            "PIPX_BIN_DIR": str(self.bin_dir),
            "PIPX_MAN_DIR": str(self.home / "man"),
            "PIPX_DEFAULT_PYTHON": str(self.python_wrapper),
            # The shared pip is the one ensurepip bundles; refreshing it would
            # need the real index.
            "PIPX_DISABLE_SHARED_LIBS_AUTO_UPGRADE": "1",
        }

    def prepare(self) -> "PipxInstall":
        """Write ``pipx`` and the Python it runs, which hooks every new venv."""
        template = self.tools_dir / "hook"
        template.mkdir(parents=True)
        write_hook(template, self.overlay)
        add_hook = self.tools_dir / "add_hook.py"
        add_hook.write_text(_ADD_HOOK_SOURCE.format(template=str(template)), encoding="utf-8")
        python = shlex.quote(os.path.realpath(sys.executable))
        self._script(self.wrapper, f'exec {shlex.quote(sys.executable)} -m pipx "$@"\n')
        self._script(
            self.python_wrapper,
            _PIPX_PYTHON_SOURCE.format(
                child_site=shlex.quote(str(CHILD_SITE_DIR)),
                python=python,
                add_hook=shlex.quote(str(add_hook)),
            ),
        )
        return self

    @staticmethod
    def _script(path: Path, body: str) -> None:
        path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        path.chmod(0o755)

    def pipx(self, sandbox: Sandbox, *args: str) -> CliResult:
        return self.runner.run(sandbox, [str(self.wrapper), *args], timeout=INSTALL_TIMEOUT_SECONDS)

    def install(self, sandbox: Sandbox, spec: str = "servonaut") -> CliResult:
        result = self.pipx(sandbox, "install", spec)
        if result.returncode == 0 and not has_hook(self.venv):
            raise RuntimeError("pipx created its venv without the e2e start-up hook")
        return result


@dataclass
class Installs:
    """The installs of one journey and the environment their processes get."""

    root: Path
    overlay: Path
    fake_cloud: Any
    # The journey's child environment for a sandbox, with overrides applied.
    base_env: Callable[[Sandbox, dict[str, str]], dict[str, str]]
    shim_dir: Path
    allowed_dirs: tuple[str, ...]
    armed_log: Path
    log: Optional[ChildLog] = None
    path_dirs: list[Path] = field(default_factory=list)
    extra_env: dict[str, str] = field(default_factory=dict)

    @property
    def spawn_dirs(self) -> list[str]:
        """Where programs may be started from: the fake tools and the installs."""
        return [str(self.shim_dir), str(self.root)]

    @property
    def index_url(self) -> str:
        """FakeCloud's simple index by host name (pip's TLS needs a name, not an address)."""
        port = urllib.parse.urlsplit(self.fake_cloud.url).port
        return f"https://localhost:{port}/simple/"

    def env(self, sandbox: Sandbox) -> dict[str, str]:
        overrides = {
            # The installed package, never the checkout's sources.
            "PYTHONPATH": str(CHILD_SITE_DIR),
            "PATH": os.pathsep.join([str(self.shim_dir), *map(str, self.path_dirs)]),
            "SERVONAUT_E2E_SPAWN_DIRS": os.pathsep.join(self.spawn_dirs),
            # The overlay's links resolve into this environment's site-packages.
            "SERVONAUT_E2E_ALLOWED_DIRS": os.pathsep.join(
                [*self.allowed_dirs, *map(str, environment_site_dirs())]
            ),
            ENV_PYPI_URL: self.fake_cloud.pypi_json_url,
            "PIP_INDEX_URL": self.index_url,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            # Only the settings above: no pip configuration from anywhere else.
            "PIP_CONFIG_FILE": os.devnull,
            **self.extra_env,
        }
        return self.base_env(sandbox, overrides)

    def runner(self) -> ToolRunner:
        return ToolRunner(self.env, self.armed_log, self.log)

    def offer(self, *wheels: Path, version: Optional[str] = None) -> None:
        """Make FakeCloud's index serve *wheels* and report *version* as the latest."""
        changes: dict[str, Any] = {"pypi_files": [str(w) for w in wheels]}
        if version is not None:
            changes["pypi_version"] = version
        self.fake_cloud.configure(**changes)

    def venv(self, sandbox: Sandbox, name: str = "venv") -> VenvInstall:
        install = VenvInstall(self.runner(), path=self.root / name)
        self.path_dirs.append(install.bin_dir)
        return install.create(sandbox, self.overlay)

    def pipx(self, sandbox: Sandbox) -> PipxInstall:
        install = PipxInstall(
            self.runner(),
            home=self.root / "pipx",
            bin_dir=self.root / "pipx-bin",
            tools_dir=self.root / "tools",
            overlay=self.overlay,
        )
        self.extra_env.update(install.env())
        self.path_dirs.extend([install.bin_dir, install.tools_dir])
        return install.prepare()
