"""Install Servonaut the way users do, inside the test root and offline.

- :func:`build_wheel` builds the checkout with ``python -m build``, as the
  publish workflow does, using the build backend already installed in this
  environment (``--no-isolation``), so nothing is downloaded.
- :class:`VenvInstall` is ``pip install servonaut`` into a fresh venv;
  :class:`PipxInstall` is ``pipx install servonaut`` with ``PIPX_HOME`` and
  ``PIPX_BIN_DIR`` under the journey. Both install Servonaut from FakeCloud's
  package index, which serves the wheels a journey offers.
- Dependencies come from this test environment. Every install sees a
  read-only *overlay* of its site-packages (symlinks, without Servonaut and
  pip), appended after the install's own site-packages, so pip finds each
  requirement already satisfied and never looks one up.
- Every Python process of an install arms the e2e guard: the direct children
  through ``PYTHONPATH``, and the processes pipx starts (pipx drops
  ``PYTHONPATH``) through a start-up hook in the install. The one exception
  is the base interpreter pipx runs to create a venv, which runs only the
  standard library's ``venv`` module.
- The same hook points the installed app's update check at FakeCloud's JSON
  document, as the ``fake_cloud`` fixture does for the in-process app.
"""

from __future__ import annotations

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

from e2e.harness.bootstrap import CHILD_SITE_DIR, REPO_ROOT, Sandbox
from e2e.harness.processes import ChildLog, CliResult, run_cli

HOOK_MODULE = "_servonaut_e2e_site"
ENV_PYPI_JSON_URL = "SERVONAUT_E2E_PYPI_JSON_URL"
PIPX_VENV_NAME = "servonaut"
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
# The source files a wheel build needs (see [tool.hatch.build] in pyproject).
_BUILD_INPUTS = ("pyproject.toml", "README.md", "LICENSE", "src")

_HOOK_SOURCE = '''\
"""Start-up hook for Servonaut installs in the e2e suite (test root only).

Arms the e2e guard, exposes the test environment's packages (the overlay)
after this install's own, and points the update check at the local package
index named by ${env_url}.
"""

import os
import sys

_GUARD_SITE = {guard_site!r}
_OVERLAY = {overlay!r}
_UPDATE_MODULE = "servonaut.services.update_service"


class _PackageIndexRedirect:
    """Set ``PYPI_URL`` once the update-service module has executed."""

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


def venv_site_packages(venv: Path) -> Path:
    """The site-packages directory of a venv made by this interpreter."""
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    return venv / "lib" / version / "site-packages"


def write_hook(site_packages: Path, overlay: Path, *, as_sitecustomize: bool = False) -> None:
    """Install the start-up hook into *site_packages*.

    A ``.pth`` line runs it in every process of that install. Where the
    directory is only a plain path entry (pipx's shared libraries), the
    ``.pth`` never runs, so ``sitecustomize`` imports it instead.
    """
    source = _HOOK_SOURCE.format(
        guard_site=str(CHILD_SITE_DIR / "sitecustomize.py"),
        overlay=str(overlay),
        env_url=ENV_PYPI_JSON_URL,
    )
    (site_packages / f"{HOOK_MODULE}.py").write_text(source, encoding="utf-8")
    (site_packages / f"{HOOK_MODULE}.pth").write_text(f"import {HOOK_MODULE}\n", encoding="utf-8")
    if as_sitecustomize:
        (site_packages / "sitecustomize.py").write_text(f"import {HOOK_MODULE}\n", encoding="utf-8")


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

    def make_venv(self, sandbox: Sandbox, path: Path) -> None:
        """``python -m venv`` with this interpreter (pip comes from ensurepip)."""
        result = self.run(
            sandbox, [sys.executable, "-m", "venv", str(path)], timeout=INSTALL_TIMEOUT_SECONDS
        )
        if result.returncode != 0:
            raise RuntimeError(f"creating the venv {path.name} failed:\n{result.describe()}")


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
        self.runner.make_venv(sandbox, self.path)
        write_hook(venv_site_packages(self.path), overlay)
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

    def env(self) -> dict[str, str]:
        return {
            "PIPX_HOME": str(self.home),
            "PIPX_BIN_DIR": str(self.bin_dir),
            "PIPX_MAN_DIR": str(self.home / "man"),
            # The shared pip is the one ensurepip bundles; refreshing it would
            # need the real index.
            "PIPX_DISABLE_SHARED_LIBS_AUTO_UPGRADE": "1",
        }

    def prepare(self, sandbox: Sandbox) -> "PipxInstall":
        """Create pipx's shared libraries (its pip) with the start-up hook."""
        self.tools_dir.mkdir(parents=True, exist_ok=True)
        script = f'#!/bin/sh\nexec {shlex.quote(sys.executable)} -m pipx "$@"\n'
        self.wrapper.write_text(script, encoding="utf-8")
        self.wrapper.chmod(0o755)
        shared = self.home / "shared"
        self.runner.make_venv(sandbox, shared)
        write_hook(venv_site_packages(shared), self.overlay, as_sitecustomize=True)
        return self

    def pipx(self, sandbox: Sandbox, *args: str) -> CliResult:
        return self.runner.run(sandbox, [str(self.wrapper), *args], timeout=INSTALL_TIMEOUT_SECONDS)

    def install(self, sandbox: Sandbox, spec: str = "servonaut") -> CliResult:
        result = self.pipx(sandbox, "install", spec)
        if result.returncode == 0:
            write_hook(venv_site_packages(self.venv), self.overlay)
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
            ENV_PYPI_JSON_URL: self.fake_cloud.pypi_json_url,
            "PIP_INDEX_URL": self.index_url,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
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
        return install.prepare(sandbox)
