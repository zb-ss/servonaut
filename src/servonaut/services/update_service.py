"""Update service for checking and applying Servonaut updates."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
import urllib.request
import urllib.error
from importlib.metadata import version as pkg_version
from typing import Optional

log = logging.getLogger(__name__)

PYPI_URL = "https://pypi.org/pypi/servonaut/json"


class UpdateService:
    """Check for new versions and run upgrades."""

    def __init__(self) -> None:
        from servonaut import get_version
        self._current: str = get_version()
        self._latest: Optional[str] = None

    @property
    def current_version(self) -> str:
        return self._current

    @property
    def latest_version(self) -> Optional[str]:
        return self._latest

    def check_for_update(self) -> Optional[str]:
        """Check PyPI for the latest version.

        Returns:
            Latest version string if newer than current, None otherwise.
        """
        try:
            req = urllib.request.Request(PYPI_URL, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
            self._latest = data["info"]["version"]
        except (urllib.error.URLError, json.JSONDecodeError, KeyError, OSError) as exc:
            log.debug("Version check failed: %s", exc)
            return None

        if self._is_newer(self._latest, self._current):
            return self._latest
        return None

    def source_install_path(self) -> Optional[str]:
        """Return the local path if servonaut runs from a source / editable
        install, else ``None``.

        A local-path or ``pip install -e`` install records a ``direct_url.json``
        (PEP 610) pointing at a local directory. ``pipx upgrade`` / ``pip
        install --upgrade`` can't pull a published release over such an
        install — they rebuild from the same local source — so the in-app
        updater must NOT pretend to update it.
        """
        try:
            from importlib.metadata import distribution
            raw = distribution("servonaut").read_text("direct_url.json")
        except Exception:  # noqa: BLE001 — metadata may be absent
            return None
        if not raw:
            return None
        try:
            info = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if isinstance(info.get("dir_info"), dict) and info["dir_info"].get("editable"):
            return info.get("url", "editable install")
        url = info.get("url", "")
        if isinstance(url, str) and url.startswith("file:"):
            return url
        return None

    def _pipx(self) -> Optional[str]:
        """Absolute path to pipx, or None. Resolved by path so it works even
        when launched from a desktop shortcut with a minimal PATH."""
        return shutil.which("pipx")

    def detect_install_method(self) -> str:
        """Detect how servonaut was installed.

        Returns:
            One of: 'source', 'pipx', 'pip', 'unknown'. ``source`` takes
            precedence — a local/editable checkout can't be release-upgraded
            in place.
        """
        if self.source_install_path():
            return "source"

        pipx = self._pipx()
        if pipx:
            try:
                result = subprocess.run(
                    [pipx, "list", "--short"],
                    capture_output=True, text=True, timeout=10,
                )
                if "servonaut" in result.stdout:
                    return "pipx"
            except (subprocess.SubprocessError, OSError):
                pass

        # Installed into the interpreter that's running us (pip / venv).
        try:
            pkg_version("servonaut")
            return "pip"
        except Exception:  # noqa: BLE001 — PackageNotFoundError et al.
            pass

        return "unknown"

    def get_upgrade_command(self) -> list[str]:
        """Get the appropriate upgrade command based on install method.

        Returns:
            Command list for subprocess. The pip path uses ``sys.executable -m
            pip`` so it always targets the interpreter actually running
            Servonaut (a bare ``pip`` on PATH can be a different environment).
        """
        method = self.detect_install_method()
        if method == "pipx":
            return [self._pipx() or "pipx", "upgrade", "servonaut"]
        # pip / unknown: upgrade THIS interpreter's environment.
        return [sys.executable, "-m", "pip", "install", "--upgrade", "servonaut"]

    def installed_version_external(self) -> Optional[str]:
        """Query the *actually installed* version via a fresh subprocess.

        The running process's ``importlib.metadata`` is cached at the old
        version, so post-upgrade verification must ask the target environment
        directly (pipx venv, or this interpreter's pip).
        """
        method = self.detect_install_method()
        try:
            pipx = self._pipx()
            if method == "pipx" and pipx:
                result = subprocess.run(
                    [pipx, "list", "--short"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "servonaut":
                        return parts[1]
                return None
            result = subprocess.run(
                [sys.executable, "-m", "pip", "show", "servonaut"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                if line.lower().startswith("version:"):
                    return line.split(":", 1)[1].strip()
        except (subprocess.SubprocessError, OSError):
            return None
        return None

    async def run_upgrade(self) -> tuple[bool, str]:
        """Run the upgrade and VERIFY the installed version actually advanced.

        Never reports success unless the installed version really changed —
        the old behaviour reported "Updated successfully" on exit-code 0 even
        when nothing happened (e.g. a local-path pipx install rebuilding from
        stale source).

        Returns:
            Tuple of (success, message).
        """
        import asyncio

        # A source / editable checkout can't be release-upgraded in place.
        src = self.source_install_path()
        if src:
            return False, (
                "Servonaut is running from a local/source install "
                f"({src}); the in-app updater can't install a published release "
                "over it. To track PyPI releases instead, reinstall from the "
                "package name:  pipx install --force 'servonaut[all]'  — or, to "
                "stay on your checkout, run  git pull  there (then  "
                "pipx install --force '.[all]'  if installed via pipx)."
            )

        before = self.installed_version_external() or self._current
        target = self._latest or self.check_for_update()

        cmd = self.get_upgrade_command()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            output = (stdout.decode() + stderr.decode()).strip()
        except OSError as exc:
            return False, (
                f"Could not run the updater ({' '.join(cmd)}): {exc}. "
                "Try updating manually: pipx upgrade servonaut"
            )

        if proc.returncode != 0:
            tail = output[-800:] if output else "(no output)"
            return False, f"Update command failed (exit {proc.returncode}):\n{tail}"

        # Verify: ask the target environment what's actually installed now.
        after = self.installed_version_external()
        if after and self._is_newer(after, before):
            return True, f"Updated v{before} → v{after}. Restart Servonaut to use it."
        if after and target and not self._is_newer(target, after):
            # Already at (or above) the target — treat as up to date.
            return True, f"Already on the latest version (v{after})."

        # Ran cleanly but the version did not advance — be honest about it.
        tail = output[-500:] if output else "(no output)"
        return False, (
            f"The update ran but the installed version is still v{after or before}"
            + (f" (expected v{target})" if target else "")
            + ". You may be on a system/distro-managed or non-standard install; "
            "update manually or reinstall via pipx.\n"
            f"Command output:\n{tail}"
        )

    @staticmethod
    def _is_newer(latest: str, current: str) -> bool:
        """Compare version strings (PEP 440)."""
        try:
            from packaging.version import Version
            return Version(latest) > Version(current)
        except ImportError:
            # Fallback: simple tuple comparison
            def parse(v: str) -> tuple:
                return tuple(int(x) for x in v.split(".") if x.isdigit())
            return parse(latest) > parse(current)
