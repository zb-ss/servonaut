"""Update service for checking and applying Servonaut updates."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import urllib.request
import urllib.error
from importlib.metadata import version as pkg_version
from typing import Optional

log = logging.getLogger(__name__)

PYPI_URL = "https://pypi.org/pypi/servonaut/json"


class UpdateService:
    """Check for new versions and run upgrades."""

    def __init__(self) -> None:
        self._current: str = pkg_version("servonaut")
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

    def detect_install_method(self) -> str:
        """Detect how servonaut was installed.

        Returns:
            One of: 'pipx', 'pip', 'unknown'.
        """
        if shutil.which("pipx"):
            try:
                result = subprocess.run(
                    ["pipx", "list", "--short"],
                    capture_output=True, text=True, timeout=10,
                )
                if "servonaut" in result.stdout:
                    return "pipx"
            except (subprocess.SubprocessError, OSError):
                pass

        # Check if installed via pip in a venv or globally
        try:
            result = subprocess.run(
                ["pip", "show", "servonaut"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return "pip"
        except (subprocess.SubprocessError, OSError):
            pass

        return "unknown"

    def get_upgrade_command(self) -> list[str]:
        """Get the appropriate upgrade command based on install method.

        Returns:
            Command list for subprocess.
        """
        method = self.detect_install_method()
        if method == "pipx":
            return ["pipx", "upgrade", "servonaut"]
        elif method == "pip":
            return ["pip", "install", "--upgrade", "servonaut"]
        else:
            return ["pip", "install", "--upgrade", "servonaut"]

    async def run_upgrade(self) -> tuple[bool, str]:
        """Run the upgrade command.

        Returns:
            Tuple of (success, output_message).
        """
        import asyncio

        cmd = self.get_upgrade_command()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            output = stdout.decode() + stderr.decode()

            if proc.returncode == 0:
                return True, f"Updated successfully. Restart Servonaut to use the new version."
            else:
                return False, f"Update failed:\n{output}"
        except OSError as exc:
            return False, f"Could not run update: {exc}"

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
