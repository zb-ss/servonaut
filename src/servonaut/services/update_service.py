"""Distribution-aware checks and upgrades for Servonaut."""

from __future__ import annotations

import json
import logging
import subprocess
import importlib.metadata
import urllib.error
import urllib.request
from typing import Optional

from servonaut.runtime import (
    DistributionKind,
    RuntimeCapabilityError,
    RuntimeLayout,
    detect_runtime,
)

log = logging.getLogger(__name__)

PYPI_URL = "https://pypi.org/pypi/servonaut/json"
_FROZEN_UPDATE_GUIDANCE = (
    "Updates for this packaged Servonaut build are not available yet. "
    "Install a newer signed build when one is provided."
)
_SOURCE_UPDATE_GUIDANCE = (
    "Servonaut is running from a source installation. Update the source "
    "checkout with its normal project workflow."
)


class UpdateService:
    """Check for published updates and upgrade mutable installations only."""

    def __init__(self, runtime: RuntimeLayout | None = None) -> None:
        self._runtime = runtime or detect_runtime()
        self._current = self._runtime.product_version
        self._latest: Optional[str] = None
        self._update_status: Optional[str] = None

    @property
    def current_version(self) -> str:
        """Version embedded in the resolved runtime layout."""
        return self._current

    @property
    def latest_version(self) -> Optional[str]:
        """The most recently discovered published version, if queried."""
        return self._latest

    @property
    def runtime(self) -> RuntimeLayout:
        """Resolved runtime used for update policy."""
        return self._runtime

    @property
    def update_status(self) -> Optional[str]:
        """Concise user-facing status when the current channel cannot update."""
        return self._update_status

    @property
    def update_guidance(self) -> Optional[str]:
        """Compatibility alias for surfaces displaying update guidance."""
        return self._update_status

    def check_for_update(self) -> Optional[str]:
        """Check PyPI for an update when this distribution has that channel."""
        if self._runtime.is_frozen:
            self._update_status = _FROZEN_UPDATE_GUIDANCE
            return None

        try:
            request = urllib.request.Request(
                PYPI_URL, headers={"Accept": "application/json"}
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                data = json.loads(response.read())
            self._latest = data["info"]["version"]
        except (urllib.error.URLError, json.JSONDecodeError, KeyError, OSError) as exc:
            log.debug("Version check failed: %s", exc)
            return None

        if self._is_newer(self._latest, self._current):
            return self._latest
        return None

    def source_install_path(self) -> Optional[str]:
        """Return local/editable package metadata when it is available.

        This compatibility helper reports evidence only. Update policy is
        determined exclusively by :attr:`runtime`.
        """
        try:
            raw = importlib.metadata.distribution("servonaut").read_text(
                "direct_url.json"
            )
        except Exception:  # noqa: BLE001 - metadata can be absent
            return None
        if not raw:
            return None
        try:
            info = json.loads(raw)
        except json.JSONDecodeError:
            return None
        directory_info = info.get("dir_info")
        url = info.get("url")
        if (
            isinstance(directory_info, dict)
            and isinstance(url, str)
            and url.startswith("file:")
            and not isinstance(info.get("archive_info"), dict)
        ):
            return url
        return None

    def detect_install_method(self) -> str:
        """Return the resolved distribution kind for compatibility callers."""
        return self._runtime.kind.value

    def get_upgrade_command(self) -> list[str] | None:
        """Return a self-update argv only when the runtime permits mutation."""
        try:
            return self._runtime.package_management.self_update_argv()
        except RuntimeCapabilityError:
            self._update_status = (
                _FROZEN_UPDATE_GUIDANCE
                if self._runtime.is_frozen
                else _SOURCE_UPDATE_GUIDANCE
            )
            return None

    def installed_version_external(self) -> Optional[str]:
        """Query the target mutable environment after an upgrade."""
        kind = self._runtime.kind
        if kind in {
            DistributionKind.SOURCE,
            DistributionKind.FROZEN_CLI,
            DistributionKind.PACKAGED_DESKTOP,
        }:
            return None

        try:
            if kind is DistributionKind.PIPX:
                result = subprocess.run(
                    [*self._runtime.package_management.argv_prefix, "list", "--short"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "servonaut":
                        return parts[1]
                return None

            result = subprocess.run(
                [*self._runtime.package_management.argv_prefix, "show", "servonaut"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in result.stdout.splitlines():
                if line.lower().startswith("version:"):
                    return line.split(":", 1)[1].strip()
        except (subprocess.SubprocessError, OSError):
            return None
        return None

    async def run_upgrade(self) -> tuple[bool, str]:
        """Run and externally verify a permitted update operation."""
        import asyncio

        command = self.get_upgrade_command()
        if command is None:
            self._update_status = (
                _FROZEN_UPDATE_GUIDANCE
                if self._runtime.is_frozen
                else _SOURCE_UPDATE_GUIDANCE
            )
            return False, self._update_status

        before = self.installed_version_external() or self._current
        target = self._latest or self.check_for_update()
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
            output = (
                stdout.decode(errors="replace") + stderr.decode(errors="replace")
            ).strip()
        except OSError as exc:
            return False, f"Could not run the updater: {exc}. Update Servonaut manually."

        if process.returncode != 0:
            return False, (
                f"Update command failed (exit {process.returncode}):\n"
                f"{output[-800:] or '(no output)'}"
            )

        after = self.installed_version_external()
        if after and self._is_newer(after, before):
            return True, f"Updated v{before} → v{after}. Restart Servonaut to use it."
        if after and target and not self._is_newer(target, after):
            return True, f"Already on the latest version (v{after})."
        return False, (
            f"The update ran but the installed version is still v{after or before}"
            + (f" (expected v{target})" if target else "")
            + ". Update Servonaut manually.\n"
            f"Command output:\n{output[-500:] or '(no output)'}"
        )

    @staticmethod
    def _is_newer(latest: str, current: str) -> bool:
        """Compare PEP 440 versions with a small dependency-free fallback."""
        try:
            from packaging.version import Version

            return Version(latest) > Version(current)
        except ImportError:
            def parse(value: str) -> tuple[int, ...]:
                return tuple(int(part) for part in value.split(".") if part.isdigit())

            return parse(latest) > parse(current)
