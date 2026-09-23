"""Distribution-aware checks and upgrades for Servonaut."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import logging
import os
import subprocess
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Optional

from servonaut.distribution import (
    ArtifactKind,
    ManifestDowngradeError,
    ManifestError,
    ReleaseArtifact,
    ReleaseManifest,
    TrustPolicy,
    check_downgrade,
    resolve_target_artifact,
    verify_manifest,
)
from servonaut.runtime import (
    DistributionKind,
    RuntimeCapabilityError,
    RuntimeLayout,
    detect_runtime,
)

log = logging.getLogger(__name__)

PYPI_URL = "https://pypi.org/pypi/servonaut/json"
DEFAULT_RELEASE_MANIFEST_URL = "https://releases.servonaut.dev/servonaut-release-manifest.json"

_FROZEN_UPDATE_GUIDANCE = (
    "Updates for this packaged Servonaut build are not available yet. "
    "Install a newer signed build when one is provided."
)
_SOURCE_UPDATE_GUIDANCE = (
    "Servonaut is running from a source installation. Update the source "
    "checkout with its normal project workflow."
)


class UpdateService:
    """Check for published updates and upgrade mutable or frozen installations."""

    def __init__(
        self,
        runtime: RuntimeLayout | None = None,
        *,
        manifest_url: Optional[str] = None,
        trust_policy: Optional[TrustPolicy] = None,
    ) -> None:
        self._runtime = runtime or detect_runtime()
        self._current = self._runtime.product_version
        self._current_revision: Optional[int] = (
            int(self._runtime.build_revision)
            if (self._runtime.build_revision and self._runtime.build_revision.isdigit())
            else None
        )
        self._manifest_url = (
            manifest_url
            or os.environ.get("SERVONAUT_RELEASE_MANIFEST_URL")
        )
        self._trust_policy = trust_policy or TrustPolicy(
            trusted_public_keys={},
            allowed_origin_prefixes=(
                "https://github.com/zb-ss/servonaut/releases/download/",
                "https://releases.servonaut.dev/",
            ),
        )
        self._latest: Optional[str] = None
        self._update_status: Optional[str] = None
        self._latest_manifest: Optional[ReleaseManifest] = None
        self._target_artifact: Optional[ReleaseArtifact] = None
        self._downloaded_path: Optional[Path] = None

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

    @property
    def latest_manifest(self) -> Optional[ReleaseManifest]:
        """Discovered and verified release manifest for frozen distributions."""
        return self._latest_manifest

    @property
    def target_artifact(self) -> Optional[ReleaseArtifact]:
        """Resolved matching update artifact for frozen distributions."""
        return self._target_artifact

    @property
    def downloaded_path(self) -> Optional[Path]:
        """Path to downloaded and integrity-verified update artifact."""
        return self._downloaded_path

    def check_for_update(self) -> Optional[str]:
        """Check for an update depending on the distribution channel."""
        if self._runtime.is_frozen:
            if not self._manifest_url:
                self._update_status = _FROZEN_UPDATE_GUIDANCE
                return None
            return self._check_frozen_update()

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

    def _check_frozen_update(self) -> Optional[str]:
        """Check the canonical signed release manifest for frozen distributions."""
        try:
            request = urllib.request.Request(
                self._manifest_url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": f"servonaut/{self._current}",
                },
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                raw_bytes = response.read()
            manifest = ReleaseManifest.from_json(raw_bytes)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log.debug("Frozen manifest request failed: %s", exc)
            self._update_status = "Could not check for updates (offline)."
            return None
        except ManifestError as exc:
            log.warning("Invalid release manifest: %s", exc)
            self._update_status = f"Invalid release manifest: {exc}"
            return None

        # Verify cryptographic signatures and trust constraints
        if self._trust_policy.trusted_public_keys or self._trust_policy.minimum_signatures > 0:
            try:
                verify_manifest(manifest, self._trust_policy)
            except ManifestError as exc:
                log.warning("Release manifest failed trust verification: %s", exc)
                self._update_status = f"Update verification failed: {exc}"
                return None

        # Check downgrade / version progression
        try:
            check_downgrade(manifest, self._current, self._current_revision)
        except ManifestDowngradeError:
            self._update_status = "Servonaut is already on the latest version."
            return None

        # Resolve compatible artifact
        try:
            target = resolve_target_artifact(manifest, self._runtime)
        except ManifestError as exc:
            log.warning("Target artifact resolution failed: %s", exc)
            self._update_status = f"No compatible update artifact found: {exc}"
            return None

        self._latest_manifest = manifest
        self._target_artifact = target
        self._latest = manifest.product_version
        self._update_status = f"Update available: v{manifest.product_version}"
        return self._latest

    def download_update(
        self,
        destination_dir: Optional[Path] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Path:
        """Download and verify the resolved update artifact.

        Raises:
            RuntimeCapabilityError: If no verified target artifact is available.
            ValueError: If the downloaded payload fails SHA-256 integrity verification.
        """
        if self._target_artifact is None:
            self.check_for_update()
            if self._target_artifact is None:
                raise RuntimeCapabilityError("No verified update artifact is available to download.")

        target = self._target_artifact
        if destination_dir is None:
            user_downloads = Path.home() / "Downloads"
            dest_dir = user_downloads if user_downloads.is_dir() else (self._runtime.data_root / "downloads")
        else:
            dest_dir = Path(destination_dir)

        dest_dir.mkdir(parents=True, exist_ok=True)
        final_file = dest_dir / target.filename
        part_file = dest_dir / f"{target.filename}.part"

        request = urllib.request.Request(
            target.download_url,
            headers={"User-Agent": f"servonaut/{self._current}"},
        )
        hasher = hashlib.sha256()
        downloaded = 0
        total_size = target.byte_size

        try:
            with urllib.request.urlopen(request, timeout=30) as resp, open(part_file, "wb") as f:
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
                    hasher.update(chunk)
                    downloaded += len(chunk)
                    if progress_callback:
                        progress_callback(downloaded, total_size)

            computed_sha256 = hasher.hexdigest().lower()
            expected_sha256 = target.sha256.lower()
            if computed_sha256 != expected_sha256:
                part_file.unlink(missing_ok=True)
                raise ValueError(
                    f"Integrity check failed: downloaded SHA-256 {computed_sha256} does not match expected {expected_sha256}."
                )

            part_file.replace(final_file)
            self._downloaded_path = final_file
            return final_file
        except Exception:
            part_file.unlink(missing_ok=True)
            raise

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

        if self._runtime.is_frozen:
            return await self._run_frozen_upgrade()

        command = self.get_upgrade_command()
        if command is None:
            self._update_status = _SOURCE_UPDATE_GUIDANCE
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

    async def _run_frozen_upgrade(self) -> tuple[bool, str]:
        """Perform verified download and present installation guidance for frozen builds."""
        import asyncio

        if not self._manifest_url:
            self._update_status = _FROZEN_UPDATE_GUIDANCE
            return False, _FROZEN_UPDATE_GUIDANCE

        if self._target_artifact is None:
            latest = await asyncio.to_thread(self.check_for_update)
            if not latest or self._target_artifact is None:
                if self._update_status and "latest version" in self._update_status.lower():
                    return True, "Already on the latest version."
                return False, self._update_status or _FROZEN_UPDATE_GUIDANCE

        try:
            if self._downloaded_path is None or not self._downloaded_path.is_file():
                downloaded_file = await asyncio.to_thread(self.download_update)
            else:
                downloaded_file = self._downloaded_path
        except Exception as exc:
            return False, f"Failed to download update: {exc}"

        guidance = self._get_install_guidance(self._target_artifact, downloaded_file)
        return True, guidance

    @staticmethod
    def _get_install_guidance(artifact: ReleaseArtifact, path: Path) -> str:
        """Return platform-tailored installation guidance for a verified download."""
        if artifact.kind == ArtifactKind.STANDALONE_CLI:
            return (
                f"Downloaded verified update to {path}.\n"
                "Extract the archive and replace your current servonaut binary to complete the upgrade."
            )
        if artifact.kind == ArtifactKind.MACOS_DMG:
            return (
                f"Downloaded verified installer to {path}.\n"
                "Open the DMG disk image and drag Servonaut to your Applications folder."
            )
        if artifact.kind == ArtifactKind.WINDOWS_MSI:
            return (
                f"Downloaded verified installer to {path}.\n"
                "Run the installer to complete the Servonaut upgrade."
            )
        if artifact.kind == ArtifactKind.UBUNTU_DEB:
            return (
                f"Downloaded verified package to {path}.\n"
                f"Install with: sudo apt install {path}"
            )
        return f"Downloaded verified update to {path}."

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
