"""Distribution-aware checks and upgrades for Servonaut."""

from __future__ import annotations

import hashlib
import http.client
import importlib.metadata
import json
import logging
import os
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Final, Optional

from servonaut.distribution import (
    ArtifactKind,
    ManifestDowngradeError,
    ManifestError,
    OperatingSystemTooOldError,
    ReleaseArtifact,
    ReleaseChannel,
    ReleaseManifest,
    TrustPolicy,
    check_downgrade,
    release_trust_policy,
    resolve_target_artifact,
    verify_manifest,
)
from servonaut.runtime import (
    DistributionKind,
    RuntimeCapabilityError,
    RuntimeLayout,
    detect_runtime,
)
from servonaut.utils.endpoints import EndpointOverrideError, endpoint_override

log = logging.getLogger(__name__)

PYPI_URL = "https://pypi.org/pypi/servonaut/json"
# Replaces PYPI_URL (the whole JSON document URL) for a mirror or a local fake.
PYPI_URL_ENV: Final = "SERVONAUT_PYPI_URL"

# A release manifest lists a handful of artifacts, so anything larger is not a
# manifest. This is a protocol bound, not deployment configuration.
_MAX_MANIFEST_BYTES: Final = 1024 * 1024
_TRANSFER_CHUNK_BYTES: Final = 64 * 1024
_MANIFEST_SOCKET_TIMEOUT_SECONDS: Final = 5
_PYPI_SOCKET_TIMEOUT_SECONDS: Final = 5
_DOWNLOAD_SOCKET_TIMEOUT_SECONDS: Final = 30
DEFAULT_MANIFEST_DEADLINE_SECONDS: Final = 30.0
DEFAULT_DOWNLOAD_DEADLINE_SECONDS: Final = 30 * 60.0

# Failures of a manifest or artifact transfer (including a malformed URL).
_TRANSFER_ERRORS: Final = (
    urllib.error.URLError,
    http.client.HTTPException,
    OSError,
    ValueError,
)

_SOURCE_UPDATE_GUIDANCE = (
    "Servonaut is running from a source installation. Update the source "
    "checkout with its normal project workflow."
)
_DOWNLOAD_IN_PROGRESS_MESSAGE = "An update download is already in progress."
_DOWNLOAD_REJECTED_MESSAGE = (
    "The downloaded update failed verification and was discarded. Try again later."
)
_DOWNLOAD_FAILED_MESSAGE = (
    "The update could not be downloaded. Check your connection and try again."
)


class UpdateCheckResult(Enum):
    """Outcome of the most recent update check."""

    UPDATE_AVAILABLE = "update-available"
    UP_TO_DATE = "up-to-date"
    NOT_CONFIGURED = "not-configured"
    OFFLINE = "offline"
    INVALID_MANIFEST = "invalid-manifest"
    VERIFICATION_FAILED = "verification-failed"
    VERSION_UNCOMPARABLE = "version-uncomparable"
    NO_COMPATIBLE_ARTIFACT = "no-compatible-artifact"
    OS_TOO_OLD = "os-too-old"


# Fixed user-facing status for each frozen-build outcome. Details, which can
# include untrusted manifest content, go to the log only.
_STATUS_MESSAGES: Final[Mapping[UpdateCheckResult, str]] = {
    UpdateCheckResult.UP_TO_DATE: "Servonaut is already on the latest version.",
    UpdateCheckResult.NOT_CONFIGURED: (
        "Automatic updates are not configured for this packaged Servonaut build. "
        "Install a newer signed build when one is provided."
    ),
    UpdateCheckResult.OFFLINE: "Could not check for updates (offline).",
    UpdateCheckResult.INVALID_MANIFEST: (
        "Could not read the published release information. Try again later."
    ),
    UpdateCheckResult.VERIFICATION_FAILED: (
        "Update verification failed: the published release information is not trusted."
    ),
    UpdateCheckResult.VERSION_UNCOMPARABLE: (
        "Could not compare this build's version with the published release."
    ),
    UpdateCheckResult.NO_COMPATIBLE_ARTIFACT: (
        "No compatible update is published for this system."
    ),
    UpdateCheckResult.OS_TOO_OLD: (
        "The latest update requires a newer operating system version."
    ),
}


class UpdateInProgressError(RuntimeError):
    """Raised when a download starts while another one is still running."""


class UpdateIntegrityError(ValueError):
    """Raised when a transfer exceeds its size limit or does not match its signed description."""


class HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to HTTPS URLs so a transfer cannot be downgraded."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if urllib.parse.urlsplit(newurl).scheme.lower() != "https":
            raise urllib.error.HTTPError(
                req.full_url, code, "Refusing a redirect to a non-HTTPS URL.", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_https_opener() -> urllib.request.OpenerDirector:
    """Return an opener whose redirects can never leave HTTPS."""
    return urllib.request.build_opener(HttpsOnlyRedirectHandler)


class UpdateService:
    """Check for published updates and upgrade mutable or frozen installations."""

    def __init__(
        self,
        runtime: RuntimeLayout | None = None,
        *,
        manifest_url: Optional[str] = None,
        trust_policy: Optional[TrustPolicy] = None,
        opener: Optional[urllib.request.OpenerDirector] = None,
        manifest_deadline_seconds: float = DEFAULT_MANIFEST_DEADLINE_SECONDS,
        download_deadline_seconds: float = DEFAULT_DOWNLOAD_DEADLINE_SECONDS,
    ) -> None:
        self._runtime = runtime or detect_runtime()
        self._current = self._runtime.product_version
        self._current_revision = self._runtime.packaging_revision
        self._manifest_url = (
            manifest_url
            or os.environ.get("SERVONAUT_RELEASE_MANIFEST_URL")
        )
        self._trust_policy = trust_policy or release_trust_policy(
            ReleaseChannel(self._runtime.release_channel)
        )
        self._opener = opener or build_https_opener()
        self._manifest_deadline_seconds = manifest_deadline_seconds
        self._download_deadline_seconds = download_deadline_seconds
        self._latest: Optional[str] = None
        self._update_status: Optional[str] = None
        self._last_result: Optional[UpdateCheckResult] = None
        self._latest_manifest: Optional[ReleaseManifest] = None
        self._target_artifact: Optional[ReleaseArtifact] = None
        self._downloaded_path: Optional[Path] = None
        self._download_lock = threading.Lock()

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
    def last_check_result(self) -> Optional[UpdateCheckResult]:
        """Typed outcome of the most recent :meth:`check_for_update` call."""
        return self._last_result

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
            return self._check_frozen_update()

        try:
            override = endpoint_override(PYPI_URL_ENV)
        except EndpointOverrideError as exc:
            log.warning("Version check skipped: %s", exc)
            self._last_result = UpdateCheckResult.OFFLINE
            self._update_status = f"Could not check for updates: {exc}"
            return None
        try:
            latest = self._fetch_pypi_version(override or PYPI_URL)
        except (*_TRANSFER_ERRORS, KeyError, TypeError) as exc:
            if override:
                # The exception text can quote the URL; name the variable only.
                log.warning(
                    "Version check via %s failed (%s).", PYPI_URL_ENV, type(exc).__name__
                )
            else:
                log.debug("Version check failed: %s", exc)
            return self._record(UpdateCheckResult.OFFLINE)

        self._latest = latest
        self._update_status = None
        if self._is_newer(self._latest, self._current):
            self._last_result = UpdateCheckResult.UPDATE_AVAILABLE
            return self._latest
        self._last_result = UpdateCheckResult.UP_TO_DATE
        return None

    def _fetch_pypi_version(self, url: str) -> str:
        """Read ``info.version`` from a PyPI-style JSON document.

        Uses the HTTPS-only opener, so a redirect can never downgrade the
        request to plain http.
        """
        request = urllib.request.Request(url, headers={"Accept": "application/json"})
        with self._opener.open(request, timeout=_PYPI_SOCKET_TIMEOUT_SECONDS) as response:
            data = json.loads(response.read())
        return data["info"]["version"]

    def _check_frozen_update(self) -> Optional[str]:
        """Check the canonical signed release manifest for frozen distributions."""
        if not self._manifest_url or self._trust_policy is None:
            return self._record(UpdateCheckResult.NOT_CONFIGURED)
        try:
            raw_bytes = self._fetch_manifest(self._manifest_url)
        except UpdateIntegrityError as exc:
            log.warning("Release manifest rejected: %s", exc)
            return self._record(UpdateCheckResult.INVALID_MANIFEST)
        except _TRANSFER_ERRORS as exc:
            log.debug("Frozen manifest request failed: %s", exc)
            return self._record(UpdateCheckResult.OFFLINE)
        try:
            manifest = ReleaseManifest.from_json(raw_bytes)
        except ManifestError as exc:
            log.warning("Invalid release manifest: %s", exc)
            return self._record(UpdateCheckResult.INVALID_MANIFEST)
        try:
            verify_manifest(manifest, self._trust_policy)
        except ManifestError as exc:
            log.warning("Release manifest failed trust verification: %s", exc)
            return self._record(UpdateCheckResult.VERIFICATION_FAILED)
        return self._select_update(manifest)

    def _fetch_manifest(self, url: str) -> bytes:
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": f"servonaut/{self._current}",
            },
        )
        deadline = time.monotonic() + self._manifest_deadline_seconds
        with self._opener.open(request, timeout=_MANIFEST_SOCKET_TIMEOUT_SECONDS) as response:
            return b"".join(
                _read_limited(response, max_bytes=_MAX_MANIFEST_BYTES, deadline=deadline)
            )

    def _select_update(self, manifest: ReleaseManifest) -> Optional[str]:
        """Accept a verified manifest when it is newer and has an artifact for this host."""
        try:
            check_downgrade(manifest, self._current, self._current_revision)
        except ManifestDowngradeError:
            return self._record(UpdateCheckResult.UP_TO_DATE)
        except ManifestError as exc:
            log.warning("Could not compare the running version with the release: %s", exc)
            return self._record(UpdateCheckResult.VERSION_UNCOMPARABLE)
        try:
            target = resolve_target_artifact(manifest, self._runtime)
        except OperatingSystemTooOldError as exc:
            log.info("Update needs a newer operating system: %s", exc)
            return self._record(UpdateCheckResult.OS_TOO_OLD)
        except ManifestError as exc:
            log.warning("Target artifact resolution failed: %s", exc)
            return self._record(UpdateCheckResult.NO_COMPATIBLE_ARTIFACT)

        self._latest_manifest = manifest
        self._target_artifact = target
        self._latest = manifest.product_version
        return self._record(UpdateCheckResult.UPDATE_AVAILABLE)

    def _record(self, result: UpdateCheckResult) -> Optional[str]:
        """Store a frozen check outcome with its fixed status; return the new version."""
        self._last_result = result
        if result is UpdateCheckResult.UPDATE_AVAILABLE:
            self._update_status = f"Update available: v{self._latest}"
            return self._latest
        self._update_status = _STATUS_MESSAGES[result]
        return None

    def download_update(
        self,
        destination_dir: Optional[Path] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Path:
        """Download and verify the resolved update artifact.

        Raises:
            RuntimeCapabilityError: If no verified target artifact is available.
            UpdateInProgressError: If another download is still running.
            UpdateIntegrityError: If the payload's size or SHA-256 digest does not match.
            TimeoutError: If the transfer does not finish before its deadline.
        """
        if not self._download_lock.acquire(blocking=False):
            raise UpdateInProgressError(_DOWNLOAD_IN_PROGRESS_MESSAGE)
        try:
            return self._download_exclusive(destination_dir, progress_callback)
        finally:
            self._download_lock.release()

    def _download_exclusive(
        self,
        destination_dir: Optional[Path],
        progress_callback: Optional[Callable[[int, int], None]],
    ) -> Path:
        if self._target_artifact is None:
            self.check_for_update()
            if self._target_artifact is None:
                raise RuntimeCapabilityError("No verified update artifact is available to download.")

        dest_dir = self._download_directory(destination_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)
        self._downloaded_path = self._download_verified(
            self._target_artifact, dest_dir, progress_callback
        )
        return self._downloaded_path

    def _download_verified(
        self,
        target: ReleaseArtifact,
        dest_dir: Path,
        progress_callback: Optional[Callable[[int, int], None]],
    ) -> Path:
        """Stream into a private temporary file; move it into place only once verified."""
        # A temporary file per call, so concurrent or leftover downloads never
        # share a partial file.
        fd, part_name = tempfile.mkstemp(
            dir=dest_dir, prefix=f".{target.filename}.", suffix=".part"
        )
        part_file = Path(part_name)
        try:
            with os.fdopen(fd, "wb") as part:
                computed_sha256 = self._stream_artifact(target, part, progress_callback)
            expected_sha256 = target.sha256.lower()
            if computed_sha256 != expected_sha256:
                raise UpdateIntegrityError(
                    f"Integrity check failed: downloaded SHA-256 {computed_sha256} "
                    f"does not match expected {expected_sha256}."
                )
            # mkstemp creates owner-only files; give the verified download the
            # permissions of an ordinary downloaded file.
            os.chmod(part_file, 0o644)
            return part_file.replace(dest_dir / target.filename)
        except BaseException:
            part_file.unlink(missing_ok=True)
            raise

    def _download_directory(self, destination_dir: Optional[Path]) -> Path:
        if destination_dir is not None:
            return Path(destination_dir)
        user_downloads = Path.home() / "Downloads"
        return user_downloads if user_downloads.is_dir() else (self._runtime.data_root / "downloads")

    def _stream_artifact(
        self,
        target: ReleaseArtifact,
        part: BinaryIO,
        progress_callback: Optional[Callable[[int, int], None]],
    ) -> str:
        """Write the artifact to ``part`` within its signed size; return its SHA-256."""
        request = urllib.request.Request(
            target.download_url,
            headers={"User-Agent": f"servonaut/{self._current}"},
        )
        deadline = time.monotonic() + self._download_deadline_seconds
        hasher = hashlib.sha256()
        downloaded = 0
        with self._opener.open(request, timeout=_DOWNLOAD_SOCKET_TIMEOUT_SECONDS) as response:
            _require_declared_length(response, target.byte_size)
            for chunk in _read_limited(response, max_bytes=target.byte_size, deadline=deadline):
                part.write(chunk)
                hasher.update(chunk)
                downloaded += len(chunk)
                if progress_callback:
                    progress_callback(downloaded, target.byte_size)
        if downloaded != target.byte_size:
            raise UpdateIntegrityError(
                f"Size mismatch: downloaded {downloaded} bytes, expected {target.byte_size}."
            )
        return hasher.hexdigest().lower()

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
        """Return a self-update argv, or None when the runtime cannot self-update.

        This has no side effects; :meth:`run_upgrade` reports why an update
        cannot run.
        """
        try:
            return self._runtime.package_management.self_update_argv()
        except RuntimeCapabilityError:
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

        if self._target_artifact is None:
            await asyncio.to_thread(self.check_for_update)
            if self._target_artifact is None:
                if self._last_result is UpdateCheckResult.UP_TO_DATE:
                    return True, "Already on the latest version."
                return False, self._update_status or _STATUS_MESSAGES[
                    UpdateCheckResult.NOT_CONFIGURED
                ]

        try:
            if self._downloaded_path is None or not self._downloaded_path.is_file():
                downloaded_file = await asyncio.to_thread(self.download_update)
            else:
                downloaded_file = self._downloaded_path
        except UpdateInProgressError:
            return False, _DOWNLOAD_IN_PROGRESS_MESSAGE
        except UpdateIntegrityError as exc:
            log.warning("Downloaded update failed verification: %s", exc)
            return False, _DOWNLOAD_REJECTED_MESSAGE
        except (RuntimeCapabilityError, *_TRANSFER_ERRORS) as exc:
            log.warning("Update download failed: %s", exc)
            return False, _DOWNLOAD_FAILED_MESSAGE

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


def _read_limited(
    response: BinaryIO, *, max_bytes: int, deadline: float
) -> Iterator[bytes]:
    """Yield response chunks, stopping a transfer that is too large or too slow."""
    received = 0
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("The transfer did not finish before its deadline.")
        chunk = response.read(_TRANSFER_CHUNK_BYTES)
        if not chunk:
            return
        received += len(chunk)
        if received > max_bytes:
            raise UpdateIntegrityError(f"The transfer exceeded its {max_bytes}-byte limit.")
        yield chunk


def _require_declared_length(response: http.client.HTTPResponse, expected: int) -> None:
    """Refuse a response whose Content-Length disagrees with the signed byte size."""
    declared = response.headers.get("Content-Length")
    if declared is None:
        return
    try:
        length = int(declared)
    except ValueError:
        raise UpdateIntegrityError("The server sent an invalid Content-Length.") from None
    if length != expected:
        raise UpdateIntegrityError(
            f"The server announced {length} bytes but the release declares {expected}."
        )
