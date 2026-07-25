"""Readiness detection and guided setup for local voice input.

Voice input is opt-in because it costs a few hundred megabytes across two
separate downloads — the Python packages and the speech model weights —
and one of its requirements (the PortAudio system library) cannot be
installed by pip at all. Rather than hide that behind a single button
that silently half-succeeds, this service reports each requirement
independently so the settings panel can name the one thing standing in
the way and offer the matching action.

Split from :mod:`servonaut.services.voice_input_service` on purpose: the
recording hot path has no business carrying subprocess and download
logic, and setup has no business holding an audio buffer.
"""

from __future__ import annotations

import asyncio
import glob
import logging
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple, TYPE_CHECKING

from servonaut.utils.platform_utils import command_exists, get_os

if TYPE_CHECKING:
    from servonaut.config.schema import VoiceConfig

logger = logging.getLogger(__name__)

# The pip-installable half of the requirements. numpy is explicit because
# the capture buffer uses it directly and neither of the other two
# declares it as a dependency.
VOICE_PACKAGES: Tuple[str, ...] = (
    "faster-whisper>=1.0",
    "sounddevice>=0.4",
    "numpy>=1.24",
)

# Rough download footprint per model size, for the confirmation copy. These
# are the int8 CTranslate2 conversions faster-whisper actually pulls, not
# the original OpenAI checkpoints.
MODEL_DOWNLOAD_SIZES: dict = {
    "tiny": "~75 MB",
    "tiny.en": "~75 MB",
    "base": "~145 MB",
    "base.en": "~145 MB",
    "small": "~490 MB",
    "small.en": "~490 MB",
    "medium": "~1.5 GB",
    "medium.en": "~1.5 GB",
    "large-v2": "~3 GB",
    "large-v3": "~3 GB",
    "distil-small.en": "~340 MB",
    "distil-medium.en": "~790 MB",
    "distil-large-v3": "~1.5 GB",
}

# Install hint for the PortAudio shared library, keyed by the package
# manager we can actually find on the box. pip cannot provide this — it is
# a system library — so every path here is a command for the user to run.
_PORTAUDIO_COMMANDS: Tuple[Tuple[str, str], ...] = (
    ("apt-get", "sudo apt install libportaudio2"),
    ("dnf", "sudo dnf install portaudio"),
    ("pacman", "sudo pacman -S portaudio"),
    ("zypper", "sudo zypper install portaudio"),
    ("apk", "sudo apk add portaudio"),
)

_PORTAUDIO_MACOS = "brew install portaudio"

# Ceiling for the package install subprocess. A cold install pulls
# ctranslate2 and onnxruntime, which is slow on a thin connection but
# should never take a quarter of an hour.
_INSTALL_TIMEOUT_SECONDS = 900

# Ceiling for the model download. Generous because the large models are
# multi-gigabyte and Hugging Face throttles.
_DOWNLOAD_TIMEOUT_SECONDS = 1800


@dataclass(frozen=True)
class VoiceReadiness:
    """Which of the voice-input requirements are currently satisfied.

    Attributes:
        packages_ok: ``faster-whisper`` and ``numpy`` are importable.
        portaudio_ok: ``sounddevice`` imports, meaning the PortAudio shared
            library resolved. False specifically when the Python package is
            present but the system library is not — the one failure pip
            cannot fix.
        device_ok: At least one capture device is present. False on a
            headless host or over SSH.
        model_ok: Weights for the configured model size are already in the
            local cache, so the first dictation will not stall on a
            download.
        model_size: The size these verdicts were resolved against.
        detail: Optional human-readable note about the first unmet
            requirement (an import error message, for instance).
    """

    packages_ok: bool
    portaudio_ok: bool
    device_ok: bool
    model_ok: bool
    model_size: str
    detail: str = ""

    @property
    def is_ready(self) -> bool:
        """Whether a dictation started right now would work end to end."""
        return (
            self.packages_ok
            and self.portaudio_ok
            and self.device_ok
            and self.model_ok
        )

    @property
    def next_step(self) -> str:
        """The first unmet requirement, as a stable identifier.

        Ordered by dependency: there is no point reporting a missing model
        to someone who has not installed the packages yet.

        Returns:
            One of ``packages``, ``portaudio``, ``device``, ``model``, or
            an empty string when everything is satisfied.
        """
        if not self.packages_ok:
            return "packages"
        if not self.portaudio_ok:
            return "portaudio"
        if not self.device_ok:
            return "device"
        if not self.model_ok:
            return "model"
        return ""


class VoiceSetupService:
    """Detects what voice input still needs, and installs it on request."""

    def __init__(self, config: 'VoiceConfig') -> None:
        self._config = config
        self._cached: Optional[VoiceReadiness] = None

    # ------------------------------------------------------------------
    # Readiness
    # ------------------------------------------------------------------

    def probe(self, *, force: bool = False) -> VoiceReadiness:
        """Resolve which requirements are met.

        Importing the audio stack and enumerating devices both cost real
        time, so the verdict is cached until something might have changed.

        Args:
            force: Re-run every check instead of returning the cached
                verdict. Pass this after an install or a download.

        Returns:
            The current :class:`VoiceReadiness`.
        """
        if self._cached is not None and not force:
            return self._cached

        packages_ok, portaudio_ok, device_ok, detail = self._probe_runtime()
        model_size = self._config.model_size
        # Only meaningful once the packages are in place: the cache layout
        # is a Hugging Face implementation detail we can still inspect
        # without them, but reporting "no model" to someone who has not
        # installed anything yet buries the actual next step.
        model_ok = self.is_model_cached(model_size) if packages_ok else False

        self._cached = VoiceReadiness(
            packages_ok=packages_ok,
            portaudio_ok=portaudio_ok,
            device_ok=device_ok,
            model_ok=model_ok,
            model_size=model_size,
            detail=detail,
        )
        return self._cached

    def _probe_runtime(self) -> Tuple[bool, bool, bool, str]:
        """Check the imports and the capture devices.

        ``sounddevice`` is imported separately from the rest because its
        failure mode is the interesting one: an :exc:`OSError` naming
        PortAudio means the pip package installed fine and the system
        library is what is missing.

        Returns:
            Tuple of (packages_ok, portaudio_ok, device_ok, detail).
        """
        detail = ""
        try:
            import numpy  # noqa: F401
            from faster_whisper import WhisperModel  # noqa: F401
            packages_ok = True
        except Exception as e:  # noqa: BLE001 — a broken ctranslate2 build raises OSError
            logger.debug("Voice packages unavailable: %s", e)
            return False, False, False, str(e)

        try:
            import sounddevice as sd
            portaudio_ok = True
        except OSError as e:
            # sounddevice raises OSError, not ImportError, when the shared
            # library is absent — that is the signal we branch on.
            logger.debug("PortAudio unavailable: %s", e)
            return True, False, False, str(e)
        except Exception as e:  # noqa: BLE001 — the package itself is broken
            logger.debug("sounddevice unavailable: %s", e)
            return False, False, False, str(e)

        try:
            devices = sd.query_devices()
            device_ok = any(
                int(device.get('max_input_channels', 0)) > 0 for device in devices
            )
            if not device_ok:
                detail = "No capture device reported by the audio system"
        except Exception as e:  # noqa: BLE001 — headless hosts raise from PortAudio
            logger.debug("Device enumeration failed: %s", e)
            device_ok = False
            detail = str(e)

        return packages_ok, portaudio_ok, device_ok, detail

    # ------------------------------------------------------------------
    # Model cache
    # ------------------------------------------------------------------

    def _model_cache_root(self) -> Path:
        """Locate the Hugging Face hub cache the model lands in.

        Honours the same environment overrides the hub library does so a
        user who redirected their cache is not told the model is missing.
        """
        for env_var in ("HF_HUB_CACHE", "HUGGINGFACE_HUB_CACHE"):
            value = os.environ.get(env_var)
            if value:
                return Path(value).expanduser()
        hf_home = os.environ.get("HF_HOME")
        if hf_home:
            return Path(hf_home).expanduser() / "hub"
        return Path.home() / ".cache" / "huggingface" / "hub"

    def _model_cache_dirs(self, model_size: str) -> List[Path]:
        """Find cache directories that look like the requested model.

        Matched by glob rather than by an exact repository id because the
        publishing org has moved before (``Systran/faster-whisper-*``,
        ``Systran/faster-distil-whisper-*``) and a hard-coded id would
        report a present model as missing after the next move.
        """
        root = self._model_cache_root()
        if not root.is_dir():
            return []
        pattern = str(root / f"models--*whisper*{model_size}")
        return [Path(p) for p in glob.glob(pattern) if Path(p).is_dir()]

    def is_model_cached(self, model_size: str) -> bool:
        """Whether usable weights for *model_size* are already downloaded.

        Checks for the weights file rather than just the directory: an
        interrupted download leaves the folder and its refs behind, and
        treating that as "done" would push the failure to the first
        dictation instead of surfacing it here.
        """
        for cache_dir in self._model_cache_dirs(model_size):
            snapshots = cache_dir / "snapshots"
            if not snapshots.is_dir():
                continue
            for weights in snapshots.glob("*/model.bin"):
                # A blob symlink that outlived its target reads as missing.
                if weights.exists():
                    return True
        return False

    def model_cache_bytes(self, model_size: str) -> int:
        """Total on-disk size of the cached weights, or 0 when absent.

        Reported so the panel can tell the user what removing the model
        would reclaim.
        """
        total = 0
        for cache_dir in self._model_cache_dirs(model_size):
            for path in cache_dir.rglob("*"):
                try:
                    if path.is_file() and not path.is_symlink():
                        total += path.stat().st_size
                except OSError:
                    continue
        return total

    def remove_model(self, model_size: str) -> Tuple[bool, str]:
        """Delete the cached weights for *model_size*.

        Returns:
            Tuple of (success, message). Removing an absent model is
            reported as success — the requested end state already holds.
        """
        cache_dirs = self._model_cache_dirs(model_size)
        if not cache_dirs:
            return True, f"No cached weights for {model_size}"

        removed = 0
        for cache_dir in cache_dirs:
            try:
                shutil.rmtree(cache_dir)
                removed += 1
            except OSError as e:
                logger.error("Could not remove %s: %s", cache_dir, e)
                return False, f"Could not remove the cached model: {e}"

        self._cached = None
        return True, f"Removed the cached {model_size} model"

    def download_size_hint(self, model_size: str) -> str:
        """Approximate download size for *model_size*, for the UI copy."""
        return MODEL_DOWNLOAD_SIZES.get(model_size, "size unknown")

    # ------------------------------------------------------------------
    # Package install
    # ------------------------------------------------------------------

    def install_method(self) -> str:
        """How Servonaut itself was installed.

        Delegates to :class:`~servonaut.services.update_service.UpdateService`
        so the extras install targets the same environment the in-app
        upgrade does, instead of guessing separately.

        Returns:
            One of ``pipx``, ``pip``, ``source``, ``unknown``.
        """
        try:
            from servonaut.services.update_service import UpdateService
            return UpdateService().detect_install_method()
        except Exception as e:  # noqa: BLE001 — detection must never block setup
            logger.debug("Install-method detection failed: %s", e)
            return "unknown"

    def install_command(self) -> Optional[List[str]]:
        """Build the argv that installs the packages, when it is safe to run.

        A source or editable checkout is deliberately excluded: its
        dependencies are owned by whoever manages that environment, and
        quietly pip-installing into it is not ours to do.

        Returns:
            The argv list, or None when the install should be left to the
            user (:meth:`manual_install_command` has the copy for them).
        """
        method = self.install_method()
        if method == "pipx":
            pipx = shutil.which("pipx")
            if not pipx:
                return None
            return [pipx, "inject", "servonaut", *VOICE_PACKAGES]
        if method == "pip":
            return [sys.executable, "-m", "pip", "install", *VOICE_PACKAGES]
        return None

    def manual_install_command(self) -> str:
        """The install command as a single copy-pasteable string.

        Always available, including for the source installs
        :meth:`install_command` refuses to run itself.
        """
        argv = self.install_command()
        if argv:
            return " ".join(argv)
        packages = " ".join(VOICE_PACKAGES)
        if self.install_method() == "source":
            # An editable checkout installs extras through the project, so
            # point at the extra rather than the loose package list.
            return "pip install -e '.[voice]'"
        return f"pip install {packages}"

    def portaudio_command(self) -> str:
        """The command that installs the PortAudio system library.

        Resolved against the package manager actually present so the
        instruction is runnable rather than a list of maybes.
        """
        if get_os() == "macos":
            return _PORTAUDIO_MACOS
        for binary, command in _PORTAUDIO_COMMANDS:
            if command_exists(binary):
                return command
        return "install the PortAudio library for your distribution"

    async def install_packages(self) -> Tuple[bool, str]:
        """Install the voice packages into Servonaut's own environment.

        Runs the package manager as a subprocess and, on success, asks
        :func:`~servonaut.services.voice_input_service.reload_voice_deps`
        to pick the new modules up so the feature works without a
        restart.

        Returns:
            Tuple of (success, message) fit for display.
        """
        argv = self.install_command()
        if argv is None:
            return False, (
                "This looks like a source checkout — install the extra "
                f"yourself with: {self.manual_install_command()}"
            )

        logger.info("Installing voice packages via %s", argv[0])
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except OSError as e:
            logger.error("Could not start the installer: %s", e)
            return False, f"Could not start the installer: {e}"

        try:
            stdout, _ = await asyncio.wait_for(
                process.communicate(), timeout=_INSTALL_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return False, "The install timed out. Try running it in a terminal."

        output = (stdout or b"").decode(errors="replace")
        if process.returncode != 0:
            logger.error("Voice package install failed (rc=%s)", process.returncode)
            return False, self._installer_failure_message(output)

        self._cached = None
        from servonaut.services.voice_input_service import reload_voice_deps
        if not reload_voice_deps():
            readiness = self.probe(force=True)
            if not readiness.portaudio_ok:
                return True, (
                    "Packages installed. PortAudio is still missing — run: "
                    f"{self.portaudio_command()}"
                )
            return True, "Packages installed. Restart Servonaut to finish enabling voice input."
        return True, "Voice packages installed."

    def _installer_failure_message(self, output: str) -> str:
        """Turn installer output into one actionable line.

        The tail of a pip failure is usually the useful part, but it can
        run to hundreds of lines of resolver noise, so it is trimmed to
        something a notification can hold.
        """
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        tail = lines[-1] if lines else "no output"
        return f"Install failed: {tail[:200]}"

    # ------------------------------------------------------------------
    # Model download
    # ------------------------------------------------------------------

    async def download_model(self, model_size: Optional[str] = None) -> Tuple[bool, str]:
        """Fetch the model weights ahead of the first dictation.

        The transcription backend would download these lazily anyway; doing
        it here means the cost is paid against a button the user pressed
        knowingly, with the size shown, instead of stalling their first
        recording for minutes.

        Args:
            model_size: Size to fetch. Defaults to the configured size.

        Returns:
            Tuple of (success, message).
        """
        size = model_size or self._config.model_size
        readiness = self.probe()
        if not readiness.packages_ok:
            return False, "Install the voice packages first."

        try:
            success, message = await asyncio.wait_for(
                asyncio.to_thread(self._download_model_blocking, size),
                timeout=_DOWNLOAD_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            return False, "The model download timed out."

        self._cached = None
        return success, message

    def _download_model_blocking(self, model_size: str) -> Tuple[bool, str]:
        """Construct the model once, which pulls the weights into the cache.

        Runs on a worker thread — it blocks for the whole download.
        """
        try:
            from faster_whisper import WhisperModel
            WhisperModel(model_size, device="cpu", compute_type="int8")
        except Exception as e:  # noqa: BLE001 — hub errors, disk-full, bad size
            logger.error("Model download failed for %s: %s", model_size, e)
            return False, f"Download failed: {e}"

        if not self.is_model_cached(model_size):
            # The model loaded from somewhere we do not recognise as the
            # cache (a local conversion path, say). Not a failure, but the
            # panel should not promise it is cached.
            return True, f"Loaded {model_size}, but it is not in the expected cache location."
        return True, f"Downloaded the {model_size} model."


def build_voice_setup_service(config: 'VoiceConfig') -> VoiceSetupService:
    """Construct the setup service.

    A factory for symmetry with the other optional-service builders, and so
    call sites do not import the class directly.
    """
    return VoiceSetupService(config)
