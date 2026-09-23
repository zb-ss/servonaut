"""Voice companion runtime requirements and dependency definitions.

Defines the isolated package requirements for the Servonaut Desktop companion
voice worker daemon. The main Servonaut package contains zero native voice
dependencies; all heavy audio, STT, and TTS packages are installed exclusively
into the managed companion virtual environment.
"""

from __future__ import annotations

import hashlib
from typing import Final, Sequence

VOICE_RUNTIME_VERSION: Final[str] = "1.0.0"

# Core packages required for companion audio capture and baseline DSP
CORE_VOICE_REQUIREMENTS: Final[tuple[str, ...]] = (
    "numpy>=1.24.0",
    "sounddevice>=0.4.6",
    "scipy>=1.10.0",
)


def compute_requirements_hash(requirements: Sequence[str]) -> str:
    """Compute a deterministic SHA-256 fingerprint for a set of requirements.

    Args:
        requirements: Sequence of pip requirement strings.

    Returns:
        Hex-encoded SHA-256 digest of the canonicalized requirements.
    """
    canonical = sorted(r.strip() for r in requirements if r.strip() and not r.startswith("#"))
    blob = "\n".join(canonical).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def get_default_requirements() -> list[str]:
    """Return the default list of companion packages to provision."""
    return list(CORE_VOICE_REQUIREMENTS)
