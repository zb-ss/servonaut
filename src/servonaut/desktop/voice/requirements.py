"""Voice package names reported by the desktop voice setup service.

The managed runtime does not install from this list: it installs the
hash-locked requirements bundled with the desktop build (see
:mod:`servonaut.desktop.voice.packaged_manifest`). These names only describe
the voice stack to the setup screen.
"""

from __future__ import annotations

from typing import Final

CORE_VOICE_REQUIREMENTS: Final[tuple[str, ...]] = (
    "numpy>=1.24.0",
    "sounddevice>=0.4.6",
    "scipy>=1.10.0",
)
