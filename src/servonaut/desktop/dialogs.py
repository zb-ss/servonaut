"""Native desktop file dialog adapters for SCP file transfer and export workflows.

Wraps pywebview's native OS file dialogs (via GTK, Cocoa, or Windows Win32/EdgeChromium)
in a typed, fail-safe Python interface.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from enum import Enum
from pathlib import Path
from typing import Any, Final

logger = logging.getLogger(__name__)

# Constants matching pywebview.FileDialogType
_DIALOG_OPEN: Final[int] = 10
_DIALOG_FOLDER: Final[int] = 20
_DIALOG_SAVE: Final[int] = 30


class FileDialogType(str, Enum):
    """Supported native file dialog interactions."""

    OPEN_FILE = "open_file"
    OPEN_FILES = "open_files"
    OPEN_FOLDER = "open_folder"
    SAVE_FILE = "save_file"


class DesktopDialogError(RuntimeError):
    """Raised when native dialog operations fail or window is unavailable."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.code = message


class DesktopDialogService:
    """Provides typed access to native OS file dialogs through pywebview."""

    def __init__(
        self,
        window: Any = None,
        *,
        window_getter: Callable[[], Any] | None = None,
    ) -> None:
        self._window = window
        self._window_getter = window_getter

    def _resolve_window(self) -> Any:
        if self._window is not None:
            return self._window
        if self._window_getter is not None:
            return self._window_getter()
        return None

    def open_file(
        self,
        *,
        title: str = "Open File",
        directory: str = "",
        file_types: Sequence[str] = (),
    ) -> Path | None:
        """Prompt user to select a single existing file."""
        window = self._resolve_window()
        if window is None:
            raise DesktopDialogError("dialog-window-unavailable")

        try:
            result = window.create_file_dialog(
                dialog_type=_DIALOG_OPEN,
                directory=directory,
                allow_multiple=False,
                file_types=tuple(file_types),
            )
        except Exception as exc:
            logger.error("Native open file dialog failed: %s", exc)
            raise DesktopDialogError(f"dialog-failed:{exc}") from exc

        paths = self._normalize_dialog_result(result)
        return paths[0] if paths else None

    def open_files(
        self,
        *,
        title: str = "Open Files",
        directory: str = "",
        file_types: Sequence[str] = (),
    ) -> tuple[Path, ...] | None:
        """Prompt user to select one or more existing files."""
        window = self._resolve_window()
        if window is None:
            raise DesktopDialogError("dialog-window-unavailable")

        try:
            result = window.create_file_dialog(
                dialog_type=_DIALOG_OPEN,
                directory=directory,
                allow_multiple=True,
                file_types=tuple(file_types),
            )
        except Exception as exc:
            logger.error("Native open files dialog failed: %s", exc)
            raise DesktopDialogError(f"dialog-failed:{exc}") from exc

        paths = self._normalize_dialog_result(result)
        return paths if paths else None

    def open_folder(
        self,
        *,
        title: str = "Select Folder",
        directory: str = "",
    ) -> Path | None:
        """Prompt user to select a single directory."""
        window = self._resolve_window()
        if window is None:
            raise DesktopDialogError("dialog-window-unavailable")

        try:
            result = window.create_file_dialog(
                dialog_type=_DIALOG_FOLDER,
                directory=directory,
                allow_multiple=False,
            )
        except Exception as exc:
            logger.error("Native open folder dialog failed: %s", exc)
            raise DesktopDialogError(f"dialog-failed:{exc}") from exc

        paths = self._normalize_dialog_result(result)
        return paths[0] if paths else None

    def save_file(
        self,
        *,
        title: str = "Save File",
        directory: str = "",
        save_filename: str = "",
        file_types: Sequence[str] = (),
    ) -> Path | None:
        """Prompt user to specify a destination file path for save/export."""
        window = self._resolve_window()
        if window is None:
            raise DesktopDialogError("dialog-window-unavailable")

        try:
            result = window.create_file_dialog(
                dialog_type=_DIALOG_SAVE,
                directory=directory,
                save_filename=save_filename,
                file_types=tuple(file_types),
            )
        except Exception as exc:
            logger.error("Native save file dialog failed: %s", exc)
            raise DesktopDialogError(f"dialog-failed:{exc}") from exc

        paths = self._normalize_dialog_result(result)
        return paths[0] if paths else None

    @staticmethod
    def _normalize_dialog_result(result: Any) -> tuple[Path, ...]:
        """Convert pywebview return types into clean Path instances."""
        if result is None:
            return ()
        if isinstance(result, str):
            result = [result]
        if not isinstance(result, (list, tuple)):
            return ()

        validated: list[Path] = []
        for item in result:
            if not isinstance(item, str):
                continue
            cleaned = item.strip()
            if not cleaned or "\x00" in cleaned:
                continue
            validated.append(Path(cleaned))

        return tuple(validated)
