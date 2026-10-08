"""The log viewer header shows its bracketed markers, and SSH errors read plainly.

Textual's markup reads ``[PAUSED]`` as a tag and drops it, so those markers
must be escaped; the queued SSH error is written as plain text, so it must
carry no markup at all.
"""

from __future__ import annotations

import io
from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock, patch

from textual.content import Content

from servonaut.screens.log_viewer import LogViewerScreen


def _service(**overrides):
    values = dict(
        classify_log_file=lambda path: "rotated",
        last_probe_source=None,
        last_probe_probed_at=None,
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def _header(screen: LogViewerScreen, service=None) -> str:
    app = SimpleNamespace(log_viewer_service=service or _service())
    header = MagicMock()
    with patch.object(LogViewerScreen, "app", new_callable=PropertyMock, return_value=app), \
            patch.object(screen, "query_one", return_value=header):
        screen._update_header()
    return Content.from_markup(header.update.call_args.args[0]).plain


def test_paused_marker_is_shown() -> None:
    screen = LogViewerScreen({"name": "web-1"})
    screen._is_paused = True
    assert "[PAUSED]" in _header(screen)


def test_file_kind_and_cache_markers_are_shown() -> None:
    screen = LogViewerScreen({"name": "web-1"})
    screen._is_static_view = True
    plain = _header(screen, _service(last_probe_source="cache"))
    assert "[rotated]" in plain
    assert "[cached]" in plain


def test_names_and_paths_with_brackets_are_shown_as_written() -> None:
    screen = LogViewerScreen({"name": "web-[b]1"})
    screen._current_log = "/var/log/[app].log"
    plain = _header(screen)
    assert "web-[b]1" in plain
    assert "/var/log/[app].log" in plain


def test_ssh_error_line_has_no_markup() -> None:
    screen = LogViewerScreen({"name": "web-1"})
    screen._process = SimpleNamespace(
        stdout=io.BytesIO(b""), stderr=io.BytesIO(b"Permission denied (publickey).\n"),
    )
    screen._reader_thread_fn()
    assert screen._line_queue.get_nowait() == "SSH error: Permission denied (publickey)."
