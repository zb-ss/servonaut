"""The theme preview draws fixed sample rows, never a name that could be the user's server."""

from __future__ import annotations

from servonaut.screens.settings.panels.appearance import _preview_content
from servonaut.styles.themes import SERVONAUT_THEMES


def test_the_preview_shows_sample_rows_not_real_looking_server_names() -> None:
    text = _preview_content(SERVONAUT_THEMES[0]).plain
    assert "sample-1" in text and "sample-2" in text
    # Names a fleet or a demo run would show must not appear in a sample.
    for name in ("app-1", "db-1", "web-1", "bastion-1"):
        assert name not in text
