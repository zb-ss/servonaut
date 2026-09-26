"""Tests for the shared rotating log configuration."""

from __future__ import annotations

import logging

import pytest

from servonaut.utils.logging_setup import _NOISY_LOGGERS, configure_rotating_log


@pytest.fixture
def restore_logging():
    """Put the root logger and the library loggers back as they were."""
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    levels = {name: logging.getLogger(name).level for name in _NOISY_LOGGERS}
    yield
    for handler in list(root.handlers):
        if handler not in handlers:
            root.removeHandler(handler)
            handler.close()
    for handler in handlers:
        if handler not in root.handlers:
            root.addHandler(handler)
    root.setLevel(level)
    for name, previous in levels.items():
        logging.getLogger(name).setLevel(previous)


def test_request_urls_with_tokens_stay_out_of_the_log(tmp_path, restore_logging):
    log_file = configure_rotating_log(tmp_path)
    logging.getLogger("httpx").info(
        "HTTP Request: GET https://hub.example.com/sse?authorization=fake-subscriber-token"
    )
    logging.getLogger("servonaut.test").info("app line")
    for handler in logging.getLogger().handlers:
        handler.flush()

    text = log_file.read_text(encoding="utf-8")
    assert "app line" in text
    assert "fake-subscriber-token" not in text
