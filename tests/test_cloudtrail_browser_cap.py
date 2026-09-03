"""The CloudTrail browser fetches at most ``cloudtrail_max_events`` per lookup."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

from servonaut.config.schema import AppConfig
from servonaut.screens.cloudtrail_browser import CloudTrailBrowserScreen
from servonaut.services.cloudtrail_service import LookupPage


def _run(coro):
    return asyncio.run(coro)


def _app(max_events: int):
    app = MagicMock()
    app.demo_mode = False
    app.redaction_service = None
    cfg = AppConfig()
    cfg.cloudtrail_max_events = max_events
    app.config_manager.get.return_value = cfg
    app.cloudtrail_service.lookup_page = AsyncMock(return_value=LookupPage(events=[], next_token=None))
    return app


def test_fetch_passes_the_configured_cap():
    app = _app(100)
    screen = CloudTrailBrowserScreen()
    with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
         patch.object(screen, "query_one", return_value=MagicMock()), \
         patch.object(screen, "_populate_table"), \
         patch.object(screen, "_update_pager"):
        _run(screen._fetch_events("eu-west-2", 60, "", "", ""))

    kwargs = app.cloudtrail_service.lookup_page.await_args.kwargs
    assert kwargs["max_results"] == 100
    assert kwargs["region"] == "eu-west-2"


def test_zero_cap_means_everything_in_the_window():
    app = _app(0)
    screen = CloudTrailBrowserScreen()
    with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
         patch.object(screen, "query_one", return_value=MagicMock()), \
         patch.object(screen, "_populate_table"), \
         patch.object(screen, "_update_pager"):
        _run(screen._fetch_events("eu-west-2", 60, "", "", ""))

    assert app.cloudtrail_service.lookup_page.await_args.kwargs["max_results"] == 0
