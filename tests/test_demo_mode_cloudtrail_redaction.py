"""Demo mode: EC2 instance ids in free text and CloudTrail usernames are redacted."""
from __future__ import annotations

from unittest.mock import MagicMock, PropertyMock, patch

from servonaut.screens.cloudtrail_browser import CloudTrailBrowserScreen
from servonaut.services.redaction_service import RedactionService


def test_scrub_stream_replaces_ec2_instance_ids_consistently():
    svc = RedactionService()
    real = "i-0abc12345678def01"
    out = svc.scrub_stream(f"UpdateInstanceInformation by {real} from {real}")
    assert real not in out
    fake = svc.redact_instance_id(real)
    assert out.count(fake) == 2
    assert fake.startswith("i-") and len(fake) == len(real)


def _demo_app():
    app = MagicMock()
    app.demo_mode = True
    app.redaction_service = RedactionService()
    return app


def test_browser_redacts_instance_role_and_human_usernames():
    app = _demo_app()
    screen = CloudTrailBrowserScreen()
    with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
        assert screen._u("i-0abc12345678def01") == app.redaction_service.redact_instance_id("i-0abc12345678def01")
        human = screen._u("jane.doe")
        assert human != "jane.doe"
        assert human == app.redaction_service.redact_username("jane.doe")
        assert screen._u("") == ""


def test_browser_leaves_usernames_alone_outside_demo_mode():
    app = MagicMock()
    app.demo_mode = False
    app.redaction_service = None
    screen = CloudTrailBrowserScreen()
    with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
        assert screen._u("jane.doe") == "jane.doe"
