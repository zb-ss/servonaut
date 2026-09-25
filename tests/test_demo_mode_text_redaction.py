"""Demo mode keeps real identifiers out of free text: toasts and status lines.

Provider errors quote what was sent (the real id, host or service name), so
the text a screen shows goes through a replacer built from the fleet's real
records. It must stay cheap on large fleets, follow fleet refreshes, and
leave ordinary words alone.
"""
from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest

from servonaut.app import ServonautApp
from servonaut.screens._demo_resolve import display_rows, replace_instances
from servonaut.services.redaction_service import RedactionService


def _app(demo: bool = True) -> SimpleNamespace:
    """The app's text path and fleet entry point, without Textual."""
    app = SimpleNamespace(
        demo_mode=demo,
        redaction_service=RedactionService() if demo else None,
        instances=[],
        _instances_pristine=[],
        _fleet_generation=0,
        _demo_known_cache=None,
    )
    app.redact_display_text = lambda text: ServonautApp.redact_display_text(app, text)
    app._demo_known_identifiers = lambda: ServonautApp._demo_known_identifiers(app)
    app.real_instance_id = lambda value: ServonautApp.real_instance_id(app, value)
    app.connection_instance = lambda row: ServonautApp.connection_instance(app, row)
    return app


HETZNER = {"id": "48151623", "name": "acme-cache", "public_ip": "1.1.1.1",
           "is_hetzner": True, "provider": "hetzner", "state": "running",
           "group": "nginx", "tags": {"role": "haproxy"}}


def test_the_hetzner_status_line_hides_a_real_server_id() -> None:
    from servonaut.screens.hetzner_manager import HetznerManagerScreen

    app = _app()
    status = MagicMock()
    screen = HetznerManagerScreen()
    screen._raw_instances = [dict(HETZNER)]
    app.hetzner_service = SimpleNamespace(
        delete_server=AsyncMock(side_effect=RuntimeError("Server not found: 48151623")),
    )
    app.notify = MagicMock()
    with (
        patch.object(HetznerManagerScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", return_value=status),
        patch.object(screen, "_render_table"),
    ):
        screen._apply_display_rows()
        shown = screen._instances[0]
        app.push_screen_wait = AsyncMock(return_value=True)
        asyncio.run(screen._do_delete(shown))
    lines = [call.args[0] for call in status.update.call_args_list]
    assert lines and all("48151623" not in line for line in lines)
    assert any(shown["id"] in line for line in lines)


def test_status_lines_are_unchanged_outside_demo_mode() -> None:
    app = _app(demo=False)
    assert app.redact_display_text("Server not found: 48151623") == (
        "Server not found: 48151623"
    )


def test_tags_and_groups_are_not_replaced_in_running_text() -> None:
    app = _app()
    replace_instances(app, "hetzner", [HETZNER])
    text = app.redact_display_text("Probing nginx and haproxy on acme-cache")
    assert "Probing nginx and haproxy on " in text
    assert "acme-cache" not in text


def test_the_replacer_follows_a_fleet_refresh() -> None:
    app = _app()
    replace_instances(app, "hetzner", [HETZNER])
    assert "acme-cache" not in app.redact_display_text("acme-cache failed")
    newcomer = dict(HETZNER, id="48151699", name="acme-queue")
    replace_instances(app, "hetzner", [HETZNER, newcomer])
    assert "acme-queue" not in app.redact_display_text("acme-queue failed")


def test_the_replacer_is_cheap_on_a_large_fleet() -> None:
    app = _app()
    rows = [
        {"id": f"i-0{n:016x}", "name": f"acme-web-{n}", "public_ip": f"9.{n // 256}.{n % 256}.7",
         "private_ip": f"10.1.{n // 256}.{n % 256}", "key_name": f"acme-key-{n % 40}"}
        for n in range(5000)
    ]
    replace_instances(app, "aws", rows)

    start = time.perf_counter()
    app.redact_display_text("warm-up")
    build = time.perf_counter() - start
    assert build < 1.0, f"building the replacer took {build:.2f}s"

    message = "Reinstall failed: acme-web-4711 at 9.18.103.7 refused (retry later)"
    start = time.perf_counter()
    for _ in range(20):
        shown = app.redact_display_text(message)
    per_toast = (time.perf_counter() - start) / 20
    assert per_toast < 0.005, f"a toast took {per_toast * 1000:.1f} ms"
    assert "acme-web-4711" not in shown and "9.18.103.7" not in shown


def test_a_manager_fetch_redraws_a_fleet_row_whose_stand_in_it_takes() -> None:
    app = _app()
    replace_instances(app, "hetzner", [dict(HETZNER, id="3", name="acme-small")])
    held = app.instances[0]
    stand_in = held["id"]

    # A provider manager fetches a server whose real id is that stand-in.
    display_rows(app, [{"id": stand_in, "name": "acme-other"}])
    assert held["id"] != stand_in, "the held row must not keep a real id"
    assert app.connection_instance(held)["name"] == "acme-small"


# ---------------------------------------------------------------------------
# Bug-report host rules
# ---------------------------------------------------------------------------


def _report_scrubber(known_hosts=()):
    from servonaut.services.report_scrubber import InventoryScrubber

    return InventoryScrubber.from_inventory([], None, known_hosts)


def test_service_labels_and_punycode_hosts_are_scrubbed() -> None:
    scrubber = _report_scrubber(known_hosts=["acmecorp.com"])
    text = scrubber.scrub_text(
        "TXT _dmarc.acmecorp.com; CNAME _acme-challenge.acmecorp.com; "
        "v=spf1 include:_spf.acmecorp.com ~all; shop.acme.xn--p1ai down"
    )
    assert "acmecorp" not in text
    assert "xn--p1ai" not in text
    assert "_dmarc." in text and "_acme-challenge." in text and "include:_spf." in text


def test_dotted_code_and_config_file_names_are_left_alone() -> None:
    scrubber = _report_scrubber()
    text = (
        "subprocess.run(cmd) raised socket.gaierror in manager.load; "
        "see nginx.conf and api.ovh.com"
    )
    assert scrubber.scrub_text(text) == text


def test_a_host_named_config_file_is_still_scrubbed() -> None:
    scrubber = _report_scrubber()
    text = scrubber.scrub_text("loading /etc/nginx/sites-enabled/acmecorp.com.conf")
    assert "acmecorp" not in text and text.endswith(".conf")
