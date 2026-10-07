"""Personal binding route keys for cloud instances and custom servers."""
from __future__ import annotations

import re

import pytest

from servonaut.services.vault.personal_targets import custom_binding_id, instance_target, personal_target
from servonaut.utils.validation import ValidationError

_SERVICE_ID = re.compile(r"[A-Za-z0-9_\-]{1,64}")


@pytest.mark.parametrize("name", [
    "web-1", "Web 1", "db.example.com", "  spaced  ", "ünïcödé-box", "x" * 200, "!!!", "web_1/prod",
])
def test_custom_ids_fit_the_service_route_and_are_stable(name: str) -> None:
    route_id = custom_binding_id(name)

    assert _SERVICE_ID.fullmatch(route_id)
    assert route_id == custom_binding_id(name)


def test_custom_ids_are_readable_and_keep_similar_names_apart() -> None:
    assert custom_binding_id("DB.Example.com").startswith("db-example-com-")
    assert custom_binding_id("web 1") != custom_binding_id("web-1")


@pytest.mark.parametrize("name", ["", "   ", None])
def test_a_custom_server_without_a_name_cannot_be_bound(name) -> None:
    with pytest.raises(ValueError, match="needs a name"):
        custom_binding_id(name)


def test_explicit_input_maps_custom_names_and_validates_cloud_ids() -> None:
    assert personal_target("custom", "Web 1") == ("custom", custom_binding_id("Web 1"))
    assert personal_target("Custom", "Web 1") == ("custom", custom_binding_id("Web 1"))
    assert personal_target("hetzner", "12345") == ("hetzner", "12345")
    with pytest.raises(ValidationError):
        personal_target("digitalocean", "12345")


def test_inventory_rows_use_custom_for_custom_servers_whatever_their_label() -> None:
    row = {"id": "custom-Web 1", "name": "Web 1", "provider": "Hetzner", "is_custom": True}

    assert instance_target(row) == ("custom", custom_binding_id("Web 1"))
    assert instance_target({"id": "i-0abc", "provider": "aws"}) == ("aws", "i-0abc")
