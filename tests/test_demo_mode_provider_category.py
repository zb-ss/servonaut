"""Demo mode hides a custom server's provider label, not what kind of server it is.

A custom server's provider label is free text (it may name a hosting
company), and the server's region repeats it. Demo mode used to hash such a
label into a pool of cloud names, so a custom server could be listed as an
AWS instance in a region called "AWS". The stand-in is now the category the
server belongs to, ``custom``, while public provider names pass through.
"""

from __future__ import annotations

import pytest

from servonaut.config.schema import CustomServer
from servonaut.services.custom_server_service import CustomServerService
from servonaut.services.redaction_service import RedactionService

# Labels the app gives to servers it fetches itself.
_FETCHED_PROVIDERS = {"aws", "ovh", "hetzner"}


def _custom_row(provider: str) -> dict:
    """A custom server's fleet row, as the app builds it."""
    server = CustomServer(name="web-1", host="10.0.0.11", provider=provider)
    # to_instance_dict reads nothing from the service's configuration.
    return CustomServerService.__new__(CustomServerService).to_instance_dict(server)


@pytest.mark.parametrize("label", ["colo", "rack-3", "Example Hosting", "my-datacenter"])
def test_a_custom_label_becomes_the_custom_category(label: str) -> None:
    row = RedactionService().redact_instance(_custom_row(label))
    assert row["provider"] == "custom"
    assert row["region"] == "custom"


@pytest.mark.parametrize("label", ["colo", "rack-3", "custom", "Example Hosting", "x" * 40])
def test_a_custom_server_is_never_shown_as_a_fetched_provider(label: str) -> None:
    row = RedactionService().redact_instance(_custom_row(label))
    assert row["provider"].lower() not in _FETCHED_PROVIDERS
    assert row["region"].lower() not in _FETCHED_PROVIDERS


def test_a_custom_server_without_a_label_stays_custom() -> None:
    row = RedactionService().redact_instance(_custom_row(""))
    assert (row["provider"], row["region"]) == ("custom", "custom")


@pytest.mark.parametrize("label", ["DigitalOcean", "digitalocean", "Hetzner", "hetzner", "OVH", "ovh", "AWS"])
def test_public_provider_names_pass_through_in_any_case(label: str) -> None:
    assert RedactionService().redact_provider(label) == label


def test_an_aws_style_region_on_a_custom_server_is_kept() -> None:
    row = _custom_row("colo")
    row["region"] = "eu-west-1"
    assert RedactionService().redact_instance(row)["region"] == "eu-west-1"


def test_fetched_rows_keep_their_provider() -> None:
    service = RedactionService()
    hetzner = service.redact_instance({"id": "4200001", "provider": "hetzner", "region": "fsn1"})
    ovh = service.redact_instance({"id": "4200002", "provider": "OVH", "region": "GRA7"})
    assert (hetzner["provider"], hetzner["region"]) == ("hetzner", "fsn1")
    assert (ovh["provider"], ovh["region"]) == ("OVH", "GRA7")
