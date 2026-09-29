"""Shared account lookups of the surfaces without an instance list."""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from servonaut.services.accounts import UnknownAccountError
from servonaut.services.accounts.headless import (
    CachedFleet,
    InstanceDirectory,
    account_labels,
    qualifier_provider,
    resolve_provider_target,
)
from servonaut.utils.instance_resolver import AmbiguousInstanceError
from tests._account_fixtures import FakeProvider, build_registry


def _run(coro):
    return asyncio.run(coro)


def _custom(*rows):
    service = MagicMock()
    service.list_as_instances.return_value = [dict(r) for r in rows]
    return service


CUSTOM_WEB = {"id": "custom-web", "name": "web-1", "is_custom": True}


# ---------------------------------------------------------------------------
# account_labels / qualifier_provider
# ---------------------------------------------------------------------------


def test_account_labels_are_labels_only(monkeypatch):
    registry, _ = build_registry(
        monkeypatch,
        aws={"aws": [], "prod": []},
        hetzner={"hetzner": [], "staging": []},
    )
    assert account_labels(registry) == {
        "aws": ["aws", "prod"], "hetzner": ["hetzner", "staging"], "ovh": [],
    }
    assert account_labels(None) == {}


def test_qualifier_provider(monkeypatch):
    registry, _ = build_registry(monkeypatch, hetzner={"hetzner": [], "staging": []})
    assert qualifier_provider(registry, "staging/web-1") == "hetzner"
    assert qualifier_provider(registry, "custom/web-1") == "custom"
    assert qualifier_provider(registry, "web-1") is None
    # A prefix that names no account (an OVH Public Cloud id) is no qualifier.
    assert qualifier_provider(registry, "0a1b2c/inst-1") is None
    assert qualifier_provider(None, "staging/web-1") is None


# ---------------------------------------------------------------------------
# CachedFleet (CLI)
# ---------------------------------------------------------------------------


def test_cached_fleet_reads_every_account_in_table_order(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "api"}], "prod": [{"id": "i-2", "name": "db"}]},
        hetzner={"hetzner": [{"id": "1", "name": "h1", "is_hetzner": True}],
                 "staging": [{"id": "2", "name": "h2", "is_hetzner": True}]},
        ovh={"ovh": [{"id": "vps-1", "name": "o1", "is_ovh": True}]},
    )
    fleet = CachedFleet.from_registry(registry, _custom(CUSTOM_WEB))

    ids = [row["id"] for row in fleet.instances()]

    assert ids == ["i-1", "i-2", "custom-web", "vps-1", "1", "2"]
    assert all(service.fetches == 0 for service in services.values())


def test_cached_fleet_resolves_qualified_and_refuses_shared_names(monkeypatch):
    registry, _ = build_registry(
        monkeypatch,
        hetzner={"hetzner": [{"id": "1", "name": "web-1", "is_hetzner": True}],
                 "staging": [{"id": "2", "name": "web-1", "is_hetzner": True}]},
    )
    fleet = CachedFleet.from_registry(registry, _custom())

    assert fleet.resolve("staging/web-1")["id"] == "2"
    assert fleet.resolve("2")["id"] == "2"
    with pytest.raises(AmbiguousInstanceError) as err:
        fleet.resolve("web-1")
    assert "hetzner/web-1" in str(err.value) and "staging/web-1" in str(err.value)


def test_cached_fleet_surfaces_an_aws_cache_bug_but_not_other_providers():
    broken = MagicMock()
    broken.get_cached_instances.side_effect = RuntimeError("boom")
    fine = FakeProvider("aws", "aws", [{"id": "i-1"}])

    with pytest.raises(RuntimeError):
        CachedFleet(_custom(), aws=broken).instances()
    rows = CachedFleet(_custom(), aws=fine, ovh=broken, hetzner=broken).instances()
    assert [r["id"] for r in rows] == ["i-1"]


# ---------------------------------------------------------------------------
# InstanceDirectory (MCP tools, relay)
# ---------------------------------------------------------------------------


def _directory(registry, custom=()):
    return InstanceDirectory(
        _custom(*custom),
        lambda: {p: registry.fleet(p) for p in ("aws", "ovh", "hetzner")},
        lambda: registry,
    )


def test_explicit_custom_id_fetches_no_provider(monkeypatch):
    registry, services = build_registry(monkeypatch, hetzner={"hetzner": []})
    found = _run(_directory(registry, [CUSTOM_WEB]).find("custom-web"))
    assert found["id"] == "custom-web"
    assert all(s.fetches == 0 and s.cache_reads == 0 for s in services.values())


def test_qualified_reference_only_consults_that_provider(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "web-1"}]},
        hetzner={"hetzner": [], "staging": [{"id": "2", "name": "web-1", "is_hetzner": True}]},
        ovh={"ovh": [{"id": "vps-1", "name": "web-1", "is_ovh": True}]},
    )
    found = _run(_directory(registry).find("staging/web-1"))
    assert found["id"] == "2" and found["account"] == "staging"
    assert services[("aws", "aws")].fetches == 0
    assert services[("ovh", "ovh")].fetches == 0
    assert services[("ovh", "ovh")].cache_reads == 0


def test_after_a_match_other_providers_are_read_from_cache_only(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "web-1"}]},
        hetzner={"hetzner": [{"id": "2", "name": "db", "is_hetzner": True}]},
        ovh={"ovh": [{"id": "vps-1", "name": "mail", "is_ovh": True}]},
    )
    found = _run(_directory(registry).find("web-1"))
    assert found["id"] == "i-1"
    assert services[("ovh", "ovh")].fetches == 0
    assert services[("hetzner", "hetzner")].fetches == 0
    assert services[("hetzner", "hetzner")].cache_reads == 1


def test_a_name_on_two_providers_is_refused_with_candidates(monkeypatch):
    registry, _ = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "web-1"}]},
        hetzner={"hetzner": [{"id": "2", "name": "web-1", "is_hetzner": True}]},
    )
    with pytest.raises(AmbiguousInstanceError) as err:
        _run(_directory(registry).find("web-1"))
    message = str(err.value)
    assert "aws/web-1" in message and "hetzner/web-1" in message


def test_single_account_primary_label_qualifies_too(monkeypatch):
    registry, _ = build_registry(
        monkeypatch, hetzner={"hetzner": [{"id": "2", "name": "web-1", "is_hetzner": True}]},
    )
    assert _run(_directory(registry).find("hetzner/web-1"))["id"] == "2"


def test_ovh_cloud_id_with_a_slash_resolves_as_an_id(monkeypatch):
    registry, _ = build_registry(
        monkeypatch,
        ovh={"ovh": [{"id": "proj1/inst-1", "name": "api", "is_ovh": True}]},
    )
    assert _run(_directory(registry).find("proj1/inst-1"))["name"] == "api"


def test_blank_reference_matches_nothing(monkeypatch):
    registry, _ = build_registry(monkeypatch, aws={"aws": [{"id": "i-1", "name": ""}]})
    assert _run(_directory(registry).find("  ")) is None


# ---------------------------------------------------------------------------
# resolve_provider_target (lifecycle calls)
# ---------------------------------------------------------------------------


@pytest.fixture
def hetzner_two_projects(monkeypatch):
    return build_registry(
        monkeypatch,
        hetzner={
            "hetzner": [{"id": "1", "name": "web-1", "is_hetzner": True},
                        {"id": "3", "name": "api", "is_hetzner": True}],
            "staging": [{"id": "2", "name": "web-1", "is_hetzner": True},
                        {"id": "4", "name": "worker", "is_hetzner": True}],
        },
    )[0]


def test_target_found_in_the_cache_of_its_account(hetzner_two_projects):
    target = resolve_provider_target(hetzner_two_projects, "hetzner", "worker")
    assert (target.account.label, target.reference, target.native_id) == ("staging", "worker", "4")


def test_target_by_id(hetzner_two_projects):
    target = resolve_provider_target(hetzner_two_projects, "hetzner", "2")
    assert target.account.label == "staging"


def test_target_qualified(hetzner_two_projects):
    target = resolve_provider_target(hetzner_two_projects, "hetzner", "staging/web-1")
    assert (target.account.label, target.reference) == ("staging", "web-1")


def test_target_with_explicit_account(hetzner_two_projects):
    target = resolve_provider_target(hetzner_two_projects, "hetzner", "web-1", "STAGING")
    assert (target.account.label, target.native_id) == ("staging", "2")


def test_target_name_in_two_projects_is_refused(hetzner_two_projects):
    with pytest.raises(AmbiguousInstanceError) as err:
        resolve_provider_target(hetzner_two_projects, "hetzner", "web-1")
    assert "hetzner/web-1" in str(err.value) and "staging/web-1" in str(err.value)


def test_target_unknown_to_the_cache_goes_to_the_default_account(hetzner_two_projects):
    target = resolve_provider_target(hetzner_two_projects, "hetzner", "brand-new")
    assert (target.account.label, target.reference, target.row) == ("hetzner", "brand-new", None)


@pytest.mark.parametrize("reference,account", [
    ("web-1", "nope"),              # unknown account
    ("custom/web-1", ""),           # custom servers have no provider account
    ("hetzner/web-1", "staging"),   # qualifier and account disagree
])
def test_target_refusals(hetzner_two_projects, reference, account):
    with pytest.raises(UnknownAccountError):
        resolve_provider_target(hetzner_two_projects, "hetzner", reference, account)


def test_target_label_of_another_provider_is_refused(monkeypatch):
    registry, _ = build_registry(
        monkeypatch, aws={"aws": [], "prod": []}, hetzner={"hetzner": []},
    )
    with pytest.raises(UnknownAccountError, match="AWS account"):
        resolve_provider_target(registry, "hetzner", "prod/web-1")


def test_target_ovh_cloud_ids(monkeypatch):
    registry, _ = build_registry(
        monkeypatch,
        ovh={"ovh": [], "eu2": [{"id": "proj1/inst-1", "name": "api", "is_ovh": True}]},
    )
    exact = resolve_provider_target(registry, "ovh", "proj1/inst-1")
    assert (exact.account.label, exact.native_id) == ("eu2", "proj1/inst-1")
    qualified = resolve_provider_target(registry, "ovh", "eu2/proj1/inst-1")
    assert (qualified.account.label, qualified.native_id) == ("eu2", "proj1/inst-1")
    uncached = resolve_provider_target(registry, "ovh", "eu2/proj9/inst-9")
    assert (uncached.account.label, uncached.native_id) == ("eu2", "proj9/inst-9")


# ---------------------------------------------------------------------------
# fetch_provider_rows
# ---------------------------------------------------------------------------


def test_fetch_provider_rows_of_one_account(hetzner_two_projects):
    from servonaut.services.accounts.headless import fetch_provider_rows

    rows = _run(fetch_provider_rows(hetzner_two_projects, "hetzner", "Staging"))
    assert [(r["id"], r["account"], r.get("account_qualified")) for r in rows] == [
        ("2", "staging", True), ("4", "staging", True),
    ]
    every = _run(fetch_provider_rows(hetzner_two_projects, "hetzner"))
    assert [r["id"] for r in every] == ["1", "3", "2", "4"]
    with pytest.raises(UnknownAccountError):
        _run(fetch_provider_rows(hetzner_two_projects, "hetzner", "nope"))
    with pytest.raises(UnknownAccountError):
        _run(fetch_provider_rows(hetzner_two_projects, "ovh"))


def test_fetch_provider_rows_reads_only_the_named_account(monkeypatch):
    from servonaut.services.accounts.headless import fetch_provider_rows

    registry, services = build_registry(monkeypatch, hetzner={"hetzner": [], "staging": []})
    _run(fetch_provider_rows(registry, "hetzner", "staging", force_refresh=True))
    assert services[("hetzner", "staging")].fetches == 1
    assert services[("hetzner", "hetzner")].fetches == 0
