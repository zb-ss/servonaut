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


def test_a_provider_never_listed_is_read_before_a_name_counts_as_unique(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "web-1"}]},
        hetzner={"hetzner": [{"id": "2", "name": "web-1", "is_hetzner": True}]},
    )
    services[("hetzner", "hetzner")].cached = None  # never listed
    with pytest.raises(AmbiguousInstanceError):
        _run(_directory(registry).find("web-1"))
    assert services[("hetzner", "hetzner")].fetches == 1


def test_one_account_never_listed_makes_its_provider_read(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "web-1"}]},
        hetzner={"hetzner": [{"id": "1", "name": "db", "is_hetzner": True}],
                 "staging": [{"id": "2", "name": "web-1", "is_hetzner": True}]},
    )
    services[("hetzner", "staging")].cached = None
    with pytest.raises(AmbiguousInstanceError) as err:
        _run(_directory(registry).find("web-1"))
    assert "staging/web-1" in str(err.value)


def _failing(service, message="Hetzner API unreachable (401)"):
    """Make *service*'s listing raise, counting the attempts."""
    attempts = []

    async def refused(force_refresh=False):
        attempts.append(1)
        raise RuntimeError(message)

    service.fetch_instances_cached = refused
    return attempts


def test_a_failing_provider_never_breaks_another_providers_lookup(monkeypatch, caplog):
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "web-1"}]},
        hetzner={"hetzner": []},
    )
    services[("hetzner", "hetzner")].cached = None  # never listed
    attempts = _failing(services[("hetzner", "hetzner")])
    directory = _directory(registry)
    for _ in range(3):
        assert _run(directory.find("web-1"))["id"] == "i-1"
    assert len(attempts) == 1
    assert "Hetzner API unreachable (401)" in caplog.text


def test_a_failing_provider_before_a_match_falls_back_to_its_cache(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "api"}]},
        hetzner={"hetzner": [{"id": "2", "name": "db", "is_hetzner": True}],
                 "staging": [{"id": "3", "name": "cache", "is_hetzner": True}]},
    )
    _failing(services[("aws", "aws")], "expired token")
    directory = _directory(registry)
    assert _run(directory.find("db"))["id"] == "2"
    # A qualified reference reads only its provider, and falls back the same way.
    for service in (services[("hetzner", "hetzner")], services[("hetzner", "staging")]):
        _failing(service)
    assert _run(directory.find("staging/cache"))["id"] == "3"


def test_an_account_without_servers_is_read_once(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "web-1"}, {"id": "i-2", "name": "api"}]},
        hetzner={"hetzner": [{"id": "1", "name": "db", "is_hetzner": True}], "empty": []},
    )
    directory = _directory(registry)
    for reference in ("web-1", "api", "web-1"):
        _run(directory.find(reference))
    assert services[("hetzner", "empty")].fetches == 1
    assert services[("hetzner", "hetzner")].fetches == 0


def test_a_single_service_without_servers_is_read_once():
    aws = FakeProvider("aws", "aws", [{"id": "i-1", "name": "web-1"}])
    hetzner = FakeProvider("hetzner", "hetzner")
    directory = InstanceDirectory(_custom(), lambda: {"aws": aws, "hetzner": hetzner})
    for _ in range(3):
        assert _run(directory.find("web-1"))["id"] == "i-1"
    assert hetzner.fetches == 1


def test_concurrent_lookups_share_one_read_and_both_see_the_account(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "web-1"}]},
        hetzner={"hetzner": [{"id": "2", "name": "web-1", "is_hetzner": True}]},
    )
    services[("hetzner", "hetzner")].cached = None
    directory = _directory(registry)

    async def both():
        return await asyncio.gather(
            directory.find("web-1"), directory.find("web-1"), return_exceptions=True,
        )

    results = _run(both())
    assert all(isinstance(r, AmbiguousInstanceError) for r in results)
    assert services[("hetzner", "hetzner")].fetches == 1


def test_a_stale_cache_is_used_as_it_is(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "web-1"}]},
        hetzner={"hetzner": [{"id": "2", "name": "db", "is_hetzner": True}]},
    )
    services[("hetzner", "hetzner")].fresh = False
    assert _run(_directory(registry).find("web-1"))["id"] == "i-1"
    assert services[("hetzner", "hetzner")].fetches == 0


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
    target = _run(resolve_provider_target(hetzner_two_projects, "hetzner", "worker"))
    assert (target.account.label, target.reference, target.native_id) == ("staging", "worker", "4")


def test_target_by_id(hetzner_two_projects):
    target = _run(resolve_provider_target(hetzner_two_projects, "hetzner", "2"))
    assert target.account.label == "staging"


def test_target_qualified(hetzner_two_projects):
    target = _run(resolve_provider_target(hetzner_two_projects, "hetzner", "staging/web-1"))
    assert (target.account.label, target.reference) == ("staging", "web-1")


def test_target_with_explicit_account(hetzner_two_projects):
    target = _run(resolve_provider_target(hetzner_two_projects, "hetzner", "web-1", "STAGING"))
    assert (target.account.label, target.native_id) == ("staging", "2")


def test_target_name_in_two_projects_is_refused(hetzner_two_projects):
    with pytest.raises(AmbiguousInstanceError) as err:
        _run(resolve_provider_target(hetzner_two_projects, "hetzner", "web-1"))
    assert "hetzner/web-1" in str(err.value) and "staging/web-1" in str(err.value)


def test_target_no_project_lists_is_refused_with_several_projects(hetzner_two_projects):
    from servonaut.services.accounts.headless import TargetNotFoundError

    with pytest.raises(TargetNotFoundError) as err:
        _run(resolve_provider_target(hetzner_two_projects, "hetzner", "brand-new"))
    assert err.value.labels == ["hetzner", "staging"]
    assert "No Hetzner server 'brand-new' in any account (hetzner, staging)" in str(err.value)


def test_target_named_account_passes_an_unlisted_server_through(hetzner_two_projects):
    target = _run(resolve_provider_target(hetzner_two_projects, "hetzner", "brand-new", "staging"))
    assert (target.account.label, target.reference, target.row) == ("staging", "brand-new", None)


def test_single_project_keeps_the_cache_only_default(monkeypatch):
    registry, services = build_registry(
        monkeypatch, hetzner={"hetzner": [{"id": "1", "name": "web-1", "is_hetzner": True}]},
    )
    target = _run(resolve_provider_target(registry, "hetzner", "brand-new"))
    assert (target.account.label, target.reference, target.row) == ("hetzner", "brand-new", None)
    assert services[("hetzner", "hetzner")].fetches == 0


def test_target_in_a_project_whose_cache_is_gone(monkeypatch):
    """A power action drops a project's cache; its servers stay findable."""
    registry, services = build_registry(
        monkeypatch,
        hetzner={
            "hetzner": [{"id": "1", "name": "web-1", "is_hetzner": True}],
            "staging": [{"id": "2", "name": "web-1", "is_hetzner": True},
                        {"id": "4", "name": "worker", "is_hetzner": True}],
        },
    )
    services[("hetzner", "staging")].cached = None
    target = _run(resolve_provider_target(registry, "hetzner", "worker"))
    assert target.account.label == "staging"
    with pytest.raises(AmbiguousInstanceError):
        _run(resolve_provider_target(registry, "hetzner", "web-1"))


def test_target_falls_back_to_caches_when_every_refresh_fails(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        hetzner={"hetzner": [], "staging": [{"id": "4", "name": "worker", "is_hetzner": True}]},
    )

    async def refused(force_refresh=False):
        raise RuntimeError("token refused")

    for service in services.values():
        if service.provider == "hetzner":
            service.fetch_instances_cached = refused
    assert _run(resolve_provider_target(registry, "hetzner", "worker")).account.label == "staging"


@pytest.mark.parametrize("reference, account", [
    ("worker", "staging"),         # the account is named
    ("staging/worker", ""),        # the reference is qualified
])
def test_a_named_account_is_the_only_one_refreshed(hetzner_two_projects, monkeypatch,
                                                   reference, account):
    registry = hetzner_two_projects
    fetched = []
    for binding in registry.fleet("hetzner").bindings:
        original = binding.service.fetch_instances_cached

        async def counted(force_refresh=False, _label=binding.ref.label, _original=original):
            fetched.append(_label)
            return await _original(force_refresh=force_refresh)

        monkeypatch.setattr(binding.service, "fetch_instances_cached", counted)
    target = _run(resolve_provider_target(registry, "hetzner", reference, account))
    assert (target.account.label, target.native_id) == ("staging", "4")
    assert fetched == ["staging"]
    # A bare name still refreshes every account: which one lists it is the question.
    fetched.clear()
    _run(resolve_provider_target(registry, "hetzner", "worker"))
    assert sorted(fetched) == ["hetzner", "staging"]


def test_a_named_account_that_cannot_refresh_keeps_its_cache(hetzner_two_projects):
    registry = hetzner_two_projects
    _failing(registry.fleet("hetzner").binding("staging").service)
    target = _run(resolve_provider_target(registry, "hetzner", "staging/worker"))
    assert (target.account.label, target.native_id) == ("staging", "4")


@pytest.mark.parametrize("reference,account", [
    ("web-1", "nope"),              # unknown account
    ("custom/web-1", ""),           # custom servers have no provider account
    ("hetzner/web-1", "staging"),   # qualifier and account disagree
])
def test_target_refusals(hetzner_two_projects, reference, account):
    with pytest.raises(UnknownAccountError):
        _run(resolve_provider_target(hetzner_two_projects, "hetzner", reference, account))


def test_target_label_of_another_provider_is_refused(monkeypatch):
    registry, _ = build_registry(
        monkeypatch, aws={"aws": [], "prod": []}, hetzner={"hetzner": []},
    )
    with pytest.raises(UnknownAccountError, match="AWS account"):
        _run(resolve_provider_target(registry, "hetzner", "prod/web-1"))


def test_target_ovh_cloud_ids(monkeypatch):
    registry, _ = build_registry(
        monkeypatch,
        ovh={"ovh": [], "eu2": [{"id": "proj1/inst-1", "name": "api", "is_ovh": True}]},
    )
    exact = _run(resolve_provider_target(registry, "ovh", "proj1/inst-1"))
    assert (exact.account.label, exact.native_id) == ("eu2", "proj1/inst-1")
    qualified = _run(resolve_provider_target(registry, "ovh", "eu2/proj1/inst-1"))
    assert (qualified.account.label, qualified.native_id) == ("eu2", "proj1/inst-1")
    uncached = _run(resolve_provider_target(registry, "ovh", "eu2/proj9/inst-9"))
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
