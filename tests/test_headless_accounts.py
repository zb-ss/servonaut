"""Shared account lookups of the surfaces without an instance list."""
from __future__ import annotations

import asyncio
import time
from datetime import datetime
from unittest.mock import MagicMock

import pytest

from servonaut.services.accounts import UnknownAccountError
from servonaut.services.accounts.headless import (
    AccountUnavailableError,
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
# CachedFleet.checked_rows (CLI name lookups)
# ---------------------------------------------------------------------------


@pytest.fixture
def staging_never_listed(monkeypatch):
    """Hetzner project staging holds web-1 too, but was never listed here."""
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "web-1"}]},
        hetzner={"hetzner": [{"id": "1", "name": "db", "is_hetzner": True}],
                 "staging": [{"id": "2", "name": "web-1", "is_hetzner": True}]},
    )
    services[("hetzner", "staging")].cached = None
    return registry, services


def test_a_never_listed_account_is_read_once_and_cached(staging_never_listed):
    registry, services = staging_never_listed
    staging = services[("hetzner", "staging")]
    fleet = CachedFleet.from_registry(registry, _custom())

    checked = _run(fleet.checked_rows("web-1"))

    assert checked.notes == []
    with pytest.raises(AmbiguousInstanceError) as err:
        fleet.resolve("web-1", rows=checked.rows)
    assert "aws/web-1" in str(err.value) and "staging/web-1" in str(err.value)
    assert staging.fetches == 1 and staging.cached is not None
    # Its cache is written, so the next command stays offline.
    _run(CachedFleet.from_registry(registry, _custom()).checked_rows("web-1"))
    assert staging.fetches == 1
    assert all(s.fetches == 0 for key, s in services.items() if key != ("hetzner", "staging"))


def test_rows_read_take_their_place_in_the_instance_list(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        hetzner={"hetzner": [{"id": "1", "name": "web-1", "is_hetzner": True}],
                 "staging": [{"id": "2", "name": "web-1", "is_hetzner": True}]},
        ovh={"ovh": [{"id": "vps-1", "name": "web-1", "is_ovh": True}],
             "backup": [{"id": "vps-2", "name": "web-1", "is_ovh": True}]},
    )
    services[("hetzner", "staging")].cached = None
    services[("ovh", "backup")].cached = None
    fleet = CachedFleet.from_registry(registry, _custom(CUSTOM_WEB))

    first = [row["id"] for row in _run(fleet.checked_rows("web-1")).rows]
    again = [row["id"] for row in _run(fleet.checked_rows("web-1")).rows]

    assert first == again == ["custom-web", "vps-1", "vps-2", "1", "2"]


def test_rows_a_read_did_not_keep_come_last(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        hetzner={"hetzner": [{"id": "1", "name": "web-1", "is_hetzner": True}],
                 "staging": [{"id": "2", "name": "web-1", "is_hetzner": True}]},
    )
    staging = services[("hetzner", "staging")]
    staging.cached = None

    async def incomplete(force_refresh=False):
        staging.last_fetch_error = "listing incomplete"
        return [dict(row) for row in staging.rows]

    staging.fetch_instances_cached = incomplete
    checked = _run(CachedFleet.from_registry(registry, _custom()).checked_rows("web-1"))

    assert [row["id"] for row in checked.rows] == ["1", "2"]
    assert len(checked.notes) == 1


def test_a_single_never_listed_account_is_read_too(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "web-1"}]},
        ovh={"ovh": [{"id": "vps-1", "name": "web-1", "is_ovh": True}]},
    )
    services[("ovh", "ovh")].cached = None
    fleet = CachedFleet.from_registry(registry, _custom())

    rows = _run(fleet.checked_rows("web-1")).rows

    assert [row["id"] for row in fleet.matches("web-1", rows)] == ["i-1", "vps-1"]
    assert services[("ovh", "ovh")].fetches == 1


def test_an_empty_cache_counts_as_listed(staging_never_listed):
    registry, services = staging_never_listed
    services[("hetzner", "staging")].cached = []
    _run(CachedFleet.from_registry(registry, _custom()).checked_rows("web-1"))
    assert services[("hetzner", "staging")].fetches == 0


def test_an_account_that_cannot_be_listed_gets_a_note(staging_never_listed):
    registry, services = staging_never_listed
    attempts = _failing(services[("hetzner", "staging")], "401 Unauthorized\nsecond line")
    fleet = CachedFleet.from_registry(registry, _custom())

    checked = _run(fleet.checked_rows("web-1"))

    assert checked.notes == [
        "Note: Hetzner project 'staging' could not be listed (401 Unauthorized); "
        "its servers were not checked for 'web-1'"
    ]
    assert fleet.resolve("web-1", rows=checked.rows)["id"] == "i-1"
    assert len(attempts) == 1


def _partly_listing(service, message="1 region(s) failed: eu-west-1", keeps_cache=False):
    """Make *service* list what it can and say why that is incomplete.

    AWS keeps such a listing out of its cache; OVH saves it (*keeps_cache*).
    """
    calls = []

    async def partial(force_refresh=False):
        calls.append(1)
        service.last_fetch_error = message
        rows = [dict(row) for row in service.rows]
        if keeps_cache:
            service.cached = rows
        return rows

    service.fetch_instances_cached = partial
    return calls


@pytest.fixture
def prod_partly_listed(monkeypatch):
    """AWS account prod was never listed; listing it skips a failing region."""
    registry, services = build_registry(
        monkeypatch, aws={"aws": [], "prod": [{"id": "i-2", "name": "web-1"}]},
    )
    prod = services[("aws", "prod")]
    prod.cached = None
    return registry, prod, _partly_listing(prod)


def test_a_partial_listing_is_noted_as_such(prod_partly_listed):
    registry, _, _ = prod_partly_listed

    checked = _run(CachedFleet.from_registry(registry, _custom()).checked_rows("web-1"))

    assert checked.notes == [
        "Note: AWS account 'prod' was only partly listed (1 region(s) failed: eu-west-1); "
        "some of its servers were not checked for 'web-1'"
    ]
    assert [row["id"] for row in checked.rows] == ["i-2"]


def test_a_reason_over_several_lines_keeps_the_note_on_one_line(monkeypatch):
    registry, services = build_registry(monkeypatch, aws={"aws": [], "prod": []})
    prod = services[("aws", "prod")]
    prod.cached = None
    _partly_listing(prod, "all 2 AWS regions failed: helper said:\nline two\nline three")
    prod.rows = []

    checked = _run(CachedFleet.from_registry(registry, _custom()).checked_rows("web-1"))

    assert checked.notes == [
        "Note: AWS account 'prod' could not be listed (all 2 AWS regions failed: helper "
        "said:); its servers were not checked for 'web-1'"
    ]


def test_a_partial_listing_counts_as_checked_until_the_ttl_ends(prod_partly_listed,
                                                                 monkeypatch):
    from servonaut.services.accounts import listing_record

    registry, prod, calls = prod_partly_listed
    _run(CachedFleet.from_registry(registry, _custom()).checked_rows("web-1"))
    assert prod.record.load().outcome == listing_record.PARTIAL

    again = _run(CachedFleet.from_registry(registry, _custom()).checked_rows("web-1"))

    assert len(calls) == 1
    assert again.notes == [] and [row["id"] for row in again.rows] == ["i-2"]
    # Once the TTL is over the account is listed again.
    later = prod.record.load().until + 1
    monkeypatch.setattr(listing_record.time, "time", lambda: later)
    _run(CachedFleet.from_registry(registry, _custom()).checked_rows("web-1"))
    assert len(calls) == 2


def test_a_partial_listing_the_provider_saved_is_its_cache(monkeypatch):
    registry, services = build_registry(
        monkeypatch, ovh={"ovh": [{"id": "vps-1", "name": "web-1", "is_ovh": True}]},
    )
    ovh = services[("ovh", "ovh")]
    ovh.cached = None
    calls = _partly_listing(ovh, "the dedicated servers could not be read", keeps_cache=True)

    first = _run(CachedFleet.from_registry(registry, _custom()).checked_rows("web-1"))
    again = _run(CachedFleet.from_registry(registry, _custom()).checked_rows("web-1"))

    assert first.notes == [
        "Note: OVH account 'ovh' was only partly listed (the dedicated servers could not "
        "be read); some of its servers were not checked for 'web-1'"
    ]
    assert again.notes == [] and len(calls) == 1
    assert ovh.record.load() is None


def test_a_failed_listing_is_not_retried_until_the_ttl_ends(staging_never_listed, monkeypatch):
    from servonaut.services.accounts import listing_record

    registry, services = staging_never_listed
    staging = services[("hetzner", "staging")]
    attempts = _failing(staging, "401 Unauthorized")
    monkeypatch.setattr(listing_record.time, "time", lambda: 1_000_000.0)

    _run(CachedFleet.from_registry(registry, _custom()).checked_rows("web-1"))
    again = _run(CachedFleet.from_registry(registry, _custom()).checked_rows("web-1"))

    assert len(attempts) == 1
    remembered = staging.record.load()
    assert remembered.outcome == listing_record.FAILED
    at, until = (datetime.fromtimestamp(t).strftime("%H:%M")
                 for t in (remembered.at, remembered.until))
    assert again.notes == [
        f"Note: Hetzner project 'staging' could not be listed (401 Unauthorized; at {at}, "
        f"tried again after {until}); its servers were not checked for 'web-1'"
    ]
    monkeypatch.setattr(listing_record.time, "time", lambda: remembered.until + 1)
    _run(CachedFleet.from_registry(registry, _custom()).checked_rows("web-1"))
    assert len(attempts) == 2


def _stalling(service):
    """Make *service*'s listing never answer (a blackholed network)."""
    started = []

    async def stalled(force_refresh=False):
        started.append(1)
        await asyncio.sleep(3600)

    service.fetch_instances_cached = stalled
    return started


def _slow_requests(service, count=5, seconds=1.0):
    """Make *service*'s listing *count* blocking requests of *seconds* each.

    Like an SDK's paging or AWS's region loop, all of them run in one call
    in the loop's default executor: a thread that cancelling cannot stop.
    """
    made = []

    def requests():
        for _ in range(count):
            time.sleep(seconds)
            made.append(1)

    async def listing(force_refresh=False):
        await asyncio.to_thread(requests)
        return [dict(row) for row in service.rows]

    service.fetch_instances_cached = listing
    return made


def test_an_abandoned_listing_does_not_hold_the_command_up(staging_never_listed):
    """The whole asyncio.run returns with the budget, not when the requests end."""
    registry, services = staging_never_listed
    made = _slow_requests(services[("hetzner", "staging")])
    registry.config.account_check_timeout_seconds = 1.5

    begin = time.monotonic()
    checked = asyncio.run(CachedFleet.from_registry(registry, _custom()).checked_rows("web-1"))
    elapsed = time.monotonic() - begin

    assert elapsed < 1.5 + 0.7, elapsed
    assert len(made) < 5
    assert "timed out after 1.5 s" in checked.notes[0]


def test_never_listed_accounts_are_read_within_the_time_allowed(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "db"}]},
        hetzner={"hetzner": [{"id": "1", "name": "web-1", "is_hetzner": True}],
                 "staging": [{"id": "2", "name": "web-1", "is_hetzner": True}]},
    )
    staging, primary = services[("hetzner", "staging")], services[("hetzner", "hetzner")]
    staging.cached = primary.cached = None
    started = _stalling(staging)
    registry.config.account_check_timeout_seconds = 0.2
    fleet = CachedFleet.from_registry(registry, _custom())

    begin = time.monotonic()
    checked = _run(fleet.checked_rows("web-1"))

    assert time.monotonic() - begin < 2
    assert checked.notes == [
        "Note: Hetzner project 'staging' could not be listed (timed out after 0.2 s); "
        "its servers were not checked for 'web-1'"
    ]
    # The project that answered is in; both had half the time to start
    # requests and half for the last one to answer.
    assert fleet.resolve("web-1", rows=checked.rows)["id"] == "1"
    assert staging.listing_time_limit == primary.listing_time_limit == (0.1, 0.1)
    # The timeout is remembered: the next command does not wait for it again.
    begin = time.monotonic()
    again = _run(CachedFleet.from_registry(registry, _custom()).checked_rows("web-1"))
    assert time.monotonic() - begin < 0.2 and len(started) == 1
    assert "timed out after 0.2 s; at " in again.notes[0]


def test_no_time_at_all_reads_nothing_and_says_so(staging_never_listed):
    registry, services = staging_never_listed
    registry.config.account_check_timeout_seconds = 0

    checked = _run(CachedFleet.from_registry(registry, _custom()).checked_rows("web-1"))

    assert services[("hetzner", "staging")].fetches == 0
    assert checked.notes == [
        "Note: Hetzner project 'staging' was not listed (no time allowed); "
        "its servers were not checked for 'web-1'"
    ]


def test_an_aws_account_without_credentials_is_not_read(monkeypatch):
    registry, services = build_registry(monkeypatch)
    aws = services[("aws", "aws")]
    aws.cached = None
    aws.credentials = False
    fleet = CachedFleet.from_registry(registry, _custom(CUSTOM_WEB))

    checked = _run(fleet.checked_rows("web-1"))

    assert checked.notes == [] and aws.fetches == 0
    assert fleet.resolve("web-1", rows=checked.rows)["id"] == "custom-web"


@pytest.mark.parametrize("reference", ["aws/web-1", "i-0123456789abcdef0"])
def test_a_reference_to_an_aws_account_without_credentials_says_so(monkeypatch, reference):
    registry, services = build_registry(monkeypatch)
    aws = services[("aws", "aws")]
    aws.cached = None
    aws.credentials = False

    checked = _run(CachedFleet.from_registry(registry, _custom()).checked_rows(reference))

    assert checked.notes == [
        "Note: AWS account 'aws' has no credentials on this machine; "
        f"its servers were not checked for {reference!r}"
    ]
    assert aws.fetches == 0


@pytest.mark.parametrize("reference", ["i-1", "I-1", "custom/web-1", "  "])
def test_an_id_or_custom_reference_reads_nothing(staging_never_listed, reference):
    registry, services = staging_never_listed
    fleet = CachedFleet.from_registry(registry, _custom(CUSTOM_WEB))

    checked = _run(fleet.checked_rows(reference))

    assert checked.notes == []
    assert all(service.fetches == 0 for service in services.values())


def test_a_qualified_reference_reads_only_its_account(staging_never_listed):
    registry, services = staging_never_listed
    services[("aws", "aws")].cached = None
    fleet = CachedFleet.from_registry(registry, _custom())

    hetzner = _run(fleet.checked_rows("hetzner/db"))
    assert fleet.resolve("hetzner/db", rows=hetzner.rows)["id"] == "1"
    assert all(service.fetches == 0 for service in services.values())

    staging = _run(fleet.checked_rows("staging/web-1"))
    assert fleet.resolve("staging/web-1", rows=staging.rows)["id"] == "2"
    assert services[("hetzner", "staging")].fetches == 1
    assert services[("aws", "aws")].fetches == 0


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


def test_a_single_account_provider_is_looked_up_in_its_cache_only(monkeypatch):
    """One account keeps the lookup it always had: no API call after a match."""
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "web-1"}]},
        hetzner={"hetzner": [{"id": "2", "name": "web-1", "is_hetzner": True}]},
    )
    services[("hetzner", "hetzner")].cached = None  # never listed
    assert _run(_directory(registry).find("web-1"))["id"] == "i-1"
    assert services[("hetzner", "hetzner")].fetches == 0


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


@pytest.fixture
def staging_unreachable(monkeypatch):
    """AWS lists web-1; Hetzner project staging was never listed and fails."""
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "web-1"}]},
        hetzner={"hetzner": [{"id": "1", "name": "db", "is_hetzner": True}], "staging": []},
    )
    services[("hetzner", "staging")].cached = None
    attempts = _failing(services[("hetzner", "staging")])
    return registry, attempts


def test_a_failing_provider_never_breaks_another_providers_lookup(staging_unreachable,
                                                                   caplog):
    registry, attempts = staging_unreachable
    directory = _directory(registry)
    for _ in range(3):
        assert _run(directory.find("web-1"))["id"] == "i-1"
    assert len(attempts) == 1
    assert caplog.text.count("Hetzner API unreachable (401)") == 1


def test_a_failed_read_is_retried_after_a_while(staging_unreachable):
    registry, attempts = staging_unreachable
    directory = _directory(registry)
    _run(directory.find("web-1"))
    for read in directory._account_reads.values():
        read.retry_at = 0.0  # the retry window has passed
    _run(directory.find("web-1"))
    assert len(attempts) == 2


def test_the_retry_window_is_the_configured_one(staging_unreachable, monkeypatch):
    registry, attempts = staging_unreachable
    registry.config.account_retry_seconds = 120
    clock = [1000.0]
    monkeypatch.setattr("servonaut.services.accounts.headless.time.monotonic", lambda: clock[0])
    directory = _directory(registry)
    _run(directory.find("web-1"))
    clock[0] += 119
    _run(directory.find("web-1"))
    assert len(attempts) == 1
    clock[0] += 2
    _run(directory.find("web-1"))
    assert len(attempts) == 2


def test_a_zero_retry_window_asks_again_on_the_next_lookup(staging_unreachable):
    registry, attempts = staging_unreachable
    registry.config.account_retry_seconds = 0
    directory = _directory(registry)
    _run(directory.find("web-1"))
    _run(directory.find("web-1"))
    assert len(attempts) == 2


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


@pytest.fixture
def empty_project(monkeypatch):
    return build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "web-1"}, {"id": "i-2", "name": "api"}]},
        hetzner={"hetzner": [{"id": "1", "name": "db", "is_hetzner": True}], "empty": []},
    )


def test_an_account_without_servers_is_read_once_while_its_cache_is_fresh(empty_project):
    registry, services = empty_project
    directory = _directory(registry)
    for reference in ("web-1", "api", "web-1"):
        _run(directory.find(reference))
    assert services[("hetzner", "empty")].fetches == 1
    assert services[("hetzner", "hetzner")].fetches == 0
    services[("hetzner", "empty")].fresh = False  # its cache TTL passed
    _run(directory.find("web-1"))
    assert services[("hetzner", "empty")].fetches == 2


def test_rebuilt_accounts_are_read_again(empty_project):
    registry, services = empty_project
    directory = _directory(registry)
    _run(directory.find("web-1"))
    first = services[("hetzner", "empty")]
    registry.rebuild(registry.config)
    _run(directory.find("web-1"))
    assert services[("hetzner", "empty")] is not first
    assert services[("hetzner", "empty")].fetches == 1
    assert all(read.inventory is registry.fleet("hetzner")
               for read in directory._account_reads.values())


def test_a_single_service_is_looked_up_in_its_cache_only():
    aws = FakeProvider("aws", "aws", [{"id": "i-1", "name": "web-1"}])
    hetzner = FakeProvider("hetzner", "hetzner")
    directory = InstanceDirectory(_custom(), lambda: {"aws": aws, "hetzner": hetzner})
    for _ in range(3):
        assert _run(directory.find("web-1"))["id"] == "i-1"
    assert hetzner.fetches == 0


def test_concurrent_lookups_share_one_read_and_both_see_the_account(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "web-1"}]},
        hetzner={"hetzner": [{"id": "1", "name": "db", "is_hetzner": True}],
                 "staging": [{"id": "2", "name": "web-1", "is_hetzner": True}]},
    )
    services[("hetzner", "staging")].cached = None
    directory = _directory(registry)

    async def both():
        return await asyncio.gather(
            directory.find("web-1"), directory.find("web-1"), return_exceptions=True,
        )

    results = _run(both())
    assert all(isinstance(r, AmbiguousInstanceError) for r in results)
    assert services[("hetzner", "staging")].fetches == 1


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


# ---------------------------------------------------------------------------
# A qualifier naming an account that cannot connect
# ---------------------------------------------------------------------------

STAGING_DOWN = (
    "Hetzner account 'staging' is not available: No Hetzner Cloud API token configured"
)


@pytest.fixture
def staging_down(monkeypatch):
    return build_registry(
        monkeypatch,
        hetzner={"hetzner": [{"id": "1", "name": "web-1", "is_hetzner": True}],
                 "staging": [{"id": "2", "name": "web-1", "is_hetzner": True}]},
        unusable={"staging"},
    )[0]


def test_a_lookup_qualified_with_an_account_that_cannot_connect_says_why(staging_down):
    # A custom server literally named like the reference is not picked instead.
    directory = _directory(staging_down, [{"id": "custom-x", "name": "staging/web-1",
                                            "is_custom": True}])
    with pytest.raises(AccountUnavailableError) as err:
        _run(directory.find("staging/web-1"))
    assert str(err.value) == STAGING_DOWN
    assert (err.value.provider, err.value.label) == ("hetzner", "staging")
    assert qualifier_provider(staging_down, "staging/web-1") == "hetzner"
    # A bare name still resolves among the accounts that connect.
    assert _run(directory.find("web-1"))["id"] == "1"


def test_a_target_qualified_with_an_account_that_cannot_connect_says_why(staging_down):
    with pytest.raises(AccountUnavailableError, match="not available: No Hetzner"):
        _run(resolve_provider_target(staging_down, "hetzner", "staging/web-1"))
    with pytest.raises(UnknownAccountError, match="not available"):
        _run(resolve_provider_target(staging_down, "hetzner", "web-1", "staging"))


def test_cached_fleet_qualified_with_an_account_that_cannot_connect_says_why(staging_down):
    fleet = CachedFleet.from_registry(staging_down, _custom())
    for lookup in (fleet.resolve, fleet.matches):
        with pytest.raises(AccountUnavailableError) as err:
            lookup("staging/web-1")
        assert str(err.value) == STAGING_DOWN
    assert fleet.resolve("hetzner/web-1")["id"] == "1"


def test_a_name_lookup_notes_accounts_that_cannot_connect(staging_down):
    fleet = CachedFleet.from_registry(staging_down, _custom())

    checked = _run(fleet.checked_rows("web-1"))

    assert checked.notes == [
        "Note: Hetzner project 'staging' is not available (No Hetzner Cloud API token "
        "configured); its servers were not checked for 'web-1'"
    ]
    assert fleet.resolve("web-1", rows=checked.rows)["id"] == "1"
    # A reference qualified with another account says nothing about it.
    assert _run(fleet.checked_rows("hetzner/web-1")).notes == []
