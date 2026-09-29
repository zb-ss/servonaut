"""Every account of a provider as one inventory, and the registry behind it."""

from __future__ import annotations

import asyncio
from typing import List, Optional

import pytest

from servonaut.config.accounts import AccountRef
from servonaut.config.schema import AppConfig, AWSAccount, HetznerAccount, OVHAccount
from servonaut.services.accounts import (
    ACCOUNT_KEY,
    QUALIFIED_KEY,
    AccountBinding,
    AccountFleet,
    AccountRegistry,
    UnknownAccountError,
    row_provider,
)


class FakeService:
    """A single-account provider service with a cache and a canned refresh."""

    def __init__(
        self,
        rows: List[dict],
        *,
        cached: Optional[List[dict]] = None,
        error: Optional[str] = None,
        raises: Optional[Exception] = None,
        fresh: bool = True,
        partial: bool = False,
    ):
        self.rows = rows
        self.cached = cached if cached is not None else rows
        self.error = error
        self.raises = raises
        self.fresh = fresh
        self.partial = partial
        self.last_fetch_error: Optional[str] = None
        self.last_fetch_partial = False
        self.calls: List[bool] = []

    async def fetch_instances_cached(self, force_refresh: bool = False) -> List[dict]:
        self.calls.append(force_refresh)
        if self.raises is not None:
            self.last_fetch_error = str(self.raises)
            raise self.raises
        self.last_fetch_error = self.error
        self.last_fetch_partial = self.partial
        return [dict(r) for r in (self.cached if self.error else self.rows)]

    def get_cached_instances(self) -> List[dict]:
        return [dict(r) for r in self.cached]

    def is_cache_fresh(self) -> bool:
        return self.fresh


def _ref(label: str, primary: bool = False) -> AccountRef:
    return AccountRef("hetzner", label, primary)


def _fleet(*services: FakeService, labels=("hetzner", "staging", "dev")) -> AccountFleet:
    bindings = [
        AccountBinding(_ref(label, i == 0), service)
        for i, (label, service) in enumerate(zip(labels, services))
    ]
    return AccountFleet("hetzner", bindings)


def _run(coro):
    return asyncio.run(coro)


class TestAccountFleet:
    def test_single_account_rows_are_tagged_but_not_qualified(self):
        fleet = _fleet(FakeService([{"id": "1", "name": "web-1"}]))
        rows = _run(fleet.fetch_instances_cached(force_refresh=True))
        assert rows == [{"id": "1", "name": "web-1", ACCOUNT_KEY: "hetzner"}]
        assert not fleet.multi

    def test_several_accounts_merge_in_config_order_and_are_qualified(self):
        fleet = _fleet(
            FakeService([{"id": "1", "name": "web-1"}]),
            FakeService([{"id": "2", "name": "web-1"}]),
        )
        rows = _run(fleet.fetch_instances_cached(force_refresh=True))
        assert [(r["id"], r[ACCOUNT_KEY], r.get(QUALIFIED_KEY)) for r in rows] == [
            ("1", "hetzner", True), ("2", "staging", True),
        ]
        assert fleet.last_fetch_error is None and fleet.last_fetch_partial is False

    def test_rows_are_copies_so_caches_stay_untagged(self):
        service = FakeService([{"id": "1", "name": "a"}])
        _fleet(service).get_cached_instances()
        assert ACCOUNT_KEY not in service.cached[0]

    def test_a_failing_account_never_hides_the_others(self):
        fleet = _fleet(
            FakeService([{"id": "1", "name": "a"}]),
            FakeService([], raises=RuntimeError("token refused")),
        )
        rows = _run(fleet.fetch_instances_cached(force_refresh=True))
        assert [r["id"] for r in rows] == ["1"]
        assert fleet.last_fetch_error == "staging: token refused"
        assert fleet.last_fetch_partial is True

    def test_an_account_serving_its_cache_is_reported_under_its_label(self):
        fleet = _fleet(
            FakeService([{"id": "1", "name": "a"}]),
            FakeService([{"id": "2"}], cached=[{"id": "2", "name": "old"}], error="timeout"),
        )
        rows = _run(fleet.fetch_instances_cached(force_refresh=True))
        assert [r.get("name") for r in rows] == ["a", "old"]
        assert fleet.last_fetch_error == "staging: timeout"
        assert fleet.last_fetch_partial is True

    def test_only_every_account_failing_raises(self):
        fleet = _fleet(
            FakeService([], raises=RuntimeError("one")),
            FakeService([], raises=RuntimeError("two")),
        )
        with pytest.raises(RuntimeError, match="one"):
            _run(fleet.fetch_instances_cached(force_refresh=True))
        assert fleet.last_fetch_error == "hetzner: one; staging: two"

    def test_a_single_failing_account_raises_like_before(self):
        fleet = _fleet(FakeService([], raises=RuntimeError("refused")))
        with pytest.raises(RuntimeError):
            _run(fleet.fetch_instances_cached(force_refresh=True))
        assert fleet.last_fetch_error == "refused"

    def test_the_same_account_configured_twice_is_listed_once(self):
        fleet = _fleet(
            FakeService([{"id": "1", "name": "a"}]),
            FakeService([{"id": "1", "name": "a"}, {"id": "3", "name": "c"}]),
        )
        rows = _run(fleet.fetch_instances_cached(force_refresh=True))
        assert [(r["id"], r[ACCOUNT_KEY]) for r in rows] == [("1", "hetzner"), ("3", "staging")]
        assert fleet.duplicate_accounts == {"staging": "hetzner"}

    def test_fresh_only_when_every_account_is(self):
        assert _fleet(FakeService([]), FakeService([])).is_cache_fresh()
        assert not _fleet(FakeService([]), FakeService([], fresh=False)).is_cache_fresh()

    def test_accounts_refresh_concurrently(self):
        started = []

        class Slow(FakeService):
            async def fetch_instances_cached(self, force_refresh=False):
                started.append(self)
                await asyncio.sleep(0.05)
                assert len(started) == 2, "the second account waited for the first"
                return []

        _run(_fleet(Slow([]), Slow([])).fetch_instances_cached(force_refresh=True))

    def test_binding_lookup_is_case_insensitive(self):
        fleet = _fleet(FakeService([]), FakeService([]))
        assert fleet.binding("STAGING").ref.label == "staging"
        assert fleet.binding(None).ref.label == "hetzner"
        assert fleet.binding("nope") is None


class TestRegistry:
    def test_a_default_config_has_only_the_primary_aws_account(self):
        registry = AccountRegistry(AppConfig())
        assert [r.label for r in registry.accounts("aws")] == ["aws"]
        assert registry.accounts("hetzner") == [] and registry.accounts("ovh") == []
        assert registry.fleet("hetzner") is None
        assert not registry.has_multiple_accounts()

    def test_extra_accounts_get_their_own_services(self, monkeypatch):
        monkeypatch.setenv("SERVONAUT_TEST_HCLOUD_A", "a")
        monkeypatch.setenv("SERVONAUT_TEST_HCLOUD_B", "b")
        config = AppConfig()
        config.hetzner.enabled = True
        config.hetzner.api_token = "$SERVONAUT_TEST_HCLOUD_A"
        config.hetzner.accounts = [
            HetznerAccount(label="staging", api_token="$SERVONAUT_TEST_HCLOUD_B")
        ]
        registry = AccountRegistry(config)
        primary = registry.service("hetzner")
        staging = registry.service("hetzner", "Staging")
        assert primary is not staging
        assert primary.resolve_token() == "a" and staging.resolve_token() == "b"
        assert registry.is_multi("hetzner") and registry.has_multiple_accounts()

    def test_an_extra_hetzner_project_never_borrows_the_ambient_token(self, monkeypatch):
        monkeypatch.setenv("HCLOUD_TOKEN", "ambient")
        config = AppConfig()
        config.hetzner.enabled = True
        config.hetzner.accounts = [HetznerAccount(label="staging", api_token="$UNSET_FOR_TEST")]
        registry = AccountRegistry(config)
        assert [r.label for r in registry.accounts("hetzner")] == ["hetzner"]
        assert "hetzner:staging" in registry.unavailable

    def test_service_for_routes_a_row_to_its_account(self, monkeypatch):
        monkeypatch.setenv("SERVONAUT_TEST_HCLOUD_A", "a")
        config = AppConfig()
        config.hetzner.enabled = True
        config.hetzner.api_token = "$SERVONAUT_TEST_HCLOUD_A"
        config.hetzner.accounts = [HetznerAccount(label="staging", api_token="b")]
        registry = AccountRegistry(config)
        row = {"id": "7", "is_hetzner": True, ACCOUNT_KEY: "staging"}
        assert registry.service_for(row) is registry.service("hetzner", "staging")
        # Rows from before accounts existed belong to the default account.
        assert registry.service_for({"id": "7", "is_hetzner": True}) is registry.service("hetzner")
        with pytest.raises(UnknownAccountError, match="staging"):
            registry.service_for({"id": "7", "is_hetzner": True, ACCOUNT_KEY: "gone"})
        with pytest.raises(ValueError):
            registry.service_for({"id": "c", "is_custom": True})

    def test_ovh_accounts_get_their_own_cache_and_sub_services(self, tmp_path, monkeypatch):
        import servonaut.services.ovh_service as ovh_module

        monkeypatch.setattr(ovh_module, "_OVH_CACHE_PATH", tmp_path / "ovh_cache.json")
        config = AppConfig()
        config.ovh.enabled = True
        config.ovh.application_key = "k"
        config.ovh.accounts = [OVHAccount(label="ca", client_id="c", client_secret="s")]
        registry = AccountRegistry(config)
        primary = registry.service("ovh")
        extra = registry.service("ovh", "ca")
        assert primary._cache_path == tmp_path / "ovh_cache.json"
        assert extra._cache_path == tmp_path / "ovh_cache.ca.json"
        bundle = registry.ovh_services("ca")
        assert bundle.ovh is extra and bundle.cloud is not registry.ovh_services().cloud

    def test_aws_accounts_have_their_own_cache_and_credentials(self, tmp_path, monkeypatch):
        from servonaut.services.cache_service import CacheService

        monkeypatch.setattr(CacheService, "CACHE_PATH", tmp_path / "cache.json")
        config = AppConfig()
        config.aws.accounts = [AWSAccount(label="prod", profile="prod", regions=["eu-west-1"])]
        registry = AccountRegistry(config)
        primary = registry.service("aws")
        prod = registry.service("aws", "prod")
        assert primary.cache_service.CACHE_PATH == tmp_path / "cache.json"
        assert prod.cache_service.CACHE_PATH == tmp_path / "cache.prod.json"
        assert registry.aws_context().uses_ambient_credentials
        assert registry.aws_context("prod").profile == "prod"
        assert registry.aws_context("prod").regions == ("eu-west-1",)

    def test_find_account_searches_every_provider(self):
        config = AppConfig()
        config.aws.accounts = [AWSAccount(label="prod", profile="p")]
        registry = AccountRegistry(config)
        assert registry.find_account("PROD").provider == "aws"
        assert registry.find_account("nope") is None

    def test_rebuild_follows_the_new_config(self):
        registry = AccountRegistry(AppConfig())
        config = AppConfig()
        config.aws.accounts = [AWSAccount(label="prod", profile="p")]
        registry.rebuild(config)
        assert [r.label for r in registry.accounts("aws")] == ["aws", "prod"]

    @pytest.mark.parametrize(
        "row, provider",
        [
            ({"is_custom": True}, "custom"),
            ({"is_ovh": True}, "ovh"),
            ({"is_hetzner": True}, "hetzner"),
            ({}, "aws"),
        ],
    )
    def test_row_provider(self, row, provider):
        assert row_provider(row) == provider


class TestControlPlaneRoles:
    def _registry(self):
        config = AppConfig()
        config.aws.control_plane_role_arn = "arn:aws:iam::111111111111:role/read"
        config.aws.control_plane_mutate_role_arn = "arn:aws:iam::111111111111:role/write"
        config.aws.control_plane_role_arns = {"222222222222": "arn:aws:iam::222222222222:role/read"}
        config.aws.accounts = [AWSAccount(label="prod", profile="prod")]
        return AccountRegistry(config)

    def test_the_primary_account_keeps_the_default_roles(self):
        factory = self._registry().aws_client_factory()
        assert factory.role_for() == "arn:aws:iam::111111111111:role/read"
        assert factory.role_for(mutate=True) == "arn:aws:iam::111111111111:role/write"

    def test_an_extra_account_never_borrows_the_default_roles(self):
        # Assumed with the extra account's credentials, the primary account's
        # role would act in the wrong account.
        factory = self._registry().aws_client_factory("prod")
        assert factory.role_for() == ""
        assert factory.role_for(mutate=True) == ""

    def test_an_extra_account_uses_a_role_mapped_to_its_id(self):
        factory = self._registry().aws_client_factory("prod")
        assert factory.role_for("222222222222") == "arn:aws:iam::222222222222:role/read"
