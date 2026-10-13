"""Matching vault SSH keys to servers by name, and binding them in one go."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from servonaut.services.vault.auto_bind import (
    ALREADY_BOUND,
    AMBIGUOUS,
    CHECK_FAILED,
    MATCHED_BY_KEY_FILE,
    MATCHED_BY_KEY_PAIR,
    MATCHED_BY_SERVER_NAME,
    NO_ADDRESS,
    NO_HOST_KEYS,
    NO_KEY,
    NO_LOGIN,
    READY,
    apply_auto_bind,
    match_ssh_key,
    normalize_key_name,
    plan_auto_bind,
)
from servonaut.services.vault.errors import VaultUserError
from servonaut.services.vault.personal_targets import instance_provider, instance_target

HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureHostKeyFixtureHostKeyFixtureHostK"


def _key(item_id: str, name, fingerprint: str | None = None) -> dict:
    return {"item_id": item_id, "name": name, "fingerprint": fingerprint or f"SHA256:{item_id}"}


@pytest.mark.parametrize("name, expected", [
    ("web-1.pem", "web-1"),
    ("  Web-1  ", "web-1"),
    ("~/.ssh/deploy_ed25519", "deploy_ed25519"),
    ("C:\\keys\\Prod.KEY", "prod"),
    (".pem", ".pem"),
])
def test_names_compare_without_case_directory_or_key_file_extension(name, expected) -> None:
    assert normalize_key_name(name) == expected


def test_the_key_pair_name_wins_over_the_server_name() -> None:
    # The instance was launched with another server's key pair: that key logs in.
    instance = {"id": "i-3", "name": "app-3", "key_name": "app-4"}
    keys = [_key("a", "app-3.pem"), _key("b", "app-4.pem")]

    match = match_ssh_key(instance, keys)

    assert (match.item_id, match.matched_by) == ("b", MATCHED_BY_KEY_PAIR)


def test_the_server_name_is_used_when_no_key_is_named_like_the_key_pair() -> None:
    instance = {"id": "i-1", "name": "Web-1", "key_name": "launch-key"}

    match = match_ssh_key(instance, [_key("a", "web-1"), _key("b", None)])

    assert (match.item_id, match.name, match.matched_by) == ("a", "web-1", MATCHED_BY_SERVER_NAME)


def test_two_different_keys_with_the_name_are_ambiguous_but_one_key_imported_twice_is_not() -> None:
    instance = {"id": "i-1", "name": "web-1"}

    ambiguous = match_ssh_key(instance, [_key("a", "web-1", "SHA256:x"), _key("b", "web-1.pem", "SHA256:y")])
    duplicate = match_ssh_key(instance, [_key("b", "web-1", "SHA256:x"), _key("a", "web-1.pem", "SHA256:x")])

    assert ambiguous.ambiguous and ambiguous.item_id is None
    assert duplicate.item_id == "a"  # either copy works; the choice is stable


def test_a_custom_server_matches_by_its_key_file() -> None:
    instance = {"id": "custom-web-1", "name": "web-1", "is_custom": True, "key_name": "~/.ssh/e2e_web1"}

    match = match_ssh_key(instance, [_key("a", "e2e_web1")])

    assert (match.item_id, match.matched_by) == ("a", MATCHED_BY_KEY_FILE)


def test_no_match_without_a_named_key() -> None:
    assert match_ssh_key({"id": "i-1", "name": "web-1"}, [_key("a", "db-1"), _key("b", None)]) is None


def test_an_aws_row_without_a_provider_is_bound_as_aws() -> None:
    row = {"id": "i-0abc", "name": "web-1"}

    assert instance_provider(row) == "aws"
    assert instance_target(row) == ("aws", "i-0abc")
    assert instance_target({"id": "web-1", "provider": "OVH"}) == ("ovh", "web-1")


class _Service:
    """The parts of VaultCommandService the planner and binder use."""

    def __init__(self, *, bound=(), failing=(), logins=None) -> None:
        self.bound = set(bound)
        self.failing = set(failing)
        self.logins = logins or {}
        self.bind_personal = AsyncMock(side_effect=self._bind)

    def ssh_destination(self, instance):
        return instance.get("public_ip"), instance.get("port") or 22

    def ssh_login(self, instance):
        return self.logins.get(instance["id"], "ubuntu")

    async def personal_binding(self, instance):
        if instance["id"] in self.failing:
            raise RuntimeError("service down")
        return {"source": "servonaut_vault"} if instance["id"] in self.bound else None

    async def _bind(self, **kwargs):
        if kwargs["instance_id"] == "i-broken":
            raise VaultUserError("this server already has a vault key")
        return {"source": "servonaut_vault"}


def _server(instance_id: str, name: str, **extra) -> dict:
    return {"id": instance_id, "name": name, "public_ip": "198.51.100.7", **extra}


@pytest.mark.asyncio
async def test_the_review_says_why_each_server_cannot_be_bound() -> None:
    servers = [
        _server("i-ready", "web-1"),
        _server("i-bound", "web-2"),
        _server("i-same", "web-3"),
        _server("i-nohost", "web-4"),
        {"id": "i-noaddr", "name": "web-5"},
        _server("i-nologin", "web-6"),
        _server("i-down", "web-7"),
        _server("i-none", "db-1"),
        {"id": "s-1", "name": "web-1", "is_shared": True, "hostname": "web.example.test"},  # a team's server
    ]
    keys = [_key(f"k{n}", f"web-{n}") for n in (1, 2, 4, 5, 6, 7)] + [
        _key("k3a", "web-3", "SHA256:a"), _key("k3b", "web-3.pem", "SHA256:b"),
    ]
    service = _Service(bound={"i-bound"}, failing={"i-down"}, logins={"i-nologin": None})
    trusted = {"i-ready": [HOST_KEY]}

    rows = await plan_auto_bind(
        service, servers, keys, host_keys_for=lambda instance, host, port: trusted.get(instance["id"], []),
    )

    status = {row.instance["id"]: row.status for row in rows}
    assert status == {
        "i-ready": READY, "i-bound": ALREADY_BOUND, "i-same": AMBIGUOUS, "i-nohost": NO_HOST_KEYS,
        "i-noaddr": NO_ADDRESS, "i-nologin": NO_LOGIN, "i-down": CHECK_FAILED, "i-none": NO_KEY,
    }
    ready = rows[0]
    assert (ready.instance["id"], ready.match.item_id, ready.login, ready.host, ready.host_keys) == (
        "i-ready", "k1", "ubuntu", "198.51.100.7", [HOST_KEY],
    )
    # The rows are the records given, so a screen can map them back to what it shows.
    assert ready.instance is servers[0]


@pytest.mark.asyncio
async def test_binding_goes_on_after_a_failure_and_never_replaces_a_key() -> None:
    servers = [_server("i-broken", "web-1"), _server("i-ok", "web-2"), {"id": "x", "name": "x", "is_custom": True, "public_ip": "192.0.2.5"}]
    keys = [_key("k1", "web-1"), _key("k2", "web-2"), _key("kx", "x")]
    service = _Service()
    rows = await plan_auto_bind(service, servers, keys, host_keys_for=lambda *_: [HOST_KEY])
    seen = []

    await apply_auto_bind(service, rows, vault_id="v", on_progress=lambda index, row: seen.append(row.instance["id"]))

    results = {row.instance["id"]: row.result for row in rows}
    assert results == {"i-broken": "this server already has a vault key", "i-ok": "bound", "x": "bound"}
    assert seen == [row.instance["id"] for row in rows]
    calls = {call.kwargs["instance_id"]: call.kwargs for call in service.bind_personal.await_args_list}
    assert all(call["replace_existing"] is False for call in calls.values())
    assert (calls["i-ok"]["provider"], calls["i-ok"]["hostname"], calls["i-ok"]["login"]) == ("aws", "198.51.100.7", "ubuntu")
    # A custom server is bound by its name under the provider "custom".
    assert calls["x"]["provider"] == "custom"
    assert SimpleNamespace(**calls["x"]).host_keys == [HOST_KEY]
