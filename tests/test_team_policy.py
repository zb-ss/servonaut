"""Signed team agent rules: verification, replay protection, expiry and cache."""
from __future__ import annotations

import asyncio
import base64
import json
import os
import stat
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from servonaut.config.schema import MCPConfig
from servonaut.services import team_policy, team_policy_keys
from servonaut.services.team_policy import (
    BAD_SIGNATURE,
    CONFLICTING,
    EXPIRED,
    MALFORMED,
    MAX_PAYLOAD_BYTES,
    MISSING,
    NOT_LOADED,
    REPLAYED,
    UNKNOWN_KEY,
    UNKNOWN_SETTING,
    UNREACHABLE,
    UNTRUSTED_ORIGIN,
    UNSUPPORTED_FORMAT,
    WRONG_TEAM,
    clock_offset,
    format_1_default_agent_rules,
    parse_agent_rules,
    verify_envelope,
)
from servonaut.services.team_policy_keys import PRODUCTION_ORIGIN, api_origin
from servonaut.services.team_rules import (
    DEFAULT_TEAM_RULES,
    TeamRules,
    guard_for_target,
    is_team_refusal,
    rules_for,
)

from tests._team_policy_fixtures import (
    LIFETIME,
    TEST_KEY_ID,
    b64url,
    encode,
    envelope,
    new_store,
    payload,
    raw_public_key,
    response,
    rfc3339,
    sign,
    team_id_for,
    team_row,
    trust_signed_team_rules,
    trust_test_key,
)

BUILTIN_ALLOWLIST = tuple(MCPConfig().command_allowlist)
BUILTIN_BLOCKLIST = tuple(MCPConfig().command_blocklist)
TEAM_ID = team_id_for("ops-team")
NOW = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)
STAGING_ORIGIN = "https://staging.example.test"


def run(coro):
    return asyncio.run(coro)


class Clock:
    """A local clock the test moves."""

    def __init__(self, moment: datetime = NOW) -> None:
        self.now = moment.timestamp()

    def __call__(self) -> float:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta.total_seconds()


def http_date(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")


def rules(**changes):
    agent_rules = format_1_default_agent_rules()
    agent_rules.update(changes)
    return agent_rules


def signed(agent_rules=None, *, version=1, issued_at=NOW, **kwargs):
    return envelope(TEAM_ID, agent_rules, version=version, issued_at=issued_at, **kwargs)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def store(clock, tmp_path):
    trust_test_key(PRODUCTION_ORIGIN)
    return new_store(
        state_path=tmp_path / "team_policy.json", origin=lambda: PRODUCTION_ORIGIN, clock=clock,
    )


def apply(store, signed_envelope, *, slug="ops-team", date=None):
    return store.apply_response(team_row(slug), response(signed_envelope), date)


def shared_row(role="member", server_id="srv-1", slug="ops-team"):
    return {
        "id": server_id, "name": "web-1", "is_shared": True,
        "team_slug": slug, "team_name": "Ops", "team_role": role,
    }


# ---------------------------------------------------------------------------
# The format 1 defaults
# ---------------------------------------------------------------------------

class TestDefaults:
    def test_the_format_1_default_object_is_pinned(self):
        assert format_1_default_agent_rules() == {
            "role_levels": {
                "owner": "standard", "admin": "standard",
                "member": "standard", "viewer": "readonly",
            },
            "servers": {},
            "command_allowlist": None,
            "command_blocklist": [],
        }

    def test_the_format_1_defaults_are_the_built_in_team_rules(self):
        assert parse_agent_rules(format_1_default_agent_rules()) == DEFAULT_TEAM_RULES

    def test_the_built_in_team_rules_are_pinned(self):
        assert dict(DEFAULT_TEAM_RULES.role_levels) == {
            "owner": "standard", "admin": "standard",
            "member": "standard", "viewer": "readonly",
        }
        assert DEFAULT_TEAM_RULES.unknown_role_level == "readonly"
        assert dict(DEFAULT_TEAM_RULES.servers) == {}
        assert DEFAULT_TEAM_RULES.command_allowlist == BUILTIN_ALLOWLIST
        assert DEFAULT_TEAM_RULES.command_blocklist == BUILTIN_BLOCKLIST
        assert DEFAULT_TEAM_RULES.fallback_reason == ""

    def test_version_0_defaults_apply_as_signed(self, store):
        status = apply(store, signed(version=0))
        assert status.problem is None
        assert status.version == 0
        assert status.rules == DEFAULT_TEAM_RULES


# ---------------------------------------------------------------------------
# Keys and origins
# ---------------------------------------------------------------------------

class TestKeys:
    def test_only_the_production_key_is_bundled(self):
        # Pinned so that adding, rotating or dropping a trusted key is a
        # deliberate change, and no other origin's key (staging) ships.
        assert {
            origin: dict(keys) for origin, keys in team_policy_keys.TEAM_POLICY_KEYS.items()
        } == {
            PRODUCTION_ORIGIN: {
                "ddab938be92e4573": "jzEqA4TczRbiz31ITQ6J2VuvNMP3lQhtWigGnliwEjk=",
            },
        }

    def test_every_bundled_key_matches_its_id(self):
        for keys in team_policy_keys.TEAM_POLICY_KEYS.values():
            for key_id, text in keys.items():
                key = team_policy_keys.decode_public_key(text)
                assert key_id == team_policy_keys.key_id_for(key)

    def test_a_key_listed_under_another_id_trusts_nothing(self, store):
        trust_test_key(PRODUCTION_ORIGIN, key_id="0123456789abcdef")
        data = encode(payload(TEAM_ID, issued_at=NOW))
        assert apply(store, sign(data, key_id="0123456789abcdef")).problem == UNKNOWN_KEY

    @pytest.mark.parametrize("text", ["", "not base64!", "AAAA", None, 7])
    def test_a_malformed_bundled_key_trusts_nothing(self, monkeypatch, text):
        monkeypatch.setattr(team_policy_keys, "TEAM_POLICY_KEYS", {
            PRODUCTION_ORIGIN: {"0123456789abcdef": text},
        })
        assert team_policy_keys.keys_for_origin(PRODUCTION_ORIGIN) == {}

    def test_a_bundled_key_is_read_from_base64(self, monkeypatch):
        key = bytes(range(32))
        monkeypatch.setattr(team_policy_keys, "TEAM_POLICY_KEYS", {
            PRODUCTION_ORIGIN: {"630dcd2966c43366": base64.b64encode(key).decode()},
        })
        assert team_policy_keys.keys_for_origin(PRODUCTION_ORIGIN) == {"630dcd2966c43366": key}

    def test_a_key_id_is_the_start_of_the_keys_sha256(self):
        key = bytes(range(32))
        assert team_policy_keys.key_id_for(key) == (
            "630dcd2966c43366"
        )

    def test_the_production_origin_is_the_default_api_base(self):
        from servonaut.services.api_client import _DEFAULT_API_BASE

        assert api_origin(_DEFAULT_API_BASE) == PRODUCTION_ORIGIN

    @pytest.mark.parametrize("base, origin", [
        ("https://api.servonaut.dev", "https://api.servonaut.dev"),
        ("HTTPS://API.Servonaut.DEV/", "https://api.servonaut.dev"),
        ("https://api.servonaut.dev:443/api/v1", "https://api.servonaut.dev"),
        ("https://staging.example.test:8443/", "https://staging.example.test:8443"),
        ("http://127.0.0.1:8080/base", "http://127.0.0.1:8080"),
        ("http://localhost:80", "http://localhost"),
        ("https://[::1]:9443", "https://[::1]:9443"),
    ])
    def test_an_origin_is_scheme_host_and_port(self, base, origin):
        assert api_origin(base) == origin

    @pytest.mark.parametrize("base", ["", "api.servonaut.dev", "https://", "https://h:x"])
    def test_a_base_without_an_origin_is_refused(self, base):
        with pytest.raises(ValueError):
            api_origin(base)

    def test_the_origin_in_use_follows_the_api_override(self, monkeypatch):
        monkeypatch.setenv("SERVONAUT_API_URL", "https://staging.example.test/")
        assert team_policy.current_api_origin() == STAGING_ORIGIN

    def test_an_invalid_api_override_has_no_origin(self, monkeypatch):
        monkeypatch.setenv("SERVONAUT_API_URL", "http://example.test")
        assert team_policy.current_api_origin() is None

    def test_production_rules_fail_closed_until_a_key_is_bundled(self, clock, tmp_path):
        store = new_store(
            state_path=tmp_path / "s.json", origin=lambda: PRODUCTION_ORIGIN, clock=clock,
        )
        status = apply(store, signed())
        assert status.problem == UNKNOWN_KEY
        assert "update Servonaut" in status.rules.fallback_reason
        assert status.rules.level_for("owner") == "readonly"

    def test_a_key_for_one_origin_is_refused_for_another(self, clock, tmp_path):
        trust_test_key(PRODUCTION_ORIGIN)
        trust_test_key(STAGING_ORIGIN, key=Ed25519PrivateKey.generate())
        store = new_store(
            state_path=tmp_path / "s.json", origin=lambda: STAGING_ORIGIN, clock=clock,
        )
        assert apply(store, signed()).problem == UNKNOWN_KEY

    def test_an_origin_no_release_trusts_does_not_ask_for_an_update(self, clock, tmp_path):
        trust_test_key(PRODUCTION_ORIGIN)
        store = new_store(
            state_path=tmp_path / "s.json", origin=lambda: STAGING_ORIGIN, clock=clock,
        )
        status = apply(store, signed())

        # Updating cannot help: releases bundle the production keys only.
        assert status.problem == UNTRUSTED_ORIGIN
        assert "update Servonaut" not in status.rules.fallback_reason
        assert status.rules.fallback_reason == (
            "this Servonaut trusts no key for agent rules from the API address it is set to use"
        )

    def test_no_origin_trusts_no_key(self, clock, tmp_path):
        trust_test_key(PRODUCTION_ORIGIN)
        store = new_store(state_path=tmp_path / "s.json", origin=lambda: None, clock=clock)
        assert apply(store, signed()).problem == UNTRUSTED_ORIGIN


# ---------------------------------------------------------------------------
# The envelope
# ---------------------------------------------------------------------------

class TestEnvelope:
    def test_a_verified_envelope_carries_its_payload_and_itself(self, store):
        good = signed(version=3)
        policy = verify_envelope(good, origin=PRODUCTION_ORIGIN, team_id=TEAM_ID)
        assert (policy.team_id, policy.version) == (TEAM_ID, 3)
        assert policy.issued_at == NOW
        assert policy.expires_at == NOW + LIFETIME
        assert policy.rules == DEFAULT_TEAM_RULES
        assert dict(policy.envelope) == good

    def test_a_signed_policy_is_accepted(self, store):
        status = apply(store, signed(rules(role_levels={"member": "readonly"})))
        assert status.problem is None
        assert status.rules.level_for("member") == "readonly"
        assert status.rules.level_for("owner") == "readonly"

    def test_a_tampered_payload_is_refused(self, store):
        good = signed()
        document = payload(TEAM_ID, rules(role_levels={"member": "dangerous"}), issued_at=NOW)
        tampered = {**good, "payload": b64url(encode(document))}
        assert apply(store, tampered).problem == BAD_SIGNATURE

    def test_a_tampered_signature_is_refused(self, store):
        good = signed()
        signature = bytearray(good["signatures"][0]["signature"].encode())
        signature[5] = ord("A") if signature[5] != ord("A") else ord("B")
        tampered = {**good, "signatures": [{"key_id": TEST_KEY_ID, "signature": signature.decode()}]}
        assert apply(store, tampered).problem == BAD_SIGNATURE

    def test_a_signature_by_an_unknown_key_only_is_refused(self, store):
        other = Ed25519PrivateKey.generate()
        data = encode(payload(TEAM_ID, issued_at=NOW))
        status = apply(store, sign(data, key=other, key_id="next-key"))
        assert status.problem == UNKNOWN_KEY
        assert status.rules.fallback_reason.endswith("update Servonaut")

    def test_an_unknown_key_beside_a_trusted_one_is_ignored(self, store):
        other = Ed25519PrivateKey.generate()
        data = encode(payload(TEAM_ID, issued_at=NOW))
        unknown = sign(data, key=other, key_id="next-key")["signatures"]
        assert apply(store, sign(data, extra_signatures=unknown)).problem is None

    def test_any_trusted_signature_that_verifies_is_enough(self, store):
        other = Ed25519PrivateKey.generate()
        trust_test_key(PRODUCTION_ORIGIN, key=other)
        other_id = team_policy_keys.key_id_for(raw_public_key(other))
        data = encode(payload(TEAM_ID, issued_at=NOW))
        wrong = [{"key_id": other_id, "signature": b64url(b"\x00" * 64)}]
        assert apply(store, sign(data, extra_signatures=wrong)).problem is None
        # Either trusted key verifies on its own.
        assert apply(store, sign(data, key=other, key_id=other_id)).problem is None

    def test_a_trusted_key_id_with_a_signature_by_another_key_is_refused(self, store):
        data = encode(payload(TEAM_ID, issued_at=NOW))
        forged = sign(data, key=Ed25519PrivateKey.generate(), key_id=TEST_KEY_ID)
        assert apply(store, forged).problem == BAD_SIGNATURE

    def test_the_plain_editor_copy_of_the_rules_is_never_used(self, store):
        body = {"data": {
            "agent_rules": format_1_default_agent_rules(), "agent_rules_signed": None,
        }}
        assert store.apply_response(team_row("ops-team"), body).problem == MISSING

    @pytest.mark.parametrize("body", [
        {"data": {"allowed_tools": []}},
        {"data": {"agent_rules_signed": None}},
        {},
        None,
    ])
    def test_a_policy_without_signed_rules_fails_closed(self, store, body):
        status = store.apply_response(team_row("ops-team"), body)
        assert status.problem == MISSING
        assert status.rules.level_for("owner") == "readonly"

    @pytest.mark.parametrize("bad", [
        "not an object",
        ["payload"],
        {"payload": "abc"},
        {"signatures": []},
        {"payload": 3, "signatures": []},
        {"payload": "abc", "signatures": "x"},
    ])
    def test_a_malformed_envelope_fails_closed(self, store, bad):
        status = apply(store, bad)
        assert status.problem == MALFORMED
        assert status.rules.level_for("owner") == "readonly"

    @pytest.mark.parametrize("signatures", [
        [],
        ["not an object"],
        [{"signature": "abc"}],
        [{"key_id": 7, "signature": "abc"}],
    ])
    def test_an_envelope_without_a_trusted_signature_asks_for_an_update(self, store, signatures):
        assert apply(store, {**signed(), "signatures": signatures}).problem == UNKNOWN_KEY

    @pytest.mark.parametrize("signature", [None, 64, "", "not*base64", b64url(b"\x00" * 63)])
    def test_an_unreadable_trusted_signature_does_not_verify(self, store, signature):
        bad = {**signed(), "signatures": [{"key_id": TEST_KEY_ID, "signature": signature}]}
        assert apply(store, bad).problem == BAD_SIGNATURE

    def test_a_payload_that_is_not_base64url_is_refused(self, store):
        good = signed()
        assert apply(store, {**good, "payload": good["payload"] + "+/"}).problem == MALFORMED

    def test_an_oversize_payload_is_refused_before_it_is_decoded(self, store):
        big = b64url(b"x" * (MAX_PAYLOAD_BYTES + 3))
        signatures = [{"key_id": TEST_KEY_ID, "signature": b64url(b"\x00" * 64)}]
        assert apply(store, {"payload": big, "signatures": signatures}).problem == MALFORMED

    @pytest.mark.parametrize("data", [
        b"not json",
        b"\xff\xfe",
        b"[1, 2]",
        b'{"format": 1, "format": 1}',
        b'{"format": NaN}',
        b"[" * 100000 + b"]" * 100000,
    ])
    def test_signed_garbage_is_refused(self, store, data):
        assert apply(store, sign(data)).problem == MALFORMED

    def test_a_payload_with_a_duplicate_key_is_refused(self, store):
        # A parser that keeps the last copy would read other rules than one
        # that keeps the first.
        text = json.dumps(payload(TEAM_ID, issued_at=NOW))
        looser = json.dumps(rules(role_levels={"member": "dangerous"}))
        data = (text[:-1] + f', "agent_rules": {looser}}}').encode("utf-8")
        assert apply(store, sign(data)).problem == MALFORMED


# ---------------------------------------------------------------------------
# The payload
# ---------------------------------------------------------------------------

DROP = object()


def signed_payload(**changes):
    """A signed payload with raw values in place (``fmt`` is ``format``; DROP removes)."""
    document = payload(TEAM_ID, issued_at=NOW)
    for key, value in changes.items():
        key = "format" if key == "fmt" else key
        if value is DROP:
            document.pop(key)
        else:
            document[key] = value
    return sign(encode(document))


class TestPayload:
    def test_another_teams_rules_are_refused(self, store):
        status = apply(store, envelope(team_id_for("other-team"), issued_at=NOW))
        assert status.problem == WRONG_TEAM

    @pytest.mark.parametrize("fmt", [2, 0])
    def test_an_unknown_format_asks_for_an_update(self, store, fmt):
        status = apply(store, signed_payload(fmt=fmt))
        assert status.problem == UNSUPPORTED_FORMAT
        assert status.rules.fallback_reason.endswith("update Servonaut")

    def test_a_newer_format_with_other_keys_still_asks_for_an_update(self, store):
        assert apply(store, signed_payload(fmt=2, rules_v2={})).problem == UNSUPPORTED_FORMAT

    @pytest.mark.parametrize("changes", [
        {"fmt": "1"},
        {"fmt": True},
        {"fmt": 1.0},
        {"version": -1},
        {"version": 1.5},
        {"version": True},
        {"version": "2"},
        {"team_id": ""},
        {"team_id": 7},
        {"issued_at": "2026-10-18 12:00:00"},
        {"issued_at": "2026-10-18T12:00:00"},
        {"issued_at": "yesterday"},
        {"issued_at": 1760788800},
        {"expires_at": "2026-02-30T12:00:00Z"},
        {"expires_at": rfc3339(NOW)},
        {"expires_at": rfc3339(NOW - timedelta(seconds=1))},
        {"issued_at": "２０２６-10-18T12:00:00Z"},
        {"agent_rules": None},
        {"agent_rules": []},
        {"signed_by": "someone"},
        {"version": DROP},
        {"expires_at": DROP},
        {"agent_rules": DROP},
    ])
    def test_a_malformed_payload_fails_closed(self, store, changes):
        status = apply(store, signed_payload(**changes))
        assert status.problem == MALFORMED
        assert status.rules.level_for("owner") == "readonly"

    @pytest.mark.parametrize("stamp", [
        "2026-10-18T12:00:00.5Z",
        "2026-10-18T12:00:00.123456789Z",
        "2026-10-18t12:00:00z",
        "2026-10-18T14:00:00+02:00",
    ])
    def test_rfc3339_spellings_are_read(self, store, stamp):
        status = apply(store, signed_payload(issued_at=stamp))
        assert status.problem is None


class TestAgentRules:
    @pytest.mark.parametrize("level", ["Standard", "STANDARD", "admin", "root", "", None, 1])
    def test_a_level_this_release_does_not_know_fails_closed(self, store, level):
        status = apply(store, signed(rules(role_levels={"owner": "standard", "member": level})))
        assert status.problem == MALFORMED

    @pytest.mark.parametrize("key", ["approvals", "max_connections", "Role_levels"])
    def test_an_unknown_agent_rules_key_fails_closed_and_asks_for_an_update(self, store, key):
        agent_rules = rules()
        agent_rules[key] = []
        status = apply(store, signed(agent_rules))

        # It may be a restriction this release cannot apply.
        assert status.problem == UNKNOWN_SETTING
        assert status.rules.fallback_reason.endswith("update Servonaut")
        assert status.rules.level_for("owner") == "readonly"

    def test_an_unknown_server_override_key_asks_for_an_update(self, store):
        servers = {"srv-1": {"role_levels": {"member": "readonly"}, "note": "x"}}
        assert apply(store, signed(rules(servers=servers))).problem == UNKNOWN_SETTING

    @pytest.mark.parametrize("key", [
        "role_levels", "servers", "command_allowlist", "command_blocklist",
    ])
    def test_a_missing_agent_rules_key_fails_closed(self, store, key):
        agent_rules = rules()
        del agent_rules[key]
        assert apply(store, signed(agent_rules)).problem == MALFORMED

    def test_a_role_this_release_does_not_know_fails_closed(self, store):
        status = apply(store, signed(rules(role_levels={"member": "standard", "guest": "standard"})))
        assert status.problem == MALFORMED

    def test_a_role_left_out_is_readonly(self, store):
        status = apply(store, signed(rules(role_levels={"owner": "dangerous", "admin": "standard"})))
        assert status.problem is None
        assert status.rules.level_for("owner") == "dangerous"
        assert status.rules.level_for("admin") == "standard"
        assert status.rules.level_for("member") == "readonly"
        assert status.rules.level_for("viewer") == "readonly"

    @pytest.mark.parametrize("servers", [
        [],
        {"srv-1": "readonly"},
        {"srv-1": {"role_levels": {"member": "Readonly"}}},
        {"srv-1": {}},
        {"": {"role_levels": {}}},
    ])
    def test_a_malformed_server_override_fails_closed(self, store, servers):
        assert apply(store, signed(rules(servers=servers))).problem == MALFORMED

    @pytest.mark.parametrize("allowlist", ["uptime", [1], ["uptime", None], {}])
    def test_an_allowlist_of_the_wrong_shape_fails_closed(self, store, allowlist):
        assert apply(store, signed(rules(command_allowlist=allowlist))).problem == MALFORMED

    @pytest.mark.parametrize("blocklist", [None, "rm", [3], {"x": 1}])
    def test_a_blocklist_of_the_wrong_shape_fails_closed(self, store, blocklist):
        assert apply(store, signed(rules(command_blocklist=blocklist))).problem == MALFORMED

    def test_allowlist_entries_that_are_not_command_names_are_dropped(self):
        parsed = parse_agent_rules(rules(command_allowlist=[
            "uptime", "rm -rf", "../bin/x", "", "-x", "ls;", "Uptime", "uptime",
            "python3.12", "g++", "a_b-c", "systemctl\n", "ünïcode",
        ]))
        assert parsed.command_allowlist == ("uptime", "Uptime", "python3.12", "g++", "a_b-c")

    def test_a_team_allowlist_replaces_the_built_in_one(self):
        parsed = parse_agent_rules(rules(command_allowlist=["uptime", "systemctl"]))
        assert parsed.command_allowlist == ("uptime", "systemctl")

    def test_an_empty_team_allowlist_allows_no_command(self):
        assert parse_agent_rules(rules(command_allowlist=[])).command_allowlist == ()

    def test_team_patterns_are_added_to_the_built_in_blocklist(self):
        parsed = parse_agent_rules(rules(command_blocklist=[r"\bcurl\b", BUILTIN_BLOCKLIST[0]]))
        assert parsed.command_blocklist == BUILTIN_BLOCKLIST + (r"\bcurl\b",)


# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------

class TestVersions:
    def test_a_newer_version_replaces_the_rules(self, store):
        apply(store, signed(version=1))
        status = apply(store, signed(rules(role_levels={"member": "readonly"}), version=2))
        assert status.problem is None
        assert status.version == 2
        assert status.rules.level_for("member") == "readonly"

    def test_an_older_version_is_refused_as_a_replay(self, store):
        apply(store, signed(rules(role_levels={"member": "readonly"}), version=3))
        status = apply(store, signed(version=2))
        assert status.problem == REPLAYED
        assert status.rules.level_for("member") == "readonly"
        assert status.rules.level_for("owner") == "readonly"

    def test_the_same_version_with_different_rules_is_refused(self, store):
        apply(store, signed(version=4))
        status = apply(store, signed(rules(role_levels={"member": "dangerous"}), version=4))
        assert status.problem == CONFLICTING
        assert status.rules.level_for("member") == "readonly"

    def test_the_same_version_signed_again_later_is_accepted(self, store, clock):
        apply(store, signed(version=4))
        clock.advance(timedelta(minutes=40))
        later = NOW + timedelta(minutes=40)
        status = apply(store, signed(version=4, issued_at=later))
        assert status.problem is None
        assert status.expires_at == later + LIFETIME

    def test_the_same_rules_in_other_key_order_are_the_same_rules(self, store):
        apply(store, signed(version=4))
        reordered = dict(reversed(list(format_1_default_agent_rules().items())))
        assert apply(store, signed(reordered, version=4)).problem is None

    def test_a_good_copy_after_a_refused_one_applies_again(self, store):
        apply(store, signed(version=5))
        assert apply(store, signed(version=4)).problem == REPLAYED
        assert apply(store, signed(version=6)).problem is None

    def test_an_answer_older_than_one_already_applied_is_dropped(self, store):
        first = store._begin(TEAM_ID)
        second = store._begin(TEAM_ID)
        store._apply(TEAM_ID, "ops-team", response(signed(version=7)), None, second)
        status = store._apply(TEAM_ID, "ops-team", response(signed(version=6)), None, first)
        assert status.problem is None
        assert status.version == 7


# ---------------------------------------------------------------------------
# Expiry, by the API's clock
# ---------------------------------------------------------------------------

class TestExpiry:
    def test_rules_expire_by_the_local_clock_without_a_date(self, store, clock):
        apply(store, signed())
        clock.advance(LIFETIME - timedelta(seconds=1))
        assert store.status("ops-team").problem is None
        clock.advance(timedelta(seconds=1))
        status = store.status("ops-team")
        assert status.problem == EXPIRED
        assert status.rules.level_for("owner") == "readonly"
        assert "could not be refreshed" in status.rules.fallback_reason

    def test_an_expired_copy_is_refused_when_fetched(self, store):
        stale = signed(issued_at=NOW - 2 * LIFETIME)
        status = apply(store, stale)
        assert status.problem == EXPIRED
        # Refused, not kept: nothing is saved and no version is recorded.
        assert status.version is None
        assert not store.state_path.exists()

    def test_expiry_follows_the_api_clock_when_it_is_ahead(self, store, clock):
        # Valid by the local clock, but the API's Date says it is past expiry.
        status = apply(store, signed(), date=http_date(NOW + LIFETIME + timedelta(minutes=1)))
        assert status.problem == EXPIRED

    def test_expiry_follows_the_api_clock_when_it_is_behind(self, store, clock):
        # The local clock runs ahead: past expiry locally, not by the API.
        clock.advance(LIFETIME + timedelta(minutes=10))
        status = apply(store, signed(), date=http_date(NOW + timedelta(minutes=5)))
        assert status.problem is None
        clock.advance(timedelta(minutes=50))
        assert store.status("ops-team").problem is None
        clock.advance(timedelta(minutes=6))
        assert store.status("ops-team").problem == EXPIRED

    def test_a_fresh_copy_ends_the_expiry(self, store, clock):
        apply(store, signed())
        clock.advance(2 * LIFETIME)
        assert store.status("ops-team").problem == EXPIRED
        later = NOW + 2 * LIFETIME
        assert apply(store, signed(version=1, issued_at=later)).problem is None

    @pytest.mark.parametrize("date", [None, "", "not a date", "Sun, 99 Oct 2026 99:00:00 GMT"])
    def test_a_missing_or_unreadable_date_means_no_offset(self, date):
        assert clock_offset(date, NOW.timestamp()) == 0.0

    def test_the_offset_is_how_far_the_api_clock_is_ahead(self):
        later = http_date(NOW + timedelta(seconds=90))
        assert clock_offset(later, NOW.timestamp()) == 90.0
        assert clock_offset(http_date(NOW - timedelta(seconds=30)), NOW.timestamp()) == -30.0

    def test_a_refresh_is_due_halfway_through_the_lifetime(self, store, clock):
        assert store.seconds_until_refresh() is None
        apply(store, signed())
        assert store.seconds_until_refresh() == LIFETIME.total_seconds() / 2

    def test_after_a_failed_refresh_the_tries_halve_toward_expiry(self, store, clock):
        apply(store, signed())
        clock.advance(LIFETIME / 2)
        # Never 0 once due: a fetch that keeps failing must not spin.
        assert store.seconds_until_refresh() == LIFETIME.total_seconds() / 4
        clock.advance(LIFETIME / 4)
        assert store.seconds_until_refresh() == LIFETIME.total_seconds() / 8

    def test_expired_rules_are_not_scheduled(self, store, clock):
        apply(store, signed())
        clock.advance(LIFETIME)
        assert store.seconds_until_refresh() is None

    def test_the_soonest_team_sets_the_next_refresh(self, store, clock):
        apply(store, signed())
        other = envelope(team_id_for("db-team"), version=1, issued_at=NOW - LIFETIME / 4)
        store.apply_response(team_row("db-team"), response(other))
        assert store.seconds_until_refresh() == LIFETIME.total_seconds() / 4

    def test_refused_rules_are_not_scheduled(self, store, clock):
        apply(store, signed(version=2))
        apply(store, signed(version=1))
        assert store.status("ops-team").problem == REPLAYED
        assert store.seconds_until_refresh() is None

    def test_load_reads_the_saved_rules_before_any_fetch(self, store, clock):
        apply(store, signed(version=4))
        again = new_store(state_path=store.state_path, origin=lambda: PRODUCTION_ORIGIN, clock=clock)
        again.load()
        assert again.status("ops-team").version == 4
        assert again.rules_for_team("ops-team").fallback_reason == ""

    def test_the_refresh_time_follows_the_api_clock(self, store):
        apply(store, signed(), date=http_date(NOW + timedelta(minutes=10)))
        assert store.seconds_until_refresh() == (LIFETIME / 2 - timedelta(minutes=10)).total_seconds()


# ---------------------------------------------------------------------------
# The state file
# ---------------------------------------------------------------------------

def reopened(store, clock, origin=PRODUCTION_ORIGIN):
    return new_store(state_path=store.state_path, origin=lambda: origin, clock=clock)


class TestStateFile:
    def test_the_last_good_copy_survives_a_restart(self, store, clock):
        apply(store, signed(rules(role_levels={"member": "readonly"}), version=3))
        again = reopened(store, clock)
        status = again.status("ops-team")
        assert status.problem is None
        assert status.version == 3
        assert status.rules.level_for("member") == "readonly"

    def test_the_file_is_owner_only(self, store):
        apply(store, signed())
        assert stat.S_IMODE(os.stat(store.state_path).st_mode) == 0o600

    def test_the_file_is_replaced_atomically(self, store, monkeypatch):
        apply(store, signed(version=1))
        before = store.state_path.read_bytes()

        def refuse(*args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(os, "replace", refuse)
        status = apply(store, signed(version=2))

        assert status.problem is None
        assert store.state_path.read_bytes() == before
        assert [path.name for path in store.state_path.parent.iterdir()] == [store.state_path.name]

    def test_a_tampered_payload_in_the_file_fails_closed(self, store, clock):
        apply(store, signed())
        document = json.loads(store.state_path.read_text())
        entry = document["origins"][PRODUCTION_ORIGIN][TEAM_ID]
        loosened = payload(TEAM_ID, rules(role_levels={"member": "dangerous"}), issued_at=NOW)
        entry["envelope"]["payload"] = b64url(encode(loosened))
        store.state_path.write_text(json.dumps(document))

        status = reopened(store, clock).status("ops-team")
        assert status.problem == BAD_SIGNATURE
        assert status.rules.level_for("member") == "readonly"

    def test_a_raised_version_in_the_file_only_refuses(self, store, clock):
        apply(store, signed(version=2))
        document = json.loads(store.state_path.read_text())
        document["origins"][PRODUCTION_ORIGIN][TEAM_ID]["highest_version"] = 99
        store.state_path.write_text(json.dumps(document))

        again = reopened(store, clock)
        assert again.status("ops-team").problem == REPLAYED
        assert apply(again, signed(version=3)).problem == REPLAYED

    def test_an_edited_clock_offset_cannot_keep_rules_alive(self, store, clock):
        apply(store, signed())
        document = json.loads(store.state_path.read_text())
        document["origins"][PRODUCTION_ORIGIN][TEAM_ID]["clock_offset"] = -1e9
        store.state_path.write_text(json.dumps(document))

        clock.advance(LIFETIME)
        assert reopened(store, clock).status("ops-team").problem == EXPIRED

    @pytest.mark.parametrize("offset", ["NaN", float("inf"), "soon", None])
    def test_an_unreadable_clock_offset_counts_as_none(self, store, clock, offset):
        apply(store, signed())
        text = store.state_path.read_text()
        document = json.loads(text)
        document["origins"][PRODUCTION_ORIGIN][TEAM_ID]["clock_offset"] = offset
        store.state_path.write_text(json.dumps(document))

        clock.advance(LIFETIME)
        assert reopened(store, clock).status("ops-team").problem == EXPIRED

    @pytest.mark.parametrize("content", ["", "not json", "[]", '{"format": 2}', '{"format": 1, "origins": []}'])
    def test_an_unreadable_file_means_nothing_is_cached(self, store, clock, content):
        store.state_path.write_text(content)
        again = reopened(store, clock)
        assert again.status("ops-team") is None
        assert again.rules_for_team("ops-team").fallback_reason == NOT_LOADED.reason

    def test_rules_cached_for_one_origin_do_not_apply_to_another(self, store, clock):
        apply(store, signed())
        trust_test_key(STAGING_ORIGIN)
        assert reopened(store, clock, origin=STAGING_ORIGIN).status("ops-team") is None

    def test_other_origins_in_the_file_are_kept(self, store, clock):
        apply(store, signed())
        trust_test_key(STAGING_ORIGIN)
        staging = reopened(store, clock, origin=STAGING_ORIGIN)
        assert apply(staging, signed()).problem is None
        origins = json.loads(store.state_path.read_text())["origins"]
        assert set(origins) == {PRODUCTION_ORIGIN, STAGING_ORIGIN}

    def test_a_newer_copy_another_process_saved_is_kept(self, store, clock):
        other = reopened(store, clock)
        apply(store, signed(version=1))
        apply(other, signed(version=5))
        apply(store, signed(version=2))

        saved = json.loads(store.state_path.read_text())["origins"][PRODUCTION_ORIGIN][TEAM_ID]
        assert saved["highest_version"] == 5
        assert reopened(store, clock).status("ops-team").version == 5

    def test_a_copy_another_process_saved_fills_a_failed_fetch(self, store, clock):
        offline = policy_service({"ops-team": ConnectionError("offline")})
        assert run(store.refresh(offline, [team_row("ops-team")]))[0].problem == UNREACHABLE
        apply(reopened(store, clock), signed(version=3))

        status = run(store.refresh(offline, [team_row("ops-team")]))[0]
        assert status.problem is None
        assert status.version == 3

    def test_a_newer_copy_another_process_saved_replaces_the_one_held_here(self, store, clock):
        other = reopened(store, clock)
        apply(store, signed(rules(role_levels={"member": "standard"}), version=5))
        apply(other, signed(rules(role_levels={"member": "readonly"}), version=6))
        offline = policy_service({"ops-team": ConnectionError("offline")})

        status = run(store.refresh(offline, [team_row("ops-team")]))[0]

        # Not the older, looser v5 this process held while the fetch failed.
        assert status.problem is None
        assert status.version == 6
        assert status.rules.level_for("member") == "readonly"

    def test_rules_older_than_a_version_this_device_accepted_are_not_used(self, store, clock):
        apply(store, signed(version=5))
        document = json.loads(store.state_path.read_text())
        entry = document["origins"][PRODUCTION_ORIGIN][TEAM_ID]
        # Another process accepted v7, but its copy here cannot be used.
        entry["highest_version"] = 7
        entry["envelope"]["signatures"] = []
        store.state_path.write_text(json.dumps(document))
        offline = policy_service({"ops-team": ConnectionError("offline")})

        status = run(store.refresh(offline, [team_row("ops-team")]))[0]

        assert status.problem == REPLAYED
        assert status.rules.level_for("member") == "readonly"

    def test_an_older_copy_never_replaces_a_newer_saved_one(self, store, clock):
        older = {"slug": "ops-team", "highest_version": 6,
                 "envelope": signed(version=5), "clock_offset": 0.0, "fetched_at": 200.0}
        newer = {"slug": "ops-team", "highest_version": 6,
                 "envelope": signed(version=6), "clock_offset": 0.0, "fetched_at": 100.0}

        kept = team_policy._newer_entry(newer, older, origin=PRODUCTION_ORIGIN, team_id=TEAM_ID)

        # Fetched later, but the older version: the saved v6 stays.
        assert kept["envelope"] == newer["envelope"]
        assert kept["highest_version"] == 6

    def test_a_saved_copy_that_does_not_verify_never_wins(self, store, clock):
        ours = {"slug": "ops-team", "highest_version": 2,
                "envelope": signed(version=2), "clock_offset": 0.0, "fetched_at": 100.0}
        forged = {"slug": "ops-team", "highest_version": 9,
                  "envelope": {**signed(version=9), "signatures": []},
                  "clock_offset": 0.0, "fetched_at": 300.0}

        kept = team_policy._newer_entry(forged, ours, origin=PRODUCTION_ORIGIN, team_id=TEAM_ID)

        assert kept["envelope"] == ours["envelope"]
        # A higher version on disk still counts against replays.
        assert kept["highest_version"] == 9

    def test_a_version_another_process_accepted_counts_on_refresh(self, store, clock):
        other = reopened(store, clock)
        apply(store, signed(version=1))
        apply(other, signed(version=5))
        service = policy_service({"ops-team": response(signed(version=2))})

        statuses = run(store.refresh(service, [team_row("ops-team")]))
        assert statuses[0].problem == REPLAYED


# ---------------------------------------------------------------------------
# Refreshing
# ---------------------------------------------------------------------------

def policy_service(bodies, date=None, teams=None):
    """A team service answering the policy of each slug in *bodies*."""

    async def fetch(slug):
        body = bodies[slug]
        if isinstance(body, Exception):
            raise body
        return body, date

    service = MagicMock()
    service.get_team_policy_with_date = AsyncMock(side_effect=fetch)
    service.list_teams = AsyncMock(return_value=teams or [])
    return service


class TestRefresh:
    def test_every_team_is_fetched_and_verified(self, store):
        other_id = team_id_for("db-team")
        service = policy_service({
            "ops-team": response(signed()),
            "db-team": response(envelope(other_id, rules(role_levels={}), issued_at=NOW)),
        })
        statuses = run(store.refresh(service, [team_row("ops-team"), team_row("db-team")]))

        assert [status.problem for status in statuses] == [None, None]
        assert store.rules_for_team("ops-team").level_for("member") == "standard"
        assert store.rules_for_team("db-team").level_for("member") == "readonly"

    def test_without_teams_the_team_list_is_read(self, store):
        service = policy_service(
            {"ops-team": response(signed())}, teams=[team_row("ops-team")],
        )
        run(store.refresh(service))
        service.list_teams.assert_awaited_once()
        assert store.status("ops-team").problem is None

    def test_a_team_list_failure_is_raised(self, store):
        service = policy_service({})
        service.list_teams = AsyncMock(side_effect=RuntimeError("401 Unauthorized"))
        with pytest.raises(RuntimeError):
            run(store.refresh(service))

    def test_the_date_header_sets_the_clock_offset(self, store):
        service = policy_service(
            {"ops-team": response(signed())}, date=http_date(NOW + LIFETIME),
        )
        assert run(store.refresh(service, [team_row("ops-team")]))[0].problem == EXPIRED

    def test_a_failed_fetch_keeps_valid_cached_rules(self, store):
        apply(store, signed(rules(role_levels={"member": "readonly", "owner": "standard"})))
        service = policy_service({"ops-team": ConnectionError("offline")})
        status = run(store.refresh(service, [team_row("ops-team")]))[0]
        assert status.problem is None
        assert status.rules.level_for("owner") == "standard"

    def test_a_failed_fetch_with_nothing_cached_is_readonly(self, store):
        service = policy_service({"ops-team": ConnectionError("offline")})
        status = run(store.refresh(service, [team_row("ops-team")]))[0]
        assert status.problem == UNREACHABLE
        assert status.rules.level_for("owner") == "readonly"

    def test_a_failed_fetch_after_expiry_says_the_rules_expired(self, store, clock):
        apply(store, signed())
        clock.advance(LIFETIME)
        service = policy_service({"ops-team": ConnectionError("offline")})
        assert run(store.refresh(service, [team_row("ops-team")]))[0].problem == EXPIRED

    def test_one_team_failing_leaves_the_others(self, store):
        service = policy_service({
            "ops-team": RuntimeError("boom"),
            "db-team": response(envelope(team_id_for("db-team"), issued_at=NOW)),
        })
        statuses = run(store.refresh(service, [team_row("ops-team"), team_row("db-team")]))
        assert [status.problem for status in statuses] == [UNREACHABLE, None]

    @pytest.mark.parametrize("team", [
        {"slug": "ops-team"}, {"id": "x"}, {"slug": "", "id": "x"}, "ops-team",
        {"slug": "ops-team", "id": True},
    ])
    def test_a_team_without_a_slug_or_id_is_skipped(self, store, team):
        service = policy_service({"ops-team": response(signed())})
        assert run(store.refresh(service, [team])) == []
        service.get_team_policy_with_date.assert_not_awaited()

    def test_a_numeric_team_id_is_compared_as_text(self, store):
        status = store.apply_response(
            {"slug": "ops-team", "id": 42},
            response(envelope("42", issued_at=NOW)),
        )
        assert status.problem is None

    def test_the_team_list_says_which_team_a_slug_names_before_any_answer(self, store):
        trust_test_key(PRODUCTION_ORIGIN)
        renamed = {"id": "team-id-renamed", "slug": "ops-team", "name": "Ops", "role": "member"}
        store.apply_response(renamed, response(envelope(
            "team-id-renamed", rules(role_levels={"member": "dangerous"}), issued_at=NOW,
        )))
        newcomer = team_row("ops-team")
        seen_during_fetch = []

        async def fetch(slug):
            # While the new team's answer is on its way.
            seen_during_fetch.append(store.status("ops-team"))
            raise ConnectionError("offline")

        service = policy_service({})
        service.get_team_policy_with_date = AsyncMock(side_effect=fetch)
        run(store.refresh(service, [newcomer]))

        assert seen_during_fetch == [None]
        assert store.rules_for_team("ops-team").level_for("member") == "readonly"
        # The renamed team's rules are still found by its id.
        assert store.status("", "team-id-renamed").rules.level_for("member") == "dangerous"

    def test_statuses_list_each_team_once(self, store):
        apply(store, signed())
        store.apply_response(
            team_row("ops-renamed", id=TEAM_ID), response(signed(version=2)),
        )
        store.apply_response(
            team_row("db-team"), response(envelope(team_id_for("db-team"), issued_at=NOW)),
        )
        statuses = store.statuses()
        assert [(status.slug, status.version) for status in statuses] == [
            ("ops-renamed", 2), ("db-team", 1),
        ]

    def test_apply_response_needs_a_slug_and_an_id(self, store):
        with pytest.raises(ValueError):
            store.apply_response({"slug": "ops-team"}, response(signed()))


# ---------------------------------------------------------------------------
# What applies on a shared server
# ---------------------------------------------------------------------------

class TestRulesForRows:
    def test_a_team_never_loaded_is_readonly_with_a_reason(self):
        rules = rules_for(shared_row("owner"))
        assert rules.level_for("owner") == "readonly"
        assert rules.fallback_reason == NOT_LOADED.reason

    def test_a_row_without_a_team_slug_is_readonly(self):
        row = shared_row()
        del row["team_slug"]
        assert rules_for(row).fallback_reason == NOT_LOADED.reason

    def test_signed_rules_apply_to_the_teams_rows(self):
        trust_signed_team_rules("ops-team", rules(role_levels={"member": "readonly"}))
        assert rules_for(shared_row("member")).level_for("member") == "readonly"
        assert rules_for(shared_row("member", slug="db-team")).fallback_reason == NOT_LOADED.reason

    def test_a_row_naming_its_team_by_id_finds_that_team_s_rules(self):
        trust_signed_team_rules("ops-team", rules(role_levels={"member": "readonly"}))
        row = {**shared_row("member"), "team_id": team_id_for("ops-team")}
        assert rules_for(row).level_for("member") == "readonly"

    def test_a_slug_another_team_now_uses_does_not_find_the_old_team_s_rules(self):
        # Rules saved for the team that used the slug before a rename.
        trust_signed_team_rules("ops-team", rules(role_levels={"member": "dangerous"}))
        row = {**shared_row("member"), "team_id": "team-id-of-another-team"}

        found = rules_for(row)
        assert found.level_for("member") == "readonly"
        assert found.fallback_reason == NOT_LOADED.reason

    def test_a_server_override_replaces_the_team_wide_level_there(self):
        trust_signed_team_rules("ops-team", rules(servers={
            "srv-2": {"role_levels": {"member": "readonly", "owner": "dangerous"}},
        }))
        on_override = rules_for(shared_row(server_id="srv-2"))
        assert on_override.level_for("member") == "readonly"
        assert on_override.level_for("owner") == "dangerous"
        # Roles the override leaves out keep the team-wide level.
        assert on_override.level_for("admin") == "standard"
        assert on_override.level_for("viewer") == "readonly"
        assert rules_for(shared_row(server_id="srv-1")).level_for("member") == "standard"

    def test_an_override_for_a_server_not_listed_changes_nothing(self):
        trust_signed_team_rules("ops-team", rules(servers={
            "gone-server": {"role_levels": {"member": "readonly"}},
        }))
        assert rules_for(shared_row(server_id="srv-1")).level_for("member") == "standard"

    def test_the_guard_applies_the_server_override(self):
        trust_signed_team_rules("ops-team", rules(servers={
            "srv-2": {"role_levels": {"member": "readonly"}},
        }))
        guard = guard_for_target(
            shared_row(server_id="srv-2"), "dangerous", BUILTIN_ALLOWLIST, BUILTIN_BLOCKLIST,
        )
        assert guard.level == "readonly"
        # The override holds on this server only, so the refusal names it.
        assert guard.refusal("run_command", "uptime") == (
            "Blocked: on team Ops's shared server web-1 your agents run at the readonly "
            "level (set by the team), and running commands is not available there."
        )

    def test_a_server_override_for_other_roles_leaves_the_refusal_team_wide(self):
        trust_signed_team_rules("ops-team", rules(
            role_levels={"member": "readonly"},
            servers={"srv-2": {"role_levels": {"owner": "readonly"}}},
        ))
        guard = guard_for_target(
            shared_row(server_id="srv-2"), "dangerous", BUILTIN_ALLOWLIST, BUILTIN_BLOCKLIST,
        )
        assert guard.refusal("run_command", "uptime").startswith(
            "Blocked: on team Ops's shared servers your agents run at the readonly level"
        )

    def test_a_refusal_naming_the_server_of_an_unnamed_team_is_a_team_refusal(self):
        trust_signed_team_rules("ops-team", rules(servers={
            "srv-2": {"role_levels": {"member": "readonly"}},
        }))
        row = {**shared_row(server_id="srv-2"), "team_name": ""}
        row["team_slug"] = "ops-team"
        guard = guard_for_target(row, "dangerous", BUILTIN_ALLOWLIST, BUILTIN_BLOCKLIST)
        refusal = guard.refusal("run_command", "uptime")
        assert "shared server web-1 your agents" in refusal
        assert is_team_refusal(refusal)

    def test_explicit_rules_with_a_server_override_are_applied_too(self):
        explicit = TeamRules(servers=MappingProxyType({"srv-2": {"member": "readonly"}}))
        guard = guard_for_target(
            shared_row(server_id="srv-2"), "dangerous", BUILTIN_ALLOWLIST, BUILTIN_BLOCKLIST,
            explicit,
        )
        assert guard.level == "readonly"
        assert guard.server == "web-1"


def team_guard(role="member", level="dangerous", allowlist=BUILTIN_ALLOWLIST,
               blocklist=BUILTIN_BLOCKLIST, server_id="srv-1"):
    return guard_for_target(shared_row(role, server_id), level, allowlist, blocklist)


class TestTeamGuardOnSignedRules:
    def test_the_stricter_of_the_team_and_the_local_level_applies(self):
        trust_signed_team_rules("ops-team", rules(role_levels={
            "owner": "dangerous", "member": "dangerous", "viewer": "readonly",
        }))
        assert team_guard("member", "standard").level == "standard"
        assert team_guard("member", "dangerous").level == "dangerous"
        assert team_guard("viewer", "dangerous").level == "readonly"
        assert team_guard("member", "readonly").level == "readonly"

    def test_a_viewer_is_readonly_by_default(self):
        trust_signed_team_rules("ops-team")
        guard = team_guard("viewer")
        assert guard.refusal("run_command", "uptime") == (
            "Blocked: on team Ops's shared servers your agents run at the readonly "
            "level (set by the team), and running commands is not available there."
        )
        assert guard.refusal("check_status") is None

    @pytest.mark.parametrize("role", ["guest", "", None, "member-ish"])
    def test_an_unknown_role_is_readonly(self, role):
        trust_signed_team_rules("ops-team", rules(role_levels={
            "owner": "dangerous", "admin": "dangerous", "member": "dangerous",
            "viewer": "dangerous",
        }))
        assert team_guard(role).level == "readonly"
        assert team_guard(" Member ").level == "dangerous"

    def test_the_team_allowlist_meets_the_local_one(self):
        trust_signed_team_rules("ops-team", rules(command_allowlist=["uptime", "systemctl"]))
        local = [*BUILTIN_ALLOWLIST, "systemctl"]
        assert team_guard(allowlist=local).refusal("run_command", "systemctl status nginx") is None
        assert team_guard().refusal("run_command", "systemctl status nginx") is not None
        assert team_guard(allowlist=local).refusal("run_command", "ls /") is not None

    def test_allowlist_names_are_exact_not_prefixes(self):
        trust_signed_team_rules("ops-team", rules(command_allowlist=["up", "Uptime"]))
        guard = team_guard(allowlist=["up", "uptime", "Uptime"])
        assert guard.refusal("run_command", "uptime") is not None
        assert guard.refusal("run_command", "sudo uptime") is not None

    def test_a_team_pattern_is_added_to_the_local_blocklist(self):
        trust_signed_team_rules("ops-team", rules(command_blocklist=[r"\buptime\b"]))
        refusal = team_guard().refusal("run_command", "uptime")
        assert refusal.endswith("it matches the blocked pattern \\buptime\\b.")

    def test_an_unusable_team_pattern_refuses_every_command(self):
        status = trust_signed_team_rules("ops-team", rules(command_blocklist=["x(", r"\bcurl\b"]))
        assert status.rules.unusable_pattern() == "x("
        guard = team_guard()
        assert guard.refusal("run_command", "uptime") == (
            "Blocked: on team Ops's shared servers your agents run at the standard "
            "level (set by the team), and no command can run there because Servonaut "
            "cannot use the team's blocked pattern 'x(' (a team owner or admin can change it)."
        )
        assert guard.refusal(
            "run_command", "tail -n 5 /var/log/syslog", requested_as="reading logs",
        ).endswith("and reading logs is not allowed there because Servonaut cannot use "
                   "the team's blocked pattern 'x(' (a team owner or admin can change it).")
        # Other tools keep the team's level.
        assert guard.refusal("check_status") is None
        assert guard.refusal("get_server_info") is None
        # The guard itself refuses too, whoever asks it.
        assert guard.guard.check_command("uptime")[0] is False

    @pytest.mark.parametrize("pattern", ["a{99999999999}", "(" * 5000 + ")" * 5000, "[z-a]"])
    def test_any_pattern_servonaut_cannot_compile_is_unusable(self, pattern):
        trust_signed_team_rules("ops-team", rules(command_blocklist=[pattern]))
        assert team_guard().refusal("run_command", "uptime").startswith(
            "Blocked: on team Ops's shared servers"
        )

    def test_an_unusable_pattern_on_a_readonly_level_names_the_level(self):
        trust_signed_team_rules("ops-team", rules(command_blocklist=["x("]))
        refusal = team_guard("viewer").refusal("run_command", "uptime")
        assert refusal.endswith("and running commands is not available there.")


class TestFallbackRefusals:
    def test_a_refusal_says_the_rules_are_not_loaded(self):
        guard = team_guard("owner")
        refusal = guard.refusal("run_command", "uptime")
        assert refusal == (
            "Blocked: on team Ops's shared servers your agents run at the readonly "
            "level (because the team's agent rules have not been loaded yet), and "
            "running commands is not available there."
        )
        assert is_team_refusal(refusal)

    def test_a_refusal_says_the_rules_expired(self, monkeypatch):
        clock = Clock()
        trust_test_key()
        store = new_store(clock=clock)
        monkeypatch.setattr(team_policy, "_default_store", store)
        store.apply_response(team_row("ops-team"), response(signed()))
        clock.advance(2 * LIFETIME)

        refusal = team_guard("owner").refusal("run_command", "uptime")
        assert "(because the team's agent rules expired and could not be refreshed; " \
               "check that you are online and signed in)" in refusal

    def test_a_refusal_asks_for_an_update_when_no_key_is_known(self, monkeypatch):
        store = new_store()
        monkeypatch.setattr(team_policy, "_default_store", store)
        store.apply_response(team_row("ops-team"), response(signed()))

        refusal = team_guard("admin").refusal("transfer_file")
        assert "(because this Servonaut cannot verify the team's agent rules; " \
               "update Servonaut)" in refusal

    def test_a_refusal_says_the_rules_could_not_be_verified(self, monkeypatch):
        trust_test_key()
        store = new_store()
        monkeypatch.setattr(team_policy, "_default_store", store)
        good = signed()
        store.apply_response(team_row("ops-team"), response({**good, "signatures": [
            {"key_id": TEST_KEY_ID, "signature": b64url(b"\x01" * 64)},
        ]}))

        refusal = team_guard().refusal("run_command", "uptime")
        assert "(because the team's agent rules could not be verified)" in refusal

    def test_a_stricter_local_level_is_still_named_as_the_setter(self):
        trust_signed_team_rules("ops-team")
        refusal = team_guard(level="readonly").refusal("run_command", "uptime")
        assert "(set by your MCP settings)" in refusal

    def test_owners_fall_back_to_readonly_too(self):
        assert team_guard("owner").level == "readonly"
