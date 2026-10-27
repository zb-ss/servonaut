"""Matching vault SSH keys to servers by name, and binding them in one go."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from servonaut.services.vault.auto_bind import (
    ALREADY_BOUND,
    AMBIGUOUS,
    AutoBindRow,
    CHECK_FAILED,
    FETCH_FAILED,
    FETCHED,
    HOST_KEY_MISMATCH,
    MATCHED_BY_KEY_FILE,
    MATCHED_BY_KEY_PAIR,
    MATCHED_BY_SERVER_NAME,
    NO_ADDRESS,
    NO_HOST_KEYS,
    NO_KEY,
    NO_LOGIN,
    READY,
    _HOST_KEY_VISITS,
    apply_auto_bind,
    fetch_host_keys_for_rows,
    match_ssh_key,
    normalize_key_name,
    plan_auto_bind,
)
from servonaut.services.vault.crypto import ssh_public_fingerprint
from servonaut.services.vault.ec2_host_keys import (
    BEGIN_FINGERPRINTS,
    BEGIN_KEYS,
    END_FINGERPRINTS,
    END_KEYS,
    MAX_CONSOLE_OUTPUT_CHARS,
    parse_ec2_console_output,
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


def _make_key() -> str:
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")


def test_parse_ec2_console_output_keys_block() -> None:
    key1 = _make_key()
    console = f"boot log\n{BEGIN_KEYS}\n{key1}\n{END_KEYS}\nkernel ready"
    res = parse_ec2_console_output(console)

    assert res.verified is True
    assert res.keys == [key1]
    assert res.has_keys_block is True
    assert res.source == "verified by AWS console output"
    assert res.error is None


def test_parse_ec2_console_output_fingerprints_only() -> None:
    key1 = _make_key()
    fp1 = ssh_public_fingerprint(key1)
    console = f"boot log\n{BEGIN_FINGERPRINTS}\n256 {fp1} root@ip-10-0-0-1 (ED25519)\n{END_FINGERPRINTS}\nready"
    res = parse_ec2_console_output(console)

    assert res.verified is False
    assert res.has_keys_block is False
    assert res.has_fingerprints_block is True
    assert res.fingerprints.get("ED25519") == fp1
    assert res.source == "AWS console output"


def test_parse_ec2_console_output_agreeing_keys_and_fingerprints() -> None:
    key1 = _make_key()
    fp1 = ssh_public_fingerprint(key1)
    console = (
        f"{BEGIN_FINGERPRINTS}\n256 {fp1} root@ip-10-0-0-1 (ED25519)\n{END_FINGERPRINTS}\n"
        f"{BEGIN_KEYS}\n{key1}\n{END_KEYS}"
    )
    res = parse_ec2_console_output(console)

    assert res.verified is True
    assert res.keys == [key1]
    assert res.has_keys_block is True
    assert res.has_fingerprints_block is True


def test_parse_ec2_console_output_disagreeing_keys_and_fingerprints() -> None:
    key1 = _make_key()
    other_fp = "SHA256:dGhpcy1pcy1hLWZha2UtZmluZ2VycHJpbnQtdmFsdWU"
    console = (
        f"{BEGIN_FINGERPRINTS}\n256 {other_fp} root@ip-10-0-0-1 (ED25519)\n{END_FINGERPRINTS}\n"
        f"{BEGIN_KEYS}\n{key1}\n{END_KEYS}"
    )
    res = parse_ec2_console_output(console)

    assert res.verified is False
    assert "disagree" in (res.error or "")


def test_parse_ec2_console_output_multiple_blocks_agreement_and_disagreement() -> None:
    key1 = _make_key()
    key2 = _make_key()

    # Agreeing multiple blocks: uses last/first
    agreeing = f"{BEGIN_KEYS}\n{key1}\n{END_KEYS}\n{BEGIN_KEYS}\n{key1}\n{END_KEYS}"
    res_agree = parse_ec2_console_output(agreeing)
    assert res_agree.verified is True
    assert res_agree.keys == [key1]

    # Disagreeing multiple blocks: unverified
    disagreeing = f"{BEGIN_KEYS}\n{key1}\n{END_KEYS}\n{BEGIN_KEYS}\n{key2}\n{END_KEYS}"
    res_disagree = parse_ec2_console_output(disagreeing)
    assert res_disagree.verified is False
    assert "disagree" in (res_disagree.error or "")


def test_parse_ec2_console_output_edge_cases() -> None:
    # Empty output
    empty_res = parse_ec2_console_output("")
    assert empty_res.verified is False
    assert "empty" in (empty_res.error or "")

    # Oversized output
    oversized = "a" * (MAX_CONSOLE_OUTPUT_CHARS + 10)
    over_res = parse_ec2_console_output(oversized)
    assert over_res.verified is False
    assert "size limit" in (over_res.error or "")

    # Rotated output (no markers)
    rotated = "Linux ip-10-0-0-1 login prompt\nUbuntu 24.04 LTS"
    rot_res = parse_ec2_console_output(rotated)
    assert rot_res.verified is False
    assert "no longer holds" in (rot_res.error or "")

    # MD5-only fingerprints (no SHA256)
    md5_console = (
        f"{BEGIN_FINGERPRINTS}\n"
        "2048 01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef root@ip (RSA)\n"
        f"{END_FINGERPRINTS}"
    )
    md5_res = parse_ec2_console_output(md5_console)
    assert md5_res.verified is False
    assert "no longer holds" in (md5_res.error or "")

    # Junk inside KEYS block
    junk_console = f"{BEGIN_KEYS}\nnot a valid key line\n{END_KEYS}"
    junk_res = parse_ec2_console_output(junk_console)
    assert junk_res.verified is False
    assert "no longer holds" in (junk_res.error or "")


class _VisitService(_Service):
    def __init__(self, *, visits=None, fail_visit=(), mock_keys=None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.visits: list[str] = []
        self.fail_visit = set(fail_visit)
        self.active_concurrency = 0
        self.max_concurrency = 0
        self.mock_keys = dict(mock_keys or {})

    async def visit_for_host_key(self, instance, login=None, known_hosts_path=None):
        import asyncio

        self.active_concurrency += 1
        self.max_concurrency = max(self.max_concurrency, self.active_concurrency)
        try:
            await asyncio.sleep(0.01)
            inst_id = instance.get("id") or ""
            self.visits.append(inst_id)
            if inst_id in self.fail_visit:
                return "connection timeout"
            if known_hosts_path and inst_id in self.mock_keys:
                host = instance.get("public_ip") or instance.get("name") or inst_id
                key = self.mock_keys[inst_id]
                with open(known_hosts_path, "a") as f:
                    f.write(f"{host} {key}\n")
            return None
        finally:
            self.active_concurrency -= 1


@pytest.mark.asyncio
async def test_fetch_host_keys_aws_keys_block_skips_ssh_visit() -> None:
    key1 = _make_key()
    server = _server("i-aws-1", "web-1")
    keys = [_key("k1", "web-1")]
    service = _VisitService()

    rows = await plan_auto_bind(service, [server], keys, host_keys_for=lambda *_: [])
    assert rows[0].status == NO_HOST_KEYS

    console = f"{BEGIN_KEYS}\n{key1}\n{END_KEYS}"
    await fetch_host_keys_for_rows(
        service, rows, console_output_reader=lambda inst: console,
    )

    row = rows[0]
    assert row.status == FETCHED
    assert row.ready is True
    assert row.verified is True
    assert row.verification_source == "verified by AWS console output"
    assert row.host_keys == [key1]
    # No visit was made!
    assert service.visits == []


@pytest.mark.asyncio
async def test_fetch_host_keys_aws_fingerprints_match_and_mismatch() -> None:
    key_match = _make_key()
    fp_match = ssh_public_fingerprint(key_match)

    key_differ = _make_key()
    # Different key than console recorded
    key_differ_actual = _make_key()

    server_ok = _server("i-ok", "web-1")
    server_bad = _server("i-bad", "web-2")
    keys = [_key("k1", "web-1"), _key("k2", "web-2")]
    service = _VisitService()

    rows = await plan_auto_bind(service, [server_ok, server_bad], keys, host_keys_for=lambda *_: [])

    consoles = {
        "i-ok": f"{BEGIN_FINGERPRINTS}\n256 {fp_match} root@ip (ED25519)\n{END_FINGERPRINTS}",
        "i-bad": f"{BEGIN_FINGERPRINTS}\n256 {ssh_public_fingerprint(key_differ)} root@ip (ED25519)\n{END_FINGERPRINTS}",
    }
    trusted = {
        "i-ok": [key_match],
        "i-bad": [key_differ_actual],
    }

    await fetch_host_keys_for_rows(
        service,
        rows,
        console_output_reader=lambda inst: consoles[inst["id"]],
        host_keys_for=lambda inst, *_: trusted[inst["id"]],
    )

    by_id = {row.instance["id"]: row for row in rows}

    ok_row = by_id["i-ok"]
    assert ok_row.status == FETCHED
    assert ok_row.ready is True
    assert ok_row.verified is True
    assert ok_row.verification_source == "verified by AWS console output"

    bad_row = by_id["i-bad"]
    assert bad_row.status == HOST_KEY_MISMATCH
    assert bad_row.status_label == "host key differs from AWS"
    assert bad_row.ready is False
    assert bad_row.verified is False
    assert bad_row.status_text == (
        "The server answered with a different host key than AWS recorded at first boot: "
        "do not bind, check the server."
    )


@pytest.mark.asyncio
async def test_fetch_host_keys_bounded_concurrency_and_per_row_failure() -> None:
    servers = [_server(f"i-{n}", f"web-{n}") for n in range(10)]
    keys = [_key(f"k{n}", f"web-{n}") for n in range(10)]
    service = _VisitService(fail_visit={"i-3"})
    trusted_key = _make_key()

    rows = await plan_auto_bind(service, servers, keys, host_keys_for=lambda *_: [])
    assert all(r.status == NO_HOST_KEYS for r in rows)

    # Empty console output -> forces SSH visit for all
    await fetch_host_keys_for_rows(
        service,
        rows,
        console_output_reader=lambda inst: "",
        host_keys_for=lambda *_: [trusted_key],
        max_concurrency=4,
    )

    assert service.max_concurrency <= 4
    by_id = {row.instance["id"]: row for row in rows}

    failing = by_id["i-3"]
    assert failing.status == FETCH_FAILED
    assert failing.ready is False
    assert "connection timeout" in failing.status_text

    success = [r for r in rows if r.instance["id"] != "i-3"]
    assert len(success) == 9
    assert all(r.status == FETCHED and r.ready is True for r in success)
    assert all(r.verified is False for r in success)


@pytest.mark.asyncio
async def test_fetch_host_keys_non_aws_server() -> None:
    server = {"id": "ovh-1", "name": "web-1", "provider": "ovh", "public_ip": "198.51.100.10"}
    keys = [_key("k1", "web-1")]
    service = _VisitService()
    trusted_key = _make_key()

    rows = await plan_auto_bind(service, [server], keys, host_keys_for=lambda *_: [])
    assert rows[0].status == NO_HOST_KEYS

    await fetch_host_keys_for_rows(
        service,
        rows,
        host_keys_for=lambda *_: [trusted_key],
    )

    row = rows[0]
    assert row.status == FETCHED
    assert row.ready is True
    assert row.verified is False
    assert "compare with the server's console or your provider" in (row.verification_source or "")


def test_parse_keys_block_normalizes_and_validates() -> None:
    from servonaut.services.vault.bindings import VaultBindingService

    key1 = _make_key()
    key2 = _make_key()
    raw_console = (
        f"{BEGIN_KEYS}\n"
        f"{key1} root@ip-10-0-0-1 (first boot comment)\n"
        f"{key2}\n"
        f"{END_KEYS}\n"
    )
    res = parse_ec2_console_output(raw_console)
    assert res.has_keys_block is True
    assert len(res.keys) == 2
    for k in res.keys:
        assert len(k.split()) == 2
    # Verify through real VaultBindingService._validate_host_keys
    VaultBindingService._validate_host_keys(res.keys)


def test_parse_fingerprints_handles_trailing_plus_and_slash() -> None:
    # 43 chars base64 sha256 ending in + and /
    fp_plus = "SHA256:" + "A" * 42 + "+"
    fp_slash = "SHA256:" + "B" * 42 + "/"
    raw_console = (
        f"{BEGIN_FINGERPRINTS}\n"
        f"256 {fp_plus} root@host (ECDSA)\n"
        f"256 {fp_slash}= root@host (ED25519)\n"
        f"{END_FINGERPRINTS}\n"
    )
    res = parse_ec2_console_output(raw_console)
    assert res.has_fingerprints_block is True
    assert res.fingerprints.get("ECDSA") == fp_plus
    assert res.fingerprints.get("ED25519") == fp_slash


@pytest.mark.asyncio
async def test_apply_auto_bind_skips_unreviewed_fetched_rows() -> None:
    server = _server("i-unrev", "web-unrev")
    key = _make_key()
    row = AutoBindRow(
        instance=server,
        status=FETCHED,
        match=match_ssh_key(server, [_key("k1", "web-unrev")]),
        host="198.51.100.99",
        port=22,
        login="ubuntu",
        host_keys=[key],
        verified=False,
    )
    service = _Service()

    # Without reviewed_fetched=True -> skipped
    await apply_auto_bind(service, [row], vault_id="v1", reviewed_fetched=False)
    assert row.result == "not reviewed"
    assert service.bind_personal.call_count == 0

    # With reviewed_fetched=True -> bound
    await apply_auto_bind(service, [row], vault_id="v1", reviewed_fetched=True)
    assert row.result == "bound"
    assert service.bind_personal.call_count == 1


def test_remove_recorded_host_key(tmp_path, monkeypatch) -> None:
    from servonaut.services.ssh_host_keys import trusted_host_keys
    from servonaut.services.vault.ec2_host_keys import remove_recorded_host_key

    fake_kh = tmp_path / "known_hosts"
    fake_kh.write_text("198.51.100.7 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureHostKeyFixtureHostKeyFixtureHostK\n")
    fake_kh.chmod(0o600)

    empty_user_kh = tmp_path / "user_known_hosts"
    monkeypatch.setattr("servonaut.services.vault.ec2_host_keys.servonaut_known_hosts_path", lambda: fake_kh)
    monkeypatch.setattr("servonaut.services.ssh_host_keys.servonaut_known_hosts_path", lambda: fake_kh)
    monkeypatch.setattr("servonaut.services.ssh_host_keys.user_known_hosts_path", lambda: empty_user_kh)

    inst = {"id": "i-bad", "name": "web-2"}
    assert len(trusted_host_keys(inst, "198.51.100.7", None)) == 1

    ok = remove_recorded_host_key(inst, "198.51.100.7", 22)
    assert ok is True
    assert trusted_host_keys(inst, "198.51.100.7", None) == []


@pytest.mark.asyncio
async def test_team_auto_bind_matches_own_key_pair_first_then_server_name() -> None:
    own_1 = {"id": "i-1", "name": "web-1", "key_name": "kp-shared-1", "public_ip": "198.51.100.1"}
    shared_1 = {"id": "srv-1", "name": "web-1", "is_shared": True, "team_slug": "devs", "hostname": "198.51.100.1", "instance_id": "i-1", "login_user": "ubuntu"}
    own_2 = {"id": "i-2", "name": "db-1", "key_name": "other-key", "public_ip": "198.51.100.2"}
    shared_2 = {"id": "srv-2", "name": "db-1", "is_shared": True, "team_slug": "devs", "hostname": "198.51.100.2", "instance_id": "i-2", "login_user": "ubuntu"}

    service = _Service()
    key_kp = _key("k1", "kp-shared-1")
    key_name = _key("k2", "db-1")

    rows = await plan_auto_bind(
        service,
        [own_1, own_2, shared_1, shared_2],
        [key_kp, key_name],
        team="devs",
        host_keys_for=lambda *_: [HOST_KEY],
    )

    by_id = {r.instance["id"]: r for r in rows}
    assert len(by_id) == 2
    assert by_id["srv-1"].match.item_id == "k1"
    assert by_id["srv-1"].match.matched_by == MATCHED_BY_KEY_PAIR
    assert by_id["srv-2"].match.item_id == "k2"
    assert by_id["srv-2"].match.matched_by == MATCHED_BY_SERVER_NAME


@pytest.mark.asyncio
async def test_team_auto_bind_existing_team_binding_is_never_replaced() -> None:
    shared = {
        "id": "srv-1",
        "name": "web-1",
        "is_shared": True,
        "team_slug": "devs",
        "hostname": "198.51.100.1",
        "login_user": "ubuntu",
        "credential_binding": {"source": "servonaut_vault", "vault_id": "tv1"},
    }
    service = _Service()
    rows = await plan_auto_bind(
        service,
        [shared],
        [_key("k1", "web-1")],
        team="devs",
        host_keys_for=lambda *_: [HOST_KEY],
    )
    row = rows[0]
    assert row.status == ALREADY_BOUND
    assert row.ready is False
    assert row.status_label == "has a team key"
    assert "Already has a team key: team keys are never replaced automatically." in row.status_text


@pytest.mark.asyncio
async def test_team_auto_bind_login_fallbacks_and_no_login() -> None:
    shared_a = {"id": "srv-a", "name": "web-a", "is_shared": True, "team_slug": "devs", "hostname": "198.51.100.1", "login_user": "admin"}
    own_b = {"id": "i-b", "name": "web-b", "public_ip": "198.51.100.2"}
    shared_b = {"id": "srv-b", "name": "web-b", "is_shared": True, "team_slug": "devs", "hostname": "198.51.100.2", "instance_id": "i-b"}
    shared_c = {"id": "srv-c", "name": "web-c", "is_shared": True, "team_slug": "devs", "hostname": "198.51.100.3"}

    service = _Service(logins={"i-b": "ubuntu"})
    keys = [_key("ka", "web-a"), _key("kb", "web-b"), _key("kc", "web-c")]

    rows = await plan_auto_bind(
        service,
        [shared_a, own_b, shared_b, shared_c],
        keys,
        team="devs",
        host_keys_for=lambda *_: [HOST_KEY],
    )
    by_id = {r.instance["id"]: r for r in rows}
    assert by_id["srv-a"].login == "admin" and by_id["srv-a"].status == READY
    assert by_id["srv-b"].login == "ubuntu" and by_id["srv-b"].status == READY
    assert by_id["srv-c"].status == NO_LOGIN
    assert "set the login on the shared server (Teams → Shared Servers)" in by_id["srv-c"].status_text


@pytest.mark.asyncio
async def test_team_auto_bind_applies_via_service_bind() -> None:
    server = {"id": "srv-1", "name": "web-1", "is_shared": True, "team_slug": "devs", "hostname": "198.51.100.1"}
    row = AutoBindRow(
        instance=server,
        status=READY,
        match=match_ssh_key(server, [_key("k1", "web-1")]),
        host="198.51.100.1",
        port=22,
        login="admin",
        host_keys=[HOST_KEY],
        team="devs",
    )
    service = _Service()
    service.bind = AsyncMock(return_value={"source": "servonaut_vault"})

    await apply_auto_bind(service, [row], vault_id="tv-1", team="devs")
    assert row.result == "bound"
    service.bind.assert_awaited_once_with(
        vault_id="tv-1",
        server="srv-1",
        item_id="k1",
        team="devs",
        login="admin",
        pin_host_key=False,
        host_keys=[HOST_KEY],
        replace_existing=False,
    )


@pytest.mark.asyncio
async def test_fetch_host_keys_aws_fingerprints_mismatch_message() -> None:
    key_differ = _make_key()
    key_differ_actual = _make_key()
    server_bad = _server("i-bad", "web-2")
    keys = [_key("k2", "web-2")]
    service = _VisitService()

    rows = await plan_auto_bind(service, [server_bad], keys, host_keys_for=lambda *_: [])
    console = f"{BEGIN_FINGERPRINTS}\n256 {ssh_public_fingerprint(key_differ)} root@ip (ED25519)\n{END_FINGERPRINTS}"

    await fetch_host_keys_for_rows(
        service,
        rows,
        console_output_reader=lambda inst: console,
        host_keys_for=lambda inst, *_: [key_differ_actual],
    )

    bad_row = rows[0]
    assert bad_row.status == HOST_KEY_MISMATCH
    assert bad_row.status_text == (
        "The server answered with a different host key than AWS recorded at first boot: "
        "do not bind, check the server."
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exc", "expected_source"),
    [
        (
            Exception("ClientError: An error occurred (AccessDenied) when calling ec2:GetConsoleOutput for arn:aws:iam::123456789012:role/admin"),  # leak-guard:allow (AWS documentation account id)
            "not verified: no permission to read the console output (ec2:GetConsoleOutput)",
        ),
        (
            Exception("UnauthorizedOperation: You are not authorized to perform this operation on account 123456789012"),
            "not verified: no permission to read the console output (ec2:GetConsoleOutput)",
        ),
        (
            Exception("RequestLimitExceeded: Request limit exceeded for instance i-bad in region us-east-1"),
            "not verified: AWS throttled the console read; fetch again later",
        ),
        (
            Exception("ThrottlingException: Rate exceeded for account 999999999999"),
            "not verified: AWS throttled the console read; fetch again later",
        ),
        (
            Exception("InternalError: Failed to fetch console output for arn:aws:ec2:us-east-1:123456789012:instance/i-bad"),  # leak-guard:allow (AWS documentation account id)
            "not verified: could not read the console output",
        ),
    ],
)
async def test_fetch_host_keys_aws_console_error_mapping(exc: Exception, expected_source: str) -> None:
    server = _server("i-1", "web-1")
    keys = [_key("k1", "web-1")]
    service = _VisitService()

    rows = await plan_auto_bind(service, [server], keys, host_keys_for=lambda *_: [])

    def faulty_reader(inst):
        raise exc

    await fetch_host_keys_for_rows(
        service,
        rows,
        console_output_reader=faulty_reader,
        host_keys_for=lambda inst, *_: [_make_key()],
    )

    row = rows[0]
    assert row.status == FETCHED
    assert row.verified is False
    assert row.verification_source == expected_source
    assert "123456789012" not in (row.verification_source or "")
    assert "arn:aws" not in (row.verification_source or "")
    assert "123456789012" not in (row.fetch_error or "")
    assert "arn:aws" not in (row.fetch_error or "")


def test_verify_fetched_host_keys_unlisted_key_family() -> None:
    from cryptography.hazmat.primitives.asymmetric import ec
    from servonaut.services.vault.ec2_host_keys import EC2ConsoleHostKeys, verify_fetched_host_keys

    ed_key = _make_key()
    fp_ed = ssh_public_fingerprint(ed_key)
    console_res = EC2ConsoleHostKeys(
        source="AWS console output (first-boot fingerprints)",
        fingerprints={"ED25519": fp_ed},
        has_fingerprints_block=True,
    )

    priv_ec = ec.generate_private_key(ec.SECP256R1())
    ecdsa_key = priv_ec.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")

    verified, reason = verify_fetched_host_keys([ecdsa_key], console_res)
    assert verified is False
    assert reason == "not verified: console output does not list a fingerprint for ECDSA"


@pytest.mark.asyncio
async def test_fetch_host_keys_mismatch_does_not_pollute_known_hosts(tmp_path, monkeypatch) -> None:
    from servonaut.services.ssh_host_keys import trusted_host_keys

    fake_kh = tmp_path / "known_hosts"
    initial_content = "198.51.100.7 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureHostKeyFixtureHostKeyFixtureHostK\n"
    fake_kh.write_text(initial_content)
    fake_kh.chmod(0o600)
    empty_user_kh = tmp_path / "user_known_hosts"

    monkeypatch.setattr("servonaut.services.vault.ec2_host_keys.servonaut_known_hosts_path", lambda: fake_kh)
    monkeypatch.setattr("servonaut.services.ssh_host_keys.servonaut_known_hosts_path", lambda: fake_kh)
    monkeypatch.setattr("servonaut.services.ssh_host_keys.user_known_hosts_path", lambda: empty_user_kh)

    server = _server("i-bad", "web-2")
    server["public_ip"] = "198.51.100.7"
    keys = [_key("k2", "web-2")]
    key_visited = _make_key()
    service = _VisitService(mock_keys={"i-bad": key_visited})

    assert len(trusted_host_keys(server, "198.51.100.7", None)) == 1

    # Plan with no host keys so status is NO_HOST_KEYS
    rows = await plan_auto_bind(service, [server], keys, host_keys_for=lambda *_: [])
    assert rows[0].status == NO_HOST_KEYS

    # Console recorded a completely different fingerprint
    key_console = _make_key()
    console = f"{BEGIN_FINGERPRINTS}\n256 {ssh_public_fingerprint(key_console)} root@ip (ED25519)\n{END_FINGERPRINTS}"

    await fetch_host_keys_for_rows(
        service,
        rows,
        console_output_reader=lambda inst: console,
    )

    bad_row = rows[0]
    assert bad_row.status == HOST_KEY_MISMATCH
    assert bad_row.host_keys == []
    assert bad_row.status_text == (
        "The server answered with a different host key than AWS recorded at first boot: "
        "do not bind, check the server."
    )
    # Servonaut's known_hosts must be completely untouched and byte-identical!
    assert fake_kh.read_text() == initial_content


@pytest.mark.asyncio
async def test_fetch_host_keys_does_not_modify_permanent_known_hosts(tmp_path, monkeypatch) -> None:
    fake_kh = tmp_path / "known_hosts"
    fake_kh.write_text("")
    fake_kh.chmod(0o600)
    empty_user_kh = tmp_path / "user_known_hosts"

    monkeypatch.setattr("servonaut.services.vault.ec2_host_keys.servonaut_known_hosts_path", lambda: fake_kh)
    monkeypatch.setattr("servonaut.services.ssh_host_keys.servonaut_known_hosts_path", lambda: fake_kh)
    monkeypatch.setattr("servonaut.services.ssh_host_keys.user_known_hosts_path", lambda: empty_user_kh)

    server = {"id": "ovh-1", "name": "web-1", "provider": "ovh", "public_ip": "198.51.100.10"}
    keys = [_key("k1", "web-1")]
    visited_key = _make_key()
    service = _VisitService(mock_keys={"ovh-1": visited_key})

    rows = await plan_auto_bind(service, [server], keys, host_keys_for=lambda *_: [])
    assert rows[0].status == NO_HOST_KEYS

    await fetch_host_keys_for_rows(service, rows)

    row = rows[0]
    assert row.status == FETCHED
    assert row.host_keys == [visited_key]
    # Servonaut's permanent known_hosts must remain empty and unmodified!
    assert fake_kh.read_bytes() == b""


def test_auto_bind_row_no_host_keys_status_text_surface_override() -> None:
    from servonaut.services.vault.auto_bind import AutoBindRow, NO_HOST_KEYS, KeyMatch

    row = AutoBindRow(
        instance={"id": "i-1", "name": "web-1"},
        status=NO_HOST_KEYS,
        match=KeyMatch(item_id="k1", name="k1.pem", matched_by="server name"),
        login="ubuntu",
        host="198.51.100.1",
    )
    assert row.status_text_for("cli") == "No trusted host key yet: run with --fetch-host-keys to fetch and review it"
    assert row.status_text_for("tui") == "No trusted host key yet: press f (Fetch host keys) to fetch and review it"
    assert row.status_text == "No trusted host key yet: run with --fetch-host-keys to fetch and review it"


@pytest.mark.asyncio
async def test_team_auto_bind_refuses_when_server_bound_concurrently() -> None:
    server = {
        "id": "s-1",
        "name": "shared-1",
        "hostname": "198.51.100.7",
        "port": 22,
        "login_user": "ubuntu",
        "is_shared": True,
        "team_slug": "ops",
        "team_role": "admin",
    }
    keys = [_key("k1", "shared-1")]
    service = _Service()
    service.bind = AsyncMock(side_effect=VaultUserError("already has a team key: left alone"))

    rows = await plan_auto_bind(service, [server], keys, team="ops", host_keys_for=lambda *_: [HOST_KEY])
    assert len(rows) == 1 and rows[0].ready

    await apply_auto_bind(service, rows, vault_id="v", team="ops")

    assert rows[0].result == "already has a team key: left alone"
    service.bind.assert_awaited_once()
    assert service.bind.await_args.kwargs["replace_existing"] is False


@pytest.mark.asyncio
async def test_fetch_host_keys_type_error_in_visit_fails_row_without_retrying_or_polluting_known_hosts(
    tmp_path, monkeypatch
) -> None:
    fake_kh = tmp_path / "known_hosts"
    initial_content = "198.51.100.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureExistingHostKeyFixtureExisting\n"
    fake_kh.write_text(initial_content)
    fake_kh.chmod(0o600)
    empty_user_kh = tmp_path / "user_known_hosts"

    monkeypatch.setattr("servonaut.services.vault.ec2_host_keys.servonaut_known_hosts_path", lambda: fake_kh)
    monkeypatch.setattr("servonaut.services.ssh_host_keys.servonaut_known_hosts_path", lambda: fake_kh)
    monkeypatch.setattr("servonaut.services.ssh_host_keys.user_known_hosts_path", lambda: empty_user_kh)

    calls = 0

    class _TypeErrorService(_Service):
        async def visit_for_host_key(self, instance, login=None, known_hosts_path=None):
            nonlocal calls
            calls += 1
            raise TypeError("ssh_service.build_ssh_command() got an unexpected keyword argument 'record_to_known_hosts'")

    server = {"id": "ovh-1", "name": "web-1", "provider": "ovh", "public_ip": "198.51.100.10"}
    keys = [_key("k1", "web-1")]
    service = _TypeErrorService()

    rows = await plan_auto_bind(service, [server], keys, host_keys_for=lambda *_: [])
    assert rows[0].status == NO_HOST_KEYS

    await fetch_host_keys_for_rows(service, rows)

    row = rows[0]
    assert calls == 1
    assert row.status == FETCH_FAILED
    assert "unexpected keyword argument" in (row.fetch_error or "")
    assert fake_kh.read_text() == initial_content






