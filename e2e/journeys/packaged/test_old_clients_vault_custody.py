"""Journey: released 2.31-2.35 clients against an account whose Memory Sync key is in the vault.

The service keeps the key of a vault-custody account without a passphrase-wrapped
copy. A client from before vault custody cannot use that key, and must neither
enrol a second key nor rotate the account's key, nor crash: it fails closed.

Opt-in, because it installs five published releases: it runs only when
``SERVONAUT_E2E_OLD_CLIENT_VERSIONS`` names minors (for example
``2.31,2.32,2.33,2.34,2.35``) and their wheels are cached::

    python e2e/tools/fetch_previous_release.py --versions 2.31,2.32,2.33,2.34,2.35
    SERVONAUT_E2E_OLD_CLIENT_VERSIONS=2.31,2.32,2.33,2.34,2.35 \\
        pytest e2e/journeys/packaged/test_old_clients_vault_custody.py -q

Each release is installed into its own venv and run with its own classes by
``e2e/harness/release_scripts/custody_probe.py`` against the fake service.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any, Optional

import pytest

from e2e.harness.bootstrap import HARNESS_DIR, Sandbox
from e2e.harness.releases import ReleaseCache
from e2e.journeys.packaged import support
from e2e.tools import fetch_previous_release as fetcher

ENV_VERSIONS = "SERVONAUT_E2E_OLD_CLIENT_VERSIONS"
_NAMED = [part.strip() for part in os.environ.get(ENV_VERSIONS, "").split(",") if part.strip()]
# A single placeholder when unset, so the module collects and skips with its reason.
MINORS = _NAMED or ["unset"]
TUI_MINORS = [minor for minor in MINORS if minor in ("2.31", "2.35") or minor == "unset"]

pytestmark = [
    pytest.mark.e2e_pr,
    pytest.mark.timeout(900),
    pytest.mark.skipif(not _NAMED, reason=f"opt-in: set {ENV_VERSIONS} (see the module docstring)"),
]

PROBE_SCRIPT = HARNESS_DIR / "release_scripts" / "custody_probe.py"
PASSPHRASE = "Neutral-Passphrase-42-xyz"
NEW_PASSPHRASE = "Another-Neutral-Phrase-77-abc"
MEMORY = "/api/v1/memory"
KEYS_PATH = f"{MEMORY}/keys"
ROTATE_PATH = f"{MEMORY}/keys/rotate"
INSTANCE = "web-1"
PLAN = "teams"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _install(journey: Any, installs: Any, release_cache: ReleaseCache, minor: str) -> tuple[Sandbox, Any, Any]:
    """A fresh home and a venv with the newest published patch of *minor*."""
    release = release_cache.release(fetcher.custody_role(minor), journey.directory / "releases")
    sandbox = journey.new_sandbox()
    installs.offer(release.wheel, version=release.version)
    venv = installs.venv(sandbox)
    support.ok(venv.pip(sandbox, "install", f"servonaut=={release.version}"))
    assert support.reported_version(venv, sandbox) == release.version
    return sandbox, venv, release


def probe(installs: Any, sandbox: Sandbox, venv: Any, operation: str, **spec: Any) -> dict[str, Any]:
    """Run one probe operation with the installed release; return its JSON report."""
    spec_path = sandbox.base / f"probe-{operation}.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    result = installs.runner().run(
        sandbox, [str(venv.python), str(PROBE_SCRIPT), operation, str(spec_path)], timeout=180.0
    )
    # A crash of the probe process itself (no report) is a hole, not a clean failure.
    assert result.returncode == 0, f"{operation} crashed the release process:\n{result.describe()}"
    lines = [line for line in result.stdout.splitlines() if line.startswith("{")]
    assert lines, f"{operation} printed no report:\n{result.describe()}"
    return json.loads(lines[-1])


def sign_in(installs: Any, sandbox: Sandbox, venv: Any, fake_cloud: Any) -> None:
    """Sign the home in with the release's own ``AuthToken``."""
    import time

    access, refresh = fake_cloud.tokens()
    entitlements = fake_cloud.entitlements()
    now = time.time()
    token = {
        "access_token": access, "refresh_token": refresh, "expires_at": now + 3600,
        "plan": entitlements["plan"], "email": entitlements.get("email", ""),
        "entitlements": entitlements, "entitlements_fetched_at": now,
        "user_id": entitlements["user_id"],
    }
    report = probe(installs, sandbox, venv, "login", token=token)
    assert report["outcome"] == "ok", report


def seed_envelope(fake_cloud: Any, public_key_b64: str, module: str = "os") -> str:
    """An envelope of web-1 sealed to the account's key, stored through the fake's intake."""
    from servonaut.services.memory.crypto import encrypt_envelope

    uid = fake_cloud.entitlements()["user_id"]
    fake_cloud.memory.upsert_instance({"instance_id": INSTANCE})
    envelope = encrypt_envelope(
        b'{"observed": {"kernel": "6.1"}}', self_public_key=base64.b64decode(public_key_b64), self_user_id=uid,
    ).to_dict()
    result = fake_cloud.memory.accept([{
        "instance_id": INSTANCE, "module": module, "probed_at": "2030-01-01T00:00:00+00:00", **envelope,
    }])
    assert result["rejected"] == [], result
    return result["accepted"][0]["id"]


def key_writes(fake_cloud: Any) -> list[dict[str, Any]]:
    """Every request that tried to enrol or rotate a Memory Sync key."""
    return [
        entry for entry in fake_cloud.requests(method="POST")
        if entry["path"] in (KEYS_PATH, ROTATE_PATH)
    ]


def active_key(fake_cloud: Any) -> Optional[dict[str, Any]]:
    row = fake_cloud.memory.enrolled_key()
    return None if row is None else {k: row.get(k) for k in ("id", "fingerprint", "custody", "public_key")}


def keys_json(sandbox: Sandbox) -> Path:
    return sandbox.home / ".servonaut" / "memory" / "keys.json"


def evidence(fake_cloud: Any, *paths: str) -> str:
    """The request log lines for *paths*, for a failure message."""
    rows = [e for e in fake_cloud.requests() if e["path"] in paths]
    return "\n".join(f"{e['method']} {e['path']} -> {e['status']}" for e in rows)


def failed_cleanly(report: dict[str, Any], label: str) -> None:
    assert report["outcome"] == "error", f"{label} did not fail: {report}"
    assert report.get("error_type"), report


# ---------------------------------------------------------------------------
# Probes (a)-(e), (g) against a vault-custody account
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("minor", MINORS)
def test_old_client_fails_closed_on_a_vault_custody_account(
    minor, journey, fake_cloud, installs, release_cache, record_property
):
    fake_cloud.configure(plan=PLAN)
    sandbox, venv, release = _install(journey, installs, release_cache, minor)
    record_property("release", release.version)
    row = fake_cloud.memory.seed_vault_custody_key()
    snapshot = fake_cloud.configs.seed_vault_snapshot()
    seed_envelope(fake_cloud, row["public_key"])
    before = active_key(fake_cloud)
    assert before and before["custody"] == "vault"
    sign_in(installs, sandbox, venv, fake_cloud)
    results: dict[str, Any] = {}

    # (a) bootstrap with a passphrase provider and no keys.json
    results["a_bootstrap"] = probe(installs, sandbox, venv, "bootstrap", passphrase=PASSPHRASE)
    failed_cleanly(results["a_bootstrap"], "(a) bootstrap")
    # (c) rotate
    results["c_rotate"] = probe(installs, sandbox, venv, "rotate", passphrase=PASSPHRASE, new_passphrase=NEW_PASSPHRASE)
    failed_cleanly(results["c_rotate"], "(c) rotate_keypair")
    # (d) retrieval
    results["d_retrieval"] = probe(
        installs, sandbox, venv, "retrieval", passphrase=PASSPHRASE, instance_id=INSTANCE, module="os"
    )
    failed_cleanly(results["d_retrieval"], "(d) get_module")
    # (e) config pull of a vault snapshot (salt: null) fails closed
    assert snapshot["key_custody"] == "vault" and snapshot.get("salt") is None
    results["e_pull"] = probe(installs, sandbox, venv, "config_pull", passphrase=PASSPHRASE)
    failed_cleanly(results["e_pull"], "(e) config pull on salt: null")
    # (g) the summary passphrase form
    results["g_summary"] = probe(installs, sandbox, venv, "summary", passphrase=PASSPHRASE, instance_id=INSTANCE)
    failed_cleanly(results["g_summary"], "(g) dispatch_summary")
    assert results["g_summary"].get("stage") == "dispatch", results["g_summary"]
    assert fake_cloud.summaries.jobs() == [], "a summary job was recorded for a vault-custody key"

    state = probe(installs, sandbox, venv, "local_state")
    results["local_state"] = state
    results["key_writes"] = [f"{e['method']} {e['path']} -> {e['status']}" for e in key_writes(fake_cloud)]
    results["active_key_unchanged"] = active_key(fake_cloud) == before
    results["summary_jobs"] = len(fake_cloud.summaries.jobs())
    _write_results(journey, minor, results)

    # Section 7.5: nothing enrolled or rotated, the key is untouched, no key file appeared.
    successful = [e for e in key_writes(fake_cloud) if 200 <= e["status"] < 300]
    assert successful == [], "HOLE: a 2xx key write\n" + evidence(fake_cloud, KEYS_PATH, ROTATE_PATH)
    assert active_key(fake_cloud) == before, "HOLE: the active key changed"
    assert fake_cloud.memory.key_history() == []
    assert state["keys_json"] is False and not keys_json(sandbox).exists(), "a new keys.json appeared"
    assert state["marker"] is False


@pytest.mark.parametrize("minor", MINORS)
def test_a_leftover_keys_json_keeps_unlocking_with_the_same_key(
    minor, journey, fake_cloud, installs, release_cache
):
    fake_cloud.configure(plan=PLAN)
    sandbox, venv, release = _install(journey, installs, release_cache, minor)
    row = fake_cloud.memory.seed_vault_custody_key()
    seed_envelope(fake_cloud, row["public_key"])
    before = active_key(fake_cloud)
    uid = fake_cloud.entitlements()["user_id"]
    sign_in(installs, sandbox, venv, fake_cloud)

    key = {"private_key": row["private_key"], "public_key": row["public_key"],
           "fingerprint": row["fingerprint"], "user_id": uid}
    written = probe(installs, sandbox, venv, "write_keys_json", key=key, passphrase=PASSPHRASE)
    assert written["outcome"] == "ok", written
    envelopes_before = len(fake_cloud.memory.envelopes())

    # (b) the local cache still unlocks with the same key, and its uploads are accepted
    report = probe(installs, sandbox, venv, "bootstrap", passphrase=PASSPHRASE, upload=True)
    assert report["outcome"] == "ok", report
    assert report["is_configured"] is True
    assert report["upload"]["accepted"] == 1 and report["upload"]["rejected"] == [], report
    assert len(fake_cloud.memory.envelopes()) == envelopes_before + 1
    assert active_key(fake_cloud) == before
    assert key_writes(fake_cloud) == [], "the cache path made a key write\n" + evidence(fake_cloud, KEYS_PATH, ROTATE_PATH)
    # The wrap the release uploaded is sealed to the account's own (vault-custody) key.
    newest = fake_cloud.memory.envelopes(INSTANCE, "os")[-1]
    assert {w["fingerprint"] for w in newest["dek_wraps"]} == {before["fingerprint"]}
    cached = probe(installs, sandbox, venv, "local_state")["keys_json_fingerprint"]
    assert cached == before["fingerprint"]
    _write_results(journey, f"{minor}-leftover-keys-json", {
        "bootstrap": report, "key_writes": len(key_writes(fake_cloud)), "active_key_unchanged": True,
        "wrap_fingerprint_is_active_key": True,
    })


@pytest.mark.parametrize("minor", MINORS)
def test_the_passphrase_config_push_follows_the_second_switch(
    minor, journey, fake_cloud, installs, release_cache
):
    fake_cloud.configure(plan=PLAN)
    sandbox, venv, release = _install(journey, installs, release_cache, minor)
    fake_cloud.memory.seed_vault_custody_key()
    sign_in(installs, sandbox, venv, fake_cloud)

    accepted = probe(installs, sandbox, venv, "config_push", passphrase=PASSPHRASE)
    assert accepted["outcome"] == "ok", f"the passphrase push was refused while the switch is on: {accepted}"
    assert [s["key_custody"] for s in fake_cloud.configs.all()] == ["passphrase"]

    fake_cloud.memory.set_passphrase_custody(False)
    refused = probe(installs, sandbox, venv, "config_push", passphrase=PASSPHRASE)
    assert refused["outcome"] == "error", f"HOLE: the push was accepted with the switch off: {refused}"
    assert evidence(fake_cloud, "/api/v1/configs").splitlines()[-1].endswith("409"), evidence(fake_cloud, "/api/v1/configs")
    assert len(fake_cloud.configs.all()) == 1
    _write_results(journey, f"{minor}-config-push", {
        "switch_on": accepted["outcome"], "switch_off": refused["outcome"],
        "switch_off_error": refused.get("error"), "snapshots_stored": len(fake_cloud.configs.all()),
        "log": evidence(fake_cloud, "/api/v1/configs").splitlines(),
    })


@pytest.mark.parametrize("minor", MINORS)
def test_a_never_enrolled_account_gets_no_key_with_the_second_switch_off(
    minor, journey, fake_cloud, installs, release_cache
):
    fake_cloud.configure(plan=PLAN)
    sandbox, venv, release = _install(journey, installs, release_cache, minor)
    fake_cloud.memory.set_passphrase_custody(False)
    assert active_key(fake_cloud) is None
    sign_in(installs, sandbox, venv, fake_cloud)

    report = probe(installs, sandbox, venv, "bootstrap", passphrase=PASSPHRASE)
    failed_cleanly(report, "bootstrap of a never-enrolled account")
    writes = key_writes(fake_cloud)
    assert writes and all(e["status"] == 409 for e in writes), evidence(fake_cloud, KEYS_PATH)
    assert active_key(fake_cloud) is None, "HOLE: a key was enrolled with the second switch off"
    assert not keys_json(sandbox).exists()
    _write_results(journey, f"{minor}-never-enrolled", {
        "bootstrap": report, "key_writes": [e["status"] for e in writes], "key_row": None,
    })


def _write_results(journey: Any, label: str, results: dict[str, Any]) -> None:
    """Keep the per-probe reports with the journey's artifacts and print them (``-rP``) for the QA report."""
    journey.staging.mkdir(parents=True, exist_ok=True)
    text = json.dumps(results, indent=2)
    (journey.staging / f"old-client-{label}.json").write_text(text, encoding="utf-8")
    print(f"OLD-CLIENT-RESULT {label} {json.dumps(results, sort_keys=True)}")


# ---------------------------------------------------------------------------
# (f) the release's real app, opening Memory Sync and pressing the set-up button
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("minor", TUI_MINORS)
def test_the_old_tui_stays_up_and_shows_an_error(minor, journey, fake_cloud, installs, release_cache):
    fake_cloud.configure(plan=PLAN)
    sandbox, venv, release = _install(journey, installs, release_cache, minor)
    row = fake_cloud.memory.seed_vault_custody_key()
    before = active_key(fake_cloud)
    sign_in(installs, sandbox, venv, fake_cloud)
    # The release reads its passphrase from this variable, so no dialog is needed.
    installs.extra_env["SERVONAUT_MEMORY_PASSPHRASE"] = PASSPHRASE

    report = probe(installs, sandbox, venv, "tui")
    _write_results(journey, f"{minor}-tui", report)
    assert report["outcome"] == "ok", f"the old TUI crashed: {report}"
    assert report["setup_button_shown"] is True, report
    assert report["app_running"] is True, report
    assert report["passphrase_modal"] is False, report
    # Releases differ: some raise a toast, others write the error into the card.
    shown = report["toasts"] or [t for t in report["statics"] if "failed" in t.lower() or "error" in t.lower()]
    assert shown, (
        f"the old TUI showed no error after the set-up button: {report}\n"
        + evidence(fake_cloud, "/api/v1/memory/keys/me", KEYS_PATH, "/api/v1/memory/settings")
    )
    assert row["fingerprint"] == before["fingerprint"]
    assert [e for e in key_writes(fake_cloud) if 200 <= e["status"] < 300] == [], evidence(fake_cloud, KEYS_PATH, ROTATE_PATH)
    assert active_key(fake_cloud) == before
    assert not keys_json(sandbox).exists()


# ---------------------------------------------------------------------------
# `vault items` and `vault rotate` from the old release, over both new item types
# ---------------------------------------------------------------------------

# Runs with the checkout (it knows the item types): create both items in the
# personal vault the old release set up, then, after the old commands ran,
# read them back and compare. The keys are throwaway values kept in a file in
# the journey's directory; nothing secret is printed.
_ITEMS_SCRIPT = r'''
import asyncio, base64, hashlib, hmac, json, os, sys
from datetime import datetime, timezone
import nacl.public
from servonaut.services.vault.command_service import VaultCommandService
from servonaut.services.vault.items import CONFIG_KEY_ID_LABEL

mode, state_path = sys.argv[1], sys.argv[2]


async def main():
    service = VaultCommandService.from_local_session()
    keys = service.app_keys
    if mode == "create":
        pair = nacl.public.PrivateKey.generate()
        public = bytes(pair.public_key)
        config_key = os.urandom(32)
        now = datetime.now(timezone.utc).isoformat()
        memory = {
            "v": 1, "name": "Servonaut Memory Sync key", "user_id": 1,
            "public_key": base64.b64encode(public).decode(),
            "private_key": base64.b64encode(bytes(pair)).decode(),
            "public_fingerprint": hashlib.sha256(public).hexdigest(), "created_at": now,
        }
        config = {
            "v": 1, "name": "Servonaut config sync key", "key": base64.b64encode(config_key).decode(),
            "public_fingerprint": hmac.new(config_key, CONFIG_KEY_ID_LABEL, hashlib.sha256).hexdigest(),
            "created_at": now,
        }
        await keys.create("memory_key", memory)
        await keys.create("config_sync_key", config)
        with open(state_path, "w", encoding="utf-8") as handle:
            json.dump({"memory_key": memory, "config_sync_key": config}, handle)
        print(json.dumps({"vault_id": await keys.personal_vault_id(), "created": 2}))
        return
    with open(state_path, encoding="utf-8") as handle:
        expected = json.load(handle)
    same = {}
    for item_type, payload in expected.items():
        read = await keys.read(item_type, payload["public_fingerprint"])
        same[item_type] = read == payload
    print(json.dumps({"vault_id": await keys.personal_vault_id(), "payload_intact": same}))


asyncio.run(main())
'''


def _app_key_items(fake_cloud: Any, vault_id: str) -> dict[str, dict[str, Any]]:
    """The two key items as the fake stores them (ciphertext fingerprinted, not shown)."""
    import hashlib

    rows = {}
    for item_id, item in fake_cloud.vault._items.get(vault_id, {}).items():
        if item.get("type") not in ("memory_key", "config_sync_key"):
            continue
        rows[item_id] = {
            "type": item["type"], "revision": item.get("revision"), "deleted_at": item.get("deleted_at"),
            "public_fingerprint": item.get("public_fingerprint"),
            "ciphertext_sha256": hashlib.sha256(json.dumps(item, sort_keys=True, default=str).encode()).hexdigest(),
        }
    return rows


@pytest.mark.parametrize("minor", MINORS)
def test_old_vault_commands_leave_the_key_items_untouched(
    minor, journey, fake_cloud, installs, release_cache, servonaut_cmd
):
    import sys

    from e2e.harness.processes import run_cli
    from e2e.harness.vault_custody import setup_vault

    fake_cloud.configure(plan=PLAN)
    sandbox, venv, release = _install(journey, installs, release_cache, minor)
    sign_in(installs, sandbox, venv, fake_cloud)
    # The old release sets up its own vault (device key and recovery key as in the
    # vault journeys). The shared helper builds the child environment from the
    # journey, so the install's own variables are lent to it for this one call.
    install_env = installs.env(sandbox)
    lent = {k: v for k, v in install_env.items() if journey.child_env(sandbox).get(k) != v}
    journey.env_overrides.update(lent)
    try:
        setup_vault(journey, sandbox, [str(venv.console)])
    finally:
        for name in lent:
            journey.env_overrides.pop(name, None)

    def old(*args: str, stdin: Optional[str] = None) -> Any:
        return venv.run(sandbox, *args, timeout=120.0, stdin=stdin)

    state_path = sandbox.base / "custody-items.json"

    def checkout(mode: str) -> dict[str, Any]:
        result = run_cli(
            [sys.executable, "-c", _ITEMS_SCRIPT, mode, str(state_path)],
            env=journey.child_env(sandbox), cwd=sandbox.base, armed_log=journey.armed_log,
            timeout=120.0, log=journey.children,
        )
        assert result.returncode == 0, result.describe()
        return json.loads(result.stdout.strip().splitlines()[-1])

    created = checkout("create")
    vault_id = created["vault_id"]
    assert vault_id and created["created"] == 2
    secrets = [
        value for payload in json.loads(state_path.read_text(encoding="utf-8")).values()
        for name, value in payload.items() if name in ("private_key", "key")
    ]
    items_before = _app_key_items(fake_cloud, vault_id)
    assert {row["type"] for row in items_before.values()} == {"memory_key", "config_sync_key"}

    listed = old("vault", "items", "--vault", vault_id, "--json")
    rotated = old("vault", "rotate", "--vault", vault_id, "--yes", "--json")
    listed_after = old("vault", "items", "--vault", vault_id, "--json")
    try:
        listed_types = sorted(str(row.get("type")) for row in json.loads(listed.stdout).get("data", []))
    except (ValueError, AttributeError):
        listed_types = None
    report = {
        "items": {"returncode": listed.returncode, "types_listed": listed_types,
                  "stderr": listed.stderr[-300:]},
        "rotate": {"returncode": rotated.returncode, "stderr": rotated.stderr[-300:]},
        "items_after": {"returncode": listed_after.returncode},
    }
    _write_results(journey, f"{minor}-vault-cli", report)

    # Nothing from the new item types is printed: no key material, by any command.
    for result in (listed, rotated, listed_after):
        if any(secret in result.stdout or secret in result.stderr for secret in secrets):
            pytest.fail("HOLE: an old vault command printed Servonaut key material")
    # The items survive untouched: same ids, types and fingerprints, none deleted ...
    items_after = _app_key_items(fake_cloud, vault_id)
    assert {k: (v["type"], v["public_fingerprint"], v["deleted_at"]) for k, v in items_after.items()} == \
        {k: (v["type"], v["public_fingerprint"], v["deleted_at"]) for k, v in items_before.items()}, \
        "HOLE: an old vault command changed or deleted a key item"
    # ... and the checkout still reads both payloads back unchanged.
    assert checkout("verify")["payload_intact"] == {"memory_key": True, "config_sync_key": True}
    # A failure of the old command is acceptable only if it is a clean refusal.
    assert listed.returncode == 0, listed.describe()
