"""Journey: hosted AI summaries send per-envelope keys, never a passphrase.

From a server's Memory screen, "Generate" asks the provider-disclosure question
(which says the keys of the memory being summarised are sent, not the Memory
Sync key or passphrase) and runs the summary.

* A vault-custody account and a passphrase-custody account each get their
  summary with no passphrase dialog: the dispatch carries ``envelope_keys`` for
  exactly the envelopes the consent named, and no ``passphrase`` field.
* A ``stale_envelopes`` answer is retried once, silently, with a fresh consent.
* With the service's custody switch off the vault account is told hosted
  summaries are not available yet (and nothing is sent in the passphrase form),
  while the passphrase account falls back to the passphrase form and gets its
  summary.
* When the service cannot open the memory with the keys it was sent, the user
  reads the failed text, not the service's code.
"""

from __future__ import annotations

import base64

import pytest

from e2e.harness.memory_sync import PASSPHRASE, use_passphrase
from e2e.harness.vault_custody import setup_vault
from e2e.journeys.custody.wi12b_support import (
    HOST, seed_probed_memory, set_up_in_vault, settle_card, synced,
)
from e2e.harness.memory_sync import open_memory_sync, status, unlock

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio, pytest.mark.xdist_group("custody-summary")]

OK = (200, 202)  # the dispatch answers 200 or 202 (queued)
SUMMARY_PATH = f"/api/v1/memory/summary/{HOST.instance_id}"
UNAVAILABLE = (
    "Hosted summaries are not available for a key kept in the vault on this "
    "Servonaut service yet. Try again later."
)


def _ok(status: int):
    return "ok" if status in OK else status


def _teams(fake_cloud) -> None:
    """Hosted summaries belong to the Teams plan."""
    fake_cloud.configure(plan="teams", mcp_connections=0)


def _passphrase_dialogs(t) -> list[str]:
    return [name for name in t.opened_screens() if "Passphrase" in name]


async def _open_memory(t) -> None:
    await t.nav("nav_list")
    await t.wait_for_screen("InstanceListScreen")
    await t.wait_and_select_instance(HOST.name)
    await t.press("m")
    await t.wait_for_screen("MemoryScreen")


async def _generate(t) -> None:
    """Press Generate and answer yes to the provider disclosure."""
    await t.press("H")
    await t.wait_for_screen("SimpleConfirmModal")
    await t.wait_for_text("keys for the memory being summarised", screen_only=True)
    await t.click("#confirm_yes_btn")


async def _wait_for_summary(t) -> None:
    await t.wait_for_screen("MemorySummaryScreen")
    await t.wait_for_text("Summary of")
    await t.press("escape")
    await t.wait_for_screen("MemoryScreen")


def _dispatches(fake_cloud) -> list[dict]:
    return fake_cloud.requests(SUMMARY_PATH, "POST")


def _consents(fake_cloud) -> list[dict]:
    return fake_cloud.requests(f"{SUMMARY_PATH}/consent", "POST")


def _newest_envelope_ids(fake_cloud) -> set[str]:
    newest = {}
    for envelope in fake_cloud.memory.envelopes(HOST.instance_id):
        newest[envelope["module"]] = envelope["id"]
    return set(newest.values())


def _assert_key_form(fake_cloud, dispatch: dict) -> None:
    """The body names exactly the consented envelopes, with 32-byte keys, and no passphrase."""
    body = dispatch["body"]
    assert "passphrase" not in body
    keys = body["envelope_keys"]
    assert {entry["envelope_id"] for entry in keys} == _newest_envelope_ids(fake_cloud)
    assert all(len(base64.b64decode(entry["dek"])) == 32 for entry in keys)
    fake_cloud.assert_absent_on_wire(PASSPHRASE)


@pytest.fixture
def vault_account(journey, fake_cloud, seed, servonaut_cmd, custody_device, signed_in_home, monkeypatch):
    _teams(fake_cloud)
    signed_in_home()
    seed_probed_memory(seed)
    setup_vault(journey, journey.ctx.sandbox, servonaut_cmd)


@pytest.fixture
def passphrase_account(journey, fake_cloud, seed, signed_in_home, monkeypatch):
    _teams(fake_cloud)
    signed_in_home()
    seed_probed_memory(seed)
    use_passphrase(monkeypatch)


async def _vault_ready(t) -> None:
    await set_up_in_vault(t)
    await synced(t)


async def _passphrase_ready(t) -> None:
    from e2e.harness.memory_sync import sync_all

    await open_memory_sync(t)
    await unlock(t)
    await sync_all(t)


async def test_a_vault_account_gets_its_summary_with_envelope_keys(tui, fake_cloud, vault_account):
    async with tui() as t:
        await _vault_ready(t)
        assert fake_cloud.memory.enrolled_key()["custody"] == "vault"
        await _open_memory(t)
        await _generate(t)
        await _wait_for_summary(t)
        assert _passphrase_dialogs(t) == []

    (dispatch,) = _dispatches(fake_cloud)
    assert dispatch["status"] in OK
    _assert_key_form(fake_cloud, dispatch)
    assert [job["form"] for job in fake_cloud.summaries.jobs()] == ["envelope_keys"]


async def test_a_passphrase_account_gets_its_summary_without_the_passphrase(tui, fake_cloud, passphrase_account):
    async with tui() as t:
        await _passphrase_ready(t)
        assert fake_cloud.memory.enrolled_key()["custody"] == "passphrase"
        await _open_memory(t)
        await _generate(t)
        await _wait_for_summary(t)
        assert _passphrase_dialogs(t) == []

    (dispatch,) = _dispatches(fake_cloud)
    _assert_key_form(fake_cloud, dispatch)
    assert [job["form"] for job in fake_cloud.summaries.jobs()] == ["envelope_keys"]


async def test_stale_envelopes_are_retried_once_with_a_fresh_consent(tui, fake_cloud, vault_account):
    async with tui() as t:
        await _vault_ready(t)
        fake_cloud.summaries.force_stale_once(1)
        await _open_memory(t)
        await _generate(t)
        await _wait_for_summary(t)
        # Silent: no stale text was shown.
        assert not [m for _, m in t.toasts() if "Memory changed while" in m]

    assert [_ok(d["status"]) for d in _dispatches(fake_cloud)] == [409, "ok"]
    assert len(_consents(fake_cloud)) == 2
    _assert_key_form(fake_cloud, _dispatches(fake_cloud)[-1])


async def test_with_the_custody_switch_off_a_vault_account_is_told_it_is_not_available(
    tui, fake_cloud, vault_account,
):
    async with tui() as t:
        await _vault_ready(t)
        fake_cloud.memory.set_vault_custody(False)
        await _open_memory(t)
        await _generate(t)
        await t.wait_for_toast(f"^{UNAVAILABLE}$", severity="error")
        assert _passphrase_dialogs(t) == []

    assert [d["status"] for d in _dispatches(fake_cloud)] == [503]
    assert all("passphrase" not in d["body"] for d in _dispatches(fake_cloud))
    assert fake_cloud.summaries.jobs() == []


async def test_with_the_custody_switch_off_a_passphrase_account_falls_back_to_the_passphrase(
    tui, fake_cloud, passphrase_account,
):
    async with tui() as t:
        await _passphrase_ready(t)
        fake_cloud.memory.set_vault_custody(False)
        await _open_memory(t)
        await _generate(t)
        await _wait_for_summary(t)

    first, second = _dispatches(fake_cloud)
    assert (first["status"], _ok(second["status"])) == (503, "ok")
    assert "envelope_keys" in first["body"] and "passphrase" not in first["body"]
    assert "passphrase" in second["body"] and "envelope_keys" not in second["body"]
    assert [job["form"] for job in fake_cloud.summaries.jobs()] == ["passphrase"]


async def test_a_key_the_service_rejects_ends_in_the_failed_text(tui, fake_cloud, vault_account, monkeypatch):
    # The service finds the data key does not open the memory it holds: the job
    # is recorded as failed and the poll answers ``status: "failed"``.
    summaries = fake_cloud.summaries
    run_job = summaries._run_job

    def failing_job(*args, **kwargs):
        job = run_job(*args, **kwargs)
        with summaries._lock:
            job.update(status="failed", reason="dek_invalid", result=None)
        return job

    monkeypatch.setattr(summaries, "_run_job", failing_job)
    async with tui() as t:
        await _vault_ready(t)
        await _open_memory(t)
        await _generate(t)
        text = await t.wait_for_toast(r"^The summary could not be created \(.+\)\.$", severity="error")
        assert "dek_invalid" not in " ".join(m for _, m in t.toasts())
        assert "decryption_failed" not in text
        assert "MemorySummaryScreen" not in t.stack_names()

    assert [job["status"] for job in fake_cloud.summaries.jobs()] == ["failed"]
