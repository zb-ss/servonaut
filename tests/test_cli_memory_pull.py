"""`servonaut memory pull` pulls BOTH annotations and findings for an instance."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from servonaut.cli.memory import _cmd_pull_annotations
from servonaut.services.memory.sync_service import VaultUnlock

_INST = {"id": "web-1", "name": "web-1", "provider": "custom"}


def _sync(*, ann="updated", fnd="updated", configured=True):
    s = MagicMock()
    s.is_configured = configured
    s.unlock_from_vault = AsyncMock(return_value=VaultUnlock.NOT_VAULT)
    s.pull_annotations = AsyncMock(return_value=ann)
    s.pull_findings = AsyncMock(return_value=fnd)
    return s


def test_pull_invokes_both_annotations_and_findings():
    sync = _sync()
    rc = _cmd_pull_annotations(MagicMock(), MagicMock(), MagicMock(), _INST, sync)
    assert rc == 0
    sync.pull_annotations.assert_awaited_once_with("web-1", "web-1", "custom")
    sync.pull_findings.assert_awaited_once_with("web-1", "web-1", "custom")


def test_pull_not_configured_skips_both():
    sync = _sync(configured=False)
    rc = _cmd_pull_annotations(MagicMock(), MagicMock(), MagicMock(), _INST, sync)
    assert rc != 0
    sync.pull_annotations.assert_not_awaited()
    sync.pull_findings.assert_not_awaited()


def test_pull_opt_out_on_either_surfaces_exit_code():
    sync = _sync(ann="updated", fnd="opt_out")
    rc = _cmd_pull_annotations(MagicMock(), MagicMock(), MagicMock(), _INST, sync)
    # opt_out / unavailable apply account-wide → non-success exit even if the
    # other surface updated.
    assert rc != 0
    sync.pull_findings.assert_awaited_once()


def test_pull_tries_the_vault_first_and_then_runs():
    sync = _sync(configured=False)

    async def unlock():
        sync.is_configured = True
        return VaultUnlock.OK

    sync.unlock_from_vault = AsyncMock(side_effect=unlock)
    rc = _cmd_pull_annotations(MagicMock(), MagicMock(), MagicMock(), _INST, sync)
    assert rc == 0
    sync.unlock_from_vault.assert_awaited_once()
    sync.pull_annotations.assert_awaited_once()


def test_pull_with_a_locked_vault_prints_the_vault_text_exits_6_and_never_prompts(capsys, monkeypatch):
    import getpass

    def no_prompt(*_a, **_k):
        raise AssertionError("must not prompt")

    monkeypatch.setattr(getpass, "getpass", no_prompt)
    sync = _sync(configured=False)
    sync.unlock_from_vault = AsyncMock(return_value=VaultUnlock.VAULT_LOCKED)

    rc = _cmd_pull_annotations(MagicMock(), MagicMock(), MagicMock(), _INST, sync)

    assert rc == 6
    err = capsys.readouterr().err
    assert "kept in your vault" in err
    assert "Unlock or add this device to your vault" in err
    sync.pull_annotations.assert_not_awaited()


def test_pull_not_vault_and_not_configured_keeps_the_old_message(capsys):
    sync = _sync(configured=False)
    rc = _cmd_pull_annotations(MagicMock(), MagicMock(), MagicMock(), _INST, sync)
    assert rc == 6
    assert "Memory Sync is not configured" in capsys.readouterr().err


def test_pull_skips_the_vault_when_already_unlocked():
    sync = _sync()
    _cmd_pull_annotations(MagicMock(), MagicMock(), MagicMock(), _INST, sync)
    sync.unlock_from_vault.assert_not_awaited()


def test_headless_sync_services_get_a_read_only_custody(monkeypatch, tmp_path):
    from servonaut.cli import memory as cli_memory
    from servonaut.services import auth_service as auth_module

    auth = MagicMock()
    auth.is_authenticated = True
    monkeypatch.setattr(auth_module, "AuthService", lambda: auth)
    vault = MagicMock()
    vault.is_unlocked = False
    monkeypatch.setattr(cli_memory, "_vault_runtime", lambda: vault)

    sync, retrieval = cli_memory._init_headless_sync_services(
        MagicMock(), MagicMock(), MagicMock()
    )

    custody = sync._key_custody
    assert custody is not None
    assert custody._writable is False
    assert retrieval is not None
