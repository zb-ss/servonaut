"""``servonaut memory move-key-to-vault``: flags, terminal checks, exit codes, no secrets printed."""

from __future__ import annotations

import io
import json
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.cli import memory as cli_memory
from servonaut.services.api_client import APIError
from servonaut.services.memory.custody_move import MoveAborted, MoveStopped
from servonaut.services.vault.command_service import VaultCommandService
from servonaut.services.vault.errors import VaultUserError

PASSPHRASE = "correct horse battery staple 7!"
RECOVERY_KEY = "SVRK1-AAAA-BBBB-CCCC-DDDD"


class _Stdin(io.StringIO):
    def __init__(self, text: str = "", tty: bool = False) -> None:
        super().__init__(text)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def _args(**over):
    base = dict(
        memory_command="move-key-to-vault", skip_config=False, skip_memory=False,
        yes=True, passphrase_stdin=False, recovery_key_stdin=False, json=False,
    )
    base.update(over)
    return SimpleNamespace(**base)


class Rig:
    """Replaces the vault session and the services the command builds."""

    def __init__(self, monkeypatch) -> None:
        self.provided: list[str] = []

        async def mover_run(passphrase_provider, recovery_provider, progress):
            progress("preflight")
            self.provided.append(recovery_provider())
            self.provided.append(passphrase_provider())
            progress("cleanup")
            return SimpleNamespace(outcome="moved", vault_created=True, warnings=["finish me"])

        self.mover = SimpleNamespace(run=AsyncMock(side_effect=mover_run))
        self.config_sync = SimpleNamespace(
            move_key_to_vault=AsyncMock(return_value={"key_created": True, "pushed": True, "deleted": 2}))
        self.auth = SimpleNamespace(has_feature=lambda feature: True)
        monkeypatch.setattr(VaultCommandService, "from_local_session",
                            classmethod(lambda cls: SimpleNamespace()))
        monkeypatch.setattr(cli_memory, "_build_move_services",
                            lambda vault: (self.mover, self.config_sync, MagicMock(), self.auth))


@pytest.fixture
def rig(monkeypatch):
    return Rig(monkeypatch)


def _run(args) -> int:
    return cli_memory.run_memory(args)


def test_success_prints_steps_and_summary_without_secrets(rig, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", _Stdin(f"{RECOVERY_KEY}\n{PASSPHRASE}\n"))

    code = _run(_args(passphrase_stdin=True, recovery_key_stdin=True))

    captured = capsys.readouterr()
    assert code == 0
    assert rig.provided == [RECOVERY_KEY, PASSPHRASE]  # recovery key line first
    assert "Memory Sync now keeps its key in your vault." in captured.out
    assert "personal vault did not exist yet" in captured.out
    assert "Warning: finish me" in captured.err
    assert "removed" in captured.out
    for secret in (RECOVERY_KEY, PASSPHRASE):
        assert secret not in captured.out + captured.err


def test_json_output_is_one_object_with_no_step_lines(rig, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", _Stdin(f"{RECOVERY_KEY}\n{PASSPHRASE}\n"))

    code = _run(_args(passphrase_stdin=True, recovery_key_stdin=True, json=True))

    out = capsys.readouterr().out
    assert code == 0
    data = json.loads(out)
    assert data["ok"] is True
    assert data["memory"]["outcome"] == "moved"
    assert data["config"] == {"key_created": True, "pushed": True, "deleted": 2}
    assert RECOVERY_KEY not in out and PASSPHRASE not in out


def test_skip_flags_select_the_parts(rig, monkeypatch):
    monkeypatch.setattr(sys, "stdin", _Stdin(f"{RECOVERY_KEY}\n{PASSPHRASE}\n"))
    assert _run(_args(skip_config=True, passphrase_stdin=True, recovery_key_stdin=True)) == 0
    rig.config_sync.move_key_to_vault.assert_not_awaited()

    rig.mover.run.reset_mock()
    assert _run(_args(skip_memory=True)) == 0
    rig.mover.run.assert_not_awaited()
    rig.config_sync.move_key_to_vault.assert_awaited_once()


def test_skipping_both_parts_is_a_usage_error(rig, capsys):
    assert _run(_args(skip_config=True, skip_memory=True)) == 4
    assert "Nothing to do" in capsys.readouterr().err


def test_config_part_is_skipped_when_the_plan_lacks_it(rig, monkeypatch, capsys):
    rig.auth.has_feature = lambda feature: feature != "config_sync"
    monkeypatch.setattr(sys, "stdin", _Stdin(f"{RECOVERY_KEY}\n{PASSPHRASE}\n"))

    code = _run(_args(passphrase_stdin=True, recovery_key_stdin=True))

    assert code == 0
    rig.config_sync.move_key_to_vault.assert_not_awaited()
    assert "Config sync is not part of your plan." in capsys.readouterr().out


def test_no_terminal_and_no_yes_is_a_usage_error(rig, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", _Stdin("", tty=False))

    assert _run(_args(yes=False)) == 4
    assert "terminal is needed to confirm" in capsys.readouterr().err
    rig.mover.run.assert_not_awaited()


def test_no_terminal_and_no_stdin_flag_is_a_usage_error(rig, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", _Stdin("", tty=False))

    assert _run(_args()) == 4
    assert "terminal is needed" in capsys.readouterr().err


def test_empty_stdin_line_is_a_usage_error(rig, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", _Stdin("\n"))

    assert _run(_args(recovery_key_stdin=True, passphrase_stdin=True)) == 4
    assert "was empty" in capsys.readouterr().err


def test_declining_the_confirmation_exits_five_and_changes_nothing(rig, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", _Stdin("n\n", tty=True))

    assert _run(_args(yes=False)) == 5
    assert "Nothing was changed" in capsys.readouterr().err
    rig.mover.run.assert_not_awaited()


def test_accepting_the_confirmation_prompts_with_getpass_on_stderr(rig, monkeypatch):
    monkeypatch.setattr(sys, "stdin", _Stdin("y\n", tty=True))
    streams: list[object] = []
    answers = iter([RECOVERY_KEY, PASSPHRASE])

    def fake_getpass(prompt, stream=None):
        streams.append(stream)
        return next(answers)

    monkeypatch.setattr(cli_memory.getpass, "getpass", fake_getpass)

    assert _run(_args(yes=False)) == 0
    assert streams == [sys.stderr, sys.stderr]
    assert rig.provided == [RECOVERY_KEY, PASSPHRASE]


def test_interrupt_at_a_prompt_is_a_user_abort(rig, monkeypatch):
    monkeypatch.setattr(sys, "stdin", _Stdin("", tty=True))

    def interrupted(prompt, stream=None):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_memory.getpass, "getpass", interrupted)

    assert _run(_args()) == 5


def test_a_refusal_exits_six_with_the_plain_message(rig, monkeypatch, capsys):
    rig.mover.run = AsyncMock(side_effect=MoveStopped("wrong_passphrase", "That passphrase did not open your key."))

    assert _run(_args()) == 6
    err = capsys.readouterr().err
    assert "That passphrase did not open your key." in err
    rig.config_sync.move_key_to_vault.assert_not_awaited()


def test_mover_abort_exits_five(rig):
    rig.mover.run = AsyncMock(side_effect=MoveAborted())

    assert _run(_args()) == 5


def test_signed_out_exits_six(rig, monkeypatch, capsys):
    def signed_out(cls):
        raise VaultUserError("Sign in with servonaut login before using the vault")

    monkeypatch.setattr(VaultCommandService, "from_local_session", classmethod(signed_out))

    assert _run(_args()) == 6
    assert "Sign in with servonaut login" in capsys.readouterr().err


def test_refusal_json_carries_the_error(rig, capsys):
    rig.mover.run = AsyncMock(side_effect=MoveStopped("vault_not_ready", "Your vault is not ready."))

    assert _run(_args(json=True)) == 6
    data = json.loads(capsys.readouterr().out)
    assert data == {"ok": False, "error": "Your vault is not ready."}


def test_config_api_refusal_uses_the_client_text_not_the_services(rig, monkeypatch, capsys):
    rig.config_sync.move_key_to_vault = AsyncMock(side_effect=APIError(
        code="no_vault_snapshot", message="service wording", status=409))
    monkeypatch.setattr(sys, "stdin", _Stdin(f"{RECOVERY_KEY}\n{PASSPHRASE}\n"))

    code = _run(_args(passphrase_stdin=True, recovery_key_stdin=True))

    err = capsys.readouterr().err
    assert code == 6
    assert "old copies were kept" in err
    assert "service wording" not in err


def test_unexpected_failure_names_only_the_exception_class(rig, monkeypatch, capsys):
    rig.mover.run = AsyncMock(side_effect=RuntimeError(f"secret {PASSPHRASE}"))

    assert _run(_args()) == 6
    err = capsys.readouterr().err
    assert "RuntimeError" in err
    assert PASSPHRASE not in err


def test_the_subcommand_is_registered_with_its_flags(monkeypatch, capsys):
    from servonaut.main import main

    monkeypatch.setattr(sys, "argv", ["servonaut", "memory", "move-key-to-vault", "--help"])
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 0
    out = capsys.readouterr().out
    for flag in ("--skip-config", "--skip-memory", "--yes", "--passphrase-stdin",
                 "--recovery-key-stdin", "--json"):
        assert flag in out
