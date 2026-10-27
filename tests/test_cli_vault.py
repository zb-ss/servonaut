"""Focused parser and command-boundary tests for ``servonaut vault``."""
from __future__ import annotations

import argparse
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.cli import vault
from servonaut.services.api_client import APIError

VAULT_ID = "5a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="subcommand")
    vault.add_vault_parser(subparsers)
    return parser


def test_vault_parser_accepts_identity_confirm() -> None:
    args = _parser().parse_args(["vault", "identity", "confirm"])

    assert vault.is_vault_command(args)
    assert args.vault_command == "identity"
    assert args.vault_identity_command == "confirm"


def test_vault_parser_requires_explicit_reveal_flag() -> None:
    args = _parser().parse_args(["vault", "show", "item-1", "--vault", VAULT_ID])

    assert args.reveal is False
    assert args.vault == VAULT_ID


def test_vault_parser_accepts_pending_device_add() -> None:
    args = _parser().parse_args(["vault", "devices", "add", "--device-name", "laptop"])

    assert args.vault_devices_command == "add"
    assert args.device_name == "laptop"


def test_vault_parser_takes_only_platform_names_the_service_accepts(capsys) -> None:
    for command in (["setup"], ["recover"], ["devices", "add"]):
        assert _parser().parse_args(["vault", *command, "--platform", "macos"]).platform == "macos"
        # What platform.system() says on a Mac: refused here, not by the service later.
        with pytest.raises(SystemExit):
            _parser().parse_args(["vault", *command, "--platform", "darwin"])
    assert "invalid choice: 'darwin'" in capsys.readouterr().err


def test_vault_status_dispatches_through_injected_service(capsys) -> None:
    class Service:
        async def status(self):
            return {"fingerprint": "abc", "recovery_wrap": {"present": True}}

    vault.set_vault_service_factory(Service)
    try:
        args = _parser().parse_args(["vault", "status"])
        assert vault.handle_vault_command(args) == 0
    finally:
        vault.set_vault_service_factory(None)

    assert "fingerprint: abc" in capsys.readouterr().out


def test_vault_json_redacts_revealed_value(capsys) -> None:
    class Service:
        async def show_item(self, **_kwargs):
            return {"item_id": "item-1", "value": "do-not-export"}

    vault.set_vault_service_factory(Service)
    try:
        args = _parser().parse_args(["vault", "--json", "show", "item-1", "--vault", VAULT_ID, "--reveal", "--yes"])
        assert vault.handle_vault_command(args) == 0
    finally:
        vault.set_vault_service_factory(None)

    output = capsys.readouterr().out
    assert "do-not-export" not in output
    assert "revealed only on terminal" in output


def test_vault_error_does_not_echo_service_message(capsys) -> None:
    class Service:
        close = MagicMock()

        async def status(self):
            raise APIError(code="invalid", message="recovery-secret", status=403)

    vault.set_vault_service_factory(Service)
    try:
        args = _parser().parse_args(["vault", "status"])
        assert vault.handle_vault_command(args) == 1
    finally:
        vault.set_vault_service_factory(None)

    error = capsys.readouterr().err
    assert "HTTP 403" in error
    assert "recovery-secret" not in error
    Service.close.assert_called_once_with()


def test_declined_device_approval_says_why(capsys) -> None:
    from servonaut.services.vault.errors import VaultUserError

    class Service:
        close = MagicMock()

        async def approve_device(self, **_kwargs):
            raise VaultUserError("device safety number was not confirmed; registration was rejected")

    vault.set_vault_service_factory(Service)
    try:
        args = _parser().parse_args(["vault", "devices", "approve", "device-1"])
        assert vault.handle_vault_command(args) == 1
    finally:
        vault.set_vault_service_factory(None)

    error = capsys.readouterr().err
    assert "safety number was not confirmed; registration was rejected" in error
    assert "RuntimeError" not in error


def test_rejected_pending_device_says_the_other_device_rejected_it(capsys) -> None:
    class Service:
        close = MagicMock()

        async def status(self):
            raise APIError(
                code="device_not_active", message="server-text", status=403,
                details={"status": "rejected"},
            )

    vault.set_vault_service_factory(Service)
    try:
        args = _parser().parse_args(["vault", "status"])
        assert vault.handle_vault_command(args) == 1
    finally:
        vault.set_vault_service_factory(None)

    error = capsys.readouterr().err
    assert "the other device rejected this registration" in error
    assert "server-text" not in error


def test_device_add_polls_at_configured_interval_and_closes_runtime(monkeypatch, capsys) -> None:
    expires_at = "2030-01-01T00:00:00+00:00"

    class Service:
        config = SimpleNamespace(
            vault=SimpleNamespace(
                approval_poll_initial_seconds=2.0,
                approval_poll_max_seconds=10.0,
            )
        )
        close = MagicMock()

        def __init__(self) -> None:
            self.polls = 0
            self.finished = None

        def approval_poll_delay(self, attempt):
            return min(10.0, 2.0 * (2 ** attempt))

        async def add_device(self, **_kwargs):
            return {"identity": {"identity_id": "identity-1"}, "expires_at": expires_at}

        async def poll_pending_device(self, **_kwargs):
            self.polls += 1
            if self.polls == 1:
                return {"state": "revealed", "safety_number": "12345"}
            return {"state": "approved", "approval": {"approval_id": "approval-1"}}

        async def finish_pending_device(self, **kwargs):
            self.finished = kwargs
            return {"device_id": "device-1"}

    service = Service()
    sleep = AsyncMock()
    monkeypatch.setattr(vault.asyncio, "sleep", sleep)
    vault.set_vault_service_factory(lambda: service)
    try:
        args = _parser().parse_args(["vault", "devices", "add"])
        assert vault.handle_vault_command(args) == 0
    finally:
        vault.set_vault_service_factory(None)

    assert sleep.await_args.args == (2.0,)
    assert service.finished == {
        "approval": {"approval_id": "approval-1"},
        "identity": {"identity_id": "identity-1"},
    }
    Service.close.assert_called_once_with()
    assert "Safety number: 12345" in capsys.readouterr().err


def test_device_add_json_is_one_redacted_document(monkeypatch, capsys) -> None:
    class Service:
        close = MagicMock()

        def approval_poll_delay(self, _attempt):
            return 0.1

        async def add_device(self, **_kwargs):
            return {"identity": {"identity_id": "identity-1"}, "expires_at": "2030-01-01T00:00:00Z"}

        async def poll_pending_device(self, **_kwargs):
            return {"state": "approved", "approval": {"approval_id": "approved-1"}}

        async def finish_pending_device(self, **_kwargs):
            return {"device_id": "device-1", "recovery_key": "never-export"}

    vault.set_vault_service_factory(Service)
    try:
        assert vault.handle_vault_command(_parser().parse_args(["vault", "devices", "add", "--json"])) == 0
    finally:
        vault.set_vault_service_factory(None)

    assert json.loads(capsys.readouterr().out) == {
        "device_id": "device-1", "recovery_key": "[revealed only on terminal]"
    }


def test_escrow_setup_requires_one_time_recovery_confirmation_and_redacts_json(monkeypatch, capsys) -> None:
    recorded: list[str] = []

    class Service:
        close = MagicMock()

        async def setup_escrow(self, *, recovery_confirmation, **_kwargs):
            recovery_key = "SVTR1-ABCDE-FGHIJ"
            assert recovery_confirmation(recovery_key) is True
            return {"escrow_id": "escrow-1", "recovery_key": recovery_key}

    monkeypatch.setattr(vault, "_confirm_recovery_key", lambda key: recorded.append(key) or True)
    vault.set_vault_service_factory(Service)
    try:
        args = _parser().parse_args(
            ["vault", "escrow", "setup", "--vault", VAULT_ID, "--label", "offline", "--json"]
        )
        assert vault.handle_vault_command(args) == 0
    finally:
        vault.set_vault_service_factory(None)

    output = capsys.readouterr().out
    assert recorded == ["SVTR1-ABCDE-FGHIJ"]
    assert "SVTR1-ABCDE-FGHIJ" not in output
    assert "[revealed only on terminal]" in output
    Service.close.assert_called_once_with()


def test_setup_json_keeps_recovery_key_off_stdout(monkeypatch, capsys) -> None:
    class Service:
        close = MagicMock()

        async def setup(self, *, recovery_confirmation, **_kwargs):
            assert recovery_confirmation("SVTR1-ABCDE-FGHIJ")
            return {"device_id": "device-1", "recovery_key": "SVTR1-ABCDE-FGHIJ"}

    answers = iter(("ABCDE", "FGHIJ"))
    monkeypatch.setattr(vault.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(vault.secrets.SystemRandom, "sample", lambda _self, _population, _count: [1, 2])
    monkeypatch.setattr(vault.getpass, "getpass", lambda *_args, **_kwargs: next(answers))
    vault.set_vault_service_factory(Service)
    try:
        assert vault.handle_vault_command(_parser().parse_args(["vault", "setup", "--json"])) == 0
    finally:
        vault.set_vault_service_factory(None)

    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "device_id": "device-1", "recovery_key": "[revealed only on terminal]"
    }
    assert "SVTR1-ABCDE-FGHIJ" not in captured.out
    assert "SVTR1-ABCDE-FGHIJ" in captured.err


def test_exposure_rotation_requires_explicit_hosts_and_dispatches_remediation(capsys) -> None:
    class Service:
        close = MagicMock()

        async def rotate_ssh_key(self, **kwargs):
            self.kwargs = kwargs
            return {"rotated": True, "hosts": [{"server_id": "server-1", "status": "rotated"}]}

    service = Service()
    vault.set_vault_service_factory(lambda: service)
    try:
        args = _parser().parse_args(
            [
                "vault", "exposures", "--vault", VAULT_ID, "--rotate-ssh", "item-1",
                "--team", "ops", "--server", "server-1", "--server", "server-2", "--yes",
            ]
        )
        assert vault.handle_vault_command(args) == 0
    finally:
        vault.set_vault_service_factory(None)

    assert service.kwargs == {
        "vault_id": VAULT_ID,
        "item_id": "item-1",
        "team": "ops",
        "servers": ["server-1", "server-2"],
    }
    assert "server-1" in capsys.readouterr().out
    Service.close.assert_called_once_with()


def test_personal_binding_requires_explicit_host_pins_and_dispatches(capsys) -> None:
    class Service:
        close = MagicMock()

        async def bind_personal(self, **kwargs):
            self.kwargs = kwargs
            return {"source": "servonaut_vault", "valid": True}

    service = Service()
    vault.set_vault_service_factory(lambda: service)
    try:
        args = _parser().parse_args(
            [
                "vault", "bind-personal", "--vault", VAULT_ID, "--item", "item-1",
                "--provider", "aws", "--instance-id", "i-123", "--hostname", "host.example",
                "--login", "ubuntu", "--host-key", "ssh-ed25519 AAAA", "--yes",
            ]
        )
        assert vault.handle_vault_command(args) == 0
    finally:
        vault.set_vault_service_factory(None)

    assert service.kwargs == {
        "vault_id": VAULT_ID,
        "item_id": "item-1",
        "provider": "aws",
        "instance_id": "i-123",
        "hostname": "host.example",
        "port": 22,
        "login": "ubuntu",
        "host_keys": ["ssh-ed25519 AAAA"],
    }
    assert "source: servonaut_vault" in capsys.readouterr().out


def test_identity_reset_polls_until_confirmed_before_runtime_closes(monkeypatch, capsys) -> None:
    class Service:
        close = MagicMock()

        def __init__(self) -> None:
            self.polls = 0

        async def reset_identity(self, *, recovery_confirmation, **_kwargs):
            assert recovery_confirmation("SVRK1-ABCDE-FGHIJ") is True
            return {"reset": {"state": "pending_reset"}, "recovery_key": "SVRK1-ABCDE-FGHIJ"}

        async def poll_reset_identity(self):
            self.polls += 1
            if self.polls == 1:
                return {"state": "pending_reset"}
            return {"state": "confirmed", "fingerprint": "fp", "device_id": "device-1"}

        def approval_poll_delay(self, attempt):
            assert attempt == 0
            return 2.0

    service = Service()
    sleep = AsyncMock()
    monkeypatch.setattr(vault, "_confirm_recovery_key", lambda _key: True)
    monkeypatch.setattr(vault.asyncio, "sleep", sleep)
    vault.set_vault_service_factory(lambda: service)
    try:
        args = _parser().parse_args(["vault", "reset-identity", "--reason", "rotate", "--yes"])
        assert vault.handle_vault_command(args) == 0
    finally:
        vault.set_vault_service_factory(None)

    assert sleep.await_args.args == (2.0,)
    assert "device_id: device-1" in capsys.readouterr().out
    Service.close.assert_called_once_with()


def test_identity_reset_json_emits_only_confirmed_result(monkeypatch, capsys) -> None:
    class Service:
        close = MagicMock()

        def __init__(self) -> None:
            self.polls = 0

        def approval_poll_delay(self, _attempt):
            return 0.1

        async def reset_identity(self, **_kwargs):
            return {"state": "pending_reset", "recovery_key": "offline-only"}

        async def poll_reset_identity(self):
            self.polls += 1
            if self.polls == 1:
                return {"state": "pending_reset"}
            return {"state": "confirmed", "device_id": "device-1"}

    service = Service()
    monkeypatch.setattr(vault, "_confirm_recovery_key", lambda _key: True)
    monkeypatch.setattr(vault.asyncio, "sleep", AsyncMock())
    vault.set_vault_service_factory(lambda: service)
    try:
        assert vault.handle_vault_command(_parser().parse_args([
            "vault", "reset-identity", "--reason", "rotate", "--yes", "--json",
        ])) == 0
    finally:
        vault.set_vault_service_factory(None)

    assert json.loads(capsys.readouterr().out) == {"state": "confirmed", "device_id": "device-1"}


def test_human_output_strips_terminal_control_characters(capsys) -> None:
    vault._print({"label": "safe\x1b[31mtext\x7f\x9f"}, json_output=False)

    assert capsys.readouterr().out == "label: safe[31mtext\n"


def test_recovery_proof_never_selects_the_public_format_prefix(monkeypatch) -> None:
    candidate_indices: list[int] = []
    prompts: list[str] = []
    answers = iter(("ABCDE", "FGHIJ"))

    def sample(_self, population, _count):
        candidate_indices.extend(population)
        return [1, 2]

    monkeypatch.setattr(vault.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(vault.secrets.SystemRandom, "sample", sample)
    monkeypatch.setattr(
        vault.getpass,
        "getpass",
        lambda prompt, **_kwargs: prompts.append(prompt) or next(answers),
    )

    assert vault._confirm_recovery_key("SVRK1-ABCDE-FGHIJ")
    assert candidate_indices == [1, 2]
    assert prompts == ["Re-enter recovery group 2: ", "Re-enter recovery group 3: "]


def test_recovery_proof_requires_two_secret_groups(monkeypatch) -> None:
    monkeypatch.setattr(vault.sys.stdin, "isatty", lambda: True)

    assert vault._confirm_recovery_key("SVRK1-ABCDE") is False


def test_identity_reset_cancel_does_not_start_a_reset(monkeypatch) -> None:
    class Service:
        close = MagicMock()
        reset_identity = AsyncMock()

    monkeypatch.setattr(vault, "_confirm", lambda *_args: False)
    vault.set_vault_service_factory(Service)
    try:
        args = _parser().parse_args(["vault", "reset-identity", "--reason", "compromised"])
        assert vault.handle_vault_command(args) == 5
    finally:
        vault.set_vault_service_factory(None)

    Service.reset_identity.assert_not_awaited()
    Service.close.assert_called_once_with()


def test_bind_refuses_a_host_key_line_with_a_host_field_before_any_request(capsys) -> None:
    class Service:
        close = MagicMock()
        bind = AsyncMock()

    vault.set_vault_service_factory(Service)
    try:
        args = _parser().parse_args([
            "vault", "bind", "server-1", "item-1", "--vault", VAULT_ID, "--team", "team-a",
            "--host-key", "[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDkr", "--yes",
        ])
        assert vault.handle_vault_command(args) == 2
    finally:
        vault.set_vault_service_factory(None)

    assert "--host-key takes one OpenSSH public key" in capsys.readouterr().err
    Service.bind.assert_not_called()


def test_incomplete_ssh_rotation_warns_and_exits_non_zero(capsys) -> None:
    class Service:
        close = MagicMock()
        rotate_ssh_key = AsyncMock(return_value={
            "rotated": False, "hosts": [{"server_id": "server-1", "status": "failed", "error": "x"}],
        })

    vault.set_vault_service_factory(Service)
    try:
        args = _parser().parse_args([
            "vault", "exposures", "--vault", VAULT_ID, "--rotate-ssh", "item-1",
            "--team", "team-a", "--server", "server-1", "--yes",
        ])
        assert vault.handle_vault_command(args) == 1
    finally:
        vault.set_vault_service_factory(None)

    error = capsys.readouterr().err
    assert "did not finish" in error and "server-1" in error
    assert "The exposure stays open" in error


def _rotate_ssh(result: dict, capsys) -> tuple[int, str, str]:
    class Service:
        close = MagicMock()
        rotate_ssh_key = AsyncMock(return_value=result)

    vault.set_vault_service_factory(Service)
    try:
        args = _parser().parse_args([
            "vault", "exposures", "--vault", VAULT_ID, "--rotate-ssh", "item-1",
            "--team", "team-a", "--server", "server-1", "--server", "server-2", "--yes",
        ])
        code = vault.handle_vault_command(args)
    finally:
        vault.set_vault_service_factory(None)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_rotation_stopped_before_saving_says_nothing_changed_on_the_servers(capsys) -> None:
    code, _out, err = _rotate_ssh({
        "rotated": False, "item_written": False, "public_fingerprint": "SHA256:new",
        "error": "the vault key must be rotated first",
        "hosts": [{"server_id": "server-1", "status": "new_key_removed"},
                  {"server_id": "server-2", "status": "new_key_removed"}],
    }, capsys)

    assert code == 1
    assert "did not finish (the vault key must be rotated first)." in err
    assert "Nothing changed on the servers: the old key is still in place" in err
    assert "The exposure stays open; run the rotation again once the cause is fixed." in err
    assert "remove the old key" not in err


def test_rotation_stopped_before_saving_names_the_hosts_that_kept_the_new_key(capsys) -> None:
    code, _out, err = _rotate_ssh({
        "rotated": False, "item_written": False, "public_fingerprint": "SHA256:new",
        "error": "HTTP 409, vault_rotation_required",
        "hosts": [{"server_id": "server-1", "status": "new_key_removed"},
                  {"server_id": "server-2", "status": "new_key_left", "error": "RuntimeError"}],
    }, capsys)

    assert code == 1
    assert "the unused new key (SHA256:new) could not be removed from: server-2;" in err
    assert "delete its line from authorized_keys there" in err
    assert "server-1" not in err.split("could not be removed from:")[1]
    assert "remove the old key" not in err


def test_rotation_stopped_after_saving_keeps_the_old_key_advice_with_the_reason(capsys) -> None:
    code, _out, err = _rotate_ssh({
        "rotated": False, "item_written": True, "error": "HTTP 500, server_error",
        "hosts": [{"server_id": "server-1", "status": "old_key_removed"},
                  {"server_id": "server-2", "status": "failed", "error": "EnrollmentError"}],
    }, capsys)

    assert code == 1
    assert "did not finish (HTTP 500, server_error). The exposed key may still log in to: server-2." in err
    assert "remove the old key from those servers, then run the rotation again." in err


def test_rotation_that_rotated_the_vault_key_first_says_so(capsys) -> None:
    code, out, _err = _rotate_ssh({
        "rotated": True, "vault_key_rotated": True, "item_written": True,
        "hosts": [{"server_id": "server-1", "status": "old_key_removed"}],
        "exposures": {"resolved": [], "needs_owner": False, "failed": []},
    }, capsys)

    assert code == 0
    assert "The vault key was rotated first, as the service required (usually after a member leaves)." in out


def test_rotation_refused_before_any_host_shows_the_fixed_reason(capsys) -> None:
    from servonaut.services.vault.errors import VAULT_ROTATION_NOT_PERMITTED, VaultUserError

    message = VAULT_ROTATION_NOT_PERMITTED.format(vault_id=VAULT_ID)

    class Service:
        close = MagicMock()
        rotate_ssh_key = AsyncMock(side_effect=VaultUserError(message))

    vault.set_vault_service_factory(Service)
    try:
        args = _parser().parse_args([
            "vault", "exposures", "--vault", VAULT_ID, "--rotate-ssh", "item-1",
            "--team", "team-a", "--server", "server-1", "--yes",
        ])
        code = vault.handle_vault_command(args)
    finally:
        vault.set_vault_service_factory(None)

    err = capsys.readouterr().err
    assert code == 1
    assert f"Vault operation failed ({message})." in err
    assert f"`servonaut vault rotate --vault {VAULT_ID}`" in err and "no server was changed" in err


def test_break_glass_import_requires_a_source_network_and_vice_versa(capsys) -> None:
    class Service:
        close = MagicMock()
        import_keys = AsyncMock()

    vault.set_vault_service_factory(Service)
    try:
        without_network = _parser().parse_args(["vault", "import", "ssh", "--vault", VAULT_ID, "--path", "k", "--break-glass"])
        without_flag = _parser().parse_args(["vault", "import", "ssh", "--vault", VAULT_ID, "--path", "k", "--from-cidr", "10.0.0.0/8"])
        assert vault.handle_vault_command(without_network) == 2
        assert vault.handle_vault_command(without_flag) == 2
    finally:
        vault.set_vault_service_factory(None)

    error = capsys.readouterr().err
    assert "needs at least one --from-cidr" in error and "only used with --break-glass" in error
    Service.import_keys.assert_not_called()


def test_vault_command_without_a_local_identity_says_how_to_get_one(capsys) -> None:
    from servonaut.services.vault.errors import NO_LOCAL_IDENTITY
    from servonaut.services.vault.team_vault_client import VaultIdentityMissingError

    class Service:
        close = MagicMock()

        async def list_vaults(self):
            raise VaultIdentityMissingError(NO_LOCAL_IDENTITY)

    vault.set_vault_service_factory(Service)
    try:
        assert vault.handle_vault_command(_parser().parse_args(["vault", "list"])) == 1
    finally:
        vault.set_vault_service_factory(None)

    error = capsys.readouterr().err
    assert "servonaut vault setup" in error and "vault devices add" in error and "vault recover" in error


def _rotate_with(outcome: dict, capsys) -> tuple[int, str, str]:
    class Service:
        close = MagicMock()
        rotate_ssh_key = AsyncMock(return_value={
            "rotated": True, "hosts": [{"server_id": "server-1", "status": "old_key_removed"}], "exposures": outcome,
        })

    vault.set_vault_service_factory(Service)
    try:
        args = _parser().parse_args([
            "vault", "exposures", "--vault", VAULT_ID, "--rotate-ssh", "item-1",
            "--team", "team-a", "--server", "server-1", "--yes",
        ])
        code = vault.handle_vault_command(args)
    finally:
        vault.set_vault_service_factory(None)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_completed_rotation_reports_the_resolved_exposure(capsys) -> None:
    code, out, _err = _rotate_with({"resolved": ["e-1"], "needs_owner": False, "failed": []}, capsys)

    assert code == 0
    assert "Exposure e-1 resolved as rotated." in out


def test_completed_rotation_asks_an_owner_to_resolve_when_not_allowed(capsys) -> None:
    code, _out, err = _rotate_with({"resolved": [], "needs_owner": True, "failed": []}, capsys)

    assert code == 0
    assert "Rotation done; ask an owner or admin to resolve the exposure." in err


def test_completed_rotation_with_an_unresolved_exposure_says_how_to_resolve_it(capsys) -> None:
    code, _out, err = _rotate_with(
        {"resolved": [], "needs_owner": False, "failed": [{"exposure_id": "e-1", "reason": "HTTP 500, server_error"}]},
        capsys,
    )

    assert code == 1
    assert "could not be marked resolved (HTTP 500, server_error)" in err
    assert f"servonaut vault exposures --vault {VAULT_ID} --resolve e-1 --resolution rotated" in err


def test_exposure_listing_notes_a_key_replaced_in_the_vault(capsys) -> None:
    class Service:
        close = MagicMock()
        list_exposures = AsyncMock(return_value={"data": [
            {"exposure_id": "e-1", "key_replaced": True}, {"exposure_id": "e-2", "key_replaced": False},
        ]})

    vault.set_vault_service_factory(Service)
    try:
        assert vault.handle_vault_command(_parser().parse_args(["vault", "exposures", "--vault", VAULT_ID])) == 0
    finally:
        vault.set_vault_service_factory(None)

    out = capsys.readouterr().out
    assert "Note: exposure e-1: key replaced in the vault; the old key may still be on servers." in out
    assert "exposure e-2: key replaced" not in out


def _run_vault(service_class, argv: list[str]) -> int:
    vault.set_vault_service_factory(service_class)
    try:
        return vault.handle_vault_command(_parser().parse_args(argv))
    finally:
        vault.set_vault_service_factory(None)


_CONFIRM_STEP = {"code": "confirm_identity", "message": "Confirm your vault identity: open the link.",
                 "command": "servonaut vault identity confirm", "action": "vault_confirm_identity"}


def test_vault_status_ends_with_the_next_step(capsys) -> None:
    class Service:
        async def status(self):
            return {"fingerprint": "abc", "remote": {"identity": {"trust_status": "pending_confirmation"}}}

        async def next_step(self, *, status):
            assert status["fingerprint"] == "abc"
            return _CONFIRM_STEP

    assert _run_vault(Service, ["vault", "status"]) == 0

    out = capsys.readouterr().out.splitlines()
    assert out[-2:] == ["Next step: Confirm your vault identity: open the link.",
                        "  Run: servonaut vault identity confirm"]


def test_vault_status_json_carries_the_next_step(capsys) -> None:
    class Service:
        async def status(self):
            return {"fingerprint": "abc"}

        async def next_step(self, *, status):
            return _CONFIRM_STEP

    assert _run_vault(Service, ["vault", "status", "--json"]) == 0

    assert json.loads(capsys.readouterr().out)["next_step"]["code"] == "confirm_identity"


def test_vault_status_still_works_when_the_next_step_cannot_be_read(capsys) -> None:
    class Service:
        async def status(self):
            return {"fingerprint": "abc"}

        async def next_step(self, *, status):
            raise APIError(code="server_error", message="x", status=500)

    assert _run_vault(Service, ["vault", "status"]) == 0

    out = capsys.readouterr().out
    assert "fingerprint: abc" in out
    assert "Next step" not in out


def test_vault_setup_says_how_to_confirm_a_new_identity(capsys) -> None:
    class Service:
        async def setup(self, **_kwargs):
            return {"identity": {"fingerprint": "abc"}, "confirmation": {"state": "pending_confirmation"}}

    assert _run_vault(Service, ["vault", "setup"]) == 0

    out = capsys.readouterr().out
    assert "Confirm your vault identity: open the link we e-mailed to you" in out
    assert "servonaut vault identity confirm" in out


def test_vault_identity_confirm_explains_an_e_mailed_link(capsys) -> None:
    class Service:
        async def confirm_identity(self):
            return {"confirmation": {"state": "email_sent", "expires_at": "2026-10-07T10:00:00Z"}}

    assert _run_vault(Service, ["vault", "identity", "confirm"]) == 0

    out = capsys.readouterr().out
    assert "We e-mailed you a new confirmation link (valid until 2026-10-07T10:00:00Z)" in out
    assert "sign in again with two-factor" in out


def test_vault_identity_confirm_reports_a_confirmed_identity(capsys) -> None:
    class Service:
        async def confirm_identity(self):
            return {"confirmation": {"state": "confirmed", "expires_at": None}}

    assert _run_vault(Service, ["vault", "identity", "confirm"]) == 0

    assert "Your vault identity is confirmed." in capsys.readouterr().out


def _encrypted_key(path, passphrase: bytes) -> str:
    """Write a passphrase-protected OpenSSH key; return its public line."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        BestAvailableEncryption, Encoding, PrivateFormat, PublicFormat,
    )

    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, BestAvailableEncryption(passphrase)))
    return key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")


class _ImportService:
    def __init__(self) -> None:
        self.imported: list[dict] = []

    async def import_keys(self, **kwargs):
        # Copy before the CLI wipes its buffer after the call.
        self.imported.append({**kwargs, "private_key": bytes(kwargs["private_key"])})
        return {"item_id": "item-1", "type": "ssh_key"}


def _run_import(service, *argv: str) -> int:
    vault.set_vault_service_factory(lambda: service)
    try:
        return vault.handle_vault_command(_parser().parse_args(["vault", "import", "ssh", "--vault", VAULT_ID, *argv]))
    finally:
        vault.set_vault_service_factory(None)


def test_import_ssh_names_the_key_file_and_bind_names_the_team(capsys) -> None:
    for argv in (
        ["vault", "import", "ssh", "--vault", VAULT_ID],
        ["vault", "bind", "server-1", "item-1", "--vault", VAULT_ID],
    ):
        try:
            _parser().parse_args(argv)
        except SystemExit as exc:
            assert exc.code == 2
        else:
            raise AssertionError(f"{argv} parsed without its required option")
    err = capsys.readouterr().err
    assert "the following arguments are required: --path" in err
    assert "the following arguments are required: --team" in err


def test_import_asks_for_the_passphrase_and_stores_the_unlocked_key(tmp_path, monkeypatch, capsys) -> None:
    from servonaut.services.bw_key_import import is_encrypted_key, load_unencrypted_key

    key_path = tmp_path / "web_ed25519"
    public_line = _encrypted_key(key_path, b"correct horse")
    answers = iter(["wrong", "correct horse"])
    prompts: list[str] = []
    monkeypatch.setattr(vault.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(vault.getpass, "getpass", lambda prompt, stream=None: prompts.append(prompt) or next(answers))
    service = _ImportService()

    assert _run_import(service, "--path", str(key_path)) == 0

    assert prompts == ["Passphrase for web_ed25519 (Enter to cancel): "] * 2
    assert "Wrong passphrase." in capsys.readouterr().err
    stored = service.imported[0]
    assert stored["path"] == str(key_path) and stored["source"] == "ssh"
    assert not is_encrypted_key(stored["private_key"])
    assert load_unencrypted_key(stored["private_key"]).public_key.split()[:2] == public_line.split()[:2]


def test_import_of_a_passphrase_key_outside_a_terminal_says_why(tmp_path, monkeypatch, capsys) -> None:
    key_path = tmp_path / "web_ed25519"
    _encrypted_key(key_path, b"correct horse")
    monkeypatch.setattr(vault.sys.stdin, "isatty", lambda: False)
    service = _ImportService()

    assert _run_import(service, "--path", str(key_path)) == 1

    assert "this SSH key has a passphrase; run the import in a terminal to enter it" in capsys.readouterr().err
    assert service.imported == []


def test_import_cancelled_at_the_passphrase_prompt_stores_nothing(tmp_path, monkeypatch, capsys) -> None:
    key_path = tmp_path / "web_ed25519"
    _encrypted_key(key_path, b"correct horse")
    monkeypatch.setattr(vault.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(vault.getpass, "getpass", lambda prompt, stream=None: "")
    service = _ImportService()

    assert _run_import(service, "--path", str(key_path)) == 5

    assert "Import cancelled; nothing was stored." in capsys.readouterr().err
    assert service.imported == []


def test_import_gives_up_after_three_wrong_passphrases(tmp_path, monkeypatch, capsys) -> None:
    key_path = tmp_path / "web_ed25519"
    _encrypted_key(key_path, b"correct horse")
    monkeypatch.setattr(vault.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(vault.getpass, "getpass", lambda prompt, stream=None: "wrong")
    service = _ImportService()

    assert _run_import(service, "--path", str(key_path)) == 1

    assert "the passphrase was wrong three times; nothing was imported" in capsys.readouterr().err
    assert service.imported == []


def test_import_normalises_a_pem_key_and_reports_an_unreadable_file(tmp_path, capsys) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    pem_path = tmp_path / "legacy.pem"
    pem_path.write_bytes(Ed25519PrivateKey.generate().private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    service = _ImportService()

    assert _run_import(service, "--path", str(pem_path)) == 0
    assert service.imported[0]["private_key"].startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")

    assert _run_import(service, "--path", str(tmp_path / "missing")) == 1
    assert "could not import missing: Could not read file." in capsys.readouterr().err


def test_a_vault_name_is_resolved_once_before_the_command_runs(capsys) -> None:
    calls: list[tuple[str, str]] = []

    class Service:
        async def resolve_vault_id(self, *, reference):
            calls.append(("resolve", reference))
            return VAULT_ID

        async def list_items(self, *, vault_id, include_deleted=False):
            calls.append(("items", vault_id))
            return {"data": []}

    vault.set_vault_service_factory(Service)
    try:
        assert vault.handle_vault_command(_parser().parse_args(["vault", "items", "--vault", "Personal"])) == 0
        assert vault.handle_vault_command(_parser().parse_args(["vault", "items", "--vault", VAULT_ID])) == 0
    finally:
        vault.set_vault_service_factory(None)

    assert calls == [("resolve", "Personal"), ("items", VAULT_ID), ("items", VAULT_ID)]


class _AutoBindService:
    """The vault service as ``vault auto-bind`` uses it."""

    HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

    def __init__(self) -> None:
        self.binds: list[dict] = []

    async def list_vaults(self):
        return getattr(
            self,
            "vaults",
            [{"vault_id": VAULT_ID, "label": "Personal", "kind": "personal"}],
        )

    async def resolve_vault_id(self, *, reference):
        return reference

    async def vault_choices(self, *, team=None):
        return [{"vault_id": VAULT_ID, "label": "Personal", "kind": "personal"}]

    async def ssh_key_choices(self, *, vault_id, name_limit):
        assert (vault_id, name_limit) == (VAULT_ID, None)
        return getattr(
            self,
            "keys",
            [{"item_id": "k1", "label": "web-1", "name": "web-1.pem", "fingerprint": "SHA256:a"}],
        )

    def records_new_host_keys(self) -> bool:
        return True

    async def visit_for_host_key(self, instance, login=None, known_hosts_path=None):
        if known_hosts_path:
            host = instance.get("public_ip") or instance.get("name") or instance.get("id")
            with open(known_hosts_path, "a") as f:
                f.write(f"{host} {self.HOST_KEY}\n")
        return None

    def ssh_destination(self, instance):
        return instance.get("public_ip"), 22

    def ssh_login(self, instance):
        return "ubuntu"

    async def personal_binding(self, instance):
        return None

    async def bind_personal(self, **kwargs):
        self.binds.append(kwargs)
        return {"source": "servonaut_vault"}


def _auto_bind(monkeypatch, argv: list[str]) -> tuple[int, _AutoBindService]:
    from servonaut.services.vault import auto_bind

    service = _AutoBindService()
    servers = [
        {"id": "i-web1", "name": "web-1", "public_ip": "198.51.100.1"},
        {"id": "i-db1", "name": "db-1", "public_ip": "198.51.100.2"},
    ]
    monkeypatch.setattr(vault, "_auto_bind_servers", lambda: servers)
    monkeypatch.setattr(auto_bind, "trusted_host_keys", lambda instance, host, port: [service.HOST_KEY])
    vault.set_vault_service_factory(lambda: service)
    try:
        return vault.handle_vault_command(_parser().parse_args(["vault", "auto-bind", *argv])), service
    finally:
        vault.set_vault_service_factory(None)


def test_auto_bind_dry_run_shows_the_plan_and_binds_nothing(monkeypatch, capsys) -> None:
    code, service = _auto_bind(monkeypatch, ["--dry-run"])

    out = capsys.readouterr()
    assert code == 0 and service.binds == []
    assert "web-1: web-1.pem (by server name) ubuntu@198.51.100.1 - ready" in out.out
    assert "host key SHA256:" in out.out
    assert "db-1: No vault key" in out.out
    assert "1 of 2 servers can get a vault key." in out.err


def test_auto_bind_refuses_without_yes_when_not_interactive(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=lambda: False))
    code, service = _auto_bind(monkeypatch, [])

    assert code != 0 and service.binds == []
    assert "Refusing in a non-interactive shell without --yes" in capsys.readouterr().err


def test_auto_bind_yes_binds_the_ready_servers_and_reports_json(monkeypatch, capsys) -> None:
    code, service = _auto_bind(monkeypatch, ["--yes", "--json"])

    assert code == 0
    (bound,) = service.binds
    assert (bound["provider"], bound["instance_id"], bound["item_id"], bound["replace_existing"]) == ("aws", "i-web1", "k1", False)
    report = json.loads(capsys.readouterr().out)
    results = {server["server"]: (server["status"], server["result"]) for server in report["servers"]}
    assert results == {"web-1": ("ready", "bound"), "db-1": ("no_key", None)}


def test_auto_bind_fetch_host_keys_refuses_without_yes_when_not_interactive(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=lambda: False))
    code, service = _auto_bind(monkeypatch, ["--fetch-host-keys"])
    assert code != 0 and service.binds == []
    assert "Refusing to bind fetched host keys without confirmation. Run interactively or pass --yes to bind only verified keys." in capsys.readouterr().err


def test_auto_bind_fetch_host_keys_dry_run_fetches_and_binds_nothing(monkeypatch, capsys) -> None:
    from servonaut.services.vault import auto_bind

    servers = [
        {"id": "i-web1", "name": "web-1", "public_ip": "198.51.100.1"},
        {"id": "i-web2", "name": "web-2", "public_ip": "198.51.100.2"},
    ]
    keys = [
        {"item_id": "k1", "label": "web-1", "name": "web-1.pem", "fingerprint": "SHA256:a"},
        {"item_id": "k2", "label": "web-2", "name": "web-2.pem", "fingerprint": "SHA256:b"},
    ]
    service = _AutoBindService()
    service.keys = keys
    monkeypatch.setattr(vault, "_auto_bind_servers", lambda: servers)
    # web-1 trusted, web-2 has no trusted key
    monkeypatch.setattr(
        auto_bind, "trusted_host_keys",
        lambda inst, h, p: [service.HOST_KEY] if inst["id"] == "i-web1" else [],
    )

    async def fake_fetch(svc, rows, on_progress=None, accounts=None):
        for r in rows:
            r.status = auto_bind.FETCHED
            r.host_keys = [service.HOST_KEY]
            r.verified = False

    monkeypatch.setattr(auto_bind, "fetch_host_keys_for_rows", fake_fetch)
    vault.set_vault_service_factory(lambda: service)
    try:
        code = vault.handle_vault_command(
            _parser().parse_args(["vault", "auto-bind", "--dry-run", "--fetch-host-keys"])
        )
    finally:
        vault.set_vault_service_factory(None)

    out = capsys.readouterr()
    assert code == 0 and service.binds == []
    assert "web-1: web-1.pem" in out.out
    assert "web-2: web-2.pem" in out.out
    assert "not verified: compare with the server's console or your provider" in out.out
    assert "2 of 2 servers can get a vault key." in out.err


def test_auto_bind_fetch_host_keys_yes_binds_only_verified_rows(monkeypatch, capsys) -> None:
    from servonaut.services.vault import auto_bind

    servers = [
        {"id": "i-web1", "name": "web-1", "public_ip": "198.51.100.1"},
        {"id": "i-web2", "name": "web-2", "public_ip": "198.51.100.2"},
        {"id": "i-web3", "name": "web-3", "public_ip": "198.51.100.3"},
    ]
    keys = [
        {"item_id": "k1", "label": "web-1", "name": "web-1.pem", "fingerprint": "SHA256:a"},
        {"item_id": "k2", "label": "web-2", "name": "web-2.pem", "fingerprint": "SHA256:b"},
        {"item_id": "k3", "label": "web-3", "name": "web-3.pem", "fingerprint": "SHA256:c"},
    ]
    service = _AutoBindService()
    service.keys = keys
    monkeypatch.setattr(vault, "_auto_bind_servers", lambda: servers)
    # web-1 trusted from before
    monkeypatch.setattr(
        auto_bind, "trusted_host_keys",
        lambda inst, h, p: [service.HOST_KEY] if inst["id"] == "i-web1" else [],
    )

    # web-2 verified by AWS, web-3 unverified
    async def fake_fetch(svc, rows, on_progress=None, accounts=None):
        for r in rows:
            r.status = auto_bind.FETCHED
            r.host_keys = [service.HOST_KEY]
            if r.instance["id"] == "i-web2":
                r.verified = True
                r.verification_source = "verified by AWS console output"
            else:
                r.verified = False

    monkeypatch.setattr(auto_bind, "fetch_host_keys_for_rows", fake_fetch)
    vault.set_vault_service_factory(lambda: service)
    try:
        code = vault.handle_vault_command(
            _parser().parse_args(["vault", "auto-bind", "--yes", "--fetch-host-keys"])
        )
    finally:
        vault.set_vault_service_factory(None)

    out = capsys.readouterr()
    assert code == 0
    # web-1 (trusted) and web-2 (verified) bound; web-3 (unverified) skipped
    bound_ids = [b["instance_id"] for b in service.binds]
    assert bound_ids == ["i-web1", "i-web2"]
    assert "Skipped 1 unverified server: run without --yes to check their fingerprints." in out.err


def test_auto_bind_fetch_host_keys_interactive_confirm_binds_all_when_confirmed(monkeypatch, capsys) -> None:
    from servonaut.services.vault import auto_bind

    servers = [
        {"id": "i-web1", "name": "web-1", "public_ip": "198.51.100.1"},
        {"id": "i-web2", "name": "web-2", "public_ip": "198.51.100.2"},
    ]
    keys = [
        {"item_id": "k1", "label": "web-1", "name": "web-1.pem", "fingerprint": "SHA256:a"},
        {"item_id": "k2", "label": "web-2", "name": "web-2.pem", "fingerprint": "SHA256:b"},
    ]
    service = _AutoBindService()
    service.keys = keys
    monkeypatch.setattr(vault, "_auto_bind_servers", lambda: servers)
    monkeypatch.setattr(
        auto_bind, "trusted_host_keys",
        lambda inst, h, p: [service.HOST_KEY] if inst["id"] == "i-web1" else [],
    )

    async def fake_fetch(svc, rows, on_progress=None, accounts=None):
        for r in rows:
            r.status = auto_bind.FETCHED
            r.host_keys = [service.HOST_KEY]
            r.verified = False

    monkeypatch.setattr(auto_bind, "fetch_host_keys_for_rows", fake_fetch)
    # TTY with "y" response
    monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=lambda: True, readline=lambda: "y\n"))
    vault.set_vault_service_factory(lambda: service)
    try:
        code = vault.handle_vault_command(
            _parser().parse_args(["vault", "auto-bind", "--fetch-host-keys"])
        )
    finally:
        vault.set_vault_service_factory(None)

    out = capsys.readouterr()
    assert code == 0
    bound_ids = [b["instance_id"] for b in service.binds]
    assert bound_ids == ["i-web1", "i-web2"]
    assert "Bound vault keys to 2 of 2 servers." in out.err


def test_auto_bind_fetch_host_keys_yes_reports_skipped_in_json(monkeypatch, capsys) -> None:
    from servonaut.services.vault import auto_bind

    servers = [
        {"id": "i-web1", "name": "web-1", "public_ip": "198.51.100.1"},
        {"id": "i-web2", "name": "web-2", "public_ip": "198.51.100.2"},
    ]
    keys = [
        {"item_id": "k1", "label": "web-1", "name": "web-1.pem", "fingerprint": "SHA256:a"},
        {"item_id": "k2", "label": "web-2", "name": "web-2.pem", "fingerprint": "SHA256:b"},
    ]
    service = _AutoBindService()
    service.keys = keys
    monkeypatch.setattr(vault, "_auto_bind_servers", lambda: servers)
    monkeypatch.setattr(
        auto_bind, "trusted_host_keys",
        lambda inst, h, p: [service.HOST_KEY] if inst["id"] == "i-web1" else [],
    )

    async def fake_fetch(svc, rows, on_progress=None, accounts=None):
        for r in rows:
            r.status = auto_bind.FETCHED
            r.host_keys = [service.HOST_KEY]
            r.verified = False

    monkeypatch.setattr(auto_bind, "fetch_host_keys_for_rows", fake_fetch)
    vault.set_vault_service_factory(lambda: service)
    try:
        code = vault.handle_vault_command(
            _parser().parse_args(["vault", "auto-bind", "--yes", "--fetch-host-keys", "--json"])
        )
    finally:
        vault.set_vault_service_factory(None)

    out = capsys.readouterr()
    assert code == 0
    report = json.loads(out.out)
    by_name = {s["server"]: s for s in report["servers"]}
    assert by_name["web-1"]["result"] == "bound"
    assert by_name["web-2"]["skipped"] == "not verified"


def test_auto_bind_prints_fetch_error_and_mismatch_detail(capsys) -> None:
    row_err = SimpleNamespace(
        instance={"id": "i-1", "name": "web-err"},
        match=SimpleNamespace(item_id="k1", name="k1.pem", matched_by="server name", ambiguous=False),
        login="ubuntu",
        host="198.51.100.1",
        port=22,
        host_keys=[],
        ready=False,
        status="fetch_failed",
        status_text="could not connect: timed out",
        fetch_error="timed out after 10s",
        result=None,
    )
    row_mismatch = SimpleNamespace(
        instance={"id": "i-2", "name": "web-mismatch"},
        match=SimpleNamespace(item_id="k2", name="k2.pem", matched_by="server name", ambiguous=False),
        login="ubuntu",
        host="198.51.100.2",
        port=22,
        host_keys=[],
        ready=False,
        status="host_key_mismatch",
        status_text="host key mismatch",
        mismatch_detail="differs from AWS console fingerprints",
        result=None,
    )
    vault._print_auto_bind([row_err, row_mismatch], results=False)
    out = capsys.readouterr().out
    assert "fetch error: timed out after 10s" in out
    assert "mismatch: differs from AWS console fingerprints" in out


def test_auto_bind_fetch_error_not_duplicated_when_in_status_text(capsys) -> None:
    from servonaut.cli import vault
    from servonaut.services.vault.auto_bind import FETCH_FAILED, HOST_KEY_MISMATCH, AutoBindRow, KeyMatch

    row_err = AutoBindRow(
        instance={"id": "i-1", "name": "web-1"},
        status=FETCH_FAILED,
        match=KeyMatch(item_id="k1", name="k1.pem", matched_by="server name"),
        login="ubuntu",
        host="198.51.100.1",
        fetch_error="ssh: connect to host 198.51.100.1 port 22: Connection refused",
    )
    row_mismatch = AutoBindRow(
        instance={"id": "i-2", "name": "web-2"},
        status=HOST_KEY_MISMATCH,
        match=KeyMatch(item_id="k2", name="k2.pem", matched_by="server name"),
        login="ubuntu",
        host="198.51.100.2",
        mismatch_detail="The server answered with a different host key than AWS recorded at first boot: do not bind, check the server.",
    )
    vault._print_auto_bind([row_err, row_mismatch], results=False)
    out = capsys.readouterr().out
    assert "Could not fetch host key: ssh: connect to host 198.51.100.1 port 22: Connection refused" in out
    assert "fetch error:" not in out
    assert "The server answered with a different host key than AWS recorded at first boot: do not bind, check the server." in out
    assert "mismatch:" not in out


def test_auto_bind_fetch_host_keys_builds_account_registry_and_calls_client_factory(monkeypatch, capsys) -> None:
    from unittest.mock import MagicMock
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from servonaut.services.vault import auto_bind
    from servonaut.services.vault.ec2_host_keys import BEGIN_KEYS, END_KEYS

    server = {
        "id": "i-web1",
        "name": "web-1",
        "public_ip": "198.51.100.1",
        "provider": "aws",
        "account": "prod-acc",
        "region": "us-east-1",
    }
    priv = ed25519.Ed25519PrivateKey.generate()
    key_openssh = priv.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
    keys = [{"item_id": "k1", "label": "web-1", "name": "web-1.pem", "fingerprint": "SHA256:a"}]

    service = _AutoBindService()
    service.keys = keys

    monkeypatch.setattr(vault, "_auto_bind_servers", lambda: [server])
    monkeypatch.setattr(auto_bind, "trusted_host_keys", lambda inst, h, p: [])

    mock_client = MagicMock()
    # botocore returns the base64-decoded console output text directly in Output
    mock_client.get_console_output.return_value = {
        "Output": f"console boot\n{BEGIN_KEYS}\n{key_openssh}\n{END_KEYS}\n"
    }
    mock_factory = MagicMock()
    mock_factory.client.return_value = mock_client
    mock_accounts = MagicMock()
    mock_accounts.aws_client_factory.return_value = mock_factory

    monkeypatch.setattr(
        "servonaut.services.accounts.headless.build_account_registry",
        lambda cfg: mock_accounts,
    )

    vault.set_vault_service_factory(lambda: service)
    try:
        code = vault.handle_vault_command(
            _parser().parse_args(["vault", "auto-bind", "--dry-run", "--fetch-host-keys"])
        )
    finally:
        vault.set_vault_service_factory(None)

    assert code == 0
    mock_accounts.aws_client_factory.assert_called_once_with("prod-acc")
    mock_factory.client.assert_called_once_with("ec2", "us-east-1")
    mock_client.get_console_output.assert_called_once_with(InstanceId="i-web1")
    out = capsys.readouterr().out
    assert "verified by AWS console output" in out


def test_auto_bind_fetch_host_keys_when_registry_fails_reports_not_verified_and_never_calls_boto3(monkeypatch, caplog, capsys) -> None:
    import logging
    from unittest.mock import MagicMock
    from servonaut.services.vault import auto_bind

    server = {
        "id": "i-web1",
        "name": "web-1",
        "public_ip": "198.51.100.1",
        "provider": "aws",
        "account": "prod-acc",
        "region": "us-east-1",
    }
    keys = [{"item_id": "k1", "label": "web-1", "name": "web-1.pem", "fingerprint": "SHA256:a"}]

    service = _AutoBindService()
    service.keys = keys

    monkeypatch.setattr(vault, "_auto_bind_servers", lambda: [server])

    calls = 0

    def fake_trusted(inst, h, p):
        nonlocal calls
        calls += 1
        return [] if calls <= 1 else [service.HOST_KEY]

    monkeypatch.setattr(auto_bind, "trusted_host_keys", fake_trusted)
    monkeypatch.setattr(auto_bind, "read_host_keys_from_file", lambda *args, **kwargs: [service.HOST_KEY])

    def bad_registry(cfg):
        raise RuntimeError("cannot initialize account store")

    monkeypatch.setattr("servonaut.services.accounts.headless.build_account_registry", bad_registry)

    mock_boto = MagicMock()
    monkeypatch.setattr("boto3.client", mock_boto, raising=False)
    monkeypatch.setattr("boto3.Session", mock_boto, raising=False)

    vault.set_vault_service_factory(lambda: service)
    with caplog.at_level(logging.DEBUG):
        try:
            code = vault.handle_vault_command(
                _parser().parse_args(["vault", "auto-bind", "--dry-run", "--fetch-host-keys"])
            )
        finally:
            vault.set_vault_service_factory(None)

    assert code == 0
    assert mock_boto.call_count == 0
    assert any("Failed to build account registry" in record.message for record in caplog.records)
    out = capsys.readouterr().out
    assert "not verified" in out


def test_auto_bind_team_resolves_team_vault_and_binds_shared_servers(monkeypatch, capsys) -> None:
    from unittest.mock import AsyncMock, MagicMock
    from servonaut.services.vault import auto_bind

    shared_server = {
        "id": "srv-1",
        "name": "dev-box",
        "hostname": "198.51.100.2",
        "is_shared": True,
        "team_slug": "devs",
        "login_user": "ubuntu",
    }
    keys = [{"item_id": "k-dev", "label": "dev-box", "name": "dev-box.pem", "fingerprint": "SHA256:dev"}]

    service = _AutoBindService()
    service.list_vaults = AsyncMock(return_value=[
        {"vault_id": "tv-devs", "kind": "team", "team": {"slug": "devs"}, "my_grant": {"sealed_key": "s1"}},
    ])
    service.teams = MagicMock()
    service.teams.list_teams = AsyncMock(return_value=[{"slug": "devs", "role": "admin", "name": "Devs"}])
    service.teams.list_shared_servers = AsyncMock(return_value=[shared_server])
    service.ssh_key_choices = AsyncMock(return_value=keys)
    service.bind = AsyncMock(return_value={"source": "servonaut_vault"})

    monkeypatch.setattr(vault, "_auto_bind_servers", lambda: [shared_server])
    monkeypatch.setattr(auto_bind, "trusted_host_keys", lambda inst, h, p: [service.HOST_KEY])

    vault.set_vault_service_factory(lambda: service)
    try:
        code = vault.handle_vault_command(
            _parser().parse_args(["vault", "auto-bind", "--team", "devs", "--yes"])
        )
    finally:
        vault.set_vault_service_factory(None)

    assert code == 0
    service.bind.assert_awaited_once_with(
        vault_id="tv-devs",
        server="srv-1",
        item_id="k-dev",
        team="devs",
        login="ubuntu",
        pin_host_key=False,
        host_keys=[service.HOST_KEY],
        replace_existing=False,
    )
    out = capsys.readouterr()
    assert "Bound vault keys to 1 of 1 servers." in out.err


def test_auto_bind_team_no_vault_returns_error(monkeypatch, capsys) -> None:
    from unittest.mock import AsyncMock, MagicMock

    service = _AutoBindService()
    service.list_vaults = AsyncMock(return_value=[
        {"vault_id": VAULT_ID, "kind": "personal", "label": "Personal"},
    ])
    service.teams = MagicMock()
    service.teams.list_teams = AsyncMock(return_value=[{"slug": "devs", "role": "admin", "name": "devs"}])
    service.teams.list_shared_servers = AsyncMock(return_value=[])

    vault.set_vault_service_factory(lambda: service)
    try:
        code = vault.handle_vault_command(
            _parser().parse_args(["vault", "auto-bind", "--team", "devs", "--yes"])
        )
    finally:
        vault.set_vault_service_factory(None)

    assert code == 1
    assert "You have no team vault for devs yet: run `servonaut vault create --team devs`." in capsys.readouterr().err


def test_auto_bind_team_vault_waiting_for_grant_approval_returns_error(monkeypatch, capsys) -> None:
    from unittest.mock import AsyncMock, MagicMock

    service = _AutoBindService()
    service.list_vaults = AsyncMock(return_value=[
        {"vault_id": "tv-devs", "kind": "team", "team": {"slug": "devs"}, "my_grant": None},
    ])
    service.teams = MagicMock()
    service.teams.list_teams = AsyncMock(return_value=[{"slug": "devs", "role": "admin", "name": "Devs"}])
    service.teams.list_shared_servers = AsyncMock(return_value=[])

    vault.set_vault_service_factory(lambda: service)
    try:
        code = vault.handle_vault_command(
            _parser().parse_args(["vault", "auto-bind", "--team", "devs", "--yes"])
        )
    finally:
        vault.set_vault_service_factory(None)

    assert code == 1
    assert "Your access to the team vault for Devs is still waiting for approval." in capsys.readouterr().err


def test_auto_bind_team_dry_run_and_json(monkeypatch, capsys) -> None:
    from unittest.mock import AsyncMock, MagicMock
    from servonaut.services.vault import auto_bind

    shared_server = {
        "id": "srv-1",
        "name": "dev-box",
        "hostname": "198.51.100.2",
        "is_shared": True,
        "team_slug": "devs",
        "login_user": "ubuntu",
    }
    keys = [{"item_id": "k-dev", "label": "dev-box", "name": "dev-box.pem", "fingerprint": "SHA256:dev"}]

    service = _AutoBindService()
    service.list_vaults = AsyncMock(return_value=[
        {"vault_id": "tv-devs", "kind": "team", "team": {"slug": "devs"}, "my_grant": {"sealed_key": "s1"}},
    ])
    service.teams = MagicMock()
    service.teams.list_teams = AsyncMock(return_value=[{"slug": "devs", "role": "admin", "name": "Devs"}])
    service.teams.list_shared_servers = AsyncMock(return_value=[shared_server])
    service.ssh_key_choices = AsyncMock(return_value=keys)
    service.bind = AsyncMock(return_value={"source": "servonaut_vault"})

    monkeypatch.setattr(vault, "_auto_bind_servers", lambda: [shared_server])
    monkeypatch.setattr(auto_bind, "trusted_host_keys", lambda inst, h, p: [service.HOST_KEY])

    vault.set_vault_service_factory(lambda: service)
    try:
        code = vault.handle_vault_command(
            _parser().parse_args(["vault", "auto-bind", "--team", "devs", "--dry-run", "--json"])
        )
    finally:
        vault.set_vault_service_factory(None)

    assert code == 0
    assert service.bind.call_count == 0
    report = json.loads(capsys.readouterr().out)
    assert report["vault_id"] == "tv-devs"
    assert len(report["servers"]) == 1
    assert report["servers"][0]["server"] == "dev-box"
    assert report["servers"][0]["team"] == "devs"
    assert report["servers"][0]["status"] == "ready"


def test_auto_bind_team_loads_shared_servers_via_team_service(monkeypatch, capsys) -> None:
    from unittest.mock import AsyncMock, MagicMock
    from servonaut.services.vault import auto_bind

    shared_server = {
        "id": "srv-remote",
        "name": "api-box",
        "hostname": "198.51.100.5",
        "is_shared": True,
        "team_slug": "devs",
        "login": "ubuntu",
    }
    keys = [{"item_id": "k-api", "label": "api-box", "name": "api-box.pem", "fingerprint": "SHA256:api"}]

    service = _AutoBindService()
    service.list_vaults = AsyncMock(return_value=[
        {"vault_id": "tv-devs", "kind": "team", "team": {"slug": "devs"}, "my_grant": {"sealed_key": "s1"}},
    ])
    service.ssh_key_choices = AsyncMock(return_value=keys)
    service.teams = MagicMock()
    service.teams.list_teams = AsyncMock(return_value=[{"slug": "devs", "role": "admin", "name": "Devs"}])
    service.teams.list_shared_servers = AsyncMock(return_value=[shared_server])

    own_server = {"id": "i-local", "name": "web-local", "public_ip": "198.51.100.1"}
    monkeypatch.setattr(vault, "_auto_bind_servers", lambda: [own_server])
    monkeypatch.setattr(auto_bind, "trusted_host_keys", lambda inst, h, p: [service.HOST_KEY])

    vault.set_vault_service_factory(lambda: service)
    try:
        code = vault.handle_vault_command(
            _parser().parse_args(["vault", "auto-bind", "--team", "devs", "--dry-run", "--json"])
        )
    finally:
        vault.set_vault_service_factory(None)

    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert len(report["servers"]) == 1
    assert report["servers"][0]["server"] == "api-box"


def test_auto_bind_team_refuses_member_role(monkeypatch, capsys) -> None:
    from unittest.mock import AsyncMock, MagicMock

    service = _AutoBindService()
    service.teams = MagicMock()
    service.teams.list_teams = AsyncMock(return_value=[{"slug": "devs", "role": "member", "name": "Devs"}])
    service.bind = AsyncMock()

    vault.set_vault_service_factory(lambda: service)
    try:
        code = vault.handle_vault_command(
            _parser().parse_args(["vault", "auto-bind", "--team", "devs", "--yes"])
        )
    finally:
        vault.set_vault_service_factory(None)

    assert code == 1
    assert "Only team owners and admins can bind vault keys for Devs." in capsys.readouterr().err
    assert service.bind.call_count == 0


def test_auto_bind_team_list_teams_failure_uses_failure_reason(monkeypatch, capsys) -> None:
    from unittest.mock import AsyncMock, MagicMock
    from servonaut.services.api_client import APIError

    service = _AutoBindService()
    service.teams = MagicMock()
    service.teams.list_teams = AsyncMock(side_effect=APIError(code="forbidden", message="Forbidden", status=403))

    vault.set_vault_service_factory(lambda: service)
    try:
        code = vault.handle_vault_command(
            _parser().parse_args(["vault", "auto-bind", "--team", "devs", "--yes"])
        )
    finally:
        vault.set_vault_service_factory(None)

    assert code == 1
    err = capsys.readouterr().err
    assert "Could not load your teams (HTTP 403, forbidden)." in err


def test_auto_bind_team_unknown_team_returns_error(monkeypatch, capsys) -> None:
    from unittest.mock import AsyncMock, MagicMock

    service = _AutoBindService()
    service.teams = MagicMock()
    service.teams.list_teams = AsyncMock(return_value=[{"slug": "other", "role": "admin"}])

    vault.set_vault_service_factory(lambda: service)
    try:
        code = vault.handle_vault_command(
            _parser().parse_args(["vault", "auto-bind", "--team", "devs", "--yes"])
        )
    finally:
        vault.set_vault_service_factory(None)

    assert code == 1
    assert "You are not in a team called devs." in capsys.readouterr().err


def test_auto_bind_team_shared_servers_failure_returns_error(monkeypatch, capsys) -> None:
    from unittest.mock import AsyncMock, MagicMock

    service = _AutoBindService()
    service.teams = MagicMock()
    service.teams.list_teams = AsyncMock(return_value=[{"slug": "devs", "role": "admin"}])
    service.teams.list_shared_servers = AsyncMock(side_effect=RuntimeError("network timeout"))

    vault.set_vault_service_factory(lambda: service)
    try:
        code = vault.handle_vault_command(
            _parser().parse_args(["vault", "auto-bind", "--team", "devs", "--yes"])
        )
    finally:
        vault.set_vault_service_factory(None)

    assert code == 1
    assert "Could not load shared servers for devs" in capsys.readouterr().err


def test_auto_bind_team_with_personal_vault_refused(monkeypatch, capsys) -> None:
    from unittest.mock import AsyncMock, MagicMock

    service = _AutoBindService()
    service.list_vaults = AsyncMock(return_value=[
        {"vault_id": VAULT_ID, "kind": "personal", "label": "Personal"},
        {"vault_id": "tv-ops", "kind": "team", "team": {"slug": "ops"}},
    ])
    service.teams = MagicMock()
    service.teams.list_teams = AsyncMock(return_value=[{"slug": "ops", "role": "admin"}])
    service.teams.list_shared_servers = AsyncMock(return_value=[])
    service.bind = AsyncMock()

    vault.set_vault_service_factory(lambda: service)
    try:
        code = vault.handle_vault_command(
            _parser().parse_args(["vault", "auto-bind", "--team", "ops", "--vault", "Personal keys", "--yes"])
        )
    finally:
        vault.set_vault_service_factory(None)

    assert code == 1
    err = capsys.readouterr().err
    assert '"Personal keys" is not ops\'s team vault: leave out --vault to use the team\'s vault.' in err
    assert service.bind.call_count == 0


def test_auto_bind_team_with_matching_team_vault_accepted(monkeypatch, capsys) -> None:
    from unittest.mock import AsyncMock, MagicMock
    from servonaut.services.vault import auto_bind

    shared_server = {
        "id": "srv-ops",
        "name": "ops-box",
        "hostname": "198.51.100.3",
        "is_shared": True,
        "team_slug": "ops",
        "login_user": "ubuntu",
    }
    keys = [{"item_id": "k-ops", "label": "ops-box", "name": "ops-box.pem", "fingerprint": "SHA256:ops"}]

    service = _AutoBindService()
    service.list_vaults = AsyncMock(return_value=[
        {"vault_id": "tv-ops", "kind": "team", "team": {"slug": "ops"}},
    ])
    service.teams = MagicMock()
    service.teams.list_teams = AsyncMock(return_value=[{"slug": "ops", "role": "owner", "name": "Ops"}])
    service.teams.list_shared_servers = AsyncMock(return_value=[shared_server])
    service.ssh_key_choices = AsyncMock(return_value=keys)
    service.bind = AsyncMock(return_value={"source": "servonaut_vault"})

    monkeypatch.setattr(vault, "_auto_bind_servers", lambda: [shared_server])
    monkeypatch.setattr(auto_bind, "trusted_host_keys", lambda inst, h, p: [service.HOST_KEY])

    vault.set_vault_service_factory(lambda: service)
    try:
        code = vault.handle_vault_command(
            _parser().parse_args(["vault", "auto-bind", "--team", "ops", "--vault", "tv-ops", "--yes"])
        )
    finally:
        vault.set_vault_service_factory(None)

    assert code == 0
    service.bind.assert_awaited_once()



def _vault_record(name, kind, vault_id, team=None, items=0):
    """A vault as the service lists it, with the signed material a person never needs to read."""
    return {
        "vault_id": vault_id, "kind": kind, "name": name, "team": team,
        "counts": {"items": items, "open_exposures": 0, "pending_recipients": 0},
        "my_grant": {"sealed_private_key": "c2VhbGVk", "signature": "c2lnbmF0dXJl"},
        "versions": [{"version": 1, "signature": "c2lnbmF0dXJl", "creator_identity_id": "creator-1"}],
    }


TEAM_VAULT_ID = "6b2c3d4e-5f60-4b7c-9d8e-0f1a2b3c4d5e"  # synthetic fixture  leak-guard:allow


def _run_with(service, argv):
    vault.set_vault_service_factory(lambda: service)
    try:
        return vault.handle_vault_command(_parser().parse_args(argv))
    finally:
        vault.set_vault_service_factory(None)


def test_vault_list_shows_one_line_per_vault(capsys) -> None:
    service = SimpleNamespace(list_vaults=AsyncMock(return_value=[
        _vault_record("Personal", "personal", VAULT_ID, items=2),
        _vault_record("Team vault", "team", TEAM_VAULT_ID, team={"slug": "example-team"}),
    ]))

    assert _run_with(service, ["vault", "list"]) == 0

    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == ["Name", "Kind", "Items", "Open", "exposures", "Vault", "ID"]
    assert lines[1].split() == ["Personal", "personal", "2", "0", VAULT_ID]
    assert lines[2].split() == ["Team", "vault", "team", "example-team", "0", "0", TEAM_VAULT_ID]
    assert len(lines) == 3


def test_vault_list_without_vaults_says_how_to_create_one(capsys) -> None:
    assert _run_with(SimpleNamespace(list_vaults=AsyncMock(return_value=[])), ["vault", "list"]) == 0

    assert capsys.readouterr().out.strip() == "You have no vaults yet: run `servonaut vault create`."


def test_vault_list_json_keeps_the_full_records(capsys) -> None:
    record = _vault_record("Personal", "personal", VAULT_ID)
    assert _run_with(SimpleNamespace(list_vaults=AsyncMock(return_value=[record])), ["vault", "list", "--json"]) == 0

    assert json.loads(capsys.readouterr().out) == [record]


def test_vault_create_names_the_vault_and_the_next_step(capsys) -> None:
    created = _vault_record("Personal", "personal", VAULT_ID)
    service = SimpleNamespace(create_vault=AsyncMock(return_value=created))

    assert _run_with(service, ["vault", "create", "--name", "Personal"]) == 0

    assert capsys.readouterr().out.splitlines() == [
        f'Created your personal vault "Personal" (ID {VAULT_ID}).',
        f"Next: import an SSH key with `servonaut vault import ssh --vault {VAULT_ID} --path ~/.ssh/<key>`.",
    ]


def test_vault_create_for_a_team_names_the_team(capsys) -> None:
    created = _vault_record("Team vault", "team", TEAM_VAULT_ID, team={"slug": "example-team"})
    service = SimpleNamespace(create_vault=AsyncMock(return_value=created))

    assert _run_with(service, ["vault", "create", "--team", "example-team", "--name", "Team vault"]) == 0

    first = capsys.readouterr().out.splitlines()[0]
    assert first == f'Created the team vault "Team vault" for example-team (ID {TEAM_VAULT_ID}).'


def test_vault_grants_process_says_what_happened(capsys) -> None:
    results = [{
        "accepted": [{"recipient_user_id": 7, "recipient_identity_id": "identity-7"}],
        "skipped": [],
        "pending_confirmation": [{"user_id": 8, "identity_id": "identity-8", "safety_number": "12345",
                                  "identity_changed": False}],
    }]
    service = SimpleNamespace(process_grants=AsyncMock(return_value=results))

    assert _run_with(service, ["vault", "grants", "process", "--yes"]) == 0

    out = capsys.readouterr().out
    assert out.strip() == "Granted access to 1 member. 1 member still needs approval before getting access."
    assert "identity-7" not in out
