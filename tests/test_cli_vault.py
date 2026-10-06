"""Focused parser and command-boundary tests for ``servonaut vault``."""
from __future__ import annotations

import argparse
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from servonaut.cli import vault
from servonaut.services.api_client import APIError


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
    args = _parser().parse_args(["vault", "show", "item-1", "--vault", "vault-1"])

    assert args.reveal is False
    assert args.vault == "vault-1"


def test_vault_parser_accepts_pending_device_add() -> None:
    args = _parser().parse_args(["vault", "devices", "add", "--device-name", "laptop"])

    assert args.vault_devices_command == "add"
    assert args.device_name == "laptop"


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
        args = _parser().parse_args(["vault", "--json", "show", "item-1", "--vault", "v", "--reveal", "--yes"])
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
            ["vault", "escrow", "setup", "--vault", "vault-1", "--label", "offline", "--json"]
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
                "vault", "exposures", "--vault", "vault-1", "--rotate-ssh", "item-1",
                "--team", "ops", "--server", "server-1", "--server", "server-2", "--yes",
            ]
        )
        assert vault.handle_vault_command(args) == 0
    finally:
        vault.set_vault_service_factory(None)

    assert service.kwargs == {
        "vault_id": "vault-1",
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
                "vault", "bind-personal", "--vault", "vault-1", "--item", "item-1",
                "--provider", "aws", "--instance-id", "i-123", "--hostname", "host.example",
                "--login", "ubuntu", "--host-key", "ssh-ed25519 AAAA", "--yes",
            ]
        )
        assert vault.handle_vault_command(args) == 0
    finally:
        vault.set_vault_service_factory(None)

    assert service.kwargs == {
        "vault_id": "vault-1",
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
            "vault", "bind", "server-1", "item-1", "--vault", "vault-1", "--team", "team-a",
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
            "vault", "exposures", "--vault", "vault-1", "--rotate-ssh", "item-1",
            "--team", "team-a", "--server", "server-1", "--yes",
        ])
        assert vault.handle_vault_command(args) == 1
    finally:
        vault.set_vault_service_factory(None)

    error = capsys.readouterr().err
    assert "did not finish" in error and "server-1" in error
    assert "The exposure stays open" in error


def test_break_glass_import_requires_a_source_network_and_vice_versa(capsys) -> None:
    class Service:
        close = MagicMock()
        import_keys = AsyncMock()

    vault.set_vault_service_factory(Service)
    try:
        without_network = _parser().parse_args(["vault", "import", "ssh", "--vault", "v", "--path", "k", "--break-glass"])
        without_flag = _parser().parse_args(["vault", "import", "ssh", "--vault", "v", "--path", "k", "--from-cidr", "10.0.0.0/8"])
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
            "vault", "exposures", "--vault", "vault-1", "--rotate-ssh", "item-1",
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
    assert "servonaut vault exposures --vault vault-1 --resolve e-1 --resolution rotated" in err


def test_exposure_listing_notes_a_key_replaced_in_the_vault(capsys) -> None:
    class Service:
        close = MagicMock()
        list_exposures = AsyncMock(return_value={"data": [
            {"exposure_id": "e-1", "key_replaced": True}, {"exposure_id": "e-2", "key_replaced": False},
        ]})

    vault.set_vault_service_factory(Service)
    try:
        assert vault.handle_vault_command(_parser().parse_args(["vault", "exposures", "--vault", "vault-1"])) == 0
    finally:
        vault.set_vault_service_factory(None)

    out = capsys.readouterr().out
    assert "Note: exposure e-1: key replaced in the vault; the old key may still be on servers." in out
    assert "exposure e-2: key replaced" not in out
