"""Focused parser and command-boundary tests for ``servonaut vault``."""
from __future__ import annotations

import argparse
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

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
