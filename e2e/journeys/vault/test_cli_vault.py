"""Default-factory CLI journey for the native Team Vault.

The test deliberately starts real child commands.  It never installs a vault
service factory, so configuration, local custody, request signing and API
clients all take their production paths against the hermetic FakeCloud.
"""

from __future__ import annotations

import base64
import json
import os
import re
import signal
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from e2e.harness.fake_cloud.routes_account import VAULT_SHARED_SERVER_HOST_KEY
from e2e.harness.interactive import InteractiveCli
from e2e.harness.processes import require_armed
from e2e.harness.terminal import _PlainText, _read_until, _start_on_pty


pytestmark = [pytest.mark.e2e_pr]

_RECOVERY_KEY = re.compile(r"(SVRK1-(?:[A-Z0-9]+-)+[A-Z0-9]+)")
_RECOVERY_PROMPT = re.compile(r"Re-enter recovery group (\d+):")
_VAULT_TEAM = {
    "id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "slug": "example-team",
    "name": "Example team",
    "role": "owner",
    "member_count": 2,
}


def _configure_test_custody(journey) -> None:
    """Use a throwaway CI KEK and a null keyring only for this child journey."""
    journey.env_overrides["SERVONAUT_VAULT_DEVICE_KEY"] = base64.b64encode(b"\0" * 32).decode("ascii")
    journey.env_overrides["PYTHON_KEYRING_BACKEND"] = "keyring.backends.null.Keyring"


def _setup_with_recovery_confirmation(journey, home, servonaut_cmd) -> tuple[object, str]:
    """Answer the two randomly selected recovery-group prompts on a real pty."""
    env = journey.child_env(home)
    process, master = _start_on_pty(
        [*servonaut_cmd, "vault", "setup", "--device-name", "journey-device", "--platform", "linux"],
        env=env, cwd=home.base, size=(160, 50),
    )
    screen = _PlainText()
    try:
        if not _read_until(
            master, screen, lambda text: _RECOVERY_KEY.search(text) is not None,
            time.monotonic() + 30, "the generated vault recovery key",
        ):
            raise AssertionError("vault setup exited before displaying its recovery key")
        match = _RECOVERY_KEY.search(screen.text)
        assert match is not None
        recovery_key = match.group(1)
        # The CLI numbers every dash-delimited group, including ``SVRK1``.
        groups = recovery_key.split("-")
        answered = 0
        while answered < 2:
            if not _read_until(
                master,
                screen,
                lambda text: len(_RECOVERY_PROMPT.findall(text)) > answered,
                time.monotonic() + 30, "a recovery-group confirmation prompt",
            ):
                raise AssertionError(
                    "vault setup exited before recovery confirmation completed; output:\n" + screen.text
                )
            prompt = _RECOVERY_PROMPT.findall(screen.text)[answered]
            os.write(master, (groups[int(prompt) - 1] + "\n").encode("ascii"))
            answered += 1
        _read_until(master, screen, lambda _text: False, time.monotonic() + 30, "vault setup completion")
        returncode = process.wait(timeout=30)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        os.close(master)
    require_armed(journey.armed_log, pid=process.pid)
    result = type("PtyResult", (), {"returncode": returncode, "text": screen.text})()
    return result, recovery_key


def _json(result) -> dict:
    assert result.returncode == 0, result.describe()
    return json.loads(result.stdout)


def _assert_only_getpass_tty_access(journey) -> None:
    """A real pty makes getpass open /dev/tty; no other sandbox escape is valid."""
    escapes = journey.take_escapes()
    assert escapes and all(
        escape.get("kind") == "filesystem" and escape.get("target") == "open /dev/tty"
        for escape in escapes
    ), escapes


def _approve_device_with_sas(journey, home, servonaut_cmd, device_id: str) -> object:
    """Approve a pending peer with the real CLI after its SAS is revealed."""
    process, master = _start_on_pty(
        [*servonaut_cmd, "vault", "devices", "approve", device_id],
        env=journey.child_env(home), cwd=home.base, size=(160, 50),
    )
    screen = _PlainText()
    try:
        if not _read_until(
            master, screen, lambda text: "Does the other device show exactly this safety number?" in text,
            time.monotonic() + 30, "the device SAS confirmation prompt",
        ):
            raise AssertionError("device approval exited before its SAS confirmation prompt:\n" + screen.text)
        os.write(master, b"y\n")
        _read_until(master, screen, lambda _text: False, time.monotonic() + 30, "device approval completion")
        returncode = process.wait(timeout=30)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        os.close(master)
    require_armed(journey.armed_log, pid=process.pid)
    journey.children.append(
        f"$ {' '.join(process.args)}\n[exit {returncode}]\n--- pty ---\n{screen.text}"
    )
    return type("PtyResult", (), {"returncode": returncode, "text": screen.text})()


def test_vault_cli_default_factory_setup_device_add_items_binding_and_ca(
    journey, fake_cloud, cli, account_home, servonaut_cmd
):
    # This team is needed only for the Vault journey.  The general account
    # fixture remains intentionally minimal so unrelated account journeys do
    # not acquire a synthetic team.
    fake_cloud.account.configure(teams=[_VAULT_TEAM])
    _configure_test_custody(journey)
    primary = account_home("vault-primary")

    before = _json(cli(primary, "vault", "status", "--json"))
    assert before["local_identity"] is None
    setup, _recovery_key = _setup_with_recovery_confirmation(journey, primary, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)

    after = _json(cli(primary, "vault", "status", "--json"))
    assert after["local_identity"] == after["fingerprint"]
    assert after["remote"]["identity"]["fingerprint"] == after["fingerprint"]

    secondary = account_home("vault-secondary")
    secondary_env = journey.child_env(secondary)
    # Device approval is a streaming interactive journey. Keep `--json` for
    # completed commands: its stdout is deliberately one final document, so
    # it cannot also expose interim registration metadata to the approver.
    secondary_env["PYTHONUNBUFFERED"] = "1"
    with InteractiveCli.start(
        servonaut_cmd, "vault", "devices", "add", "--device-name", "second-device", "--platform", "linux",
        env=secondary_env, cwd=secondary.base, armed_log=journey.armed_log, log=journey.children,
    ) as added:
        device_id = added.expect(r"device_id: ([0-9a-f-]{36})").group(1)
        approved = _approve_device_with_sas(journey, primary, servonaut_cmd, device_id)
        assert approved.returncode == 0, approved.text
    assert added.result is not None and added.result.returncode == 0, added.result.describe() if added.result else ""
    second_status = _json(cli(secondary, "vault", "status", "--json"))
    assert second_status["local_identity"] == after["local_identity"]

    created = _json(cli(primary, "vault", "create", "--team", "example-team", "--name", "Journey vault", "--json"))
    vault_id = created["vault_id"]
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).private_bytes(
        Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
    )
    source = primary.home / "journey_ed25519"
    source.write_bytes(private_key)
    source.chmod(0o600)
    imported = _json(cli(primary, "vault", "import", "ssh", "--vault", vault_id, "--path", str(source), "--json"))
    item_id = imported["item_id"]

    listed = _json(cli(primary, "vault", "items", "--vault", vault_id, "--json"))
    assert [row["item_id"] for row in listed["data"]] == [item_id]

    emergency = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65))).private_bytes(
        Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
    )
    emergency_path = primary.home / "break_glass_ed25519"
    emergency_path.write_bytes(emergency)
    emergency_path.chmod(0o600)
    break_glass = _json(cli(
        primary, "vault", "import", "ssh", "--vault", vault_id, "--path", str(emergency_path),
        "--break-glass", "--from-cidr", "10.0.0.0/8", "--json",
    ))
    assert break_glass["type"] == "break_glass"
    assert break_glass["item"]["type"] == "break_glass"
    metadata = _json(cli(primary, "vault", "show", item_id, "--vault", vault_id, "--json"))
    assert "ciphertext" not in metadata and "private_key_openssh" not in metadata
    revealed = _json(cli(primary, "vault", "show", item_id, "--vault", vault_id, "--reveal", "--yes", "--json"))
    assert revealed["plaintext"] == "[revealed only on terminal]"

    untrusted = cli(
        primary, "vault", "bind", "server-1", item_id, "--vault", vault_id,
        "--team", "example-team", "--pin-host-key", "--yes", "--json",
    )
    assert untrusted.returncode == 1
    assert "does not trust a host key for the server yet" in untrusted.stderr

    bound = _json(cli(
        primary, "vault", "bind", "server-1", item_id, "--vault", vault_id,
        "--team", "example-team", "--host-key", VAULT_SHARED_SERVER_HOST_KEY, "--yes", "--json",
    ))
    assert bound["source"] == "servonaut_vault"
    assert bound["valid"] is True

    enabled = _json(cli(primary, "ca", "enable", "--team", "example-team", "--yes", "--json"))
    assert enabled["enabled"] is True
    status = _json(cli(primary, "ca", "status", "--team", "example-team", "--json"))
    assert status["enabled"] is True

    refused = cli(primary, "ca", "policy", "--team", "example-team", "--set", '{"role_logins": {"member": ["Bad Login!"]}}')
    assert refused.returncode == 1
    assert "HTTP 422, validation_failed" in refused.stderr
    updated = cli(
        primary, "ca", "policy", "--team", "example-team",
        "--set", '{"role_logins": {"member": ["deploy"]}, "interactive_ttl_seconds": 3600}',
    )
    assert updated.returncode == 0, updated.stderr
    assert "policy.role_logins.member.1: deploy" in updated.stdout
    assert "policy.interactive_ttl_seconds: 3600" in updated.stdout
    fake_cloud.assert_no_unexpected_errors(("PUT", r"/api/v1/teams/example-team/ssh-ca/policy", 422))
