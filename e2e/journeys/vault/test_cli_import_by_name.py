"""Importing a passphrase-protected SSH key into a vault named on the command line.

Real child commands run against the hermetic FakeCloud: the passphrase is typed
on a real terminal, and every ``--vault`` below is the vault's name.
"""
from __future__ import annotations

import json
import os
import signal
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, Encoding, PrivateFormat, PublicFormat,
)

from e2e.harness.processes import require_armed
from e2e.harness.terminal import _PlainText, _read_until, _start_on_pty
from e2e.journeys.vault.test_cli_vault import (
    _assert_only_getpass_tty_access,
    _configure_test_custody,
    _setup_with_recovery_confirmation,
)
from servonaut.services.vault import crypto

pytestmark = [pytest.mark.e2e_pr]

PASSPHRASE = "correct horse battery"


def _json(result) -> dict:
    assert result.returncode == 0, result.describe()
    return json.loads(result.stdout)


def _import_on_terminal(journey, home, servonaut_cmd, key_path, answers: list[str]) -> tuple[int, str]:
    """Run `vault import ssh` on a pty and answer each passphrase prompt in turn."""
    process, master = _start_on_pty(
        [*servonaut_cmd, "vault", "import", "ssh", "--vault", "personal", "--path", str(key_path)],
        env=journey.child_env(home), cwd=home.base, size=(160, 50),
    )
    screen = _PlainText()
    try:
        for answered, answer in enumerate(answers):
            _read_until(
                master, screen, lambda text: text.count("Passphrase for web_ed25519") > answered,
                time.monotonic() + 30, "a passphrase prompt",
            )
            os.write(master, (answer + "\n").encode("utf-8"))
        _read_until(master, screen, lambda _text: False, time.monotonic() + 30, "the import result")
        returncode = process.wait(timeout=30)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        os.close(master)
    require_armed(journey.armed_log, pid=process.pid)
    return returncode, screen.text


def test_a_passphrase_key_is_imported_into_a_vault_named_by_its_name(journey, fake_cloud, cli, account_home, servonaut_cmd):
    _configure_test_custody(journey)
    home = account_home("vault-import-by-name")
    setup, _ = _setup_with_recovery_confirmation(journey, home, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    vault_id = _json(cli(home, "vault", "create", "--name", "Personal", "--json"))["vault_id"]

    key = Ed25519PrivateKey.generate()
    key_path = home.home / "web_ed25519"
    key_path.write_bytes(key.private_bytes(
        Encoding.PEM, PrivateFormat.OpenSSH, BestAvailableEncryption(PASSPHRASE.encode("utf-8")),
    ))
    key_path.chmod(0o600)
    fingerprint = crypto.ssh_public_fingerprint(
        key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
    )

    # Without a terminal there is nobody to ask: refuse and say how to do it.
    piped = cli(home, "vault", "import", "ssh", "--vault", "Personal", "--path", str(key_path))
    assert piped.returncode == 1
    assert "this SSH key has a passphrase; run the import in a terminal to enter it" in piped.stderr

    # On a terminal: one wrong passphrase, then the right one. The name matches ignoring case.
    returncode, text = _import_on_terminal(journey, home, servonaut_cmd, key_path, ["not it", PASSPHRASE])
    assert returncode == 0, text
    assert "Wrong passphrase." in text
    assert PASSPHRASE not in text
    _assert_only_getpass_tty_access(journey)

    listed = _json(cli(home, "vault", "items", "--vault", "Personal", "--json"))
    assert [item["public_fingerprint"] for item in listed["data"]] == [fingerprint]
    assert key_path.read_bytes().startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")  # the file is left as it was

    unknown = cli(home, "vault", "items", "--vault", "No such vault")
    assert unknown.returncode == 1
    assert "no vault you can read has that name; `servonaut vault list` shows your vaults" in unknown.stderr
    by_id = _json(cli(home, "vault", "items", "--vault", vault_id, "--json"))
    assert by_id["data"] == listed["data"]
