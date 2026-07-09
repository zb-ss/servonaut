"""Tests for bw_key_import — local SSH key scanning + decryption.

All key fixtures are generated in-test with ``cryptography`` — no committed key
files and no ssh-keygen dependency (a single cross-validation test is skipped
when ssh-keygen is absent).
"""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

from tests._key_fixtures import OPENSSH_HEADER, openssh_armor

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, x25519
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_ssh_private_key,
)

from servonaut.services.bw_key_import import (
    DEFAULT_MAX_KEY_BYTES,
    DecryptedKey,
    KeyImportError,
    ScannedKey,
    WrongPassphraseError,
    decrypt_private_key,
    load_unencrypted_key,
    read_key_bytes,
    scan_directory,
)

PASSPHRASE = "correct horse battery staple"


def _ed25519_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def _rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _openssh_private_bytes(key, passphrase: str | None = None) -> bytes:
    encryption = (
        BestAvailableEncryption(passphrase.encode()) if passphrase else NoEncryption()
    )
    return key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, encryption)


def _x25519_pkcs8_bytes(passphrase: str | None = None) -> bytes:
    """A parseable-but-not-SSH PKCS#8 key (e.g. dropped by WireGuard/age tooling)."""
    encryption = (
        BestAvailableEncryption(passphrase.encode()) if passphrase else NoEncryption()
    )
    return x25519.X25519PrivateKey.generate().private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, encryption
    )


def _public_line(key) -> str:
    return key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()


def _expected_fingerprint(key) -> str:
    """Hand-computed fingerprint: SHA256: + unpadded b64 of sha256(pubkey blob)."""
    blob = base64.b64decode(_public_line(key).split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


class TestScanDirectory:
    def test_finds_unencrypted_ed25519_with_correct_fingerprint(self, tmp_path: Path):
        key = _ed25519_key()
        (tmp_path / "id_ed25519").write_bytes(_openssh_private_bytes(key))

        results = scan_directory(tmp_path)

        assert len(results) == 1
        scanned = results[0]
        assert scanned.filename == "id_ed25519"
        assert scanned.encrypted is False
        assert scanned.error is None
        assert scanned.key_type == "ed25519"
        assert scanned.fingerprint == _expected_fingerprint(key)
        assert scanned.public_key is not None
        assert scanned.public_key.startswith("ssh-ed25519 ")

    def test_finds_unencrypted_rsa(self, tmp_path: Path):
        key = _rsa_key()
        (tmp_path / "id_rsa").write_bytes(_openssh_private_bytes(key))

        results = scan_directory(tmp_path)

        assert len(results) == 1
        assert results[0].key_type == "rsa"
        assert results[0].fingerprint == _expected_fingerprint(key)

    def test_detects_encrypted_key(self, tmp_path: Path):
        key = _ed25519_key()
        (tmp_path / "id_locked").write_bytes(_openssh_private_bytes(key, PASSPHRASE))

        results = scan_directory(tmp_path)

        assert len(results) == 1
        scanned = results[0]
        assert scanned.encrypted is True
        assert scanned.fingerprint is None
        assert scanned.public_key is None
        assert scanned.error is None

    @pytest.mark.parametrize(
        "name",
        ["known_hosts", "known_hosts.old", "config", "authorized_keys",
         "authorized_keys2", "environment", "id_ed25519.pub",
         "id_rsa-cert.pub", "leftover.dec"],
    )
    def test_skips_well_known_names_even_with_key_content(self, tmp_path: Path, name: str):
        # Key-shaped content under a skip-listed name must still be skipped.
        (tmp_path / name).write_bytes(_openssh_private_bytes(_ed25519_key()))

        assert scan_directory(tmp_path) == []

    def test_skips_oversized_files(self, tmp_path: Path):
        data = _openssh_private_bytes(_ed25519_key())
        (tmp_path / "id_big").write_bytes(data)

        assert scan_directory(tmp_path, max_bytes=len(data) - 1) == []

    def test_silently_omits_non_key_text_file(self, tmp_path: Path):
        (tmp_path / "notes.txt").write_text("remember to rotate keys quarterly\n")

        assert scan_directory(tmp_path) == []

    def test_corrupt_key_file_yields_error_row(self, tmp_path: Path):
        (tmp_path / "id_broken").write_text(openssh_armor("not-actually-base64!!"))

        results = scan_directory(tmp_path)

        assert len(results) == 1
        assert results[0].error is not None
        assert results[0].encrypted is False
        assert results[0].fingerprint is None

    @pytest.mark.skipif(os.geteuid() == 0, reason="root can read anything")
    def test_unreadable_file_yields_error_row(self, tmp_path: Path):
        unreadable = tmp_path / "id_secret"
        unreadable.write_bytes(_openssh_private_bytes(_ed25519_key()))
        unreadable.chmod(0o000)
        try:
            results = scan_directory(tmp_path)
        finally:
            unreadable.chmod(0o600)

        assert len(results) == 1
        assert results[0].filename == "id_secret"
        assert results[0].error is not None
        assert results[0].encrypted is False

    def test_skips_directories_and_dir_symlinks(self, tmp_path: Path):
        (tmp_path / "subdir").mkdir()
        (tmp_path / "dir_link").symlink_to(tmp_path / "subdir")

        assert scan_directory(tmp_path) == []

    def test_follows_file_symlinks(self, tmp_path: Path):
        target = tmp_path / "real_key_store"
        target.mkdir()
        real = target / "backing"
        real.write_bytes(_openssh_private_bytes(_ed25519_key()))
        (tmp_path / "id_linked").symlink_to(real)

        results = scan_directory(tmp_path)

        # The symlinked entry AND nothing from the subdirectory (non-recursive).
        assert [r.filename for r in results] == ["id_linked"]

    def test_symlink_records_resolved_target_for_provenance(self, tmp_path: Path):
        # A symlink in a less-trusted scanned directory can point at a key
        # elsewhere on disk — the UI must be able to show its real origin.
        target = tmp_path / "real_key_store"
        target.mkdir()
        real = target / "backing"
        real.write_bytes(_openssh_private_bytes(_ed25519_key()))
        (tmp_path / "deploy_key").symlink_to(real)

        results = scan_directory(tmp_path)

        assert len(results) == 1
        assert results[0].resolved_target == str(real.resolve())

    def test_regular_file_has_no_resolved_target(self, tmp_path: Path):
        (tmp_path / "id_ed25519").write_bytes(_openssh_private_bytes(_ed25519_key()))

        results = scan_directory(tmp_path)

        assert len(results) == 1
        assert results[0].resolved_target is None

    def test_comment_recovered_from_matching_sibling_pub(self, tmp_path: Path):
        key = _ed25519_key()
        (tmp_path / "id_ed25519").write_bytes(_openssh_private_bytes(key))
        (tmp_path / "id_ed25519.pub").write_text(_public_line(key) + " ops@web-1\n")

        results = scan_directory(tmp_path)

        assert len(results) == 1
        assert results[0].comment == "ops@web-1"
        assert results[0].public_key.endswith(" ops@web-1")

    def test_mismatched_sibling_pub_comment_ignored(self, tmp_path: Path):
        key = _ed25519_key()
        other = _ed25519_key()
        (tmp_path / "id_ed25519").write_bytes(_openssh_private_bytes(key))
        (tmp_path / "id_ed25519.pub").write_text(_public_line(other) + " stale@web-1\n")

        results = scan_directory(tmp_path)

        assert len(results) == 1
        assert results[0].comment is None

    def test_max_files_caps_examination(self, tmp_path: Path):
        for i in range(3):
            (tmp_path / f"id_{i}").write_bytes(_openssh_private_bytes(_ed25519_key()))

        results = scan_directory(tmp_path, max_files=2)

        assert len(results) == 2

    def test_missing_directory_raises(self, tmp_path: Path):
        # List-failure must be distinguishable from an empty directory — a
        # silent [] would render a misleading "no keys found" state.
        with pytest.raises(KeyImportError):
            scan_directory(tmp_path / "nope")

    @pytest.mark.skipif(os.geteuid() == 0, reason="root can read anything")
    def test_unreadable_directory_raises(self, tmp_path: Path):
        locked = tmp_path / "locked"
        locked.mkdir()
        locked.chmod(0o000)
        try:
            with pytest.raises(KeyImportError):
                scan_directory(locked)
        finally:
            locked.chmod(0o700)

    def test_non_ssh_pkcs8_key_yields_error_row_not_crash(self, tmp_path: Path):
        # An X25519 PKCS#8 key parses but cannot be SSH-serialised — it must
        # become a dim error row, never an exception out of the scan worker.
        (tmp_path / "wg_private").write_bytes(_x25519_pkcs8_bytes())

        results = scan_directory(tmp_path)

        assert len(results) == 1
        assert results[0].error is not None
        assert results[0].fingerprint is None


class TestLoadUnencryptedKey:
    def test_normalises_to_openssh_pem(self):
        key = _ed25519_key()
        result = load_unencrypted_key(_openssh_private_bytes(key))

        assert isinstance(result, DecryptedKey)
        assert result.private_key.startswith(OPENSSH_HEADER)
        assert result.public_key == _public_line(key)
        assert result.fingerprint == _expected_fingerprint(key)
        assert result.key_type == "ed25519"

    def test_garbage_raises_key_import_error(self):
        with pytest.raises(KeyImportError) as exc_info:
            load_unencrypted_key(b"definitely not a key")
        assert exc_info.value.message

    def test_non_ssh_pkcs8_key_raises_key_import_error(self):
        # Parses fine, fails at SSH serialisation — must still classify.
        with pytest.raises(KeyImportError) as exc_info:
            load_unencrypted_key(_x25519_pkcs8_bytes())
        assert exc_info.value.message


class TestDecryptPrivateKey:
    def test_roundtrip_and_result_loadable_again(self):
        key = _ed25519_key()
        encrypted = _openssh_private_bytes(key, PASSPHRASE)

        result = decrypt_private_key(encrypted, PASSPHRASE)

        assert result.key_type == "ed25519"
        assert result.fingerprint == _expected_fingerprint(key)
        assert result.public_key == _public_line(key)
        # The normalised output must itself be a loadable unencrypted OpenSSH key.
        reloaded = load_ssh_private_key(result.private_key.encode(), password=None)
        assert isinstance(reloaded, ed25519.Ed25519PrivateKey)

    def test_rsa_roundtrip(self):
        key = _rsa_key()
        result = decrypt_private_key(_openssh_private_bytes(key, PASSPHRASE), PASSPHRASE)
        assert result.key_type == "rsa"
        assert result.fingerprint == _expected_fingerprint(key)

    def test_wrong_passphrase_raises_wrong_passphrase_error(self):
        encrypted = _openssh_private_bytes(_ed25519_key(), PASSPHRASE)

        with pytest.raises(WrongPassphraseError) as exc_info:
            decrypt_private_key(encrypted, "not-the-passphrase")

        assert exc_info.value.message == "Wrong passphrase."

    def test_encrypted_non_ssh_key_correct_passphrase_raises_key_import_error(self):
        # Decryption succeeds, SSH serialisation fails: KeyImportError — NOT
        # WrongPassphraseError (the passphrase was right) and NOT a raw
        # ValueError (which would crash the import worker).
        encrypted = _x25519_pkcs8_bytes(PASSPHRASE)

        with pytest.raises(KeyImportError) as exc_info:
            decrypt_private_key(encrypted, PASSPHRASE)

        assert not isinstance(exc_info.value, WrongPassphraseError)
        assert exc_info.value.message

    def test_unsupported_openssh_algorithm_is_terminal_not_wrong_passphrase(self):
        # UnsupportedAlgorithm from the OpenSSH loader (broken/missing bcrypt,
        # unsupported cipher/KDF) must NOT fall through to the PEM loader —
        # that path always raises ValueError on OpenSSH armor and would be
        # misclassified as a wrong passphrase, trapping the user in a
        # re-prompt loop that can never succeed.
        encrypted = _openssh_private_bytes(_ed25519_key(), PASSPHRASE)

        with patch(
            "servonaut.services.bw_key_import.load_ssh_private_key",
            side_effect=UnsupportedAlgorithm("unsupported KDF"),
        ):
            with pytest.raises(KeyImportError) as exc_info:
                decrypt_private_key(encrypted, PASSPHRASE)

        assert not isinstance(exc_info.value, WrongPassphraseError)
        assert exc_info.value.message

    def test_passphrase_never_leaks_into_exception_chain(self):
        encrypted = _openssh_private_bytes(_ed25519_key(), PASSPHRASE)
        secret_attempt = "super-secret-wrong-guess"

        with pytest.raises(WrongPassphraseError) as exc_info:
            decrypt_private_key(encrypted, secret_attempt)

        exc: BaseException | None = exc_info.value
        while exc is not None:
            assert secret_attempt not in str(exc)
            exc = exc.__cause__


class TestReadKeyBytes:
    def test_reads_file_within_cap(self, tmp_path: Path):
        path = tmp_path / "id_small"
        path.write_bytes(b"key-data")

        assert read_key_bytes(path) == b"key-data"

    def test_oversized_file_raises_before_reading(self, tmp_path: Path):
        # The scan-time cap must be re-enforced at import time — the file may
        # have been replaced/grown between the scan and the import click.
        path = tmp_path / "id_grown"
        path.write_bytes(b"x" * (DEFAULT_MAX_KEY_BYTES + 1))

        with pytest.raises(KeyImportError):
            read_key_bytes(path)

    def test_custom_cap_respected(self, tmp_path: Path):
        path = tmp_path / "id_key"
        path.write_bytes(b"x" * 10)

        with pytest.raises(KeyImportError):
            read_key_bytes(path, max_bytes=9)

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(KeyImportError):
            read_key_bytes(tmp_path / "gone")

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo not available")
    def test_fifo_raises_instead_of_blocking(self, tmp_path: Path):
        # A FIFO swapped in at a scanned key path must fail fast — a blocking
        # open() with no writer would wedge the import worker forever.
        fifo = tmp_path / "id_fifo"
        os.mkfifo(fifo)

        with pytest.raises(KeyImportError):
            read_key_bytes(fifo)

    def test_reads_exactly_max_bytes(self, tmp_path: Path):
        # Boundary: a file of exactly max_bytes is fine; the +1 sentinel byte
        # only trips when the file actually exceeds the cap.
        path = tmp_path / "id_exact"
        path.write_bytes(b"x" * 10)

        assert read_key_bytes(path, max_bytes=10) == b"x" * 10


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen not on PATH")
def test_fingerprint_matches_ssh_keygen(tmp_path: Path):
    key = _ed25519_key()
    result = load_unencrypted_key(_openssh_private_bytes(key))

    # Only the PUBLIC key touches disk — private material never does.
    pub_path = tmp_path / "check.pub"
    pub_path.write_text(result.public_key + "\n")
    output = subprocess.run(
        ["ssh-keygen", "-lf", str(pub_path)],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    ).stdout

    assert result.fingerprint in output
