"""Team host-CA files stay constrained to explicit enrolled hosts."""

from __future__ import annotations

import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from servonaut.services.vault.known_hosts import KnownHostsError, TeamKnownHosts


HOST_CA = Ed25519PrivateKey.generate().public_key().public_bytes(
    Encoding.OpenSSH, PublicFormat.OpenSSH
).decode("ascii") + " team-ca"


def test_writes_scoped_cert_authority_and_strict_options(tmp_path):
    known_hosts = TeamKnownHosts(tmp_path)
    path = known_hosts.write("example-team", HOST_CA, ["web-1.example.test", "192.0.2.10"])

    assert path.read_text(encoding="utf-8") == (
        "@cert-authority 192.0.2.10,web-1.example.test " + HOST_CA + "\n"
    )
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert known_hosts.ssh_options(path) == [
        "-o", f"UserKnownHostsFile={path}", "-o", "StrictHostKeyChecking=yes"
    ]


def test_allocates_one_immutable_file_per_lease_and_formats_nondefault_port(tmp_path):
    known_hosts = TeamKnownHosts(tmp_path)
    first = known_hosts.write("example-team", HOST_CA, [("web-1.example.test", 2222)])
    second = known_hosts.write("example-team", HOST_CA, [("web-2.example.test", 22)])

    assert first != second
    assert "@cert-authority [web-1.example.test]:2222 " in first.read_text(encoding="utf-8")
    assert "@cert-authority web-2.example.test " in second.read_text(encoding="utf-8")


@pytest.mark.parametrize("host", ["*", "*.example.test", "", "web host"])
def test_rejects_wildcard_or_ambiguous_hosts(tmp_path, host):
    with pytest.raises(KnownHostsError):
        TeamKnownHosts(tmp_path).write("team", HOST_CA, [host])


def test_rejects_newline_injected_ca_key(tmp_path):
    injected = HOST_CA + "\nattacker.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGF0dGFja2Vy"
    with pytest.raises(KnownHostsError):
        TeamKnownHosts(tmp_path).write("team", injected, ["web-1.example.test"])


def test_allows_a_comment_on_one_canonical_ca_key_line(tmp_path):
    path = TeamKnownHosts(tmp_path).write("team", HOST_CA, ["web-1.example.test"])

    assert HOST_CA in path.read_text(encoding="utf-8")


def test_rejects_a_symlinked_or_insecure_known_hosts_directory(tmp_path):
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    symlink = tmp_path / "known-hosts-link"
    symlink.symlink_to(target, target_is_directory=True)
    with pytest.raises(KnownHostsError, match="real directory"):
        TeamKnownHosts(symlink).write("team", HOST_CA, ["web-1.example.test"])

    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    with pytest.raises(KnownHostsError, match="unsafe ownership or permissions"):
        TeamKnownHosts(unsafe).write("team", HOST_CA, ["web-1.example.test"])
