"""Concrete enrollment transport keeps host trust and proof leases strict."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from servonaut.services.vault.ca_enrollment import CommandResult, EnrollmentError
from servonaut.services.vault.remote_executor import SshHostExecutor


class _Ssh:
    def get_key_path(self, *_): return None
    def discover_key(self, *_): return None
    def build_ssh_command(self, **kwargs):
        self.kwargs = kwargs
        return ["ssh"]


class _Connection:
    def resolve_profile(self, *_): return None
    def get_target_host(self, instance, *_): return instance["host"]
    def get_proxy_args(self, *_): return []
    def get_extra_options(self, *_): return []


class _Resolver:
    async def resolve(self, _):
        return SimpleNamespace(source="local", local_key_path="/key", lease=None)


def _executor(tmp_path: Path) -> SshHostExecutor:
    pins = tmp_path / "known_hosts"
    pins.write_text("127.0.0.1 ssh-ed25519 AAAA\n", encoding="ascii")
    pins.chmod(0o600)
    return SshHostExecutor(
        {"is_custom": True, "host": "127.0.0.1", "username": "root", "port": 22},
        _Ssh(), _Connection(), _Resolver(), known_hosts_path=pins,
    )


@pytest.mark.asyncio
async def test_a_route_without_a_lease_requires_an_existing_pinned_host_file(tmp_path: Path):
    executor = SshHostExecutor(
        {"is_custom": True, "host": "127.0.0.1", "username": "root"},
        _Ssh(), _Connection(), _Resolver(), known_hosts_path=tmp_path / "missing",
    )
    with pytest.raises(EnrollmentError, match="existing known_hosts"):
        await executor._prepare()


@pytest.mark.asyncio
async def test_proof_uses_fresh_lease_and_always_closes(tmp_path: Path, monkeypatch):
    executor = _executor(tmp_path)
    closed = False
    lease = SimpleNamespace(identity_agent="/agent", certificate_path="/cert", known_hosts_path="/pins", login_user="root")
    def close():
        nonlocal closed
        closed = True
    lease.close = close
    async def supplier(): return lease
    async def execute(command, **kwargs):
        assert command == ("true",)
        assert executor.lease is lease
        return CommandResult(0)
    executor.proof_certificate_supplier = supplier
    monkeypatch.setattr(executor, "_exec", execute)

    assert await executor.prove_certificate_login()
    assert closed


def _public_key(comment: str) -> str:
    return Ed25519PrivateKey.generate().public_key().public_bytes(
        Encoding.OpenSSH, PublicFormat.OpenSSH
    ).decode("ascii") + " " + comment


@pytest.mark.asyncio
async def test_rotation_keeps_other_authorized_keys_and_removes_only_exact_old_key(tmp_path: Path, monkeypatch):
    executor = _executor(tmp_path)
    old_key, new_key, other_key = (_public_key(name) for name in ("old", "new", "other"))
    content = (old_key + "\n" + other_key + "\n").encode("ascii")
    writes: list[bytes] = []
    monkeypatch.setattr(executor, "_authorized_keys_path", lambda _: _await(Path("/home/deploy/.ssh/authorized_keys")))  # leak-guard:allow — generic test path
    monkeypatch.setattr(executor, "_read_user_file", lambda _, __: _await(content))
    monkeypatch.setattr(executor, "_write_user_file", lambda _, data, __: _record(writes, data))

    await executor.append_authorized_key("deploy", new_key)
    assert writes == [(old_key + "\n" + other_key + "\n" + new_key + "\n").encode("ascii")]

    content = writes[-1]
    await executor.remove_authorized_key("deploy", old_key)
    assert writes[-1] == (other_key + "\n" + new_key + "\n").encode("ascii")


@pytest.mark.asyncio
async def test_rotation_rejects_control_character_in_public_key(tmp_path: Path, monkeypatch):
    executor = _executor(tmp_path)
    path_called = False

    async def path(_):
        nonlocal path_called
        path_called = True
        return Path("/home/deploy/.ssh/authorized_keys")  # leak-guard:allow — generic test path

    monkeypatch.setattr(executor, "_authorized_keys_path", path)
    with pytest.raises(EnrollmentError, match="invalid login or public key"):
        await executor.append_authorized_key("deploy", _public_key("new") + "\nattacker")
    assert not path_called


def test_user_owned_authorized_keys_do_not_require_sudo(tmp_path: Path):
    executor = _executor(tmp_path)
    executor._connection = {"username": "deploy"}

    assert executor._privileged(("cat", "/home/deploy/.ssh/authorized_keys"), "deploy") == (  # leak-guard:allow — generic test path
        "cat", "/home/deploy/.ssh/authorized_keys"  # leak-guard:allow — generic test path
    )
    assert executor._privileged(("cat", "/home/other/.ssh/authorized_keys"), "other")[:3] == ("sudo", "-n", "--")  # leak-guard:allow — generic test path


@pytest.mark.asyncio
async def test_lease_ssh_command_uses_its_explicit_public_identity_file(tmp_path: Path, monkeypatch):
    executor = _executor(tmp_path)
    identity_file = tmp_path / "identity.pub"
    identity_file.write_text(_public_key("lease") + "\n", encoding="ascii")
    lease_pins = tmp_path / "lease-pins"
    lease_pins.write_text("host ssh-ed25519 AAAA\n", encoding="ascii")
    lease_pins.chmod(0o600)
    executor.lease = SimpleNamespace(
        identity_agent="/agent", certificate_path="/certificate", identity_file=str(identity_file),
        known_hosts_path=str(lease_pins), login_user="deploy",
    )

    class _Process:
        returncode = 0
        async def communicate(self, _): return b"", b""

    async def spawn(*_, **__): return _Process()
    monkeypatch.setattr("servonaut.services.vault.remote_executor.asyncio.create_subprocess_exec", spawn)

    await executor._exec(("true",))

    assert executor.ssh_service.kwargs["identity_file"] == str(identity_file)
    assert executor.ssh_service.kwargs["identity_agent"] == "/agent"


async def _await(value):
    return value


async def _record(writes: list[bytes], data: bytes) -> None:
    writes.append(data)


@pytest.mark.asyncio
async def test_shared_server_lease_connects_to_its_pinned_target_and_proves_with_its_pins(tmp_path: Path, monkeypatch):
    lease_pins = tmp_path / "lease-pins"
    lease_pins.write_text("[web-1.example.com]:2222 ssh-ed25519 AAAA\n", encoding="ascii")
    lease_pins.chmod(0o600)
    identity_file = tmp_path / "identity.pub"
    identity_file.write_text(_public_key("lease") + "\n", encoding="ascii")
    lease = SimpleNamespace(
        identity_agent="/agent", certificate_path=None, identity_file=str(identity_file),
        known_hosts_path=str(lease_pins), login_user="deploy",
        target_host="web-1.example.com", target_port=2222,
    )

    class _NoIpConnection(_Connection):
        def get_target_host(self, *_): return ""

    # A shared row as the API sends it: ``hostname``, no IP fields; no general known_hosts exists.
    executor = SshHostExecutor(
        {"id": "c2a4e6f8-1b3d-4f5a-9c7e-0a2b4c6d8e1f", "hostname": "web-1.example.com", "port": 2222},
        _Ssh(), _NoIpConnection(), _Resolver(), lease=lease, known_hosts_path=tmp_path / "missing",
    )

    class _Process:
        returncode = 0
        async def communicate(self, _): return b"", b""

    async def spawn(*_, **__): return _Process()
    monkeypatch.setattr("servonaut.services.vault.remote_executor.asyncio.create_subprocess_exec", spawn)

    proof_key = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat
    assert await executor.verify_new_key("deploy", proof_key.private_bytes(
        Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption(),
    )) is True

    kwargs = executor.ssh_service.kwargs
    assert (kwargs["host"], kwargs["port"]) == ("web-1.example.com", 2222)
    assert kwargs["known_hosts_file"] == str(lease_pins)


@pytest.mark.asyncio
async def test_rotation_matches_installed_keys_by_key_material_not_line_text(tmp_path: Path, monkeypatch):
    """Installed lines often carry options and a comment the vault item does not."""
    executor = _executor(tmp_path)
    old_key, other_key = _public_key("vault-copy"), _public_key("other")
    old_material = " ".join(old_key.split()[:2])
    installed = f'from="10.0.0.0/8",no-pty {old_material} laptop@example\n{other_key}\n'
    content = installed.encode("ascii")
    writes: list[bytes] = []
    monkeypatch.setattr(executor, "_authorized_keys_path", lambda _: _await(Path("/home/deploy/.ssh/authorized_keys")))  # leak-guard:allow — generic test path
    monkeypatch.setattr(executor, "_read_user_file", lambda _, __: _await(content))
    monkeypatch.setattr(executor, "_write_user_file", lambda _, data, __: _record(writes, data))

    await executor.append_authorized_key("deploy", old_material)
    assert writes == []  # already authorised under another comment: not appended twice

    await executor.remove_authorized_key("deploy", old_material)
    assert writes[-1] == (other_key + "\n").encode("ascii")


@pytest.mark.asyncio
async def test_auth_log_is_read_with_a_fixed_privileged_template(tmp_path: Path, monkeypatch):
    executor = _executor(tmp_path)
    executor.server["username"] = "deploy"
    captured: list[tuple[str, ...]] = []

    async def fake_exec(argv, **_kwargs):
        captured.append(argv)
        return CommandResult(0, "log line\n", "", b"log line\n")

    monkeypatch.setattr(executor, "_exec", fake_exec)

    assert await executor.read_auth_log(24) == "log line\n"
    assert captured[0][:3] == ("sudo", "-n", "--")
    assert captured[0][3:6] == ("sh", "-c", captured[0][5]) and captured[0][-1] == "24"
    with pytest.raises(EnrollmentError, match="between 1 and 720"):
        await executor.read_auth_log(0)



def test_enrollment_paths_are_limited_to_etc_ssh_and_the_break_glass_file() -> None:
    from pathlib import PurePosixPath

    SshHostExecutor._safe_path(PurePosixPath("/etc/ssh/servonaut/revoked.krl"))
    SshHostExecutor._safe_path(PurePosixPath("/root/.ssh/authorized_keys"))
    for unsafe in ("/root/.ssh/id_ed25519", "/home/deploy/.ssh/authorized_keys", "/etc/ssh/../shadow"):  # leak-guard:allow — generic test path
        with pytest.raises(EnrollmentError, match="unsafe remote path"):
            SshHostExecutor._safe_path(PurePosixPath(unsafe))



def test_write_template_never_changes_an_existing_directory(tmp_path: Path):
    import subprocess

    from servonaut.services.vault.remote_executor import _WRITE_TEMPLATE

    existing = tmp_path / "etc_ssh"
    existing.mkdir(mode=0o755)
    existing.chmod(0o755)
    subprocess.run(["sh", "-c", _WRITE_TEMPLATE, "sh", str(existing / "file"), "644", "700"],
                   input=b"x", check=True)
    created = tmp_path / "new_dir"
    subprocess.run(["sh", "-c", _WRITE_TEMPLATE, "sh", str(created / "file"), "600", "700"],
                   input=b"y", check=True)

    assert oct(existing.stat().st_mode & 0o777) == "0o755"
    assert oct(created.stat().st_mode & 0o777) == "0o700"
    assert oct((existing / "file").stat().st_mode & 0o777) == "0o644"
