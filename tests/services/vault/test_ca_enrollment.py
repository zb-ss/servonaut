"""The local v1 enrollment template stays structured and rolls back safely."""

from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess
from pathlib import Path, PurePosixPath
from time import time

import pytest

from servonaut.services.vault.ca_enrollment import (
    CaEnrollmentExecutor,
    CommandResult,
    DROP_IN,
    EnrollmentError,
    MANAGED_DIR,
    deliver_krl,
)
from servonaut.services.vault.crypto import build_krl
from servonaut.services.vault.crypto import build_ed25519_certificate, ssh_ed25519_public_blob


CA_SEED = b"c" * 32
HOST_SEED = b"h" * 32


def _public_line(raw_key: bytes) -> str:
    return "ssh-ed25519 " + base64.b64encode(ssh_ed25519_public_blob(raw_key)).decode("ascii")


def _raw_public(seed: bytes) -> bytes:
    from nacl.signing import SigningKey

    return bytes(SigningKey(seed).verify_key)


HOST_PUBLIC = _public_line(_raw_public(HOST_SEED))
HOST_CA_PUBLIC = _public_line(_raw_public(CA_SEED))


def _host_certificate() -> str:
    now = int(time())
    _, _, blob = build_ed25519_certificate(
        _raw_public(HOST_SEED), 8, 2, "host", ["web-1.example.test"], now - 30, now + 3600,
        {}, [], b"n" * 32, _raw_public(CA_SEED), CA_SEED,
    )
    return "ssh-ed25519-cert-v01@openssh.com " + base64.b64encode(blob).decode("ascii")


def _other_ca() -> str:
    return _public_line(_raw_public(b"z" * 32))


class _Host:
    def __init__(self, foreign: bool = False, fail_config_test: bool = False, fail_remove: PurePosixPath | None = None) -> None:
        self.writes: list[PurePosixPath] = []
        self.removed: list[PurePosixPath] = []
        self.commands: list[list[str]] = []
        self.foreign = foreign
        self.fail_config_test = fail_config_test
        self.fail_remove = fail_remove
        self.files: dict[PurePosixPath, bytes] = {
            PurePosixPath("/etc/ssh/ssh_host_ed25519_key.pub"): HOST_PUBLIC.encode(),
        }

    async def run(self, argv):
        self.commands.append(list(argv))
        if argv == ["sshd", "-V"]:
            return CommandResult(0, stderr="OpenSSH_9.6")
        if argv == ["sshd", "-T"]:
            ca = "/other/ca" if self.foreign else "none"
            return CommandResult(0, stdout=f"trustedusercakeys {ca}\nauthorizedprincipalsfile none\nrevokedkeys none\n")
        if argv == ["sshd", "-t"] and self.fail_config_test:
            # Only the new configuration is broken; the restored one tests clean.
            self.fail_config_test = False
            return CommandResult(1)
        return CommandResult(0)

    async def read_file(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    async def write_atomic(self, path, content, mode):
        self.writes.append(path)
        self.files[path] = content

    async def remove(self, path):
        if path == self.fail_remove:
            raise OSError("injected remove failure")
        self.removed.append(path)
        self.files.pop(path, None)


def _params() -> dict:
    return {
        "script_version": "1", "kind": "enroll", "managed_dir": "/etc/ssh/servonaut",
        "drop_in": "/etc/ssh/sshd_config.d/50-servonaut.conf",
        "server": {"hostname": "web-1.example.test"},
        "user_ca_public_keys": [HOST_CA_PUBLIC], "host_ca_public_key": HOST_CA_PUBLIC,
        "principals_by_login": {"deploy": ["svn:server:deploy"]},
        "host_principals": ["web-1.example.test"],
        "krl": base64.b64encode(build_krl(b"k" * 32, 3, 1, [])).decode("ascii"),
    }


@pytest.mark.asyncio
async def test_enrollment_writes_krl_before_drop_in_and_proves_login():
    host = _Host()
    result = await CaEnrollmentExecutor(host, host_ca_public_key=HOST_CA_PUBLIC).execute(
        _params(), confirmed_host_name="web-1.example.test",
        request_host_certificate=lambda key: _return(_host_certificate()),
        prove_certificate_login=lambda: _return(True),
    )

    assert result.status == "succeeded"
    assert host.writes[0] == MANAGED_DIR / "revoked.krl"
    assert host.writes[-1] == PurePosixPath("/etc/ssh/sshd_config.d/50-servonaut.conf")


@pytest.mark.asyncio
async def test_foreign_configuration_aborts_before_writing():
    host = _Host(foreign=True)
    result = await CaEnrollmentExecutor(host, host_ca_public_key=HOST_CA_PUBLIC).execute(
        _params(), confirmed_host_name="web-1.example.test",
        request_host_certificate=lambda key: _return("unused"), prove_certificate_login=lambda: _return(True),
    )

    assert result.status == "rolled_back"
    assert result.error_code == "foreign_ca_config"
    assert not host.writes
    assert not host.removed and ("systemctl", "reload", "ssh") not in [tuple(call) for call in host.commands]


@pytest.mark.asyncio
async def test_krl_is_hashed_and_delivered_without_reload():
    host = _Host()
    krl = build_krl(b"k" * 32, 3, 1, [])
    digest = base64.b64encode(hashlib.sha256(krl).digest()).decode("ascii")
    report = await deliver_krl({"server": host}, krl, digest, 3)

    assert report.to_dict()["results"] == [{"server_id": "server", "status": "delivered"}]
    assert host.writes == [MANAGED_DIR / "revoked.krl"]
    with pytest.raises(EnrollmentError, match="SHA-256"):
        await deliver_krl({"server": host}, krl, base64.b64encode(b"x" * 32).decode("ascii"), 3)
    malformed = b"X" + krl[1:]
    with pytest.raises(EnrollmentError, match="OpenSSH"):
        await deliver_krl({"server": host}, malformed, base64.b64encode(hashlib.sha256(malformed).digest()).decode("ascii"), 3)


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="OpenSSH ssh-keygen is unavailable")
def test_generated_krl_is_accepted_by_openssh(tmp_path: Path):
    host_public = tmp_path / "host.pub"
    host_public.write_text(HOST_PUBLIC + "\n", encoding="ascii")
    krl_path = tmp_path / "revoked.krl"
    krl_path.write_bytes(build_krl(_raw_public(CA_SEED), 3, 1, []))

    checked = subprocess.run(
        ["ssh-keygen", "-Q", "-f", str(krl_path), str(host_public)],
        capture_output=True, text=True, check=False,
    )

    # An empty KRL reports an unrevoked key with status 1; parse failures are 255.
    assert checked.returncode in {0, 1}, checked.stderr


@pytest.mark.asyncio
async def test_break_glass_append_and_unenroll_preserve_existing_authorized_keys():
    host = _Host()
    authorized = PurePosixPath("/root/.ssh/authorized_keys")
    host.files[authorized] = b"ssh-ed25519 AAAAexisting operator\n"
    params = _params()
    params["break_glass"] = {
        "login": "root", "public_key": "ssh-ed25519 AAAAbreakglass", "from_cidrs": ["192.0.2.0/24"], "item_id": "item-1",
    }
    executor = CaEnrollmentExecutor(host, host_ca_public_key=HOST_CA_PUBLIC)
    result = await executor.execute(
        params, confirmed_host_name="web-1.example.test",
        request_host_certificate=lambda key: _return(_host_certificate()),
        prove_certificate_login=lambda: _return(True),
    )
    assert result.status == "succeeded"
    assert b"AAAAexisting" in host.files[authorized]
    assert b"servonaut-break-glass:item-1" in host.files[authorized]
    await executor._unenroll(params)
    assert host.files[authorized] == b"ssh-ed25519 AAAAexisting operator\n"


@pytest.mark.asyncio
async def test_failed_refresh_restores_existing_managed_files_and_drop_in():
    host = _Host(fail_config_test=True)
    original_krl = b"old-krl"
    host.files[MANAGED_DIR / "revoked.krl"] = original_krl
    drop_in = PurePosixPath("/etc/ssh/sshd_config.d/50-servonaut.conf")
    host.files[drop_in] = b"old drop in\n"
    result = await CaEnrollmentExecutor(host, host_ca_public_key=HOST_CA_PUBLIC).execute(
        _params() | {"kind": "refresh"}, confirmed_host_name="web-1.example.test",
        request_host_certificate=lambda key: _return(_host_certificate()),
        prove_certificate_login=lambda: _return(True),
    )
    assert result.status == "rolled_back"
    assert host.files[MANAGED_DIR / "revoked.krl"] == original_krl
    assert host.files[drop_in] == b"old drop in\n"


@pytest.mark.asyncio
async def test_unenroll_remove_failure_restores_the_entire_previous_configuration():
    host = _Host(fail_remove=MANAGED_DIR / "revoked.krl")
    params = _params() | {"kind": "unenroll"}
    drop_in = b"old drop in\n"
    krl = b"old krl\n"
    user_ca = b"old ca\n"
    principal = b"old principal\n"
    host.files[DROP_IN] = drop_in
    host.files[MANAGED_DIR / "revoked.krl"] = krl
    host.files[MANAGED_DIR / "user_ca_keys.pub"] = user_ca
    host.files[MANAGED_DIR / "principals" / "deploy"] = principal

    result = await CaEnrollmentExecutor(host, host_ca_public_key=HOST_CA_PUBLIC).execute(
        params, confirmed_host_name="web-1.example.test",
        request_host_certificate=lambda key: _return("unused"), prove_certificate_login=lambda: _return(True),
    )

    assert result.status == "rolled_back"
    assert result.steps[-1].name == "rollback"
    assert host.files[DROP_IN] == drop_in
    assert host.files[MANAGED_DIR / "revoked.krl"] == krl
    assert host.files[MANAGED_DIR / "user_ca_keys.pub"] == user_ca
    assert host.files[MANAGED_DIR / "principals" / "deploy"] == principal


@pytest.mark.asyncio
async def test_host_certificate_from_an_unpinned_ca_is_rolled_back_before_write():
    host = _Host()
    result = await CaEnrollmentExecutor(host, host_ca_public_key=_other_ca()).execute(
        _params(), confirmed_host_name="web-1.example.test",
        request_host_certificate=lambda key: _return(_host_certificate()),
        prove_certificate_login=lambda: _return(True),
    )
    assert result.status == "rolled_back"
    assert result.error_code == "host_certificate_was_not_signed_by_the_pinned_host_ca"
    assert PurePosixPath("/etc/ssh/sshd_config.d/50-servonaut.conf") not in host.files


async def _return(value):
    return value



def test_enrollment_error_codes_always_match_the_api_pattern():
    import re

    from servonaut.services.api_client import APIError
    from servonaut.services.vault.ca_enrollment import enrollment_error_code

    samples = [
        EnrollmentError("sshd_config_test_failed"),
        EnrollmentError("Could not resolve the requested SSH login home directory, really " * 3),
        EnrollmentError("!!!"),
        APIError(code="x", message="server text", status=422),
        ValueError("anything"),
    ]
    codes = [enrollment_error_code(error) for error in samples]

    assert codes[0] == "sshd_config_test_failed"
    assert codes[2] == "enrollment_failed"
    assert codes[3] == "api_error"
    assert all(re.fullmatch(r"[a-z0-9_]{1,64}", code) for code in codes)



@pytest.mark.asyncio
async def test_rollback_reloads_without_the_drop_in_before_deleting_the_krl():
    """A running sshd whose RevokedKeys file vanished refuses every key login."""
    events: list[str] = []
    host = _Host()

    original_run, original_remove = host.run, host.remove

    async def run(argv):
        events.append(" ".join(argv))
        return await original_run(argv)

    async def remove(path):
        events.append(f"rm {path}")
        return await original_remove(path)

    host.run, host.remove = run, remove
    result = await CaEnrollmentExecutor(host, host_ca_public_key=HOST_CA_PUBLIC).execute(
        _params(), confirmed_host_name="web-1.example.test",
        request_host_certificate=lambda key: _return(_host_certificate()),
        prove_certificate_login=lambda: _return(False),
    )

    assert result.status == "rolled_back"
    rollback = events[events.index(f"rm {DROP_IN}"):]
    reload_at = next(i for i, event in enumerate(rollback) if event.startswith("systemctl reload"))
    krl_at = rollback.index(f"rm {MANAGED_DIR / 'revoked.krl'}")
    assert rollback.index("sshd -t") < reload_at < krl_at


@pytest.mark.asyncio
async def test_unenroll_reloads_before_deleting_the_files_the_config_names():
    events: list[str] = []
    host = _Host()
    host.files[DROP_IN] = b"drop in\n"
    host.files[MANAGED_DIR / "revoked.krl"] = b"krl"
    original_run, original_remove = host.run, host.remove

    async def run(argv):
        events.append(" ".join(argv))
        return await original_run(argv)

    async def remove(path):
        events.append(f"rm {path}")
        return await original_remove(path)

    host.run, host.remove = run, remove
    result = await CaEnrollmentExecutor(host, host_ca_public_key=HOST_CA_PUBLIC).execute(
        _params() | {"kind": "unenroll"}, confirmed_host_name="web-1.example.test",
        request_host_certificate=lambda key: _return("unused"), prove_certificate_login=lambda: _return(True),
    )

    assert result.status == "succeeded"
    reload_at = next(i for i, event in enumerate(events) if event.startswith("systemctl reload"))
    assert events.index(f"rm {DROP_IN}") < reload_at < events.index(f"rm {MANAGED_DIR / 'revoked.krl'}")


@pytest.mark.asyncio
async def test_drop_in_header_names_the_team_and_server_that_own_the_host():
    host = _Host()
    params = _params()
    params["server"] = {**params["server"], "id": "c2a4e6f8-1b3d-4f5a-9c7e-0a2b4c6d8e1f"}
    await CaEnrollmentExecutor(host, host_ca_public_key=HOST_CA_PUBLIC, team="example-team").execute(
        params, confirmed_host_name="web-1.example.test",
        request_host_certificate=lambda key: _return(_host_certificate()), prove_certificate_login=lambda: _return(True),
    )

    header = host.files[DROP_IN].decode().splitlines()[0]
    assert header == (
        f"# Managed by Servonaut (script v1, team example-team, server {params['server']['id']}). Do not edit."
    )


class _EnrolledHost(_Host):
    """A host Servonaut already enrolled: ``sshd -T`` reports its managed paths."""

    def __init__(self, *, revoked_keys: str = f"{MANAGED_DIR}/revoked.krl", team: str = "team-a") -> None:
        super().__init__()
        self.revoked_keys = revoked_keys
        drop_in = CaEnrollmentExecutor(self, host_ca_public_key=HOST_CA_PUBLIC, team=team)._drop_in(_params())
        self.files[DROP_IN] = drop_in.encode()

    async def run(self, argv):
        if argv == ["sshd", "-T"]:
            self.commands.append(list(argv))
            return CommandResult(0, stdout=(
                f"trustedusercakeys {MANAGED_DIR}/user_ca_keys.pub\n"
                f"authorizedprincipalsfile {MANAGED_DIR}/principals/%u\n"
                f"revokedkeys {self.revoked_keys}\n"
            ))
        return await super().run(argv)


@pytest.mark.asyncio
async def test_refreshing_an_enrolled_host_accepts_its_own_managed_configuration():
    result = await CaEnrollmentExecutor(_EnrolledHost(), host_ca_public_key=HOST_CA_PUBLIC, team="team-a").execute(
        _params(), confirmed_host_name="web-1.example.test",
        request_host_certificate=lambda key: _return(_host_certificate()), prove_certificate_login=lambda: _return(True),
    )

    assert result.error_code != "foreign_ca_config"
    assert result.status == "succeeded"


@pytest.mark.asyncio
async def test_a_managed_host_with_one_foreign_setting_is_still_refused():
    host = _EnrolledHost(revoked_keys="/etc/ssh/other.krl")
    result = await CaEnrollmentExecutor(host, host_ca_public_key=HOST_CA_PUBLIC, team="team-a").execute(
        _params(), confirmed_host_name="web-1.example.test",
        request_host_certificate=lambda key: _return("unused"), prove_certificate_login=lambda: _return(True),
    )

    assert result.error_code == "foreign_ca_config"
    assert not host.writes


def test_a_pin_mismatch_is_reported_with_a_fixed_code():
    from servonaut.services.vault.ca_enrollment import enrollment_error_code
    from servonaut.services.vault.ca_pins import CaPinMismatchError

    assert enrollment_error_code(CaPinMismatchError("The team SSH CA changed; compare …")) == "ca_pin_mismatch"


@pytest.mark.asyncio
async def test_a_host_another_team_enrolled_is_not_taken_over():
    host = _EnrolledHost(team="team-b")
    result = await CaEnrollmentExecutor(host, host_ca_public_key=HOST_CA_PUBLIC, team="team-a").execute(
        _params(), confirmed_host_name="web-1.example.test",
        request_host_certificate=lambda key: _return("unused"), prove_certificate_login=lambda: _return(True),
    )

    assert result.error_code == "foreign_ca_config"
    assert not host.writes


def _legacy_drop_in() -> bytes:
    lines = CaEnrollmentExecutor(_Host(), host_ca_public_key=HOST_CA_PUBLIC)._drop_in(_params()).splitlines()
    return ("# Managed by Servonaut (script v1). Do not edit.\n" + "\n".join(lines[1:]) + "\n").encode()


@pytest.mark.asyncio
async def test_a_refresh_migrates_a_host_enrolled_before_owners_were_recorded():
    host = _EnrolledHost()
    host.files[DROP_IN] = _legacy_drop_in()
    result = await CaEnrollmentExecutor(host, host_ca_public_key=HOST_CA_PUBLIC, team="team-a").execute(
        {**_params(), "kind": "refresh"}, confirmed_host_name="web-1.example.test",
        request_host_certificate=lambda key: _return(_host_certificate()), prove_certificate_login=lambda: _return(True),
    )

    assert result.status == "succeeded", result
    assert DROP_IN in host.writes  # rewritten with this team and server as owners


@pytest.mark.asyncio
async def test_an_enroll_does_not_adopt_a_host_whose_owner_is_unknown():
    host = _EnrolledHost()
    host.files[DROP_IN] = _legacy_drop_in()
    result = await CaEnrollmentExecutor(host, host_ca_public_key=HOST_CA_PUBLIC, team="team-a").execute(
        _params(), confirmed_host_name="web-1.example.test",
        request_host_certificate=lambda key: _return("unused"), prove_certificate_login=lambda: _return(True),
    )

    assert result.error_code == "foreign_ca_config"
    assert not host.writes
