"""Journey: a team SSH CA user-key rollover carried through by the CLI.

The owner enrols ``server-1`` in the team SSH CA, the CA rolls its user key
over from Ed25519 to ECDSA P-256 (a change of key type, too), and the CLI's
``ca refresh`` installs both keys on the host before the rollover completes. Certificate logins keep working throughout, the new CA's
certificates are accepted without a "CA changed" refusal, and a revoked
certificate is refused once ``ca krl`` delivers the revocation list.

``server-1`` is a loopback SSH host. Its remote commands run like on the
suite's other hosts (a remote root with its own tools); its sshd is emulated
in this module as OpenSSH documents it, because the suite may start no real
``sshd``:

* ``sshd -V``, ``sshd -T`` and ``sshd -t`` answer from the configuration on
  disk, so the CLI's pre-checks see what a real host would report;
* ``systemctl reload ssh`` loads the Servonaut drop-in: from then on the host
  presents its ``HostCertificate`` and accepts user certificates only per
  ``TrustedUserCAKeys``, ``AuthorizedPrincipalsFile`` and ``RevokedKeys``,
  reading those files at every authentication, as sshd does;
* an owner's bootstrap key logs in as the image's admin user (who has
  passwordless sudo): the existing credential the first enrolment needs.

Every login decision reads the files the CLI wrote on the host, so the
journey proves what was installed, not what the CLI reported. Another
member's device is stood in for by a FakeCloud control
(``issue_member_certificate``) and an in-process SSH client that holds its
key. The web UI's rollover buttons are FakeCloud controls too.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import shlex
import signal
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import asyncssh
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    SSHCertificate,
    SSHCertificateType,
    load_ssh_public_identity,
    load_ssh_public_key,
)

from e2e.harness import fleet
from e2e.harness.bootstrap import Sandbox
from e2e.harness.fake_cloud.routes_vault import SERVER_ID, TEAM_SLUG
from e2e.harness.processes import require_armed
from e2e.harness.remote_root import SYSTEM_TOOL_DIRS, RemoteRoot, SessionLauncher
from e2e.harness.seed import HomeSeeder
from e2e.harness.session_seed import seed_relay_config, seed_session
from e2e.harness.sshd import LOOPBACK, RemoteHost, _loop
from e2e.harness.terminal import _PlainText, _read_until, _start_on_pty
from e2e.journeys.vault.test_cli_vault import (
    _VAULT_TEAM,
    _assert_only_getpass_tty_access,
    _configure_test_custody,
    _setup_with_recovery_confirmation,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd]

HOST_NAME = "server-1"
LOGIN = "deploy"
# The owner's existing access before the CA: a key for the image's admin user.
ADMIN_USER = "ec2-user"
DROP_IN = "/etc/ssh/sshd_config.d/50-servonaut.conf"
HOST_KEY_FILE = "/etc/ssh/ssh_host_ed25519_key.pub"
SSHD_VERSION = "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024"
# Tools the enrolment template runs that the suite's remote roots leave out.
EXTRA_TOOLS = ("install", "mktemp", "chmod", "mv", "rm")
# Passwordless sudo for the login users, as many cloud images grant it.
SUDO = """#!/bin/sh
# server-1 grants its login users passwordless sudo.
while [ $# -gt 0 ]; do
  case "$1" in
    -n) shift ;;
    --) shift; break ;;
    -*) echo "sudo: unsupported option $1" >&2; exit 1 ;;
    *) break ;;
  esac
done
exec "$@"
"""
CA_CHANGED = "The team SSH CA changed"
TRUST_PROMPT = "Trust this SSH CA for team {team}? [y/N]"
# Another owner or admin of the team, with a device of their own.
OTHER_ADMIN_USER_ID = 4244
WAIT_SECONDS = 120.0


# ---------------------------------------------------------------------------
# The OpenSSH KRL format (PROTOCOL.krl), read independently of the client
# ---------------------------------------------------------------------------


class _Reader:
    """SSH wire-format fields (uint32, uint64, string), read in order."""

    def __init__(self, data: bytes) -> None:
        self.data, self.offset = data, 0

    def take(self, size: int) -> bytes:
        if self.offset + size > len(self.data):
            raise ValueError("truncated SSH wire data")
        chunk = self.data[self.offset:self.offset + size]
        self.offset += size
        return chunk

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def string(self) -> bytes:
        return self.take(self.u32())

    def done(self) -> bool:
        return self.offset == len(self.data)


@dataclass
class _Krl:
    version: int
    # (CA key blob, or b"" for any CA) -> revoked serials, ranges, key ids
    serials: dict[bytes, set[int]] = field(default_factory=dict)
    ranges: dict[bytes, list[tuple[int, int]]] = field(default_factory=dict)
    key_ids: dict[bytes, set[bytes]] = field(default_factory=dict)
    keys: set[bytes] = field(default_factory=set)
    sha1: set[bytes] = field(default_factory=set)
    sha256: set[bytes] = field(default_factory=set)

    def revokes(self, ca_blob: bytes, serial: int, key_id: bytes, key_blob: bytes) -> bool:
        if key_blob in self.keys or hashlib.sha1(key_blob).digest() in self.sha1 \
                or hashlib.sha256(key_blob).digest() in self.sha256:
            return True
        for ca in (ca_blob, b""):
            if serial in self.serials.get(ca, ()) or key_id in self.key_ids.get(ca, ()):
                return True
            if any(low <= serial <= high for low, high in self.ranges.get(ca, ())):
                return True
        return False


def _parse_krl(data: bytes) -> _Krl:
    """Parse a KRL the way ``sshd`` must; anything unexpected raises ValueError."""
    reader = _Reader(data)
    if reader.u64() != 0x5353484B524C0A00 or reader.u32() != 1:
        raise ValueError("not an OpenSSH v1 KRL")
    krl = _Krl(version=reader.u64())
    reader.u64(), reader.u64()  # generated date, flags
    reader.string(), reader.string()  # reserved, comment
    while not reader.done():
        kind, section = reader.take(1)[0], _Reader(reader.string())
        if kind == 1:  # KRL_SECTION_CERTIFICATES
            ca = section.string()
            section.string()  # reserved
            while not section.done():
                subtype, body = section.take(1)[0], _Reader(section.string())
                if subtype == 0x20:
                    while not body.done():
                        krl.serials.setdefault(ca, set()).add(body.u64())
                elif subtype == 0x21:
                    krl.ranges.setdefault(ca, []).append((body.u64(), body.u64()))
                elif subtype == 0x22:
                    offset, bitmap = body.u64(), int.from_bytes(body.string(), "big")
                    bits = {offset + bit for bit in range(bitmap.bit_length()) if bitmap >> bit & 1}
                    krl.serials.setdefault(ca, set()).update(bits)
                elif subtype == 0x23:
                    while not body.done():
                        krl.key_ids.setdefault(ca, set()).add(body.string())
                else:
                    raise ValueError(f"unknown KRL certificate section {subtype:#x}")
        elif kind in (2, 3, 5):  # explicit keys, SHA-1 and SHA-256 fingerprints
            target = {2: krl.keys, 3: krl.sha1, 5: krl.sha256}[kind]
            while not section.done():
                target.add(section.string())
        elif kind == 4:  # KRL_SECTION_SIGNATURE ends the revocation data
            break
        else:
            raise ValueError(f"unknown KRL section {kind}")
    return krl


# ---------------------------------------------------------------------------
# server-1: sshd with the Servonaut drop-in, emulated in-process
# ---------------------------------------------------------------------------


def _blob(line: str) -> bytes:
    return base64.b64decode(line.split()[1])


def _fingerprint(line: str) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(_blob(line)).digest()).decode().rstrip("=")


def _certificate_line(blob: bytes) -> bytes:
    """``<algorithm> <base64>`` for a certificate's wire blob."""
    return _Reader(blob).string() + b" " + base64.b64encode(blob)


def _is_certificate(blob: bytes) -> bool:
    try:
        return isinstance(load_ssh_public_identity(_certificate_line(blob)), SSHCertificate)
    except (ValueError, UnicodeError):
        return _Reader(blob).string().endswith(b"-cert-v01@openssh.com")  # leak-guard:allow (OpenSSH certificate algorithm suffix)


def _openssh_line(public_key: Any) -> str:
    return public_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")


def _key_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


@dataclass
class _Login:
    """One public-key authentication the emulated sshd decided."""

    user: str
    kind: str  # "key" or "certificate"
    accepted: bool
    reason: str
    serial: Optional[int] = None
    ca_fingerprint: Optional[str] = None
    ca_alg: Optional[str] = None


@dataclass
class _SshdHost(RemoteHost):
    """``server-1`` (see the module docstring for what is emulated, and how)."""

    bootstrap_key: Any = None
    active: Optional[dict[str, str]] = None  # the drop-in as of the last reload
    logins: list[_Login] = field(default_factory=list)
    # Problems the next ``sshd -t`` runs report, one per run (a journey's knob).
    config_test_failures: list[str] = field(default_factory=list)

    # -- lifecycle --------------------------------------------------------

    async def _start(self) -> None:
        self._server = await asyncssh.create_server(
            lambda: _SshdCallbacks(self), LOOPBACK, 0,
            server_host_keys=[self.host_key], process_factory=self._handle_process,
            encoding=None, gss_host=None, agent_forwarding=False, x11_forwarding=False,
            line_editor=False, allow_scp=False,
        )
        self.port = self._server.sockets[0].getsockname()[1]

    # -- sshd and systemctl -----------------------------------------------

    async def _handle_process(self, process: Any) -> None:
        user = process.get_extra_info("username") or "root"
        command = process.command
        words = shlex.split(command) if command else []
        privileged = user == "root"
        if words[:3] == ["sudo", "-n", "--"]:
            words, privileged = words[3:], True
        if not words or not (words[0] == "sshd" or words[:2] == ["systemctl", "reload"]):
            await super()._handle_process(process)
            return
        self.log.add(host=self.name, event="exec", user=user, command=command)
        if not privileged:
            status, out, err = 1, "", f"{words[0]}: must be run as root\n"
        else:
            status, out, err = self._sshd_tool(words)
        process.stdout.write(out.encode())
        process.stderr.write(err.encode())
        self.log.add(host=self.name, event="exit", user=user, command=command, status=status)
        process.exit(status)

    def _sshd_tool(self, words: list[str]) -> tuple[int, str, str]:
        if words == ["sshd", "-V"]:
            return 0, "", SSHD_VERSION + "\n"
        if words == ["sshd", "-T"]:
            return 0, self._effective_config(), ""
        if words == ["sshd", "-t"]:
            problem = self.config_test_failures.pop(0) if self.config_test_failures else self._config_problem()
            return (0, "", "") if problem is None else (255, "", problem + "\n")
        if words in (["systemctl", "reload", "ssh"], ["systemctl", "reload", "sshd"]):
            problem = self._config_problem()
            if problem is not None:
                return 1, "", f"Job for ssh.service failed: {problem}\n"
            self._reload()
            return 0, "", ""
        return 1, "", f"{words[0]}: unsupported in this fixture: {' '.join(words[1:])}\n"

    def _drop_in(self) -> Optional[dict[str, str]]:
        """The drop-in's directives on disk (lower-case keywords), or None."""
        try:
            text = self.remote.read_bytes(DROP_IN).decode("utf-8")
        except FileNotFoundError:
            return None
        directives: dict[str, str] = {}
        for line in _key_lines(text):
            keyword, _, value = line.partition(" ")
            directives.setdefault(keyword.lower(), value.strip())
        return directives

    def _effective_config(self) -> str:
        directives = self._drop_in() or {}
        lines = ["port 22", "pubkeyauthentication yes", "passwordauthentication no",
                 "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2"]
        for keyword in ("trustedusercakeys", "authorizedprincipalsfile", "revokedkeys"):
            lines.append(f"{keyword} {directives.get(keyword, 'none')}")
        if "hostcertificate" in directives:
            lines.append(f"hostcertificate {directives['hostcertificate']}")
        return "\n".join(lines) + "\n"

    def _config_problem(self) -> Optional[str]:
        """What ``sshd -t`` would refuse in the drop-in (None when it loads)."""
        directives = self._drop_in()
        if directives is None:
            return None
        try:
            if "trustedusercakeys" in directives:
                for line in _key_lines(self.remote.read_bytes(directives["trustedusercakeys"]).decode("ascii")):
                    load_ssh_public_key(" ".join(line.split()[:2]).encode("ascii"))
            if "revokedkeys" in directives:
                _parse_krl(self.remote.read_bytes(directives["revokedkeys"]))
            if "hostcertificate" in directives:
                certificate = load_ssh_public_identity(self.remote.read_bytes(directives["hostcertificate"]).strip())
                if certificate.type is not SSHCertificateType.HOST:
                    return "HostCertificate is not a host certificate"
                if _blob(_openssh_line(certificate.public_key())) != self.host_key.public_data:
                    return "HostCertificate does not match the host key"
        except (OSError, ValueError, UnicodeError) as exc:
            return f"/etc/ssh/sshd_config.d/50-servonaut.conf: {exc}"
        return None

    def _reload(self) -> None:
        """Load the drop-in, as ``sshd`` re-reads its configuration on SIGHUP."""
        self.active = self._drop_in()
        keys: list[Any] = [self.host_key]
        if self.active and "hostcertificate" in self.active:
            certificate = asyncssh.import_certificate(self.remote.read_bytes(self.active["hostcertificate"]))
            keys = [(self.host_key, certificate)]
        self._server.update(server_host_keys=keys)

    # -- authentication ---------------------------------------------------

    def accepts_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        accepted = username == ADMIN_USER and key.public_data == self.bootstrap_key.public_data
        login = _Login(username, "key", accepted, "authorized key" if accepted else "unknown key")
        self.logins.append(login)
        self.log.add(host=self.name, event="auth", user=username, key=key.get_fingerprint(),
                     accepted=accepted, reason=login.reason)
        return accepted

    def certificate_key(self, username: str, key_data: bytes) -> Optional[asyncssh.SSHKey]:
        """sshd's user-certificate decision, from the files on disk right now.

        asyncssh asks about every offered key; a plain key is not a
        certificate (None), and goes on to :meth:`accepts_key`.
        """
        if not _is_certificate(key_data):
            return None
        login = self._certificate_verdict(username, key_data)
        self.logins.append(login)
        self.log.add(host=self.name, event="auth", user=username, key=f"certificate serial {login.serial}",
                     accepted=login.accepted, reason=login.reason)
        if not login.accepted:
            return None
        subject = load_ssh_public_identity(_certificate_line(key_data)).public_key()
        return asyncssh.import_public_key(_openssh_line(subject))

    def _certificate_verdict(self, username: str, key_data: bytes) -> _Login:
        def refused(reason: str, **details: Any) -> _Login:
            return _Login(username, "certificate", False, reason, **details)

        try:
            certificate = load_ssh_public_identity(_certificate_line(key_data))
        except (ValueError, UnicodeError):
            return refused("malformed certificate")
        ca_line = _openssh_line(certificate.signature_key())
        details = {"serial": certificate.serial, "ca_fingerprint": _fingerprint(ca_line), "ca_alg": ca_line.split()[0]}
        config = self.active
        if not config or "trustedusercakeys" not in config:
            return refused("no TrustedUserCAKeys", **details)
        if "revokedkeys" in config:
            try:
                krl = _parse_krl(self.remote.read_bytes(config["revokedkeys"]))
            except (OSError, ValueError):
                # sshd refuses every public key when RevokedKeys cannot be read.
                return refused("RevokedKeys unreadable", **details)
            subject = _blob(_openssh_line(certificate.public_key()))
            if krl.revokes(_blob(ca_line), certificate.serial, certificate.key_id, subject):
                return refused("revoked", **details)
        try:
            trusted = {_blob(line) for line in _key_lines(
                self.remote.read_bytes(config["trustedusercakeys"]).decode("ascii"))}
        except OSError:
            return refused("TrustedUserCAKeys unreadable", **details)
        if _blob(ca_line) not in trusted:
            return refused("CA not trusted", **details)
        if certificate.type is not SSHCertificateType.USER:
            return refused("not a user certificate", **details)
        now = time.time()
        if not certificate.valid_after <= now < certificate.valid_before:
            return refused("outside the validity window", **details)
        principals_file = config.get("authorizedprincipalsfile", "none")
        if principals_file == "none":
            allowed = {username}
        else:
            try:
                text = self.remote.read_bytes(principals_file.replace("%u", username)).decode("utf-8")
            except (OSError, ValueError):
                return refused("no principals file for the login", **details)
            allowed = set(_key_lines(text))
        if not {value.decode() for value in certificate.valid_principals} & allowed:
            return refused("no listed principal", **details)
        try:
            certificate.verify_cert_signature()
        except Exception:  # noqa: BLE001 - any failure is a refusal
            return refused("bad CA signature", **details)
        return _Login(username, "certificate", True, "trusted CA", **details)

    def certificate_logins(self) -> list[_Login]:
        return [login for login in self.logins if login.kind == "certificate"]


class _SshdCallbacks(asyncssh.SSHServer):
    """Public-key authentication for :class:`_SshdHost`.

    asyncssh validates user certificates itself, without sshd's principals
    file or revocation list; the connection's certificate check is replaced
    by the host's sshd rules (``_validate_client_certificate`` takes the raw
    certificate blob and returns the key it certifies, or None).
    """

    def __init__(self, host: _SshdHost) -> None:
        self._host = host
        self._conn: Any = None

    def connection_made(self, conn: Any) -> None:
        self._conn = conn
        self._host._connections.add(conn)
        if not hasattr(conn, "_validate_client_certificate"):
            raise RuntimeError("asyncssh changed its certificate check; update the sshd emulation")

        async def certificate(username: str, key_data: bytes) -> Optional[asyncssh.SSHKey]:
            return self._host.certificate_key(username, key_data)

        conn._validate_client_certificate = certificate

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self._host._connections.discard(self._conn)

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return False

    def kbdint_auth_supported(self) -> bool:
        return False

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        return self._host.accepts_key(username, key)


def _start_server_1(sshd: Any, journey: Any) -> _SshdHost:
    remote_dir = journey.directory / "remote"
    remote = RemoteRoot(remote_dir / HOST_NAME, HOST_NAME, (LOGIN, ADMIN_USER))
    launcher = SessionLauncher(
        remote, remote_dir / f".launch-{HOST_NAME}", hidden=[*journey.ctx.protected_dirs, str(journey.ctx.root)],
    )
    sshd.log.add(host=HOST_NAME, event="confinement", mode=launcher.mode, detail=launcher.detail)
    for tool in EXTRA_TOOLS:
        source = next((Path(d) / tool for d in SYSTEM_TOOL_DIRS if (Path(d) / tool).exists()), None)
        assert source is not None, f"{tool} is missing from {SYSTEM_TOOL_DIRS}"
        remote.write(f"/bin/{tool}", f'#!/bin/sh\nexec {shlex.quote(str(source.resolve()))} "$@"\n', mode=0o755)
    remote.write("/bin/sudo", SUDO, mode=0o755)
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    remote.write(HOST_KEY_FILE, host_key.export_public_key("openssh").decode("ascii"))
    remote.path("/etc/ssh/sshd_config.d").mkdir(parents=True, exist_ok=True)
    host = _SshdHost(
        name=HOST_NAME, remote=remote, launcher=launcher, log=sshd.log, host_key=host_key, authorized=[],
        bootstrap_key=asyncssh.generate_private_key("ssh-ed25519"),
    )
    _loop().call(host._start())
    return host


@pytest.fixture
def server_1(sshd: Any, journey: Any) -> Any:
    host = _start_server_1(sshd, journey)
    yield host
    _loop().call(host._stop())


# ---------------------------------------------------------------------------
# Another member's device: its own key, an in-process OpenSSH-compatible client
# ---------------------------------------------------------------------------


def _member_login(host: _SshdHost, key: asyncssh.SSHKey, certificate: str, host_ca: str) -> str:
    """Log in as the member with *certificate*; "refused" when sshd says no."""
    async def attempt() -> str:
        trusted = asyncssh.import_known_hosts(f"@cert-authority [{LOOPBACK}]:{host.port} {host_ca}\n")
        try:
            async with asyncssh.connect(
                LOOPBACK, host.port, username=LOGIN, known_hosts=trusted, config=[],
                client_keys=[(key, asyncssh.import_certificate(certificate))], agent_path=None,
                password_auth=False, kbdint_auth=False, gss_auth=False, connect_timeout=30,
            ) as connection:
                result = await connection.run("hostname", check=False)
                return str(result.stdout).strip()
        except asyncssh.PermissionDenied:
            return "refused"

    return asyncio.run(attempt())


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------


def _json(result: Any) -> dict:
    assert result.returncode == 0, result.describe()
    return json.loads(result.stdout)


@dataclass
class _PtyRun:
    returncode: int
    text: str
    prompted: bool


def _confirmed(journey: Any, home: Any, servonaut_cmd: list[str], *args: str, answer: str,
               prompt: Optional[str] = None) -> _PtyRun:
    """Run a CA command on a terminal and type *answer* at its prompt.

    The prompt defaults to the typed host-name confirmation of host jobs.
    """
    expected = f"Type {answer} to continue:" if prompt is None else prompt
    process, master = _start_on_pty(
        [*servonaut_cmd, *args], env=journey.child_env(home), cwd=home.base, size=(160, 50),
    )
    screen = _PlainText()
    prompted = False
    try:
        prompted = _read_until(
            master, screen, lambda text: expected in text, time.monotonic() + WAIT_SECONDS, repr(expected),
        )
        if prompted:
            os.write(master, (answer + "\n").encode("ascii"))
            _read_until(master, screen, lambda _text: False, time.monotonic() + WAIT_SECONDS, "the command")
        returncode = process.wait(timeout=30)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        os.close(master)
    require_armed(journey.armed_log, pid=process.pid)
    journey.children.append(f"$ {' '.join(process.args)}\n[exit {returncode}]\n--- pty ---\n{screen.text}")
    return _PtyRun(returncode, screen.text, prompted)


def _short_account_home(journey: Any, fake_cloud: Any) -> Sandbox:
    """A signed-in child home close to the test root.

    A certificate login needs the private ssh-agent's socket in
    ``~/.servonaut/vault/tmp``, the only place the suite's OpenSSH
    pass-through accepts one; under a journey's own folder that path is
    longer than a Unix socket name may be (108 bytes).
    """
    sandbox = Sandbox(journey.ctx.root / f"ca{journey.directory.name[:4]}").create()
    journey.homes.append(sandbox.home)
    seeder = HomeSeeder(sandbox.home, api_url=fake_cloud.url)
    seed_relay_config(seeder)
    seeder.cache(fleet.cache_rows(), fresh=True)
    seed_session(sandbox.home, fake_cloud)
    return sandbox


def _owner_home(journey: Any, fake_cloud: Any, servonaut_cmd: list[str], host: _SshdHost) -> Any:
    """A signed-in owner with a vault identity and an admin login on server-1."""
    _configure_test_custody(journey)
    key_name = "server-1_bootstrap"
    home = _short_account_home(journey, fake_cloud)
    ssh_dir = home.home / ".ssh"
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    key_path = ssh_dir / key_name
    key_path.write_bytes(host.bootstrap_key.export_private_key("openssh"))
    key_path.chmod(0o600)
    # The existing credential the first enrolment uses: the admin user's key
    # and the host key the owner already trusts.
    config_path = home.home / ".servonaut" / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config.setdefault("instance_keys", {})[SERVER_ID] = str(key_path)
    config_path.write_text(json.dumps(config), encoding="utf-8")
    known_hosts = home.home / ".servonaut" / "known_hosts"
    host_line = host.host_key.export_public_key("openssh").decode("ascii").strip()
    known_hosts.write_text(f"[{LOOPBACK}]:{host.port} {host_line}\n", encoding="utf-8")
    known_hosts.chmod(0o600)
    (home.home / ".servonaut").chmod(0o700)
    setup, _recovery = _setup_with_recovery_confirmation(journey, home, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    return home


def _newest_certificate(home: Any) -> Any:
    """The user certificate the CLI holds most recently (its ``~/.servonaut/certs``)."""
    paths = sorted((home.home / ".servonaut" / "certs" / TEAM_SLUG).glob("*.cert.pub"),
                   key=lambda path: int(path.name.split("-")[-2]))
    assert paths, "the CLI holds no SSH CA certificate"
    return load_ssh_public_identity(paths[-1].read_bytes().strip())


def _managed_files(host: _SshdHost) -> dict[str, bytes]:
    """Everything an enrolment writes on the host, by remote path."""
    paths = [DROP_IN, "/etc/ssh/ssh_host_ed25519_key-cert.pub"]
    managed = host.remote.path("/etc/ssh/servonaut")
    paths += ["/" + str(path.relative_to(host.remote.base)) for path in sorted(managed.rglob("*")) if path.is_file()]
    return {path: host.remote.read_bytes(path) for path in paths}


def _ca_roles(text: str) -> dict[str, str]:
    """The role the confirmation screen gives each user CA fingerprint."""
    roles = {}
    for line in text.splitlines():
        words = line.split(maxsplit=1)
        if words and words[0].startswith("SHA256:") and len(words) == 2:
            roles[words[0]] = words[1].strip()
    return roles


def _pins_file(home: Any) -> Any:
    return home.home / ".servonaut" / "vault" / "ca_pins.json"


def _held_certificates(home: Any) -> list[str]:
    directory = home.home / ".servonaut" / "certs" / TEAM_SLUG
    return sorted(path.name for path in directory.iterdir()) if directory.is_dir() else []


def _refresh_as_other_admin(fake_cloud: Any, host: _SshdHost, device: Any, enrollment_id: str) -> None:
    """Another admin's CLI carries out a refresh job, as the v1 template does.

    A refresh rewrites the CA keys, principals and KRL; sshd reads those files
    at every authentication, so the loaded drop-in and host certificate stay.
    """
    vault = fake_cloud.vault
    status, params = vault.enrollment_params(TEAM_SLUG, enrollment_id, device.user_id)
    assert status == 200, params
    status, claimed = vault.claim_enrollment(TEAM_SLUG, enrollment_id, device)
    assert status == 200, claimed
    host.remote.write("/etc/ssh/servonaut/revoked.krl", base64.b64decode(params["krl"]))
    host.remote.write("/etc/ssh/servonaut/user_ca_keys.pub", "\n".join(params["user_ca_public_keys"]) + "\n")
    for login, principals in params["principals_by_login"].items():
        host.remote.write(f"/etc/ssh/servonaut/principals/{login}", "\n".join(principals) + "\n")
    status, done = vault.enrollment_result(TEAM_SLUG, enrollment_id, device, {
        "status": "succeeded", "steps": [{"name": "managed_files", "status": "ok", "detail": ""}],
    })
    assert status == 200 and done["status"] == "succeeded", done


def _installed_ca_keys(host: _SshdHost) -> set[str]:
    text = host.remote.read_bytes("/etc/ssh/servonaut/user_ca_keys.pub").decode("ascii")
    return {_fingerprint(line) for line in _key_lines(text)}


def _host_row(fake_cloud: Any) -> dict:
    rows = [row for row in fake_cloud.vault.ca_hosts()["data"] if row["server_id"] == SERVER_ID]
    assert len(rows) == 1, rows
    return rows[0]


# ---------------------------------------------------------------------------
# The journey
# ---------------------------------------------------------------------------


def test_a_user_ca_rollover_is_carried_through_by_ca_refresh(journey, fake_cloud, cli, servonaut_cmd, server_1):
    fake_cloud.account.configure(teams=[_VAULT_TEAM])
    fake_cloud.account.place_shared_server(TEAM_SLUG, SERVER_ID, hostname=LOOPBACK, port=server_1.port)
    owner = _owner_home(journey, fake_cloud, servonaut_cmd, server_1)

    # 1. The CA is enabled and server-1 enrolled with generation 1 (Ed25519).
    enabled = _json(cli(owner, "ca", "enable", "--team", TEAM_SLUG, "--yes", "--json"))
    assert enabled["enabled"] is True
    gen1 = fake_cloud.vault.ca_payload(TEAM_SLUG)["user_ca"]
    host_ca = fake_cloud.vault.ca_payload(TEAM_SLUG)["host_ca"]["public_key"]
    assert gen1["alg"] == "ssh-ed25519"

    enrolled = _confirmed(journey, owner, servonaut_cmd, "ca", "enroll", HOST_NAME, "--team", TEAM_SLUG,
                          answer=LOOPBACK)
    assert enrolled.prompted, enrolled.text
    assert enrolled.returncode == 0, enrolled.text
    assert "result.status: succeeded" in enrolled.text, enrolled.text
    assert _installed_ca_keys(server_1) == {gen1["fingerprint"]}
    assert _host_row(fake_cloud)["status"] == "enrolled"
    assert _host_row(fake_cloud)["user_ca_generations"] == [1]
    # The enrolment proved a certificate login before it reported success
    # (a plain key would not do: the host takes it only for the admin user).
    assert any(login.accepted for login in server_1.certificate_logins())

    owner_login = cli(owner, "ssh", HOST_NAME, stdin="hostname\n")
    assert owner_login.returncode == 0, owner_login.describe()
    assert owner_login.stdout.splitlines()[0] == HOST_NAME
    member_key = asyncssh.generate_private_key("ssh-ed25519")
    member_public = member_key.export_public_key("openssh").decode("ascii").strip()
    member_gen1 = fake_cloud.vault.issue_member_certificate(member_public)
    assert _member_login(server_1, member_key, member_gen1["certificate"], host_ca) == HOST_NAME

    # 2. The owner starts a rollover on the web: the next CA is ECDSA P-256,
    # announced, and server-1 has a queued refresh job. gen1 certificates work.
    status, rolled = fake_cloud.vault.start_ca_rollover()
    assert status == 201, rolled
    gen2 = rolled["user_ca_next"]
    assert gen2["alg"] == "ecdsa-sha2-nistp256" and gen2["status"] == "next"
    queued = fake_cloud.vault.list_enrollments(TEAM_SLUG, "requested")["data"]
    assert [(job["kind"], job["server_id"]) for job in queued] == [("refresh", SERVER_ID)]
    waiting = cli(owner, "ca", "jobs", "--team", TEAM_SLUG)
    assert waiting.returncode == 0, waiting.describe()
    assert f"servonaut ca refresh {SERVER_ID} --team {TEAM_SLUG}" in waiting.stdout, waiting.describe()
    status, refused = fake_cloud.vault.complete_ca_rollover()
    assert status == 409 and refused["error"]["code"] == "hosts_not_ready", refused
    assert _member_login(server_1, member_key, member_gen1["certificate"], host_ca) == HOST_NAME
    still = cli(owner, "ssh", HOST_NAME, stdin="hostname\n")
    assert still.returncode == 0, still.describe()

    # 3. ``ca refresh`` resumes the rollover's job (the service answers 409
    # enrollment_in_progress to a second one) and installs both CA keys.
    refreshed = _confirmed(journey, owner, servonaut_cmd, "ca", "refresh", HOST_NAME, "--team", TEAM_SLUG,
                           "--yes", answer=LOOPBACK)
    assert refreshed.prompted, refreshed.text
    assert "SSH certificate job: refresh" in refreshed.text, refreshed.text
    roles = _ca_roles(refreshed.text)
    assert "active" in roles.get(gen1["fingerprint"], "") and "next" in roles.get(gen2["fingerprint"], ""), roles
    assert refreshed.returncode == 0, refreshed.text
    assert "result.status: succeeded" in refreshed.text, refreshed.text
    jobs = fake_cloud.vault.list_enrollments(TEAM_SLUG, None)["data"]
    assert [job["kind"] for job in jobs if job["server_id"] == SERVER_ID] == ["refresh", "enroll"]
    assert jobs[0]["enrollment_id"] == queued[0]["enrollment_id"] and jobs[0]["status"] == "succeeded"
    assert _installed_ca_keys(server_1) == {gen1["fingerprint"], gen2["fingerprint"]}
    assert _host_row(fake_cloud)["user_ca_generations"] == [1, 2]
    assert _member_login(server_1, member_key, member_gen1["certificate"], host_ca) == HOST_NAME

    # 4. The owner completes the rollover on the web. That publishes no KRL.
    krl_before = fake_cloud.vault.ca_payload(TEAM_SLUG)["krl_version"]
    status, completed = fake_cloud.vault.complete_ca_rollover()
    assert status == 200, completed
    assert completed["user_ca"]["fingerprint"] == gen2["fingerprint"] and completed["user_ca_next"] is None
    assert [ca["fingerprint"] for ca in completed["user_ca_previous"]] == [gen1["fingerprint"]]
    assert completed["krl_version"] == krl_before

    # 5. Logins now use certificates signed by the ECDSA P-256 CA, and the CLI
    # follows the announced CA instead of refusing a changed pin.
    after = cli(owner, "ssh", HOST_NAME, stdin="hostname\n")
    assert CA_CHANGED not in after.stderr, after.describe()
    assert after.returncode == 0, after.describe()
    assert after.stdout.splitlines()[0] == HOST_NAME
    held = _newest_certificate(owner)
    signer = held.signature_key()
    assert isinstance(signer, ec.EllipticCurvePublicKey) and signer.curve.name == "secp256r1"
    assert _fingerprint(_openssh_line(signer)) == gen2["fingerprint"]
    last = server_1.certificate_logins()[-1]
    assert last.accepted and last.serial == held.serial and last.ca_alg == "ecdsa-sha2-nistp256"
    status_after = _json(cli(owner, "ca", "status", "--team", TEAM_SLUG, "--json"))
    assert status_after["user_ca_fingerprint"] == gen2["fingerprint"]

    member_gen2 = fake_cloud.vault.issue_member_certificate(member_public)
    assert _member_login(server_1, member_key, member_gen2["certificate"], host_ca) == HOST_NAME

    # 6. Revoking that certificate and delivering the KRL makes the host refuse it.
    revoked = _json(cli(owner, "ca", "revoke", str(member_gen2["serial"]), "--team", TEAM_SLUG, "--yes", "--json"))
    assert revoked["serial"] == member_gen2["serial"]
    assert _member_login(server_1, member_key, member_gen2["certificate"], host_ca) == HOST_NAME  # not delivered yet
    delivered = _json(cli(owner, "ca", "krl", "--team", TEAM_SLUG, "--json"))
    assert [row["status"] for row in delivered["results"]] == ["delivered"]
    assert _member_login(server_1, member_key, member_gen2["certificate"], host_ca) == "refused"
    assert server_1.certificate_logins()[-1].reason == "revoked"
    assert _host_row(fake_cloud)["krl_version_delivered"] == revoked["krl_version"]

    # 7. With a job of another kind open, ``ca refresh`` is refused clearly and
    # creates no second job.
    status, other = fake_cloud.vault.request_enrollment("unenroll")
    assert status == 201, other
    # Without a terminal nobody can type the host name: refused before any job.
    piped = cli(owner, "ca", "refresh", HOST_NAME, "--team", TEAM_SLUG, "--yes")
    assert piped.returncode == 5, piped.describe()
    assert "needs the host name typed" in piped.stderr, piped.describe()
    second = _confirmed(journey, owner, servonaut_cmd, "ca", "refresh", HOST_NAME, "--team", TEAM_SLUG, "--yes",
                        answer=LOOPBACK)
    assert not second.prompted and second.returncode == 1, second.text
    assert "open SSH certificate unenroll job" in second.text and "Traceback" not in second.text, second.text
    open_jobs = [job for job in fake_cloud.vault.list_enrollments(TEAM_SLUG, None)["data"]
                 if job["status"] in {"requested", "claimed"}]
    assert [job["enrollment_id"] for job in open_jobs] == [other["enrollment_id"]]
    assert open_jobs[0]["status"] == "requested"
    assert _installed_ca_keys(server_1) == {gen1["fingerprint"], gen2["fingerprint"]}
    status, cancelled = fake_cloud.vault.cancel_enrollment(TEAM_SLUG, other["enrollment_id"])
    assert status == 200 and cancelled["status"] == "cancelled", cancelled

    # 8. A refresh the host's sshd refuses is rolled back: the CLI says so,
    # exits 1, and the host keeps the setup it had, logins included.
    before = _managed_files(server_1)
    server_1.config_test_failures.append("/etc/ssh/sshd_config line 12: Bad configuration option")
    failed = _confirmed(journey, owner, servonaut_cmd, "ca", "refresh", HOST_NAME, "--team", TEAM_SLUG,
                        "--yes", answer=LOOPBACK)
    assert failed.prompted, failed.text
    # After the rollover a host job installs only the active CA.
    assert set(_ca_roles(failed.text)) == {gen2["fingerprint"]}, failed.text
    assert failed.returncode == 1, failed.text
    assert "result.status: rolled_back" in failed.text and "did not complete (rolled_back)" in failed.text, failed.text
    assert not server_1.config_test_failures
    assert _managed_files(server_1) == before
    assert server_1.active is not None and "trustedusercakeys" in server_1.active
    row = _host_row(fake_cloud)
    assert row["status"] == "enrolled" and row["user_ca_generations"] == [1, 2] and row["last_error"], row
    assert fake_cloud.vault.list_enrollments(TEAM_SLUG, None)["data"][0]["status"] == "rolled_back"
    again = cli(owner, "ssh", HOST_NAME, stdin="hostname\n")
    assert again.returncode == 0, again.describe()
    assert again.stdout.splitlines()[0] == HOST_NAME

    # 9. Another admin rolls the CA over again (gen3) while this device is not
    # looking, and the retired CAs' certificates expire: nothing links the
    # pinned gen2 to gen3, so the CLI refuses it until a person trusts it.
    other_admin = fake_cloud.vault.seed_identity(OTHER_ADMIN_USER_ID, name="other admin device")
    other_device = fake_cloud.vault._devices[other_admin["device"]["device_id"]]
    status, rolled = fake_cloud.vault.start_ca_rollover(user_id=OTHER_ADMIN_USER_ID)
    assert status == 201, rolled
    gen3 = rolled["user_ca_next"]
    assert gen3["generation"] == 3 and gen3["alg"] == "ecdsa-sha2-nistp256", gen3
    (job,) = fake_cloud.vault.list_enrollments(TEAM_SLUG, "requested")["data"]
    assert job["executor_user_id"] == OTHER_ADMIN_USER_ID, job
    _refresh_as_other_admin(fake_cloud, server_1, other_device, job["enrollment_id"])
    # A host job lists the active and the next CA only, never a retired one.
    assert _installed_ca_keys(server_1) == {gen2["fingerprint"], gen3["fingerprint"]}
    assert _host_row(fake_cloud)["user_ca_generations"] == [2, 3]
    assert _member_login(server_1, member_key, member_gen1["certificate"], host_ca) == "refused"
    assert server_1.certificate_logins()[-1].reason == "CA not trusted"
    status, completed = fake_cloud.vault.complete_ca_rollover()
    assert status == 200 and completed["user_ca"]["fingerprint"] == gen3["fingerprint"], completed
    assert fake_cloud.vault.expire_retired_user_cas() == [1, 2]
    payload = fake_cloud.vault.ca_payload(TEAM_SLUG)
    assert payload["user_ca_previous"] == [] and payload["user_ca_next"] is None, payload

    pins_before = _pins_file(owner).read_bytes()
    assert json.loads(pins_before)["teams"][TEAM_SLUG]["user_ca_fingerprint"] == gen2["fingerprint"]
    held_before = _held_certificates(owner)
    logins_before = len(server_1.certificate_logins())
    changed = cli(owner, "ssh", HOST_NAME, stdin="hostname\n")
    assert changed.returncode != 0, changed.describe()
    assert CA_CHANGED in changed.stderr, changed.describe()
    assert f"servonaut ca trust --team {TEAM_SLUG}" in changed.stderr, changed.describe()
    assert _pins_file(owner).read_bytes() == pins_before
    assert _held_certificates(owner) == held_before
    assert len(server_1.certificate_logins()) == logins_before

    # Trusting a changed CA needs a person at a terminal.
    piped_trust = cli(owner, "ca", "trust", "--team", TEAM_SLUG)
    assert piped_trust.returncode == 5, piped_trust.describe()
    assert "needs a person" in piped_trust.stderr, piped_trust.describe()
    assert _pins_file(owner).read_bytes() == pins_before

    prompt = TRUST_PROMPT.format(team=TEAM_SLUG)
    declined = _confirmed(journey, owner, servonaut_cmd, "ca", "trust", "--team", TEAM_SLUG, answer="n", prompt=prompt)
    assert declined.prompted, declined.text
    assert gen2["fingerprint"] in declined.text and gen3["fingerprint"] in declined.text, declined.text
    assert declined.returncode == 5, declined.text
    assert "Nothing changed." in declined.text, declined.text
    assert _pins_file(owner).read_bytes() == pins_before

    trusted = _confirmed(journey, owner, servonaut_cmd, "ca", "trust", "--team", TEAM_SLUG, answer="y", prompt=prompt)
    assert trusted.prompted, trusted.text
    assert gen2["fingerprint"] in trusted.text and gen3["fingerprint"] in trusted.text, trusted.text
    assert trusted.returncode == 0, trusted.text
    assert "changed: True" in trusted.text, trusted.text
    pinned = json.loads(_pins_file(owner).read_bytes())["teams"][TEAM_SLUG]
    assert pinned["user_ca_fingerprint"] == gen3["fingerprint"], pinned
    assert pinned["host_ca_fingerprint"] == _fingerprint(host_ca), pinned

    # The other admin's refresh installed gen3, so the owner logs in again.
    trusted_login = cli(owner, "ssh", HOST_NAME, stdin="hostname\n")
    assert CA_CHANGED not in trusted_login.stderr, trusted_login.describe()
    assert trusted_login.returncode == 0, trusted_login.describe()
    assert trusted_login.stdout.splitlines()[0] == HOST_NAME
    assert _fingerprint(_openssh_line(_newest_certificate(owner).signature_key())) == gen3["fingerprint"]
    assert server_1.certificate_logins()[-1].accepted
