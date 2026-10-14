"""A loopback SSH host whose sshd honours the Servonaut SSH CA drop-in.

:func:`start_ca_host` starts ``server-1``: a loopback SSH host whose remote
commands run like on the suite's other hosts (a remote root with its own
tools, see :mod:`e2e.harness.remote_root`). Its sshd is emulated here as
OpenSSH documents it, because neither the suite nor the QA sandbox may start
a real ``sshd``:

* ``sshd -V``, ``sshd -T`` and ``sshd -t`` answer from the configuration on
  disk, so the CLI's pre-checks see what a real host would report;
* ``systemctl reload ssh`` loads the Servonaut drop-in: from then on the host
  presents its ``HostCertificate`` and accepts user certificates only per
  ``TrustedUserCAKeys``, ``AuthorizedPrincipalsFile`` and ``RevokedKeys``,
  reading those files at every authentication, as sshd does;
* an owner's bootstrap key logs in as the image's admin user (who has
  passwordless sudo): the existing credential the first enrolment needs.
  :func:`install_owner_credential` puts it in a home, with the host key the
  owner already trusts.

Every login decision reads the files the CLI wrote on the host, so a journey
proves what was installed, not what the CLI reported. :attr:`CaSshdHost.logins`
records each decision, and the shared command log every session.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

import asyncssh
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    SSHCertificate,
    SSHCertificateType,
    load_ssh_public_identity,
    load_ssh_public_key,
)

from e2e.harness.remote_root import SYSTEM_TOOL_DIRS, RemoteRoot, SessionLauncher
from e2e.harness.sshd import LOOPBACK, CommandLog, RemoteHost, _loop

HOST_NAME = "server-1"
# The login the team's certificates are for (the shared server's login user).
LOGIN = "deploy"
# The owner's existing access before the CA: a key for the image's admin user.
ADMIN_USER = "ec2-user"
# Where the owner keeps that key (in ``~/.ssh``).
BOOTSTRAP_KEY_NAME = "server-1_bootstrap"
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
class Krl:
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


def parse_krl(data: bytes) -> Krl:
    """Parse a KRL the way ``sshd`` must; anything unexpected raises ValueError."""
    reader = _Reader(data)
    if reader.u64() != 0x5353484B524C0A00 or reader.u32() != 1:
        raise ValueError("not an OpenSSH v1 KRL")
    krl = Krl(version=reader.u64())
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
# Key and certificate lines
# ---------------------------------------------------------------------------


def _blob(line: str) -> bytes:
    return base64.b64decode(line.split()[1])


def fingerprint(line: str) -> str:
    """The ``SHA256:...`` fingerprint of an OpenSSH public key line."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(_blob(line)).digest()).decode().rstrip("=")


def _certificate_line(blob: bytes) -> bytes:
    """``<algorithm> <base64>`` for a certificate's wire blob."""
    return _Reader(blob).string() + b" " + base64.b64encode(blob)


def _is_certificate(blob: bytes) -> bool:
    try:
        return isinstance(load_ssh_public_identity(_certificate_line(blob)), SSHCertificate)
    except (ValueError, UnicodeError):
        return _Reader(blob).string().endswith(b"-cert-v01@openssh.com")  # leak-guard:allow (OpenSSH certificate algorithm suffix)


def openssh_line(public_key: Any) -> str:
    """A ``cryptography`` public key as an OpenSSH public key line."""
    return public_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")


def key_lines(text: str) -> list[str]:
    """The non-empty, non-comment lines of a key or principals file."""
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


# ---------------------------------------------------------------------------
# server-1: sshd with the Servonaut drop-in, emulated in-process
# ---------------------------------------------------------------------------


@dataclass
class SshdLogin:
    """One public-key authentication the emulated sshd decided."""

    user: str
    kind: str  # "key" or "certificate"
    accepted: bool
    reason: str
    serial: Optional[int] = None
    ca_fingerprint: Optional[str] = None
    ca_alg: Optional[str] = None


@dataclass
class CaSshdHost(RemoteHost):
    """``server-1`` (see the module docstring for what is emulated, and how)."""

    bootstrap_key: Any = None
    active: Optional[dict[str, str]] = None  # the drop-in as of the last reload
    logins: list[SshdLogin] = field(default_factory=list)
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

    def stop(self) -> None:
        """Stop listening and drop every session."""
        _loop().call(self._stop())

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
        for line in key_lines(text):
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
                for line in key_lines(self.remote.read_bytes(directives["trustedusercakeys"]).decode("ascii")):
                    load_ssh_public_key(" ".join(line.split()[:2]).encode("ascii"))
            if "revokedkeys" in directives:
                parse_krl(self.remote.read_bytes(directives["revokedkeys"]))
            if "hostcertificate" in directives:
                certificate = load_ssh_public_identity(self.remote.read_bytes(directives["hostcertificate"]).strip())
                if certificate.type is not SSHCertificateType.HOST:
                    return "HostCertificate is not a host certificate"
                if _blob(openssh_line(certificate.public_key())) != self.host_key.public_data:
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
        login = SshdLogin(username, "key", accepted, "authorized key" if accepted else "unknown key")
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
        return asyncssh.import_public_key(openssh_line(subject))

    def _certificate_verdict(self, username: str, key_data: bytes) -> SshdLogin:
        def refused(reason: str, **details: Any) -> SshdLogin:
            return SshdLogin(username, "certificate", False, reason, **details)

        try:
            certificate = load_ssh_public_identity(_certificate_line(key_data))
        except (ValueError, UnicodeError):
            return refused("malformed certificate")
        ca_line = openssh_line(certificate.signature_key())
        details = {"serial": certificate.serial, "ca_fingerprint": fingerprint(ca_line), "ca_alg": ca_line.split()[0]}
        config = self.active
        if not config or "trustedusercakeys" not in config:
            return refused("no TrustedUserCAKeys", **details)
        if "revokedkeys" in config:
            try:
                krl = parse_krl(self.remote.read_bytes(config["revokedkeys"]))
            except (OSError, ValueError):
                # sshd refuses every public key when RevokedKeys cannot be read.
                return refused("RevokedKeys unreadable", **details)
            subject = _blob(openssh_line(certificate.public_key()))
            if krl.revokes(_blob(ca_line), certificate.serial, certificate.key_id, subject):
                return refused("revoked", **details)
        try:
            trusted = {_blob(line) for line in key_lines(
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
            allowed = set(key_lines(text))
        if not {value.decode() for value in certificate.valid_principals} & allowed:
            return refused("no listed principal", **details)
        try:
            certificate.verify_cert_signature()
        except Exception:  # noqa: BLE001 - any failure is a refusal
            return refused("bad CA signature", **details)
        return SshdLogin(username, "certificate", True, "trusted CA", **details)

    def certificate_logins(self) -> list[SshdLogin]:
        return [login for login in self.logins if login.kind == "certificate"]

    # -- the owner's side ---------------------------------------------------

    def known_hosts_line(self) -> str:
        """The line an owner who already trusts this host has in a known_hosts file."""
        host_line = self.host_key.export_public_key("openssh").decode("ascii").strip()
        return f"[{LOOPBACK}]:{self.port} {host_line}"


class _SshdCallbacks(asyncssh.SSHServer):
    """Public-key authentication for :class:`CaSshdHost`.

    asyncssh validates user certificates itself, without sshd's principals
    file or revocation list; the connection's certificate check is replaced
    by the host's sshd rules (``_validate_client_certificate`` takes the raw
    certificate blob and returns the key it certifies, or None).
    """

    def __init__(self, host: CaSshdHost) -> None:
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


def start_ca_host(*, log: CommandLog, remote_dir: Path, hidden: Iterable[str]) -> CaSshdHost:
    """Start ``server-1`` on loopback; stop it with :meth:`CaSshdHost.stop`.

    Its remote root and launcher go in *remote_dir* (beside the other hosts'
    roots); remote commands never see the *hidden* directories when they run
    under bubblewrap. Sessions are recorded in *log*.
    """
    remote = RemoteRoot(remote_dir / HOST_NAME, HOST_NAME, (LOGIN, ADMIN_USER))
    launcher = SessionLauncher(remote, remote_dir / f".launch-{HOST_NAME}", hidden=list(hidden))
    log.add(host=HOST_NAME, event="confinement", mode=launcher.mode, detail=launcher.detail)
    for tool in EXTRA_TOOLS:
        source = next((Path(d) / tool for d in SYSTEM_TOOL_DIRS if (Path(d) / tool).exists()), None)
        assert source is not None, f"{tool} is missing from {SYSTEM_TOOL_DIRS}"
        remote.write(f"/bin/{tool}", f'#!/bin/sh\nexec {shlex.quote(str(source.resolve()))} "$@"\n', mode=0o755)
    remote.write("/bin/sudo", SUDO, mode=0o755)
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    remote.write(HOST_KEY_FILE, host_key.export_public_key("openssh").decode("ascii"))
    remote.path("/etc/ssh/sshd_config.d").mkdir(parents=True, exist_ok=True)
    host = CaSshdHost(
        name=HOST_NAME, remote=remote, launcher=launcher, log=log, host_key=host_key, authorized=[],
        bootstrap_key=asyncssh.generate_private_key("ssh-ed25519"),
    )
    _loop().call(host._start())
    return host


def install_owner_credential(home: Path, host: CaSshdHost, server_id: str) -> Path:
    """Give the Servonaut home *home* the owner's existing access to *host*.

    That is the credential the first enrolment uses: the admin user's key in
    ``~/.ssh`` (mapped to *server_id* in ``config.json``'s ``instance_keys``)
    and the host key the owner already trusts, in ``~/.servonaut/known_hosts``.
    The home's ``config.json`` must exist. Returns the key's path.
    """
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    key_path = ssh_dir / BOOTSTRAP_KEY_NAME
    key_path.write_bytes(host.bootstrap_key.export_private_key("openssh"))
    key_path.chmod(0o600)
    config_path = home / ".servonaut" / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config.setdefault("instance_keys", {})[server_id] = str(key_path)
    config_path.write_text(json.dumps(config), encoding="utf-8")
    known_hosts = home / ".servonaut" / "known_hosts"
    with known_hosts.open("a", encoding="utf-8") as handle:
        handle.write(host.known_hosts_line() + "\n")
    known_hosts.chmod(0o600)
    (home / ".servonaut").chmod(0o700)
    return key_path
