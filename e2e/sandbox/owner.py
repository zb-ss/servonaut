"""``python -m e2e.sandbox up``: start the fakes, seed a home, wait for ``down``.

The owner is one foreground process. Under a lock on the per-user pointer's
directory it creates its root (by default ``<checkout>/.qa-sandbox``) with
the marker, takes the owner lock on that marker for its whole life (see
``state.py``) and writes the pointer. It then bootstraps a hermetic
environment in that root, starts the same fakes the end-to-end suite uses,
seeds one home for the scenario and records everything a driver needs in
``<root>/state.json``:

``schema``, ``scenario``, ``signed_in``, ``keep``, ``started_at``,
``owner_pid``, ``owner_identity``, ``root``, ``pointer``
    what the sandbox is, which process owns it, and where it lives;
``repo_root``, ``src_dir``, ``python``, ``version``, ``distribution``
    the checkout it runs, the interpreter every child uses, and the version
    and package metadata (``.dist-info``) those children report;
``sandbox``
    the home (``home``) and the directory children start in (``base``);
``env``
    the complete child environment (``bootstrap.build_env``): home, fake
    tools on ``PATH``, fake credentials, the fakes' URLs, the guard settings
    and the module redirects;
``urls``, ``logs``, ``fleet``, ``notes``
    the fakes, where their request logs are, and the seeded servers;
``teams``
    with ``--teams``, the team the account owns and its shared server (see
    :meth:`Owner._teams_record`); otherwise None;
``personas``
    with ``--teams``, the people beside the owner: ``member``, with their
    e-mail address, FakeCloud user id, home and complete child environment
    (``run --as member``); otherwise empty;
``desktop``
    the desktop child last started on request (``python -m e2e.sandbox desktop``).

Then it prints ``SANDBOX READY <state.json>`` and serves: it writes the
fakes' request logs to disk and answers desktop requests and, with
``--teams``, the member's requests (accept an invitation, approve their next
sign-in), which arrive as files in ``<root>/control`` (no signal is ever
needed to reach it). SIGINT,
SIGTERM or SIGHUP stop it, also during start-up: it stops everything,
removes the root (unless ``--keep``) and releases the pointer. Every child it
starts also stops by itself once the owner or the root is gone
(``child_guard.py``).
"""

from __future__ import annotations

import base64
import importlib.metadata
import json
import logging
import os
import queue
import re
import select
import shutil
import signal
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from e2e.harness import bootstrap
from e2e.sandbox import state

# A Vault key's private SSH agent puts its socket under TMPDIR, and uses /tmp
# when TMPDIR leaves too little room for a Unix socket path ("svn-agent-",
# eight random characters, separators and "agent-<pid>-<16 hex>.sock", with
# slack). The guard keeps the sandbox's children out of /tmp, so a sandbox
# whose own temp directory is that long gives its children a short one.
_UNIX_SOCKET_PATH_MAX = 107 if sys.platform.startswith("linux") else 103
_AGENT_SOCKET_ROOM = 60
_SHORT_TMP_BASE = "/tmp"


def needs_short_temp_dir(tmp: Path) -> bool:
    """Whether *tmp* is too long to hold a private SSH agent's socket."""
    return len(os.fsencode(os.path.realpath(tmp))) + _AGENT_SOCKET_ROOM > _UNIX_SOCKET_PATH_MAX


def _short_temp_base() -> Optional[str]:
    """Where a short temp directory may go, or None.

    /tmp, unless an outer e2e guard confines this process (a sandbox started
    by a journey): then only one of its write roots that is short enough, and
    otherwise none, since even an attempt outside them counts as an escape.
    """
    confined = os.environ.get("SERVONAUT_E2E_WRITE_ROOTS")
    if not confined:
        return _SHORT_TMP_BASE if os.path.isdir(_SHORT_TMP_BASE) else None
    for root in sorted(filter(None, confined.split(os.pathsep)), key=len):
        if not needs_short_temp_dir(Path(root) / "servonaut-qa-xxxxxxxx"):
            return root
    return None


def make_short_temp_dir(user_base: Path) -> Optional[Path]:
    """A new private temp directory when *user_base*/tmp is too long, else None."""
    from e2e.harness.bootstrap import Sandbox

    base = _short_temp_base() if needs_short_temp_dir(Sandbox(user_base).tmp) else None
    if base is None:
        return None
    import tempfile

    return Path(tempfile.mkdtemp(prefix="servonaut-qa-", dir=base)).resolve()


# With --teams, a certificate login's private SSH agent listens in the home's
# Vault custody directory, the only place the sandbox's OpenSSH pass-through
# accepts one (as agent-<pid>-<16 hex>.sock; the pid has up to 7 digits).
_CUSTODY_AGENT_SOCKET = Path(".servonaut", "vault", "tmp", "agent-4194304-0123456789abcdef.sock")
# The Vault custody key of a --teams sandbox's children, which have no OS keyring.
VAULT_DEVICE_KEY_ENV = "SERVONAUT_VAULT_DEVICE_KEY"
_TEAMS_PLAN = "teams"
# With --teams, a second person beside the owner: a team member to be, with
# a home of their own (<root>/member) and a FakeCloud account, signed out.
MEMBER = "member"
MEMBER_EMAIL = "member@example.com"
MEMBER_NAME = "Team member"
_OWNER_DIR = "user"
# Each person's home; the longest decides how long a --teams root may be.
_PERSONA_DIRS = (_OWNER_DIR, MEMBER)
# Requests to act for the member (accept an invitation, approve a sign-in),
# which arrive as files in <root>/control like the desktop requests.
_TEAM_REQUEST_FILE = re.compile(r"^team-([0-9a-f]{32})\.request\.json$")


def teams_root_problem(root: Path) -> Optional[str]:
    """Why *root* leaves no room for a --teams certificate login, or None."""
    from e2e.harness.bootstrap import Sandbox

    real_root = Path(os.path.realpath(root))
    socket = max(
        (Sandbox(real_root / name).home / _CUSTODY_AGENT_SOCKET for name in _PERSONA_DIRS),
        key=lambda path: len(os.fsencode(path)),
    )
    excess = len(os.fsencode(socket)) - _UNIX_SOCKET_PATH_MAX
    if excess <= 0:
        return None
    length = len(os.fsencode(real_root))
    return (
        f"--teams needs a shorter --root: a certificate login's private SSH agent listens in "
        f"<root>/{socket.parent.relative_to(real_root)}, and a Unix socket path holds at most "
        f"{_UNIX_SOCKET_PATH_MAX} bytes, so the root may be {length - excess} bytes long "
        f"({root} is {length}); for example --root /tmp/svt"
    )


def _fleet_host(name: str) -> Any:
    """The AWS fleet server called *name*, or None."""
    from e2e.harness import fleet

    return next((host for host in fleet.AWS_FLEET if host.name == name), None)


def team_server_as_problem(name: Optional[str], teams: bool) -> Optional[str]:
    """Why ``--team-server-as`` *name* cannot be used, or None."""
    if not name:
        return None
    if not teams:
        return "--team-server-as needs --teams (it names what the team's shared server also is)"
    if _fleet_host(name) is None:
        from e2e.harness import fleet

        names = ", ".join(host.name for host in fleet.AWS_FLEET)
        return f"--team-server-as {name!r} names no AWS server of the sandbox fleet ({names})"
    return None


READY_PREFIX = "SANDBOX READY"
# How often the owner looks for desktop requests and writes the request logs.
_POLL_SECONDS = 0.5
_STOP_TIMEOUT_SECONDS = 15.0
_REQUEST_FILE = re.compile(r"^desktop-([0-9a-f]{32})\.request\.json$")
# Modules `up` needs beyond the suite's own list (bootstrap.REQUIRED_MODULES).
_EXTRA_MODULES = ("asyncssh", "pytest")


class Refused(RuntimeError):
    """``up`` cannot start (the message says why and what to do)."""


def _say(message: str) -> None:
    sys.stderr.write(f"qa-sandbox: {message}\n")
    sys.stderr.flush()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Claiming the pointer and the root
# ---------------------------------------------------------------------------


def _refuse_if_running(current: dict, pointer: Path) -> None:
    """Refuse while the sandbox the pointer names is still running."""
    if current.get("schema") != state.SCHEMA:
        raise Refused(state.unknown_schema(current, pointer))
    liveness, why = state.owner_status(current.get("root", ""))
    if liveness == state.UNKNOWN:
        raise Refused(
            f"cannot tell whether the QA sandbox in {current.get('root')} still runs ({why})"
        )
    if liveness == state.ALIVE:
        raise Refused(
            "a QA sandbox is already running for this user (owner pid "
            f"{current.get('owner_pid')}, started from {current.get('repo_root')}, state "
            f"{current.get('state')}); stop it with `python -m e2e.sandbox down` from any "
            "checkout, or use that one"
        )


def _clean_after_stale_pointer(current: dict, root: Path) -> None:
    """The pointer names a sandbox that stopped without cleaning up elsewhere."""
    stale = Path(str(current.get("root", "")))
    if not current.get("root") or stale == root or not stale.exists():
        return
    if state.remove_stale_root(stale):
        _say(f"removed {stale}, left behind by a sandbox that stopped without cleaning up")
    else:
        _say(
            f"the sandbox this pointer named (started from {current.get('repo_root')}) may "
            f"have left {stale} behind; remove it with `rm -r {stale}` if you do not need it"
        )


def _clear_root(root: Path) -> None:
    """Make way for a new sandbox at *root*, or refuse and say why."""
    if not root.exists():
        return
    found = state.marker(root)
    liveness, why = state.owner_status(root)
    if liveness == state.UNKNOWN:
        raise Refused(
            f"cannot tell whether a QA sandbox still runs in {root} ({why}); choose another --root"
        )
    if liveness == state.ALIVE:
        pid = (found or {}).get("owner_pid")
        raise Refused(
            f"a QA sandbox is running in {root} (owner pid {pid}); stop it with "
            f"`kill -TERM {pid}` or choose another --root"
        )
    if found is None:
        raise Refused(
            f"{root} exists but has no sandbox marker. It may hold files something wrote "
            "after a sandbox there stopped (for example an MCP server that still had the "
            "TUI open), or it is not a sandbox directory at all. Remove it with "
            f"`rm -r {root}` if it is yours to delete, or choose another --root"
        )
    if found.get("schema") != state.SCHEMA:
        raise Refused(state.unknown_schema(found, root / state.MARKER))
    _say(f"removing {root}, left behind by a sandbox that stopped")
    shutil.rmtree(root)


def claim(pointer: Path, root: Path, repo_root: Path, scenario: str,
          cancelled: Callable[[], bool] = lambda: False) -> tuple[dict, state.OwnerLock]:
    """Make this process the owner of the per-user pointer and of *root*.

    Waits while another command (a `down` stopping survivors) holds the
    pointer lock; *cancelled()* ends that wait.
    """
    def waiting() -> None:
        _say("waiting for another QA sandbox command (a `down`) to finish")

    try:
        with state.pointer_lock(pointer, waiting=waiting, cancelled=cancelled):
            return _claim(pointer, root, repo_root, scenario)
    except (state.LockUnsupported, state.LockWaitCancelled) as exc:
        raise Refused(str(exc)) from None


def _claim(pointer: Path, root: Path, repo_root: Path,
           scenario: str) -> tuple[dict, state.OwnerLock]:
    """The claim itself, under the pointer lock."""
    current = state.read_json(pointer)
    if current is not None:
        _refuse_if_running(current, pointer)
        _clean_after_stale_pointer(current, root)
    _clear_root(root)
    root.mkdir(mode=0o700, parents=True)
    record = {
        "schema": state.SCHEMA,
        "state": str(root / state.STATE_FILE),
        "root": str(root),
        "repo_root": str(repo_root),
        "scenario": scenario,
        "owner_pid": os.getpid(),
        "owner_identity": state.process_identity(os.getpid()),
        "started_at": _now(),
    }
    lock = state.OwnerLock(root)
    try:
        locked = lock.acquire({**record, "phase": state.STARTING})
    except state.LockUnsupported as exc:
        shutil.rmtree(root, ignore_errors=True)  # created just above, holding nothing else
        raise Refused(str(exc)) from None
    if not locked:
        raise Refused(f"another process is starting a QA sandbox in {root}")
    state.write_json(pointer, record)
    return record, lock


def release(pointer: Path, record: dict) -> None:
    """Remove the pointer if it still names this sandbox."""
    with state.pointer_lock(pointer):
        current = state.read_json(pointer)
        if current is not None and current.get("state") == record["state"] and (
            current.get("owner_pid") == record["owner_pid"]
        ):
            pointer.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Stop requests
# ---------------------------------------------------------------------------


class StopRequest:
    """SIGINT, SIGTERM and SIGHUP: interrupt the start-up, or end serving.

    Installed before anything else happens, so a signal at any moment leads
    to the same clean stop.
    """

    SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)

    def __init__(self) -> None:
        self.event = threading.Event()
        # While true a signal raises KeyboardInterrupt into the running code.
        self.interrupts = True
        for signum in self.SIGNALS:
            signal.signal(signum, self)

    def __call__(self, signum: int, _frame: Any) -> None:
        self.event.set()
        if self.interrupts:
            self.interrupts = False
            raise KeyboardInterrupt(f"signal {signum}")

    @contextmanager
    def deferred(self) -> Iterator[None]:
        """Hold a stop request back until the block is done.

        For steps that must not stop half-way: taking the claim, and
        installing the guard (an interrupt between its settings would leave
        this process refusing its own checkout).
        """
        interrupts, self.interrupts = self.interrupts, False
        try:
            yield
        finally:
            self.interrupts = interrupts

    def raise_if_requested(self) -> None:
        """Act on a stop request that arrived while it was held back."""
        if self.interrupts and self.event.is_set():
            self.interrupts = False
            raise KeyboardInterrupt("stop requested")


# ---------------------------------------------------------------------------
# The running sandbox
# ---------------------------------------------------------------------------


class Owner:
    """Everything one ``up`` started, and how to stop it."""

    def __init__(self, root: Path, scenario: str, pointer: Path, claim_record: dict,
                 lock: state.OwnerLock, stop_request: StopRequest, *,
                 signed_in: bool, keep: bool, ssh_ca_off: bool = False,
                 ssh_ca_refuse: Optional[str] = None, api_delay: float = 0.0,
                 teams: bool = False, account_email: str = "",
                 verification_uri: Optional[str] = None, user_code: Optional[str] = None,
                 hostname: Optional[str] = None, ai_script: Optional[dict] = None,
                 team_server_as: Optional[str] = None) -> None:
        self.root = root
        self.scenario = scenario
        self.pointer = pointer
        self.claim_record = claim_record
        self.lock = lock
        self.stop_request = stop_request
        self.signed_in = signed_in
        self.keep = keep
        self.ssh_ca_off = ssh_ca_off
        self.ssh_ca_refuse = ssh_ca_refuse
        self.api_delay = api_delay
        self.teams = teams
        # --team-server-as: the AWS fleet server the team's shared server also is.
        self.team_server_as = team_server_as
        self.account_email = account_email
        self.verification_uri = verification_uri
        self.user_code = user_code
        self.hostname = hostname
        self.ai_script = ai_script
        self.logs = root / "logs"
        self.control = root / state.CONTROL_DIR
        self.state_path = root / state.STATE_FILE
        self.ctx: Any = None
        self.fake_cloud: Any = None
        self.moto: Any = None
        self.cloudtrail: Any = None
        self.providers: Any = None
        self.world: Any = None
        self.shims: Any = None
        self.user: Any = None
        self.child_env: Optional[dict] = None
        # --teams: the team's shared server, and the owner's key for it.
        self.ca_host: Any = None
        self.admin_key: Optional[Path] = None
        # --teams: the member's home and child environment.
        self.member: Any = None
        self.member_env: Optional[dict] = None
        # Short temp directory for the children, when the root makes theirs too long.
        self.agent_tmp: Optional[Path] = None
        self._state_lock = threading.Lock()
        self._state: dict = {}
        self._started: list[Any] = []  # things with .stop(), in start order
        self._monkeypatch: Any = None
        self._keeper: Optional[subprocess.Popen] = None
        self._desktop_count = 0
        self._requests: "queue.Queue[Optional[str]]" = queue.Queue()
        self._seen_requests: set[str] = set()
        self._desktop_worker: Optional[threading.Thread] = None
        self._closing = False  # set once stopping: no new desktop starts
        self._flushed: dict[str, int] = {}

    def _set_phase(self, phase: str) -> None:
        self.lock.write({**self.claim_record, "phase": phase})

    # -- start -------------------------------------------------------------

    def start(self) -> None:
        with self.stop_request.deferred():
            # Made before this process's guard is armed: it lies outside the root.
            self.agent_tmp = make_short_temp_dir(self.root / "user")
            self.ctx = bootstrap.bootstrap(self.root)
            self.logs.mkdir()
            self.control.mkdir()
            self._arm_owner_guard()
        self.stop_request.raise_if_requested()
        self._start_fakes()
        self._seed_and_record()
        self._set_phase(state.RUNNING)

    def _arm_owner_guard(self) -> None:
        """This process's refusals go to the sandbox guard log, like its children's."""
        # asyncssh probes for native libraries with ldconfig on import; the
        # guard refuses that, and asyncssh falls back to its own code.
        import asyncssh  # noqa: F401

        ctx = self.ctx
        guard = bootstrap.load_guard()
        guard.clear()
        guard.install(
            log_path=str(self.logs / "guard.jsonl"),
            protected=ctx.protected_dirs,
            allowed=ctx.allowed_dirs,
            write_roots=ctx.write_roots,
            spawn_dirs=[str(ctx.default_shims)],
        )

    def _start(self, server: Any) -> Any:
        self._started.append(server)
        return server

    def _start_fakes(self) -> None:
        import pytest
        from servonaut import get_version

        from e2e.harness import aws_logs_filter
        from e2e.harness.aws import MotoAws
        from e2e.harness.cloudtrail_stub import CloudTrailStub
        from e2e.harness.fake_cloud.app import FakeCloud
        from e2e.harness.fake_cloud.tls import TlsMaterial
        from e2e.harness.fake_providers import FakeProviders
        from e2e.harness.shims import ShimSet
        from e2e.harness.sshd import CommandLog, SshWorld

        ctx = self.ctx
        # moto's web server logs every request to stderr; the owner's output
        # is for its own start and stop messages.
        logging.getLogger("werkzeug").setLevel(logging.WARNING)
        material = TlsMaterial(ctx.ca_cert, ctx.server_cert, ctx.server_key)
        self.fake_cloud = self._start(FakeCloud(material, default_pypi_version=get_version()).start())
        if self.ssh_ca_off:
            self.fake_cloud.switch_off_ssh_ca()
        if self.ssh_ca_refuse:
            self.fake_cloud.vault.refuse_ca_activation(self.ssh_ca_refuse)
        if self.api_delay:
            self.fake_cloud.slow_down(self.api_delay)
        if self.account_email or self.verification_uri:
            self.fake_cloud.configure(email=self.account_email, verification_uri=self.verification_uri)
        if self.user_code:
            self.fake_cloud.configure(user_code=self.user_code)
        if self.ai_script is not None:
            from e2e.sandbox import ai_script

            ai_script.apply(self.fake_cloud, self.ai_script)
        if self.teams:
            self._join_team()
        self.moto = self._start(MotoAws().start())
        # CloudWatch filter patterns are evaluated as AWS documents them.
        self._monkeypatch = pytest.MonkeyPatch()
        aws_logs_filter.install(self._monkeypatch)
        self.cloudtrail = self._start(CloudTrailStub().start())
        self.providers = self._start(FakeProviders().start())
        self.shims = ShimSet(self.root / "shims")
        self.world = SshWorld(
            directory=self.root / "ssh" / "client",
            remote_dir=self.root / "ssh" / "remote",
            log=CommandLog(self.logs / "ssh-sessions.jsonl"),
            test_root=ctx.root,
            hidden=ctx.protected_dirs,
        )
        self._start(self.world.start())
        self.world.install_clients(self.shims.directory)
        if self.teams:
            self._start_team_server()
        # Host keys the user accepted with the real ssh are found again with
        # the real ssh-keygen (Use Vault Key and Auto-bind read them).
        from e2e.harness import keygen_lookup_shim

        keygen = shutil.which("ssh-keygen", path="/usr/bin:/bin:/usr/local/bin")
        if keygen:
            keygen_lookup_shim.install(str(self.shims.directory), keygen, str(ctx.root))

    def _seed_and_record(self) -> None:
        from e2e.harness import session_seed
        from e2e.harness.bootstrap import Sandbox
        from e2e.sandbox.scenarios import ScenarioSeeder

        self.user = Sandbox(self.root / _OWNER_DIR).create()
        seeded = ScenarioSeeder(
            home=self.user.home, moto=self.moto, cloudtrail=self.cloudtrail,
            providers=self.providers, world=self.world, api_url=self.fake_cloud.url,
        ).seed(self.scenario)
        if self.teams:
            seeded.notes.extend(self._seed_team_owner())
            if self.team_server_as:
                self._share_as_own(seeded.fleet)
        if self.signed_in:
            session_seed.seed_session(self.user.home, self.fake_cloud)
        self.child_env = self._child_env(self.user)
        if self.teams:
            seeded.notes.extend(self._seed_member())
        self._state = self._record(seeded)
        self._write_state()

    def _child_env(self, sandbox: Any) -> dict:
        """The complete environment of a child living in *sandbox* (a person's home)."""
        from e2e.harness import endpoints
        from e2e.harness.bootstrap import build_env

        env = build_env(
            sandbox,
            shim_dir=self.shims.directory,
            guard_log=self.logs / "guard.jsonl",
            armed_log=self.logs / "armed.jsonl",
            extra={
                **endpoints.fake_cloud_env(self.fake_cloud),
                **endpoints.moto_env(self.moto),
                **endpoints.cloudtrail_env(self.cloudtrail),
                **endpoints.providers_env(self.providers),
            },
        )
        if self.agent_tmp is not None:
            for name in ("TMPDIR", "TMP", "TEMP"):
                env[name] = str(self.agent_tmp)
            env["SERVONAUT_E2E_WRITE_ROOTS"] = os.pathsep.join(
                filter(None, [env.get("SERVONAUT_E2E_WRITE_ROOTS", ""), str(self.agent_tmp)])
            )
        if self.teams:
            # A throwaway Vault custody key: the children have no OS keyring.
            env[VAULT_DEVICE_KEY_ENV] = base64.b64encode(os.urandom(32)).decode("ascii")
        if self.hostname:
            # child_guard.ENV_HOSTNAME (that file is loaded by path, not imported).
            env["SERVONAUT_E2E_HOSTNAME"] = self.hostname
        return env

    def _record(self, seeded: Any) -> dict:
        """The contents of ``state.json`` (see the module docstring)."""
        from servonaut import get_version

        from e2e.harness.bootstrap import SRC_DIR
        from e2e.sandbox.scenarios import fleet_summary

        record = {
            "schema": state.SCHEMA,
            "scenario": self.scenario,
            "signed_in": self.signed_in,
            "ssh_ca_off": self.ssh_ca_off,
            "ssh_ca_refuse": self.ssh_ca_refuse,
            "api_delay": self.api_delay,
            "keep": self.keep,
            "started_at": self.claim_record["started_at"],
            "owner_pid": self.claim_record["owner_pid"],
            "owner_identity": self.claim_record["owner_identity"],
            "repo_root": str(bootstrap.REPO_ROOT),
            "src_dir": str(SRC_DIR),
            "python": sys.executable,
            "version": get_version(),
            "distribution": _distribution_dir(),
            "root": str(self.root),
            "pointer": str(self.pointer),
            "sandbox": {"base": str(self.user.base), "home": str(self.user.home)},
            "env": self.child_env,
            "urls": {
                "servonaut_api": self.fake_cloud.url,
                "package_index": self.fake_cloud.pypi_json_url,
                "aws": self.moto.url,
                "cloudtrail": self.cloudtrail.url,
                "hetzner": self.providers.hetzner_url,
                "ovh": self.providers.ovh_url,
                "ssh_target": f"127.0.0.1:{self.world.target.port}",
                "ssh_bastion": f"127.0.0.1:{self.world.bastion.port}",
            },
            "logs": {
                "servonaut": str(self.user.home / ".servonaut" / "logs" / "servonaut.log"),
                "fake_cloud_requests": str(self.logs / "fake-cloud-requests.jsonl"),
                "provider_requests": str(self.logs / "provider-requests.jsonl"),
                "cloudtrail_lookups": str(self.logs / "cloudtrail-lookups.jsonl"),
                "cloudwatch_refused_filters": str(self.logs / "cloudwatch-refused-filters.log"),
                "ssh_sessions": str(self.logs / "ssh-sessions.jsonl"),
                "fake_tools": str(self.shims.log_path),
                "guard": str(self.logs / "guard.jsonl"),
                "armed": str(self.logs / "armed.jsonl"),
                "children": str(self.logs),
            },
            "fleet": fleet_summary(seeded.fleet),
            "notes": seeded.notes,
            "teams": self._teams_record(),
            "personas": self._personas_record(),
            "desktop": None,
        }
        if self.ca_host is not None:
            record["urls"]["ssh_team_host"] = f"127.0.0.1:{self.ca_host.port}"
        return record

    # -- --teams -----------------------------------------------------------

    def _join_team(self) -> None:
        """The account is on the Teams plan and owns the team the fake's Vault and CA serve.

        Before any session is seeded: ``auth.json`` keeps the plan it was
        signed in with. The team keeps its members (invitations, roles), and
        the member to be has an account of their own, not yet in the team.
        """
        from e2e.harness.fake_cloud.routes_vault import MEMBER_USER_ID, TEAM_ID, TEAM_ROW, TEAM_SLUG

        self.fake_cloud.configure(plan=_TEAMS_PLAN)
        self.fake_cloud.account.configure(teams=[])
        self.fake_cloud.account.create_team(
            name=TEAM_ROW["name"], slug=TEAM_SLUG, team_id=TEAM_ID,
            owner_user_id=self.fake_cloud.entitlements()["user_id"],
        )
        self.fake_cloud.add_user(MEMBER_USER_ID, email=MEMBER_EMAIL, name=MEMBER_NAME, plan=_TEAMS_PLAN)

    def _start_team_server(self) -> None:
        """The team's shared server: a loopback host whose sshd honours SSH certificates."""
        from e2e.harness.ca_sshd import start_ca_host
        from e2e.harness.fake_cloud.routes_vault import SERVER_ID, TEAM_SLUG
        from e2e.harness.sshd import LOOPBACK

        ctx = self.ctx
        self.ca_host = self._start(start_ca_host(
            log=self.world.log, remote_dir=self.world.remote_dir,
            hidden=[*ctx.protected_dirs, str(ctx.root)],
        ))
        self.fake_cloud.account.place_shared_server(
            TEAM_SLUG, SERVER_ID, hostname=LOOPBACK, port=self.ca_host.port,
        )

    def _share_as_own(self, entries: list) -> None:
        """Record the team's shared server as the fleet's ``--team-server-as`` server.

        The team records the instance it shares, so the account lists that
        machine once, as its own server marked as shared. The instance id is
        the one the AWS fake gave the server when the fleet was seeded.
        """
        from e2e.harness.fake_cloud.routes_vault import SERVER_ID, TEAM_SLUG

        # The default account's server: in the multi-account scenario its name
        # is shown qualified (``<account>/edge-1``).
        name = self.team_server_as
        entry = next((e for e in entries if e.provider == "aws" and e.shown == name), None) or next(
            (e for e in entries if e.provider == "aws" and e.shown.endswith(f"/{name}")), None,
        )
        if entry is None:
            raise RuntimeError(f"--team-server-as: no AWS server {name!r} in the seeded fleet")
        self.fake_cloud.account.place_shared_server(TEAM_SLUG, SERVER_ID, instance_id=entry.instance_id)

    def _seed_team_owner(self) -> list[str]:
        """Give the home the owner's existing access to the shared server; return the notes.

        Nothing of the Vault or the CA is set up: that is what a person walks.
        """
        from e2e.harness.ca_sshd import ADMIN_USER, HOST_NAME, LOGIN, install_owner_credential
        from e2e.harness.fake_cloud.routes_vault import SERVER_ID, TEAM_SLUG

        self.admin_key = install_owner_credential(self.user.home, self.ca_host, SERVER_ID)
        key = f"~/{self.admin_key.relative_to(self.user.home)}"
        return [
            f"Teams: you own the team {TEAM_SLUG} (Teams plan). Its shared server {HOST_NAME} "
            f"listens on 127.0.0.1:{self.ca_host.port} with an sshd that honours the team's SSH "
            f"certificates for the login {LOGIN}; your existing key {key} logs in as "
            f"{ADMIN_USER} (passwordless sudo), and its host key is in ~/.servonaut/known_hosts.",
            f"Teams walk (nothing is set up yet): vault setup; vault create --team {TEAM_SLUG}; "
            f"ca enable --team {TEAM_SLUG}; ca enroll {HOST_NAME} --team {TEAM_SLUG} (type "
            f"127.0.0.1 to confirm); ssh {HOST_NAME}. The vault's custody key is in "
            f"{VAULT_DEVICE_KEY_ENV} (the sandbox has no OS keyring).",
        ]

    def _seed_member(self) -> list[str]:
        """The second person: a home of their own, signed out; return the notes."""
        from e2e.harness.bootstrap import Sandbox
        from e2e.harness.ca_sshd import HOST_NAME
        from e2e.harness.fake_cloud.routes_vault import TEAM_SLUG
        from e2e.harness.seed import HomeSeeder

        self.member = Sandbox(self.root / MEMBER).create()
        aws_keys = bool(self.team_server_as)
        # A teammate with no cloud accounts of their own: AWS stays off. With
        # --team-server-as they were given the account's AWS keys, but none of
        # its SSH key files.
        HomeSeeder(self.member.home, api_url=self.fake_cloud.url).config(
            aws=HomeSeeder.aws_config(enabled=aws_keys),
        )
        self.member_env = self._child_env(self.member)
        if not aws_keys:
            # Nor AWS credentials: the product lists AWS servers whenever it
            # finds credentials, and a new teammate's list starts empty.
            for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
                self.member_env.pop(name, None)
            self.member_env["AWS_SHARED_CREDENTIALS_FILE"] = str(self.member.home / ".aws" / "credentials")
            self.member_env["AWS_CONFIG_FILE"] = str(self.member.home / ".aws" / "config")
        run_member = "python -m e2e.sandbox run --as member --"
        notes = []
        if aws_keys:
            notes.append(
                f"Team server as own: {HOST_NAME} is also {self.team_server_as} of the AWS fleet. "
                f"The member lists the fleet with the account's AWS keys and has no SSH key "
                f"files: `{run_member} ssh {self.team_server_as}` connects with the team's key "
                f"once the owner has enrolled {HOST_NAME}. The owner's own ~/.ssh/ops-key.pem "
                f"opens it too; remove it to see the owner fall back the same way."
            )
        return notes + [
            f"Team member: {MEMBER_EMAIL} has a home of their own ({self.member.home}), is signed "
            f"out and is not in {TEAM_SLUG} yet. Run their commands with `{run_member} <args>`.",
            f"Member walk: invite {MEMBER_EMAIL} on the Teams screen; accept the invitation with "
            f"`python -m e2e.sandbox accept-invite {MEMBER_EMAIL}` (their browser step); "
            f"`{run_member} login` (approved as the member); `{run_member} vault setup`; the owner "
            f"runs `vault grants process`; then `{run_member} vault list` and `{run_member} ssh "
            f"{HOST_NAME}` (once the owner has enrolled it in the team's SSH CA).",
        ]

    def _personas_record(self) -> dict:
        """The ``personas`` entry of ``state.json``: the people beside the owner."""
        if self.member is None:
            return {}
        from e2e.harness.fake_cloud.routes_vault import MEMBER_USER_ID

        return {
            MEMBER: {
                "email": MEMBER_EMAIL,
                "user_id": MEMBER_USER_ID,
                "sandbox": {"base": str(self.member.base), "home": str(self.member.home)},
                "env": self.member_env,
            },
        }

    def _teams_record(self) -> Optional[dict]:
        """The ``teams`` entry of ``state.json`` (None without ``--teams``)."""
        if self.ca_host is None:
            return None
        from e2e.harness.ca_sshd import ADMIN_USER, HOST_NAME, LOGIN
        from e2e.harness.fake_cloud.routes_vault import SERVER_ID, TEAM_ROW

        return {
            "plan": _TEAMS_PLAN,
            "team": TEAM_ROW["slug"],
            "role": TEAM_ROW["role"],
            "shared_server": {
                "name": HOST_NAME,
                "id": SERVER_ID,
                "same_as": self.team_server_as,
                "address": f"127.0.0.1:{self.ca_host.port}",
                "login": LOGIN,
                "admin_login": ADMIN_USER,
                "admin_key": str(self.admin_key),
            },
            "member": {"email": MEMBER_EMAIL, "home": str(self.member.home) if self.member else None},
        }

    def _write_state(self) -> None:
        with self._state_lock:
            state.write_json(self.state_path, self._state)

    # -- serve ---------------------------------------------------------------

    def serve(self) -> None:
        """Answer desktop requests and write the request logs until asked to stop."""
        self.stop_request.interrupts = False
        self._desktop_worker = threading.Thread(
            target=self._answer_desktop_requests, name="qa-desktop", daemon=True
        )
        self._desktop_worker.start()
        while not self.stop_request.event.wait(_POLL_SECONDS):
            self._queue_desktop_requests()
            self._answer_team_requests()
            self._flush_logs()

    # -- the member's requests ---------------------------------------------------

    def _answer_team_requests(self) -> None:
        """Act for the member as their browser would, one request file at a time."""
        for path in sorted(self.control.iterdir()):
            match = _TEAM_REQUEST_FILE.match(path.name)
            if match is None:
                continue
            try:
                answer = self._team_action(state.read_json(path) or {})
            except (KeyError, ValueError) as exc:
                answer = {"error": str(exc.args[0]) if exc.args else type(exc).__name__}
            state.write_json(self.control / f"team-{match.group(1)}.answer.json", answer)
            path.unlink(missing_ok=True)

    def _team_action(self, request: dict) -> dict:
        """``accept-invite`` (their browser's accept), ``sign-in`` (their browser
        approves the next device code) and ``sign-in-done`` (drop an unused one)."""
        from e2e.harness.fake_cloud.routes_vault import MEMBER_USER_ID

        persona, action = request.get("persona"), request.get("action")
        if self.member is None or persona != MEMBER:
            raise ValueError(f"this sandbox has no person called {persona!r} (start it with --teams)")
        if action == "accept-invite":
            accepted = self.fake_cloud.accept_invitation(str(request.get("email", "")), user_id=MEMBER_USER_ID)
            return {"persona": persona, "team": accepted["team"], "role": accepted["role"],
                    "email": accepted["invitation_email"]}
        if action == "sign-in":
            self.fake_cloud.sign_in_next_as(MEMBER_USER_ID)
            return {"persona": persona}
        if action == "sign-in-done":
            self.fake_cloud.cancel_sign_in(MEMBER_USER_ID)
            return {"persona": persona}
        raise ValueError(f"unknown request {action!r}")

    def _flush_logs(self) -> None:
        from e2e.harness import aws_logs_filter

        sources: dict[str, Callable[[], list]] = {}
        for name, server, read in (
            ("fake-cloud-requests.jsonl", self.fake_cloud, "requests"),
            ("provider-requests.jsonl", self.providers, "requests"),
            ("cloudtrail-lookups.jsonl", self.cloudtrail, "lookups"),
        ):
            if server is not None:
                sources[name] = getattr(server, read)
        for name, read in sources.items():
            entries = read()
            if self._flushed.get(name) != len(entries):
                _write_jsonl(self.logs / name, entries)
                self._flushed[name] = len(entries)
        refused = aws_logs_filter.take_refused()
        if refused:
            with (self.logs / "cloudwatch-refused-filters.log").open("a", encoding="utf-8") as out:
                out.write("".join(f"{line}\n" for line in refused))

    # -- desktop ---------------------------------------------------------------

    def _queue_desktop_requests(self) -> None:
        for path in sorted(self.control.iterdir()):
            match = _REQUEST_FILE.match(path.name)
            if match and match.group(1) not in self._seen_requests:
                self._seen_requests.add(match.group(1))
                self._requests.put(match.group(1))

    def _answer_desktop_requests(self) -> None:
        """One request at a time, in the order they arrived."""
        while True:
            request_id = self._requests.get()
            if request_id is None or self._closing:
                return
            request_file = self.control / f"desktop-{request_id}.request.json"
            request = state.read_json(request_file) or {}
            try:
                info = self._desktop(fresh=bool(request.get("new")))
            except Exception as exc:  # noqa: BLE001 - reported to the requester
                info = {"error": f"{type(exc).__name__}: {exc}"}
            state.write_json(self.control / f"desktop-{request_id}.answer.json", info)
            request_file.unlink(missing_ok=True)
            if "error" not in info:
                with self._state_lock:
                    self._state["desktop"] = {k: v for k, v in info.items() if k != "reused"}
                self._write_state()

    def _desktop(self, *, fresh: bool) -> dict:
        current = self._state.get("desktop") or {}
        keeper = self._keeper
        if (not fresh and keeper is not None and keeper.poll() is None
                and state.process_alive(current.get("pid"), current.get("identity"))):
            return {**current, "reused": True}
        self._stop_keeper()
        return self._start_desktop()

    def _start_desktop(self) -> dict:
        from e2e.harness.desktop import CHILD_STARTUP_TIMEOUT, WINDOW_STAND_IN
        from e2e.harness.processes import require_armed

        self._desktop_count += 1
        stderr_path = self.logs / f"desktop-{self._desktop_count}.stderr.log"
        with stderr_path.open("wb") as stderr:
            # Stands in for the desktop window: starts the real desktop child
            # through the product's launcher and holds its control pipe.
            keeper = subprocess.Popen(
                [sys.executable, str(WINDOW_STAND_IN), str(CHILD_STARTUP_TIMEOUT)],
                env=self.child_env,
                cwd=self.user.base,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=stderr,
                # The owner alone decides when it stops, not the terminal.
                start_new_session=True,
            )
        self._keeper = keeper
        try:
            if self._closing:  # the stop began while this one started
                raise RuntimeError("the sandbox is stopping")
            assert keeper.stdout is not None
            ready, _, _ = select.select([keeper.stdout], [], [], CHILD_STARTUP_TIMEOUT + 10)
            line = keeper.stdout.readline() if ready else b""
            if not line:
                raise RuntimeError(f"the desktop child did not start; see {stderr_path}")
            started = json.loads(line)
            require_armed(self.logs / "armed.jsonl", pid=keeper.pid)
            require_armed(self.logs / "armed.jsonl", pid=started["pid"])
        except BaseException:
            self._stop_keeper()
            raise
        return {
            "origin": started["origin"],
            "token": started["token"],
            "pid": started["pid"],
            "identity": state.process_identity(started["pid"]),
            "keeper_pid": keeper.pid,
            "keeper_identity": state.process_identity(keeper.pid),
            "started_at": _now(),
            "stderr": str(stderr_path),
            "reused": False,
        }

    def _stop_keeper(self) -> None:
        keeper, self._keeper = self._keeper, None
        if keeper is None:
            return
        # Closing the control pipe is how the window tells the child to go.
        for stream in (keeper.stdin, keeper.stdout):
            if stream is not None:
                stream.close()
        try:
            keeper.wait(_STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            keeper.kill()
            keeper.wait()

    # -- stop ------------------------------------------------------------------

    def stop(self) -> None:
        """Stop every process and server, release the pointer, remove the root.

        Each step runs whatever happened before it; one that fails is
        reported and the rest still run. The marker goes last, while the
        lock is still held: until then the owner counts as alive.
        """
        self.stop_request.interrupts = False
        self._closing = True
        steps: list[tuple[str, Callable[[], Any]]] = [
            ("mark the sandbox as stopping", lambda: self._set_phase(state.STOPPING)),
            # The keeper first: a desktop start in progress waits on it.
            ("stop the desktop child", self._stop_keeper),
            ("stop answering desktop requests", self._end_desktop_worker),
            *((f"stop {type(s).__name__}", s.stop) for s in reversed(self._started)),
            ("restore the CloudWatch filter emulation", self._undo_patches),
            ("write the request logs", self._flush_kept_logs),
            ("stop the sandbox's remaining processes", self._stop_remaining),
            ("empty the sandbox directory", self._empty_root),
            # Nothing of the sandbox runs any more; what is left lies
            # outside the root: the pointer, and a kept root's new name.
            ("lift this process's guard", bootstrap.load_guard().disarm_filesystem_and_spawns),
            ("remove the short temp directory", self._remove_agent_tmp),
            ("release the pointer", lambda: release(self.pointer, self.claim_record)),
            ("put the kept sandbox directory aside", self._set_kept_root_aside),
            ("remove the sandbox directory", self._remove_root),
        ]
        for description, step in steps:
            try:
                step()
            except Exception as exc:  # noqa: BLE001 - stopping must finish
                _say(f"could not {description}: {type(exc).__name__}: {exc}")
        self.lock.release()

    def _remove_agent_tmp(self) -> None:
        """Remove the children's short temp directory (kept roots keep only the root)."""
        if self.agent_tmp is not None:
            shutil.rmtree(self.agent_tmp, ignore_errors=True)

    def _flush_kept_logs(self) -> None:
        if self.keep and self.logs.is_dir():
            self._flush_logs()

    def _end_desktop_worker(self) -> None:
        self._requests.put(None)
        worker = self._desktop_worker
        if worker is not None:
            worker.join(_STOP_TIMEOUT_SECONDS)

    def _undo_patches(self) -> None:
        if self._monkeypatch is not None:
            self._monkeypatch.undo()

    def _stop_remaining(self) -> None:
        from e2e.harness.processes import stop_sandbox_pid

        for pid in state.sandbox_pids(self.root):
            _say(stop_sandbox_pid(pid, sandbox_root=self.root))

    def _empty_root(self) -> None:
        """Remove everything but the marker (this process created the root and holds its lock)."""
        if self.keep:
            return
        for entry in self.root.iterdir():
            if entry.name == state.MARKER:
                continue
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry, ignore_errors=True)
            else:
                entry.unlink(missing_ok=True)

    def _set_kept_root_aside(self) -> None:
        """Rename a kept root, so the next sandbox here starts fresh and leaves it alone."""
        if not self.keep:
            return
        kept = self.root.with_name(
            f"{self.root.name}.kept-{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}"
        )
        self.root.rename(kept)
        _say(f"kept the sandbox directory as {kept}; delete it yourself when done")

    def _remove_root(self) -> None:
        if self.keep:
            return
        left = [entry.name for entry in self.root.iterdir() if entry.name != state.MARKER]
        if left:
            # The marker stays: the next `up` or `down` here can still tell
            # the directory is a finished sandbox and remove it.
            raise RuntimeError(f"{self.root} still holds {', '.join(sorted(left))}")
        self.lock.remove()
        self.root.rmdir()


def _distribution_dir() -> Optional[str]:
    """The ``.dist-info`` directory the sandbox's children read Servonaut's
    version and install details from, if the interpreter has one."""
    try:
        distribution = importlib.metadata.distribution("servonaut")
    except importlib.metadata.PackageNotFoundError:
        return None
    for path in distribution.files or ():
        if path.name == "METADATA":
            return str(Path(distribution.locate_file(path)).parent)
    return None


def _write_jsonl(path: Path, entries: list) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text("".join(json.dumps(entry, default=str) + "\n" for entry in entries),
                   encoding="utf-8")
    tmp.replace(path)


def root_problem(root: Path, repo_root: Path) -> Optional[str]:
    """Why *root* is no place for a sandbox, or None.

    Inside the checkout, git ignores only top-level ``.qa-sandbox*``
    directories, and a sandbox holds private keys and tokens.
    """
    if root != repo_root and repo_root not in root.parents:
        return None
    if root.parent == repo_root and root.name.startswith(state.DEFAULT_ROOT_NAME):
        return None
    return (
        f"{root} is inside the checkout, where git ignores only "
        f"{repo_root / state.DEFAULT_ROOT_NAME}* (a sandbox holds private keys and tokens); "
        f"choose a --root outside the checkout, or {repo_root / state.DEFAULT_ROOT_NAME}-<name>"
    )


def up(
    *, root: Optional[Path], scenario: str, signed_in: bool, keep: bool,
    ssh_ca_off: bool = False, ssh_ca_refuse: Optional[str] = None, api_delay: float = 0.0, teams: bool = False,
    account_email: str = "", verification_uri: Optional[str] = None, hostname: Optional[str] = None,
    ai_script: Optional[Path] = None, user_code: Optional[str] = None,
    team_server_as: Optional[str] = None,
) -> int:
    stop_request = StopRequest()
    missing = bootstrap.missing_modules(_EXTRA_MODULES)
    if missing:
        _say(
            f"not starting: the sandbox needs the e2e and provider extras "
            f"({', '.join(missing)} not installed): {bootstrap.INSTALL_HINT}"
        )
        return 2
    repo_root = bootstrap.REPO_ROOT
    # Resolved: children carry this exact path, and `down` finds them by it.
    root = (root or state.default_root(repo_root)).resolve()
    problem = (
        root_problem(root, repo_root) or (teams_root_problem(root) if teams else None)
        or team_server_as_problem(team_server_as, teams)
    )
    if problem:
        _say(f"not starting: {problem}")
        return 2
    script = None
    if ai_script is not None:
        from e2e.sandbox import ai_script as ai_script_module

        try:
            script = ai_script_module.load(ai_script)
        except ai_script_module.ScriptError as exc:
            _say(f"not starting: {exc}")
            return 2
    pointer = state.pointer_path()
    owner: Optional[Owner] = None
    try:
        # A signal during the claim takes effect once the owner exists.
        with stop_request.deferred():
            try:
                record, lock = claim(pointer, root, repo_root, scenario,
                                     cancelled=stop_request.event.is_set)
            except Refused as exc:
                _say(f"not starting: {exc}")
                return 2
            owner = Owner(root, scenario, pointer, record, lock, stop_request,
                          signed_in=signed_in, keep=keep, ssh_ca_off=ssh_ca_off,
                          ssh_ca_refuse=ssh_ca_refuse, api_delay=api_delay, teams=teams, account_email=account_email,
                          verification_uri=verification_uri, user_code=user_code,
                          hostname=hostname, ai_script=script, team_server_as=team_server_as)
        stop_request.raise_if_requested()
        _say(f"starting the {scenario} sandbox in {root}")
        started = time.monotonic()
        owner.start()
        _say(f"ready after {time.monotonic() - started:.1f}s")
        print(f"{READY_PREFIX} {owner.state_path}", flush=True)
        owner.serve()
    except KeyboardInterrupt:
        _say("interrupted")
    finally:
        if owner is not None:
            _say("stopping")
            owner.stop()
    return 0
