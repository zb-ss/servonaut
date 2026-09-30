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
``desktop``
    the desktop child last started on request (``python -m e2e.sandbox desktop``).

Then it prints ``SANDBOX READY <state.json>`` and serves: it writes the
fakes' request logs to disk and answers desktop requests, which arrive as
files in ``<root>/control`` (no signal is ever needed to reach it). SIGINT,
SIGTERM or SIGHUP stop it, also during start-up: it stops everything,
removes the root (unless ``--keep``) and releases the pointer. Every child it
starts also stops by itself once the owner or the root is gone
(``child_guard.py``).
"""

from __future__ import annotations

import fcntl
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


@contextmanager
def _pointer_lock(pointer: Path) -> Iterator[None]:
    """Serialise claims on the pointer (the lock is its directory: no extra file)."""
    pointer.parent.mkdir(parents=True, exist_ok=True)
    directory = os.open(pointer.parent, os.O_RDONLY)
    try:
        fcntl.flock(directory, fcntl.LOCK_EX)
        yield
    finally:
        os.close(directory)


def _refuse_if_running(current: dict) -> None:
    """Refuse while the sandbox the pointer names is still running."""
    if current.get("schema") != state.SCHEMA:
        if state.legacy_owner_alive(current):
            raise Refused(state.legacy_message(current))
        return
    if state.owner_alive(current.get("root", "")):
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
    if state.owner_alive(root):
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
    if found.get("schema") != state.SCHEMA and state.legacy_owner_alive(found):
        raise Refused(state.legacy_message(found))
    _say(f"removing {root}, left behind by a sandbox that stopped")
    shutil.rmtree(root)


def claim(pointer: Path, root: Path, repo_root: Path,
          scenario: str) -> tuple[dict, state.OwnerLock]:
    """Make this process the owner of the per-user pointer and of *root*."""
    with _pointer_lock(pointer):
        current = state.read_json(pointer)
        if current is not None:
            _refuse_if_running(current)
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
        if not lock.acquire({**record, "phase": state.STARTING}):
            raise Refused(f"another process is starting a QA sandbox in {root}")
        state.write_json(pointer, record)
    return record, lock


def release(pointer: Path, record: dict) -> None:
    """Remove the pointer if it still names this sandbox."""
    with _pointer_lock(pointer):
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
                 signed_in: bool, keep: bool) -> None:
        self.root = root
        self.scenario = scenario
        self.pointer = pointer
        self.claim_record = claim_record
        self.lock = lock
        self.stop_request = stop_request
        self.signed_in = signed_in
        self.keep = keep
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
        self._state_lock = threading.Lock()
        self._state: dict = {}
        self._started: list[Any] = []  # things with .stop(), in start order
        self._monkeypatch: Any = None
        self._keeper: Optional[subprocess.Popen] = None
        self._desktop_count = 0
        self._requests: "queue.Queue[Optional[str]]" = queue.Queue()
        self._seen_requests: set[str] = set()
        self._desktop_worker: Optional[threading.Thread] = None
        self._flushed: dict[str, int] = {}

    def _set_phase(self, phase: str) -> None:
        self.lock.write({**self.claim_record, "phase": phase})

    # -- start -------------------------------------------------------------

    def start(self) -> None:
        with self.stop_request.deferred():
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

    def _seed_and_record(self) -> None:
        from e2e.harness import endpoints, session_seed
        from e2e.harness.bootstrap import Sandbox, build_env
        from e2e.sandbox.scenarios import ScenarioSeeder

        self.user = Sandbox(self.root / "user").create()
        seeded = ScenarioSeeder(
            home=self.user.home, moto=self.moto, cloudtrail=self.cloudtrail,
            providers=self.providers, world=self.world, api_url=self.fake_cloud.url,
        ).seed(self.scenario)
        if self.signed_in:
            session_seed.seed_session(self.user.home, self.fake_cloud)
        self.child_env = build_env(
            self.user,
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
        self._state = self._record(seeded)
        self._write_state()

    def _record(self, seeded: Any) -> dict:
        """The contents of ``state.json`` (see the module docstring)."""
        from servonaut import get_version

        from e2e.harness.bootstrap import SRC_DIR
        from e2e.sandbox.scenarios import fleet_summary

        return {
            "schema": state.SCHEMA,
            "scenario": self.scenario,
            "signed_in": self.signed_in,
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
            "desktop": None,
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
            self._flush_logs()

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
            if request_id is None:
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
        """Stop every process and server, then remove the root and the pointer.

        Each step runs whatever happened before it; one that fails is
        reported and the rest still run.
        """
        self.stop_request.interrupts = False
        steps: list[tuple[str, Callable[[], Any]]] = [
            ("mark the sandbox as stopping", lambda: self._set_phase(state.STOPPING)),
            ("stop answering desktop requests", self._end_desktop_worker),
            ("stop the desktop child", self._stop_keeper),
            *((f"stop {type(s).__name__}", s.stop) for s in reversed(self._started)),
            ("restore the CloudWatch filter emulation", self._undo_patches),
            ("write the request logs", self._flush_kept_logs),
            ("stop the sandbox's remaining processes", self._stop_remaining),
            ("remove the sandbox directory", self._remove_root),
            ("release the pointer", self._release_pointer),
        ]
        for description, step in steps:
            try:
                step()
            except Exception as exc:  # noqa: BLE001 - stopping must finish
                _say(f"could not {description}: {type(exc).__name__}: {exc}")
        self.lock.release()

    def _flush_kept_logs(self) -> None:
        if self.keep and self.logs.is_dir():
            self._flush_logs()

    def _end_desktop_worker(self) -> None:
        self._requests.put(None)

    def _undo_patches(self) -> None:
        if self._monkeypatch is not None:
            self._monkeypatch.undo()

    def _stop_remaining(self) -> None:
        from e2e.harness.processes import stop_sandbox_pid

        for pid in state.sandbox_pids(self.root):
            _say(stop_sandbox_pid(pid, sandbox_root=self.root))

    def _remove_root(self) -> None:
        # This process created the root and holds its lock: it is ours.
        if not self.keep:
            shutil.rmtree(self.root, ignore_errors=True)

    def _release_pointer(self) -> None:
        # Nothing of the sandbox runs any more; the pointer, outside the
        # root, is the last thing to clean up.
        bootstrap.load_guard().disarm_filesystem_and_spawns()
        release(self.pointer, self.claim_record)


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


def up(*, root: Optional[Path], scenario: str, signed_in: bool, keep: bool) -> int:
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
    pointer = state.pointer_path()
    with stop_request.deferred():
        try:
            record, lock = claim(pointer, root, repo_root, scenario)
        except Refused as exc:
            _say(f"not starting: {exc}")
            return 2
        owner = Owner(root, scenario, pointer, record, lock, stop_request,
                      signed_in=signed_in, keep=keep)
    try:
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
        _say("stopping")
        owner.stop()
    return 0
