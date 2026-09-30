"""``python -m e2e.sandbox up``: start the fakes, seed a home, wait for ``down``.

The owner is one foreground process. It claims the per-user pointer,
bootstraps a hermetic environment rooted at a fixed directory (by default
``<checkout>/.qa-sandbox``), starts the same fakes the end-to-end suite
uses, seeds one home for the scenario and records everything a driver needs
in ``<root>/state.json``:

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
    the desktop child started on request (``python -m e2e.sandbox desktop``).

Then it prints ``SANDBOX READY <state.json>`` and serves until SIGINT or
SIGTERM, when it stops everything, removes the root and releases the
pointer. Every child it starts also stops by itself once the owner or the
root is gone (``child_guard.py``).
"""

from __future__ import annotations

import fcntl
import importlib.metadata
import json
import logging
import os
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
from typing import Any, Iterator, Optional

from e2e.harness import bootstrap
from e2e.sandbox import state

READY_PREFIX = "SANDBOX READY"
# How often the owner writes the fakes' request logs to disk.
_FLUSH_SECONDS = 1.0
_STOP_TIMEOUT_SECONDS = 15.0


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


def _describe_owner(record: dict) -> str:
    return (
        f"owner pid {record.get('owner_pid')}, started from {record.get('repo_root')}, "
        f"state {record.get('state')}"
    )


def _clear_stale_root(root: Path) -> None:
    if not root.exists():
        return
    marker = state.read_json(root / state.MARKER)
    if marker is None:
        raise Refused(
            f"{root} exists and is not a QA sandbox root; remove it or choose another --root"
        )
    if state.owner_alive(marker):
        raise Refused(
            f"the QA sandbox at {root} is still running (owner pid {marker.get('owner_pid')}); "
            "stop it with `python -m e2e.sandbox down`"
        )
    _say(f"removing the stale sandbox root {root}")
    shutil.rmtree(root)


def claim(pointer: Path, root: Path, repo_root: Path, scenario: str) -> dict:
    """Make this process the owner of the per-user pointer and of *root*."""
    with _pointer_lock(pointer):
        current = state.read_json(pointer)
        if current is not None and state.owner_alive(current):
            raise Refused(
                "a QA sandbox is already running for this user "
                f"({_describe_owner(current)}); stop it with `python -m e2e.sandbox down` "
                "from any checkout, or use that one"
            )
        _clear_stale_root(root)
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
        state.write_json(pointer, record)
    return record


def release(pointer: Path, record: dict) -> None:
    """Remove the pointer if it still names this sandbox."""
    with _pointer_lock(pointer):
        current = state.read_json(pointer)
        if current is not None and current.get("state") == record["state"] and (
            current.get("owner_pid") == record["owner_pid"]
        ):
            pointer.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# The running sandbox
# ---------------------------------------------------------------------------


class Owner:
    """Everything one ``up`` started, and how to stop it."""

    def __init__(self, root: Path, scenario: str, pointer: Path, claim_record: dict, *,
                 signed_in: bool, keep: bool) -> None:
        self.root = root
        self.scenario = scenario
        self.pointer = pointer
        self.claim_record = claim_record
        self.signed_in = signed_in
        self.keep = keep
        self.logs = root / "logs"
        self.state_path = root / state.STATE_FILE
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._desktop_wanted = False
        self._state_lock = threading.Lock()
        self._state: dict = {}
        self._started: list[Any] = []  # things with .stop(), in start order
        self._keeper: Optional[subprocess.Popen] = None
        self._desktop_count = 0
        self._flushed: dict[str, int] = {}
        self._monkeypatch: Any = None
        self.ctx: Any = None

    # -- start -------------------------------------------------------------

    def start(self) -> None:
        self.ctx = bootstrap.bootstrap(self.root)
        state.write_json(self.root / state.MARKER, {
            "owner_pid": self.claim_record["owner_pid"],
            "owner_identity": self.claim_record["owner_identity"],
        })
        self.logs.mkdir()
        self._arm_owner_guard()
        self._start_fakes()
        self._seed_and_record()

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
        """Wait for a stop signal; start the desktop child when asked."""
        def stop(signum: int, _frame: Any) -> None:
            self._stop.set()
            self._wake.set()

        def desktop(signum: int, _frame: Any) -> None:
            self._desktop_wanted = True
            self._wake.set()

        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, stop)
        signal.signal(signal.SIGUSR1, desktop)
        while not self._stop.is_set():
            self._wake.wait(_FLUSH_SECONDS)
            self._wake.clear()
            if self._desktop_wanted and not self._stop.is_set():
                self._desktop_wanted = False
                threading.Thread(target=self._desktop_request, name="qa-desktop", daemon=True).start()
            self._flush_logs()

    def _flush_logs(self) -> None:
        from e2e.harness import aws_logs_filter

        sources = {
            "fake-cloud-requests.jsonl": self.fake_cloud.requests,
            "provider-requests.jsonl": self.providers.requests,
            "cloudtrail-lookups.jsonl": self.cloudtrail.lookups,
        }
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

    def _desktop_request(self) -> None:
        request = state.read_json(self.root / state.DESKTOP_REQUEST) or {}
        try:
            info = self._desktop(fresh=bool(request.get("new")))
        except Exception as exc:  # noqa: BLE001 - reported to the requester
            info = {"error": f"{type(exc).__name__}: {exc}"}
        info["request"] = request.get("id")
        with self._state_lock:
            self._state["desktop"] = info
        self._write_state()

    def _desktop(self, *, fresh: bool) -> dict:
        from e2e.harness.desktop import CHILD_STARTUP_TIMEOUT, WINDOW_STAND_IN
        from e2e.harness.processes import require_armed

        current = self._state.get("desktop") or {}
        if (not fresh and self._keeper is not None and self._keeper.poll() is None
                and current.get("pid") and _running(current["pid"])):
            return {**current, "reused": True}
        self._stop_keeper()
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
        assert keeper.stdout is not None
        ready, _, _ = select.select([keeper.stdout], [], [], CHILD_STARTUP_TIMEOUT + 10)
        line = keeper.stdout.readline() if ready else b""
        if not line:
            self._stop_keeper()
            raise RuntimeError(f"the desktop child did not start; see {stderr_path}")
        started = json.loads(line)
        require_armed(self.logs / "armed.jsonl", pid=keeper.pid)
        require_armed(self.logs / "armed.jsonl", pid=started["pid"])
        return {
            "origin": started["origin"],
            "token": started["token"],
            "pid": started["pid"],
            "keeper_pid": keeper.pid,
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
        """Stop every process and server, then remove the root and the pointer."""
        from e2e.harness.processes import stop_sandbox_pid

        try:
            self._stop_keeper()
        finally:
            for server in reversed(self._started):
                try:
                    server.stop()
                except Exception as exc:  # noqa: BLE001 - stopping must finish
                    _say(f"could not stop {type(server).__name__}: {exc}")
            if self._monkeypatch is not None:
                self._monkeypatch.undo()
            if self.keep and self.logs.exists():
                self._flush_logs()
            for pid in state.sandbox_pids(self.root):
                _say(stop_sandbox_pid(pid, sandbox_root=self.root))
            if not self.keep and self._owns_root():
                shutil.rmtree(self.root, ignore_errors=True)
            # Nothing of the sandbox runs any more; the pointer, outside the
            # root, is the last thing to clean up.
            bootstrap.load_guard().disarm_filesystem_and_spawns()
            release(self.pointer, self.claim_record)

    def _owns_root(self) -> bool:
        """True when the root carries this process's marker (never remove another's)."""
        marker = state.read_json(self.root / state.MARKER)
        return marker is not None and marker.get("owner_pid") == self.claim_record["owner_pid"]


def _running(pid: int) -> bool:
    """True while *pid* exists and has not exited (a zombie has)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    identity = state.process_identity(pid)
    return identity is None or identity[0] not in ("Z", "X")


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


def _interrupt(signum: int, _frame: Any) -> None:
    raise KeyboardInterrupt(f"signal {signum}")


def up(*, root: Optional[Path], scenario: str, signed_in: bool, keep: bool) -> int:
    # Until the sandbox serves, a stop request interrupts the start-up, which
    # then cleans up after itself like a normal stop.
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, _interrupt)
    repo_root = bootstrap.REPO_ROOT
    # Resolved: children carry this exact path, and `down` finds them by it.
    root = (root or state.default_root(repo_root)).resolve()
    pointer = state.pointer_path()
    try:
        record = claim(pointer, root, repo_root, scenario)
    except Refused as exc:
        _say(f"not starting: {exc}")
        return 2
    owner = Owner(root, scenario, pointer, record, signed_in=signed_in, keep=keep)
    try:
        _say(f"starting the {scenario} sandbox in {root}")
        started = time.monotonic()
        owner.start()
        _say(f"ready after {time.monotonic() - started:.1f}s")
        print(f"{READY_PREFIX} {owner.state_path}", flush=True)
        owner.serve()
    finally:
        _say("stopping")
        owner.stop()
    return 0
