"""Pytest fixtures for journeys against the loopback SSH servers.

Registered from ``e2e/conftest.py``. A journey that asks for the ``sshd``
fixture gets a started :class:`~e2e.harness.sshd.SshWorld` whose target and
bastion live in the journey's own folder, with the journey's ``ssh`` and
``scp`` replaced by the guarded pass-through to the real OpenSSH clients,
for the test process and for every child the journey starts.

Such journeys must carry the ``needs_sshd`` marker (collection fails
otherwise), so ``-m "not needs_sshd"`` reliably deselects them on a machine
without the OpenSSH client.
"""

from __future__ import annotations

import importlib.util
from typing import Any

import pytest

from e2e.harness import artifacts, remote_root
from e2e.harness.bootstrap import load_guard

MARKER = "needs_sshd"
FIXTURE = "sshd"


def pytest_configure(config: pytest.Config) -> None:
    if importlib.util.find_spec("asyncssh") is None:
        raise pytest.UsageError(
            "the end-to-end suite needs the e2e extra (asyncssh not installed): "
            "pip install -e '.[e2e]'"
        )
    _import_asyncssh()


def _import_asyncssh() -> None:
    """Import asyncssh before any journey starts.

    Its import looks for optional native libraries with ``ldconfig``; the
    sandbox refuses that probe and asyncssh falls back to its own code.
    Importing here keeps the refusal with the rest of start-up (which the
    first journey clears) instead of charging it to whichever journey
    happens to import asyncssh first. Anything else fails the run.
    """
    guard = load_guard()
    seen = len(guard.violations())
    import asyncssh  # noqa: F401

    unexpected = [
        v for v in guard.violations()[seen:]
        if not (v["kind"] == "spawn" and v["target"].endswith("/ldconfig"))
    ]
    if unexpected:
        raise pytest.UsageError(f"importing asyncssh tried to leave the e2e sandbox: {unexpected}")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    unmarked = [
        item.nodeid for item in items
        if FIXTURE in getattr(item, "fixturenames", ()) and item.get_closest_marker(MARKER) is None
    ]
    if unmarked:
        raise pytest.UsageError(
            f"journeys using the {FIXTURE} fixture need the {MARKER} marker; missing on: "
            + ", ".join(unmarked)
        )


@pytest.fixture
def sshd(journey: Any, request: pytest.FixtureRequest) -> Any:
    """A target (``web-1``) and a bastion on loopback, reached with real OpenSSH."""
    from e2e.harness.sshd import CommandLog, OpenSshMissing, SshWorld

    try:
        world = SshWorld(
            directory=journey.directory / "ssh-client",
            remote_dir=journey.directory / "remote",
            log=CommandLog(journey.staging / "sshd-commands.jsonl"),
            test_root=journey.ctx.root,
            hidden=journey.ctx.protected_dirs,
        )
    except OpenSshMissing as exc:
        pytest.fail(str(exc), pytrace=False)
    world.start()
    try:
        world.install_clients(journey.shims.directory)
    except BaseException:
        world.stop()
        raise
    yield world
    world.stop()
    if artifacts.journey_failed(request.node):
        listing = remote_root.describe({h.name: h.remote for h in (world.target, world.bastion)})
        (journey.staging / "remote-files.txt").write_text(
            f"remote commands confined by: {world.confinement} "
            f"({world.target.launcher.detail})\n{listing}",
            encoding="utf-8",
        )
