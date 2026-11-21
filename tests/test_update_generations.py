"""Test generation selection, leases, and background update decisions."""

import asyncio
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from servonaut import entry
from servonaut.mcp.reconnect import (
    MCPDisplayText, PIPX_GENERATION_CURRENT, PipxReconnectHint, ReconnectBuild, _MAX_STATE_BYTES,
)
from servonaut.updates import builder, index, state
from servonaut.updates.generations import directory_for, evacuate_unused, select_generation
from servonaut.updates.layout import python_for
from servonaut.updates.processes import UnknownProcess, birth
from servonaut.updates.profile import Profile, load_profile
from servonaut.updates.state import InstallState, Preferences
from servonaut.updates.status import MARKER_NAME, PIPX_METADATA, mark_update_presented, read_update_status
from servonaut.utils.package_version import PackageVersion


OLD, CURRENT, READY, UNUSED = ("1" * 32, "2" * 32, "3" * 32, "4" * 32)


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))
    mock = InstallState(tmp_path / "pipx" / "servonaut")
    mock.directory.mkdir(parents=True)
    return mock


def _healthy(store, record, identifier, version, when=None):
    root = directory_for(store, identifier)
    python = python_for(root)
    python.parent.mkdir(parents=True)
    python.touch()
    python.chmod(0o700)
    (root / MARKER_NAME).write_text(json.dumps({"anchor": str(store.root), "generation": identifier}))
    record.setdefault("generations", {})[identifier] = {
        "version": version, "health": "healthy", "verified_at": time.time() if when is None else when,
        "created_at": float(identifier[0]),
    }


def _pick(store, record, launcher="2.34.0", activate=True):
    return select_generation(store, record, Preferences(),
                             activate=activate, launcher_version=launcher)


def test_mcp_reconnect_skips_pipx_when_the_launcher_bypasses_generations(store, monkeypatch):
    store.root.mkdir(parents=True)
    (store.root / PIPX_METADATA).write_text("{}")
    monkeypatch.setattr(sys, "prefix", str(store.root))
    monkeypatch.delenv("SERVONAUT_SKIP_AUTO_APPLY", raising=False)
    assert PipxReconnectHint.detect("2.34.0") is not None
    monkeypatch.setenv("SERVONAUT_SKIP_AUTO_APPLY", "1")
    assert PipxReconnectHint.detect("2.34.0") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["ready", "pinned", "fallback", "older", "equal", "newer-launcher"])
async def test_mcp_reconnect_tracks_current_healthy_pipx_route(store, change):
    record = {"current": READY, "previous": CURRENT, "last_launcher_version": "2.34.0"}
    _healthy(store, record, CURRENT, "2.34.0")
    _healthy(store, record, READY, "2.35.0")
    hint = PipxReconnectHint(store, PackageVersion.parse("2.34.0"), 60)
    store.write("state.json", record)
    await hint._refresh()
    assert "2.35.0 is installed" in hint.message(diagnostic=True)

    if change == "ready":
        record.update(current=CURRENT, ready=READY, previous=None)
    elif change == "pinned":
        record["pin"] = {"version": "2.34.0", "from": "2.35.0"}
    elif change == "fallback":
        record["generations"][READY]["health"] = "failed"
        record["generations"][CURRENT]["version"] = "2.34.1"
    elif change == "older":
        record["last_launcher_version"] = "2.33.0"
        record["generations"][READY]["version"] = "2.33.0"
    elif change == "equal":
        record["generations"][READY]["version"] = "2.34"
    else:
        record["last_launcher_version"] = "2.36.0"

    store.write("state.json", record)
    await hint._refresh()
    message = hint.message(diagnostic=True)
    if change == "fallback":
        assert "2.34.1 is installed" in message
    else:
        assert message is None


@pytest.mark.asyncio
async def test_mcp_reconnect_probe_is_coalesced_and_rate_limited(store, monkeypatch):
    hint = PipxReconnectHint(store, PackageVersion.parse("2.34.0"), 60)
    observe = Mock(return_value=ReconnectBuild(PackageVersion.parse("2.35.0")))
    monkeypatch.setattr(hint, "_read_current_target", observe)
    hint.refresh_if_due()
    first = hint._probe
    hint.refresh_if_due()
    assert hint._probe is first
    await first
    hint.refresh_if_due()
    assert hint._probe is first
    observe.assert_called_once_with()


@pytest.mark.asyncio
async def test_mcp_reconnect_reuses_the_state_stamp_but_clears_a_bad_record(store, monkeypatch):
    record = {"current": READY, "last_launcher_version": "2.34.0"}
    _healthy(store, record, READY, "2.35.0")
    store.write("state.json", record)
    hint = PipxReconnectHint(store, PackageVersion.parse("2.34.0"), 60)
    read_state = Mock(wraps=store.load_state)
    monkeypatch.setattr(store, "load_state", read_state)

    await hint._refresh()
    await hint._refresh()
    assert hint.message(diagnostic=True)
    read_state.assert_called_once_with(maximum_bytes=_MAX_STATE_BYTES)
    (store.directory / "state.json").write_text('{"current":')
    await hint._refresh()
    assert hint.message(diagnostic=False) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ("directory", "oversized"))
async def test_mcp_reconnect_does_not_open_unsafe_state_files(store, monkeypatch, kind):
    path = store.directory / "state.json"
    if kind == "directory":
        path.mkdir()
    else:
        with path.open("wb") as state_file:
            state_file.truncate(_MAX_STATE_BYTES + 1)
    hint = PipxReconnectHint(store, PackageVersion.parse("2.34.0"), 60)
    read_state = Mock(wraps=store.load_state)
    monkeypatch.setattr(store, "load_state", read_state)
    await hint._refresh()
    read_state.assert_not_called()
    assert hint.message(diagnostic=True) is None


@pytest.mark.asyncio
async def test_mcp_reconnect_does_not_start_a_second_probe_after_deadline(store, monkeypatch):
    started, finish = asyncio.Event(), asyncio.Event()

    async def blocked_probe():
        started.set()
        await finish.wait()

    hint = PipxReconnectHint(store, PackageVersion.parse("2.34.0"), 60)
    monkeypatch.setattr(hint, "_refresh", blocked_probe)
    hint.refresh_if_due()
    first = hint._probe
    try:
        await started.wait()
        hint._next_poll = 0.0
        hint.refresh_if_due()
        assert hint._probe is first
    finally:
        finish.set()
        await first
        await hint.close()


@pytest.mark.asyncio
async def test_mcp_reconnect_shutdown_logs_unexpected_probe_errors(store, monkeypatch, caplog):
    async def failed_probe():
        raise KeyError("broken probe")

    hint = PipxReconnectHint(store, PackageVersion.parse("2.34.0"), 60)
    monkeypatch.setattr(hint, "_refresh", failed_probe)
    hint.refresh_if_due()
    await asyncio.sleep(0)
    assert hint._probe.done()
    with caplog.at_level("DEBUG", logger="servonaut.mcp.reconnect"):
        await hint.close()
    assert "MCP reconnect probe failed during shutdown (KeyError)." in caplog.text


def test_mcp_reconnect_notifies_once_for_each_build_revision(store):
    hint = PipxReconnectHint(store, PackageVersion.parse("2.34.0"), 60)
    hint._target = ReconnectBuild(PackageVersion.parse("2.35.0"), revision=1)
    assert "revision 1" in hint.message(diagnostic=False)
    hint._target = ReconnectBuild(PackageVersion.parse("2.35"), revision=1)
    assert hint.message(diagnostic=False) is None
    hint._target = ReconnectBuild(PackageVersion.parse("2.35.0"), revision=2)
    assert "revision 2" in hint.message(diagnostic=False)
    assert hint.message(diagnostic=False) is None


@pytest.mark.asyncio
async def test_mcp_reconnect_diagnostics_and_concurrent_notice_preserve_results(store):
    pytest.importorskip("mcp")
    from servonaut.mcp.server import _dispatch_tool

    record = {"current": READY, "last_launcher_version": "2.34.0"}
    _healthy(store, record, READY, "2.35.0")
    store.write("state.json", record)
    hint = PipxReconnectHint(store, PackageVersion.parse("2.34.0"), 60)
    await hint._refresh()

    async def inventory():
        await asyncio.sleep(0)
        return MCPDisplayText("Quiet inventory")

    async def whoami():
        return '{"logged_in": false}'

    async def check_status(**_kwargs):
        return MCPDisplayText("State: running")

    async def api_request():
        return '{"body": {"ok": true}}'

    async def get_server_info(**_kwargs):
        raise RuntimeError("unavailable")

    tools = SimpleNamespace(
        list_instances=inventory, whoami=whoami, check_status=check_status,
        api_request=api_request, get_server_info=get_server_info,
    )

    async def dispatch(name):
        return await _dispatch_tool(tools, name, {}, hint)

    try:
        assert len(await dispatch("api_request")) == 1
        await hint._probe
        assert len(await dispatch("get_server_info")) == 1
        first = await dispatch("whoami")
        assert json.loads(first[0].text) == {"logged_in": False}
        assert first[1].meta == {"servonaut.dev/reason": PIPX_GENERATION_CURRENT}
        assert "2.35.0 is installed" in first[1].text
        assert (await dispatch("check_status"))[1].text == first[1].text

        results = await asyncio.gather(*(dispatch("list_instances") for _ in range(4)))
        assert all(result[0].text == "Quiet inventory" for result in results)
        assert [result[1].text for result in results if len(result) == 2] == [first[1].text]
        assert (await dispatch("whoami"))[1].text == first[1].text

        record["generations"][READY]["version"] = "2.35"
        store.write("state.json", record)
        await hint._refresh()
        assert len(await dispatch("list_instances")) == 1
        record["generations"][READY]["version"] = "2.36.0"
        store.write("state.json", record)
        await hint._refresh()
        assert "2.36.0 is installed" in (await dispatch("list_instances"))[1].text
    finally:
        await hint.close()


def test_switch_does_not_wait_for_an_active_mcp_lease(store):
    record = {"current": CURRENT, "ready": READY, "offered": "2.35.0",
              "offered_at": time.time() - 1, "presented_at": time.time()}
    _healthy(store, record, CURRENT, "2.34.0")
    _healthy(store, record, READY, "2.35.0")
    store.write("leases.json", {
        str(os.getpid()): {"birth": birth(os.getpid()), "role": "mcp", "generation": CURRENT},
    })
    with store.gate():
        assert _pick(store, record) == READY
        assert record["previous"] == CURRENT
        assert record["current"] == READY
        assert "offered" not in record
        assert (directory_for(store, CURRENT) / MARKER_NAME).exists()


@pytest.mark.parametrize("reason", ["postponed", "stale", "skip", "launcher", "rc"])
def test_ready_generation_waits_until_eligible(store, reason):
    target = "2.35.0rc1" if reason == "rc" else "2.35.0"
    record = {"current": CURRENT, "ready": READY, "offered": target,
              "offered_at": time.time() - 1, "presented_at": time.time()}
    _healthy(store, record, CURRENT, "2.34.0")
    _healthy(store, record, READY, target, when=0 if reason == "stale" else None)
    if reason == "postponed":
        record["postponed"] = {"2.35.0": time.time() + 3600}
    assert _pick(store, record, "2.36.0" if reason == "launcher" else "2.34.0",
                 activate=reason != "skip") == CURRENT
    assert record["ready"] == READY


@pytest.mark.parametrize(("age", "presented", "postponed", "launcher", "expected"), [
    (60, False, False, "2.34.0", CURRENT),
    (24 * 3600, False, False, "2.34.0", READY),
    (60, True, False, "2.34.0", READY),
    (60, True, True, "2.34.0", CURRENT),
    (24 * 3600, True, False, "2.34.0", READY),
    (60, False, False, "2.35.0", READY),
])
def test_offer_admission(store, age, presented, postponed, launcher, expected):
    now = time.time()
    record = {"current": CURRENT, "ready": READY, "offered": "2.35.0",
              "offered_at": now - age}
    if presented:
        record["presented_at"] = now - age / 2
    if postponed:
        record["postponed"] = {"2.35.0": now + 3600}
    elif presented:
        record["postponed"] = {"2.35.0": now - 1}
    _healthy(store, record, CURRENT, "2.34.0")
    _healthy(store, record, READY, "2.35.0")
    assert _pick(store, record, launcher) == expected


def test_presentation_matches_the_current_offer(store, monkeypatch):
    monkeypatch.setattr(sys, "prefix", str(store.root))
    store.root.mkdir(parents=True)
    (store.root / "pipx_metadata.json").touch()
    store.write("state.json", {"offered": "2.35.0"})
    assert not mark_update_presented("2.36.0")
    assert mark_update_presented("2.35.0")
    recorded = store.read("state.json")["presented_at"]
    assert mark_update_presented("2.35.0")
    assert store.read("state.json")["presented_at"] == recorded


def test_update_status_reads_the_shared_policy_cache(store, monkeypatch):
    monkeypatch.setattr(sys, "prefix", str(store.root))
    store.root.mkdir(parents=True)
    (store.root / "pipx_metadata.json").touch()
    policy = SimpleNamespace(mode="enforce", minimum_version="9.0.0")
    monkeypatch.setattr(
        "servonaut.services.version_policy.VersionPolicyClient.cached", lambda _self: policy,
    )
    assert read_update_status().required_minimum == "9.0.0"


def test_missing_current_rolls_back_to_healthy_previous(store):
    record = {"current": CURRENT, "previous": OLD}
    _healthy(store, record, CURRENT, "2.35.0")
    _healthy(store, record, OLD, "2.34.0")
    python_for(directory_for(store, CURRENT)).unlink()
    assert _pick(store, record) == OLD
    assert record["status"] == "rolled_back"
    assert record["generations"][CURRENT]["health"] == "failed"


def test_gc_retains_unknown_lease_but_collects_after_pid_reuse(store, monkeypatch):
    record = {"current": READY, "previous": CURRENT}
    for gen in (OLD, CURRENT, READY, UNUSED):
        _healthy(store, record, gen, "2.34.0")
    record["generations"][UNUSED]["health"] = "failed"
    store.write("leases.json", {"8081": {"birth": "old-start", "generation": OLD}})

    def unavailable(_pid):
        raise UnknownProcess("inaccessible")

    monkeypatch.setattr(state, "birth", unavailable)
    with store.gate():
        paths = evacuate_unused(store, record, Preferences())
    assert [path.name for path in paths] == [f".retired-{UNUSED}"]
    assert directory_for(store, OLD).exists()

    monkeypatch.setattr(state, "birth", lambda _pid: "new-start")
    with store.gate():
        paths = evacuate_unused(store, record, Preferences())
    assert [path.name for path in paths] == [f".retired-{OLD}"]
    assert not directory_for(store, OLD).exists()


@pytest.fixture
def public_index(monkeypatch):
    for name in ("SERVONAUT_PYPI_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS",
                 "PIP_NO_INDEX", "PIPX_GLOBAL", "PIP_CONSTRAINT", "PIP_TARGET",
                 "PIP_PREFIX", "PIP_ROOT", "PIP_USER", "PIP_REQUIREMENT",
                 "PIP_EDITABLE", "PIP_TRUSTED_HOST"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PIP_INDEX_URL", index.DEFAULT_INDEX_URL)
    return index.PackageIndex()


def _file(version, *, yanked=False):
    filename = f"servonaut-{version}-py3-none-any.whl"
    return {
        "filename": filename, "url": f"https://files.pythonhosted.org/{filename}",
        "size": 3, "digests": {"sha256": hashlib.sha256(b"abc").hexdigest()}, "yanked": yanked,
    }


def test_public_index_obeys_rc_opt_in_and_ignores_yanked_files(public_index):
    document = {"releases": {
        "2.34.1": [_file("2.34.1")],
        "2.35.0rc3": [_file("2.35.0rc3")],
        "2.35.0rc4": [_file("2.35.0rc4", yanked=True)],
        "2.35.0rc5.dev1": [_file("2.35.0rc5.dev1")],
    }}
    assert public_index.target(document, "2.34.0", "stable") == "2.34.1"
    assert public_index.target(document, "2.34.0", "rc") == "2.35.0rc3"


def test_yank_after_download_rejects_exact_pin(public_index, monkeypatch, tmp_path):
    target = "2.35.0"
    selected = {"releases": {target: [_file(target)]}}
    metadata = iter([
        selected,
        {"releases": {target: [_file(target, yanked=True)]}},
    ])
    monkeypatch.setattr(public_index, "document", lambda _timeout: next(metadata))
    monkeypatch.setattr(index, "_copy_wheel", lambda _wheel, path, _timeout: path.write_bytes(b"abc"))
    with pytest.raises(index.UpdateUnavailable, match="withdrawn"):
        wheel = public_index.wheel(selected, target)
        with index.pinned_wheel(public_index, target, wheel, tmp_path, lambda: 1):
            pytest.fail("A withdrawn wheel reached pip")


def test_pipx_profile_reads_encoded_interpreter_and_injection(store, monkeypatch):
    store.root.mkdir(parents=True)
    profile_python = store.root.parent / "python"
    profile_python.touch()
    state.write_json(store.root / "pipx_metadata.json", {
        "source_interpreter": {"__Path__": str(profile_python), "__type__": "Path"},
        "main_package": {"package_or_url": "servonaut[mcp]==2.34.0"},
        "injected_packages": {"httpx": {"package_or_url": "httpx==0.28.1"}},
    })
    monkeypatch.setattr("shutil.which", lambda _name: str(store.root.parent / "pipx"))
    monkeypatch.setattr("subprocess.check_output", lambda *_args, **_kw: str(store.root.parent))
    assert load_profile(store.root, 1) == Profile(
        str(profile_python), "servonaut[mcp]", ("httpx==0.28.1",),
    )


def test_abandoned_build_is_replaced_only_after_its_writer_exits(store, monkeypatch):
    record = {"builder": {"pid": 11, "birth": "a", "writer": {"pid": 12, "birth": "b"}}}
    monkeypatch.setattr(state, "birth", lambda pid: "b" if pid == 12 else None)
    builder.schedule(store, record, Preferences(), "2.34.0")
    assert record["builder"]["pid"] == 11
    monkeypatch.setattr(state, "birth", lambda _pid: None)
    called = []

    class Worker:
        pid = 13

    def start(args, **_kwargs):
        called.append(args)
        return Worker()

    monkeypatch.setattr(builder.subprocess, "Popen", start)
    builder.schedule(store, record, Preferences(), "2.34.0")
    assert record["builder"]["pid"] == 13
    assert record["status"] == "failed"
    assert called[0][2] == "servonaut.updates.builder"


def test_offline_revalidation_does_not_spawn_a_worker_for_every_launch(store, monkeypatch):
    now = time.time()
    record = {
        "ready": READY, "generations": {READY: {"verified_at": now - 60}},
        "checked_at": now - 120, "launcher_version": "2.34.0",
    }
    prefs = Preferences(validation_max_age_seconds=30)
    worker = SimpleNamespace(pid=os.getpid())
    monkeypatch.setattr(builder.subprocess, "Popen", lambda *_args, **_kwargs: worker)
    assert builder.schedule(store, record, prefs, "2.34.0") is worker
    record.pop("builder")  # The background refresh finished without reaching the index.
    assert builder.schedule(store, record, prefs, "2.34.0") is None


def test_failed_health_probe_preserves_pointer_and_sets_backoff(store, monkeypatch):
    record = {"current": CURRENT, "builder": {"token": "test"}}
    _healthy(store, record, CURRENT, "2.34.0")
    store.write("state.json", record)
    profile = Profile(sys.executable, "servonaut", ())
    monkeypatch.setattr(builder, "_refresh_policy", lambda *_args: None)
    monkeypatch.setattr(builder, "load_profile", lambda *_args: profile)

    class FakeIndex:
        def target(self, *_args):
            return "2.35.0"

        def wheel(self, _data, version):
            return index.Wheel("name", "url", "hash", 3) if version == "2.35.0" else None

        def document(self, _timeout):
            return {}

    def fail_probe(*_args):
        raise index.UpdateUnavailable("The new copy did not pass its startup check.")

    monkeypatch.setattr(builder, "PackageIndex", FakeIndex)
    monkeypatch.setattr(builder, "_build", fail_probe)
    builder._stage(store, "test", "2.34.0")
    state_after = store.read("state.json")
    assert state_after["current"] == CURRENT
    assert state_after["status"] == "failed"
    assert not state_after.get("ready")
    assert state_after["failure"]["retry_at"] > time.time()


@pytest.mark.parametrize("args,interactive", [([], True), (["--debug"], True),
                                               (["--mcp"], False), (["team", "rules"], False)])
def test_only_tui_shapes_schedule_a_background_check(monkeypatch, args, interactive):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    assert entry._interactive(args) is interactive
