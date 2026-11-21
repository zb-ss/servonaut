"""Exercise the installer with real filesystem state and simulated Apple tools."""

from __future__ import annotations

import ctypes
import hashlib
import os
import plistlib
import shutil
import struct
import sys
import time
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from servonaut.distribution.apply_policy import DesktopArtifactIdentity
from servonaut.distribution.manifest import ArtifactKind
from servonaut.runtime import DistributionKind
from servonaut.services import update_service
from servonaut.updates import macos_install as installer
from servonaut.updates import macos_native as native
from servonaut.updates import macos_transaction as transaction
from servonaut.updates.desktop_apply import DesktopApplyDecision, StagedDesktopUpdate
from servonaut.updates.macos_transaction import BUNDLE_NAME, BundleTransaction, MacUpdateError, identity
from servonaut.utils.atomic_file import write_json_atomic

fcntl = pytest.importorskip("fcntl")
_TEAM = "EXAMPLE123"
_IMAGE = b"verified installer fixture"


def _bundle(path: Path, version: str) -> Path:
    contents = path / "Contents"
    programs = contents / "MacOS"
    resources = contents / "Resources"
    programs.mkdir(parents=True)
    resources.mkdir()
    path.chmod(0o755)
    (contents / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": native.BUNDLE_ID, "CFBundleShortVersionString": version,
        "CFBundleExecutable": native.EXECUTABLES[0],
        native.ADMISSION_VERSION_KEY: native.ADMISSION_VERSION, native.ROLLBACK_EPOCH_KEY: native.ROLLBACK_EPOCH,
    }))
    (resources / "servonaut-runtime.json").write_text(
        f'{{"product_version":"{version}","packaging_revision":2,"distribution":"packaged-desktop"}}',
    )
    for name in native.EXECUTABLES:
        for entry in (name, name + native.WORKER_SUFFIX):
            (programs / entry).write_bytes(struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0))
    return path


@contextmanager
def _shared_gate(parent: Path):
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


class InstallFixture:
    def __init__(self, root: Path, monkeypatch):
        parent = root / "Applications"
        parent.mkdir(mode=0o700)
        self.installed = _bundle(parent / BUNDLE_NAME, "1.0.0")
        self.candidate = _bundle(root / "image" / BUNDLE_NAME, "1.0.1")
        self.install = installer.Installation(self.installed)
        self.runtime = self.runtime_for(self.installed, root / "data")
        staging = self.runtime.data_root / installer.DESKTOP_STAGING_DIR
        staging.mkdir(mode=0o700, parents=True)
        dmg = staging / "installer.dmg"
        dmg.write_bytes(_IMAGE)
        dmg.chmod(0o600)
        self.staged = StagedDesktopUpdate(
            DesktopArtifactIdentity("1.0.1", 2, ArtifactKind.MACOS_DMG, "darwin", "arm64",
                                    hashlib.sha256(_IMAGE).hexdigest()),
            dmg,
        )
        self.denied_signatures: set[Path] = set()
        self.calls = []
        self.active_processes = ()
        self.evidence = SimpleNamespace(is_current=Mock(return_value=True))
        self.update = SimpleNamespace(prepare_staged_desktop_apply=self.authorize, update_guidance=None)
        self.tx = BundleTransaction(self.installed, self.install.work / "transaction", self.rename)
        monkeypatch.setattr(installer, "sys", SimpleNamespace(platform="darwin"))
        monkeypatch.setattr(installer, "_account_applications", lambda: parent)
        monkeypatch.setattr(installer, "SYSTEM_APPLICATIONS", root / "system")
        monkeypatch.setattr(installer, "require_replacement_tools", lambda: None)
        monkeypatch.setattr(installer, "native_command", self.command)
        monkeypatch.setattr(native, "native_command", self.command)
        monkeypatch.setattr(installer, "mounted_application", self.mounted)
        monkeypatch.setattr(installer, "bundle_processes", lambda _bundle: self.active_processes)
        monkeypatch.setattr(installer, "legacy_files_in_use", lambda *_args, **_kwargs: False)
        monkeypatch.setattr(installer, "rename_native", self.probe_exchange)
        monkeypatch.setattr(installer, "birth", lambda pid: f"birth-{pid}")
        monkeypatch.setattr(installer.Installation, "transaction", property(lambda _: self.tx))
        monkeypatch.setattr(installer, "_launch", self.launch)
        monkeypatch.setattr(update_service, "UpdateService", lambda _runtime: self.update)
        monkeypatch.setattr("servonaut.utils.logging_setup.configure_rotating_log", lambda *_a, **_kw: None)

    @staticmethod
    def runtime_for(bundle: Path, data_root: Path):
        return SimpleNamespace(
            kind=DistributionKind.PACKAGED_DESKTOP, is_frozen=True,
            executable_root=bundle / "Contents" / "MacOS", data_root=data_root,
        )

    def command(self, tool, *args, **_kwargs):
        self.calls.append((tool, args))
        if tool == "/bin/ls":
            return "directory"
        if tool == "/usr/bin/xattr":
            return ""
        if tool == "/usr/bin/ditto":
            shutil.copytree(args[-2], args[-1])
            return ""
        if tool == "/usr/sbin/spctl":
            return "source=Notarized Developer ID"
        if tool == "/usr/bin/codesign":
            if args[-1] in self.denied_signatures:
                raise MacUpdateError("signature rejected by fixture")
            return f"TeamIdentifier={_TEAM}\nCodeDirectory v=20400 flags=0x10000(runtime) hashes=4"
        raise AssertionError(tool)

    @contextmanager
    def mounted(self, image, _mountpoint):
        assert image == self.staged.path
        self.calls.append(("mount", image))
        yield self.candidate

    def authorize(self, staged):
        assert staged == self.staged
        with _shared_gate(self.install.bundle.parent):
            self.calls.append(("authorizer", staged.path))
        return self.evidence

    def launch(self, bundle):
        self.calls.append(("launch", identity(bundle)))
        installer.acknowledge_startup(self.runtime)

    def probe_exchange(self, source, destination, *, exchange):
        with _shared_gate(self.install.bundle.parent):
            self.rename_paths(source, destination, exchange=exchange)

    def rename(self, source, destination, *, exchange):
        with pytest.raises(BlockingIOError):
            with _shared_gate(self.install.bundle.parent):
                pass
        self.rename_paths(source, destination, exchange=exchange)

    @staticmethod
    def rename_paths(source, destination, *, exchange):
        if exchange:
            holding = source.with_name("holding")
            source.rename(holding)
            destination.rename(source)
            holding.rename(destination)
        else:
            assert not destination.exists()
            source.rename(destination)

    def quit_request(self, *, started: str | None = None):
        pid = os.getpid()
        write_json_atomic(installer._quit_request_path(self.runtime, pid), {
            "started": started or f"birth-{pid}",
            "file": self.staged.path.name,
            "artifact": asdict(self.staged.identity),
        })

    def ready_helper(self, monkeypatch):
        inherited = []
        monkeypatch.setattr(installer, "_spawn", lambda _installation, fd: inherited.append(os.dup(fd)))
        self.quit_request()
        installer.start_on_quit(self.runtime)
        return self.runtime_for(self.install.helper, self.runtime.data_root), inherited.pop()


@pytest.fixture
def setup(tmp_path, monkeypatch):
    return InstallFixture(tmp_path.resolve(), monkeypatch)


def test_real_helper_verifies_and_exchanges_only_under_exclusive_admission(setup, monkeypatch, caplog):
    if sys.platform == "darwin":
        monkeypatch.setattr(setup, "rename_paths", transaction.rename_native)
        monkeypatch.setattr(installer, "bundle_processes", native.bundle_processes)
    original = identity(setup.installed)
    helper, fd = setup.ready_helper(monkeypatch)
    try:
        with caplog.at_level("INFO", logger=installer.__name__):
            assert installer.run_helper(helper, str(fd)) == 0
    finally:
        os.close(fd)
    durations = [
        record.args[0] for record in caplog.records
        if record.msg.startswith("Exclusive application admission held")
    ]
    assert len(durations) == 1 and durations[0] >= 0
    current = identity(setup.installed)
    assert current != original and identity(setup.tx.previous) == original
    assert not setup.tx.journal_path.exists()
    assert installer._confirmed_installation(setup.install) == (current, original)
    assert not setup.staged.path.exists()
    assert ("launch", current) in setup.calls
    assert ("authorizer", setup.staged.path) in setup.calls
    setup.evidence.is_current.assert_called_once()


@pytest.mark.parametrize("refusal", ["current-signature", "helper-signature", "birth"])
def test_quit_validates_both_signed_copies_and_the_launcher_birth(setup, monkeypatch, refusal):
    spawn = Mock()
    monkeypatch.setattr(installer, "_spawn", spawn)
    if refusal != "birth":
        setup.denied_signatures.add(setup.installed if refusal == "current-signature" else setup.install.helper)
    setup.quit_request(started="previous-process" if refusal == "birth" else None)
    expected = "expired" if refusal == "birth" else "signature"
    with pytest.raises(MacUpdateError, match=expected):
        installer.start_on_quit(setup.runtime)
    spawn.assert_not_called()


def test_helper_checks_canonical_installation_and_inherited_lock(setup, monkeypatch):
    helper, fd = setup.ready_helper(monkeypatch)
    another = os.open(setup.staged.path, os.O_RDONLY)
    try:
        assert installer.run_helper(helper, str(another)) == 1
        setup.installed.chmod(0o775)
        assert installer.run_helper(helper, str(fd)) == 1
        assert not setup.tx.journal_path.exists()
    finally:
        os.close(another)
        os.close(fd)


@pytest.mark.parametrize("adverse", ["tampered-image", "candidate-signature", "rollback-epoch"])
def test_staged_bundle_must_be_the_verified_signed_copy(setup, monkeypatch, adverse):
    expected = "did not match"
    if adverse == "tampered-image":
        setup.staged.path.write_bytes(b"changed")
    if adverse == "candidate-signature":
        setup.denied_signatures.add(setup.tx.incoming)
        expected = "signature"
    if adverse == "rollback-epoch":
        read_info = installer.read_info
        monkeypatch.setattr(installer, "read_info", lambda path: {
            **read_info(path), native.ROLLBACK_EPOCH_KEY: 2 if path == setup.tx.incoming else 1,
        })
        expected = "Open the disk image"
    setup.install.work.mkdir(mode=0o700)
    with pytest.raises(MacUpdateError, match=expected):
        installer._prepare_candidate(setup.install, setup.staged, _TEAM)
    assert not setup.tx.journal_path.exists()
    if adverse == "tampered-image":
        assert not any(name == "mount" for name, _ in setup.calls)


def test_real_admission_refuses_an_active_reader_and_is_exclusive(setup):
    with _shared_gate(setup.install.bundle.parent):
        with pytest.raises(MacUpdateError, match="Close other Servonaut"):
            with installer._admission(setup.install, timeout=0):
                pass
    with installer._admission(setup.install, timeout=0):
        with pytest.raises(BlockingIOError):
            with _shared_gate(setup.install.bundle.parent):
                pass


def test_admission_records_the_exclusive_hold_duration(setup, caplog):
    with caplog.at_level("INFO", logger=installer.__name__):
        with installer._admission(setup.install):
            assert "Exclusive application admission held" not in caplog.text
    durations = [
        record.args[0] for record in caplog.records
        if record.msg.startswith("Exclusive application admission held")
    ]
    assert len(durations) == 1 and durations[0] >= 0


def test_another_account_skips_before_reading_private_recovery(setup, monkeypatch):
    uid = os.getuid()
    monkeypatch.setattr(installer.os, "getuid", lambda: uid + 1)
    private = Mock(side_effect=AssertionError("other account reached private update state"))
    monkeypatch.setattr(installer, "_private_dir", private)
    assert installer._owned_installation(setup.runtime) is None
    installer.acknowledge_startup(setup.runtime)
    installer.recover_after_quit(setup.runtime)
    installer.sweep_startup(setup.runtime)
    assert installer.consume_result(setup.runtime) is None
    private.assert_not_called()


@pytest.mark.parametrize("permission", ["bundle-writable", "parent-writable", "acl", "non-owner"])
def test_installation_requires_an_owner_safe_bundle_and_parent(setup, monkeypatch, permission):
    setup.install.validate()
    if permission == "acl":
        monkeypatch.setattr(installer, "native_command", lambda *_: "directory\n ACL entry")
    elif permission == "non-owner":
        uid = os.getuid()
        monkeypatch.setattr(installer.os, "getuid", lambda: uid + 1)
    elif permission == "bundle-writable":
        setup.installed.chmod(0o775)
    else:
        setup.install.bundle.parent.chmod(0o777)
    with pytest.raises(MacUpdateError):
        setup.install.validate()


def test_notarization_failure_refuses_the_candidate(setup, monkeypatch):
    command = setup.command
    monkeypatch.setattr(native, "native_command", lambda tool, *args, **kwargs:
                        "source=Developer ID" if tool == "/usr/sbin/spctl" else command(tool, *args, **kwargs))
    with pytest.raises(MacUpdateError, match="Gatekeeper"):
        native.validate_bundle(setup.candidate, artifact=setup.staged.identity)


def test_process_scan_keeps_only_stable_bundle_executables(setup, monkeypatch):
    bundle_entry = setup.installed / "Contents" / "MacOS" / "servonaut.runtime"

    def pids(_kind, _uid, entries, _size):
        if entries is not None:
            entries[0], entries[1], entries[2] = 101, 102, 103
        return 3 * ctypes.sizeof(ctypes.c_int)

    def executable(pid, buffer, _size):
        if pid == 103:
            return 0
        value = os.fsencode(bundle_entry if pid == 101 else "/bin/sh") + b"\0"
        ctypes.memmove(buffer, value, len(value))
        return len(value)

    library = SimpleNamespace(proc_listpids=Mock(side_effect=pids), proc_pidpath=Mock(side_effect=executable))
    monkeypatch.setattr(native.ctypes, "CDLL", lambda _: library)
    births = iter(["stable", "stable", "elsewhere", "elsewhere", "ended", None])
    monkeypatch.setattr(native, "birth", lambda _: next(births))
    assert native.bundle_processes(setup.installed) == (native.Process(101, "stable", bundle_entry),)
    monkeypatch.setattr(native, "birth", lambda _: "stable")
    with pytest.raises(MacUpdateError, match="could not be identified"):
        native.bundle_processes(setup.installed)


def test_detach_retries_busy_mount_and_uses_force_last(setup, monkeypatch):
    class Mount:
        active = True

        def is_symlink(self):
            return False

        def is_mount(self):
            return self.active

    mount = Mount()
    commands = []
    delays = []

    def detach(tool, action, *args):
        assert (tool, action) == ("/usr/bin/hdiutil", "detach")
        commands.append(args)
        if args != ("-force", mount):
            raise MacUpdateError("disk image is busy")
        mount.active = False

    monkeypatch.setattr(native, "native_command", detach)
    monkeypatch.setattr(native, "time", SimpleNamespace(sleep=delays.append))
    native.detach_application_image(mount)
    assert commands == [(mount,)] * len(native._DETACH_BACKOFF) + [("-force", mount)]
    assert delays == list(native._DETACH_BACKOFF)


@pytest.mark.parametrize("state", ["denied", "expired-before-gate", "active-consumer"])
def test_helper_abandons_denial_stale_policy_or_active_process(setup, monkeypatch, state):
    helper, fd = setup.ready_helper(monkeypatch)
    original = identity(setup.installed)
    if state == "denied":
        setup.evidence = DesktopApplyDecision.DENIED
    elif state == "expired-before-gate":
        setup.evidence.is_current.return_value = False
    else:
        setup.active_processes = (object(),)
    try:
        assert installer.run_helper(helper, str(fd)) == 1
    finally:
        os.close(fd)
    assert identity(setup.installed) == original and not setup.tx.journal_path.exists()
    assert identity(setup.tx.previous) is None
    if state == "denied":
        assert not setup.tx.incoming.exists()
        assert "rejected" in installer.consume_result(setup.runtime)


def _committed_swap(setup, *, earlier=False):
    setup.install.work.mkdir(mode=0o700, exist_ok=True)
    setup.tx.work.mkdir(mode=0o700)
    shutil.copytree(setup.candidate, setup.tx.incoming)
    if earlier:
        shutil.copytree(setup.installed, setup.tx.previous)
    with installer._admission(setup.install):
        journal = setup.tx.prepare(identity(setup.tx.previous))
        setup.tx.commit(journal)
    return journal


def test_rollback_checks_for_a_running_replacement_without_wrapper_lock(setup, monkeypatch):
    journal = _committed_swap(setup)
    setup.active_processes = (object(),)
    monkeypatch.setattr(installer, "_HEALTH_SECONDS", 0)
    monkeypatch.setattr(installer, "_launch", lambda _: None)
    installer._finish_launch(setup.install, journal)
    assert identity(setup.installed) == journal.new and setup.tx.journal_path.is_file()


def test_recovery_waits_for_the_real_exclusive_gate(setup, monkeypatch):
    journal = _committed_swap(setup)
    acquire = installer._admission
    monkeypatch.setattr(installer, "_admission", lambda installation: acquire(installation, timeout=0))
    with _shared_gate(setup.install.bundle.parent):
        with pytest.raises(MacUpdateError, match="Close other Servonaut"):
            installer._recover(setup.install)
    assert identity(setup.installed) == journal.new and setup.tx.journal_path.is_file()
    installer._recover(setup.install)
    assert identity(setup.installed) == journal.old and not setup.tx.journal_path.exists()


def test_missing_previous_clears_only_after_verifying_canonical_bundle(setup):
    journal = _committed_swap(setup)
    shutil.rmtree(setup.tx.previous)
    setup.denied_signatures.add(setup.installed)
    with pytest.raises(MacUpdateError, match="signature"):
        installer._recover(setup.install)
    assert setup.tx.journal_path.is_file()
    setup.denied_signatures.clear()
    installer._recover(setup.install)
    assert identity(setup.installed) == journal.new and not setup.tx.journal_path.exists()
    assert installer._confirmed_installation(setup.install) == (journal.new, None)


def test_failed_recovery_exits_without_relaunch_and_notifies_once(setup, monkeypatch):
    helper, fd = setup.ready_helper(monkeypatch)
    _committed_swap(setup)
    monkeypatch.setattr(installer, "_recover", Mock(side_effect=MacUpdateError("fixture recovery failure")))
    launch = Mock()
    monkeypatch.setattr(installer, "_launch", launch)
    try:
        assert installer.run_helper(helper, str(fd)) == 1
    finally:
        os.close(fd)
    launch.assert_not_called()
    assert installer.consume_result(setup.runtime) == installer._RECOVERY_GUIDANCE
    spawn = Mock()
    monkeypatch.setattr(installer, "_spawn", spawn)
    installer.recover_after_quit(setup.runtime)
    spawn.assert_not_called()
    assert installer.consume_result(setup.runtime) is None


def test_recovery_contention_retries_with_backoff_before_guiding(setup, monkeypatch):
    helper, fd = setup.ready_helper(monkeypatch)
    os.close(fd)
    _committed_swap(setup)
    retry = Mock(side_effect=installer.MacUpdateBusy("fixture gate still held"))
    monkeypatch.setattr(installer, "_recover", retry)
    launch = Mock()
    monkeypatch.setattr(installer, "_launch", launch)
    spawn = Mock()
    monkeypatch.setattr(installer, "_spawn", spawn)
    ticks = [time.time_ns()]
    monkeypatch.setattr(installer.time, "time_ns", lambda: ticks[0])

    for attempt, delay in enumerate(installer._RECOVERY_BACKOFF_SECONDS, start=1):
        with installer._request_lock(setup.install) as inherited:
            assert installer.run_helper(helper, str(inherited)) == 1
        assert installer._read_recovery_retry(setup.install) == (attempt, ticks[0] + delay * 1_000_000_000)
        assert not installer._recovery_marker(setup.install).exists()
        assert installer.consume_result(setup.runtime) is None
        installer.recover_after_quit(setup.runtime)
        spawn.assert_not_called()
        ticks[0] += delay * 1_000_000_000
        installer.recover_after_quit(setup.runtime)
        spawn.assert_called_once()
        spawn.reset_mock()

    with installer._request_lock(setup.install) as inherited:
        assert installer.run_helper(helper, str(inherited)) == 1
    assert installer._recovery_marker(setup.install).is_file()
    assert installer.consume_result(setup.runtime) == installer._RECOVERY_GUIDANCE
    installer.recover_after_quit(setup.runtime)
    spawn.assert_not_called()
    launch.assert_not_called()


def test_held_operation_lock_leaves_recovery_eligible_later(setup, monkeypatch):
    _helper, fd = setup.ready_helper(monkeypatch)
    os.close(fd)
    _committed_swap(setup)
    spawn = Mock()
    monkeypatch.setattr(installer, "_spawn", spawn)
    with installer._request_lock(setup.install):
        installer.recover_after_quit(setup.runtime)
        spawn.assert_not_called()
    assert not installer._recovery_marker(setup.install).exists()
    installer.recover_after_quit(setup.runtime)
    spawn.assert_called_once()


def test_journal_and_each_rename_sync_the_changed_directories(setup, monkeypatch):
    synced = []
    monkeypatch.setattr(transaction, "sync_directory", synced.append)
    _committed_swap(setup, earlier=True)
    assert synced == [setup.tx.work] + [setup.tx.work, setup.installed.parent] * 3


def test_commit_rechecks_canonical_and_candidate_identity(setup):
    setup.tx.work.mkdir(mode=0o700, parents=True)
    shutil.copytree(setup.candidate, setup.tx.incoming)
    with installer._admission(setup.install):
        journal = setup.tx.prepare(None)
        setup.tx.incoming.rename(setup.tx.work / "changed")
        shutil.copytree(setup.candidate, setup.tx.incoming)
        with pytest.raises(MacUpdateError, match="changed"):
            setup.tx.commit(journal)
    assert identity(setup.installed) == journal.old


@pytest.mark.parametrize("changed", ["displaced", "archived", "confirm"])
def test_backup_and_confirmation_never_accept_a_different_copy(setup, changed):
    journal = _committed_swap(setup, earlier=True)
    if changed == "displaced":
        with installer._admission(setup.install):
            setup.tx.previous.rename(setup.tx.work / "saved")
            shutil.copytree(setup.candidate, setup.tx.incoming)
            with pytest.raises(MacUpdateError, match="displaced"):
                setup.tx.file_previous(journal)
    else:
        changed_path = setup.tx.archived if changed == "archived" else setup.tx.previous
        changed_path.rename(setup.tx.work / "saved")
        shutil.copytree(setup.candidate, changed_path)
        with pytest.raises(MacUpdateError, match="changed"):
            installer._confirm(setup.install, journal)
        assert changed_path.is_dir()
    assert setup.tx.journal_path.exists()


def test_healthy_start_sweeps_only_known_retired_bundles_and_stale_staging(setup):
    journal = _committed_swap(setup)
    installer._confirm(setup.install, journal)
    directory = setup.staged.path.parent
    old_image = directory / ("a" * 64 + ".dmg")
    old_image.write_bytes(_IMAGE)
    old_image.chmod(0o600)
    old = time.time() - installer._STAGE_RETENTION_SECONDS - 60
    os.utime(old_image, (old, old))
    abandoned = installer._quit_request_path(setup.runtime, 101)
    live = installer._quit_request_path(setup.runtime, 102)
    write_json_atomic(abandoned, {"started": "stale"})
    write_json_atomic(live, {"started": "birth-102"})

    installer.sweep_startup(setup.runtime)

    assert identity(setup.tx.previous) == journal.old and not setup.tx.work.exists()
    assert not old_image.exists() and not abandoned.exists() and live.exists()
    assert setup.staged.path.exists() and identity(setup.installed) == journal.new


@pytest.mark.parametrize(("days_old", "configured", "retained"), [
    (13, None, True), (14, None, False), (2, "3", True), (3, "3", False), (13, "0", True),
])
def test_confirmed_previous_is_retained_until_the_configured_age(setup, monkeypatch, days_old, configured, retained):
    journal = _committed_swap(setup)
    installer._confirm(setup.install, journal)
    if configured is None:
        monkeypatch.delenv(installer._ROLLBACK_RETENTION_ENV, raising=False)
    else:
        monkeypatch.setenv(installer._ROLLBACK_RETENTION_ENV, configured)
    now = time.time_ns()
    age = days_old * 24 * 60 * 60 * 1_000_000_000
    os.utime(setup.install.work / "previous.json", ns=(now - age, now - age))

    installer.sweep_startup(setup.runtime)

    assert identity(setup.tx.previous) == (journal.old if retained else None)
    assert identity(setup.installed) == journal.new


def test_guided_reinstallation_can_retire_an_abandoned_transaction(setup, monkeypatch):
    _helper, fd = setup.ready_helper(monkeypatch)
    os.close(fd)
    journal = _committed_swap(setup)
    installer._record_recovery_failure(setup.install)
    setup.installed.rename(setup.installed.parent / "manual-backup")
    shutil.copytree(setup.candidate, setup.installed)
    current = identity(setup.installed)
    assert current not in (journal.old, journal.new)
    setup.denied_signatures.add(setup.installed)
    installer.sweep_startup(setup.runtime)
    assert setup.tx.journal_path.exists()
    setup.denied_signatures.clear()

    installer.sweep_startup(setup.runtime)

    assert identity(setup.installed) == current
    assert not setup.tx.work.exists() and not setup.tx.previous.exists()
    setup.install.validate_offer()


def test_installation_resolves_an_alias_to_the_canonical_directory_object(setup, tmp_path):
    alias = tmp_path / "Applications-alias"
    alias.symlink_to(setup.installed.parent)
    alternate = setup.runtime_for(alias / BUNDLE_NAME, setup.runtime.data_root)
    assert installer.Installation.from_runtime(alternate) == setup.install


def test_unobservable_active_user_prevents_legacy_replacement(setup, monkeypatch):
    import pwd

    other_uid = os.getuid() + 100
    monkeypatch.setattr(native, "native_command", lambda *_args: f"0 {os.getuid()} {other_uid}")
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: SimpleNamespace(pw_shell="/bin/sh") if uid == other_uid else None)
    with pytest.raises(MacUpdateError, match="Another user"):
        native.legacy_files_in_use(setup.installed, shared=True)


def test_missing_stock_replacement_tool_is_a_guided_fallback(monkeypatch):
    monkeypatch.setattr(native.os, "access", lambda tool, mode: tool != "/usr/bin/hdiutil")
    with pytest.raises(MacUpdateError, match="tools required"):
        native.require_replacement_tools()
