"""Portable recovery cases and real Darwin admission and swap qualification."""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from servonaut.updates.macos_native import copy_bundle, mounted_application, native_command
from servonaut.updates.macos_transaction import (
    BUNDLE_NAME, BundleTransaction, MacUpdateError, SwapJournal, identity, rename_native,
)

_DARWIN = pytest.mark.skipif(sys.platform != "darwin", reason="Darwin filesystem and signing tools required")
_ROOT = Path(__file__).resolve().parents[2]


def _portable_rename(source: Path, destination: Path, *, exchange: bool) -> None:
    if exchange:
        holding = source.with_name("holding")
        source.rename(holding)
        destination.rename(source)
        holding.rename(destination)
    else:
        assert not destination.exists()
        source.rename(destination)


def _make_transaction(root: Path, rename, *, previously_installed: bool = False) -> BundleTransaction:
    tx = BundleTransaction(root / BUNDLE_NAME, root / "work", rename=rename)
    tx.work.mkdir()
    for path, version in ((tx.installed, "old"), (tx.incoming, "new")):
        path.mkdir()
        (path / "version").write_text(version)
    if previously_installed:
        tx.previous.mkdir()
        (tx.previous / "version").write_text("earlier")
    return tx


@pytest.mark.parametrize("cutoff", [0, 1, 2, 3])
@pytest.mark.parametrize("has_previous", [False, True])
def test_interrupted_swap_preserves_canonical_and_recovers(tmp_path: Path, cutoff: int, has_previous: bool) -> None:
    class Interrupted(Exception):
        pass

    calls = 0

    def interrupted(source: Path, destination: Path, *, exchange: bool) -> None:
        nonlocal calls
        if calls == cutoff:
            raise Interrupted
        calls += 1
        _portable_rename(source, destination, exchange=exchange)

    tx = _make_transaction(tmp_path, interrupted, previously_installed=has_previous)
    former_previous = identity(tx.previous)
    journal = tx.prepare(former_previous)
    try:
        tx.commit(journal)
    except Interrupted:
        pass

    assert tx.installed.is_dir()
    recovered = BundleTransaction(tx.installed, tx.work, rename=_portable_rename)
    saved = SwapJournal.read(tx.journal_path)
    assert saved == journal
    recovered.rollback(saved)
    assert identity(tx.installed) == journal.old
    assert identity(tx.previous) == former_previous
    assert (tx.installed / "version").read_text() == "old"
    assert (tx.incoming / "version").read_text() == "new"
    assert not tx.journal_path.exists()


def test_refuses_unrecognized_previous(tmp_path: Path) -> None:
    tx = _make_transaction(tmp_path, _portable_rename, previously_installed=True)
    with pytest.raises(MacUpdateError, match="unrecognized"):
        tx.prepare(None)
    assert (tx.previous / "version").read_text() == "earlier"
    assert (tx.installed / "version").read_text() == "old"


@_DARWIN
def test_darwin_swap_and_no_replace(tmp_path: Path) -> None:
    tx = _make_transaction(tmp_path, rename_native, previously_installed=True)
    journal = tx.prepare(identity(tx.previous))
    tx.commit(journal)
    assert (tx.installed / "version").read_text() == "new"
    assert (tx.previous / "version").read_text() == "old"
    assert (tx.archived / "version").read_text() == "earlier"
    with pytest.raises(FileExistsError):
        rename_native(tx.previous, tx.installed)
    tx.rollback(journal)
    assert (tx.installed / "version").read_text() == "old"
    assert (tx.previous / "version").read_text() == "earlier"


@_DARWIN
def test_darwin_cross_user_entry_admission() -> None:
    import fcntl

    with tempfile.TemporaryDirectory(dir="/private/tmp") as scratch:
        root = Path(scratch)
        root.chmod(0o755)
        source = _ROOT / "packaging/macos/admission.c"
        launcher = root / "admit"
        subprocess.run(
            ["/usr/bin/clang", "-Wall", "-Wextra", "-Werror", f'-DSYSTEM_APPS="{root}"',
             "-DSERVONAUT_ADMISSION_WAIT_SECONDS=1",
             "-o", launcher, source], check=True,
        )
        bundle = root / BUNDLE_NAME / "Contents/MacOS"
        independent = root / "Independent.app/Contents/MacOS"
        bundle.mkdir(parents=True)
        independent.mkdir(parents=True)
        names = ("servonaut-desktop", "servonaut-desktop-child", "servonaut")
        for directory in (bundle, independent):
            for name in names:
                entry = directory / name
                shutil.copy2(launcher, entry)
                subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", entry], check=True)
                worker = entry.with_name(f"{name}.runtime")
                worker.write_text("#!/bin/sh\n[ \"$1\" != hold ] || sleep 60\nexit 0\n")
                worker.chmod(0o755)
        symlink = root / "linked-servonaut"
        symlink.symlink_to(bundle / "servonaut")
        other_account = ["/usr/bin/sudo", "-n", "-u", "nobody", "--"]
        assert subprocess.check_output([*other_account, "/usr/bin/id", "-u"]).strip() != str(os.getuid()).encode()

        fd = os.open(root, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            launches = []
            try:
                for invocation in (*[bundle / name for name in names], symlink):
                    launches.extend((subprocess.Popen([invocation]), subprocess.Popen([*other_account, invocation])))
                time.sleep(0.2)
                assert all(process.poll() is None for process in launches)
                fcntl.flock(fd, fcntl.LOCK_UN)
                assert all(process.wait(timeout=5) == 0 for process in launches)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                for process in launches:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)
            assert subprocess.run([*other_account, symlink], timeout=5).returncode == 0
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            started = time.monotonic()
            fallback = subprocess.run([*other_account, symlink], timeout=6, capture_output=True)
            assert fallback.returncode == 0 and time.monotonic() - started >= 1
            assert b"Continuing to launch" in fallback.stderr
            assert subprocess.run([independent / "servonaut"], timeout=5).returncode == 0
            fcntl.flock(fd, fcntl.LOCK_UN)

            # The wrapper must keep admission across exec into the real worker.
            worker = (bundle / "servonaut.runtime")
            worker.write_text("#!/bin/sh\ntouch \"$1\"\nexec sleep 60\n")
            ready = root / "ready"
            process = subprocess.Popen([symlink, ready])
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                assert ready.exists()
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                process.terminate()
                process.wait(timeout=5)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)


@_DARWIN
def test_read_only_image_preserves_quarantine_on_copy(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    source = root / "source"
    app = source / BUNDLE_NAME
    app.mkdir(parents=True)
    (app / "example").write_text("signed payload stand-in")
    image = root / "fixture.dmg"
    native_command("/usr/bin/hdiutil", "create", "-fs", "HFS+", "-srcfolder", source, "-format", "UDZO", image)
    quarantine = "0081;00000000;Fixture;"
    native_command("/usr/bin/xattr", "-w", "com.apple.quarantine", quarantine, image)
    output = root / "copied.app"
    mountpoint = root / "image"
    with mounted_application(image, mountpoint) as mounted:
        assert os.statvfs(mounted).f_flag & os.ST_RDONLY
        copy_bundle(mounted, output, image=image)
    assert not mountpoint.exists()
    assert (output / "example").read_text() == "signed payload stand-in"
    applied = native_command("/usr/bin/xattr", "-p", "com.apple.quarantine", output).strip()
    assert applied == quarantine or applied.startswith("0081;")


def test_policy_defer_never_commits_or_removes_the_private_stage(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace

    from servonaut.updates import macos_install
    from servonaut.updates.desktop_apply import DesktopApplyDecision

    installed = macos_install.Installation(tmp_path / BUNDLE_NAME)
    tx = _make_transaction(tmp_path, _portable_rename)
    staged = tmp_path / "verified.dmg"
    staged.write_bytes(b"test installer payload")
    requested = SimpleNamespace(path=staged)
    calls = []
    monkeypatch.setattr(macos_install, "_get_request", lambda *_: (requested, "EXAMPLETEAM"))
    monkeypatch.setattr(macos_install, "validate_bundle", lambda *args, **kwargs: None)
    monkeypatch.setattr(macos_install, "_prepare_candidate", lambda *_: calls.append("candidate"))
    monkeypatch.setattr(macos_install, "_admission", lambda *_: nullcontext())
    monkeypatch.setattr(macos_install, "_can_exchange", lambda *_: calls.append("exchange check"))

    def check_consumers(*args, **kwargs):
        pytest.fail("A deferred policy reached the final consumer check")

    monkeypatch.setattr(macos_install, "_require_no_consumers", check_consumers)

    def authorizer(argument):
        calls.append("authorization")
        assert argument is requested
        return DesktopApplyDecision.DEFERRED

    update = SimpleNamespace(prepare_staged_desktop_apply=authorizer, update_guidance="Check this computer's date and time.")
    with pytest.raises(MacUpdateError, match="date and time"):
        macos_install._replace(installed, None, update)
    assert calls == ["candidate", "exchange check", "authorization"]
    assert staged.exists()
    assert (tx.installed / "version").read_text() == "old"


def test_running_unacknowledged_replacement_defers_rollback(tmp_path, monkeypatch):
    from contextlib import contextmanager

    from servonaut.updates import macos_install

    installation = macos_install.Installation(tmp_path / BUNDLE_NAME)
    installation.work.mkdir()
    tx = installation.transaction
    tx.work.mkdir()
    tx.installed.mkdir()
    tx.incoming.mkdir()
    journal = tx.prepare(None)
    tx_with_test_rename = BundleTransaction(tx.installed, tx.work, _portable_rename)
    tx_with_test_rename.commit(journal)
    monkeypatch.setattr(macos_install.Installation, "transaction", property(lambda _: tx_with_test_rename))
    monkeypatch.setattr(macos_install, "_launch", lambda *_: None)
    monkeypatch.setattr(macos_install, "_HEALTH_SECONDS", 0)
    monkeypatch.setattr(macos_install, "_require_no_consumers", lambda *args, **kwargs: None)

    @contextmanager
    def busy(*args, **kwargs):
        raise MacUpdateError("the newly opened app is still running")
        yield

    monkeypatch.setattr(macos_install, "_admission", busy)
    with pytest.raises(MacUpdateError, match="is still running"):
        macos_install._finish_launch(installation, journal)
    assert identity(tx.installed) == journal.new
    assert identity(tx.previous) == journal.old
    assert tx.journal_path.exists()


def test_failed_startup_restores_previous_after_quiet(tmp_path, monkeypatch):
    from contextlib import nullcontext

    from servonaut.updates import macos_install

    installation = macos_install.Installation(tmp_path / BUNDLE_NAME)
    installation.work.mkdir()
    tx = installation.transaction
    tx.work.mkdir()
    tx.installed.mkdir()
    tx.incoming.mkdir()
    journal = tx.prepare(None)
    tx = BundleTransaction(tx.installed, tx.work, _portable_rename)
    tx.commit(journal)
    monkeypatch.setattr(macos_install.Installation, "transaction", property(lambda _: tx))
    launches = []
    monkeypatch.setattr(macos_install, "_launch", lambda bundle: launches.append(identity(bundle)))
    monkeypatch.setattr(macos_install, "_HEALTH_SECONDS", 0)
    monkeypatch.setattr(macos_install, "_admission", lambda *args, **kwargs: nullcontext())
    monkeypatch.setattr(macos_install, "_require_no_consumers", lambda *args, **kwargs: None)
    macos_install._finish_launch(installation, journal)

    assert launches == [journal.new, journal.old]
    assert "restored" in (installation.work / "result.json").read_text()
    assert not tx.journal_path.exists()


def test_acknowledgment_can_recover_swap_interrupted_before_filing_previous(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace

    from servonaut.updates import macos_install

    installation = macos_install.Installation(tmp_path / BUNDLE_NAME)
    installation.work.mkdir()
    tx = installation.transaction
    tx.work.mkdir()
    tx.installed.mkdir()
    tx.incoming.mkdir()
    tx = BundleTransaction(tx.installed, tx.work, _portable_rename)
    journal = tx.prepare(None)
    _portable_rename(tx.incoming, tx.installed, exchange=True)
    monkeypatch.setattr(macos_install.Installation, "from_runtime", lambda _: installation)
    monkeypatch.setattr(macos_install.Installation, "transaction", property(lambda _: tx))
    monkeypatch.setattr(macos_install, "_private_dir", lambda path: path)
    monkeypatch.setattr(macos_install, "_admission", lambda *args, **kwargs: nullcontext())
    scans = []
    monkeypatch.setattr(macos_install, "_require_no_consumers", lambda *args, **kwargs: scans.append(kwargs))
    macos_install.acknowledge_startup(SimpleNamespace())
    macos_install._recover(installation)

    assert scans == [{"known_guarded": True}]
    assert identity(tx.installed) == journal.new
    assert identity(tx.previous) == journal.old
    assert macos_install._confirmed_installation(installation) == (journal.new, journal.old)
    assert not tx.journal_path.exists()


def test_candidate_release_revision_and_architecture_follow_signed_identity(tmp_path, monkeypatch):
    from unittest.mock import Mock

    from servonaut.distribution.apply_policy import DesktopArtifactIdentity
    from servonaut.distribution.manifest import ArtifactKind
    from servonaut.updates import macos_native

    root = tmp_path / BUNDLE_NAME
    resources = root / "Contents" / "Resources"
    resources.mkdir(parents=True)
    marker = resources / "servonaut-runtime.json"
    marker.write_text('{"distribution":"packaged-desktop","product_version":"2.35.0rc2","packaging_revision":7}')
    artifact = DesktopArtifactIdentity("2.35.0-rc.2", 7, ArtifactKind.MACOS_DMG, "darwin", "arm64", "a" * 64)
    info = {"CFBundleShortVersionString": "2.35.0rc2"}
    commands = Mock(side_effect=AssertionError("Architecture checks must use the sealed file bytes"))
    monkeypatch.setattr(macos_native, "native_command", commands)
    executables = root / "Contents" / "MacOS"
    executables.mkdir()
    names = (*macos_native.EXECUTABLES, *(f"{name}.runtime" for name in macos_native.EXECUTABLES))
    for name in names:
        (executables / name).write_bytes(_thin_macho("<", 0x0100000C, 0))
    macos_native._require_build(root, info, artifact)
    commands.assert_not_called()
    (executables / names[-1]).write_bytes(_thin_macho("<", 0x01000007, 3))
    with pytest.raises(MacUpdateError, match="architecture"):
        macos_native._require_build(root, info, artifact)
    marker.write_text('{"distribution":"packaged-desktop","product_version":"2.35.0rc2","packaging_revision":6}')
    with pytest.raises(MacUpdateError, match="revision"):
        macos_native._require_build(root, info, artifact)


def _thin_macho(order: str, cpu: int, subtype: int) -> bytes:
    return struct.pack(f"{order}IIIIIIII", 0xFEEDFACF, cpu, subtype, 2, 0, 0, 0, 0)


@pytest.mark.parametrize("order", ["<", ">"])
@pytest.mark.parametrize(("cpu", "subtype", "architecture"), [
    (0x01000007, 3, "x86_64"),
    (0x01000007, 8, "x86_64h"),
    (0x0100000C, 0, "arm64"),
    (0x0100000C, 0x80000002, "arm64e"),
])
def test_thin_macho_architecture(tmp_path, order, cpu, subtype, architecture):
    from servonaut.updates.macho import macho_architectures

    path = tmp_path / "executable"
    path.write_bytes(_thin_macho(order, cpu, subtype))
    assert macho_architectures(path) == {architecture}


@pytest.mark.parametrize("wide", [False, True])
@pytest.mark.parametrize("order", ["<", ">"])
def test_universal_macho_architectures_and_matching_slices(tmp_path, wide, order):
    from servonaut.updates.macho import macho_architectures

    path = tmp_path / "executable"
    rows = [(0x01000007, 3), (0x0100000C, 0)]
    layout = struct.Struct(order + ("IIQQII" if wide else "IIIII"))
    header = struct.pack(f"{order}II", 0xCAFEBABF if wide else 0xCAFEBABE, len(rows))
    offset = len(header) + len(rows) * layout.size
    table, slices = b"", b""
    for cpu, subtype in rows:
        thin = _thin_macho("<", cpu, subtype)
        table += layout.pack(cpu, subtype, offset + len(slices), len(thin), *([0, 0] if wide else [0]))
        slices += thin
    path.write_bytes(header + table + slices)
    assert macho_architectures(path) == {"x86_64", "arm64"}
    path.write_bytes(header + table + slices[:-1])
    with pytest.raises(ValueError, match="slice range"):
        macho_architectures(path)
    path.write_bytes(header + table + slices[:32] * 2)
    with pytest.raises(ValueError, match="does not match"):
        macho_architectures(path)


@_DARWIN
def test_darwin_bundle_process_scan_finds_an_executable(tmp_path):
    from servonaut.updates.macos_native import bundle_processes

    bundle = tmp_path.resolve() / BUNDLE_NAME
    bundle.mkdir()
    sleeper = bundle / "sleep"
    shutil.copy2("/bin/sleep", sleeper)
    with subprocess.Popen([sleeper, "10"]) as process:
        try:
            assert any(item.pid == process.pid for item in bundle_processes(bundle))
        finally:
            process.terminate()


@_DARWIN
def test_legacy_working_process_with_a_bundle_file_keeps_its_session(tmp_path):
    from servonaut.updates.macos_native import legacy_files_in_use

    bundle = tmp_path / BUNDLE_NAME
    bundle.mkdir()
    path = bundle / "runtime-data.txt"
    path.write_text("fixture")
    with path.open():
        assert legacy_files_in_use(bundle, shared=False)
    assert not legacy_files_in_use(bundle, shared=False)
