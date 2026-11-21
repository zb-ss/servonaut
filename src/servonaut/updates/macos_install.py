"""Coordinate a user-approved macOS installation and recovery."""

from __future__ import annotations

import contextlib
import errno
import json
import logging
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from servonaut.distribution.apply_policy import DesktopArtifactIdentity
from servonaut.distribution.manifest import ArtifactKind, ManifestError
from servonaut.distribution.verify import verify_file_sha256
from servonaut.runtime import DistributionKind, RuntimeLayout
from servonaut.updates.desktop_apply import (
    DESKTOP_STAGING_DIR, DesktopApplyDecision, StagedDesktopUpdate,
)
from servonaut.updates.macos_native import (
    ROLLBACK_EPOCH_KEY, bundle_processes, copy_bundle, detach_application_image, legacy_files_in_use,
    mounted_application, native_command, read_info, require_bootstrap, require_replacement_tools, validate_bundle,
)
from servonaut.updates.macos_transaction import (
    BUNDLE_NAME, WORK_NAME, BundleTransaction, DirectoryIdentity, MacUpdateError,
    SwapJournal, identity, rename_native, sync_directory,
)
from servonaut.updates.processes import UnknownProcess, birth
from servonaut.utils.atomic_file import write_json_atomic

if TYPE_CHECKING:
    from servonaut.services.update_service import UpdateService

logger = logging.getLogger(__name__)
SYSTEM_APPLICATIONS = Path("/Applications")
HELPER_FLAG = "--_macos-install-update"
INSTALL_QUIT_CODE = 76
GUIDANCE = "Open the disk image to install the update."
_BUSY = "Close other Servonaut sessions using this installation and try again."
_RECOVERY_GUIDANCE = "Servonaut could not recover the previous update. " + GUIDANCE
_QUIET_SECONDS = 20.0
_HEALTH_SECONDS = 45.0
_POLL_SECONDS = 0.2
_STAGE_RETENTION_SECONDS = 24 * 60 * 60
_ROLLBACK_RETENTION_DAYS = 14
_ROLLBACK_RETENTION_ENV = "SERVONAUT_MACOS_ROLLBACK_RETENTION_DAYS"
_RECOVERY_BACKOFF_SECONDS = (30, 120, 600)


class MacUpdateBusy(MacUpdateError):
    """A different process still has the installation open."""


def _account_applications() -> Path:
    import pwd

    return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve() / "Applications"


def _regular_owned(path: Path) -> os.stat_result:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
        or info.st_nlink != 1 or info.st_mode & 0o077
    ):
        raise MacUpdateError("The application update state is not private.")
    return info


def _read_state(path: Path) -> dict:
    _regular_owned(path)
    with path.open("rb") as stream:
        raw = stream.read(4097)
    try:
        result = json.loads(raw)
        if len(raw) > 4096 or not isinstance(result, dict):
            raise ValueError("Invalid state")
        return result
    except ValueError as exc:
        raise MacUpdateError("The application update state could not be verified.") from exc


def _has_acl(path: Path) -> bool:
    return len(native_command("/bin/ls", "-lde", path).splitlines()) != 1


def _private_dir(path: Path, *, create: bool = False) -> Path:
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    if (
        identity(path) is None or stat.S_IMODE(path.lstat().st_mode) != 0o700
        or path.resolve() != path
    ):
        raise MacUpdateError("The application update folder is not private.")
    if _has_acl(path):
        raise MacUpdateError("The application update folder has an unexpected access policy.")
    return path


@dataclass(frozen=True)
class Installation:
    """The canonical bundle and stable filesystem gate for one install."""

    bundle: Path

    @property
    def work(self) -> Path:
        return self.bundle.parent / WORK_NAME

    @property
    def helper(self) -> Path:
        return self.work / "helper" / BUNDLE_NAME

    @property
    def transaction(self) -> BundleTransaction:
        return BundleTransaction(self.bundle, self.work / "transaction")

    def validate(self) -> None:
        parent = self.bundle.parent
        if parent not in (SYSTEM_APPLICATIONS, _account_applications()):
            raise MacUpdateError(GUIDANCE)
        if self.bundle.name != BUNDLE_NAME or not self.bundle.is_absolute():
            raise MacUpdateError(GUIDANCE)
        if self.bundle.resolve(strict=True) != self.bundle or identity(self.bundle) is None:
            raise MacUpdateError(GUIDANCE)
        if self.bundle.lstat().st_mode & 0o022 or _has_acl(self.bundle):
            raise MacUpdateError(GUIDANCE)
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o002 or not os.access(parent, os.W_OK | os.X_OK):
            raise MacUpdateError(GUIDANCE)
        if parent == SYSTEM_APPLICATIONS and info.st_uid != 0:
            raise MacUpdateError(GUIDANCE)
        if parent != SYSTEM_APPLICATIONS:
            if info.st_uid != os.getuid() or info.st_mode & 0o022 or not self._private_user_domain():
                raise MacUpdateError(GUIDANCE)
        require_replacement_tools()
        require_bootstrap(self.bundle, read_info(self.bundle))

    def _private_user_domain(self) -> bool:
        parent = self.bundle.parent
        for path in (parent, parent.parent):
            info = path.lstat()
            if info.st_uid == os.getuid() and not info.st_mode & 0o011 and not _has_acl(path):
                return True
        return False

    def validate_offer(self) -> None:
        self.validate()
        if self.transaction.journal_path.is_file():
            raise MacUpdateError(_RECOVERY_GUIDANCE)

    @classmethod
    def from_runtime(cls, runtime: RuntimeLayout) -> Installation | None:
        if sys.platform != "darwin" or runtime.kind is not DistributionKind.PACKAGED_DESKTOP or not runtime.is_frozen:
            return None
        root = runtime.executable_root
        if root.name != "MacOS" or root.parent.name != "Contents":
            return None
        try:
            bundle = root.parent.parent.resolve(strict=True)
            for directory in (SYSTEM_APPLICATIONS, _account_applications()):
                canonical = directory / BUNDLE_NAME
                try:
                    if bundle.samefile(canonical):
                        return cls(canonical)
                except FileNotFoundError:
                    continue
        except (OSError, RuntimeError, KeyError, ValueError):
            return None
        return None


@contextlib.contextmanager
def _admission(installation: Installation, timeout: float = _QUIET_SECONDS) -> Iterator[None]:
    installation.validate()
    expected = identity(installation.bundle)
    parent = installation.bundle.parent
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    acquired_at = None
    try:
        _wait_until_exclusive(fd, timeout)
        acquired_at = time.monotonic()
        if not os.path.samestat(os.fstat(fd), parent.lstat()):
            raise MacUpdateError(GUIDANCE)
        if identity(installation.bundle) != expected:
            raise MacUpdateError("The application changed while obtaining exclusive access.")
        yield
    finally:
        os.close(fd)
        if acquired_at is not None:
            logger.info("Exclusive application admission held for %.3f seconds.", time.monotonic() - acquired_at)


def _require_no_consumers(installation: Installation, *, known_guarded: bool = False) -> None:
    if bundle_processes(installation.bundle):
        raise MacUpdateBusy(_BUSY)
    if not known_guarded and legacy_files_in_use(
        installation.bundle, shared=installation.bundle.parent == SYSTEM_APPLICATIONS,
    ):
        raise MacUpdateBusy(_BUSY)


def _wait_until_exclusive(fd: int, timeout: float) -> None:
    import fcntl

    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError as exc:
            if time.monotonic() >= deadline:
                raise MacUpdateBusy(_BUSY) from exc
            time.sleep(_POLL_SECONDS)


@contextlib.contextmanager
def _request_lock(installation: Installation) -> Iterator[int]:
    import fcntl

    path = installation.work / "operation.lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        if not os.path.samestat(os.fstat(fd), _regular_owned(path)):
            raise MacUpdateError("The application update lock changed.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise MacUpdateBusy("An application update is already being handled.") from exc
        yield fd
    finally:
        os.close(fd)


def _can_exchange(installation: Installation) -> None:
    """Prove the real filesystem and parent accept a same-volume exchange."""
    with tempfile.TemporaryDirectory(dir=installation.bundle.parent) as sibling:
        with tempfile.TemporaryDirectory(dir=installation.work) as private:
            rename_native(Path(sibling), Path(private), exchange=True)


def _spawn(installation: Installation, fd: int) -> None:
    executable = installation.helper / "Contents" / "MacOS" / "servonaut"
    subprocess.Popen(
        [str(executable), HELPER_FLAG, str(fd)], pass_fds=(fd,), start_new_session=True,
        cwd=installation.work, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def _quit_request_path(runtime: RuntimeLayout, pid: int) -> Path:
    return runtime.data_root / DESKTOP_STAGING_DIR / f"quit-{pid}.json"


def discard_quit_request(runtime: RuntimeLayout) -> None:
    """Discard this launcher's request when the app cannot finish quitting."""
    with contextlib.suppress(OSError, MacUpdateError):
        _private_dir(runtime.data_root / DESKTOP_STAGING_DIR)
        _quit_request_path(runtime, os.getppid()).unlink(missing_ok=True)


def _staged_request(raw: dict, runtime: RuntimeLayout) -> StagedDesktopUpdate:
    filename = raw.get("file")
    if not isinstance(filename, str) or Path(filename).name != filename or not filename.endswith(".dmg"):
        raise MacUpdateError("The application replacement request is invalid.")
    artifact = DesktopArtifactIdentity.from_dict(raw["artifact"])
    if artifact.kind is not ArtifactKind.MACOS_DMG:
        raise MacUpdateError("The update is not a macOS disk image.")
    staging = _private_dir(runtime.data_root / DESKTOP_STAGING_DIR)
    path = staging / filename
    _regular_owned(path)
    return StagedDesktopUpdate(artifact, path)


def request_on_quit(runtime: RuntimeLayout, staged: StagedDesktopUpdate) -> None:
    """Bind the user's choice to the current native launcher process."""
    _private_dir(runtime.data_root / DESKTOP_STAGING_DIR)
    pid = os.getppid()
    started = birth(pid)
    if not started:
        raise MacUpdateError("The desktop launcher could not be identified.")
    write_json_atomic(_quit_request_path(runtime, pid), {
        "started": started, "file": staged.path.name, "artifact": asdict(staged.identity),
    })


def start_on_quit(runtime: RuntimeLayout) -> None:
    """Start the signed helper only after the child accepted a normal quit."""
    installation = Installation.from_runtime(runtime)
    if installation is None:
        raise MacUpdateError(GUIDANCE)
    installation.validate()
    path = _quit_request_path(runtime, os.getpid())
    raw = _read_state(path)
    path.unlink()
    if set(raw) != {"started", "file", "artifact"} or raw["started"] != birth(os.getpid()):
        raise MacUpdateError("The application replacement request expired.")
    staged = _staged_request(raw, runtime)
    _private_dir(installation.work, create=True)
    with _request_lock(installation) as fd:
        if installation.transaction.journal_path.exists():
            raise MacUpdateError("An earlier application update is waiting for recovery.")
        _private_dir(installation.helper.parent, create=True)
        if os.path.lexists(installation.helper):
            if identity(installation.helper) is None:
                raise MacUpdateError("The previous helper could not be identified.")
            shutil.rmtree(installation.helper)
        team = validate_bundle(installation.bundle)
        copy_bundle(installation.bundle, installation.helper)
        validate_bundle(installation.helper, expected_team=team)
        write_json_atomic(installation.work / "request.json", {
            "file": staged.path.name, "artifact": asdict(staged.identity), "team": team,
        })
        _spawn(installation, fd)


def _get_request(runtime: RuntimeLayout, work: Path) -> tuple[StagedDesktopUpdate, str]:
    raw = _read_state(work / "request.json")
    team = raw.get("team")
    if set(raw) != {"file", "artifact", "team"} or not isinstance(team, str):
        raise MacUpdateError("The application replacement request is invalid.")
    return _staged_request(raw, runtime), team


def _prepare_candidate(
    installation: Installation, staged: StagedDesktopUpdate, team: str,
) -> DirectoryIdentity:
    tx = installation.transaction
    if tx.journal_path.exists():
        raise MacUpdateError("An earlier application update is waiting for recovery.")
    if os.path.lexists(tx.work):
        _private_dir(tx.work)
        detach_application_image(tx.work / "image")
        shutil.rmtree(tx.work)
    _private_dir(tx.work, create=True)
    before = _regular_owned(staged.path)
    if not verify_file_sha256(staged.path, staged.identity.sha256):
        raise MacUpdateError("The disk image did not match the verified download.")
    with mounted_application(staged.path, tx.work / "image") as source:
        copy_bundle(source, tx.incoming, image=staged.path)
    after = _regular_owned(staged.path)
    if not os.path.samestat(before, after) or before.st_mtime_ns != after.st_mtime_ns:
        raise MacUpdateError("The staged disk image changed during preparation.")
    prepared = identity(tx.incoming)
    validate_bundle(tx.incoming, expected_team=team, artifact=staged.identity)
    if read_info(tx.incoming)[ROLLBACK_EPOCH_KEY] != read_info(installation.bundle)[ROLLBACK_EPOCH_KEY]:
        raise MacUpdateError(GUIDANCE)
    if prepared is None or identity(tx.incoming) != prepared:
        raise MacUpdateError("The verified application changed during preparation.")
    return prepared


def _confirmed_installation(installation: Installation) -> tuple[DirectoryIdentity | None, DirectoryIdentity | None]:
    try:
        result = _read_state(installation.work / "previous.json")
    except FileNotFoundError:
        return None, None

    def parse(raw: object) -> DirectoryIdentity:
        if not isinstance(raw, dict) or set(raw) != {"device", "inode"}:
            raise MacUpdateError("The previous application record is invalid.")
        if any(type(value) is not int or value <= 0 for value in raw.values()):
            raise MacUpdateError("The previous application record is invalid.")
        return DirectoryIdentity(**raw)

    if set(result) != {"current", "previous"}:
        raise MacUpdateError("The previous application record is invalid.")
    previous = result["previous"]
    return parse(result["current"]), None if previous is None else parse(previous)



def _launch(bundle: Path) -> None:
    native_command("/usr/bin/open", "-a", bundle)


def _health_path(installation: Installation) -> Path:
    return installation.transaction.work / "healthy.json"


def _owned_installation(runtime: RuntimeLayout) -> Installation | None:
    installation = Installation.from_runtime(runtime)
    if installation is None or installation.bundle.lstat().st_uid != os.getuid():
        return None
    return installation


def acknowledge_startup(runtime: RuntimeLayout) -> None:
    """Called by the child after the native browser has authenticated and rendered."""
    try:
        installation = _owned_installation(runtime)
        if installation is None or not installation.transaction.journal_path.is_file():
            return
        _private_dir(installation.work)
        _private_dir(installation.transaction.work)
        journal = SwapJournal.read(installation.transaction.journal_path)
        if identity(installation.bundle) == journal.new:
            write_json_atomic(_health_path(installation), asdict(journal.new))
    except (OSError, MacUpdateError) as exc:
        logger.debug("Could not acknowledge application update for this account (%s).", type(exc).__name__)


def _healthy(installation: Installation, journal: SwapJournal) -> bool:
    try:
        return _read_state(_health_path(installation)) == asdict(journal.new)
    except FileNotFoundError:
        return False


def _confirm(installation: Installation, journal: SwapJournal) -> None:
    tx = installation.transaction
    if identity(tx.installed) != journal.new or identity(tx.previous) != journal.old:
        raise MacUpdateError("The installed application or its rollback changed.")
    if identity(tx.archived) == journal.archived_previous and journal.archived_previous is not None:
        shutil.rmtree(tx.archived)
    elif identity(tx.archived) is not None:
        raise MacUpdateError("The earlier previous application changed.")
    _record_confirmation(installation, journal, journal.old)


def _record_confirmation(
    installation: Installation, journal: SwapJournal, previous: DirectoryIdentity | None,
) -> None:
    tx = installation.transaction
    write_json_atomic(installation.work / "previous.json", {
        "current": asdict(journal.new), "previous": asdict(previous) if previous else None,
    })
    sync_directory(installation.work)
    tx.journal_path.unlink()
    sync_directory(tx.work)


def _finish_launch(installation: Installation, journal: SwapJournal) -> None:
    try:
        _launch(installation.bundle)
    except MacUpdateError:
        logger.info("Launch Services did not start the replacement.")
    deadline = time.monotonic() + _HEALTH_SECONDS
    while time.monotonic() < deadline:
        if _healthy(installation, journal):
            _confirm(installation, journal)
            return
        time.sleep(_POLL_SECONDS)
    try:
        with _admission(installation, timeout=0):
            if _healthy(installation, journal):
                _confirm(installation, journal)
                return
            _require_no_consumers(installation, known_guarded=True)
            installation.transaction.rollback(journal)
    except MacUpdateBusy:
        logger.info("The replacement is still running. Application health can be confirmed later.")
        return
    with contextlib.suppress(OSError):
        _record(installation, "The update could not start. Servonaut restored the previous version.")
    _launch(installation.bundle)


def _recover(installation: Installation) -> None:
    tx = installation.transaction
    journal = SwapJournal.read(tx.journal_path)
    if _healthy(installation, journal) and identity(tx.previous) == journal.old:
        _confirm(installation, journal)
        return
    missing_previous = (
        identity(tx.installed) == journal.new and identity(tx.previous) is None and identity(tx.incoming) is None
    )
    if missing_previous:
        validate_bundle(tx.installed)
    observed = identity(installation.bundle)
    if observed != journal.new and legacy_files_in_use(
        installation.bundle, shared=installation.bundle.parent == SYSTEM_APPLICATIONS,
    ):
        raise MacUpdateBusy(_BUSY)
    with _admission(installation):
        current = identity(installation.bundle)
        if current != observed:
            raise MacUpdateError("The application changed while obtaining exclusive access.")
        _require_no_consumers(installation, known_guarded=True)
        if missing_previous and current == journal.new and identity(tx.previous) is None and identity(tx.incoming) is None:
            _record(installation, "The rollback copy is missing. " + GUIDANCE)
            _record_confirmation(installation, journal, None)
        elif _healthy(installation, journal):
            tx.file_previous(journal)
            _confirm(installation, journal)
        else:
            tx.rollback(journal)


def recover_after_quit(runtime: RuntimeLayout) -> None:
    """Retry an interrupted transaction when no other helper holds it."""
    try:
        installation = _owned_installation(runtime)
        if installation is None or not installation.transaction.journal_path.is_file():
            return
        _private_dir(installation.work)
        with _request_lock(installation) as fd:
            if _recovery_marker(installation).is_file():
                return
            try:
                _, retry_at = _read_recovery_retry(installation)
                if time.time_ns() < retry_at:
                    return
                validate_bundle(installation.helper, expected_team=validate_bundle(installation.bundle))
                (installation.work / "request.json").unlink(missing_ok=True)
                _spawn(installation, fd)
            except (OSError, MacUpdateError) as error:
                _record_recovery_failure(installation, error)
    except (OSError, MacUpdateError):
        logger.debug("Application update recovery will wait for a later quiet window.")


def _record(installation: Installation, message: str) -> None:
    write_json_atomic(installation.work / "result.json", {"message": message})


def _recovery_marker(installation: Installation) -> Path:
    return installation.transaction.work / "recovery-deferred.json"


def _recovery_retry_path(installation: Installation) -> Path:
    return installation.transaction.work / "recovery-retry.json"


def _read_recovery_retry(installation: Installation) -> tuple[int, int]:
    try:
        state = _read_state(_recovery_retry_path(installation))
    except FileNotFoundError:
        return 0, 0
    attempts, retry_at = state.get("attempts"), state.get("retry_at_ns")
    if type(attempts) is not int or attempts < 0 or type(retry_at) is not int or retry_at < 0:
        raise MacUpdateError("The application recovery retry state could not be verified.")
    return attempts, retry_at


def _record_recovery_failure(installation: Installation, error: Exception | None = None) -> None:
    marker = _recovery_marker(installation)
    try:
        if marker.is_file():
            return
        if isinstance(error, MacUpdateBusy) or (
            isinstance(error, OSError) and error.errno in (errno.EAGAIN, errno.EBUSY, errno.ETIMEDOUT)
        ):
            attempts, _ = _read_recovery_retry(installation)
            if attempts < len(_RECOVERY_BACKOFF_SECONDS):
                delay = _RECOVERY_BACKOFF_SECONDS[attempts]
                write_json_atomic(_recovery_retry_path(installation), {
                    "attempts": attempts + 1, "retry_at_ns": time.time_ns() + delay * 1_000_000_000,
                })
                logger.debug("Application recovery deferred for %d seconds.", delay)
                return
        _record(installation, _RECOVERY_GUIDANCE)
        write_json_atomic(marker, {"recovery": "guided"})
    except (OSError, MacUpdateError):
        logger.debug("Could not save application recovery status.")


def consume_result(runtime: RuntimeLayout) -> str | None:
    try:
        installation = _owned_installation(runtime)
        if installation is None:
            return None
        _private_dir(installation.work)
        result = installation.work / "result.json"
        message = _read_state(result).get("message")
        result.unlink()
        return message if isinstance(message, str) else None
    except (OSError, MacUpdateError):
        return None


def _sweep_stage(runtime: RuntimeLayout) -> None:
    directory = _private_dir(runtime.data_root / DESKTOP_STAGING_DIR)
    cutoff = time.time() - _STAGE_RETENTION_SECONDS
    for path in directory.iterdir():
        try:
            info = _regular_owned(path)
            if path.suffix == ".dmg" and len(path.stem) == 64 and info.st_mtime < cutoff:
                path.unlink()
            elif path.name.startswith("quit-") and path.suffix == ".json":
                pid = int(path.stem.removeprefix("quit-"))
                if _read_state(path).get("started") != birth(pid):
                    path.unlink()
        except (OSError, MacUpdateError, ValueError):
            continue


def _retire_manually_replaced_bundle(installation: Installation, tx: BundleTransaction) -> bool:
    if not _recovery_marker(installation).is_file():
        return False
    journal = SwapJournal.read(tx.journal_path)
    current = identity(installation.bundle)
    if current is None or current in (journal.old, journal.new):
        return False
    validate_bundle(installation.bundle, expected_team=validate_bundle(installation.helper))
    if identity(installation.bundle) != current:
        return False
    previous = identity(tx.previous)
    if previous is not None and previous in (journal.old, journal.new, journal.archived_previous):
        shutil.rmtree(tx.previous)
    tx.journal_path.unlink()
    sync_directory(tx.work)
    return True


def _retire_expired_backup(installation: Installation, tx: BundleTransaction) -> None:
    current, previous = _confirmed_installation(installation)
    if current != identity(installation.bundle) or previous is None or identity(tx.previous) != previous:
        return
    try:
        days = int(os.environ.get(_ROLLBACK_RETENTION_ENV, str(_ROLLBACK_RETENTION_DAYS)))
    except ValueError:
        days = _ROLLBACK_RETENTION_DAYS
    if days < 1:
        days = _ROLLBACK_RETENTION_DAYS
    confirmed_at = _regular_owned(installation.work / "previous.json").st_mtime_ns
    retention = days * 24 * 60 * 60 * 1_000_000_000
    if time.time_ns() - confirmed_at >= retention:
        shutil.rmtree(tx.previous)


def sweep_startup(runtime: RuntimeLayout) -> None:
    """Retire this owner's known leftovers when no replacement is in progress."""
    try:
        installation = _owned_installation(runtime)
        if installation is None:
            return
        if not os.path.lexists(installation.work):
            _sweep_stage(runtime)
            return
        _private_dir(installation.work)
        with _request_lock(installation):
            tx = installation.transaction
            transaction_exists = os.path.lexists(tx.work)
            if transaction_exists:
                _private_dir(tx.work)
                if tx.journal_path.is_file() and not _retire_manually_replaced_bundle(installation, tx):
                    return
            _retire_expired_backup(installation, tx)
            if transaction_exists:
                detach_application_image(tx.work / "image")
                shutil.rmtree(tx.work)
            if identity(installation.helper) is not None:
                shutil.rmtree(installation.helper)
            _sweep_stage(runtime)
    except (OSError, MacUpdateError, KeyError, ValueError):
        logger.debug("Application update cleanup will wait for a later startup.")


def _replace(installation: Installation, runtime: RuntimeLayout, update: UpdateService) -> None:
    staged, team = _get_request(runtime, installation.work)
    validate_bundle(installation.helper, expected_team=team)
    prepared = _prepare_candidate(installation, staged, team)
    tx = installation.transaction
    _can_exchange(installation)
    evidence = update.prepare_staged_desktop_apply(staged)
    if evidence is DesktopApplyDecision.DENIED:
        with contextlib.suppress(OSError, MacUpdateError):
            if identity(tx.incoming) == prepared:
                shutil.rmtree(tx.incoming)
        raise MacUpdateError("The signed update policy rejected the download. Check again for an available release.")
    if evidence is DesktopApplyDecision.DEFERRED:
        raise MacUpdateError(update.update_guidance or "Servonaut could not authorize automatic installation.")
    current, previous = _confirmed_installation(installation)
    installed = identity(installation.bundle)
    if current != installed and legacy_files_in_use(installation.bundle, shared=installation.bundle.parent == SYSTEM_APPLICATIONS):
        raise MacUpdateBusy(_BUSY)
    with _admission(installation):
        if identity(installation.bundle) != installed or identity(tx.incoming) != prepared:
            raise MacUpdateError("The installed or staged application changed.")
        journal = tx.prepare(previous)
        try:
            if not evidence.is_current():
                raise MacUpdateError(update.update_guidance or "Servonaut could not authorize automatic installation.")
            _require_no_consumers(installation, known_guarded=True)
            tx.commit(journal)
        except (OSError, MacUpdateError):
            with contextlib.suppress(OSError, MacUpdateError):
                tx.rollback(journal)
            raise
    if update.update_guidance:
        with contextlib.suppress(OSError):
            _record(installation, update.update_guidance)
    _finish_launch(installation, journal)
    if not tx.journal_path.exists() and identity(installation.bundle) == journal.new:
        with contextlib.suppress(OSError, MacUpdateError):
            _regular_owned(staged.path)
            staged.path.unlink()


def run_helper(runtime: RuntimeLayout, argument: str) -> int:
    """Enter only from the private signed helper with its inherited operation lock."""
    if sys.platform != "darwin" or not runtime.is_frozen or runtime.kind is not DistributionKind.PACKAGED_DESKTOP:
        return 1
    helper = runtime.executable_root.parent.parent.resolve()
    work = helper.parent.parent
    installation = Installation(work.parent / BUNDLE_NAME)
    try:
        import fcntl

        if helper != installation.helper or work != installation.work:
            raise MacUpdateError("The application update helper is in an unexpected location.")
        installation.validate()
        _private_dir(work)
        fd = int(argument)
        if fd < 3 or not os.path.samestat(os.fstat(fd), _regular_owned(work / "operation.lock")):
            raise MacUpdateError("The application update operation lock is invalid.")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, MacUpdateError, ValueError, UnknownProcess):
        return 1
    # Keep the inherited descriptor open for the helper process lifetime.
    os.set_inheritable(fd, False)
    from servonaut.utils.logging_setup import configure_rotating_log

    log_path = work / "helper.log"
    if not log_path.is_symlink():
        configure_rotating_log(work, filename=log_path.name, warn_on_failure=False)
    recovery = True
    try:
        request = work / "request.json"
        if installation.transaction.journal_path.is_file():
            _recover(installation)
        elif request.is_file():
            recovery = False
            from servonaut.services.update_service import UpdateService

            _replace(installation, runtime, UpdateService(runtime))
        request.unlink(missing_ok=True)
        return 0
    except (OSError, MacUpdateError, ManifestError, ValueError) as exc:
        logger.warning("Automatic application installation was deferred (%s).", type(exc).__name__)
        with contextlib.suppress(OSError):
            (work / "request.json").unlink(missing_ok=True)
        if recovery:
            _record_recovery_failure(installation, exc)
            return 1
        detail = str(exc) if isinstance(exc, MacUpdateError) else GUIDANCE
        with contextlib.suppress(OSError):
            _record(installation, detail)
        with contextlib.suppress(OSError, MacUpdateError):
            _launch(installation.bundle)
        return 1
