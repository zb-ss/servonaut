"""Tests for the managed voice runtime provisioner.

Provisioning runs against ``fake_uv.py``, a stand-in for the bundled uv
executable that creates real virtual environments from the test interpreter,
so the smoke test starts the real voice worker from this source tree. Nothing
touches the network.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import site
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import pytest

import servonaut
from servonaut.desktop.voice import release_lock
from servonaut.desktop.voice import runtime as runtime_module
from servonaut.desktop.voice.protocol import VOICE_PROTOCOL_VERSION
from servonaut.desktop.voice.runtime import (
    VoiceRuntimeCancelledError,
    VoiceRuntimeCommandError,
    VoiceRuntimeError,
    VoiceRuntimeIntegrityError,
    VoiceRuntimeLock,
    VoiceRuntimeLockError,
    VoiceRuntimeManager,
    VoiceRuntimeManifest,
    VoiceRuntimeNotReadyError,
    VoiceRuntimeSmokeError,
    VoiceRuntimeState,
    VoiceRuntimeTimeoutError,
    VoiceRuntimeUnavailableError,
    compute_runtime_id,
)
from servonaut.runtime import (
    DistributionKind,
    PackageManagementCapability,
    PackageManagementKind,
    RuntimeLayout,
)

FAKE_UV = Path(__file__).with_name("fake_uv.py")
POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="the fake uv is a POSIX shell wrapper")
# The smoke test starts the worker from this source tree, which reports its
# own version; the product version must match it.
PRODUCT_VERSION = servonaut.__version__
DEFAULT_TIMEOUTS = {"uv_command_seconds": 30, "stall_seconds": 10, "provision_seconds": 120}
POLLUTED_ENV = {
    "PYTHONPATH": "/nonexistent/pythonpath",
    "VIRTUAL_ENV": "/nonexistent/venv",
    "UV_INDEX_URL": "https://index.invalid/simple",
    "PIP_INDEX_URL": "https://index.invalid/simple",
    "UV_PYTHON_INSTALL_DIR": "/nonexistent/python",
    "AWS_SECRET_ACCESS_KEY": "not-a-real-secret",
    "LD_LIBRARY_PATH": "/nonexistent/lib",
    "HTTPS_PROXY": "http://proxy.invalid:3128",
}
ENGINE_STUBS = {
    "numpy.py": "",
    "faster_whisper/__init__.py": "",
    "sherpa_onnx.py": "",
    "sounddevice.py": (
        "import json, os, pathlib\n"
        "pathlib.Path(__file__).parent.parent.joinpath('smoke-env.json')"
        ".write_text(json.dumps(sorted(os.environ)))\n\n"
        "def query_devices():\n    return []\n\n"
        "class _Default:\n    device = (None, None)\n\n"
        "default = _Default()\n"
    ),
}


def _layout(
    tmp_path: Path,
    kind: DistributionKind = DistributionKind.PACKAGED_DESKTOP,
    product_version: str = PRODUCT_VERSION,
) -> RuntimeLayout:
    return RuntimeLayout(
        kind=kind,
        product_version=product_version,
        build_revision=None,
        resource_root=tmp_path / "resources",
        executable_root=tmp_path / "app",
        data_root=tmp_path / "data",
        executable=tmp_path / "app" / "servonaut-desktop",
        python_executable=None,
        path_console=None,
        console_helper=tmp_path / "app" / "servonaut",
        desktop_child=None,
        package_management=PackageManagementCapability(
            kind=PackageManagementKind.UNSUPPORTED,
            argv_prefix=(),
            allows_automatic_mutation=False,
        ),
        is_frozen=True,
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _venv_python(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


@dataclass
class VoiceBundle:
    """A fake desktop voice payload plus the control directory of the fake uv."""

    tmp_path: Path
    layout: RuntimeLayout = field(init=False)
    voice_dir: Path = field(init=False)
    control: Path = field(init=False)

    def __post_init__(self) -> None:
        self.layout = _layout(self.tmp_path)
        self.voice_dir = self.layout.resource_root / "voice"
        self.control = self.tmp_path / "fake-uv"
        self.voice_dir.mkdir(parents=True)
        self.control.mkdir()
        self._write_payload()
        self._write_control()
        self.write_manifest()

    @property
    def uv(self) -> Path:
        return self.voice_dir / "uv"

    @property
    def requirements(self) -> Path:
        return self.voice_dir / "voice-requirements.txt"

    @property
    def wheel(self) -> Path:
        return self.voice_dir / f"servonaut-{PRODUCT_VERSION}-py3-none-any.whl"

    def write_manifest(self, **overrides: Any) -> None:
        document = {
            "schema_version": 1,
            "target": "test-target",
            "python_version": "3.12.7",
            "uv": {"filename": "uv", "sha256": _sha256(self.uv)},
            "wheel": {"filename": self.wheel.name, "sha256": _sha256(self.wheel)},
            "requirements": {
                "filename": self.requirements.name,
                "sha256": _sha256(self.requirements),
            },
            "timeouts": dict(DEFAULT_TIMEOUTS),
        }
        document.update(overrides)
        (self.voice_dir / "voice-runtime.json").write_text(json.dumps(document), encoding="utf-8")

    def manager(self, product_version: str = PRODUCT_VERSION) -> VoiceRuntimeManager:
        layout = _layout(self.tmp_path, product_version=product_version)
        manager = VoiceRuntimeManager.for_runtime(layout)
        assert manager is not None
        return manager

    def behave(self, **behavior: Any) -> None:
        (self.control / "behavior.json").write_text(json.dumps(behavior), encoding="utf-8")

    def calls(self) -> list[dict[str, Any]]:
        path = self.control / "calls.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    def commands(self) -> list[str]:
        return [call["command"] for call in self.calls()]

    def pid(self, name: str) -> int:
        return int((self.control / name).read_text(encoding="utf-8"))

    def _write_payload(self) -> None:
        self.uv.write_text(
            "#!/bin/sh\n"
            f"FAKE_UV_CONTROL='{self.control}' exec '{sys.executable}' '{FAKE_UV}' \"$@\"\n",
            encoding="utf-8",
        )
        self.uv.chmod(0o755)
        self.requirements.write_text(
            "sherpa-onnx==1.0.0 --hash=sha256:" + "0" * 64 + "\n", encoding="utf-8"
        )
        self.wheel.write_bytes(b"not really a wheel")

    def _write_control(self) -> None:
        source_root = Path(servonaut.__file__).resolve().parents[1]
        import_paths = [path for path in site.getsitepackages() if Path(path).is_dir()]
        config = {"src": str(source_root), "paths": import_paths}
        (self.control / "config.json").write_text(json.dumps(config), encoding="utf-8")
        for relative, content in ENGINE_STUBS.items():
            stub = self.control / "engines" / relative
            stub.parent.mkdir(parents=True, exist_ok=True)
            stub.write_text(content, encoding="utf-8")


@pytest.fixture
def bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> VoiceBundle:
    # A packaged desktop build is frozen; this also keeps the process-tree
    # helper from adding the development source path to child environments.
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    for name, value in POLLUTED_ENV.items():
        monkeypatch.setenv(name, value)
    return VoiceBundle(tmp_path)


def install_synthetic_release(
    manager: VoiceRuntimeManager,
    *,
    runtime_id: Optional[str] = None,
    protocol_version: int = VOICE_PROTOCOL_VERSION,
) -> VoiceRuntimeManifest:
    """Record an installed release without provisioning one."""
    runtime_id = runtime_id or manager.expected_runtime_id
    python = _venv_python(manager.runtime_dir / "releases" / runtime_id / "venv")
    python.parent.mkdir(parents=True)
    python.write_text("", encoding="utf-8")
    record = VoiceRuntimeManifest(
        runtime_id=runtime_id,
        release=runtime_id,
        python_version="3.12.7",
        lock_sha256="a" * 64,
        wheel_sha256="b" * 64,
        product_version="1.0.0",
        protocol_version=protocol_version,
        created_at="2026-01-01T00:00:00+00:00",
    )
    (manager.runtime_dir / "current.json").write_bytes(record.to_json())
    return record


def _snapshot(manager: VoiceRuntimeManager) -> tuple[bytes, list[str]]:
    current = (manager.runtime_dir / "current.json").read_bytes()
    releases = sorted(path.name for path in (manager.runtime_dir / "releases").iterdir())
    return current, releases


def _releases(manager: VoiceRuntimeManager) -> list[str]:
    return sorted(path.name for path in (manager.runtime_dir / "releases").iterdir())


def _staging_entries(manager: VoiceRuntimeManager) -> list[Path]:
    staging = manager.runtime_dir / "staging"
    return list(staging.iterdir()) if staging.exists() else []


def _process_gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    stat = Path(f"/proc/{pid}/stat")
    return stat.exists() and stat.read_text().split(") ", 1)[1].startswith("Z")


def _wait_until_gone(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _process_gone(pid):
            return True
        time.sleep(0.05)
    return False


def _wait_for(path: Path, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        assert time.monotonic() < deadline, f"{path.name} never appeared"
        time.sleep(0.05)


# ---------------------------------------------------------------------------
# Construction and identity
# ---------------------------------------------------------------------------


class TestForRuntime:
    @pytest.mark.parametrize(
        "kind",
        [
            DistributionKind.SOURCE,
            DistributionKind.PIP,
            DistributionKind.PIPX,
            DistributionKind.FROZEN_CLI,
        ],
    )
    def test_other_distributions_keep_voice_in_process(
        self, tmp_path: Path, kind: DistributionKind
    ) -> None:
        assert VoiceRuntimeManager.for_runtime(_layout(tmp_path, kind)) is None

    def test_packaged_desktop_without_a_voice_payload_is_unavailable(self, tmp_path: Path) -> None:
        with pytest.raises(VoiceRuntimeUnavailableError, match="cannot install voice"):
            VoiceRuntimeManager.for_runtime(_layout(tmp_path))

    def test_packaged_desktop_with_an_invalid_manifest_is_unavailable(
        self, bundle: VoiceBundle
    ) -> None:
        bundle.write_manifest(schema_version=2)

        with pytest.raises(VoiceRuntimeUnavailableError):
            bundle.manager()

    def test_layout_lives_under_the_data_root(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager()

        assert manager.runtime_dir == bundle.layout.data_root / "runtimes" / "voice"
        assert manager.models_root == bundle.layout.data_root / "voice_models"
        assert manager.packaged_manifest.python_version == "3.12.7"


class TestRuntimeId:
    BASE: dict[str, Any] = {
        "product_version": "2.30.0",
        "protocol_version": 1,
        "target": "linux-x64",
        "python_version": "3.12.7",
        "lock_sha256": "a" * 64,
        "wheel_sha256": "b" * 64,
    }

    def test_is_deterministic_and_readable(self) -> None:
        runtime_id = compute_runtime_id(**self.BASE)

        assert runtime_id == compute_runtime_id(**self.BASE)
        assert runtime_id.startswith("v2.30.0-")
        assert len(runtime_id.rsplit("-", 1)[1]) == 16

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("product_version", "2.30.1"),
            ("protocol_version", 2),
            ("target", "windows-x64"),
            ("python_version", "3.12.8"),
            ("lock_sha256", "c" * 64),
            ("wheel_sha256", "d" * 64),
        ],
    )
    def test_changes_with_every_input(self, name: str, value: object) -> None:
        assert compute_runtime_id(**{**self.BASE, name: value}) != compute_runtime_id(**self.BASE)

    def test_unsafe_version_characters_are_replaced(self) -> None:
        runtime_id = compute_runtime_id(**{**self.BASE, "product_version": "2.30.0+local/../x"})

        assert "/" not in runtime_id and "+" not in runtime_id


# ---------------------------------------------------------------------------
# Status (cheap, no subprocess)
# ---------------------------------------------------------------------------


@pytest.fixture
def no_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("status() must not start a process")

    monkeypatch.setattr(subprocess.Popen, "__init__", refuse)


class TestStatus:
    def test_not_installed(self, bundle: VoiceBundle, no_subprocess: None) -> None:
        status = bundle.manager().status()

        assert status.state is VoiceRuntimeState.NOT_INSTALLED
        assert not status.is_usable
        assert not (bundle.layout.data_root / "runtimes").exists()

    def test_ready(self, bundle: VoiceBundle, no_subprocess: None) -> None:
        manager = bundle.manager()
        record = install_synthetic_release(manager)

        status = manager.status()

        assert status.state is VoiceRuntimeState.READY
        assert status.is_ready and status.is_usable
        assert status.installed == record
        assert status.expected_runtime_id == manager.expected_runtime_id

    def test_update_available(self, bundle: VoiceBundle, no_subprocess: None) -> None:
        install_synthetic_release(bundle.manager(product_version="9.9.8"))

        status = bundle.manager().status()

        assert status.state is VoiceRuntimeState.UPDATE_AVAILABLE
        assert status.is_usable and not status.is_ready

    def test_installing_while_the_lock_is_held(
        self, bundle: VoiceBundle, no_subprocess: None
    ) -> None:
        manager = bundle.manager()
        install_synthetic_release(manager)
        with VoiceRuntimeLock(manager.runtime_dir / "lock", timeout=0.0):
            assert manager.status().state is VoiceRuntimeState.INSTALLING
        assert manager.status().state is VoiceRuntimeState.READY

    def test_broken_when_the_release_is_missing(
        self, bundle: VoiceBundle, no_subprocess: None
    ) -> None:
        manager = bundle.manager()
        record = install_synthetic_release(manager)
        _venv_python(manager.runtime_dir / "releases" / record.release / "venv").unlink()

        assert manager.status().state is VoiceRuntimeState.BROKEN

    def test_broken_when_the_protocol_changed(
        self, bundle: VoiceBundle, no_subprocess: None
    ) -> None:
        manager = bundle.manager()
        install_synthetic_release(manager, protocol_version=VOICE_PROTOCOL_VERSION + 1)

        status = manager.status()

        assert status.state is VoiceRuntimeState.BROKEN
        assert "repair" in status.message

    @pytest.mark.parametrize(
        "damage",
        [
            lambda document: "{not json",
            lambda document: json.dumps({**document, "extra": 1}),
            lambda document: json.dumps({**document, "schema_version": True}),
            lambda document: json.dumps({**document, "release": "../../elsewhere"}),
            lambda document: json.dumps({**document, "protocol_version": "1"}),
            lambda document: json.dumps({**document, "lock_sha256": "nope"}),
            lambda document: " " * (64 * 1024 + 1),
        ],
    )
    def test_broken_when_current_json_is_damaged(
        self, bundle: VoiceBundle, no_subprocess: None, damage: Any
    ) -> None:
        manager = bundle.manager()
        install_synthetic_release(manager)
        current = manager.runtime_dir / "current.json"
        current.write_text(damage(json.loads(current.read_text())), encoding="utf-8")

        status = manager.status()

        assert status.state is VoiceRuntimeState.BROKEN
        assert status.installed is None

    def test_worker_command_for_ready_and_update_available(
        self, bundle: VoiceBundle, no_subprocess: None
    ) -> None:
        old = bundle.manager(product_version="9.9.8")
        record = install_synthetic_release(old)
        manager = bundle.manager()
        assert manager.status().state is VoiceRuntimeState.UPDATE_AVAILABLE

        argv = manager.get_worker_cmd()

        release = manager.runtime_dir / "releases" / record.release
        assert argv == [
            str(_venv_python(release / "venv")),
            "-I",
            "-m",
            "servonaut.desktop.voice.release_lock",
            "--hold",
            str(release / ".in-use"),
            "--",
            "--models-root",
            str(manager.models_root),
            "--manifest-id",
            record.runtime_id,
        ]
        assert old.get_worker_cmd() == argv

    @pytest.mark.parametrize("prepare", ["not-installed", "broken", "installing"])
    def test_worker_command_refused_when_unusable(
        self, bundle: VoiceBundle, no_subprocess: None, prepare: str
    ) -> None:
        manager = bundle.manager()
        lock = VoiceRuntimeLock(manager.runtime_dir / "lock", timeout=0.0)
        if prepare == "broken":
            install_synthetic_release(manager, protocol_version=0)
        if prepare == "installing":
            install_synthetic_release(manager)
            lock.acquire()
        try:
            with pytest.raises(VoiceRuntimeNotReadyError):
                manager.get_worker_cmd()
        finally:
            lock.release()


# ---------------------------------------------------------------------------
# Provisioning
# ---------------------------------------------------------------------------


@POSIX_ONLY
class TestProvision:
    def test_installs_to_ready(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager()
        progress: list[tuple[str, int, int]] = []

        status = manager.provision(progress=lambda *update: progress.append(update))

        assert status.state is VoiceRuntimeState.READY
        record = status.installed
        assert record is not None
        assert record.release == record.runtime_id == manager.expected_runtime_id
        assert record.product_version == PRODUCT_VERSION
        assert record.protocol_version == VOICE_PROTOCOL_VERSION
        assert record.python_version == "3.12.7"
        assert record.lock_sha256 == _sha256(bundle.requirements)
        assert record.wheel_sha256 == _sha256(bundle.wheel)
        assert _staging_entries(manager) == []
        assert [count for _, count, _ in progress] == list(range(9))
        assert {total for _, _, total in progress} == {8}
        assert manager.get_worker_cmd()[0] == str(status.python_executable)

    def test_runs_the_pinned_commands(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager()
        manager.provision()

        calls = bundle.calls()
        staging_venv = Path(calls[1]["argv"][-1])
        venv_python = str(_venv_python(staging_venv))
        inputs = staging_venv.parent / "inputs"
        assert [call["argv"] for call in calls] == [
            ["python", "install", "3.12.7"],
            ["venv", "--python", "3.12.7", str(staging_venv)],
            [
                "pip", "install", "--python", venv_python, "--require-hashes",
                "--only-binary", ":all:", "--no-deps", "-r",
                str(inputs / bundle.requirements.name),
            ],
            [
                "pip", "install", "--python", venv_python, "--no-deps", "--no-index",
                str(inputs / bundle.wheel.name),
            ],
        ]
        assert staging_venv.parent.parent == manager.runtime_dir / "staging"
        release = manager.runtime_dir / "releases" / manager.expected_runtime_id
        assert not (release / "inputs").exists()

    def test_children_get_a_scrubbed_environment(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager()
        manager.provision()

        for call in bundle.calls():
            env = call["env"]
            assert env["UV_PYTHON_INSTALL_DIR"] == str(manager.runtime_dir / "python")
            assert env["UV_CACHE_DIR"] == str(manager.runtime_dir / "cache")
            assert env["UV_NO_CONFIG"] == "1"
            assert env["UV_PYTHON_PREFERENCE"] == "only-managed"
            assert env["UV_PYTHON_DOWNLOADS"] == "automatic"
            assert env["UV_PYTHON_INSTALL_BIN"] == "0"
            for name in (
                "PYTHONPATH", "VIRTUAL_ENV", "UV_INDEX_URL", "PIP_INDEX_URL",
                "AWS_SECRET_ACCESS_KEY", "LD_LIBRARY_PATH",
            ):
                assert name not in env
            assert env["HTTPS_PROXY"] == POLLUTED_ENV["HTTPS_PROXY"]

    def test_smoke_test_runs_with_the_worker_environment(self, bundle: VoiceBundle) -> None:
        bundle.manager().provision()

        smoke_env = json.loads((bundle.control / "smoke-env.json").read_text(encoding="utf-8"))
        for name in ("AWS_SECRET_ACCESS_KEY", "LD_LIBRARY_PATH", "PYTHONPATH"):
            assert name not in smoke_env
        assert "PYTHONUNBUFFERED" in smoke_env
        # The worker fetches Whisper weights itself, so it keeps the proxy.
        assert "HTTPS_PROXY" in smoke_env

    def test_provision_is_a_no_op_when_ready(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager()
        manager.provision()
        calls_before = len(bundle.calls())

        assert manager.provision().state is VoiceRuntimeState.READY
        assert len(bundle.calls()) == calls_before

    def test_update_keeps_only_the_previous_release(self, bundle: VoiceBundle) -> None:
        oldest = install_synthetic_release(bundle.manager(product_version="9.9.7"))
        previous = install_synthetic_release(bundle.manager(product_version="9.9.8"))
        manager = bundle.manager()

        status = manager.provision()

        assert status.state is VoiceRuntimeState.READY
        assert _releases(manager) == sorted([previous.release, manager.expected_runtime_id])
        assert oldest.release not in _releases(manager)

    def test_stale_staging_is_swept(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager()
        stale = manager.runtime_dir / "staging" / "interrupted"
        (stale / "venv").mkdir(parents=True)

        manager.provision()

        assert not stale.exists()

    def test_refused_while_another_operation_holds_the_lock(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager()
        with VoiceRuntimeLock(manager.runtime_dir / "lock", timeout=0.0):
            with pytest.raises(VoiceRuntimeLockError, match="already in progress"):
                manager.provision()
        assert bundle.calls() == []


@POSIX_ONLY
class TestIntegrity:
    def test_uv_checksum_mismatch_is_refused_before_it_runs(self, bundle: VoiceBundle) -> None:
        bundle.write_manifest(uv={"filename": "uv", "sha256": "0" * 64})
        manager = bundle.manager()

        with pytest.raises(VoiceRuntimeIntegrityError, match="uv"):
            manager.provision()

        assert bundle.calls() == []
        assert _staging_entries(manager) == []
        assert manager.status().state is VoiceRuntimeState.NOT_INSTALLED

    @pytest.mark.parametrize("entry", ["requirements", "wheel"])
    def test_input_checksum_mismatch_is_refused_before_any_command(
        self, bundle: VoiceBundle, entry: str
    ) -> None:
        path = bundle.requirements if entry == "requirements" else bundle.wheel
        bundle.write_manifest(**{entry: {"filename": path.name, "sha256": "0" * 64}})

        with pytest.raises(VoiceRuntimeIntegrityError, match=path.name):
            bundle.manager().provision()

        assert bundle.calls() == []

    def test_missing_bundled_file_is_an_integrity_error(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager()
        bundle.wheel.unlink()

        with pytest.raises(VoiceRuntimeIntegrityError, match="cannot be read"):
            manager.provision()

    def test_staged_wheel_changed_during_install_is_refused(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager()
        bundle.behave(**{"tamper-staged-wheel": True})

        with pytest.raises(VoiceRuntimeIntegrityError, match=bundle.wheel.name):
            manager.provision()

        assert "pip-wheel" not in bundle.commands()
        assert _staging_entries(manager) == []


@POSIX_ONLY
class TestFailureKeepsThePreviousRelease:
    @pytest.mark.parametrize(
        ("behavior", "error"),
        [
            ({"python-install": "fail"}, VoiceRuntimeCommandError),
            ({"venv": "fail"}, VoiceRuntimeCommandError),
            ({"pip-requirements": "fail"}, VoiceRuntimeCommandError),
            ({"pip-wheel": "fail"}, VoiceRuntimeCommandError),
            ({"empty-wheel": True}, VoiceRuntimeSmokeError),
        ],
    )
    def test_each_failing_step(
        self, bundle: VoiceBundle, behavior: dict[str, Any], error: type[Exception]
    ) -> None:
        install_synthetic_release(bundle.manager(product_version="9.9.8"))
        manager = bundle.manager()
        before = _snapshot(manager)
        bundle.behave(**behavior)

        with pytest.raises(error):
            manager.provision()

        assert _snapshot(manager) == before
        assert _staging_entries(manager) == []
        assert manager.status().state is VoiceRuntimeState.UPDATE_AVAILABLE
        assert manager.get_worker_cmd()

    def test_command_failure_reports_the_step_and_output(self, bundle: VoiceBundle) -> None:
        bundle.behave(venv="fail")

        with pytest.raises(VoiceRuntimeCommandError) as caught:
            bundle.manager().provision()

        assert caught.value.step == "Creating the voice environment"
        assert caught.value.returncode == 2
        assert "simulated uv failure" in str(caught.value)

    def test_missing_native_audio_library_fails_the_smoke_test(self, bundle: VoiceBundle) -> None:
        (bundle.control / "engines" / "sounddevice.py").write_text(
            "raise OSError('PortAudio library not found')\n", encoding="utf-8"
        )
        manager = bundle.manager()

        with pytest.raises(VoiceRuntimeSmokeError, match="PortAudio library not found"):
            manager.provision()

        assert manager.status().state is VoiceRuntimeState.NOT_INSTALLED
        assert _staging_entries(manager) == []

    def test_worker_that_cannot_start_fails_the_smoke_test(self, bundle: VoiceBundle) -> None:
        bundle.behave(**{"empty-wheel": True})

        with pytest.raises(VoiceRuntimeSmokeError, match="No module named"):
            bundle.manager().provision()


@POSIX_ONLY
class TestLimits:
    def test_cancel_mid_install_cleans_only_staging(self, bundle: VoiceBundle) -> None:
        install_synthetic_release(bundle.manager(product_version="9.9.8"))
        manager = bundle.manager()
        before = _snapshot(manager)
        bundle.behave(**{"pip-requirements": "hang"})
        cancel = threading.Event()
        outcome: list[BaseException] = []

        def install() -> None:
            try:
                manager.provision(cancel=cancel)
            except VoiceRuntimeError as error:
                outcome.append(error)

        worker = threading.Thread(target=install)
        worker.start()
        _wait_for(bundle.control / "grandchild.pid")
        cancel.set()
        worker.join(timeout=15)

        assert not worker.is_alive()
        assert len(outcome) == 1 and isinstance(outcome[0], VoiceRuntimeCancelledError)
        assert _snapshot(manager) == before
        assert _staging_entries(manager) == []
        assert (manager.runtime_dir / "python").is_dir()
        assert _wait_until_gone(bundle.pid("uv.pid"))
        assert _wait_until_gone(bundle.pid("grandchild.pid"))

    def test_cancel_before_start_runs_nothing(self, bundle: VoiceBundle) -> None:
        cancel = threading.Event()
        cancel.set()

        with pytest.raises(VoiceRuntimeCancelledError):
            bundle.manager().provision(cancel=cancel)

        assert bundle.calls() == []

    def test_command_timeout_kills_the_process_tree(self, bundle: VoiceBundle) -> None:
        bundle.write_manifest(
            timeouts={"uv_command_seconds": 1, "stall_seconds": 1, "provision_seconds": 60}
        )
        bundle.behave(**{"python-install": "hang"})
        manager = bundle.manager()

        started = time.monotonic()
        with pytest.raises(VoiceRuntimeTimeoutError, match="1-second limit"):
            manager.provision()

        assert time.monotonic() - started < 10
        assert _wait_until_gone(bundle.pid("uv.pid"))
        assert _wait_until_gone(bundle.pid("grandchild.pid"))
        assert _staging_entries(manager) == []

    def test_stall_kills_the_process_tree(self, bundle: VoiceBundle) -> None:
        bundle.write_manifest(
            timeouts={"uv_command_seconds": 30, "stall_seconds": 1, "provision_seconds": 60}
        )
        bundle.behave(**{"python-install": "hang-silent"})
        manager = bundle.manager()

        started = time.monotonic()
        with pytest.raises(VoiceRuntimeTimeoutError, match="stopped making progress"):
            manager.provision()

        assert time.monotonic() - started < 10
        assert _wait_until_gone(bundle.pid("uv.pid"))
        assert _wait_until_gone(bundle.pid("grandchild.pid"))

    def test_overall_limit_bounds_the_whole_install(self, bundle: VoiceBundle) -> None:
        bundle.write_manifest(
            timeouts={"uv_command_seconds": 1, "stall_seconds": 1, "provision_seconds": 1}
        )
        bundle.behave(**{"python-install": "hang"})

        with pytest.raises(VoiceRuntimeTimeoutError, match="installation limit"):
            bundle.manager().provision()


# ---------------------------------------------------------------------------
# Verify, repair and remove
# ---------------------------------------------------------------------------


@POSIX_ONLY
class TestVerifyAndRepair:
    def test_verify_marks_a_damaged_release_broken_until_reinstalled(
        self, bundle: VoiceBundle
    ) -> None:
        manager = bundle.manager()
        status = manager.provision()
        assert status.installed is not None
        assert manager.verify().state is VoiceRuntimeState.READY
        release = manager.runtime_dir / "releases" / status.installed.release
        next(release.rglob("10-fake-servonaut.pth")).unlink()

        verified = manager.verify()

        assert verified.state is VoiceRuntimeState.BROKEN
        assert "No module named" in verified.message
        with pytest.raises(VoiceRuntimeNotReadyError):
            manager.get_worker_cmd()
        assert manager.provision().state is VoiceRuntimeState.READY

    def test_repair_keeps_the_working_release_until_the_new_one_succeeds(
        self, bundle: VoiceBundle
    ) -> None:
        manager = bundle.manager()
        first = manager.provision().installed
        assert first is not None
        before = _snapshot(manager)
        bundle.behave(**{"pip-wheel": "fail"})

        with pytest.raises(VoiceRuntimeCommandError):
            manager.repair()

        assert _snapshot(manager) == before
        assert manager.status().state is VoiceRuntimeState.READY
        assert manager.get_worker_cmd()

        bundle.behave()
        repaired = manager.repair().installed

        assert repaired is not None
        assert repaired.runtime_id == first.runtime_id
        assert repaired.release != first.release
        assert _releases(manager) == sorted([first.release, repaired.release])
        assert manager.status().state is VoiceRuntimeState.READY

    def test_repair_rebuilds_even_when_ready(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager()
        manager.provision()
        calls_before = len(bundle.calls())

        manager.repair()

        assert len(bundle.calls()) == calls_before + 4


class TestRemove:
    def _models(self, manager: VoiceRuntimeManager) -> Path:
        weights = manager.models_root / "kokoro" / "model.onnx"
        weights.parent.mkdir(parents=True)
        weights.write_bytes(b"weights")
        return weights

    def test_remove_keeps_models_by_default(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager()
        install_synthetic_release(manager)
        (manager.runtime_dir / "staging" / "old").mkdir(parents=True)
        (manager.runtime_dir / "python" / "cpython").mkdir(parents=True)
        (manager.runtime_dir / "cache" / "wheels").mkdir(parents=True)
        weights = self._models(manager)

        status = manager.remove()

        assert status.state is VoiceRuntimeState.NOT_INSTALLED
        assert [p.name for p in manager.runtime_dir.iterdir()] == ["lock"]
        assert weights.read_bytes() == b"weights"

    def test_remove_models_on_request(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager()
        install_synthetic_release(manager)
        self._models(manager)

        manager.remove(remove_models=True)

        assert [p.name for p in manager.models_root.iterdir()] == [".models.lock"]

    def test_symlinks_are_unlinked_not_followed(self, bundle: VoiceBundle, tmp_path: Path) -> None:
        manager = bundle.manager()
        install_synthetic_release(manager)
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("keep", encoding="utf-8")
        (manager.runtime_dir / "cache").symlink_to(outside, target_is_directory=True)
        manager.models_root.symlink_to(outside, target_is_directory=True)

        manager.remove(remove_models=True)

        assert (outside / "keep.txt").read_text(encoding="utf-8") == "keep"
        assert not manager.models_root.is_symlink()
        assert not (manager.runtime_dir / "cache").is_symlink()

    def test_remove_refused_while_locked(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager()
        install_synthetic_release(manager)
        with VoiceRuntimeLock(manager.runtime_dir / "lock", timeout=0.0):
            with pytest.raises(VoiceRuntimeLockError):
                manager.remove()
        assert manager.status().state is VoiceRuntimeState.READY


# ---------------------------------------------------------------------------
# Lock
# ---------------------------------------------------------------------------


class TestVoiceRuntimeLock:
    def test_acquire_and_release(self, tmp_path: Path) -> None:
        lock = VoiceRuntimeLock(tmp_path / "lock", timeout=1.0)
        assert not lock.is_locked()

        with lock:
            assert lock.is_locked()

        assert not lock.is_locked()

    def test_contention_times_out(self, tmp_path: Path) -> None:
        holder = VoiceRuntimeLock(tmp_path / "lock", timeout=1.0)
        waiter = VoiceRuntimeLock(tmp_path / "lock", timeout=0.2)
        holder.acquire()
        try:
            with pytest.raises(VoiceRuntimeLockError, match="Failed to acquire"):
                waiter.acquire()
        finally:
            holder.release()
        waiter.acquire()
        waiter.release()

    def test_probe_does_not_create_the_lock_file(self, tmp_path: Path) -> None:
        assert not VoiceRuntimeLock(tmp_path / "missing" / "lock").is_locked()
        assert not (tmp_path / "missing").exists()


# ---------------------------------------------------------------------------
# Application wiring
# ---------------------------------------------------------------------------


class TestApplicationWiring:
    def test_packaged_desktop_app_builds_the_managed_runtime(self, tmp_path: Path) -> None:
        from servonaut.app import ServonautApp

        bundle = VoiceBundle(tmp_path)
        app = ServonautApp(runtime_layout=bundle.layout)
        app._init_services()

        setup = app.voice_setup_service
        manager = setup.runtime_manager
        assert isinstance(manager, VoiceRuntimeManager)
        assert manager.runtime_dir == bundle.layout.data_root / "runtimes" / "voice"
        assert setup.model_cache.root_dir == manager.models_root.resolve()
        with pytest.raises(VoiceRuntimeNotReadyError):
            setup.connection._worker_cmd()

    def test_packaged_desktop_without_voice_payload_leaves_voice_unavailable(
        self, tmp_path: Path
    ) -> None:
        from servonaut.app import ServonautApp

        app = ServonautApp(runtime_layout=_layout(tmp_path))
        app._init_services()

        assert app.voice_setup_service is None
        assert app.voice_input_service is None


# ---------------------------------------------------------------------------
# Hardening
# ---------------------------------------------------------------------------


def _start_worker(manager: VoiceRuntimeManager) -> subprocess.Popen[bytes]:
    """Launch the worker the way the voice connection does, and wait for its lock."""
    worker = subprocess.Popen(
        manager.get_worker_cmd(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=manager.worker_env(),
    )
    installed = manager.status().installed
    assert installed is not None
    in_use = manager.runtime_dir / "releases" / installed.release / ".in-use"
    deadline = time.monotonic() + 20
    while release_lock.can_lock(in_use, exclusive=True):
        assert worker.poll() is None, worker.communicate()[1].decode()
        assert time.monotonic() < deadline, "the worker never took its release lock"
        time.sleep(0.05)
    return worker


def _stop_worker(worker: subprocess.Popen[bytes]) -> None:
    worker.communicate(timeout=20)


@POSIX_ONLY
class TestReleasesInUse:
    def test_a_running_worker_keeps_its_release_through_updates(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager()
        first = manager.provision().installed
        assert first is not None
        worker = _start_worker(manager)
        try:
            manager.repair()
            manager.repair()

            assert first.release in _releases(manager)
            assert len(_releases(manager)) == 3
            with pytest.raises(VoiceRuntimeLockError, match="still running"):
                manager.remove()
            assert manager.status().state is VoiceRuntimeState.READY
        finally:
            _stop_worker(worker)

        latest = manager.repair().installed
        assert latest is not None
        assert first.release not in _releases(manager)
        assert len(_releases(manager)) == 2
        assert manager.remove().state is VoiceRuntimeState.NOT_INSTALLED

    def test_an_in_use_release_is_never_pruned_even_without_retention(
        self, bundle: VoiceBundle
    ) -> None:
        oldest = install_synthetic_release(bundle.manager(product_version="9.9.7"))
        in_use = bundle.manager().runtime_dir / "releases" / oldest.release / ".in-use"
        holder = release_lock.open_and_lock(in_use, exclusive=False, timeout=0.0)
        try:
            install_synthetic_release(bundle.manager(product_version="9.9.8"))
            bundle.manager().provision()

            assert oldest.release in _releases(bundle.manager())
        finally:
            os.close(holder)


class TestConcurrentStatus:
    def test_concurrent_probes_never_report_installing(
        self, bundle: VoiceBundle, no_subprocess: None
    ) -> None:
        manager = bundle.manager()
        install_synthetic_release(manager)
        (manager.runtime_dir / "lock").touch()
        states: list[VoiceRuntimeState] = []
        stop = time.monotonic() + 1.0

        def poll() -> None:
            while time.monotonic() < stop:
                states.append(manager.status().state)

        readers = [threading.Thread(target=poll) for _ in range(3)]
        for reader in readers:
            reader.start()
        for reader in readers:
            reader.join()

        assert states and VoiceRuntimeState.INSTALLING not in states

    def test_operations_are_not_refused_because_of_probes(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager()
        done = threading.Event()

        def poll() -> None:
            while not done.is_set():
                manager.status()

        reader = threading.Thread(target=poll)
        reader.start()
        try:
            for _ in range(20):
                manager.remove()
        finally:
            done.set()
            reader.join()

    def test_a_real_holder_still_reports_installing_to_another_process(
        self, bundle: VoiceBundle
    ) -> None:
        manager = bundle.manager()
        install_synthetic_release(manager)
        holder = subprocess.Popen(
            [
                sys.executable, "-c",
                "import sys, time; from pathlib import Path; "
                "from servonaut.desktop.voice.release_lock import open_and_lock; "
                "open_and_lock(Path(sys.argv[1]), exclusive=True, timeout=0.0); "
                "print('held', flush=True); time.sleep(30)",
                str(manager.runtime_dir / "lock"),
            ],
            stdout=subprocess.PIPE,
            env={**os.environ, "PYTHONPATH": str(Path(servonaut.__file__).resolve().parents[1])},
        )
        try:
            assert holder.stdout is not None and holder.stdout.readline().strip() == b"held"
            assert manager.status().state is VoiceRuntimeState.INSTALLING
        finally:
            holder.kill()
            holder.wait()
        assert manager.status().state is VoiceRuntimeState.READY


class TestCurrentRecordFile:
    @pytest.mark.parametrize("damage", ["deep", "symlink", "directory", "fifo"])
    def test_current_json_must_be_a_plain_regular_file(
        self, bundle: VoiceBundle, no_subprocess: None, damage: str, tmp_path: Path
    ) -> None:
        if damage == "fifo" and not hasattr(os, "mkfifo"):
            pytest.skip("named pipes are POSIX only")
        manager = bundle.manager()
        install_synthetic_release(manager)
        current = manager.runtime_dir / "current.json"
        if damage == "deep":
            current.write_text("[" * 60000, encoding="utf-8")
        else:
            elsewhere = tmp_path / "elsewhere.json"
            elsewhere.write_bytes(current.read_bytes())
            current.unlink()
            if damage == "symlink":
                current.symlink_to(elsewhere)
            elif damage == "directory":
                current.mkdir()
            else:
                os.mkfifo(current)

        assert manager.status().state is VoiceRuntimeState.BROKEN
        with pytest.raises(VoiceRuntimeNotReadyError):
            manager.get_worker_cmd()


class TestWorkerEnvironment:
    def test_worker_env_carries_no_credentials_or_loader_settings(
        self, bundle: VoiceBundle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secrets = {
            "AWS_ACCESS_KEY_ID": "id",
            "AWS_SESSION_TOKEN": "token",
            "OPENAI_API_KEY": "key",
            "ANTHROPIC_API_KEY": "key",
            "HF_TOKEN": "token",
            "HUGGING_FACE_HUB_TOKEN": "token",
            "SERVONAUT_API_TOKEN": "token",
            "LD_PRELOAD": "/nonexistent/preload.so",
            "DYLD_LIBRARY_PATH": "/nonexistent/lib",
            "PYTHONHOME": "/nonexistent/home",
        }
        for name, value in secrets.items():
            monkeypatch.setenv(name, value)
        monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")

        env = bundle.manager().worker_env()

        for name in [*secrets, "AWS_SECRET_ACCESS_KEY", "LD_LIBRARY_PATH"]:
            assert name not in env
        assert "PYTHONPATH" not in env and "VIRTUAL_ENV" not in env
        assert env["PYTHONUNBUFFERED"] == "1"
        assert env["PYTHONIOENCODING"] == "utf-8"
        assert env["XDG_RUNTIME_DIR"] == "/run/user/1000"

    def test_worker_env_keeps_network_settings_for_first_use_downloads(
        self, bundle: VoiceBundle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        network = {
            "HTTPS_PROXY": "http://proxy.invalid:3128",
            "http_proxy": "http://proxy.invalid:3128",
            "NO_PROXY": "localhost",
            "SSL_CERT_FILE": "/nonexistent/ca.pem",
            "SSL_CERT_DIR": "/nonexistent/certs",
            "REQUESTS_CA_BUNDLE": "/nonexistent/bundle.pem",
            "HF_ENDPOINT": "https://mirror.invalid",
        }
        for name, value in network.items():
            monkeypatch.setenv(name, value)

        env = bundle.manager().worker_env()

        for name, value in network.items():
            assert env[name] == value


@POSIX_ONLY
class TestSmokeHandshake:
    def test_a_worker_that_never_answers_is_stopped_as_stalled(self, bundle: VoiceBundle) -> None:
        source = bundle.tmp_path / "hung-src"
        package = source / "servonaut" / "desktop" / "voice"
        package.mkdir(parents=True)
        for directory in (source / "servonaut", source / "servonaut" / "desktop", package):
            (directory / "__init__.py").write_text("", encoding="utf-8")
        shutil.copyfile(release_lock.__file__, package / "release_lock.py")
        (package / "worker.py").write_text("import time\ntime.sleep(600)\n", encoding="utf-8")
        (bundle.control / "config.json").write_text(
            json.dumps({"src": str(source), "paths": []}), encoding="utf-8"
        )
        bundle.write_manifest(
            timeouts={"uv_command_seconds": 60, "stall_seconds": 1, "provision_seconds": 120}
        )
        manager = bundle.manager()

        started = time.monotonic()
        with pytest.raises(VoiceRuntimeTimeoutError, match="stopped making progress") as caught:
            manager.provision()

        assert caught.value.step == "Testing the voice runtime"
        assert time.monotonic() - started < 20
        assert manager.status().state is VoiceRuntimeState.NOT_INSTALLED

    def test_a_worker_of_another_version_fails_the_smoke_test(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager(product_version="0.0.1")

        with pytest.raises(VoiceRuntimeSmokeError, match="expected 0.0.1"):
            manager.provision()


@POSIX_ONLY
class TestCommitPoint:
    def test_cancel_after_activation_starts_is_ignored(self, bundle: VoiceBundle) -> None:
        install_synthetic_release(bundle.manager(product_version="9.9.8"))
        manager = bundle.manager()
        cancel = threading.Event()

        def progress(label: str, completed: int, total: int) -> None:
            if label == "Activating the voice runtime":
                cancel.set()

        status = manager.provision(progress=progress, cancel=cancel)

        assert status.state is VoiceRuntimeState.READY
        assert status.installed is not None
        assert status.installed.runtime_id == manager.expected_runtime_id

    def test_release_is_flushed_before_it_is_activated(
        self, bundle: VoiceBundle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        manager = bundle.manager()
        release = manager.runtime_dir / "releases" / manager.expected_runtime_id
        observed: list[tuple[bool, bool]] = []
        monkeypatch.setattr(
            os,
            "sync",
            lambda: observed.append(
                ((manager.runtime_dir / "current.json").exists(), release.is_dir())
            ),
            raising=False,
        )

        manager.provision()

        assert observed == [(False, True)]

    def test_download_cache_is_emptied_after_an_install(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager()
        cached = manager.runtime_dir / "cache" / "wheels" / "download.whl"
        cached.parent.mkdir(parents=True)
        cached.write_bytes(b"cached")

        manager.provision()

        assert not (manager.runtime_dir / "cache").exists()


@pytest.fixture
def transient_permission_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enable the Windows retry behaviour on any platform, with a short delay."""
    monkeypatch.setattr(runtime_module, "_RETRY_PERMISSION_ERRORS", True)
    monkeypatch.setattr(runtime_module, "_PERMISSION_RETRY_DELAY_SECONDS", 0.01)


@POSIX_ONLY
class TestPermissionRetries:
    def _flaky(self, original: Any, matches: Any, failures: int) -> tuple[Any, list[object]]:
        calls: list[object] = []

        def flaky(*args: Any) -> Any:
            if matches(*args):
                calls.append(args)
                if len(calls) <= failures:
                    raise PermissionError(13, "The file is in use")
            return original(*args)

        return flaky, calls

    def test_release_rename_is_retried(
        self,
        bundle: VoiceBundle,
        transient_permission_errors: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        flaky, calls = self._flaky(
            Path.rename, lambda source, target: Path(target).parent.name == "releases", 2
        )
        monkeypatch.setattr(Path, "rename", flaky)

        assert bundle.manager().provision().state is VoiceRuntimeState.READY
        assert len(calls) == 3

    def test_rename_that_keeps_failing_leaves_the_previous_release(
        self,
        bundle: VoiceBundle,
        transient_permission_errors: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        install_synthetic_release(bundle.manager(product_version="9.9.8"))
        manager = bundle.manager()
        before = _snapshot(manager)
        flaky, calls = self._flaky(
            Path.rename, lambda source, target: Path(target).parent.name == "releases", 99
        )
        monkeypatch.setattr(Path, "rename", flaky)

        with pytest.raises(VoiceRuntimeError, match="could not be activated"):
            manager.provision()

        assert len(calls) == 10
        assert _snapshot(manager) == before
        assert _staging_entries(manager) == []

    def test_current_json_replace_is_retried(
        self,
        bundle: VoiceBundle,
        transient_permission_errors: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        flaky, calls = self._flaky(
            os.replace, lambda source, target: Path(target).name == "current.json", 2
        )
        monkeypatch.setattr(os, "replace", flaky)

        assert bundle.manager().provision().state is VoiceRuntimeState.READY
        assert len(calls) == 3

    def test_release_deletion_is_retried(
        self,
        bundle: VoiceBundle,
        transient_permission_errors: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        oldest = install_synthetic_release(bundle.manager(product_version="9.9.7"))
        install_synthetic_release(bundle.manager(product_version="9.9.8"))
        flaky, calls = self._flaky(
            shutil.rmtree, lambda path: Path(path).name == oldest.release, 2
        )
        monkeypatch.setattr(shutil, "rmtree", flaky)

        bundle.manager().provision()

        assert len(calls) == 3
        assert oldest.release not in _releases(bundle.manager())

    def test_permission_errors_are_not_retried_off_windows(
        self, bundle: VoiceBundle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(runtime_module, "_RETRY_PERMISSION_ERRORS", False)
        flaky, calls = self._flaky(
            Path.rename, lambda source, target: Path(target).parent.name == "releases", 1
        )
        monkeypatch.setattr(Path, "rename", flaky)

        with pytest.raises(VoiceRuntimeError, match="could not be activated"):
            bundle.manager().provision()

        assert len(calls) == 1


class TestPythonPruning:
    def _release(self, paths: Any, name: str, home: Optional[Path]) -> None:
        venv = paths.release(name) / "venv"
        venv.mkdir(parents=True)
        if home is not None:
            (venv / "pyvenv.cfg").write_text(f"home = {home}\nversion = 3.12\n", encoding="utf-8")

    def _installs(self, paths: Any) -> list[str]:
        return sorted(path.name for path in paths.python.iterdir())

    def test_interpreters_no_retained_release_uses_are_removed(self, tmp_path: Path) -> None:
        paths = runtime_module._RuntimePaths(tmp_path / "voice")
        for name in ("cpython-3.12.6-test", "cpython-3.12.7-test", "cpython-3.12.8-test"):
            (paths.python / name / "bin").mkdir(parents=True)
        (paths.python / "cpython-3.12-test").symlink_to(
            paths.python / "cpython-3.12.7-test", target_is_directory=True
        )
        (paths.python / ".lock").write_text("", encoding="utf-8")
        self._release(paths, "current", paths.python / "cpython-3.12-test" / "bin")
        self._release(paths, "previous", paths.python / "cpython-3.12.6-test" / "bin")

        runtime_module._prune_python_installs(paths, ["current", "previous"])

        assert self._installs(paths) == [
            ".lock", "cpython-3.12-test", "cpython-3.12.6-test", "cpython-3.12.7-test",
        ]

    def test_all_interpreters_are_kept_when_one_release_is_unknown(self, tmp_path: Path) -> None:
        paths = runtime_module._RuntimePaths(tmp_path / "voice")
        for name in ("cpython-3.12.6-test", "cpython-3.12.7-test"):
            (paths.python / name / "bin").mkdir(parents=True)
        self._release(paths, "current", paths.python / "cpython-3.12.7-test" / "bin")
        self._release(paths, "previous", None)

        runtime_module._prune_python_installs(paths, ["current", "previous"])

        assert self._installs(paths) == ["cpython-3.12.6-test", "cpython-3.12.7-test"]


class TestRemoveWithModelDownloads:
    def test_remove_models_is_refused_while_a_download_holds_the_model_lock(
        self, bundle: VoiceBundle
    ) -> None:
        manager = bundle.manager()
        install_synthetic_release(manager)
        partial = manager.models_root / "kokoro" / "model.onnx.part"
        partial.parent.mkdir(parents=True)
        partial.write_bytes(b"half a download")
        current = (manager.runtime_dir / "current.json").read_bytes()

        with VoiceRuntimeLock(manager.models_root / ".models.lock", timeout=0.0):
            with pytest.raises(VoiceRuntimeLockError, match="download"):
                manager.remove(remove_models=True)
            assert partial.exists()
            assert (manager.runtime_dir / "current.json").read_bytes() == current

        manager.remove(remove_models=True)

        assert [p.name for p in manager.models_root.iterdir()] == [".models.lock"]
        assert manager.status().state is VoiceRuntimeState.NOT_INSTALLED

    def test_remove_without_models_ignores_the_model_lock(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager()
        install_synthetic_release(manager)
        manager.models_root.mkdir(parents=True)

        with VoiceRuntimeLock(manager.models_root / ".models.lock", timeout=0.0):
            assert manager.remove().state is VoiceRuntimeState.NOT_INSTALLED


# ---------------------------------------------------------------------------
# Removal: ordering, owned entries only, never through links
# ---------------------------------------------------------------------------


class TestRemovalSafety:
    def test_the_worker_is_stopped_only_once_nothing_can_restart_it(
        self, bundle: VoiceBundle
    ) -> None:
        manager = bundle.manager()
        record = install_synthetic_release(manager)
        in_use = manager.runtime_dir / "releases" / record.release / ".in-use"
        holder = release_lock.open_and_lock(in_use, exclusive=False, timeout=0.0)
        seen: dict = {}

        def stop_worker() -> None:
            # The runtime is locked by now, so no worker can be (re)started.
            with pytest.raises(VoiceRuntimeNotReadyError):
                manager.get_worker_cmd()
            seen["stopped"] = True
            os.close(holder)

        status = manager.remove(stop_worker=stop_worker)

        assert seen == {"stopped": True}
        assert status.state is VoiceRuntimeState.NOT_INSTALLED

    def test_only_the_runtime_s_own_entries_are_deleted(self, bundle: VoiceBundle) -> None:
        manager = bundle.manager()
        install_synthetic_release(manager)
        (manager.runtime_dir / "current.json.0a1b2c3d.tmp").write_text("{}", encoding="utf-8")
        foreign = manager.runtime_dir / "notes.txt"
        foreign.write_text("keep", encoding="utf-8")

        manager.remove()

        assert sorted(p.name for p in manager.runtime_dir.iterdir()) == ["lock", "notes.txt"]

    @POSIX_ONLY
    def test_a_linked_releases_directory_is_refused(
        self, bundle: VoiceBundle, tmp_path: Path
    ) -> None:
        manager = bundle.manager()
        outside = tmp_path / "elsewhere"
        (outside / "important").mkdir(parents=True)
        manager.runtime_dir.mkdir(parents=True)
        (manager.runtime_dir / "releases").symlink_to(outside, target_is_directory=True)

        with pytest.raises(VoiceRuntimeError, match="is a link"):
            manager.remove()

        assert (outside / "important").is_dir()

    @POSIX_ONLY
    def test_a_linked_runtime_root_is_refused(self, bundle: VoiceBundle, tmp_path: Path) -> None:
        manager = bundle.manager()
        outside = tmp_path / "elsewhere"
        (outside / "releases" / "keep").mkdir(parents=True)
        manager.runtime_dir.parent.mkdir(parents=True)
        manager.runtime_dir.symlink_to(outside, target_is_directory=True)

        with pytest.raises(VoiceRuntimeError):
            manager.remove()

        assert (outside / "releases" / "keep").is_dir()

    def test_a_runtime_outside_the_data_root_is_refused(self, tmp_path: Path) -> None:
        manager = VoiceRuntimeManager(
            runtime_dir=tmp_path / "other" / "runtimes" / "voice",
            bundle_dir=tmp_path / "bundle",
            manifest=_minimal_manifest(),
            models_root=tmp_path / "data" / "voice_models",
            product_version="1.0.0",
            data_root=tmp_path / "data",
        )
        (manager.runtime_dir / "releases" / "keep").mkdir(parents=True)

        with pytest.raises(VoiceRuntimeError, match="outside the data directory"):
            manager.remove()

        assert (manager.runtime_dir / "releases" / "keep").is_dir()


def _minimal_manifest() -> Any:
    from servonaut.desktop.voice.packaged_manifest import (
        BundledFile,
        PackagedVoiceManifest,
        ProvisionTimeouts,
    )

    return PackagedVoiceManifest(
        schema_version=1,
        target="test-target",
        python_version="3.12.7",
        uv=BundledFile("uv", "a" * 64),
        wheel=BundledFile("servonaut-1.0.0-py3-none-any.whl", "b" * 64),
        requirements=BundledFile("voice-requirements.txt", "c" * 64),
        timeouts=ProvisionTimeouts(**DEFAULT_TIMEOUTS),
    )


# ---------------------------------------------------------------------------
# Step output never carries credentials
# ---------------------------------------------------------------------------


class TestStepOutputScrubbing:
    def test_a_failing_step_s_output_and_error_are_scrubbed(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        proxy = "http://alice:s%40cret99@example.com:3128"
        script = (
            "import sys\n"
            "print('fetching via http://u:p@ss@h:3128/simple')\n"
            "print('proxy password s@cret99 was rejected', file=sys.stderr)\n"
            "print('retrying with ' + sys.argv[1], file=sys.stderr)\n"
            "sys.exit(3)\n"
        )
        runner = runtime_module._StepRunner(
            cwd=tmp_path,
            timeouts=_minimal_manifest().timeouts,
            cancel=None,
            watch=(),
        )
        caplog.set_level("DEBUG")

        with pytest.raises(VoiceRuntimeCommandError) as caught:
            runner.run(
                "Downloading voice packages",
                [sys.executable, "-c", script, proxy],
                env={**os.environ, "HTTPS_PROXY": proxy},
            )

        surfaces = (str(caught.value), caught.value.output, caplog.text)
        for text in surfaces:
            for secret in ("p@ss", "s@cret99", "s%40cret99"):
                assert secret not in text
        assert "rejected" in caught.value.output
