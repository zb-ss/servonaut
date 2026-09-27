"""The packaged desktop build's authenticated, headless self-test."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import servonaut._artifact_selftest as cli_selftest
from servonaut.desktop import artifact_selftest as selftest
from servonaut.runtime import (
    DistributionKind,
    PackageManagementCapability,
    PackageManagementKind,
    RuntimeLayout,
)


def _request(check: str, token: str = "test-token") -> bytes:
    return json.dumps({"schema_version": 1, "token": token, "check": check}).encode()


@pytest.mark.parametrize("check", ["desktop", "desktop-window"])
def test_desktop_checks_are_accepted_only_by_the_desktop_self_test(check: str) -> None:
    request = cli_selftest._read_request(io.BytesIO(_request(check)), selftest._CHECKS)

    assert request.check == check
    with pytest.raises(cli_selftest._SelftestFailure, match="request-invalid"):
        cli_selftest._read_request(io.BytesIO(_request(check)))


def test_desktop_self_test_refuses_the_cli_check() -> None:
    with pytest.raises(cli_selftest._SelftestFailure, match="request-invalid"):
        cli_selftest._read_request(io.BytesIO(_request("tui")), selftest._CHECKS)


def _run(monkeypatch: pytest.MonkeyPatch, stdin: bytes) -> tuple[int, dict[str, object]]:
    output = io.StringIO()
    monkeypatch.setattr(selftest.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(stdin)))
    monkeypatch.setattr(selftest.sys, "stdout", output)
    code = selftest.run_desktop_artifact_selftest(SimpleNamespace(product_version="1"))
    return code, json.loads(output.getvalue())


def test_wrong_token_never_starts_the_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SERVONAUT_ARTIFACT_SELFTEST_TOKEN", "expected-token")
    monkeypatch.setattr(
        selftest,
        "_run_isolated_check",
        lambda *_args: pytest.fail("an unauthenticated request must not start"),
    )

    code, result = _run(monkeypatch, _request("desktop", token="wrong-token"))

    assert code == 1
    assert result == {"schema_version": 1, "ok": False, "error": "authentication-failed"}
    assert "wrong-token" not in json.dumps(result)


def test_authenticated_request_reports_the_check_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SERVONAUT_ARTIFACT_SELFTEST_TOKEN", "test-token")
    monkeypatch.setattr(
        selftest,
        "_run_isolated_check",
        lambda _runtime, check: {"schema_version": 1, "ok": True, "check": check},
    )

    code, result = _run(monkeypatch, _request("desktop-window"))

    assert code == 0
    assert result == {"schema_version": 1, "ok": True, "check": "desktop-window"}


def test_missing_standard_streams_refuse_without_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(selftest.sys, "stdin", None)

    assert selftest.run_desktop_artifact_selftest(SimpleNamespace()) == 1


def _layout(
    tmp_path: Path, *, kind: DistributionKind, home: Path, **overrides: object
) -> RuntimeLayout:
    values: dict[str, object] = {
        "kind": kind,
        "product_version": "2.27.0",
        "build_revision": "ci-r1",
        "resource_root": tmp_path / "_internal",
        "executable_root": tmp_path,
        "data_root": home / ".servonaut",
        "executable": Path(sys.executable),
        "python_executable": None,
        "path_console": None,
        "console_helper": None,
        "desktop_child": None,
        "package_management": PackageManagementCapability(
            PackageManagementKind.UNSUPPORTED, (), False
        ),
        "is_frozen": True,
        "release_channel": "stable",
        "packaging_revision": 1,
    }
    values.update(overrides)
    return RuntimeLayout(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "overrides",
    [
        {"kind": DistributionKind.FROZEN_CLI},
        {"kind": DistributionKind.SOURCE, "is_frozen": False},
        {"packaging_revision": None},
        {"product_version": "2.26.0"},
    ],
)
def test_only_the_packaged_desktop_runtime_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]
) -> None:
    home = tmp_path / "home"
    values = {"kind": DistributionKind.PACKAGED_DESKTOP, **overrides}
    runtime = _layout(tmp_path, home=home, **values)  # type: ignore[arg-type]
    monkeypatch.setattr("servonaut.runtime.detect_runtime", lambda: runtime)

    with pytest.raises(cli_selftest._SelftestFailure, match="runtime-invalid"):
        selftest._packaged_runtime(home, SimpleNamespace(product_version="2.27.0"))


_VOICE_TARGET = "linux-x64-ubuntu-22.04"
_VOICE_ROLES = ("uv", "wheel", "requirements")


def _voice_file_names() -> dict[str, str]:
    return {
        "uv": "uv",
        "wheel": "servonaut-2.27.0-py3-none-any.whl",
        "requirements": "voice-requirements.txt",
    }


def _write_voice_manifest(voice: Path, **overrides: object) -> None:
    """Pin every bundled file by its current digest, as the build does."""
    document: dict[str, object] = {
        "schema_version": 1,
        "target": _VOICE_TARGET,
        "python_version": "3.12.7",
        "timeouts": {
            "uv_command_seconds": 600,
            "stall_seconds": 120,
            "provision_seconds": 1800,
        },
    }
    for role, name in _voice_file_names().items():
        digest = hashlib.sha256((voice / name).read_bytes()).hexdigest()
        document[role] = {"filename": name, "sha256": digest}
    document.update(overrides)
    (voice / "voice-runtime.json").write_text(json.dumps(document), encoding="utf-8")


def _voice_payload(tmp_path: Path) -> RuntimeLayout:
    runtime = _layout(
        tmp_path, kind=DistributionKind.PACKAGED_DESKTOP, home=tmp_path / "home"
    )
    voice = runtime.resource_root / "voice"
    voice.mkdir(parents=True)
    contents = {
        "uv": b"\x7fELF" + bytes(range(256)) * 64,
        "wheel": b"PK\x03\x04 product wheel stand-in",
        "requirements": b"sherpa-onnx==1.0.0 --hash=sha256:" + b"0" * 64 + b"\n",
    }
    for role, name in _voice_file_names().items():
        (voice / name).write_bytes(contents[role])
    _write_voice_manifest(voice)
    return runtime


def _voice_file(runtime: RuntimeLayout, role: str) -> Path:
    return runtime.resource_root / "voice" / _voice_file_names()[role]


def test_voice_payload_is_verified_file_by_file(tmp_path: Path) -> None:
    runtime = _voice_payload(tmp_path)

    assert selftest._verify_voice_payload(runtime) == {
        "directory": True,
        "manifest": True,
        "target": _VOICE_TARGET,
        "uv": True,
        "wheel": True,
        "requirements": True,
    }


def test_voice_files_are_hashed_in_bounded_chunks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A large uv binary is streamed through the digest, never read at once."""
    from servonaut.desktop.voice import runtime as voice_runtime

    runtime = _voice_payload(tmp_path)
    uv = _voice_file(runtime, "uv")
    reads: list[int] = []
    open_file = Path.open

    class _RecordingReader:
        def __init__(self, handle: io.BufferedReader) -> None:
            self._handle = handle

        def __enter__(self) -> _RecordingReader:
            return self

        def __exit__(self, *_exc: object) -> None:
            self._handle.close()

        def read(self, size: int = -1) -> bytes:
            reads.append(size)
            return self._handle.read(size)

    def recording_open(path: Path, *args: object, **kwargs: object) -> object:
        handle = open_file(path, *args, **kwargs)  # type: ignore[arg-type]
        return _RecordingReader(handle) if path == uv else handle

    monkeypatch.setattr(voice_runtime, "_HASH_CHUNK_BYTES", 1024)
    monkeypatch.setattr(Path, "open", recording_open)

    selftest._verify_voice_payload(runtime)

    assert uv.stat().st_size > 1024
    assert len(reads) > 1
    assert all(0 < size <= 1024 for size in reads)


@pytest.mark.parametrize("role", _VOICE_ROLES)
def test_tampered_voice_file_fails_its_digest(tmp_path: Path, role: str) -> None:
    runtime = _voice_payload(tmp_path)
    path = _voice_file(runtime, role)
    path.write_bytes(path.read_bytes() + b"tampered")

    with pytest.raises(cli_selftest._SelftestFailure, match=f"^voice-{role}-digest$"):
        selftest._verify_voice_payload(runtime)


@pytest.mark.parametrize("role", _VOICE_ROLES)
def test_missing_voice_file_is_refused(tmp_path: Path, role: str) -> None:
    runtime = _voice_payload(tmp_path)
    _voice_file(runtime, role).unlink()

    with pytest.raises(cli_selftest._SelftestFailure, match=f"^voice-{role}-file$"):
        selftest._verify_voice_payload(runtime)


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
@pytest.mark.parametrize("role", _VOICE_ROLES)
def test_symlinked_voice_file_is_refused_even_when_its_target_matches(
    tmp_path: Path, role: str
) -> None:
    runtime = _voice_payload(tmp_path)
    path = _voice_file(runtime, role)
    outside = tmp_path / f"elsewhere-{path.name}"
    outside.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(outside)

    with pytest.raises(cli_selftest._SelftestFailure, match=f"^voice-{role}-file$"):
        selftest._verify_voice_payload(runtime)


@pytest.mark.parametrize("role", _VOICE_ROLES)
def test_voice_file_that_is_a_directory_is_refused(tmp_path: Path, role: str) -> None:
    runtime = _voice_payload(tmp_path)
    path = _voice_file(runtime, role)
    path.unlink()
    path.mkdir()

    with pytest.raises(cli_selftest._SelftestFailure, match=f"^voice-{role}-file$"):
        selftest._verify_voice_payload(runtime)


@pytest.mark.parametrize(
    "overrides",
    [
        {"schema_version": 2},
        {"target": "../elsewhere"},
        {"uv": {"filename": "../uv", "sha256": "0" * 64}},
        {"wheel": {"filename": "servonaut.zip", "sha256": "0" * 64}},
        {"requirements": {"filename": "voice-requirements.txt", "sha256": "0" * 63}},
        {"timeouts": {"uv_command_seconds": 60, "stall_seconds": 120, "provision_seconds": 1800}},
        {"unexpected": True},
    ],
    ids=[
        "schema-version",
        "target",
        "uv-filename",
        "wheel-filename",
        "requirements-digest",
        "timeouts-order",
        "unknown-key",
    ],
)
def test_manifest_the_app_would_reject_fails_the_self_test(
    tmp_path: Path, overrides: dict[str, object]
) -> None:
    """The app's own manifest reader decides, including rules only it knows."""
    runtime = _voice_payload(tmp_path)
    _write_voice_manifest(runtime.resource_root / "voice", **overrides)

    with pytest.raises(cli_selftest._SelftestFailure, match="^voice-manifest$"):
        selftest._verify_voice_payload(runtime)


@pytest.mark.parametrize("content", [b"", b"{", b"[]", b"\xff\xfe", b" " * (64 * 1024 + 1)])
def test_unreadable_manifest_fails_the_self_test(tmp_path: Path, content: bytes) -> None:
    runtime = _voice_payload(tmp_path)
    (runtime.resource_root / "voice" / "voice-runtime.json").write_bytes(content)

    with pytest.raises(cli_selftest._SelftestFailure, match="^voice-manifest$"):
        selftest._verify_voice_payload(runtime)


def test_voice_result_reports_the_manifest_target_for_the_smoke_runner(
    tmp_path: Path,
) -> None:
    """The runtime has no build target; the runner compares the reported one."""
    runtime = _voice_payload(tmp_path)
    _write_voice_manifest(runtime.resource_root / "voice", target="macos-arm64")

    assert selftest._verify_voice_payload(runtime)["target"] == "macos-arm64"


@pytest.mark.parametrize("remove", ["manifest", "directory"])
def test_missing_voice_payload_has_its_own_code(tmp_path: Path, remove: str) -> None:
    runtime = _voice_payload(tmp_path)
    voice = runtime.resource_root / "voice"
    (voice / "voice-runtime.json").unlink()
    if remove == "directory":
        for entry in voice.iterdir():
            entry.unlink()
        voice.rmdir()

    with pytest.raises(cli_selftest._SelftestFailure, match="^voice-payload$"):
        selftest._verify_voice_payload(runtime)


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_symlinked_voice_manifest_is_refused(tmp_path: Path) -> None:
    runtime = _voice_payload(tmp_path)
    manifest = runtime.resource_root / "voice" / "voice-runtime.json"
    outside = tmp_path / "elsewhere.json"
    outside.write_bytes(manifest.read_bytes())
    manifest.unlink()
    manifest.symlink_to(outside)

    with pytest.raises(cli_selftest._SelftestFailure, match="^voice-payload$"):
        selftest._verify_voice_payload(runtime)


def test_resources_need_notices(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _layout(
        tmp_path, kind=DistributionKind.PACKAGED_DESKTOP, home=tmp_path / "home"
    )
    monkeypatch.setattr(
        "servonaut.desktop.assets.load_and_verify_assets",
        lambda **_kwargs: ({"/": (b"page", "text/html")}, {}),
    )

    with pytest.raises(cli_selftest._SelftestFailure, match="resources-notices"):
        selftest._verify_resources(runtime)

    (runtime.resource_root / "notices").mkdir(parents=True)
    (runtime.resource_root / "notices" / "runtime-notice.txt").write_text("notice")
    assert selftest._verify_resources(runtime) == {"frontend": True, "notices": True}


def _load_gui_entry() -> object:
    entry = (
        Path(__file__).resolve().parents[2]
        / "packaging"
        / "desktop_shell"
        / "entries"
        / "servonaut_desktop.py"
    )
    spec = importlib.util.spec_from_file_location("servonaut_desktop_gui_entry", entry)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_gui_entry_dispatches_the_desktop_self_test(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry = _load_gui_entry()
    runtime = _layout(
        tmp_path, kind=DistributionKind.SOURCE, home=tmp_path / "home", is_frozen=False
    )
    received: list[object] = []
    monkeypatch.setattr(entry, "detect_runtime", lambda: runtime)
    monkeypatch.setattr(
        entry, "run_desktop", lambda _request: pytest.fail("no window in a self-test")
    )
    monkeypatch.setattr(
        selftest, "run_desktop_artifact_selftest", lambda value: received.append(value) or 7
    )

    assert entry.main(["--_artifact-selftest"]) == 7
    assert received == [runtime]


@pytest.mark.skipif(os.name == "nt", reason="the stand-in child uses a POSIX shebang")
def test_isolated_check_runs_one_real_session_through_the_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Everything after the packaging checks runs for real against a source child."""
    pytest.importorskip("aiohttp")
    pytest.importorskip("textual_serve")
    child = tmp_path / "servonaut-desktop-child"
    child.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "from servonaut.desktop.child import main\n"
        "sys.exit(main())\n",
        encoding="utf-8",
    )
    child.chmod(0o755)

    def source_runtime(home: Path, _initial: object) -> RuntimeLayout:
        return _layout(
            tmp_path,
            kind=DistributionKind.SOURCE,
            home=home,
            is_frozen=False,
            desktop_child=child,
            packaging_revision=3,
        )

    from servonaut.desktop import model as desktop_model

    generate = desktop_model.SecretToken.generate
    session_tokens: list[str] = []

    def recording_generate() -> desktop_model.SecretToken:
        token = generate()
        session_tokens.append(token.encoded_value())
        return token

    temporary = tmp_path / "temporary"
    temporary.mkdir()
    monkeypatch.setenv("TMPDIR", str(temporary))
    monkeypatch.setattr(desktop_model.SecretToken, "generate", staticmethod(recording_generate))
    monkeypatch.setattr(selftest, "_packaged_runtime", source_runtime)
    monkeypatch.setattr(selftest, "_import_desktop_stack", lambda: None)
    monkeypatch.setattr(selftest, "_verify_resources", lambda _runtime: {"frontend": True})
    _voice_payload(tmp_path)
    before = dict(os.environ)

    result = selftest._run_isolated_check(SimpleNamespace(), "desktop")
    output = io.StringIO()
    cli_selftest._write_result(result, output)

    assert session_tokens
    assert all(token not in output.getvalue() for token in session_tokens)
    assert list(temporary.iterdir()) == []

    assert result["ok"] is True
    assert result["runtime"] == {
        "kind": "packaged-desktop",
        "marker": True,
        "channel": "stable",
        "packaging_revision": 3,
    }
    assert result["host"] == {
        "page": True,
        "refused_unauthenticated": True,
        "window": False,
        "session_rendered": True,
        "session_answered": True,
        "child_exited": True,
    }
    assert result["voice"] == {
        "directory": True,
        "manifest": True,
        "target": _VOICE_TARGET,
        "uv": True,
        "wheel": True,
        "requirements": True,
    }
    assert result["fixtures"] == {"config": True, "cache": True}
    assert dict(os.environ) == before


class _FakeEvent:
    def __init__(self) -> None:
        self.handlers: list[object] = []

    def __iadd__(self, handler: object) -> _FakeEvent:
        self.handlers.append(handler)
        return self


class _FakeWebview:
    """Stands in for the native toolkit, which needs a display."""

    def __init__(self, *, loads: bool) -> None:
        self.loads = loads
        self.destroyed = False
        self.urls: list[str] = []
        self.events = SimpleNamespace(loaded=_FakeEvent())

    def create_window(self, _title: str, *, url: str, **_kwargs: object) -> object:
        self.urls.append(url)
        return self

    def destroy(self) -> None:
        self.destroyed = True

    def start(self, func: object, **_kwargs: object) -> None:
        if self.loads:
            for handler in self.events.loaded.handlers:
                handler()  # type: ignore[operator]
        func()  # type: ignore[operator]


@pytest.mark.parametrize("loads", [True, False])
def test_window_check_requires_the_page_to_load(
    monkeypatch: pytest.MonkeyPatch, loads: bool
) -> None:
    fake = _FakeWebview(loads=loads)
    monkeypatch.setitem(sys.modules, "webview", fake)
    monkeypatch.setattr(selftest, "_WINDOW_SECONDS", 0.01)

    if loads:
        selftest._open_window("http://127.0.0.1:8000")
    else:
        with pytest.raises(cli_selftest._SelftestFailure, match="window-failed"):
            selftest._open_window("http://127.0.0.1:8000")

    assert fake.urls == ["http://127.0.0.1:8000"]
    assert fake.destroyed



def _stub_steps(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, homes: list[Path], *, fail: bool
) -> Path:
    """Run the isolation for real with every packaged-build step replaced."""
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    monkeypatch.setenv("TMPDIR", str(temporary))

    def packaged_runtime(home: Path, _initial: object) -> RuntimeLayout:
        homes.append(home)
        return _layout(tmp_path, kind=DistributionKind.PACKAGED_DESKTOP, home=home)

    def bootstrap(_runtime: object, *, open_window: bool) -> dict[str, bool]:
        (homes[-1] / "left-behind.txt").write_text("session data", encoding="utf-8")
        if fail:
            raise cli_selftest._SelftestFailure("host-session")
        return {"page": True}

    monkeypatch.setattr(selftest, "_packaged_runtime", packaged_runtime)
    monkeypatch.setattr(selftest, "_import_desktop_stack", lambda: None)
    monkeypatch.setattr(selftest, "_verify_resources", lambda _runtime: {"frontend": True})
    monkeypatch.setattr(selftest, "_verify_voice_payload", lambda _runtime: {"manifest": True})
    monkeypatch.setattr(selftest, "_bootstrap_host", bootstrap)
    return temporary


@pytest.mark.parametrize("fail", [False, True])
def test_isolated_home_is_removed_afterwards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail: bool
) -> None:
    homes: list[Path] = []
    temporary = _stub_steps(monkeypatch, tmp_path, homes, fail=fail)
    before = (dict(os.environ), Path.cwd())

    if fail:
        with pytest.raises(cli_selftest._SelftestFailure, match="host-session"):
            selftest._run_isolated_check(SimpleNamespace(), "desktop")
    else:
        assert selftest._run_isolated_check(SimpleNamespace(), "desktop")["ok"] is True

    assert len(homes) == 1
    assert homes[0].parent == temporary
    assert not homes[0].exists()
    assert list(temporary.iterdir()) == []
    assert (dict(os.environ), Path.cwd()) == before


@pytest.mark.parametrize("fail", [False, True])
def test_stdout_never_carries_the_request_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail: bool
) -> None:
    token = "request-token-" + "7" * 40
    _stub_steps(monkeypatch, tmp_path, [], fail=fail)
    monkeypatch.setenv("SERVONAUT_ARTIFACT_SELFTEST_TOKEN", token)
    output = io.StringIO()
    monkeypatch.setattr(
        selftest.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(_request("desktop", token)))
    )
    monkeypatch.setattr(selftest.sys, "stdout", output)

    code = selftest.run_desktop_artifact_selftest(SimpleNamespace())

    assert code == (1 if fail else 0)
    assert token not in output.getvalue()
    assert json.loads(output.getvalue())["ok"] is not fail
