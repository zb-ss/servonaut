"""Behaviour tests for the desktop build engine around PyInstaller."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.desktop_shell.build as desktop_build
from scripts.desktop_shell.model import (
    DesktopBuildPolicy,
    DesktopBuildRequest,
    DesktopPolicyValidationError,
    DesktopTargetSpec,
    load_desktop_build_policy,
    load_desktop_target_spec,
    load_voice_runtime_policy,
)
from scripts.desktop_shell.voice_bundle import VoiceBundleError
from scripts.standalone_cli.release_identity import DEVELOPMENT_IDENTITY, ReleaseIdentity

_REPO_ROOT = Path(__file__).resolve().parents[2]
_POLICY_PATH = _REPO_ROOT / "packaging" / "desktop_shell" / "target-policy.json"
_VERSION = "2.26.3"


@pytest.fixture
def target() -> DesktopTargetSpec:
    return load_desktop_target_spec(_POLICY_PATH, "linux-x64-ubuntu-22.04")


@pytest.fixture
def wheel(tmp_path: Path) -> Path:
    path = tmp_path / f"servonaut-{_VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            f"servonaut-{_VERSION}.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: servonaut\nVersion: {_VERSION}\n",
        )
    return path


def _request(
    wheel: Path, target: DesktopTargetSpec, output_dir: Path
) -> DesktopBuildRequest:
    return DesktopBuildRequest(
        wheel=wheel,
        target=target,
        product_version=_VERSION,
        build_revision="rev1",
        source_commit="commit1",
        output_dir=output_dir,
    )


def _context(tmp_path: Path, **policy_overrides: int) -> desktop_build._BuildContext:
    policy = dataclasses.replace(load_desktop_build_policy(), **policy_overrides)
    return desktop_build._BuildContext(
        python=Path(sys.executable),
        environment=desktop_build._sanitized_environment(),
        working_directory=tmp_path,
        policy=policy,
    )


def _stage_outputs(staging_root: Path) -> tuple[Path, Path]:
    payload = staging_root / "dist" / "servonaut-desktop"
    payload.mkdir(parents=True)
    (payload / "servonaut-desktop").write_text("gui")
    metadata = staging_root / "build-metadata"
    warnings = metadata / "pyinstaller" / "warn-servonaut_desktop.txt"
    warnings.parent.mkdir(parents=True)
    warnings.write_text("missing module named example\n")
    return payload, metadata


def test_the_artifact_selftest_is_not_a_build_option(
    wheel: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The GUI entry always bundles the self-test, so a build cannot claim otherwise."""
    monkeypatch.setattr(desktop_build, "build_desktop", lambda _request: None)
    base = [
        "--wheel",
        str(wheel),
        "--target",
        "linux-x64-ubuntu-22.04",
        "--output-dir",
        str(tmp_path / "out"),
    ]

    for option in ("--require-artifact-selftest", "--no-require-artifact-selftest"):
        with pytest.raises(SystemExit) as error:
            desktop_build.main([*base, option])
        assert error.value.code == 2
    assert "servonaut_desktop.py" in str(desktop_build._GUI_ENTRY)
    assert "--_artifact-selftest" in desktop_build._GUI_ENTRY.read_text(encoding="utf-8")


def test_main_stamps_the_development_identity_unless_told_otherwise(
    wheel: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    requests: list[DesktopBuildRequest] = []
    monkeypatch.setattr(desktop_build, "build_desktop", requests.append)
    base = [
        "--wheel",
        str(wheel),
        "--target",
        "linux-x64-ubuntu-22.04",
        "--output-dir",
        str(tmp_path / "out"),
    ]

    assert desktop_build.main(base) == 0
    assert (
        desktop_build.main([*base, "--channel", "preview", "--packaging-revision", "3"])
        == 0
    )

    assert [request.release_identity for request in requests] == [
        DEVELOPMENT_IDENTITY,
        ReleaseIdentity("preview", 3),
    ]


def _release_argv(wheel: Path, tmp_path: Path, tag: str, *identity: str) -> list[str]:
    return [
        "--wheel",
        str(wheel),
        "--target",
        "linux-x64-ubuntu-22.04",
        "--output-dir",
        str(tmp_path / "out"),
        "--release-tag",
        tag,
        *identity,
    ]


@pytest.mark.parametrize(
    ("tag", "identity_args", "reason"),
    [
        (f"v{_VERSION}", [], "require an explicit --packaging-revision"),
        (f"v{_VERSION}", ["--channel", "stable"], "require an explicit --packaging-revision"),
        (
            f"v{_VERSION}",
            ["--channel", "preview", "--packaging-revision", "2"],
            "contradicts the stable release tag",
        ),
        (
            f"v{_VERSION}-preview.1",
            ["--channel", "stable", "--packaging-revision", "2"],
            "contradicts the preview release tag",
        ),
        ("v9.9.9", ["--packaging-revision", "2"], "does not match the product version"),
        (f"v{_VERSION}-rc.1", ["--packaging-revision", "2"], "must be a stable"),
        (f"v{_VERSION}", ["--packaging-revision", "0"], "integer from 1 to 65535"),
    ],
)
def test_release_builds_refuse_an_identity_their_tag_contradicts(
    wheel: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tag: str,
    identity_args: list[str],
    reason: str,
) -> None:
    monkeypatch.setattr(
        desktop_build,
        "build_desktop",
        lambda _request: pytest.fail("an inconsistent release build must not start"),
    )

    with pytest.raises(SystemExit) as error:
        desktop_build.main(_release_argv(wheel, tmp_path, tag, *identity_args))

    assert error.value.code == 2
    assert reason in capsys.readouterr().err


@pytest.mark.parametrize(
    ("tag", "identity_args", "expected"),
    [
        (f"v{_VERSION}", ["--packaging-revision", "2"], ReleaseIdentity("stable", 2)),
        (
            f"v{_VERSION}-preview.3",
            ["--packaging-revision", "1"],
            ReleaseIdentity("preview", 1),
        ),
        (
            f"v{_VERSION}-preview.3",
            ["--channel", "preview", "--packaging-revision", "4"],
            ReleaseIdentity("preview", 4),
        ),
    ],
)
def test_release_build_takes_its_channel_from_the_tag(
    wheel: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tag: str,
    identity_args: list[str],
    expected: ReleaseIdentity,
) -> None:
    requests: list[DesktopBuildRequest] = []
    monkeypatch.setattr(desktop_build, "build_desktop", requests.append)

    assert desktop_build.main(_release_argv(wheel, tmp_path, tag, *identity_args)) == 0
    assert requests[0].release_identity == expected


def _pin_host_python(
    monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    major, minor = version.split(".")
    monkeypatch.setattr(
        desktop_build.host_platform, "python_version_tuple", lambda: (major, minor, "0")
    )


def test_host_target_mismatch_is_refused_before_output_is_created(
    wheel: Path,
    target: DesktopTargetSpec,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_host_python(monkeypatch, target.python_version)
    monkeypatch.setattr(desktop_build.sys, "platform", "linux")
    monkeypatch.setattr(desktop_build.host_platform, "machine", lambda: "aarch64")
    output_dir = tmp_path / "out"

    with pytest.raises(DesktopPolicyValidationError, match="built on x86_64, not arm64"):
        desktop_build.build_desktop(_request(wheel, target, output_dir))

    assert not output_dir.exists()


def test_host_platform_mismatch_is_refused(
    target: DesktopTargetSpec, monkeypatch: pytest.MonkeyPatch
) -> None:
    _pin_host_python(monkeypatch, target.python_version)
    monkeypatch.setattr(desktop_build.sys, "platform", "darwin")

    with pytest.raises(DesktopPolicyValidationError, match="built on linux"):
        desktop_build._validate_host_target(target)


def test_host_python_mismatch_is_refused(
    target: DesktopTargetSpec, monkeypatch: pytest.MonkeyPatch
) -> None:
    _pin_host_python(monkeypatch, "3.13")

    with pytest.raises(DesktopPolicyValidationError, match="require Python 3.12, not 3.13"):
        desktop_build._validate_host_target(target)


def test_non_empty_output_directory_is_refused_before_building(
    wheel: Path,
    target: DesktopTargetSpec,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(desktop_build, "_validate_host_target", lambda target: None)

    def unexpected_build(*args: object) -> tuple[Path, Path]:
        raise AssertionError("the build must not start")

    monkeypatch.setattr(desktop_build, "_build_staged_payload", unexpected_build)
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    (output_dir / "servonaut-desktop").mkdir()

    with pytest.raises(DesktopPolicyValidationError, match="must be empty"):
        desktop_build.build_desktop(_request(wheel, target, output_dir))


def test_build_publishes_payload_and_persisted_warning_file(
    wheel: Path,
    target: DesktopTargetSpec,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(desktop_build, "_validate_host_target", lambda target: None)
    monkeypatch.setattr(
        desktop_build,
        "_build_staged_payload",
        lambda request, staging_root, policy: _stage_outputs(staging_root),
    )
    output_dir = tmp_path / "out"

    result = desktop_build.build_desktop(_request(wheel, target, output_dir))

    assert result.pyinstaller_warning_file.is_file()
    assert result.pyinstaller_warning_file.is_relative_to(result.build_metadata_dir)
    assert sorted(path.name for path in output_dir.iterdir()) == [
        "build-metadata",
        "servonaut-desktop",
    ]


def test_failed_publish_rolls_back_every_output(
    wheel: Path,
    target: DesktopTargetSpec,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(desktop_build, "_validate_host_target", lambda target: None)
    monkeypatch.setattr(
        desktop_build,
        "_build_staged_payload",
        lambda request, staging_root, policy: _stage_outputs(staging_root),
    )
    publish = desktop_build._publish_directory

    def publish_then_fail(source: Path, destination: Path, published: list) -> Path:
        if published:
            raise OSError("simulated rename failure")
        return publish(source, destination, published)

    monkeypatch.setattr(desktop_build, "_publish_directory", publish_then_fail)
    output_dir = tmp_path / "out"

    with pytest.raises(DesktopPolicyValidationError, match="desktop build failed"):
        desktop_build.build_desktop(_request(wheel, target, output_dir))

    assert not output_dir.exists()


def test_capture_build_metadata_persists_warnings_and_every_toc(
    wheel: Path,
    target: DesktopTargetSpec,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        desktop_build, "_write_runtime_notice", lambda path, notice: path.touch()
    )
    monkeypatch.setattr(
        desktop_build,
        "write_embedded_notice_metadata",
        lambda path, notices: path.touch(),
    )
    spec_work = tmp_path / "work" / "servonaut_desktop"
    spec_work.mkdir(parents=True)
    (spec_work / "warn-servonaut_desktop.txt").write_text("warnings\n")
    for index in range(3):
        for kind in ("Analysis", "PYZ"):
            (spec_work / f"{kind}-{index:02d}.toc").write_text(f"[('{kind}{index}',)]")
    metadata = tmp_path / "build-metadata"
    metadata.mkdir()

    notices = SimpleNamespace(runtime=None, embedded=None)

    desktop_build._capture_build_metadata(
        tmp_path / "work", metadata, _request(wheel, target, tmp_path), notices
    )

    assert (metadata / "pyinstaller" / "warn-servonaut_desktop.txt").is_file()
    assert (metadata / "runtime-notice.json").is_file()
    assert (metadata / "third-party-notices.json").is_file()
    for index, role in enumerate(("gui", "child", "console")):
        tocs = metadata / "executables" / role / "pyinstaller"
        assert (tocs / "Analysis-00.toc").read_text() == f"[('Analysis{index}',)]"
        assert (tocs / "PYZ-00.toc").read_text() == f"[('PYZ{index}',)]"
    provenance = json.loads((metadata / "dependency-provenance.json").read_text())
    assert provenance["require_artifact_selftest"] is True
    voice_policy = load_voice_runtime_policy()
    assert provenance["voice_runtime"] == {
        "python_version": voice_policy.python_version,
        "uv_version": voice_policy.uv_version,
        "uv_archive_url": voice_policy.uv_archives[target.name].url,
        "uv_archive_sha256": voice_policy.uv_archives[target.name].sha256,
    }


def test_capture_build_metadata_requires_every_toc(
    wheel: Path, target: DesktopTargetSpec, tmp_path: Path
) -> None:
    spec_work = tmp_path / "work" / "servonaut_desktop"
    spec_work.mkdir(parents=True)
    (spec_work / "warn-servonaut_desktop.txt").write_text("warnings\n")
    (spec_work / "Analysis-00.toc").write_text("[]")
    metadata = tmp_path / "build-metadata"
    metadata.mkdir()

    with pytest.raises(DesktopPolicyValidationError, match="PYZ-00.toc"):
        desktop_build._capture_build_metadata(
            tmp_path / "work", metadata, _request(wheel, target, tmp_path), None
        )


def test_pip_is_bootstrapped_from_the_bundled_wheel(
    wheel: Path,
    target: DesktopTargetSpec,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    class _Stop(Exception):
        pass

    def record(context: object, command: list[str], **kwargs: object) -> str:
        commands.append(command)
        raise _Stop

    monkeypatch.setattr(desktop_build, "_create_build_venv", lambda path: Path("py"))
    monkeypatch.setattr(desktop_build, "_run", record)

    with pytest.raises(_Stop):
        desktop_build._build_staged_payload(
            _request(wheel, target, tmp_path), tmp_path, load_desktop_build_policy()
        )

    assert commands == [["py", "-m", "ensurepip"]]


def test_dependencies_install_only_hash_verified_artifacts(
    wheel: Path,
    target: DesktopTargetSpec,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        desktop_build,
        "_run",
        lambda context, command, **kwargs: commands.append(command) or "",
    )
    report = tmp_path / "report.json"

    desktop_build._install_locked_environment(
        _context(tmp_path), _request(wheel, target, tmp_path), report
    )

    tools, locked = commands
    for command in commands:
        assert command[1:4] == ["-m", "pip", "install"]
        for flag in (
            "--isolated",
            "--require-hashes",
            "--disable-pip-version-check",
            "--no-input",
            "--no-deps",
        ):
            assert flag in command
        assert not any(argument.startswith("--upgrade") for argument in command)
    assert tools[-2:] == ["-r", str(desktop_build._SOURCE_BUILD_TOOLS_LOCK)]
    wheel_hash = hashlib.sha256(wheel.read_bytes()).hexdigest()
    assert f"{wheel.resolve().as_uri()}#sha256={wheel_hash}" in locked
    assert "--no-build-isolation" in locked
    assert locked[-2:] == ["-r", str(target.requirements_lock.resolve())]
    assert locked[locked.index("--report") + 1] == str(report)


def test_sanitized_environment_drops_inherited_build_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PYTHONPATH", "/elsewhere")
    monkeypatch.setenv("PIP_INDEX_URL", "https://example.invalid/simple")
    monkeypatch.setenv("SERVONAUT_DESKTOP_FRONTEND_DIR", "/elsewhere")
    monkeypatch.setenv("SERVONAUT_KEEP_ME", "1")

    environment = desktop_build._sanitized_environment()

    assert "PYTHONPATH" not in environment
    assert "PIP_INDEX_URL" not in environment
    assert "SERVONAUT_DESKTOP_FRONTEND_DIR" not in environment
    assert environment["SERVONAUT_KEEP_ME"] == "1"
    assert environment["PYTHONNOUSERSITE"] == "1"


def test_run_failure_reports_bounded_stderr_tail(tmp_path: Path) -> None:
    context = _context(tmp_path, failure_output_tail_chars=256)
    script = "import sys; sys.stderr.write('x' * 5000 + 'LAST-LINE'); sys.exit(3)"

    with pytest.raises(DesktopPolicyValidationError) as raised:
        desktop_build._run(
            context, [sys.executable, "-c", script], timeout_seconds=60, step="probe"
        )

    message = str(raised.value)
    assert message.startswith("probe failed with exit code 3")
    assert message.endswith("LAST-LINE")
    assert len(message) < 400


def test_run_timeout_is_a_domain_error(tmp_path: Path) -> None:
    context = _context(tmp_path)

    with pytest.raises(DesktopPolicyValidationError, match="probe timed out after 1s"):
        desktop_build._run(
            context,
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout_seconds=1,
            step="probe",
        )


def test_run_missing_program_is_a_domain_error(tmp_path: Path) -> None:
    context = _context(tmp_path)

    with pytest.raises(DesktopPolicyValidationError, match="probe could not start"):
        desktop_build._run(
            context,
            [str(tmp_path / "missing-program")],
            timeout_seconds=5,
            step="probe",
        )


def test_build_policy_rejects_out_of_bounds_timeouts(tmp_path: Path) -> None:
    raw = json.loads(
        (_REPO_ROOT / "packaging" / "desktop_shell" / "build-policy.json").read_text()
    )
    raw["pyinstaller_timeout_seconds"] = 0
    policy_path = tmp_path / "build-policy.json"
    policy_path.write_text(json.dumps(raw))

    with pytest.raises(DesktopPolicyValidationError, match="out of bounds"):
        load_desktop_build_policy(policy_path)

    assert isinstance(load_desktop_build_policy(), DesktopBuildPolicy)


def _voice_bundle(root: Path) -> Path:
    voice = root / "voice"
    voice.mkdir(parents=True)
    (voice / "uv").write_bytes(b"\x7fELF uv")
    (voice / "uv").chmod(0o755)
    for name in ("servonaut-2.26.3-py3-none-any.whl", "voice-requirements.txt"):
        (voice / name).write_bytes(name.encode())
    (voice / "voice-runtime.json").write_text("{}")
    return voice


def test_voice_bundle_is_copied_into_the_payload_unchanged(tmp_path: Path) -> None:
    voice = _voice_bundle(tmp_path / "staging")
    payload = tmp_path / "servonaut-desktop"
    (payload / "_internal").mkdir(parents=True)

    desktop_build._install_voice_bundle(payload, voice)

    installed = payload / "_internal" / "voice"
    assert sorted(path.name for path in installed.iterdir()) == sorted(
        path.name for path in voice.iterdir()
    )
    for source in voice.iterdir():
        assert (installed / source.name).read_bytes() == source.read_bytes()
    assert (installed / "uv").stat().st_mode & 0o777 == 0o755


@pytest.mark.parametrize("existing", ["voice", "voice-link"])
def test_voice_bundle_never_merges_into_pyinstaller_output(
    tmp_path: Path, existing: str
) -> None:
    voice = _voice_bundle(tmp_path / "staging")
    internal = tmp_path / "servonaut-desktop" / "_internal"
    internal.mkdir(parents=True)
    if existing == "voice":
        (internal / "voice").mkdir()
    else:
        (internal / "voice").symlink_to(voice, target_is_directory=True)

    with pytest.raises(DesktopPolicyValidationError, match="already contains a voice"):
        desktop_build._install_voice_bundle(tmp_path / "servonaut-desktop", voice)


def test_voice_bundle_requires_the_pyinstaller_contents_directory(tmp_path: Path) -> None:
    voice = _voice_bundle(tmp_path / "staging")
    (tmp_path / "servonaut-desktop").mkdir()

    with pytest.raises(DesktopPolicyValidationError, match="contents directory"):
        desktop_build._install_voice_bundle(tmp_path / "servonaut-desktop", voice)


def test_voice_bundle_is_staged_before_dependencies_and_pyinstaller(
    wheel: Path,
    target: DesktopTargetSpec,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staged: list[tuple[Path, str]] = []
    monkeypatch.setattr(
        desktop_build, "_bootstrap_build_venv", lambda root, policy: _context(root)
    )

    def refuse_download(staging_root: Path, spec: DesktopTargetSpec, *args: object) -> Path:
        staged.append((staging_root, spec.name))
        raise VoiceBundleError("the uv archive does not match its pinned SHA-256")

    def unexpected(*args: object) -> None:
        raise AssertionError("the long build steps must not start")

    monkeypatch.setattr(desktop_build, "stage_voice_bundle", refuse_download)
    monkeypatch.setattr(desktop_build, "_prepare_spec_inputs", unexpected)
    monkeypatch.setattr(desktop_build, "_run_pyinstaller", unexpected)

    with pytest.raises(DesktopPolicyValidationError, match="pinned SHA-256"):
        desktop_build._build_staged_payload(
            _request(wheel, target, tmp_path), tmp_path, load_desktop_build_policy()
        )

    assert staged == [(tmp_path, target.name)]


def test_malformed_voice_lock_is_refused_before_output_is_created(
    wheel: Path,
    target: DesktopTargetSpec,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(desktop_build, "_validate_host_target", lambda target: None)
    lock = tmp_path / "voice-lock.txt"
    lock.write_text("numpy>=1.24\n", encoding="ascii")
    monkeypatch.setattr(desktop_build, "voice_lock_path", lambda name: lock)
    output_dir = tmp_path / "out"

    with pytest.raises(DesktopPolicyValidationError, match="only name==version pins"):
        desktop_build.build_desktop(_request(wheel, target, output_dir))

    assert not output_dir.exists()
