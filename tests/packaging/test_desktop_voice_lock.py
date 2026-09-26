"""Behaviour tests for the managed voice runtime lock generator (no network)."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

import pytest
from packaging.requirements import Requirement

import scripts.desktop_shell.voice_lock as voice_lock
from scripts.desktop_shell.model import (
    DesktopTargetSpec,
    load_desktop_target_spec,
    voice_lock_path,
    voice_release_cutoff,
    voice_wheel_platforms,
)
from scripts.desktop_shell.voice_bundle import VoiceBundleError, load_voice_lock
from scripts.desktop_shell.voice_lock import (
    VoiceLockError,
    marker_environment,
    parse_pip_report,
    render_lock,
    target_closure,
)



def _sha(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()


def _item(name: str, version: str, requires: list[str], filename: str | None = None) -> dict:
    wheel = filename or f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
    return {
        "metadata": {"name": name, "version": version, "requires_dist": requires},
        "download_info": {
            "url": f"https://files.example.invalid/packages/{wheel}",
            "archive_info": {"hashes": {"sha256": _sha(name)}},
        },
    }


def _report(*items: dict) -> dict:
    return {"version": "1", "pip_version": "26.0.1", "install": list(items)}


def _target(name: str) -> DesktopTargetSpec:
    return load_desktop_target_spec(name)


def test_voice_wheel_platforms_follow_each_target_floor() -> None:
    assert voice_wheel_platforms(_target("windows-x64")) == ("win_amd64",)
    assert voice_wheel_platforms(_target("macos-x64")) == ("macosx_13_0_x86_64",)
    assert voice_wheel_platforms(_target("macos-arm64")) == ("macosx_13_0_arm64",)
    linux = voice_wheel_platforms(_target("linux-x64-ubuntu-22.04"))
    assert linux[0] == "manylinux_2_35_x86_64"
    assert linux[-2:] == ("manylinux_2_17_x86_64", "manylinux2014_x86_64")


def test_marker_environment_describes_the_target_not_the_build_host() -> None:
    windows = marker_environment("windows-x64", "3.12.14")
    assert windows["sys_platform"] == "win32"
    assert windows["platform_system"] == "Windows"
    assert windows["python_version"] == "3.12"
    assert windows["python_full_version"] == "3.12.14"
    assert marker_environment("macos-arm64", "3.12.14")["platform_machine"] == "arm64"


def test_parse_pip_report_indexes_canonical_names_and_requires_hashed_wheels() -> None:
    resolved = parse_pip_report(_report(_item("Typing_Extensions", "4.16.0", [])))
    assert set(resolved) == {"typing-extensions"}
    assert resolved["typing-extensions"].wheel.filename == (
        "Typing_Extensions-4.16.0-py3-none-any.whl"
    )

    sdist = _item("numpy", "2.5.3", [], filename="numpy-2.5.3.tar.gz")
    with pytest.raises(VoiceLockError, match="hashed wheel"):
        parse_pip_report(_report(sdist))
    with pytest.raises(VoiceLockError, match="unsupported"):
        parse_pip_report({"version": "0", "install": []})


def _tqdm_report(*extra: dict) -> dict:
    return _report(
        _item("faster-whisper", "1.2.1", ["tqdm", "av>=11; extra == 'video'"]),
        _item("tqdm", "4.70.1", ['colorama; platform_system == "Windows"']),
        *extra,
    )


def test_closure_reports_dependencies_only_the_target_selects() -> None:
    resolved = parse_pip_report(_tqdm_report())
    roots = [Requirement("faster-whisper>=1.0")]

    linux, linux_missing = target_closure(
        roots, resolved, marker_environment("linux-x64-ubuntu-22.04", "3.12.14")
    )
    windows, windows_missing = target_closure(
        roots, resolved, marker_environment("windows-x64", "3.12.14")
    )

    assert linux == {"faster-whisper", "tqdm"} and linux_missing == []
    assert windows == {"faster-whisper", "tqdm"}
    assert [str(requirement) for requirement in windows_missing] == [
        'colorama; platform_system == "Windows"'
    ]


def test_closure_drops_host_only_dependencies_and_follows_requested_extras() -> None:
    resolved = parse_pip_report(
        _tqdm_report(
            _item("av", "18.1.0", []),
            _item("colorama", "0.4.6", []),
        )
    )
    environment = marker_environment("linux-x64-ubuntu-22.04", "3.12.14")

    plain, _ = target_closure([Requirement("faster-whisper")], resolved, environment)
    with_extra, _ = target_closure(
        [Requirement("faster-whisper[video]")], resolved, environment
    )

    assert plain == {"faster-whisper", "tqdm"}
    assert with_extra == {"faster-whisper", "tqdm", "av"}


def test_closure_rejects_a_resolution_outside_a_specifier() -> None:
    resolved = parse_pip_report(_report(_item("numpy", "1.20.0", [])))

    with pytest.raises(VoiceLockError, match="violates"):
        target_closure(
            [Requirement("numpy>=1.24")],
            resolved,
            marker_environment("windows-x64", "3.12.14"),
        )


def test_resolve_target_adds_target_only_dependencies_and_renders_a_parseable_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "voice.in"
    source.write_text("# comment\nfaster-whisper>=1.0\n", encoding="utf-8")
    monkeypatch.setattr(voice_lock, "VOICE_REQUIREMENTS_INPUT", source)
    rounds: list[list[str]] = []

    def fake_report(target: object, python_version: str, cutoff: str, added: list) -> dict:
        assert cutoff == "2026-09-01T00:00:00Z"
        rounds.append([str(requirement) for requirement in added])
        extra = [_item("colorama", "0.4.6", [])] if added else []
        return _tqdm_report(*extra)

    monkeypatch.setattr(voice_lock, "_pip_report", fake_report)

    text = voice_lock.resolve_target(
        _target("windows-x64"), "3.12.14", "2026-09-01T00:00:00Z"
    )

    assert rounds == [[], ["colorama"]]
    assert "-r voice.in colorama" in text
    assert "# pip 26.0.1:" in text
    lock = tmp_path / "voice-windows-x64.txt"
    lock.write_text(text, encoding="ascii")
    assert [(pin.name, pin.version) for pin in load_voice_lock(lock)] == [
        ("colorama", "0.4.6"),
        ("faster-whisper", "1.2.1"),
        ("tqdm", "4.70.1"),
    ]


def test_resolve_target_gives_up_when_the_closure_never_closes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "voice.in"
    source.write_text("faster-whisper\n", encoding="utf-8")
    monkeypatch.setattr(voice_lock, "VOICE_REQUIREMENTS_INPUT", source)
    monkeypatch.setattr(voice_lock, "_pip_report", lambda *args: _tqdm_report())

    with pytest.raises(VoiceLockError, match="did not converge"):
        voice_lock.resolve_target(
            _target("windows-x64"), "3.12.14", "2026-09-01T00:00:00Z"
        )


def test_rendered_header_names_the_platform_tags_and_the_regeneration_command() -> None:
    wheel = parse_pip_report(_report(_item("numpy", "2.5.3", [])))["numpy"].wheel
    text = render_lock(
        _target("linux-x64-ubuntu-22.04"),
        [wheel],
        "3.12.14",
        [],
        "26.0.1",
        "2026-09-01T00:00:00Z",
    )

    assert "--platform manylinux_2_35_x86_64 ... manylinux2014_x86_64" in text
    assert "--python-version 3.12.14" in text
    assert "--uploaded-prior-to 2026-09-01T00:00:00Z" in text
    assert "--target linux-x64-ubuntu-22.04" in text
    assert text.endswith(
        f"numpy==2.5.3 \\\n    --hash=sha256:{_sha('numpy')}\n"
        "    # numpy-2.5.3-py3-none-any.whl\n"
    )


def test_release_cutoff_is_the_start_of_the_day_the_cooldown_allows() -> None:
    now = datetime(2026, 9, 25, 1, 40, tzinfo=timezone.utc)

    assert voice_release_cutoff(7, now) == "2026-09-18T00:00:00Z"
    assert voice_release_cutoff(1, now) == "2026-09-24T00:00:00Z"


@pytest.mark.parametrize("cutoff", ["2999-01-01T00:00:00Z", "2026-09-01", "yesterday"])
def test_generator_refuses_a_cutoff_inside_the_cooldown(
    cutoff: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(voice_lock.sys, "version_info", (3, 12, 14))

    def unexpected(*args: object) -> str:
        raise AssertionError("nothing may be resolved")

    monkeypatch.setattr(voice_lock, "resolve_target", unexpected)

    with pytest.raises(SystemExit):
        voice_lock.main(["--target", "windows-x64", "--uploaded-prior-to", cutoff])

    assert "no later than" in capsys.readouterr().err


def test_committed_locks_record_their_cooldown_cutoff() -> None:
    for name in ("windows-x64", "macos-x64", "macos-arm64", "linux-x64-ubuntu-22.04"):
        header = voice_lock_path(name).read_text(encoding="utf-8").split("\n\n", 1)[0]
        assert "--uploaded-prior-to 20" in header, name
        assert "minimum_release_age_days" in header, name


def test_generator_validates_a_lock_before_writing_it_with_lf_endings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "voice-windows-x64.txt"
    output.write_text("reviewed lock\n", encoding="ascii")
    monkeypatch.setattr(voice_lock.sys, "version_info", (3, 12, 14))
    monkeypatch.setattr(voice_lock, "voice_lock_path", lambda name: output)
    monkeypatch.setattr(voice_lock, "resolve_target", lambda *args: "numpy>=1.24\n")

    with pytest.raises(VoiceBundleError, match="only name==version pins"):
        voice_lock.main(["--target", "windows-x64"])
    assert output.read_text(encoding="ascii") == "reviewed lock\n"

    lock = f"numpy==2.5.3 \\\n    --hash=sha256:{'0' * 64}\n"
    monkeypatch.setattr(voice_lock, "resolve_target", lambda *args: lock)
    voice_lock.main(["--target", "windows-x64"])
    assert output.read_bytes() == lock.encode("ascii")
