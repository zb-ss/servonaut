"""Unit tests for the desktop smoke test runner."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from scripts.desktop_shell.model import load_desktop_target_spec
from scripts.desktop_shell.smoke_artifact import (
    DesktopSmokeError,
    DesktopSmokePolicy,
    DesktopSmokeReport,
    load_desktop_smoke_policy,
    smoke_desktop_payload,
)


def _make_mock_payload(
    tmp_path: Path,
    *,
    version: str = "1.2.3",
    platform: str = "linux",
    fail_version: bool = False,
    fail_help: bool = False,
    fail_child: bool = False,
    fail_selftest: bool = False,
) -> Path:
    """Create a mock desktop onedir payload with lightweight executable scripts."""
    root = tmp_path / "servonaut-desktop"
    root.mkdir(parents=True, exist_ok=True)
    ext = ".exe" if platform == "win32" else ""

    cli = root / f"servonaut{ext}"
    child = root / f"servonaut-desktop-child{ext}"
    gui = root / f"servonaut-desktop{ext}"

    cli_script = f"""#!{sys.executable}
import sys
args = sys.argv[1:]
if args == ["--version"]:
    if {fail_version}:
        sys.exit(1)
    print("servonaut {version}")
    sys.exit(0)
elif args == ["--help"]:
    if {fail_help}:
        sys.exit(1)
    print("usage: servonaut [options]")
    sys.exit(0)
elif args == ["--mcp"]:
    print("mcp dummy", file=sys.stderr)
    sys.exit(0)
else:
    sys.stderr.write("unrecognized option\\n")
    sys.exit(2)
"""

    child_script = f"""#!{sys.executable}
import sys
# Without valid parent frame on stdin, exit 1
if {fail_child}:
    sys.exit(0)
sys.exit(1)
"""

    gui_script = f"""#!{sys.executable}
import json, os, sys
args = sys.argv[1:]
if args and args[0] == "--_artifact-selftest":
    expected = os.environ.get("SERVONAUT_ARTIFACT_SELFTEST_TOKEN", "")
    try:
        data = json.loads(sys.stdin.read())
        token = data.get("token")
        if token != expected:
            sys.exit(1)
    except Exception:
        sys.exit(1)
    if {fail_selftest}:
        print(json.dumps({{"schema_version": 1, "ok": False, "error": "test-err"}}))
        sys.exit(0)
    print(json.dumps({{"schema_version": 1, "ok": True}}))
    sys.exit(0)
sys.exit(0)
"""

    for file_path, content in (
        (cli, cli_script),
        (child, child_script),
        (gui, gui_script),
    ):
        file_path.write_text(content, encoding="utf-8")
        file_path.chmod(0o755)

    return root


def test_load_desktop_smoke_policy():
    """Verify default smoke policy loads valid fields."""
    policy = load_desktop_smoke_policy()
    assert isinstance(policy, DesktopSmokePolicy)
    assert policy.schema_version == 1
    assert policy.public_command_timeout_seconds > 0
    assert policy.child_rejection_timeout_seconds > 0


def test_load_desktop_smoke_policy_invalid(tmp_path: Path):
    """Verify invalid policy raises DesktopSmokeError."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_text(json.dumps({"schema_version": 2}), encoding="utf-8")
    with pytest.raises(DesktopSmokeError, match="missing required keys"):
        load_desktop_smoke_policy(bad_file)


def test_smoke_desktop_payload_success(tmp_path: Path):
    """Verify end-to-end smoke test succeeds with valid mock payload."""
    payload = _make_mock_payload(tmp_path, version="1.2.3")
    target = load_desktop_target_spec("linux-x64-ubuntu-22.04")
    evidence_dir = tmp_path / "evidence"

    report = smoke_desktop_payload(
        payload,
        target,
        product_version="1.2.3",
        evidence_dir=evidence_dir,
        skip_mcp=True,
    )

    assert isinstance(report, DesktopSmokeReport)
    assert report.overall_ok is True
    assert "cli_version" in report.checks
    assert "cli_help" in report.checks
    assert "cli_bad_args" in report.checks
    assert "child_unauthorized_rejection" in report.checks
    assert "gui_selftest" in report.checks
    assert "gui_selftest_auth_rejection" in report.checks

    report_path = evidence_dir / f"smoke-report-{target.name}.json"
    assert report_path.is_file()
    saved = json.loads(report_path.read_text(encoding="utf-8"))
    assert saved["overall_ok"] is True


def test_smoke_desktop_payload_version_mismatch(tmp_path: Path):
    """Verify smoke test catches product version mismatch."""
    payload = _make_mock_payload(tmp_path, version="1.2.3")
    target = load_desktop_target_spec("linux-x64-ubuntu-22.04")

    with pytest.raises(DesktopSmokeError, match="did not include version '9.9.9'"):
        smoke_desktop_payload(
            payload,
            target,
            product_version="9.9.9",
            skip_mcp=True,
            skip_selftest=True,
        )


def test_smoke_desktop_payload_child_failure(tmp_path: Path):
    """Verify smoke test fails if child process does not exit 1."""
    payload = _make_mock_payload(tmp_path, version="1.2.3", fail_child=True)
    target = load_desktop_target_spec("linux-x64-ubuntu-22.04")

    with pytest.raises(DesktopSmokeError, match="did not exit with code 1"):
        smoke_desktop_payload(
            payload,
            target,
            product_version="1.2.3",
            skip_mcp=True,
            skip_selftest=True,
        )


def test_smoke_desktop_payload_selftest_failure(tmp_path: Path):
    """Verify smoke test catches selftest reporting failure."""
    payload = _make_mock_payload(tmp_path, version="1.2.3", fail_selftest=True)
    target = load_desktop_target_spec("linux-x64-ubuntu-22.04")

    with pytest.raises(DesktopSmokeError, match="GUI selftest reported failure"):
        smoke_desktop_payload(
            payload,
            target,
            product_version="1.2.3",
            skip_mcp=True,
        )


def test_smoke_desktop_payload_missing_executable(tmp_path: Path):
    """Verify smoke test catches missing executable."""
    payload = _make_mock_payload(tmp_path, version="1.2.3")
    (payload / "servonaut").unlink()
    target = load_desktop_target_spec("linux-x64-ubuntu-22.04")

    with pytest.raises(
        DesktopSmokeError, match="Missing CLI console helper executable"
    ):
        smoke_desktop_payload(
            payload,
            target,
            product_version="1.2.3",
            skip_mcp=True,
        )


_SMOKE_POLICY_PATH = (
    Path(__file__).resolve().parents[2] / "packaging" / "desktop_shell" / "smoke-policy.json"
)


def _selftest_policy(tmp_path: Path, targets: list[str]) -> DesktopSmokePolicy:
    raw = json.loads(_SMOKE_POLICY_PATH.read_text(encoding="utf-8"))
    raw["selftest_targets"] = targets
    policy_path = tmp_path / "smoke-policy.json"
    policy_path.write_text(json.dumps(raw), encoding="utf-8")
    return load_desktop_smoke_policy(policy_path)


def _build_metadata(tmp_path: Path, *, embedded: bool) -> Path:
    metadata = tmp_path / "build-metadata"
    metadata.mkdir()
    (metadata / "dependency-provenance.json").write_text(
        json.dumps({"require_artifact_selftest": embedded}), encoding="utf-8"
    )
    return metadata


def test_smoke_refuses_to_skip_an_embedded_runnable_selftest(tmp_path: Path):
    """A target that can run the embedded self-test must not skip it."""
    payload = _make_mock_payload(tmp_path, version="1.2.3")
    target = load_desktop_target_spec("linux-x64-ubuntu-22.04")
    policy = _selftest_policy(tmp_path, [target.name])

    with pytest.raises(DesktopSmokeError, match="cannot be skipped"):
        smoke_desktop_payload(
            payload,
            target,
            product_version="1.2.3",
            policy=policy,
            skip_mcp=True,
            skip_selftest=True,
            build_metadata_dir=_build_metadata(tmp_path, embedded=True),
        )


def test_smoke_requires_build_metadata_to_skip_a_runnable_selftest(tmp_path: Path):
    payload = _make_mock_payload(tmp_path, version="1.2.3")
    target = load_desktop_target_spec("linux-x64-ubuntu-22.04")
    policy = _selftest_policy(tmp_path, [target.name])

    with pytest.raises(DesktopSmokeError, match="cannot be skipped"):
        smoke_desktop_payload(
            payload,
            target,
            product_version="1.2.3",
            policy=policy,
            skip_mcp=True,
            skip_selftest=True,
        )


def test_smoke_allows_skip_when_the_build_did_not_embed_the_selftest(tmp_path: Path):
    payload = _make_mock_payload(tmp_path, version="1.2.3")
    target = load_desktop_target_spec("linux-x64-ubuntu-22.04")
    policy = _selftest_policy(tmp_path, [target.name])

    report = smoke_desktop_payload(
        payload,
        target,
        product_version="1.2.3",
        policy=policy,
        skip_mcp=True,
        skip_selftest=True,
        build_metadata_dir=_build_metadata(tmp_path, embedded=False),
    )

    assert "gui_selftest" not in report.checks


def test_smoke_policy_rejects_unknown_selftest_targets(tmp_path: Path):
    with pytest.raises(DesktopSmokeError, match="selftest_targets"):
        _selftest_policy(tmp_path, ["not-a-target"])
