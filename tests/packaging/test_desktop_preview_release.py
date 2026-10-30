"""Versions, release identity and asset names of the desktop previews attached to releases."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.desktop_shell.model import DESKTOP_TARGET_NAMES
from scripts.distribution.desktop_preview import (
    MACOS_TARGETS,
    DesktopPreviewError,
    declared_versions,
    main,
    preview_for_tag,
    require_marker_identity,
    require_matching_checkout,
)
from scripts.standalone_cli.release_identity import ReleaseIdentity

_REPO_ROOT = Path(__file__).resolve().parents[2]
_RELEASE_POLICY = _REPO_ROOT / ".github" / "scripts" / "release-policy.py"
# Characters GitHub keeps in a release asset name; it renames others.
_SAFE_ASSET_NAME = re.compile(r"[A-Za-z0-9._-]+")


def _checkout(root: Path, pyproject_version: str, init_version: str | None = None) -> Path:
    (root / "src" / "servonaut").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "servonaut"\nversion = "{pyproject_version}"\n',
        encoding="utf-8",
    )
    (root / "src" / "servonaut" / "__init__.py").write_text(
        f"__version__ = '{init_version or pyproject_version}'\n", encoding="utf-8"
    )
    return root


def test_a_release_candidate_sorts_before_its_release() -> None:
    preview = preview_for_tag("v2.28.0rc1")

    assert preview.product_version == "2.28.0rc1"
    assert preview.debian_version == "2.28.0~rc1"
    assert preview.prerelease is True
    assert preview.deb_asset == "servonaut-desktop-preview_2.28.0rc1_amd64.deb"
    assert preview.sums_asset == "servonaut-desktop-preview_2.28.0rc1_SHA256SUMS"


def test_a_release_keeps_its_version() -> None:
    preview = preview_for_tag("v2.28.0")

    assert preview.product_version == "2.28.0"
    assert preview.debian_version == "2.28.0"
    assert preview.prerelease is False
    assert preview.deb_asset == "servonaut-desktop-preview_2.28.0_amd64.deb"
    assert preview.sums_asset == "servonaut-desktop-preview_2.28.0_SHA256SUMS"


@pytest.mark.parametrize("tag", ["v2.28.0", "v2.28.0rc1", "v10.0.3rc12"])
def test_asset_names_survive_upload_unchanged(tag: str) -> None:
    preview = preview_for_tag(tag)

    for name in (preview.deb_asset, preview.sums_asset):
        assert _SAFE_ASSET_NAME.fullmatch(name), name
        assert name.startswith("servonaut-desktop-preview_")


@pytest.mark.parametrize(
    "tag",
    [
        "",
        "2.28.0",
        "v2.28",
        "v2.28.0-preview.1",
        "v2.28.0rc0",
        "v2.28.0-rc1",
        "v2.28.0.rc1",
        "v2.28.0a1",
        "v02.28.0",
        "refs/tags/v2.28.0",
        "v2.28.0\n",
    ],
)
def test_other_tags_carry_no_preview(tag: str) -> None:
    with pytest.raises(DesktopPreviewError, match="vX.Y.ZrcN"):
        preview_for_tag(tag)


def test_outputs_name_every_value_the_workflow_reads() -> None:
    outputs = preview_for_tag("v2.28.0rc1").outputs()

    assert outputs == {
        "tag": "v2.28.0rc1",
        "product-version": "2.28.0rc1",
        "debian-version": "2.28.0~rc1",
        "package-name": "servonaut",
        "architecture": "amd64",
        "deb-asset": "servonaut-desktop-preview_2.28.0rc1_amd64.deb",
        "sums-asset": "servonaut-desktop-preview_2.28.0rc1_SHA256SUMS",
        "prerelease": "true",
        "channel": "preview",
        "packaging-revision": "1",
    }


@pytest.mark.parametrize(
    ("tag", "identity"),
    [
        ("v2.28.0", ReleaseIdentity("stable", 1)),
        ("v2.28.0rc1", ReleaseIdentity("preview", 1)),
        ("v10.0.3rc12", ReleaseIdentity("preview", 1)),
    ],
)
def test_the_tag_decides_the_release_identity(tag: str, identity: ReleaseIdentity) -> None:
    preview = preview_for_tag(tag)

    assert preview.identity == identity
    for outputs in (preview.outputs(), preview.macos_outputs()):
        assert outputs["channel"] == identity.channel
        assert outputs["packaging-revision"] == str(identity.packaging_revision)


def test_the_macos_preview_has_one_image_per_target_and_its_own_sums() -> None:
    preview = preview_for_tag("v2.28.0rc1")

    assert preview.macos_outputs() == {
        "tag": "v2.28.0rc1",
        "product-version": "2.28.0rc1",
        "dmg-asset-macos-arm64": "servonaut-desktop-preview_2.28.0rc1_macos-arm64.dmg",
        "dmg-asset-macos-x64": "servonaut-desktop-preview_2.28.0rc1_macos-x64.dmg",
        "sums-asset": "servonaut-desktop-preview_2.28.0rc1_macos_SHA256SUMS",
        "prerelease": "true",
        "channel": "preview",
        "packaging-revision": "1",
    }
    # Both previews are attached to the same release.
    linux = {preview.deb_asset, preview.sums_asset}
    macos = {preview.macos_dmg_asset(target) for target in MACOS_TARGETS}
    assert len(macos | {preview.macos_sums_asset}) == len(MACOS_TARGETS) + 1
    assert not linux & (macos | {preview.macos_sums_asset})


@pytest.mark.parametrize("tag", ["v2.28.0", "v2.28.0rc1", "v10.0.3rc12"])
def test_macos_asset_names_survive_upload_unchanged(tag: str) -> None:
    preview = preview_for_tag(tag)

    for name in (*map(preview.macos_dmg_asset, MACOS_TARGETS), preview.macos_sums_asset):
        assert _SAFE_ASSET_NAME.fullmatch(name), name
        assert name.startswith(f"servonaut-desktop-preview_{preview.product_version}_")


@pytest.mark.parametrize("target", ["linux-x64-ubuntu-22.04", "macos-universal", "arm64", ""])
def test_only_the_macos_desktop_targets_have_an_image(target: str) -> None:
    with pytest.raises(DesktopPreviewError, match="macos-arm64, macos-x64"):
        preview_for_tag("v2.28.0").macos_dmg_asset(target)


def test_the_macos_targets_are_desktop_targets() -> None:
    macos = {name for name in DESKTOP_TARGET_NAMES if name.startswith("macos-")}
    assert set(MACOS_TARGETS) == macos


def test_the_repository_declares_one_version_twice() -> None:
    pyproject, init = declared_versions(_REPO_ROOT)

    assert pyproject == init


def test_a_matching_checkout_is_accepted(tmp_path: Path) -> None:
    checkout = _checkout(tmp_path, "2.28.0rc1")

    require_matching_checkout(preview_for_tag("v2.28.0rc1"), checkout)


@pytest.mark.parametrize(
    ("pyproject_version", "init_version"),
    [("2.27.0", "2.27.0"), ("2.28.0rc1", "2.28.0"), ("2.28.0", "2.28.0rc1")],
)
def test_a_checkout_disagreeing_with_the_tag_is_refused(
    tmp_path: Path, pyproject_version: str, init_version: str
) -> None:
    checkout = _checkout(tmp_path, pyproject_version, init_version)

    with pytest.raises(DesktopPreviewError, match="does not match the package version"):
        require_matching_checkout(preview_for_tag("v2.28.0rc1"), checkout)


def test_an_unreadable_declaration_is_refused(tmp_path: Path) -> None:
    checkout = _checkout(tmp_path, "2.28.0")
    (checkout / "src" / "servonaut" / "__init__.py").write_text(
        "from ._version import __version__\n", encoding="utf-8"
    )

    with pytest.raises(DesktopPreviewError, match="one static version"):
        declared_versions(checkout)


def test_reads_the_versions_the_release_workflow_sets(tmp_path: Path) -> None:
    """A candidate commit carries whatever release-policy.py set-version wrote."""
    checkout = tmp_path / "checkout"
    (checkout / "src" / "servonaut").mkdir(parents=True)
    shutil.copy(_REPO_ROOT / "pyproject.toml", checkout / "pyproject.toml")
    shutil.copy(
        _REPO_ROOT / "src" / "servonaut" / "__init__.py",
        checkout / "src" / "servonaut" / "__init__.py",
    )
    subprocess.run(
        [sys.executable, str(_RELEASE_POLICY), "set-version", "2.99.0rc3"],
        cwd=checkout,
        check=True,
        capture_output=True,
    )

    assert declared_versions(checkout) == ("2.99.0rc3", "2.99.0rc3")
    require_matching_checkout(preview_for_tag("v2.99.0rc3"), checkout)


def test_plan_prints_github_outputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    checkout = _checkout(tmp_path, "2.28.0")

    assert main(["plan", "--tag", "v2.28.0", "--checkout", str(checkout)]) == 0

    lines = capsys.readouterr().out.splitlines()
    assert "debian-version=2.28.0" in lines
    assert "deb-asset=servonaut-desktop-preview_2.28.0_amd64.deb" in lines
    assert "prerelease=false" in lines
    assert all(re.fullmatch(r"[a-z-]+=[^\s]+", line) for line in lines)


def test_plan_fails_loudly_on_a_version_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    checkout = _checkout(tmp_path, "2.27.0")

    assert main(["plan", "--tag", "v2.28.0rc1", "--checkout", str(checkout)]) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("::error::v2.28.0rc1 does not match")


def test_plan_runs_as_a_module(tmp_path: Path) -> None:
    """The workflow's own invocation, with the product sources on the path."""
    checkout = _checkout(tmp_path, "2.28.0rc2")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.distribution.desktop_preview",
            "plan",
            "--tag",
            "v2.28.0rc2",
            "--checkout",
            str(checkout),
        ],
        cwd=_REPO_ROOT,
        env={"PYTHONPATH": str(_REPO_ROOT / "src"), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "debian-version=2.28.0~rc2" in result.stdout.splitlines()


def test_plan_prints_the_macos_preview(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    checkout = _checkout(tmp_path, "2.28.0")

    argv = ["plan", "--tag", "v2.28.0", "--checkout", str(checkout), "--platform", "macos"]
    assert main(argv) == 0

    lines = capsys.readouterr().out.splitlines()
    planned = preview_for_tag("v2.28.0").macos_outputs()
    assert lines == [f"{key}={value}" for key, value in planned.items()]
    assert "channel=stable" in lines
    assert "dmg-asset-macos-x64=servonaut-desktop-preview_2.28.0_macos-x64.dmg" in lines
    assert all(re.fullmatch(r"[a-z0-9-]+=[^\s]+", line) for line in lines)


def test_the_macos_plan_also_refuses_a_checkout_disagreeing_with_the_tag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    checkout = _checkout(tmp_path, "2.27.0")

    argv = ["plan", "--tag", "v2.28.0", "--checkout", str(checkout), "--platform", "macos"]
    assert main(argv) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("::error::v2.28.0 does not match")


# ---------------------------------------------------------------------------
# The release identity of a packaged build
# ---------------------------------------------------------------------------


def _marker(tmp_path: Path, **fields: object) -> Path:
    """A runtime marker as the desktop builder writes it for v2.28.0rc1."""
    marker = {
        "schema_version": 1,
        "distribution": "packaged-desktop",
        "product_version": "2.28.0rc1",
        "build_revision": "1234",
        "channel": "preview",
        "packaging_revision": 1,
        "console_helper": "servonaut",
        "desktop_child": "servonaut-desktop-child",
        **fields,
    }
    path = tmp_path / "servonaut-runtime.json"
    path.write_text(json.dumps({k: v for k, v in marker.items() if v is not None}), "utf-8")
    return path


def test_a_marker_carrying_the_tags_release_is_accepted(tmp_path: Path) -> None:
    identity = require_marker_identity(preview_for_tag("v2.28.0rc1"), _marker(tmp_path))

    assert identity == ReleaseIdentity("preview", 1)


@pytest.mark.parametrize(
    ("fields", "reason"),
    [
        # A development build: stable, the builder's default without release inputs.
        ({"channel": "stable"}, "follows the stable channel at packaging revision 1, but"),
        ({"packaging_revision": 2}, "at packaging revision 2, but v2.28.0rc1 needs the preview"),
        ({"product_version": "2.28.0"}, "is version '2.28.0', but v2.28.0rc1 needs 2.28.0rc1"),
        ({"channel": None}, "runtime marker release channel must be one of"),
        ({"packaging_revision": "1"}, "runtime marker packaging revision must be an integer"),
        ({"distribution": "standalone-cli"}, "does not describe a packaged-desktop build"),
    ],
)
def test_a_marker_of_another_build_is_refused(
    tmp_path: Path, fields: dict[str, object], reason: str
) -> None:
    with pytest.raises(DesktopPreviewError, match=re.escape(reason)):
        require_marker_identity(preview_for_tag("v2.28.0rc1"), _marker(tmp_path, **fields))


@pytest.mark.parametrize("content", ["", "[]", "{", "\udcff"])
def test_an_unreadable_marker_is_refused(tmp_path: Path, content: str) -> None:
    marker = tmp_path / "servonaut-runtime.json"
    marker.write_bytes(content.encode("utf-8", "surrogateescape"))

    with pytest.raises(DesktopPreviewError, match="runtime marker"):
        require_marker_identity(preview_for_tag("v2.28.0"), marker)


def test_a_missing_marker_is_refused(tmp_path: Path) -> None:
    with pytest.raises(DesktopPreviewError, match="could not be read"):
        require_marker_identity(preview_for_tag("v2.28.0"), tmp_path / "absent.json")


def test_check_marker_reports_the_identity(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["check-marker", "--tag", "v2.28.0rc1", "--marker", str(_marker(tmp_path))]) == 0

    assert capsys.readouterr().out == (
        "The packaged build is 2.28.0rc1 on the preview channel at packaging revision 1.\n"
    )


def test_check_marker_fails_loudly(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    marker = _marker(tmp_path, channel="stable")

    assert main(["check-marker", "--tag", "v2.28.0rc1", "--marker", str(marker)]) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("::error::The packaged build follows the stable channel")
