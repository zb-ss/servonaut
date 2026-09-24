"""Unit tests for standalone CLI release packaging."""

from __future__ import annotations

import os
from pathlib import Path
import tarfile
import zipfile

import pytest

from scripts.distribution.package_cli import package_standalone_cli
from scripts.distribution.payload_tree import PayloadTreeError


def _create_mock_build_dir(tmp_path: Path, is_windows: bool = False) -> Path:
    build_dir = tmp_path / "mock_build"
    build_dir.mkdir(parents=True, exist_ok=True)

    bin_name = "servonaut.exe" if is_windows else "servonaut"
    binary = build_dir / bin_name
    binary.write_bytes(b"#!/bin/sh\necho 'mock servonaut binary'\n")
    # Set executable bit
    binary.chmod(0o755)

    data_dir = build_dir / "resources"
    data_dir.mkdir()
    (data_dir / "config.sample").write_text("sample config")
    return build_dir


class TestPackageCli:
    def test_package_tar_gz_linux(self, tmp_path: Path) -> None:
        build_dir = _create_mock_build_dir(tmp_path)
        out_dir = tmp_path / "dist"

        archive_path, sha256_1, size_1 = package_standalone_cli(
            build_dir,
            out_dir,
            target="linux-x64-ubuntu-22.04",
            product_version="2.27.0",
            source_epoch=1700000000,
        )

        assert archive_path.is_file()
        assert archive_path.name == "servonaut-2.27.0-linux-x64-ubuntu-22.04.tar.gz"
        assert size_1 > 0
        assert len(sha256_1) == 64

        # Read back tar.gz and verify members
        with tarfile.open(archive_path, "r:gz") as tar:
            names = tar.getnames()
            assert "servonaut" in names
            assert "resources/config.sample" in names
            servonaut_info = tar.getmember("servonaut")
            assert servonaut_info.mode == 0o755
            assert servonaut_info.mtime == 1700000000
            assert servonaut_info.uid == 0
            assert servonaut_info.gid == 0

        # Determinism check: pack again to a different destination and compare sha256
        out_dir_2 = tmp_path / "dist_2"
        _, sha256_2, _ = package_standalone_cli(
            build_dir,
            out_dir_2,
            target="linux-x64-ubuntu-22.04",
            product_version="2.27.0",
            source_epoch=1700000000,
        )
        assert sha256_1 == sha256_2

    def test_package_zip_windows(self, tmp_path: Path) -> None:
        build_dir = _create_mock_build_dir(tmp_path, is_windows=True)
        out_dir = tmp_path / "dist"

        archive_path, sha256_1, size_1 = package_standalone_cli(
            build_dir,
            out_dir,
            target="windows-x64",
            product_version="2.27.0",
            source_epoch=1700000000,
        )

        assert archive_path.is_file()
        assert archive_path.name == "servonaut-2.27.0-windows-x64.zip"
        assert size_1 > 0
        assert len(sha256_1) == 64

        # Read back zip and verify members
        with zipfile.ZipFile(archive_path, "r") as zf:
            namelist = zf.namelist()
            assert "servonaut.exe" in namelist
            assert "resources/config.sample" in namelist

        # Determinism check
        out_dir_2 = tmp_path / "dist_2"
        _, sha256_2, _ = package_standalone_cli(
            build_dir,
            out_dir_2,
            target="windows-x64",
            product_version="2.27.0",
            source_epoch=1700000000,
        )
        assert sha256_1 == sha256_2

    def test_missing_binary_raises(self, tmp_path: Path) -> None:
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        with pytest.raises(FileNotFoundError, match="Expected executable"):
            package_standalone_cli(
                empty_dir,
                tmp_path / "dist",
                target="linux-x64-ubuntu-22.04",
                product_version="2.27.0",
            )

    def test_missing_build_dir_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="Build directory does not exist"):
            package_standalone_cli(
                tmp_path / "nonexistent",
                tmp_path / "dist",
                target="linux-x64-ubuntu-22.04",
                product_version="2.27.0",
            )


class TestPackageCliPayloadLinks:
    """Symbolic links are archived as links and must stay inside the payload."""

    def _create_linked_build_dir(self, tmp_path: Path) -> Path:
        build_dir = tmp_path / "linked_build"
        real_dir = build_dir / "_internal" / "real"
        real_dir.mkdir(parents=True)
        binary = build_dir / "servonaut"
        binary.write_bytes(b"#!/bin/sh\n")
        binary.chmod(0o755)
        (real_dir / "lib.so.1").write_bytes(b"L" * 64)
        os.symlink("real/lib.so.1", build_dir / "_internal" / "lib.so")
        os.symlink("real", build_dir / "_internal" / "linkdir")
        return build_dir

    def test_tar_keeps_symlinked_files_and_directories_as_links(self, tmp_path: Path) -> None:
        build_dir = self._create_linked_build_dir(tmp_path)

        archive_path, _, _ = package_standalone_cli(
            build_dir,
            tmp_path / "dist",
            target="linux-x64-ubuntu-22.04",
            product_version="2.27.0",
            source_epoch=1700000000,
        )

        with tarfile.open(archive_path, "r:gz") as tar:
            members = {member.name: member for member in tar.getmembers()}
        assert members["_internal/lib.so"].issym()
        assert members["_internal/lib.so"].linkname == "real/lib.so.1"
        assert members["_internal/linkdir"].issym()
        assert members["_internal/linkdir"].linkname == "real"
        assert "_internal/linkdir/lib.so.1" not in members
        assert members["_internal/real/lib.so.1"].isfile()

    @pytest.mark.parametrize("link_target", ["/etc/hostname", "../../outside"])
    def test_link_leaving_the_payload_is_rejected(self, tmp_path: Path, link_target: str) -> None:
        build_dir = _create_mock_build_dir(tmp_path)
        os.symlink(link_target, build_dir / "resources" / "escape")

        with pytest.raises(PayloadTreeError, match="Unsafe symbolic link"):
            package_standalone_cli(
                build_dir,
                tmp_path / "dist",
                target="linux-x64-ubuntu-22.04",
                product_version="2.27.0",
            )

    def test_windows_zip_rejects_symlinks(self, tmp_path: Path) -> None:
        build_dir = _create_mock_build_dir(tmp_path, is_windows=True)
        os.symlink("config.sample", build_dir / "resources" / "alias.sample")

        with pytest.raises(PayloadTreeError, match="symbolic link"):
            package_standalone_cli(
                build_dir,
                tmp_path / "dist",
                target="windows-x64",
                product_version="2.27.0",
            )



class TestPackageCliTargets:
    """Targets come from the standalone target policy."""

    @pytest.mark.parametrize("target", ["linux-x64", "../escape", "windows-arm64"])
    def test_unknown_target_is_rejected(self, tmp_path: Path, target: str) -> None:
        build_dir = tmp_path / "build"
        build_dir.mkdir()
        (build_dir / "servonaut").write_bytes(b"#!/bin/sh\n")
        (build_dir / "servonaut.exe").write_bytes(b"MZ")

        with pytest.raises(ValueError, match="target"):
            package_standalone_cli(
                build_dir,
                tmp_path / "dist",
                target=target,
                product_version="2.27.0",
            )
        assert not (tmp_path / "dist").exists() or not any((tmp_path / "dist").iterdir())
