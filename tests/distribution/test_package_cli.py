"""Unit tests for standalone CLI release packaging."""

from __future__ import annotations

import os
from pathlib import Path
import tarfile
import zipfile

import pytest

from scripts.distribution.package_cli import package_standalone_cli


class TestPackageCli:
    def _create_mock_build_dir(self, tmp_path: Path, is_windows: bool = False) -> Path:
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

    def test_package_tar_gz_linux(self, tmp_path: Path) -> None:
        build_dir = self._create_mock_build_dir(tmp_path)
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
        build_dir = self._create_mock_build_dir(tmp_path, is_windows=True)
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
