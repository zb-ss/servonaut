"""Contract tests for Debian (.deb) package assembly, metadata, determinism, and verification."""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from scripts.distribution.package_deb import (
    DEFAULT_DEPENDENCIES,
    REQUIRED_PAYLOAD_FILES,
    DebPackagingError,
    main,
    package_deb,
)
from scripts.distribution.payload_tree import PayloadTreeError
from servonaut.distribution.builder import ManifestBuilder
from servonaut.distribution.manifest import (
    ArtifactKind,
    ReleaseChannel,
)
from servonaut.distribution.trust import TrustPolicy
from servonaut.distribution.verify import verify_release_file
from servonaut.runtime import DistributionKind

# Reserved example domain: a test fixture, not a real contact address.
_MAINTAINER = "Package Maintainer <maintainer@example.org>"


@pytest.fixture
def mock_payload(tmp_path: Path) -> Path:
    """Create a minimal valid onedir desktop payload."""
    payload_dir = tmp_path / "mock-payload"
    payload_dir.mkdir(parents=True)

    # Required executables & marker
    for binary_name in REQUIRED_PAYLOAD_FILES:
        file_path = payload_dir / binary_name
        if binary_name.endswith(".json"):
            file_path.write_text('{"distribution": "packaged-desktop"}', encoding="utf-8")
        else:
            file_path.write_bytes(b"\x7fELFfakebinaryexecutablecontent")
            file_path.chmod(0o755)

    # Nested library in _internal
    internal_dir = payload_dir / "_internal" / "lib"
    internal_dir.mkdir(parents=True)
    shared_lib = internal_dir / "libtest.so"
    shared_lib.write_bytes(b"\x7fELFfakeshareddependency")
    shared_lib.chmod(0o755)

    data_file = payload_dir / "_internal" / "config.dat"
    data_file.write_bytes(b"sample_data")
    data_file.chmod(0o644)

    return payload_dir


def _parse_ar_archive(deb_path: Path) -> list[tuple[str, int, int, int, int, bytes]]:
    """Parse standard ar archive members into tuples of:

    (name, mtime, uid, gid, mode, data)
    """
    raw = deb_path.read_bytes()
    assert raw[:8] == b"!<arch>\n", "Not a valid ar archive"

    members = []
    idx = 8
    while idx < len(raw):
        hdr = raw[idx : idx + 60]
        if len(hdr) < 60:
            break
        name = hdr[0:16].decode("ascii").strip()
        mtime = int(hdr[16:28].decode("ascii").strip())
        uid = int(hdr[28:34].decode("ascii").strip())
        gid = int(hdr[34:40].decode("ascii").strip())
        mode = int(hdr[40:48].decode("ascii").strip(), 8)
        size = int(hdr[48:58].decode("ascii").strip())
        magic = hdr[58:60]
        assert magic == b"`\n", f"Invalid ar header magic for member {name}"

        idx += 60
        data = raw[idx : idx + size]
        members.append((name, mtime, uid, gid, mode, data))

        # Advance past size + optional 1-byte padding
        idx += size
        if size % 2 != 0 and idx < len(raw) and raw[idx : idx + 1] == b"\n":
            idx += 1

    return members


class TestDebPackageStructure:
    """Tests covering .deb ar container format and member structure."""

    def test_package_deb_creates_standard_ar_container(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        out_dir = tmp_path / "out"
        deb_path, sha256_hex, byte_size = package_deb(
            maintainer=_MAINTAINER,
            payload_dir=mock_payload,
            output_dir=out_dir,
            product_version="2.26.3",
            packaging_revision=1,
            source_epoch=1700000000,
        )

        assert deb_path.is_file()
        assert deb_path.name == "servonaut_2.26.3-1_amd64.deb"
        assert len(sha256_hex) == 64
        assert byte_size == deb_path.stat().st_size

        members = _parse_ar_archive(deb_path)
        assert len(members) == 3
        names = [m[0] for m in members]
        assert names == ["debian-binary", "control.tar.gz", "data.tar.gz"]

        # debian-binary content must be 2.0\n
        deb_bin_data = members[0][5]
        assert deb_bin_data == b"2.0\n"

    def test_missing_required_payload_binary_raises_error(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        (mock_payload / "servonaut-desktop").unlink()
        out_dir = tmp_path / "out"

        with pytest.raises(FileNotFoundError, match="servonaut-desktop"):
            package_deb(
                maintainer=_MAINTAINER,
                payload_dir=mock_payload,
                output_dir=out_dir,
                product_version="2.26.3",
            )

    def test_missing_payload_directory_raises_error(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="Payload directory does not exist"):
            package_deb(
                maintainer=_MAINTAINER,
                payload_dir=tmp_path / "nonexistent",
                output_dir=tmp_path / "out",
                product_version="2.26.3",
            )

    def test_custom_filename_is_respected(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        out_dir = tmp_path / "out"
        deb_path, _, _ = package_deb(
            maintainer=_MAINTAINER,
            payload_dir=mock_payload,
            output_dir=out_dir,
            product_version="2.26.3",
            filename="servonaut-desktop.deb",
        )
        assert deb_path.name == "servonaut-desktop.deb"


class TestDebControlMetadata:
    """Tests validating control.tar.gz metadata and dependencies."""

    def test_control_file_fields_and_dependencies(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        out_dir = tmp_path / "out"
        deb_path, _, _ = package_deb(
            maintainer=_MAINTAINER,
            payload_dir=mock_payload,
            output_dir=out_dir,
            product_version="2.26.3",
            packaging_revision=2,
            architecture="amd64",
        )

        members = _parse_ar_archive(deb_path)
        control_tar_data = members[1][5]

        with tarfile.open(fileobj=io.BytesIO(control_tar_data), mode="r:gz") as tar:
            names = tar.getnames()
            assert "./control" in names
            assert "./md5sums" in names
            assert "./postinst" in names
            assert "./postrm" in names

            ctrl_file = tar.extractfile("./control")
            assert ctrl_file is not None
            ctrl_text = ctrl_file.read().decode("utf-8")

        assert "Package: servonaut\n" in ctrl_text
        assert "Version: 2.26.3-2\n" in ctrl_text
        assert "Architecture: amd64\n" in ctrl_text
        assert "Section: utils\n" in ctrl_text
        assert "Priority: optional\n" in ctrl_text
        assert f"Maintainer: {_MAINTAINER}\n" in ctrl_text
        assert "Installed-Size: " in ctrl_text

        # Check required dependencies
        for dep in DEFAULT_DEPENDENCIES:
            assert dep in ctrl_text

    def test_md5sums_contains_valid_checksums(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        out_dir = tmp_path / "out"
        deb_path, _, _ = package_deb(
            maintainer=_MAINTAINER,
            payload_dir=mock_payload,
            output_dir=out_dir,
            product_version="2.26.3",
        )

        members = _parse_ar_archive(deb_path)
        control_tar_data = members[1][5]
        data_tar_data = members[2][5]

        with tarfile.open(fileobj=io.BytesIO(control_tar_data), mode="r:gz") as tar:
            md5_file = tar.extractfile("./md5sums")
            assert md5_file is not None
            md5_text = md5_file.read().decode("utf-8")

        lines = [line.strip() for line in md5_text.splitlines() if line.strip()]
        assert len(lines) > 0

        # Unpack data tar and verify checksums
        with tarfile.open(fileobj=io.BytesIO(data_tar_data), mode="r:gz") as dtar:
            for line in lines:
                md5_hex, rel_path = line.split("  ", 1)
                tar_member = dtar.extractfile(f"./{rel_path}")
                assert tar_member is not None, f"File {rel_path} listed in md5sums not found in data tar"
                computed = hashlib.md5(tar_member.read()).hexdigest()
                assert computed == md5_hex, f"Checksum mismatch for {rel_path}"


class TestDebDataHierarchy:
    """Tests validating data.tar.gz directory layout, symlinks, and permissions."""

    def test_data_tar_hierarchy_and_permissions(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        out_dir = tmp_path / "out"
        deb_path, _, _ = package_deb(
            maintainer=_MAINTAINER,
            payload_dir=mock_payload,
            output_dir=out_dir,
            product_version="2.26.3",
            source_epoch=1700000000,
        )

        members = _parse_ar_archive(deb_path)
        data_tar_data = members[2][5]

        with tarfile.open(fileobj=io.BytesIO(data_tar_data), mode="r:gz") as tar:
            members_by_name = {m.name: m for m in tar.getmembers()}

            # Directory permissions
            assert members_by_name["./opt"].mode == 0o755
            assert members_by_name["./opt/servonaut"].mode == 0o755
            assert members_by_name["./usr/bin"].mode == 0o755

            # Executable modes
            gui_info = members_by_name["./opt/servonaut/servonaut-desktop"]
            assert gui_info.mode == 0o755
            child_info = members_by_name["./opt/servonaut/servonaut-desktop-child"]
            assert child_info.mode == 0o755
            cli_info = members_by_name["./opt/servonaut/servonaut"]
            assert cli_info.mode == 0o755

            # Marker mode
            marker_info = members_by_name["./opt/servonaut/servonaut-runtime.json"]
            assert marker_info.mode == 0o644

            # Symlinks in /usr/bin/
            sym_cli = members_by_name["./usr/bin/servonaut"]
            assert sym_cli.issym()
            assert sym_cli.linkname == "/opt/servonaut/servonaut"

            sym_gui = members_by_name["./usr/bin/servonaut-desktop"]
            assert sym_gui.issym()
            assert sym_gui.linkname == "/opt/servonaut/servonaut-desktop"

            # Desktop entry
            assert "./usr/share/applications/servonaut.desktop" in members_by_name
            desk_entry = members_by_name["./usr/share/applications/servonaut.desktop"]
            assert desk_entry.mode == 0o644

            # Scalable SVG Icon
            assert "./usr/share/icons/hicolor/scalable/apps/servonaut.svg" in members_by_name
            icon_entry = members_by_name["./usr/share/icons/hicolor/scalable/apps/servonaut.svg"]
            assert icon_entry.mode == 0o644

            # Copyright
            assert "./usr/share/doc/servonaut/copyright" in members_by_name


class TestDebianDeterminism:
    """Tests proving bit-for-bit reproducible packaging."""

    def test_deterministic_packaging_hash_equality(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        out1 = tmp_path / "out1"
        out2 = tmp_path / "out2"

        path1, hash1, size1 = package_deb(
            maintainer=_MAINTAINER,
            payload_dir=mock_payload,
            output_dir=out1,
            product_version="2.26.3",
            packaging_revision=1,
            source_epoch=1700000000,
        )
        path2, hash2, size2 = package_deb(
            maintainer=_MAINTAINER,
            payload_dir=mock_payload,
            output_dir=out2,
            product_version="2.26.3",
            packaging_revision=1,
            source_epoch=1700000000,
        )

        assert hash1 == hash2
        assert size1 == size2
        assert path1.read_bytes() == path2.read_bytes()


class TestUserDataPreservation:
    """Tests ensuring user configuration and data in ~/.servonaut is never destroyed."""

    def test_postrm_does_not_contain_destructive_home_commands(self) -> None:
        postrm_file = Path(__file__).resolve().parents[2] / "packaging" / "deb" / "postrm"
        assert postrm_file.is_file()
        content = postrm_file.read_text(encoding="utf-8")

        # Explicit safety assertions
        assert "rm -rf ~/.servonaut" not in content
        assert "rm -rf /home" not in content
        assert "rm -rf $HOME" not in content
        assert "preserved" in content.lower()

    def test_postrm_execution_leaves_user_data_intact(self, tmp_path: Path) -> None:
        postrm_file = Path(__file__).resolve().parents[2] / "packaging" / "deb" / "postrm"

        # Setup mock user home with .servonaut configuration and tokens
        fake_home = tmp_path / "userhome"
        fake_home.mkdir()
        servonaut_dir = fake_home / ".servonaut"
        servonaut_dir.mkdir()
        (servonaut_dir / "tokens.json").write_text('{"token": "secret"}', encoding="utf-8")
        (servonaut_dir / "servers.json").write_text('[{"name": "srv1"}]', encoding="utf-8")

        # Execute postrm with remove and purge arguments
        for action in ("remove", "purge"):
            res = subprocess.run(
                ["/bin/sh", str(postrm_file), action],
                env={"HOME": str(fake_home), "PATH": "/usr/bin:/bin"},
                capture_output=True,
                text=True,
            )
            assert res.returncode == 0
            assert (servonaut_dir / "tokens.json").is_file()
            assert (servonaut_dir / "servers.json").is_file()
            assert (servonaut_dir / "tokens.json").read_text(encoding="utf-8") == '{"token": "secret"}'


class TestSystemToolInteroperability:
    """Tests verifying Debian package with dpkg-deb and desktop-file-validate if installed."""

    @pytest.mark.skipif(
        shutil.which("dpkg-deb") is None, reason="dpkg-deb tool not installed"
    )
    def test_dpkg_deb_inspect_and_extract(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        out_dir = tmp_path / "out"
        deb_path, _, _ = package_deb(
            maintainer=_MAINTAINER,
            payload_dir=mock_payload,
            output_dir=out_dir,
            product_version="2.26.3",
            packaging_revision=1,
        )

        # 1. dpkg-deb -I (inspect control)
        res_info = subprocess.run(
            ["dpkg-deb", "-I", str(deb_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "Package: servonaut" in res_info.stdout
        assert "Version: 2.26.3-1" in res_info.stdout
        assert "Architecture: amd64" in res_info.stdout
        assert "Depends:" in res_info.stdout

        # 2. dpkg-deb -c (list contents)
        res_contents = subprocess.run(
            ["dpkg-deb", "-c", str(deb_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "./opt/servonaut/servonaut" in res_contents.stdout
        assert "./usr/bin/servonaut -> /opt/servonaut/servonaut" in res_contents.stdout
        assert "./usr/share/applications/servonaut.desktop" in res_contents.stdout

        # 3. dpkg-deb -x (extract data)
        extract_dir = tmp_path / "extracted"
        subprocess.run(
            ["dpkg-deb", "-x", str(deb_path), str(extract_dir)],
            capture_output=True,
            text=True,
            check=True,
        )
        assert (extract_dir / "opt" / "servonaut" / "servonaut-desktop").is_file()
        assert (extract_dir / "usr" / "bin" / "servonaut").is_symlink()
        assert (extract_dir / "usr" / "bin" / "servonaut").readlink() == Path(
            "/opt/servonaut/servonaut"
        )

    @pytest.mark.skipif(
        shutil.which("desktop-file-validate") is None,
        reason="desktop-file-validate tool not installed",
    )
    def test_desktop_file_validates_cleanly(self) -> None:
        desktop_file = (
            Path(__file__).resolve().parents[2] / "packaging" / "deb" / "servonaut.desktop"
        )
        res = subprocess.run(
            ["desktop-file-validate", str(desktop_file)],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"Validation failed: {res.stderr}"


class TestManifestIntegration:
    """Tests integrating Debian packages with ManifestBuilder and verify_release_file."""

    def test_manifest_builder_with_deb_artifact_and_verification(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        out_dir = tmp_path / "out"
        deb_path, sha256_hex, byte_size = package_deb(
            maintainer=_MAINTAINER,
            payload_dir=mock_payload,
            output_dir=out_dir,
            product_version="2.26.3",
            packaging_revision=1,
        )

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        key_id = "test-key-2026"

        builder = ManifestBuilder(
            product_version="2.26.3",
            channel=ReleaseChannel.STABLE,
            packaging_revision=1,
            expires_at="2099-01-01T00:00:00Z",
        )
        builder.add_artifact_file(
            deb_path,
            kind=ArtifactKind.UBUNTU_DEB,
            distribution=DistributionKind.PACKAGED_DESKTOP,
            platform="linux",
            arch="x86_64",
            download_url=f"https://github.com/zb-ss/servonaut/releases/download/v2.26.3/{deb_path.name}",
            min_os="Ubuntu 22.04",
            artifact_id="desktop-ubuntu-deb",
        )
        builder.sign_artifact("desktop-ubuntu-deb", private_key)

        manifest = builder.build_signed(private_key, key_id=key_id)
        assert len(manifest.artifacts) == 1
        art = manifest.artifacts[0]
        assert art.kind == ArtifactKind.UBUNTU_DEB
        assert art.distribution == DistributionKind.PACKAGED_DESKTOP
        assert art.platform == "linux"
        assert art.arch == "x86_64"
        assert art.min_os == "Ubuntu 22.04"
        assert art.sha256 == sha256_hex
        assert art.byte_size == byte_size
        assert art.signature is not None

        policy = TrustPolicy(
            trusted_public_keys={key_id: public_key},
            allowed_origin_prefixes=("https://github.com/zb-ss/servonaut/releases/download/",),
        )

        # Successful verification
        valid, msg = verify_release_file(manifest, deb_path, trust_policy=policy)
        assert valid is True
        assert "successfully verified" in msg

        # Tampered verification
        tampered_dir = tmp_path / "tampered"
        tampered_dir.mkdir()
        tampered_deb = tampered_dir / deb_path.name
        tampered_deb.write_bytes(deb_path.read_bytes() + b"\x00")
        valid_t, msg_t = verify_release_file(manifest, tampered_deb, trust_policy=policy)
        assert valid_t is False
        assert "Size mismatch" in msg_t or "integrity verification failed" in msg_t


class TestCLIExecution:
    """Tests executing package_deb CLI entry point."""

    def test_cli_package_deb_success(
        self, mock_payload: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out_dir = tmp_path / "out"
        ret = main([
            "--payload-dir",
            str(mock_payload),
            "--output-dir",
            str(out_dir),
            "--version",
            "2.26.3",
            "--revision",
            "1",
            "--maintainer",
            _MAINTAINER,
        ])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Debian package created:" in captured.out
        assert "SHA-256:" in captured.out

    def test_cli_package_deb_failure(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ret = main([
            "--payload-dir",
            str(tmp_path / "nonexistent"),
            "--output-dir",
            str(tmp_path / "out"),
            "--version",
            "2.26.3",
            "--maintainer",
            _MAINTAINER,
        ])
        assert ret == 1
        captured = capsys.readouterr()
        assert "Error:" in captured.err


def _data_members(deb_path: Path) -> dict[str, tarfile.TarInfo]:
    data_tar_data = _parse_ar_archive(deb_path)[2][5]
    with tarfile.open(fileobj=io.BytesIO(data_tar_data), mode="r:gz") as tar:
        return {member.name: member for member in tar.getmembers()}


def _md5sums_paths(deb_path: Path) -> set[str]:
    control_tar_data = _parse_ar_archive(deb_path)[1][5]
    with tarfile.open(fileobj=io.BytesIO(control_tar_data), mode="r:gz") as tar:
        md5_file = tar.extractfile("./md5sums")
        assert md5_file is not None
        lines = md5_file.read().decode("utf-8").splitlines()
    return {line.split("  ", 1)[1] for line in lines if line}


class TestDebPayloadLinks:
    """Payload symbolic links are packaged as links and must stay inside the payload."""

    def test_symlinked_files_and_directories_are_kept_as_links(
        self, mock_payload: Path, tmp_path: Path
    ) -> None:
        os.symlink("lib/libtest.so", mock_payload / "_internal" / "libtest.so")
        os.symlink("lib", mock_payload / "_internal" / "lib-alias")

        deb_path, _, _ = package_deb(
            payload_dir=mock_payload,
            maintainer=_MAINTAINER,
            output_dir=tmp_path / "out",
            product_version="2.26.3",
        )

        members = _data_members(deb_path)
        file_link = members["./opt/servonaut/_internal/libtest.so"]
        dir_link = members["./opt/servonaut/_internal/lib-alias"]
        assert file_link.issym() and file_link.linkname == "lib/libtest.so"
        assert dir_link.issym() and dir_link.linkname == "lib"
        assert "./opt/servonaut/_internal/lib-alias/libtest.so" not in members

        md5_paths = _md5sums_paths(deb_path)
        assert "opt/servonaut/_internal/lib/libtest.so" in md5_paths
        assert "opt/servonaut/_internal/libtest.so" not in md5_paths

    @pytest.mark.skipif(shutil.which("dpkg-deb") is None, reason="dpkg-deb tool not installed")
    def test_dpkg_deb_extracts_payload_links(self, mock_payload: Path, tmp_path: Path) -> None:
        os.symlink("lib", mock_payload / "_internal" / "lib-alias")
        deb_path, _, _ = package_deb(
            payload_dir=mock_payload,
            maintainer=_MAINTAINER,
            output_dir=tmp_path / "out",
            product_version="2.26.3",
        )

        extract_dir = tmp_path / "extracted"
        subprocess.run(["dpkg-deb", "-x", str(deb_path), str(extract_dir)], check=True)

        alias = extract_dir / "opt" / "servonaut" / "_internal" / "lib-alias"
        assert alias.is_symlink()
        assert (alias / "libtest.so").read_bytes() == b"\x7fELFfakeshareddependency"

    @pytest.mark.parametrize("link_target", ["/etc/hostname", "../../../outside"])
    def test_link_leaving_the_payload_is_rejected(
        self, mock_payload: Path, tmp_path: Path, link_target: str
    ) -> None:
        os.symlink(link_target, mock_payload / "_internal" / "escape")

        with pytest.raises(PayloadTreeError, match="Unsafe symbolic link"):
            package_deb(
                payload_dir=mock_payload,
                maintainer=_MAINTAINER,
                output_dir=tmp_path / "out",
                product_version="2.26.3",
            )


class TestDebMaintainer:
    """The maintainer is an explicit, validated input with no placeholder default."""

    def test_maintainer_is_a_required_argument(self, mock_payload: Path, tmp_path: Path) -> None:
        with pytest.raises(TypeError, match="maintainer"):
            package_deb(  # type: ignore[call-arg]
                payload_dir=mock_payload,
                output_dir=tmp_path / "out",
                product_version="2.26.3",
            )

    def test_cli_requires_maintainer(
        self, mock_payload: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main([
                "--payload-dir",
                str(mock_payload),
                "--output-dir",
                str(tmp_path / "out"),
                "--version",
                "2.26.3",
            ])
        assert excinfo.value.code == 2
        assert "--maintainer" in capsys.readouterr().err

    @pytest.mark.parametrize(
        "maintainer",
        [
            "",
            "Package Maintainer",
            "<maintainer@example.org>",
            "Package Maintainer <not-an-address>",
            "Package Maintainer <maintainer@example.org>\nDescription: injected",
        ],
    )
    def test_malformed_maintainer_is_rejected(
        self, mock_payload: Path, tmp_path: Path, maintainer: str
    ) -> None:
        with pytest.raises(DebPackagingError, match="Maintainer"):
            package_deb(
                payload_dir=mock_payload,
                maintainer=maintainer,
                output_dir=tmp_path / "out",
                product_version="2.26.3",
            )


class TestDebPackagingAssets:
    """Static packaging assets describe the application accurately."""

    _DEB_DIR = Path(__file__).resolve().parents[2] / "packaging" / "deb"

    def test_desktop_entry_categories(self) -> None:
        desktop = (self._DEB_DIR / "servonaut.desktop").read_text(encoding="utf-8")
        categories = [
            line.split("=", 1)[1]
            for line in desktop.splitlines()
            if line.startswith("Categories=")
        ]
        assert categories == ["System;Network;"]

    def test_assets_carry_no_placeholder_contact_address(self) -> None:
        for asset in self._DEB_DIR.iterdir():
            if asset.suffix == ".svg":
                continue
            assert "@example." not in asset.read_text(encoding="utf-8"), asset.name
