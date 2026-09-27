"""The signable layout of the macOS app bundle.

Payloads here mimic a PyInstaller onedir: Mach-O code is recognised by its
magic bytes only, so fixtures give code files a Mach-O header and data files
anything else, whatever their names.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

import pytest

from scripts.distribution.macos_layout import (
    BundleEntry,
    MacosLayoutError,
    code_files,
    plan_app_layout,
    require_frontend_copy_matches,
    verify_app_layout,
)
from scripts.distribution.package_macos import MacosPackagingError, assemble_app_bundle
from scripts.distribution.payload_tree import walk_payload

pytestmark = pytest.mark.skipif(os.name == "nt", reason="payload links need POSIX symlinks")

_MACHO = b"\xcf\xfa\xed\xfe" + bytes(28)
_FAT_MACHO = b"\xca\xfe\xba\xbe" + bytes(28)
_UV = b"\xcf\xfa\xed\xfe publisher-signed uv"


class _Payload:
    """A PyInstaller-style onedir payload under construction."""

    def __init__(self, root: Path) -> None:
        self.root = root
        for name in ("servonaut-desktop", "servonaut-desktop-child", "servonaut"):
            self.file(name, _MACHO, mode=0o755)
        self.file("servonaut-runtime.json", b'{"distribution": "packaged-desktop"}')
        self.file("_internal/base_library.zip", b"PK")

    def file(self, relative: str, content: bytes = b"data", *, mode: int = 0o644) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def link(self, relative: str, target: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, path)


@pytest.fixture
def payload(tmp_path: Path) -> _Payload:
    return _Payload(tmp_path / "payload")


def _assemble(payload: _Payload, tmp_path: Path) -> Path:
    return assemble_app_bundle(payload.root, tmp_path / "out", "2.28.0")


def _is_link_to(path: Path, target: str) -> bool:
    return path.is_symlink() and os.readlink(path) == target and path.exists()


class TestCodeDetection:
    def test_code_is_recognised_by_magic_bytes_not_by_name(self, payload: _Payload) -> None:
        payload.file("_internal/_speedups.cpython-312-darwin.so", b"not a binary")
        payload.file("_internal/helper-tool", _MACHO, mode=0o755)
        payload.file("_internal/universal", _FAT_MACHO)

        found = code_files(payload.root, walk_payload(payload.root))

        internal = {path for path in found if path.parts[0] == "_internal"}
        assert internal == {
            PurePosixPath("_internal/helper-tool"),
            PurePosixPath("_internal/universal"),
        }

    def test_an_executable_that_is_not_macho_is_refused(self, payload: _Payload) -> None:
        payload.file("servonaut", b"#!/bin/sh\n", mode=0o755)
        entries = walk_payload(payload.root)

        with pytest.raises(MacosLayoutError, match="'servonaut' is not Mach-O code"):
            plan_app_layout(entries, code_files(payload.root, entries))


class TestPlacement:
    def test_executables_alone_are_code_in_contents_macos(
        self, payload: _Payload, tmp_path: Path
    ) -> None:
        app = _assemble(payload, tmp_path)

        macos = app / "Contents" / "MacOS"
        assert sorted(entry.name for entry in macos.iterdir()) == [
            "servonaut",
            "servonaut-desktop",
            "servonaut-desktop-child",
            "servonaut-runtime.json",
        ]
        for name in ("servonaut", "servonaut-desktop", "servonaut-desktop-child"):
            assert (macos / name).is_file() and not (macos / name).is_symlink()
            assert (macos / name).stat().st_mode & 0o777 == 0o755

    def test_the_runtime_marker_is_data_linked_beside_the_executables(
        self, payload: _Payload, tmp_path: Path
    ) -> None:
        app = _assemble(payload, tmp_path)

        marker = app / "Contents" / "Resources" / "servonaut-runtime.json"
        assert marker.is_file() and not marker.is_symlink()
        link = app / "Contents" / "MacOS" / "servonaut-runtime.json"
        assert _is_link_to(link, "../Resources/servonaut-runtime.json")
        assert link.read_bytes() == (payload.root / "servonaut-runtime.json").read_bytes()

    def test_top_level_code_and_data_are_placed_by_kind_and_cross_linked(
        self, payload: _Payload, tmp_path: Path
    ) -> None:
        payload.file("_internal/libcrypto.3.dylib", _MACHO, mode=0o755)

        app = _assemble(payload, tmp_path)

        frameworks, resources = app / "Contents" / "Frameworks", app / "Contents" / "Resources"
        assert (frameworks / "libcrypto.3.dylib").is_file()
        assert not (frameworks / "libcrypto.3.dylib").is_symlink()
        assert _is_link_to(resources / "libcrypto.3.dylib", "../Frameworks/libcrypto.3.dylib")
        assert (resources / "base_library.zip").is_file()
        assert not (resources / "base_library.zip").is_symlink()
        assert _is_link_to(frameworks / "base_library.zip", "../Resources/base_library.zip")

    def test_single_kind_directories_are_placed_whole_and_linked(
        self, payload: _Payload, tmp_path: Path
    ) -> None:
        payload.file("_internal/botocore/data/ec2/service.json")
        payload.file("_internal/lib-dynload/_ssl.cpython-312-darwin.so", _MACHO, mode=0o755)

        app = _assemble(payload, tmp_path)

        frameworks, resources = app / "Contents" / "Frameworks", app / "Contents" / "Resources"
        assert (resources / "botocore" / "data" / "ec2" / "service.json").is_file()
        assert _is_link_to(frameworks / "botocore", "../Resources/botocore")
        assert (frameworks / "lib-dynload" / "_ssl.cpython-312-darwin.so").is_file()
        assert _is_link_to(resources / "lib-dynload", "../Frameworks/lib-dynload")

    def test_mixed_directories_exist_on_both_sides_with_file_links(
        self, payload: _Payload, tmp_path: Path
    ) -> None:
        payload.file("_internal/objc/_objc.cpython-312-darwin.so", _MACHO, mode=0o755)
        payload.file("_internal/objc/notes.txt")
        payload.file("_internal/objc/data/table.json")

        app = _assemble(payload, tmp_path)

        frameworks = app / "Contents" / "Frameworks" / "objc"
        resources = app / "Contents" / "Resources" / "objc"
        assert (frameworks / "_objc.cpython-312-darwin.so").is_file()
        assert not (frameworks / "_objc.cpython-312-darwin.so").is_symlink()
        assert _is_link_to(
            resources / "_objc.cpython-312-darwin.so",
            "../../Frameworks/objc/_objc.cpython-312-darwin.so",
        )
        assert (resources / "notes.txt").is_file() and not (resources / "notes.txt").is_symlink()
        assert _is_link_to(frameworks / "notes.txt", "../../Resources/objc/notes.txt")
        assert _is_link_to(frameworks / "data", "../../Resources/objc/data")

    def test_dotted_code_directories_are_renamed_and_linked(
        self, payload: _Payload, tmp_path: Path
    ) -> None:
        payload.file("_internal/vendor.libs/libx.dylib", _MACHO, mode=0o755)
        payload.file("_internal/example-1.0.dist-info/METADATA")

        app = _assemble(payload, tmp_path)

        frameworks = app / "Contents" / "Frameworks"
        assert (frameworks / "vendor__dot__libs" / "libx.dylib").is_file()
        assert _is_link_to(frameworks / "vendor.libs", "vendor__dot__libs")
        assert (frameworks / "vendor.libs" / "libx.dylib").is_file()
        # A data directory lives in Resources and keeps its name everywhere.
        assert _is_link_to(frameworks / "example-1.0.dist-info", "../Resources/example-1.0.dist-info")

    def test_framework_bundles_stay_whole_in_contents_frameworks(
        self, payload: _Payload, tmp_path: Path
    ) -> None:
        payload.file("_internal/Python.framework/Versions/3.12/Python", _MACHO, mode=0o755)
        payload.file("_internal/Python.framework/Versions/3.12/Resources/Info.plist", b"<plist/>")
        payload.link("_internal/Python.framework/Versions/Current", "3.12")
        payload.link("_internal/Python.framework/Python", "Versions/Current/Python")
        payload.link("_internal/Python", "Python.framework/Versions/3.12/Python")

        app = _assemble(payload, tmp_path)

        framework = app / "Contents" / "Frameworks" / "Python.framework"
        assert (framework / "Versions" / "3.12" / "Resources" / "Info.plist").is_file()
        assert _is_link_to(framework / "Versions" / "Current", "3.12")
        assert _is_link_to(framework / "Python", "Versions/Current/Python")
        resources = app / "Contents" / "Resources"
        assert _is_link_to(resources / "Python.framework", "../Frameworks/Python.framework")
        for side in ("Frameworks", "Resources"):
            assert _is_link_to(
                app / "Contents" / side / "Python", "Python.framework/Versions/3.12/Python"
            )

    def test_uv_stays_code_beside_its_linked_voice_inputs(
        self, payload: _Payload, tmp_path: Path
    ) -> None:
        payload.file("_internal/voice/uv", _UV, mode=0o755)
        payload.file("_internal/voice/voice-runtime.json", b"{}")
        payload.file("_internal/voice/servonaut-2.28.0-py3-none-any.whl", b"PK")

        app = _assemble(payload, tmp_path)

        frameworks = app / "Contents" / "Frameworks" / "voice"
        resources = app / "Contents" / "Resources" / "voice"
        uv = frameworks / "uv"
        assert uv.is_file() and not uv.is_symlink()
        assert uv.read_bytes() == _UV
        assert _is_link_to(resources / "uv", "../../Frameworks/voice/uv")
        for name in ("voice-runtime.json", "servonaut-2.28.0-py3-none-any.whl"):
            assert (resources / name).is_file() and not (resources / name).is_symlink()
            assert _is_link_to(frameworks / name, f"../../Resources/voice/{name}")

    def test_data_keeps_its_executable_bit_and_code_is_executable(
        self, payload: _Payload, tmp_path: Path
    ) -> None:
        payload.file("_internal/tool.sh", b"#!/bin/sh\n", mode=0o755)
        payload.file("_internal/libz.dylib", _MACHO, mode=0o644)

        app = _assemble(payload, tmp_path)

        assert (app / "Contents/Resources/tool.sh").stat().st_mode & 0o777 == 0o755
        assert (app / "Contents/Resources/base_library.zip").stat().st_mode & 0o777 == 0o644
        assert (app / "Contents/Frameworks/libz.dylib").stat().st_mode & 0o777 == 0o755

    def test_every_link_resolves_inside_the_bundle(
        self, payload: _Payload, tmp_path: Path
    ) -> None:
        payload.file("_internal/pkg/sub.dir/_m.so", _MACHO, mode=0o755)
        payload.file("_internal/pkg/sub.dir/data.txt")
        payload.file("_internal/pkg/data/x.json")
        payload.link("_internal/pkg/alias.so", "sub.dir/_m.so")

        app = _assemble(payload, tmp_path)

        links = [path for path in app.rglob("*") if path.is_symlink()]
        assert links
        for link in links:
            assert link.resolve(strict=True).is_relative_to(app.resolve())
        assert (app / "Contents/Frameworks/pkg/alias.so").read_bytes() == _MACHO
        assert (app / "Contents/Resources/pkg/alias.so").read_bytes() == _MACHO

    def test_the_layout_is_deterministic(self, payload: _Payload, tmp_path: Path) -> None:
        payload.file("_internal/objc/_objc.so", _MACHO, mode=0o755)
        payload.file("_internal/objc/notes.txt")
        entries = walk_payload(payload.root)
        code = code_files(payload.root, entries)

        first = plan_app_layout(entries, code)

        assert first == plan_app_layout(list(reversed(entries)), code)
        assert first == sorted(first)
        assert len({entry.path for entry in first}) == len(first)
        assert all(isinstance(entry, BundleEntry) for entry in first)


class TestPayloadRules:
    def test_an_unexpected_top_level_entry_is_refused(
        self, payload: _Payload, tmp_path: Path
    ) -> None:
        payload.file("README.txt")

        with pytest.raises(MacosPackagingError, match="unexpected top-level payload entries"):
            _assemble(payload, tmp_path)

    def test_a_payload_without_its_contents_directory_is_refused(
        self, tmp_path: Path
    ) -> None:
        payload = _Payload(tmp_path / "payload")
        (payload.root / "_internal" / "base_library.zip").unlink()
        (payload.root / "_internal").rmdir()

        with pytest.raises(MacosPackagingError, match="contents directory '_internal' is missing"):
            _assemble(payload, tmp_path)

    def test_the_identical_top_level_frontend_copy_is_left_out(
        self, payload: _Payload, tmp_path: Path
    ) -> None:
        for root in ("frontend", "_internal/frontend"):
            payload.file(f"{root}/index.html", b"<html>")
            payload.file(f"{root}/manifest.json", b"{}")

        app = _assemble(payload, tmp_path)

        assert not (app / "Contents" / "MacOS" / "frontend").exists()
        assert (app / "Contents" / "Resources" / "frontend" / "index.html").read_bytes() == b"<html>"
        assert _is_link_to(app / "Contents" / "Frameworks" / "frontend", "../Resources/frontend")

    @pytest.mark.parametrize("change", ["content", "extra-file"])
    def test_a_differing_frontend_copy_is_refused(self, payload: _Payload, change: str) -> None:
        for root in ("frontend", "_internal/frontend"):
            payload.file(f"{root}/index.html", b"<html>")
        if change == "content":
            payload.file("frontend/index.html", b"<html>changed")
        else:
            payload.file("frontend/extra.js", b"")

        with pytest.raises(MacosLayoutError, match="frontend copy"):
            require_frontend_copy_matches(payload.root, walk_payload(payload.root))


class TestVerifyAppLayout:
    @pytest.fixture
    def app(self, payload: _Payload, tmp_path: Path) -> Path:
        payload.file("_internal/Python.framework/Versions/3.12/Python", _MACHO, mode=0o755)
        payload.file("_internal/Python.framework/Versions/3.12/Resources/Info.plist", b"<plist/>")
        return _assemble(payload, tmp_path)

    def test_an_assembled_bundle_passes(self, app: Path) -> None:
        verify_app_layout(app)

    @pytest.mark.parametrize(
        ("relative", "content", "message"),
        [
            ("Contents/Frameworks/stray.json", b"{}", "data file in a code location"),
            ("Contents/MacOS/notes.txt", b"notes", "data file in a code location"),
            ("Contents/Resources/libstray.dylib", _MACHO, "code outside"),
            ("Contents/Frameworks/pkg.libs/libx.dylib", _MACHO, "code directory name contains a dot"),
        ],
    )
    def test_misplaced_content_is_refused(
        self, app: Path, relative: str, content: bytes, message: str
    ) -> None:
        path = app / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

        with pytest.raises(MacosLayoutError, match=message):
            verify_app_layout(app)

    def test_a_framework_keeps_its_own_data(self, app: Path) -> None:
        info = app / "Contents/Frameworks/Python.framework/Versions/3.12/Resources/Info.plist"

        assert info.is_file()
        verify_app_layout(app)
