"""The Linux build freezes the GTK binding and leaves the host's GTK stack to the host.

Everything here runs without GTK: the build's subprocesses, the probe's
PyInstaller helpers and the frozen payload are all stand-ins.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import zipfile
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

import scripts.desktop_shell.build as desktop_build
from scripts.desktop_shell import linux_gi_probe
from scripts.desktop_shell.linux_abi import (
    GI_ROOT_NAMESPACES,
    REQUIRED_TYPELIBS,
    LinuxAbiError,
    LinuxGiBinding,
    bundled_distribution_version,
    find_bundled_host_libraries,
    missing_gi_payload_components,
    validate_gi_binding_probe,
)
from scripts.desktop_shell.model import (
    DesktopBuildRequest,
    DesktopPolicyValidationError,
    load_desktop_build_policy,
    load_desktop_target_spec,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_POLICY_PATH = _REPO_ROOT / "packaging" / "desktop_shell" / "target-policy.json"
_HOOKS_DIR = _REPO_ROOT / "packaging" / "desktop_shell" / "hooks"
_LINUX = "linux-x64-ubuntu-22.04"
_VERSION = "2.26.3"
_HOST_LIBRARIES = {
    "libcairo.so.2": "/usr/lib/x86_64-linux-gnu/libcairo.so.2",
    "libgirepository-1.0.so.1": "/usr/lib/x86_64-linux-gnu/libgirepository-1.0.so.1",
    "libglib-2.0.so.0": "/lib/x86_64-linux-gnu/libglib-2.0.so.0",
    "libgobject-2.0.so.0": "/lib/x86_64-linux-gnu/libgobject-2.0.so.0",
    "libgtk-3.so.0": "/usr/lib/x86_64-linux-gnu/libgtk-3.so.0",
    "libjavascriptcoregtk-4.1.so.0": "/usr/lib/x86_64-linux-gnu/libjavascriptcoregtk-4.1.so.0",
    "libwebkit2gtk-4.1.so.0": "/usr/lib/x86_64-linux-gnu/libwebkit2gtk-4.1.so.0",
}


@pytest.fixture
def site_packages(tmp_path: Path) -> Path:
    path = tmp_path / "build-venv" / "lib" / "python3.12" / "site-packages"
    path.mkdir(parents=True)
    return path


def _probe(site_packages: Path, **changes: object) -> dict[str, object]:
    probe: dict[str, object] = {
        "pygobject_version": "3.48.2",
        "pycairo_version": "1.29.1",
        "glib_version": "2.72.4",
        "modules": {
            "gi": str(site_packages / "gi" / "__init__.py"),
            "cairo": str(site_packages / "cairo" / "__init__.py"),
        },
        "extension_modules": [
            str(site_packages / "gi" / "_gi.cpython-312-x86_64-linux-gnu.so"),
            str(site_packages / "gi" / "_gi_cairo.cpython-312-x86_64-linux-gnu.so"),
            str(site_packages / "cairo" / "_cairo.cpython-312-x86_64-linux-gnu.so"),
        ],
        "typelibs": {
            name: {"path": f"/usr/lib/girepository-1.0/{name}.typelib", "shared_libraries": []}
            for name in REQUIRED_TYPELIBS
        },
        "host_libraries": dict(_HOST_LIBRARIES),
    }
    probe.update(changes)
    return probe


def test_a_probe_of_the_pinned_binding_is_accepted(site_packages: Path) -> None:
    binding = validate_gi_binding_probe(_probe(site_packages), site_packages)

    assert binding.pygobject_version == "3.48.2"
    assert binding.glib_version == "2.72.4"
    assert set(binding.typelibs) == REQUIRED_TYPELIBS
    assert binding.host_libraries == tuple(sorted(_HOST_LIBRARIES))
    assert LinuxGiBinding.from_json(binding.to_json()) == binding


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        (
            {"modules": {"gi": "/usr/lib/python3/dist-packages/gi/__init__.py", "cairo": "x"}},
            "distro Python modules are never used",
        ),
        ({"pygobject_version": "3.50.0"}, "requires GLib >= 2.80"),
        ({"pygobject_version": "3.48.1"}, "must be exactly 3.48.2"),
        ({"glib_version": "2.70.1"}, "below required floor"),
        ({"pycairo_version": "1.25.1"}, "older than 1.26.0"),
        ({"typelibs": {"Gtk-3.0": {}}}, "typelib closure differs"),
        ({"host_libraries": {"libgtk-3.so.0": "/usr/lib/libgtk-3.so.0"}}, "does not include"),
        ({"host_libraries": {**_HOST_LIBRARIES, "../evil": "/x"}}, "invalid host library name"),
        ({"host_libraries": {**_HOST_LIBRARIES, "libz.so.1": "libz.so.1"}}, "no absolute location"),
        ({"extension_modules": ["/usr/lib/python3/dist-packages/gi/_gi.so"]}, "outside the build venv"),
    ],
)
def test_a_probe_outside_the_contract_is_refused(
    site_packages: Path, changes: dict[str, object], message: str
) -> None:
    with pytest.raises(LinuxAbiError, match=message):
        validate_gi_binding_probe(_probe(site_packages, **changes), site_packages)


def test_a_binding_without_its_cairo_extension_is_refused(site_packages: Path) -> None:
    probe = _probe(site_packages)
    probe["extension_modules"] = probe["extension_modules"][:2]  # type: ignore[index]

    with pytest.raises(LinuxAbiError, match="cairo/_cairo"):
        validate_gi_binding_probe(probe, site_packages)


def test_a_host_library_inside_the_build_venv_is_refused(site_packages: Path) -> None:
    libraries = {**_HOST_LIBRARIES, "libffi.so.8": str(site_packages / "libffi.so.8")}

    with pytest.raises(LinuxAbiError, match="resolves into the build venv"):
        validate_gi_binding_probe(
            _probe(site_packages, host_libraries=libraries), site_packages
        )


def _payload(root: Path) -> Path:
    contents = root / "_internal"
    for relative in (
        "gi/_gi.cpython-312-x86_64-linux-gnu.so",
        "gi/_gi_cairo.cpython-312-x86_64-linux-gnu.so",
        "cairo/_cairo.cpython-312-x86_64-linux-gnu.so",
    ):
        (contents / relative).parent.mkdir(parents=True, exist_ok=True)
        (contents / relative).write_bytes(b"\x7fELF")
    (contents / "gi_typelibs").mkdir()
    for name in REQUIRED_TYPELIBS:
        (contents / "gi_typelibs" / f"{name}.typelib").write_bytes(b"GOBJ")
    return root


def test_a_complete_payload_binding_has_nothing_missing(tmp_path: Path) -> None:
    assert missing_gi_payload_components(_payload(tmp_path)) == []


def test_a_payload_without_the_binding_lists_every_part(tmp_path: Path) -> None:
    problems = missing_gi_payload_components(tmp_path)

    assert len(problems) == len(REQUIRED_TYPELIBS) + 3
    assert "missing gi_typelibs/Gtk-3.0.typelib" in problems
    assert "missing gi/_gi.cpython-312-*.so" in problems


def test_bundled_host_libraries_are_found_anywhere_in_the_payload(tmp_path: Path) -> None:
    payload = _payload(tmp_path)
    (payload / "_internal" / "libcairo.so.2").write_bytes(b"\x7fELF")
    (payload / "_internal" / "nested").mkdir()
    (payload / "_internal" / "nested" / "libgtk-3.so.0").symlink_to("/nowhere")
    (payload / "_internal" / "libssl.so.3").write_bytes(b"\x7fELF")

    assert find_bundled_host_libraries(payload, _HOST_LIBRARIES) == [
        "_internal/libcairo.so.2",
        "_internal/nested/libgtk-3.so.0",
    ]


def test_bundled_distribution_version_reads_copied_metadata(tmp_path: Path) -> None:
    dist_info = tmp_path / "_internal" / "pygobject-3.48.2.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: PyGObject\nVersion: 3.48.2\n\nVersion: body\n"
    )

    assert bundled_distribution_version(tmp_path, "pygobject") == "3.48.2"
    assert bundled_distribution_version(tmp_path, "pycairo") is None


# --- build stages ------------------------------------------------------------


@pytest.fixture
def linux_request(tmp_path: Path) -> DesktopBuildRequest:
    wheel = tmp_path / f"servonaut-{_VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            f"servonaut-{_VERSION}.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: servonaut\nVersion: {_VERSION}\n",
        )
    return DesktopBuildRequest(
        wheel=wheel,
        target=load_desktop_target_spec(_POLICY_PATH, _LINUX),
        product_version=_VERSION,
        build_revision="rev1",
        source_commit="commit1",
        output_dir=tmp_path / "out",
    )


def _context(tmp_path: Path) -> desktop_build._BuildContext:
    return desktop_build._BuildContext(
        python=tmp_path / "venv" / "bin" / "python",
        environment={"PATH": "/usr/bin"},
        working_directory=tmp_path,
        policy=load_desktop_build_policy(),
    )


def test_linux_installs_the_meson_toolchain_then_pycairo_then_the_lock(
    linux_request: DesktopBuildRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[list[str], dict[str, str] | None]] = []
    monkeypatch.setattr(
        desktop_build,
        "_run",
        lambda context, command, environment=None, **kwargs: calls.append(
            (command, environment)
        )
        or "",
    )

    desktop_build._install_locked_environment(
        _context(tmp_path), linux_request, tmp_path / "report.json"
    )

    (tools, _), (meson, meson_env), (pycairo, pycairo_env), (locked, locked_env) = calls
    assert tools[-1] == str(desktop_build._SOURCE_BUILD_TOOLS_LOCK)
    assert meson[-1] == str(desktop_build._GI_BUILD_TOOLS_LOCK)
    assert meson_env is None  # wheels only; nothing builds
    assert "--no-build-isolation" in pycairo
    assert "--no-build-isolation" in locked
    scripts = tmp_path / "venv" / "bin"
    for environment in (pycairo_env, locked_env):
        assert environment == {
            "PATH": "/usr/bin",
            "MESON": str(scripts / "meson"),
            "NINJA": str(scripts / "ninja"),
        }
    requirement = Path(pycairo[-1]).read_text(encoding="utf-8").splitlines()
    assert requirement[0] == "--no-binary pycairo"
    assert requirement[1].startswith("pycairo==")
    assert all(line.strip().startswith("--hash=sha256:") for line in requirement[2:])
    lock_text = linux_request.target.requirements_lock.read_text(encoding="utf-8")
    assert "\n".join(requirement[1:]) in lock_text


_LOCK = """\
--no-binary pycairo
pycairo==1.29.1 ; sys_platform == 'linux' \\
    --hash=sha256:aaaa \\
    --hash=sha256:bbbb
    # via pygobject
pycairo-extra==1.0 \\
    --hash=sha256:cccc
"""


def test_a_locked_requirement_is_copied_with_its_hashes_and_marker() -> None:
    assert desktop_build._locked_requirement(_LOCK, "pycairo") == (
        "--no-binary pycairo\n"
        "pycairo==1.29.1 ; sys_platform == 'linux' \\\n"
        "    --hash=sha256:aaaa \\\n"
        "    --hash=sha256:bbbb\n"
    )


@pytest.mark.parametrize(
    ("lock", "message"),
    [
        ("pycairo-extra==1.0 \\\n    --hash=sha256:cccc\n", "does not pin pycairo"),
        ("pycairo==1.29.1\n", "has no hash"),
        ("pycairo==1.29.1 \\\n    # via pygobject\n", "is malformed"),
    ],
)
def test_a_missing_or_unhashed_locked_requirement_is_refused(lock: str, message: str) -> None:
    with pytest.raises(DesktopPolicyValidationError, match=message):
        desktop_build._locked_requirement(lock, "pycairo")


def test_the_probe_runs_isolated_in_the_build_venv(
    tmp_path: Path, site_packages: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[list[str]] = []

    def run(context: object, command: list[str], **kwargs: object) -> str:
        commands.append(command)
        return json.dumps(_probe(site_packages))

    monkeypatch.setattr(desktop_build, "_run", run)

    binding = desktop_build._probe_gi_binding(_context(tmp_path), site_packages)

    assert binding.pygobject_version == "3.48.2"
    (command,) = commands
    assert command[1:3] == ["-I", str(desktop_build._GI_BINDING_PROBE)]
    assert json.loads(command[3]) == dict(GI_ROOT_NAMESPACES)


@pytest.mark.parametrize(
    ("output", "message"),
    [
        ("not json", "did not report JSON"),
        (json.dumps({"pygobject_version": "3.48.2"}), "GTK binding is invalid"),
    ],
)
def test_an_unusable_probe_report_fails_the_build(
    tmp_path: Path,
    site_packages: Path,
    monkeypatch: pytest.MonkeyPatch,
    output: str,
    message: str,
) -> None:
    monkeypatch.setattr(desktop_build, "_run", lambda *args, **kwargs: output)

    with pytest.raises(DesktopPolicyValidationError, match=message):
        desktop_build._probe_gi_binding(_context(tmp_path), site_packages)


def test_profile_and_provenance_carry_the_binding(
    linux_request: DesktopBuildRequest, tmp_path: Path, site_packages: Path
) -> None:
    binding = validate_gi_binding_probe(_probe(site_packages), site_packages)

    profile = json.loads(
        desktop_build._write_profile(tmp_path, linux_request, binding).read_text()
    )
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    desktop_build._write_build_provenance(metadata, linux_request, binding)
    provenance = json.loads((metadata / "dependency-provenance.json").read_text())

    assert profile["linux_gi"] == {"host_libraries": sorted(_HOST_LIBRARIES)}
    assert LinuxGiBinding.from_json(provenance["linux_gi"]) == binding


def test_other_targets_record_no_binding(
    linux_request: DesktopBuildRequest, tmp_path: Path
) -> None:
    profile = json.loads(
        desktop_build._write_profile(tmp_path, linux_request, None).read_text()
    )

    assert "linux_gi" not in profile


# --- probe -------------------------------------------------------------------


class _FakeModuleInfo:
    graph = {
        "Gtk-3.0": ["Gdk-3.0", "GLib-2.0"],
        "Gdk-3.0": ["GLib-2.0"],
        "GLib-2.0": [],
    }

    def __init__(self, namespace: str, version: str) -> None:
        key = f"{namespace}-{version}"
        self.available = key in self.graph
        self.typelib = f"/usr/lib/girepository-1.0/{key}.typelib"
        self.sharedlibs = [f"lib{namespace.lower()}.so.0"]
        self.dependencies = self.graph.get(key, [])


@pytest.fixture
def fake_pyinstaller(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    gi_hooks = pytest.importorskip("PyInstaller.utils.hooks.gi")
    from PyInstaller.depend import bindepend

    links = {
        "/usr/lib/libgtk.so.0": {("libglib-2.0.so.0", "/usr/lib/libglib-2.0.so.0")},
        "/site/gi/_gi.so": {("libffi.so.8", "/usr/lib/libffi.so.8")},
    }
    monkeypatch.setattr(gi_hooks, "GiModuleInfo", _FakeModuleInfo)
    monkeypatch.setattr(bindepend, "resolve_library_path", lambda name: f"/usr/lib/{name}")
    monkeypatch.setattr(bindepend, "get_imports", lambda path: links.get(path, set()))
    return SimpleNamespace(links=links)


def test_the_probe_follows_typelib_dependencies(fake_pyinstaller: SimpleNamespace) -> None:
    closure = linux_gi_probe._typelib_closure({"Gtk": "3.0"})

    assert sorted(closure) == ["GLib-2.0", "Gdk-3.0", "Gtk-3.0"]
    assert closure["Gtk-3.0"]["shared_libraries"] == ["libgtk.so.0"]


def test_the_probe_refuses_an_unavailable_typelib(fake_pyinstaller: SimpleNamespace) -> None:
    with pytest.raises(SystemExit, match="WebKit2-4.1 is not available"):
        linux_gi_probe._typelib_closure({"WebKit2": "4.1"})


def test_the_probe_maps_typelib_libraries_and_everything_they_link(
    fake_pyinstaller: SimpleNamespace,
) -> None:
    typelibs = {"Gtk-3.0": {"shared_libraries": ["libgtk.so.0"]}}

    libraries = linux_gi_probe._host_libraries(["/site/gi/_gi.so"], typelibs)

    assert libraries == {
        "libgtk.so.0": "/usr/lib/libgtk.so.0",
        "libglib-2.0.so.0": "/usr/lib/libglib-2.0.so.0",
        "libffi.so.8": "/usr/lib/libffi.so.8",
    }


def test_the_probe_refuses_an_unresolved_link(fake_pyinstaller: SimpleNamespace) -> None:
    fake_pyinstaller.links["/site/gi/_gi.so"] = {("libmissing.so.1", None)}

    with pytest.raises(SystemExit, match="libmissing.so.1"):
        linux_gi_probe._host_libraries(["/site/gi/_gi.so"], {})


def test_the_probe_reports_json_for_valid_roots(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(linux_gi_probe, "probe", lambda roots: {"roots": roots})

    assert linux_gi_probe.main(["probe", json.dumps({"Gtk": "3.0"})]) == 0
    assert json.loads(capsys.readouterr().out) == {"roots": {"Gtk": "3.0"}}
    assert linux_gi_probe.main(["probe", "[]"]) == 2
    assert linux_gi_probe.main(["probe"]) == 2


def test_the_probe_imports_nothing_from_this_repository() -> None:
    """The build venv runs it by path and cannot import the repository."""
    tree = ast.parse(Path(linux_gi_probe.__file__).read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert imported <= {"__future__", "json", "sys", "pathlib", "PyInstaller", "gi", "cairo"}


# --- typelib hooks -----------------------------------------------------------


def _load_hook(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"_test_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_required_typelib_has_its_own_hook() -> None:
    hooks = {
        path.name.removeprefix("hook-gi.repository.").removesuffix(".py")
        for path in _HOOKS_DIR.glob("hook-gi.repository.*.py")
    }
    assert hooks == {name.rsplit("-", 1)[0] for name in REQUIRED_TYPELIBS}


@pytest.mark.parametrize("typelib", sorted(REQUIRED_TYPELIBS))
def test_typelib_hooks_collect_the_typelib_and_never_the_library(
    typelib: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("PyInstaller.utils.hooks.gi")
    namespace, version = typelib.rsplit("-", 1)
    requested: list[tuple[str, str]] = []

    class _Info:
        available = True

        def __init__(self, name: str, requested_version: str) -> None:
            requested.append((name, requested_version))

        def collect_typelib_data(self) -> tuple[list[object], list[object], list[str]]:
            return (
                [("/usr/lib/libhost.so.0", ".")],
                [(f"/usr/lib/girepository-1.0/{typelib}.typelib", "gi_typelibs")],
                ["gi.repository.GObject"],
            )

    module = _load_hook(_HOOKS_DIR / f"hook-gi.repository.{namespace}.py")
    monkeypatch.setattr(module, "GiModuleInfo", _Info)
    hook_api = SimpleNamespace(datas=[], imports=[], binaries=[])
    hook_api.add_datas = hook_api.datas.extend
    hook_api.add_imports = lambda *names: hook_api.imports.extend(names)
    hook_api.add_binaries = hook_api.binaries.extend

    module.hook(hook_api)

    assert requested == [(namespace, version)]
    assert hook_api.datas == [(f"/usr/lib/girepository-1.0/{typelib}.typelib", "gi_typelibs")]
    assert hook_api.imports == ["gi.repository.GObject"]
    assert hook_api.binaries == []


def test_typelib_hooks_skip_an_unavailable_namespace(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("PyInstaller.utils.hooks.gi")
    module = _load_hook(_HOOKS_DIR / "hook-gi.repository.WebKit2.py")
    monkeypatch.setattr(
        module, "GiModuleInfo", lambda name, version: SimpleNamespace(available=False)
    )
    hook_api = SimpleNamespace()

    module.hook(hook_api)  # touches nothing on the hook API
