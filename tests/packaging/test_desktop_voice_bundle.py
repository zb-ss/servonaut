"""Behaviour tests for the managed voice runtime policy, locks and bundle staging."""

from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import shutil
import socket
import subprocess
import stat
import tarfile
import threading
import time
import urllib.request
import zipfile
from collections.abc import Callable
from email.message import Message
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

import scripts.desktop_shell.voice_bundle as voice_bundle
from scripts.desktop_shell.model import (
    DESKTOP_TARGET_NAMES,
    VOICE_REQUIREMENTS_INPUT,
    DesktopPolicyValidationError,
    DesktopTargetSpec,
    VoiceRuntimePolicy,
    load_desktop_target_spec,
    load_voice_runtime_policy,
    voice_lock_path,
    voice_wheel_platforms,
)
from scripts.desktop_shell.voice_bundle import (
    VoiceBundleError,
    load_voice_lock,
    parse_voice_manifest,
    stage_voice_bundle,
    uv_asset_rules,
    verify_voice_bundle,
)
from scripts.standalone_cli import pinned_asset
from scripts.standalone_cli.pinned_asset import (
    download_pinned_asset,
    extract_pinned_member,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_POLICY_DIR = _REPO_ROOT / "packaging" / "desktop_shell"
_VOICE_POLICY = _POLICY_DIR / "voice-runtime.json"
_VOICE_SCHEMA = _POLICY_DIR / "voice-runtime.schema.json"
_VERSION = "2.26.3"
_ELF_X86_64 = b"\x7fELF\x02\x01" + bytes(12) + (0x3E).to_bytes(2, "little") + bytes(44)
_ELF_ARM64 = b"\x7fELF\x02\x01" + bytes(12) + (0xB7).to_bytes(2, "little") + bytes(44)
_MEMBER = "uv-x86_64-unknown-linux-gnu/uv"
# Fake upstream URLs on the pinned origin and redirect host (no network is used).
_URL = (
    "https://github.com/astral-sh/uv/releases/download/0.0.0/"
    "uv-x86_64-unknown-linux-gnu.tar.gz"
)
_FINAL_URL = "https://release-assets.githubusercontent.com/uv?signature=x"
_HASH = "0" * 64
_MANIFEST_KEYS = {
    "schema_version",
    "target",
    "python_version",
    "uv",
    "wheel",
    "requirements",
    "timeouts",
}


# --- policy --------------------------------------------------------------------


def _write_policy(tmp_path: Path, change: object) -> Path:
    raw = json.loads(_VOICE_POLICY.read_text(encoding="utf-8"))
    change(raw)
    path = tmp_path / "voice-runtime.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def test_committed_voice_policy_is_schema_valid_and_loads() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    raw = json.loads(_VOICE_POLICY.read_text(encoding="utf-8"))
    schema = json.loads(_VOICE_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(raw)

    policy = load_voice_runtime_policy()

    assert set(policy.uv_archives) == DESKTOP_TARGET_NAMES
    assert policy.python_version.startswith("3.12.")
    # The supply-chain cooldown: pins are at least a week old when chosen.
    assert policy.minimum_release_age_days >= 7
    assert "minimum_release_age_days" in raw["$comment"]
    assert policy.uv_archives["windows-x64"].executable_name == "uv.exe"
    assert policy.uv_archives["windows-x64"].archive_format == "zip"
    for name in DESKTOP_TARGET_NAMES - {"windows-x64"}:
        assert policy.uv_archives[name].executable_name == "uv"
        assert policy.uv_archives[name].archive_format == "tar.gz"
    for archive in policy.uv_archives.values():
        assert f"/{policy.uv_version}/" in archive.url


_INVALID_POLICIES = [
    (lambda raw: raw.update(extra=1), "unsupported or missing fields"),
    (lambda raw: raw.pop("$comment"), "unsupported or missing fields"),
    (lambda raw: raw.update({"$comment": " "}), "pinning rule"),
    (lambda raw: raw.pop("minimum_release_age_days"), "unsupported or missing fields"),
    (lambda raw: raw.update(minimum_release_age_days=0), "out of bounds"),
    (lambda raw: raw.update(python_version="3.12"), "exact 3.12 patch"),
    (lambda raw: raw.update(python_version="3.13.1"), "exact 3.12 patch"),
    (lambda raw: raw.update(stall_timeout_seconds=0), "out of bounds"),
    (lambda raw: raw.update(uv_command_timeout_seconds=True), "out of bounds"),
    (lambda raw: raw.update(provision_timeout_seconds=60), "stall <= uv command"),
    (lambda raw: raw["build_download"].update(max_archive_bytes=10), "out of bounds"),
    (lambda raw: raw["build_download"].pop("timeout_seconds"), "build_download"),
    (lambda raw: raw["uv"].update(version="latest"), "uv version must be exact"),
    (lambda raw: raw["uv"].update(origin_host="GitHub.com"), "download hosts"),
    (lambda raw: raw["uv"].update(redirect_hosts=[]), "download hosts"),
    (
        lambda raw: raw["uv"].update(redirect_hosts=["github.com", "github.com"]),
        "download hosts",
    ),
    (lambda raw: raw["uv"].pop("redirect_hosts"), "version, hosts and targets"),
    (lambda raw: raw["uv"].update(origin_host="example.org"), "on example.org"),
    (
        lambda raw: raw["build_download"].update(socket_timeout_seconds=301),
        "must not exceed timeout_seconds",
    ),
    (lambda raw: raw["uv"]["targets"].pop("macos-x64"), "one archive per desktop target"),
    (
        lambda raw: raw["uv"]["targets"]["macos-x64"].update(size=1),
        "must define url, sha256 and member",
    ),
    (
        lambda raw: raw["uv"]["targets"]["macos-x64"].update(
            url=raw["uv"]["targets"]["macos-x64"]["url"].replace("https", "http", 1)
        ),
        "https tar.gz",
    ),
    (
        lambda raw: raw["uv"]["targets"]["macos-x64"].update(
            url=raw["uv"]["targets"]["macos-x64"]["url"].replace(
                raw["uv"]["version"], "0.0.1"
            )
        ),
        "of release",
    ),
    (
        lambda raw: raw["uv"]["targets"]["windows-x64"].update(
            url=raw["uv"]["targets"]["macos-x64"]["url"]
        ),
        "https zip",
    ),
    (lambda raw: raw["uv"]["targets"]["macos-x64"].update(sha256="ab" * 31), "sha256"),
    (
        lambda raw: raw["uv"]["targets"]["macos-x64"].update(member="../uv"),
        "relative path to uv",
    ),
    (
        lambda raw: raw["uv"]["targets"]["macos-x64"].update(member="dir/uvx"),
        "relative path to uv",
    ),
    (
        lambda raw: raw["uv"]["targets"]["windows-x64"].update(member="uv"),
        "relative path to uv.exe",
    ),
]


@pytest.mark.parametrize(("change", "message"), _INVALID_POLICIES)
def test_voice_policy_rejects_unpinned_or_unbounded_values(
    tmp_path: Path, change: object, message: str
) -> None:
    with pytest.raises(DesktopPolicyValidationError, match=message):
        load_voice_runtime_policy(_write_policy(tmp_path, change))


@pytest.mark.parametrize(("change", "message"), _INVALID_POLICIES)
def test_voice_schema_agrees_with_the_loader(
    change: object, message: str
) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    raw = json.loads(_VOICE_POLICY.read_text(encoding="utf-8"))
    change(raw)
    schema = json.loads(_VOICE_SCHEMA.read_text(encoding="utf-8"))
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(raw))
    # Cross-field rules (timeout order, URL naming the pinned release) live in
    # the loader only.
    if message in {
        "stall <= uv command",
        "of release",
        "on example.org",
        "must not exceed timeout_seconds",
    }:
        assert not errors
    else:
        assert errors, message


# --- locks ---------------------------------------------------------------------


def _pyproject_voice_requirements() -> set[str]:
    tomllib = pytest.importorskip("tomllib", reason="reading pyproject.toml needs Python 3.11+")
    extras = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]["optional-dependencies"]
    return {
        requirement
        for extra in ("voice", "voice-streaming", "voice-output")
        for requirement in extras[extra]
    }


def _voice_inputs() -> list[Requirement]:
    lines = VOICE_REQUIREMENTS_INPUT.read_text(encoding="utf-8").splitlines()
    return [Requirement(line) for line in lines if line and not line.startswith("#")]


def test_voice_input_mirrors_the_pyproject_voice_extras() -> None:
    assert {str(requirement) for requirement in _voice_inputs()} == (
        _pyproject_voice_requirements()
    )


@pytest.mark.parametrize("target_name", sorted(DESKTOP_TARGET_NAMES))
def test_committed_voice_locks_pin_the_voice_extras_with_one_wheel_each(
    target_name: str,
) -> None:
    lock = voice_lock_path(target_name)
    pins = {pin.name: pin for pin in load_voice_lock(lock)}
    header = lock.read_text(encoding="utf-8").split("\n\n", 1)[0]

    assert f"for the {target_name} desktop target" in header
    assert f"--target {target_name}" in header
    for requirement in _voice_inputs():
        pin = pins[canonicalize_name(requirement.name)]
        assert requirement.specifier.contains(pin.version), pin
    # The engines' native runtimes are part of the closure, not left to chance.
    assert {"ctranslate2", "onnxruntime", "sherpa-onnx-core", "cffi"} <= set(pins)
    assert all(len(pin.sha256) == 1 for pin in pins.values())
    assert ("colorama" in pins) == (target_name == "windows-x64")


def _lock(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "voice.txt"
    path.write_text(text, encoding="ascii")
    return path




@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("numpy==2.5.3\n", "only name==version pins"),
        (f"numpy>=2 \\\n    --hash=sha256:{_HASH}\n", "only name==version pins"),
        (f"NumPy==2.5.3 \\\n    --hash=sha256:{_HASH}\n", "only name==version pins"),
        ("--index-url https://example.invalid\n", "only name==version pins"),
        ("-r other.txt\n", "only name==version pins"),
        (
            f"numpy @ https://example.invalid/numpy.whl \\\n    --hash=sha256:{_HASH}\n",
            "only name==version pins",
        ),
        ("numpy==2.5.3 ; sys_platform == 'linux' \\\n", "only name==version pins"),
        (f"numpy==2.5.3 \\\n    --hash=md5:{'0' * 32}\n", "expected a --hash line"),
        (f"numpy==2.5.3 \\\n    --hash=sha256:{_HASH} \\\n", "no final hash line"),
        (
            f"numpy==2.5.3 \\\n    --hash=sha256:{_HASH}\n"
            f"numpy==2.5.4 \\\n    --hash=sha256:{_HASH}\n",
            "present and unique",
        ),
        ("# only a comment\n", "present and unique"),
    ],
)
def test_voice_lock_parser_accepts_only_hashed_exact_pins(
    tmp_path: Path, text: str, message: str
) -> None:
    with pytest.raises(VoiceBundleError, match=message):
        load_voice_lock(_lock(tmp_path, text))


def test_voice_lock_parser_reads_pins_hashes_and_comments(tmp_path: Path) -> None:
    other = "1" * 64
    pins = load_voice_lock(
        _lock(
            tmp_path,
            "# header\n\n"
            f"numpy==2.5.3 \\\n    --hash=sha256:{_HASH} \\\n    --hash=sha256:{other}\n"
            "    # numpy-2.5.3-cp312-cp312-win_amd64.whl\n"
            f"typing-extensions==4.16.0 \\\n    --hash=sha256:{_HASH}\n",
        )
    )

    assert [(pin.name, pin.version, pin.sha256) for pin in pins] == [
        ("numpy", "2.5.3", (_HASH, other)),
        ("typing-extensions", "4.16.0", (_HASH,)),
    ]


def test_voice_lock_parser_requires_lf_line_endings(tmp_path: Path) -> None:
    lock = tmp_path / "voice-windows-x64.txt"
    lock.write_bytes(voice_lock_path("windows-x64").read_bytes().replace(b"\n", b"\r\n"))

    with pytest.raises(VoiceBundleError, match="must use LF line endings"):
        load_voice_lock(lock)


def test_voice_locks_are_checked_out_with_lf_endings() -> None:
    """A checkout that rewrote line endings would change the hashed lock bytes."""
    git = shutil.which("git")
    paths = [
        *(voice_lock_path(name) for name in sorted(DESKTOP_TARGET_NAMES)),
        VOICE_REQUIREMENTS_INPUT,
        VOICE_REQUIREMENTS_INPUT.with_name("voice-drift-tools.txt"),
    ]
    if git is None or not (_REPO_ROOT / ".git").exists():
        pytest.skip("needs a git checkout")
    completed = subprocess.run(
        [
            git,
            "check-attr",
            "eol",
            "--",
            *(path.relative_to(_REPO_ROOT).as_posix() for path in paths),
        ],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )

    assert completed.stdout.splitlines() == [
        f"{path.relative_to(_REPO_ROOT).as_posix()}: eol: lf" for path in paths
    ]
    for path in paths:
        assert b"\r" not in path.read_bytes(), path.name


def _supported_tags(target_name: str) -> set[object]:
    tags = pytest.importorskip("packaging.tags")
    target = load_desktop_target_spec(target_name)
    platforms: list[str] = []
    for tag in voice_wheel_platforms(target):
        if tag.startswith("macosx_"):
            _, major, minor, arch = tag.split("_", 3)
            platforms += tags.mac_platforms((int(major), int(minor)), arch)
        else:
            platforms.append(tag)
    return {
        *tags.cpython_tags((3, 12), abis=["cp312"], platforms=platforms),
        *tags.compatible_tags((3, 12), "cp312", platforms),
    }


@pytest.mark.parametrize("target_name", sorted(DESKTOP_TARGET_NAMES))
def test_each_locked_wheel_is_the_named_pin_and_installs_on_its_target(
    target_name: str,
) -> None:
    """Offline: the recorded wheel file names the pin and a tag the target accepts."""
    utils = pytest.importorskip("packaging.utils")
    supported = _supported_tags(target_name)
    lines = voice_lock_path(target_name).read_text(encoding="ascii").splitlines()
    pins = {pin.name: pin for pin in load_voice_lock(voice_lock_path(target_name))}
    wheels = {}
    for index, line in enumerate(lines):
        if line.startswith("    # "):
            pin_line = lines[index - 2]
            wheels[pin_line.split("==", 1)[0]] = line.removeprefix("    # ")

    assert set(wheels) == set(pins)
    for name, filename in wheels.items():
        wheel_name, wheel_version, _build, wheel_tags = utils.parse_wheel_filename(filename)
        assert (wheel_name, str(wheel_version)) == (
            utils.canonicalize_name(name),
            pins[name].version,
        ), filename
        assert wheel_tags & supported, filename


# --- download ------------------------------------------------------------------


class _FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        url: str = _FINAL_URL,
        content_length: str | None = None,
        chunk: int | None = None,
    ) -> None:
        self._body = io.BytesIO(body)
        self._url = url
        self._chunk = chunk
        self.headers = Message()
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    def read1(self, amount: int) -> bytes:
        return self._body.read(min(amount, self._chunk or amount))

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


def _opener(response: _FakeResponse, requests: list[str] | None = None) -> object:
    def open_url(request: object, timeout: float) -> _FakeResponse:
        if requests is not None:
            requests.append(request.full_url)
        return response

    return open_url


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _download(
    destination: Path, body_sha256: str, opener: object, url: str = _URL
) -> None:
    policy = dataclasses.replace(load_voice_runtime_policy(), max_archive_bytes=1024)
    download_pinned_asset(
        uv_asset_rules(policy),
        url,
        destination,
        body_sha256,
        max_bytes=policy.max_archive_bytes,
        deadline_seconds=30,
        socket_timeout_seconds=5,
        opener=opener,
    )


def test_download_writes_only_a_verified_archive(tmp_path: Path) -> None:
    body = b"archive bytes"
    destination = tmp_path / "archive"
    requests: list[str] = []

    _download(destination, _sha(body), _opener(_FakeResponse(body, chunk=3), requests))

    assert destination.read_bytes() == body
    assert requests == [_URL]


@pytest.mark.parametrize(
    ("response", "sha256", "message"),
    [
        (_FakeResponse(b"x" * 10), _sha(b"y" * 10), "does not match policy"),
        (_FakeResponse(b"x" * 10, content_length="2048"), _sha(b"x" * 10), "size limit"),
        (_FakeResponse(b"x" * 10, content_length="ten"), _sha(b"x" * 10), "length"),
        (_FakeResponse(b"x" * 2048), _sha(b"x" * 2048), "size limit"),
        (
            _FakeResponse(b"x", url="http://release-assets.githubusercontent.com/uv"),
            _sha(b"x"),
            "URL is invalid",
        ),
        (
            _FakeResponse(b"x", url="https://downloads.example.invalid/uv"),
            _sha(b"x"),
            "URL is invalid",
        ),
    ],
)
def test_download_rejects_unverified_oversized_or_redirected_transfers(
    tmp_path: Path, response: _FakeResponse, sha256: str, message: str
) -> None:
    destination = tmp_path / "archive"

    with pytest.raises(VoiceBundleError, match=message):
        _download(destination, sha256, _opener(response))

    assert not destination.exists()


@pytest.mark.parametrize(
    "url",
    [
        _URL.replace("https", "http", 1),
        _URL.replace("github.com", "release-assets.githubusercontent.com"),
        _URL + "?token=x",
        _URL.replace("github.com", "user@github.com"),  # leak-guard:allow
    ],
)
def test_download_refuses_a_url_off_the_pinned_origin_before_connecting(
    tmp_path: Path, url: str
) -> None:
    def unexpected(request: object, timeout: float) -> _FakeResponse:
        raise AssertionError("no connection may be opened")

    with pytest.raises(VoiceBundleError, match="URL is invalid"):
        _download(tmp_path / "archive", _HASH, unexpected, url=url)


def test_download_reports_network_errors_as_bundle_errors(tmp_path: Path) -> None:
    def refuse(request: object, timeout: float) -> _FakeResponse:
        raise ConnectionRefusedError("refused")

    with pytest.raises(VoiceBundleError, match="download failed"):
        _download(tmp_path / "archive", _HASH, refuse)


def test_download_never_replaces_an_existing_file(tmp_path: Path) -> None:
    destination = tmp_path / "archive"
    destination.write_bytes(b"keep")

    with pytest.raises(VoiceBundleError, match="download failed"):
        _download(destination, _sha(b"x"), _opener(_FakeResponse(b"x")))

    assert destination.read_bytes() == b"keep"


def test_redirects_stay_on_the_reviewed_https_hosts() -> None:
    handler = pinned_asset._ValidatingRedirects(
        uv_asset_rules(load_voice_runtime_policy())
    )
    request = urllib.request.Request(_URL)

    for target in (
        "http://release-assets.githubusercontent.com/uv",
        "https://objects.example.invalid/uv",
    ):
        with pytest.raises(VoiceBundleError, match="URL is invalid"):
            handler.redirect_request(request, io.BytesIO(), 302, "Found", Message(), target)
    followed = handler.redirect_request(
        request, io.BytesIO(), 302, "Found", Message(), _FINAL_URL
    )
    assert followed is not None and followed.full_url == _FINAL_URL


def _serve_once(respond: Callable[[socket.socket], None]) -> str:
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def handle() -> None:
        connection, _address = server.accept()
        with connection:
            connection.recv(65536)
            try:
                respond(connection)
            except OSError:
                pass
        server.close()

    threading.Thread(target=handle, daemon=True).start()
    return f"http://127.0.0.1:{server.getsockname()[1]}/uv.tar.gz"


def test_download_stops_at_its_deadline_while_a_server_trickles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``read1`` returns each trickled byte, so the deadline is checked in time."""

    def trickle(connection: socket.socket) -> None:
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
        for _ in range(40):
            connection.sendall(b"x")
            time.sleep(0.1)

    monkeypatch.setattr(voice_bundle, "_validate_download_url", lambda *_a, **_k: None)
    policy = load_voice_runtime_policy()
    destination = tmp_path / "archive"
    started = time.monotonic()

    with pytest.raises(VoiceBundleError, match="timed out"):
        download_pinned_asset(
            uv_asset_rules(policy),
            _serve_once(trickle),
            destination,
            _HASH,
            max_bytes=policy.max_archive_bytes,
            deadline_seconds=1,
            socket_timeout_seconds=policy.socket_timeout_seconds,
        )

    assert time.monotonic() - started < 3
    assert not destination.exists()


# --- extraction ----------------------------------------------------------------


def _tar_gz(members: list[tuple[str, bytes | None, bytes]]) -> bytes:
    """Build a tar.gz from (name, data or None for a link, type) entries."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.mode = 0o755
            if kind == tarfile.SYMTYPE:
                info.linkname = "/etc/passwd"
                archive.addfile(info)
            elif kind == tarfile.DIRTYPE:
                archive.addfile(info)
            else:
                info.size = len(data or b"")
                archive.addfile(info, io.BytesIO(data or b""))
    return buffer.getvalue()


def _zip(members: list[tuple[str, bytes, int]], *, encrypted: str = "") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data, mode in members:
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            archive.writestr(info, data)
    raw = bytearray(buffer.getvalue())
    if encrypted:
        # Set the encryption flag in the local and the central directory header.
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            index = raw.index(signature)
            raw[index + offset] |= 0x1
    return bytes(raw)


def _extract(archive: Path, archive_format: str, member: str, destination: Path) -> None:
    extract_pinned_member(
        uv_asset_rules(load_voice_runtime_policy()),
        archive,
        archive_format,
        member,
        destination,
        1024,
    )


def test_extracts_the_pinned_tar_member_only(tmp_path: Path) -> None:
    archive = tmp_path / "uv.tar.gz"
    archive.write_bytes(
        _tar_gz(
            [
                ("uv-x86_64-unknown-linux-gnu", None, tarfile.DIRTYPE),
                ("uv-x86_64-unknown-linux-gnu/uvx", b"uvx", tarfile.REGTYPE),
                (_MEMBER, _ELF_X86_64, tarfile.REGTYPE),
            ]
        )
    )

    _extract(archive, "tar.gz", _MEMBER, tmp_path / "uv")

    assert (tmp_path / "uv").read_bytes() == _ELF_X86_64
    assert sorted(path.name for path in tmp_path.iterdir()) == ["uv", "uv.tar.gz"]


def test_extracts_the_pinned_zip_member(tmp_path: Path) -> None:
    archive = tmp_path / "uv.zip"
    archive.write_bytes(_zip([("uv.exe", b"MZ exe", 0), ("uvx.exe", b"MZ", 0)]))

    _extract(archive, "zip", "uv.exe", tmp_path / "uv.exe")

    assert (tmp_path / "uv.exe").read_bytes() == b"MZ exe"


@pytest.mark.parametrize(
    ("members", "message"),
    [
        ([("other/uv", b"x", tarfile.REGTYPE)], "member is missing"),
        (
            [(_MEMBER, b"x", tarfile.REGTYPE), (_MEMBER, b"y", tarfile.REGTYPE)],
            "duplicate members",
        ),
        (
            [(_MEMBER, b"x", tarfile.REGTYPE), ("link", None, tarfile.SYMTYPE)],
            "unsafe member",
        ),
        ([(_MEMBER, None, tarfile.DIRTYPE)], "member is missing"),
        ([(_MEMBER, b"x" * 2048, tarfile.REGTYPE)], "size limit"),
        ([("../uv", b"x", tarfile.REGTYPE)], "member is invalid"),
    ],
)
def test_tar_extraction_rejects_missing_duplicate_unsafe_or_large_members(
    tmp_path: Path, members: list[tuple[str, bytes | None, bytes]], message: str
) -> None:
    archive = tmp_path / "uv.tar.gz"
    archive.write_bytes(_tar_gz(members))

    with pytest.raises(VoiceBundleError, match=message):
        _extract(archive, "tar.gz", _MEMBER, tmp_path / "uv")

    assert not (tmp_path / "uv").exists()


@pytest.mark.parametrize(
    ("archive_bytes", "message"),
    [
        (_zip([("uv.exe", b"x", stat.S_IFLNK | 0o777)]), "unsafe member"),
        (_zip([("uv.exe", b"x", stat.S_IFREG | 0o755)], encrypted="yes"), "unsafe member"),
        (_zip([("uv.exe", b"x" * 2048, 0)]), "size limit"),
        (_zip([("bin/uv.exe", b"x", 0)]), "member is missing"),
    ],
)
def test_zip_extraction_rejects_links_encrypted_large_or_missing_members(
    tmp_path: Path, archive_bytes: bytes, message: str
) -> None:
    archive = tmp_path / "uv.zip"
    archive.write_bytes(archive_bytes)

    with pytest.raises(VoiceBundleError, match=message):
        _extract(archive, "zip", "uv.exe", tmp_path / "uv.exe")

    assert not (tmp_path / "uv.exe").exists()


def test_extraction_reports_a_corrupt_archive(tmp_path: Path) -> None:
    archive = tmp_path / "uv.tar.gz"
    archive.write_bytes(b"not a gzip stream")

    with pytest.raises(VoiceBundleError, match="archive is invalid"):
        _extract(archive, "tar.gz", _MEMBER, tmp_path / "uv")


def test_extraction_never_replaces_an_existing_file(tmp_path: Path) -> None:
    archive = tmp_path / "uv.tar.gz"
    archive.write_bytes(_tar_gz([(_MEMBER, _ELF_X86_64, tarfile.REGTYPE)]))
    (tmp_path / "uv").write_bytes(b"keep")

    with pytest.raises(VoiceBundleError):
        _extract(archive, "tar.gz", _MEMBER, tmp_path / "uv")

    assert (tmp_path / "uv").read_bytes() == b"keep"


# --- staging and verification --------------------------------------------------


@pytest.fixture
def target() -> DesktopTargetSpec:
    return load_desktop_target_spec("linux-x64-ubuntu-22.04")


@pytest.fixture
def wheel(tmp_path: Path) -> Path:
    path = tmp_path / "dist" / f"servonaut-{_VERSION}-py3-none-any.whl"
    path.parent.mkdir()
    path.write_bytes(b"product wheel")
    return path


def _policy_with_archive(
    target: DesktopTargetSpec, archive: bytes
) -> VoiceRuntimePolicy:
    policy = load_voice_runtime_policy()
    pinned = dataclasses.replace(
        policy.uv_archives[target.name], url=_URL, sha256=_sha(archive)
    )
    return dataclasses.replace(
        policy, uv_archives={**policy.uv_archives, target.name: pinned}
    )


def _stage(
    tmp_path: Path,
    target: DesktopTargetSpec,
    wheel: Path,
    uv: bytes = _ELF_X86_64,
) -> tuple[Path, VoiceRuntimePolicy, list[str]]:
    archive = _tar_gz([(_MEMBER, uv, tarfile.REGTYPE)])
    policy = _policy_with_archive(target, archive)
    staging = tmp_path / "staging"
    staging.mkdir()
    requests: list[str] = []
    voice = stage_voice_bundle(
        staging,
        target,
        wheel,
        _VERSION,
        policy,
        opener=_opener(_FakeResponse(archive), requests),
    )
    return voice, policy, requests


def test_stage_writes_exactly_the_bundle_and_its_manifest(
    tmp_path: Path, target: DesktopTargetSpec, wheel: Path
) -> None:
    voice, policy, requests = _stage(tmp_path, target, wheel)

    assert requests == [_URL]
    assert sorted(path.name for path in voice.parent.iterdir()) == ["voice"]
    assert sorted(path.name for path in voice.iterdir()) == [
        f"servonaut-{_VERSION}-py3-none-any.whl",
        "uv",
        "voice-requirements.txt",
        "voice-runtime.json",
    ]
    assert (voice / "uv").stat().st_mode & 0o777 == 0o755
    assert (voice / "voice-requirements.txt").read_bytes() == voice_lock_path(
        target.name
    ).read_bytes()
    raw = json.loads((voice / "voice-runtime.json").read_text(encoding="utf-8"))
    assert set(raw) == _MANIFEST_KEYS
    assert raw == {
        "schema_version": 1,
        "target": target.name,
        "python_version": policy.python_version,
        "uv": {"filename": "uv", "sha256": _sha(_ELF_X86_64)},
        "wheel": {
            "filename": f"servonaut-{_VERSION}-py3-none-any.whl",
            "sha256": _sha(b"product wheel"),
        },
        "requirements": {
            "filename": "voice-requirements.txt",
            "sha256": _sha(voice_lock_path(target.name).read_bytes()),
        },
        "timeouts": {
            "uv_command_seconds": policy.uv_command_timeout_seconds,
            "stall_seconds": policy.stall_timeout_seconds,
            "provision_seconds": policy.provision_timeout_seconds,
        },
    }
    assert verify_voice_bundle(voice, target, _VERSION, policy).uv.filename == "uv"


def test_stage_rejects_a_uv_built_for_another_cpu(
    tmp_path: Path, target: DesktopTargetSpec, wheel: Path
) -> None:
    with pytest.raises(VoiceBundleError, match="architecture 'arm64'"):
        _stage(tmp_path, target, wheel, uv=_ELF_ARM64)


def test_stage_rejects_a_non_native_uv(
    tmp_path: Path, target: DesktopTargetSpec, wheel: Path
) -> None:
    with pytest.raises(VoiceBundleError, match="not a elf binary"):
        _stage(tmp_path, target, wheel, uv=b"#!/bin/sh\n")


def test_stage_requires_the_release_wheel_name(
    tmp_path: Path, target: DesktopTargetSpec
) -> None:
    wheel = tmp_path / "servonaut-2.26.3-cp312-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(VoiceBundleError, match="must be named"):
        _stage(tmp_path, target, wheel)


def test_verify_rejects_a_bundle_for_another_product_version(
    tmp_path: Path, target: DesktopTargetSpec, wheel: Path
) -> None:
    voice, policy, _ = _stage(tmp_path, target, wheel)

    with pytest.raises(VoiceBundleError, match="differ from policy"):
        verify_voice_bundle(voice, target, "9.9.9", policy)


def test_verify_rejects_a_symlinked_bundle_directory(
    tmp_path: Path, target: DesktopTargetSpec, wheel: Path
) -> None:
    voice, policy, _ = _stage(tmp_path, target, wheel)
    link = tmp_path / "linked-voice"
    link.symlink_to(voice, target_is_directory=True)

    with pytest.raises(VoiceBundleError, match="real directory"):
        verify_voice_bundle(link, target, _VERSION, policy)


def test_manifest_parser_rejects_repeated_keys(
    tmp_path: Path, target: DesktopTargetSpec, wheel: Path
) -> None:
    voice, policy, _ = _stage(tmp_path, target, wheel)
    manifest = voice / "voice-runtime.json"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            '"schema_version": 1', '"schema_version": 1, "schema_version": 1'
        ),
        encoding="utf-8",
    )

    with pytest.raises(VoiceBundleError, match="repeats a key"):
        verify_voice_bundle(voice, target, _VERSION, policy)


@pytest.mark.parametrize(
    "change",
    [
        lambda raw: raw["uv"].update(sha256="A" * 64),
        lambda raw: raw["wheel"].update(size=1),
        lambda raw: raw["timeouts"].update(stall_seconds=0),
        lambda raw: raw["timeouts"].update(stall_seconds=1.5),
        lambda raw: raw.update(target=None),
        lambda raw: raw.pop("requirements"),
    ],
)
def test_manifest_parser_is_strict(change: object) -> None:
    file = {"filename": "x", "sha256": _HASH}
    raw = {
        "schema_version": 1,
        "target": "linux-x64-ubuntu-22.04",
        "python_version": "3.12.14",
        "uv": dict(file),
        "wheel": dict(file),
        "requirements": dict(file),
        "timeouts": {"uv_command_seconds": 1, "stall_seconds": 1, "provision_seconds": 1},
    }
    parse_voice_manifest(json.loads(json.dumps(raw)))
    change(raw)

    with pytest.raises(VoiceBundleError):
        parse_voice_manifest(raw)
