"""Checksum-pinned Syft policy, extraction, and invocation tests."""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import socket
import tarfile
import threading
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from scripts.standalone_cli import syft_tool
from scripts.standalone_cli.artifact_types import ArtifactEvidenceError
from scripts.standalone_cli.model import load_target_spec
from scripts.standalone_cli.syft_tool import (
    _extract_tar_member,
    _validate_download_url,
    acquire_syft,
    load_syft_policy,
    run_syft_scan,
)

_ROOT = Path(__file__).resolve().parents[2]
_POLICY_ROOT = _ROOT / "packaging" / "standalone_cli"
_SYFT_POLICY = _POLICY_ROOT / "syft-tools.json"
_TARGET_POLICY = _POLICY_ROOT / "target-policy.json"


def test_syft_policy_is_schema_valid_and_exactly_pinned() -> None:
    raw = json.loads(_SYFT_POLICY.read_text(encoding="utf-8"))
    schema = json.loads(
        _SYFT_POLICY.with_name("syft-tools.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(raw)

    policy = load_syft_policy(_SYFT_POLICY)

    assert policy.version == "1.51.1"
    assert set(policy.targets) == {
        "windows-x64",
        "macos-x64",
        "macos-arm64",
        "linux-x64-ubuntu-22.04",
    }
    assert (
        policy.targets["linux-x64-ubuntu-22.04"].sha256
        == "8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3"
    )


def test_syft_policy_rejects_asset_url_or_checksum_drift(tmp_path: Path) -> None:
    raw = json.loads(_SYFT_POLICY.read_text(encoding="utf-8"))
    linux = raw["tool"]["targets"]["linux-x64-ubuntu-22.04"]
    linux["url"] = "https://example.invalid/syft.tar.gz"
    path = tmp_path / "syft-tools.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ArtifactEvidenceError, match="URL is invalid"):
        load_syft_policy(path)


def test_tar_extraction_rejects_links_before_writing_executable(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "syft.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        executable = tarfile.TarInfo("syft")
        payload = b"binary"
        executable.size = len(payload)
        archive.addfile(executable, io.BytesIO(payload))
        unsafe = tarfile.TarInfo("link")
        unsafe.type = tarfile.SYMTYPE
        unsafe.linkname = "syft"
        archive.addfile(unsafe)

    destination = tmp_path / "tool" / "syft"
    destination.parent.mkdir()
    with pytest.raises(ArtifactEvidenceError, match="unsafe member"):
        _extract_tar_member(archive_path, "syft", destination, 1024)
    assert not destination.exists()


def test_acquisition_reconciles_manifest_archive_and_executable_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable_bytes = b"verified executable"
    archive_path = tmp_path / "source.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        member = tarfile.TarInfo("syft")
        member.mode = 0o755
        member.size = len(executable_bytes)
        archive.addfile(member, io.BytesIO(executable_bytes))
    archive_sha = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    archive_name = "syft_1.51.1_linux_amd64.tar.gz"
    manifest_bytes = f"{archive_sha}  {archive_name}\n".encode()
    policy_raw = json.loads(_SYFT_POLICY.read_text(encoding="utf-8"))
    policy_raw["tool"]["manifest"]["sha256"] = hashlib.sha256(
        manifest_bytes
    ).hexdigest()
    policy_raw["tool"]["targets"]["linux-x64-ubuntu-22.04"]["sha256"] = archive_sha
    policy_path = tmp_path / "syft-tools.json"
    policy_path.write_text(json.dumps(policy_raw), encoding="utf-8")
    cache = tmp_path / "cache"
    cache.mkdir(mode=0o700)
    target = load_target_spec(_TARGET_POLICY, "linux-x64-ubuntu-22.04")

    def fake_download(
        url: str,
        destination: Path,
        _expected_sha256: str,
        _policy: object,
    ) -> None:
        if url.endswith("checksums.txt"):
            destination.write_bytes(manifest_bytes)
        else:
            shutil.copyfile(archive_path, destination)

    def fake_run(*_args: object) -> bytes:
        return json.dumps(
            {
                "application": "syft",
                "version": "1.51.1",
                "platform": "linux/amd64",
            }
        ).encode()

    monkeypatch.setattr("scripts.standalone_cli.syft_tool._download", fake_download)
    monkeypatch.setattr(
        "scripts.standalone_cli.syft_tool.run_bounded_command", fake_run
    )

    executable = acquire_syft(policy_path, target, cache)

    assert executable.read_bytes() == executable_bytes
    assert executable.stat().st_mode & 0o777 == 0o700


def test_scan_uses_exact_cyclonedx_version_and_isolated_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = load_syft_policy(_SYFT_POLICY)
    target = load_target_spec(_TARGET_POLICY, "linux-x64-ubuntu-22.04")
    executable = tmp_path / "syft"
    executable.write_bytes(b"tool")
    payload = tmp_path / "payload"
    payload.mkdir()
    config = tmp_path / "private"
    config.mkdir(mode=0o700)
    output = config / "payload.cdx.json"
    captured: dict[str, object] = {}

    def fake_run(
        command: list[str],
        environment: dict[str, str],
        _working_directory: Path,
        _timeout_seconds: int,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
        _label: str,
    ) -> bytes:
        captured["command"] = command
        captured["environment"] = environment
        captured["stdout_limit"] = max_stdout_bytes
        captured["stderr_limit"] = max_stderr_bytes
        return b'{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}'

    monkeypatch.setattr(
        "scripts.standalone_cli.syft_tool.run_bounded_command", fake_run
    )

    run_syft_scan(
        executable,
        policy,
        target,
        payload,
        "1.2.3",
        output,
        config,
    )

    command = captured["command"]
    assert isinstance(command, list)
    assert "cyclonedx-json@1.6" in command
    assert all(str(output) not in item for item in command)
    environment = captured["environment"]
    assert isinstance(environment, dict)
    assert environment["SYFT_CHECK_FOR_APP_UPDATE"] == "false"
    assert "PATH" not in environment
    assert captured["stdout_limit"] == policy.max_sbom_bytes
    assert captured["stderr_limit"] == policy.max_process_output_bytes
    assert output.stat().st_size < policy.max_sbom_bytes


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
    return f"http://127.0.0.1:{server.getsockname()[1]}/asset"


def _local_download(
    monkeypatch: pytest.MonkeyPatch,
    url: str,
    destination: Path,
    **policy_changes: object,
) -> None:
    monkeypatch.setattr(syft_tool, "_validate_download_url", lambda *_a, **_k: None)
    policy = replace(load_syft_policy(_SYFT_POLICY), **policy_changes)
    syft_tool._download(url, destination, "0" * 64, policy)


def test_download_maps_a_truncated_response_and_removes_the_partial_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = _serve_once(
        lambda connection: connection.sendall(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n400\r\n"
            + b"x" * 100
        )
    )
    destination = tmp_path / "asset.tar.gz"

    with pytest.raises(ArtifactEvidenceError, match="download failed"):
        _local_download(monkeypatch, url, destination)

    assert not destination.exists()


def test_download_stops_at_the_policy_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def trickle(connection: socket.socket) -> None:
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
        for _ in range(40):
            connection.sendall(b"x")
            time.sleep(0.1)

    url = _serve_once(trickle)
    destination = tmp_path / "asset.tar.gz"
    started = time.monotonic()

    with pytest.raises(ArtifactEvidenceError, match="timed out"):
        _local_download(monkeypatch, url, destination, download_timeout_seconds=1)

    assert time.monotonic() - started < 3
    assert not destination.exists()


def test_download_preserves_a_file_it_did_not_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = _serve_once(
        lambda connection: connection.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"
        )
    )
    destination = tmp_path / "asset.tar.gz"
    destination.write_text("existing", encoding="utf-8")

    with pytest.raises(ArtifactEvidenceError, match="download failed"):
        _local_download(monkeypatch, url, destination)

    assert destination.read_text(encoding="utf-8") == "existing"


def test_redirect_hosts_come_from_the_tool_policy(tmp_path: Path) -> None:
    policy = load_syft_policy(_SYFT_POLICY)

    assert policy.redirect_hosts == frozenset(
        {"github.com", "release-assets.githubusercontent.com"}
    )
    _validate_download_url(
        "https://release-assets.githubusercontent.com/asset?signature=x",
        policy.redirect_hosts,
        is_redirect=True,
    )
    with pytest.raises(ArtifactEvidenceError, match="URL is invalid"):
        _validate_download_url(
            "https://objects.example.invalid/asset",
            policy.redirect_hosts,
            is_redirect=True,
        )

    raw = json.loads(_SYFT_POLICY.read_text(encoding="utf-8"))
    for hosts in ([], ["github.com", "github.com"], ["GitHub.com"], ["localhost"]):
        raw["tool"]["redirect_hosts"] = hosts
        path = tmp_path / "syft-tools.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        with pytest.raises(ArtifactEvidenceError, match="redirect hosts"):
            load_syft_policy(path)
