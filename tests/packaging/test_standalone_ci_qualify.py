from __future__ import annotations

import hashlib
import json
import os
import sys
import tarfile
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import CodeType, FunctionType, SimpleNamespace
from typing import get_args

import pytest

from scripts.standalone_cli import ci_qualify, smoke_artifact, smoke_mcp
from scripts.standalone_cli.artifact_types import (
    ArchiveOwner,
    ArtifactDescriptor,
    PayloadEntry,
    PayloadSnapshot,
)
from scripts.standalone_cli.ci_qualify import (
    QualificationError,
    QualificationRequest,
    _classify_failure,
    main,
    qualify,
)
from scripts.standalone_cli.model import BuildRequest, BuildValidationError


class _PoisonError(Exception):
    def __str__(self) -> str:
        raise AssertionError("exception text must not be formatted")

    def __repr__(self) -> str:
        raise AssertionError("exception details must not be formatted")


class _LengthPoisonString(str):
    def __len__(self) -> int:
        raise AssertionError("string subclass length must not be inspected")


class _EqualityPoisonString(str):
    def __eq__(self, _other: object) -> bool:
        raise AssertionError("string subclass equality must not be inspected")


def _captured_exception(call: Callable[[], object]) -> BaseException:
    try:
        call()
    except Exception as error:  # noqa: BLE001 - controlled classification fixture
        return error
    raise AssertionError("classification fixture did not raise")


def _set_explicit_cause(error: BaseException, cause: BaseException | None) -> None:
    BaseException.__cause__.__set__(error, cause)


def _request(tmp_path: Path, *, target: str = "macos-x64") -> QualificationRequest:
    wheel = tmp_path / "servonaut-9.8.7-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    root = tmp_path / "qualification"
    root.mkdir(mode=0o700)
    docker = None
    if target == "linux-x64-ubuntu-22.04":
        docker = tmp_path / "docker"
        docker.write_text("executable", encoding="utf-8")
        docker.chmod(0o755)
    return QualificationRequest(
        wheel=wheel.resolve(),
        wheel_sha256=hashlib.sha256(b"wheel").hexdigest(),
        target_name=target,
        product_version="9.8.7",
        build_revision="run-1",
        source_commit="a" * 40,
        checkout=ci_qualify._PROJECT_ROOT,
        qualification_root=root.resolve(),
        public_evidence_dir=(root / "public evidence").resolve(),
        docker=docker.resolve() if docker else None,
    )


def _minimal_artifact(tmp_path: Path) -> ArtifactDescriptor:
    target = ci_qualify.load_target_spec(
        ci_qualify._TARGET_POLICY, "linux-x64-ubuntu-22.04"
    )
    payload = tmp_path / "payload"
    (payload / "_internal").mkdir(parents=True)
    executable = payload / "servonaut"
    executable.write_bytes(b"executable")
    executable.chmod(0o700)
    (payload / "servonaut-runtime.json").write_text("{}", encoding="utf-8")
    wheel = tmp_path / "servonaut-1.2.3-py3-none-any.whl"
    wheel.write_bytes(b"not-a-wheel")
    metadata = tmp_path / "build-metadata"
    metadata.mkdir()
    warning = metadata / "warning.txt"
    warning.write_text("", encoding="utf-8")
    return ArtifactDescriptor(
        payload,
        executable,
        None,
        target,
        wheel,
        warning,
        metadata,
    )


def _normalizer_fixture(
    tmp_path: Path,
    *,
    target_name: str = "linux-x64-ubuntu-22.04",
) -> tuple[PayloadSnapshot, ArtifactDescriptor, dict[str, object]]:
    artifact = _minimal_artifact(tmp_path)
    target = ci_qualify.load_target_spec(ci_qualify._TARGET_POLICY, target_name)
    artifact = ArtifactDescriptor(
        artifact.payload_root,
        artifact.executable,
        artifact.archive,
        target,
        artifact.wheel,
        artifact.pyinstaller_warning_file,
        artifact.build_metadata_dir,
    )
    sample = artifact.payload_root / "_internal" / "sample.bin"
    sample.write_bytes(b"sample payload")
    sample_digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    directory = artifact.payload_root / "_internal" / "folder"
    directory.mkdir()
    snapshot = PayloadSnapshot(
        root=artifact.payload_root,
        entries=(
            PayloadEntry(PurePosixPath("_internal"), "directory", 0o755, 0, None, None),
            PayloadEntry(
                PurePosixPath("_internal/folder"),
                "directory",
                0o755,
                0,
                None,
                None,
            ),
            PayloadEntry(
                PurePosixPath("_internal/sample.bin"),
                "file",
                0o644,
                sample.stat().st_size,
                sample_digest,
                None,
            ),
        ),
        expanded_regular_bytes=sample.stat().st_size,
        executable_relative_path=PurePosixPath(artifact.executable.name),
        marker={"product_version": "1.2.3"},
        build_provenance={
            "product_version": "1.2.3",
            "target": target.name,
        },
        build_toolchain={
            "python_implementation": "CPython",
            "python_version": "3.12.14",
        },
        runtime_notice={
            "schema_version": 1,
            "runtime": "cpython",
            "python_implementation": "CPython",
            "python_version": "3.12.14",
            "license_id": "Python-2.0",
            "payload_path": "_internal/notices/CPython-LICENSE.txt",
            "sha256": "a" * 64,
        },
    )
    raw = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {"type": "file", "name": "servonaut", "bom-ref": "root"}
        },
        "components": [
            {
                "type": "library",
                "name": "example",
                "version": "1.0",
                "purl": "pkg:pypi/example@1.0",
                "bom-ref": "raw-example",
                "licenses": [{"license": {"id": "MIT"}}],
            }
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["raw-example"]},
            {"ref": "raw-example"},
        ],
    }
    return snapshot, artifact, raw


def _payload_file_component(name: str, digest: str = "b" * 64) -> dict[str, object]:
    return {
        "type": "file",
        "name": name,
        "bom-ref": "raw-file",
        "hashes": [{"alg": "SHA-256", "content": digest}],
    }


def _snapshot_with_runtime_file(snapshot: PayloadSnapshot) -> PayloadSnapshot:
    runtime_file = snapshot.root / "_internal" / "libpython3.12.so.1.0"
    runtime_file.write_bytes(b"runtime")
    entry = PayloadEntry(
        PurePosixPath("_internal/libpython3.12.so.1.0"),
        "file",
        0o755,
        runtime_file.stat().st_size,
        hashlib.sha256(runtime_file.read_bytes()).hexdigest(),
        None,
    )
    return PayloadSnapshot(
        root=snapshot.root,
        entries=snapshot.entries + (entry,),
        expanded_regular_bytes=snapshot.expanded_regular_bytes + entry.size,
        executable_relative_path=snapshot.executable_relative_path,
        marker=snapshot.marker,
        build_provenance=snapshot.build_provenance,
        build_toolchain=snapshot.build_toolchain,
        runtime_notice=snapshot.runtime_notice,
    )


def _runtime_payload_component(family: str) -> dict[str, object]:
    component: dict[str, object] = {
        "type": "application",
        "name": "python",
        "version": "3.12.14",
        "purl": "pkg:generic/python@3.12.14",
        "bom-ref": "raw-runtime",
        "licenses": [{"license": {"id": "Python-2.0"}}],
        "properties": [
            {"name": "syft:package:type", "value": "binary"},
            {
                "name": "syft:location:0:path",
                "value": "/_internal/libpython3.12.so.1.0",
            },
        ],
    }
    if family == "payload-purl":
        component["name"] = "not-python"
    elif family == "payload-runtime-properties":
        component["properties"] = []
    elif family == "payload-runtime-license":
        component["licenses"] = [
            {"license": {"id": "Python-2.0"}},
            {"license": {"id": "MIT"}},
        ]
    elif family == "malformed-runtime-purl":
        component["purl"] = "pkg:generic /python@3.12.14"
    return component


def _apply_neutral_sbom_failure(
    component: dict[str, object], raw: dict[str, object], family: str
) -> bool:
    mutations: dict[str, tuple[str, object]] = {
        "fields": ("bom-ref", []),
        "hash": ("hashes", {}),
        "license": ("licenses", {}),
        "purl": ("purl", "pkg:pypi/example"),
        "reference": ("externalReferences", {}),
    }
    mutation = mutations.get(family)
    if mutation is not None:
        component[mutation[0]] = mutation[1]
        return True
    if family == "dependencies":
        raw["dependencies"] = {}
        return True
    return False


def _apply_payload_component_failure(
    component: dict[str, object], snapshot: PayloadSnapshot, family: str
) -> bool:
    if family == "component-fields-type":
        component["type"] = None
    elif family == "component-fields-name":
        component["name"] = None
    elif family in {"component-file-hash", "component-conflicting-file-hash"}:
        component.clear()
        component.update(
            _payload_file_component(str(snapshot.root / "_internal" / "sample.bin"))
        )
        if family == "component-conflicting-file-hash":
            component["hashes"] = [
                {"alg": "SHA-256", "content": "b" * 64},
                {"alg": "SHA-256", "content": "c" * 64},
            ]
    elif family == "component-version":
        component.pop("version")
    elif family == "component-package-name":
        component["name"] = "invalid package name"
    elif family == "component-package-conflict":
        component["name"] = "other-example"
    elif family == "component-purl-type":
        component["purl"] = "pkg:deb/debian/example@1.0"
    elif family == "component-runtime-identity":
        component.clear()
        component.update(
            {
                "type": "application",
                "name": "python",
                "version": "3.12.14",
                "bom-ref": "raw-runtime",
            }
        )
    elif family == "properties":
        component["properties"] = {}
    else:
        return False
    return True


def _payload_normalizer_error(tmp_path: Path, family: str) -> BaseException:
    target_name = (
        "windows-x64" if family == "latent-windows-path" else "linux-x64-ubuntu-22.04"
    )
    snapshot, artifact, raw = _normalizer_fixture(tmp_path, target_name=target_name)
    component = raw["components"][0]
    assert isinstance(component, dict)
    closure_names = frozenset({"example"})

    if _apply_neutral_sbom_failure(
        component, raw, family
    ) or _apply_payload_component_failure(component, snapshot, family):
        pass
    elif family == "payload-component":
        component.clear()
        component.update(
            _payload_file_component(str(snapshot.root / "_internal" / "sample.bin"))
        )
    elif family == "payload-path":
        component.clear()
        component.update(_payload_file_component("../outside"))
    elif family == "payload-file":
        component.clear()
        component.update(
            _payload_file_component(str(snapshot.root / "_internal" / "folder"))
        )
    elif family.startswith("payload-runtime") or family in {
        "payload-purl",
        "malformed-runtime-purl",
    }:
        snapshot = _snapshot_with_runtime_file(snapshot)
        component.clear()
        component.update(_runtime_payload_component(family))
        closure_names = frozenset()
    elif family == "payload-vendor":
        component["properties"] = [
            {
                "name": "syft:location:0:path",
                "value": "/_internal/sample.bin",
            }
        ]
        closure_names = frozenset()
    elif family == "nested-reference-hash":
        component["externalReferences"] = [
            {
                "type": "website",
                "url": "https://example.invalid/project",
                "hashes": {},
            }
        ]
    elif family == "latent-windows-path":
        snapshot = replace(snapshot, root=PureWindowsPath("C:/owned/payload"))
        component.clear()
        component.update(
            _payload_file_component("/c/owned/payload/_internal/missing.bin")
        )
    else:
        raise AssertionError("unknown payload normalizer fixture")

    policy = ci_qualify._sbom_normalize._NormalizationPolicy(frozenset(), ())
    return _captured_exception(
        lambda: ci_qualify._sbom_normalize._normalize_payload_sbom(
            raw,
            snapshot,
            "1.2.3",
            closure_names,
            [],
            policy,
            100,
            target=artifact.target,
        )
    )


def _python_normalizer_error(tmp_path: Path, family: str) -> BaseException:
    _snapshot, artifact, _raw_payload = _normalizer_fixture(tmp_path)
    component: dict[str, object] = {
        "type": "library",
        "name": "example",
        "version": "1.0",
        "purl": "pkg:pypi/example@1.0",
        "bom-ref": "raw-example",
        "licenses": [{"license": {"id": "MIT"}}],
    }
    raw: dict[str, object] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [component],
        "dependencies": [{"ref": "raw-example"}],
    }
    if family == "hash":
        component["externalReferences"] = [
            {
                "type": "website",
                "url": "https://example.invalid/project",
                "hashes": {},
            }
        ]
    elif family == "properties":
        component["properties"] = {}
    elif not _apply_neutral_sbom_failure(component, raw, family):
        raise AssertionError("unknown Python normalizer fixture")

    installed = ci_qualify._sbom_normalize._InstalledLicense(
        "example", "1.0", None, None, (), ()
    )
    return _captured_exception(
        lambda: ci_qualify._sbom_normalize._normalize_python_sbom(
            raw,
            {"example": {"version": "1.0", "hashes": ("sha256:" + "c" * 64,)}},
            {"example": installed},
            artifact,
            "1.2.3",
            "d" * 64,
            [],
            frozenset(),
        )
    )


def _payload_component_stack_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    supplied: BaseException,
) -> BaseException:
    snapshot, artifact, raw = _normalizer_fixture(tmp_path)
    original = ci_qualify._sbom_normalize._required_string

    def reject_component_type(value: object, label: str) -> str:
        if label == "component type":
            raise supplied
        return original(value, label)

    monkeypatch.setattr(
        ci_qualify._sbom_normalize, "_required_string", reject_component_type
    )
    policy = ci_qualify._sbom_normalize._NormalizationPolicy(frozenset(), ())
    return _captured_exception(
        lambda: ci_qualify._sbom_normalize._normalize_payload_sbom(
            raw,
            snapshot,
            "1.2.3",
            frozenset({"example"}),
            [],
            policy,
            100,
            target=artifact.target,
        )
    )


def _warning_stack_error(supplied: BaseException) -> BaseException:
    class _WarningFile:
        def read_bytes(self) -> bytes:
            raise supplied

    artifact = SimpleNamespace(pyinstaller_warning_file=_WarningFile())
    canonical = FunctionType(
        ci_qualify._evidence_policy._canonical_warnings.__code__,
        ci_qualify._evidence_policy._canonical_warnings.__globals__,
        name=ci_qualify._evidence_policy._canonical_warnings.__name__,
    )
    return _captured_exception(lambda: canonical(object(), artifact, 1))


def _warning_canonical_error(
    tmp_path: Path, raw: bytes, maximum: int = 4096
) -> BaseException:
    snapshot, artifact, _raw_sbom = _normalizer_fixture(tmp_path)
    resolved = artifact.build_metadata_dir / "resolved"
    resolved.mkdir()
    (resolved / "environment.json").write_text(
        '{"schema_version":1,"packages":[]}', encoding="utf-8"
    )
    artifact.pyinstaller_warning_file.write_bytes(raw)
    snapshot = replace(
        snapshot,
        build_toolchain={
            "schema_version": 1,
            "python_implementation": "CPython",
            "python_version": "3.12.14",
            "spec_sha256": "a" * 64,
            "hooks_sha256": "b" * 64,
        },
    )
    return _captured_exception(
        lambda: ci_qualify._evidence_policy._canonical_warnings(
            snapshot, artifact, maximum
        )
    )


def _warning_contents(*records: str) -> bytes:
    return (
        "\n".join((*ci_qualify._evidence_policy._PYINSTALLER_PREAMBLE, *records)) + "\n"
    ).encode("utf-8")


def _warning_analysis_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    raw: bytes,
    *,
    toolchain: dict[str, object] | None = None,
    allowlist: object | None = None,
    reject_warnings_write: bool = False,
) -> BaseException:
    snapshot, artifact, _raw_sbom = _normalizer_fixture(tmp_path)
    resolved = artifact.build_metadata_dir / "resolved"
    resolved.mkdir()
    (resolved / "environment.json").write_text(
        '{"schema_version":1,"packages":[]}', encoding="utf-8"
    )
    warning_allowlist = tmp_path / "warnings-allowlist.json"
    target_names = ci_qualify._evidence_policy._TARGET_NAMES
    warning_allowlist.write_text(
        json.dumps(
            allowlist
            if allowlist is not None
            else {
                "schema_version": 1,
                "targets": {name: [] for name in target_names},
            }
        ),
        encoding="utf-8",
    )
    artifact = replace(
        artifact,
        target=replace(artifact.target, warning_allowlist=warning_allowlist),
    )
    artifact.pyinstaller_warning_file.write_bytes(raw)
    snapshot = replace(
        snapshot,
        build_toolchain=toolchain
        if toolchain is not None
        else {
            "schema_version": 1,
            "python_implementation": "CPython",
            "python_version": "3.12.14",
            "spec_sha256": "a" * 64,
            "hooks_sha256": "b" * 64,
        },
    )
    monkeypatch.setattr(
        ci_qualify._evidence_policy, "validate_toc_policy", lambda *_: None
    )
    monkeypatch.setattr(
        ci_qualify._evidence_policy, "inspect_native_payload", lambda *_: []
    )
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    if reject_warnings_write:
        (evidence / "warnings.json").write_text("occupied", encoding="utf-8")
    return _captured_exception(
        lambda: ci_qualify._evidence_policy.analyse_policy_evidence(
            snapshot,
            artifact,
            ci_qualify.load_evidence_policy(ci_qualify._EVIDENCE_POLICY),
            evidence,
        )
    )


def _unsafe_link_snapshot(root: Path) -> PayloadSnapshot:
    return PayloadSnapshot(
        root=root,
        entries=(
            PayloadEntry(
                PurePosixPath("framework/Python"),
                "symlink",
                0o777,
                7,
                None,
                "missing",
            ),
        ),
        expanded_regular_bytes=0,
        executable_relative_path=PurePosixPath("servonaut"),
        marker={"product_version": "1.2.3"},
        build_provenance={},
        build_toolchain={},
    )


def _captured_link_exception() -> BaseException:
    entries = (
        PayloadEntry(
            PurePosixPath("framework/Python"),
            "symlink",
            0o777,
            7,
            None,
            "/unsafe",
        ),
    )
    resolver = ci_qualify._artifact_filesystem.SnapshotPathResolver(entries, 8)
    return _captured_exception(
        lambda: resolver.resolve_entry(PurePosixPath("framework/Python"))
    )


def _install_successful_fakes(
    monkeypatch: pytest.MonkeyPatch,
    request: QualificationRequest,
    calls: list[str],
) -> None:
    target = SimpleNamespace(name=request.target_name)
    monkeypatch.setattr(ci_qualify, "load_target_spec", lambda *_args: target)

    def fake_build(build_request: BuildRequest) -> object:
        calls.append("build")
        assert build_request.wheel == request.wheel
        assert build_request.product_version == request.product_version
        assert build_request.build_revision == request.build_revision
        assert build_request.source_commit == request.source_commit
        assert build_request.require_artifact_selftest is True
        output = request.qualification_root / "build output"
        output.mkdir(mode=0o700)
        payload = output / "servonaut"
        payload.mkdir()
        executable = payload / (
            "servonaut.exe" if "windows" in request.target_name else "servonaut"
        )
        executable.write_bytes(b"executable")
        return SimpleNamespace(
            payload_root=payload,
            executable=executable,
            archive=None,
            pyinstaller_warning_file=output / "warning.txt",
            build_metadata_dir=output / "build-metadata",
        )

    @contextmanager
    def fake_collect(artifact: object, evidence_dir: Path) -> object:
        calls.append("evidence")
        assert artifact.archive is None
        assert artifact.wheel == request.wheel
        (evidence_dir / "manifest.json").write_text(
            '{"schema_version":1}\n', encoding="utf-8"
        )
        workspace = request.qualification_root / ".artifact-evidence-test"
        archive_root = workspace / "archive"
        workspace.mkdir(mode=0o700)
        archive_root.mkdir(mode=0o700)
        archive = archive_root / "artifact.tar.gz"
        archive.write_bytes(b"archive")
        archive_status = archive.stat()
        root_status = archive_root.stat()
        owner = ArchiveOwner(
            archive,
            archive_root,
            archive_status.st_dev,
            archive_status.st_ino,
            "0" * 64,
            root_status.st_dev,
            root_status.st_ino,
            {},
            1,
        )
        result = SimpleNamespace(archive=archive, _archive_owner=owner)
        yield result
        ci_qualify._inspect_facade._enforce(result, target, object())

    def fake_extract(_archive: Path, destination: Path) -> Path:
        calls.append("extract")
        assert _archive == (
            request.qualification_root
            / ".artifact-evidence-test"
            / "archive"
            / "artifact.tar.gz"
        )
        destination.mkdir(mode=0o700)
        executable = destination / (
            "servonaut.exe" if "windows" in request.target_name else "servonaut"
        )
        executable.write_bytes(b"executable")
        return destination

    def fake_native(smoke_request: object, _policy: object) -> object:
        calls.append("native-smoke")
        assert (
            smoke_request.payload_root
            == request.qualification_root / "extracted payload"
        )
        return object()

    def fake_container(container_request: object, _policy: object) -> object:
        calls.append("container-smoke")
        assert (
            container_request.payload_root
            == request.qualification_root / "extracted payload"
        )
        assert container_request.docker == request.docker
        return object()

    def fake_delete(owner: ArchiveOwner) -> None:
        calls.append("delete-archive")
        owner.path.unlink()
        owner.output_root.rmdir()

    monkeypatch.setattr(ci_qualify, "build_standalone", fake_build)
    monkeypatch.setattr(
        ci_qualify._inspect_facade, "_collected_artifact_for_smoke", fake_collect
    )
    monkeypatch.setattr(
        ci_qualify._inspect_facade,
        "_enforce",
        lambda *_args: calls.append("enforce"),
    )
    monkeypatch.setattr(ci_qualify, "extract_archive_for_smoke", fake_extract)
    monkeypatch.setattr(ci_qualify, "run_smoke", fake_native)
    monkeypatch.setattr(ci_qualify, "assert_smoke", lambda _result: None)
    monkeypatch.setattr(ci_qualify, "run_container_smoke", fake_container)
    monkeypatch.setattr(ci_qualify, "load_smoke_policy", lambda _path: object())
    monkeypatch.setattr(ci_qualify, "delete_owned_archive", fake_delete)


def test_qualify_runs_fixed_non_linux_sequence_and_cleans_private_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    calls: list[str] = []
    _install_successful_fakes(monkeypatch, request, calls)

    result = qualify(request)

    assert result.status == "passed"
    assert result.completed_stages == (
        "build",
        "evidence",
        "archive",
        "extract",
        "native-smoke",
        "cleanup",
    )
    assert calls == [
        "build",
        "evidence",
        "extract",
        "native-smoke",
        "enforce",
        "delete-archive",
    ]
    assert {path.name for path in request.qualification_root.iterdir()} == {
        "public evidence"
    }
    status = json.loads(result.public_status.read_text(encoding="utf-8"))
    assert status == {
        "schema_version": 1,
        "target": "macos-x64",
        "status": "passed",
        "completed_stages": list(result.completed_stages),
        "completed_stage_count": 6,
        "failure_code": None,
    }
    assert (request.public_evidence_dir / "manifest.json").is_file()
    assert not any(
        path.name in {"servonaut", "servonaut.exe"}
        for path in request.public_evidence_dir.iterdir()
    )


def test_linux_uses_same_extracted_bits_for_native_then_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path, target="linux-x64-ubuntu-22.04")
    calls: list[str] = []
    _install_successful_fakes(monkeypatch, request, calls)

    result = qualify(request)

    assert result.status == "passed"
    assert result.completed_stages[-3:] == (
        "native-smoke",
        "container-smoke",
        "cleanup",
    )
    assert calls.index("native-smoke") < calls.index("container-smoke")


def test_failed_final_enforcement_follows_smoke_and_still_writes_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    calls: list[str] = []
    _install_successful_fakes(monkeypatch, request, calls)

    def reject(*_args: object) -> None:
        calls.append("enforce-rejected")
        raise ValueError("private rejection detail")

    monkeypatch.setattr(ci_qualify._inspect_facade, "_enforce", reject)

    result = qualify(request)

    assert result.status == "failed"
    assert result.completed_stages == (
        "build",
        "evidence",
        "archive",
        "extract",
        "native-smoke",
        "cleanup",
    )
    assert calls.index("native-smoke") < calls.index("enforce-rejected")
    status_text = result.public_status.read_text(encoding="utf-8")
    assert "private rejection detail" not in status_text
    assert str(request.qualification_root) not in status_text
    assert json.loads(status_text)["failure_code"] == "evidence-policy"
    assert (request.public_evidence_dir / "manifest.json").is_file()


def test_archive_identity_cleanup_failure_cannot_be_bypassed_by_tree_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    calls: list[str] = []
    _install_successful_fakes(monkeypatch, request, calls)
    monkeypatch.setattr(ci_qualify, "delete_owned_archive", lambda _owner: None)

    result = qualify(request)

    assert result.status == "failed"
    assert "cleanup" not in result.completed_stages
    assert json.loads(result.public_status.read_text())["failure_code"] == "cleanup"
    workspace = request.qualification_root / ".artifact-evidence-test"
    assert (workspace / "archive" / "artifact.tar.gz").is_file()


def test_cleanup_preserves_unowned_root_entry_and_fails_qualification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    calls: list[str] = []
    _install_successful_fakes(monkeypatch, request, calls)
    native = ci_qualify.run_smoke

    def add_foreign_entry(*args: object, **kwargs: object) -> object:
        result = native(*args, **kwargs)
        (request.qualification_root / "foreign").write_text("keep", encoding="utf-8")
        return result

    monkeypatch.setattr(ci_qualify, "run_smoke", add_foreign_entry)

    result = qualify(request)

    assert result.status == "failed"
    assert "cleanup" not in result.completed_stages
    assert json.loads(result.public_status.read_text())["failure_code"] == "cleanup"
    assert (request.qualification_root / "foreign").read_text(
        encoding="utf-8"
    ) == "keep"


@pytest.mark.parametrize(
    ("target", "with_docker"),
    [("linux-x64-ubuntu-22.04", False), ("macos-x64", True)],
)
def test_qualify_rejects_docker_target_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    with_docker: bool,
) -> None:
    request = _request(tmp_path, target=target)
    monkeypatch.setattr(
        ci_qualify,
        "load_target_spec",
        lambda *_args: SimpleNamespace(name=target),
    )
    if with_docker:
        docker = tmp_path / "docker"
        docker.write_text("executable", encoding="utf-8")
        docker.chmod(0o755)
        request = QualificationRequest(
            **{**request.__dict__, "docker": docker.resolve()}
        )
    else:
        request = QualificationRequest(**{**request.__dict__, "docker": None})

    with pytest.raises(QualificationError, match="Docker selection"):
        qualify(request)


def test_qualify_rejects_nonempty_or_nonprivate_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    monkeypatch.setattr(
        ci_qualify,
        "load_target_spec",
        lambda *_args: SimpleNamespace(name=request.target_name),
    )
    (request.qualification_root / "foreign").write_text("keep", encoding="utf-8")

    with pytest.raises(QualificationError, match="must be empty"):
        qualify(request)

    assert (request.qualification_root / "foreign").read_text(
        encoding="utf-8"
    ) == "keep"
    if os.name != "nt":
        (request.qualification_root / "foreign").unlink()
        request.qualification_root.chmod(0o755)
        with pytest.raises(QualificationError, match="permissions"):
            qualify(request)


@pytest.mark.parametrize("checksum", ("f" * 64, "F" * 64, "not-a-checksum", None))
def test_qualify_rejects_a_wheel_that_differs_from_its_recorded_checksum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, checksum: object
) -> None:
    request = replace(_request(tmp_path), wheel_sha256=checksum)
    builds: list[object] = []
    monkeypatch.setattr(ci_qualify, "build_standalone", builds.append)

    with pytest.raises(QualificationError, match="wheel checksum"):
        qualify(request)

    assert builds == []
    assert not any(request.qualification_root.iterdir())


def test_qualify_rejects_output_root_inside_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    root = checkout / "qualification"
    root.mkdir(mode=0o700)
    wheel = tmp_path / "servonaut-9.8.7-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    request = QualificationRequest(
        wheel.resolve(),
        hashlib.sha256(b"wheel").hexdigest(),
        "macos-x64",
        "9.8.7",
        "run-1",
        "a" * 40,
        checkout.resolve(),
        root.resolve(),
        (root / "public").resolve(),
        None,
    )
    monkeypatch.setattr(ci_qualify, "_PROJECT_ROOT", request.checkout)

    with pytest.raises(QualificationError, match="outside the checkout"):
        qualify(request)


def test_main_accepts_exact_workflow_flags_and_returns_qualification_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    captured: list[QualificationRequest] = []

    def fake_qualify(value: QualificationRequest) -> object:
        captured.append(value)
        return SimpleNamespace(status="failed")

    monkeypatch.setattr(ci_qualify, "qualify", fake_qualify)
    exit_code = main(
        [
            "--wheel",
            str(request.wheel),
            "--wheel-sha256",
            request.wheel_sha256,
            "--target-name",
            request.target_name,
            "--product-version",
            request.product_version,
            "--build-revision",
            request.build_revision,
            "--source-commit",
            request.source_commit,
            "--checkout",
            str(request.checkout),
            "--qualification-root",
            str(request.qualification_root),
            "--public-evidence-dir",
            str(request.public_evidence_dir),
        ]
    )

    assert exit_code == 1
    assert captured == [request]


def test_main_rejects_relative_paths_without_printing_values(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(
        [
            "--wheel",
            "private-wheel.whl",
            "--wheel-sha256",
            "0" * 64,
            "--target-name",
            "macos-x64",
            "--product-version",
            "9.8.7",
            "--build-revision",
            "run-1",
            "--source-commit",
            "a" * 40,
            "--checkout",
            "checkout",
            "--qualification-root",
            "qualification",
            "--public-evidence-dir",
            "evidence",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert not captured.out and not captured.err


def test_unknown_public_child_forces_generic_failed_status_and_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    calls: list[str] = []
    _install_successful_fakes(monkeypatch, request, calls)
    original = ci_qualify._inspect_facade._collected_artifact_for_smoke

    @contextmanager
    def write_unknown(artifact: object, evidence_dir: Path) -> object:
        with original(artifact, evidence_dir) as result:
            (evidence_dir / "raw-private.json").write_text(
                json.dumps(
                    {
                        "private_exception": "supply failed at local input",
                        "private_path": str(request.qualification_root),
                    }
                ),
                encoding="utf-8",
            )
            yield result

    monkeypatch.setattr(
        ci_qualify._inspect_facade, "_collected_artifact_for_smoke", write_unknown
    )

    result = qualify(request)

    assert result.status == "failed"
    assert (request.public_evidence_dir / "raw-private.json").is_file()
    status = result.public_status.read_text(encoding="utf-8")
    assert "raw-private" not in status
    assert "supply failed" not in status
    assert str(request.qualification_root) not in status
    assert json.loads(status)["failure_code"] == "public-candidate"


def test_unknown_public_directory_is_preserved_with_generic_failed_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    calls: list[str] = []
    _install_successful_fakes(monkeypatch, request, calls)
    original = ci_qualify._inspect_facade._collected_artifact_for_smoke

    @contextmanager
    def write_unknown_directory(artifact: object, evidence_dir: Path) -> object:
        with original(artifact, evidence_dir) as result:
            (evidence_dir / "unexpected").mkdir()
            yield result

    monkeypatch.setattr(
        ci_qualify._inspect_facade,
        "_collected_artifact_for_smoke",
        write_unknown_directory,
    )

    result = qualify(request)

    assert result.status == "failed"
    assert (request.public_evidence_dir / "unexpected").is_dir()
    assert result.public_status.is_file()
    assert json.loads(result.public_status.read_text())["failure_code"] == (
        "public-candidate"
    )


def test_occupied_status_target_hard_fails_without_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    calls: list[str] = []
    _install_successful_fakes(monkeypatch, request, calls)
    original = ci_qualify._inspect_facade._collected_artifact_for_smoke

    @contextmanager
    def occupy_status(artifact: object, evidence_dir: Path) -> object:
        with original(artifact, evidence_dir) as result:
            (evidence_dir / "qualification-status.json").write_text(
                "foreign\n", encoding="utf-8"
            )
            yield result

    monkeypatch.setattr(
        ci_qualify._inspect_facade, "_collected_artifact_for_smoke", occupy_status
    )

    with pytest.raises(QualificationError, match="status already exists"):
        qualify(request)

    assert (request.public_evidence_dir / "qualification-status.json").read_text(
        encoding="utf-8"
    ) == "foreign\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink status boundary")
def test_symlinked_status_target_hard_fails_without_following_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    calls: list[str] = []
    _install_successful_fakes(monkeypatch, request, calls)
    original = ci_qualify._inspect_facade._collected_artifact_for_smoke
    foreign = tmp_path / "foreign-status.json"
    foreign.write_text("foreign\n", encoding="utf-8")

    @contextmanager
    def link_status(artifact: object, evidence_dir: Path) -> object:
        with original(artifact, evidence_dir) as result:
            (evidence_dir / "qualification-status.json").symlink_to(foreign)
            yield result

    monkeypatch.setattr(
        ci_qualify._inspect_facade, "_collected_artifact_for_smoke", link_status
    )

    with pytest.raises(QualificationError, match="status already exists"):
        qualify(request)

    assert foreign.read_text(encoding="utf-8") == "foreign\n"
    assert (request.public_evidence_dir / "qualification-status.json").is_symlink()


def test_replaced_public_directory_hard_fails_without_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    calls: list[str] = []
    _install_successful_fakes(monkeypatch, request, calls)
    native = ci_qualify.run_smoke

    def replace_public(*args: object, **kwargs: object) -> object:
        result = native(*args, **kwargs)
        original = request.qualification_root / "original-public"
        request.public_evidence_dir.rename(original)
        request.public_evidence_dir.mkdir(mode=0o700)
        return result

    monkeypatch.setattr(ci_qualify, "run_smoke", replace_public)

    with pytest.raises(QualificationError, match="ownership changed"):
        qualify(request)

    assert not (request.public_evidence_dir / "qualification-status.json").exists()
    assert not (
        request.qualification_root / "original-public" / "qualification-status.json"
    ).exists()


@pytest.mark.parametrize(
    ("function", "expected"),
    [
        (ci_qualify._model.validate_build_request, "build-validation"),
        (ci_qualify._build._validate_host_target, "build-validation"),
        (ci_qualify._build._require_builder_inputs, "build-profile"),
        (ci_qualify._build._copy_build_profile, "build-profile"),
        (ci_qualify._build._write_profile, "build-profile"),
        (ci_qualify._build._build_staged_payload, "build-staged"),
        (ci_qualify._build._publish_staged_outputs, "build-staged"),
        (ci_qualify._build._publish_owned_directory, "build-staged"),
        (ci_qualify._build._venv_python, "build-venv"),
        (ci_qualify._build._assert_venv_prefix, "build-venv"),
        (ci_qualify._build._venv_site_packages, "build-venv"),
        (ci_qualify._build._bootstrap_venv_pip, "build-pip-bootstrap"),
        (ci_qualify._build._install_wheel_and_lock, "build-dependency-install"),
        (ci_qualify._build._run_pyinstaller, "build-pyinstaller"),
        (
            ci_qualify._build._raise_pyinstaller_profile_failure,
            "build-pyinstaller-profile",
        ),
        (
            ci_qualify._build._raise_pyinstaller_runtime_metadata_failure,
            "build-pyinstaller-runtime-metadata",
        ),
        (
            ci_qualify._build._raise_pyinstaller_analysis_failure,
            "build-pyinstaller-analysis",
        ),
        (
            ci_qualify._build._raise_pyinstaller_data_filter_failure,
            "build-pyinstaller-data-filter",
        ),
        (
            ci_qualify._build._raise_pyinstaller_pyz_failure,
            "build-pyinstaller-pyz",
        ),
        (
            ci_qualify._build._raise_pyinstaller_exe_failure,
            "build-pyinstaller-exe",
        ),
        (
            ci_qualify._build._raise_pyinstaller_collect_failure,
            "build-pyinstaller-collect",
        ),
        (
            ci_qualify._build._raise_pyinstaller_isolated_child_failure,
            "build-pyinstaller-isolated-child",
        ),
        (
            ci_qualify._build._raise_pyinstaller_hook_import_failure,
            "build-pyinstaller-hook-import",
        ),
        (
            ci_qualify._build._raise_pyinstaller_python_library_failure,
            "build-pyinstaller-python-library",
        ),
        (
            ci_qualify._build._raise_pyinstaller_filesystem_missing_failure,
            "build-pyinstaller-filesystem-missing",
        ),
        (
            ci_qualify._build._raise_pyinstaller_filesystem_access_failure,
            "build-pyinstaller-filesystem-access",
        ),
        (
            ci_qualify._build._raise_pyinstaller_filesystem_capacity_failure,
            "build-pyinstaller-filesystem-capacity",
        ),
        (
            ci_qualify._build._raise_pyinstaller_recursion_failure,
            "build-pyinstaller-recursion",
        ),
        (
            ci_qualify._build._raise_pyinstaller_memory_failure,
            "build-pyinstaller-memory",
        ),
        (ci_qualify._build._capture_build_metadata, "build-metadata"),
        (
            ci_qualify._build._write_environment_inventory,
            "build-metadata-environment",
        ),
        (ci_qualify._build._write_license_inventory, "build-metadata-licenses"),
        (ci_qualify._build._write_python_sbom, "build-metadata-python-sbom"),
        (ci_qualify._build._write_build_provenance, "build-metadata-provenance"),
        (ci_qualify._build._write_build_toolchain, "build-metadata-toolchain"),
        (ci_qualify._runtime_marker.write_runtime_marker, "build-runtime-marker"),
        (
            ci_qualify._runtime_marker._validate_marker_with_runtime,
            "build-runtime-marker",
        ),
        (ci_qualify._artifact_filesystem._walk_payload, "evidence-snapshot-walk"),
        (
            ci_qualify._artifact_filesystem.SnapshotPathResolver.validate_links,
            "artifact-link-validation",
        ),
        (
            ci_qualify._artifact_filesystem.SnapshotPathResolver.resolve_entry,
            "artifact-link-validation",
        ),
        (
            ci_qualify._artifact_filesystem._relative_regular_file,
            "evidence-snapshot-executable",
        ),
        (
            ci_qualify._artifact_filesystem._read_marker,
            "evidence-snapshot-marker",
        ),
        (
            ci_qualify._artifact_filesystem._validate_marker,
            "evidence-snapshot-marker",
        ),
        (
            ci_qualify._artifact_filesystem._validate_metadata,
            "evidence-snapshot-metadata",
        ),
        (
            ci_qualify._artifact_filesystem._read_build_provenance,
            "evidence-snapshot-provenance",
        ),
        (
            ci_qualify._artifact_filesystem._read_build_toolchain,
            "evidence-snapshot-toolchain",
        ),
        (
            ci_qualify._artifact_filesystem._validate_forbidden_paths,
            "evidence-snapshot-forbidden",
        ),
        (
            ci_qualify._sbom_normalize._load_environment,
            "evidence-supply-environment",
        ),
        (
            ci_qualify._sbom_normalize._load_installed_licenses,
            "evidence-supply-licenses",
        ),
        (
            ci_qualify._sbom_normalize._load_normalization_policy,
            "evidence-supply-policy",
        ),
        (
            ci_qualify._sbom_normalize._validate_wheel_provenance,
            "evidence-supply-wheel-provenance",
        ),
        (
            ci_qualify._sbom_normalize._normalize_payload_sbom,
            "evidence-supply-payload",
        ),
        (
            ci_qualify._sbom_normalize._normalize_python_sbom,
            "evidence-supply-python",
        ),
        (
            ci_qualify._sbom_normalize._normalize_payload_component,
            "evidence-supply-payload-component",
        ),
        (
            ci_qualify._sbom_normalize._normalize_properties,
            "evidence-supply-properties",
        ),
        (
            ci_qualify._sbom_normalize._payload_relative_path,
            "evidence-supply-payload-path",
        ),
        (
            ci_qualify._sbom_normalize._windows_payload_relative_path,
            "evidence-supply-payload-path",
        ),
        (
            ci_qualify._sbom_normalize._snapshot_content_sha256,
            "evidence-supply-payload-file",
        ),
        (
            ci_qualify._sbom_normalize._embedded_python_runtime_purl,
            "evidence-supply-payload-purl",
        ),
        (
            ci_qualify._sbom_normalize._validate_embedded_python_runtime_properties,
            "evidence-supply-payload-runtime-properties",
        ),
        (
            ci_qualify._sbom_normalize._normalize_embedded_runtime_licenses,
            "evidence-supply-payload-runtime-license",
        ),
        (
            ci_qualify._sbom_normalize._vendored_python_component,
            "evidence-supply-payload-vendor",
        ),
        (ci_qualify._sbom_normalize._component, "evidence-supply-fields"),
        (ci_qualify._sbom_normalize._component_ref, "evidence-supply-fields"),
        (ci_qualify._sbom_normalize._optional_string, "evidence-supply-fields"),
        (ci_qualify._sbom_normalize._normalize_hashes, "evidence-supply-hash"),
        (ci_qualify._sbom_normalize._normalize_licenses, "evidence-supply-license"),
        (ci_qualify._sbom_normalize._validate_purl, "evidence-supply-purl"),
        (ci_qualify._sbom_normalize._parse_pypi_purl, "evidence-supply-purl"),
        (
            ci_qualify._sbom_normalize._normalize_external_references,
            "evidence-supply-reference",
        ),
        (
            ci_qualify._sbom_normalize._normalize_dependencies,
            "evidence-supply-dependencies",
        ),
        (
            ci_qualify._sbom_normalize._dependency_provenance,
            "evidence-supply-dependency-reconciliation",
        ),
        (
            ci_qualify._sbom_normalize._license_inventory,
            "evidence-supply-license-reconciliation",
        ),
        (
            ci_qualify._evidence_sanitize.encode_public_json,
            "evidence-public-sanitize",
        ),
    ],
)
def test_failure_classifier_has_exact_identity_for_each_refined_group(
    function: Callable[..., object], expected: str
) -> None:
    matches = [
        token
        for code, token in ci_qualify._SEMANTIC_FAILURE_CODES
        if code is function.__code__
    ]

    assert matches == [expected]


def test_failure_taxonomy_and_semantic_code_identities_are_unique() -> None:
    assert set(get_args(ci_qualify._FailureCode)) == ci_qualify._FAILURE_CODES
    identities = [id(code) for code, _token in ci_qualify._SEMANTIC_FAILURE_CODES]
    assert len(identities) == len(set(identities))

    messages = [
        message for message, _token in ci_qualify._PAYLOAD_COMPONENT_FAILURE_CODES
    ]
    tokens = {token for _message, token in ci_qualify._PAYLOAD_COMPONENT_FAILURE_CODES}
    assert len(messages) == len(set(messages))
    assert max(map(len, messages)) <= ci_qualify._MAX_FAILURE_MESSAGE_CHARS
    assert tokens == {
        "evidence-supply-payload-component-fields",
        "evidence-supply-payload-component-file-hash",
        "evidence-supply-payload-component-package-identity",
        "evidence-supply-payload-component-purl-type",
        "evidence-supply-payload-component-runtime-identity",
        "evidence-supply-payload-component-version",
    }

    warning_messages = [
        message for message, _token in ci_qualify._WARNING_CANONICAL_FAILURE_CODES
    ]
    warning_tokens = {
        token for _message, token in ci_qualify._WARNING_CANONICAL_FAILURE_CODES
    }
    assert len(warning_messages) == len(set(warning_messages))
    assert max(map(len, warning_messages)) <= ci_qualify._MAX_FAILURE_MESSAGE_CHARS
    assert warning_tokens == {
        "evidence-warning-input",
        "evidence-warning-preamble",
        "evidence-warning-record",
    }


@pytest.mark.parametrize(
    ("function", "expected"),
    [
        (ci_qualify._evidence_policy._canonical_warnings, "evidence-warning-canonical"),
        (
            ci_qualify._evidence_policy._warning_toolchain_sha256,
            "evidence-warning-toolchain",
        ),
        (ci_qualify._evidence_policy._parse_importers, "evidence-warning-importers"),
        (
            ci_qualify._evidence_policy._split_importers,
            "evidence-warning-importer-list",
        ),
        (
            ci_qualify._evidence_policy._parse_qualifiers,
            "evidence-warning-importer-qualifiers",
        ),
        (
            ci_qualify._evidence_policy._load_warning_allowlist,
            "evidence-warning-allowlist",
        ),
        (
            ci_qualify._evidence_policy._classify_warnings,
            "evidence-warning-classification",
        ),
    ],
)
def test_warning_failure_classifier_uses_exact_identity(
    function: Callable[..., object], expected: str
) -> None:
    assert [
        token
        for code, token in ci_qualify._SEMANTIC_FAILURE_CODES
        if code is function.__code__
    ] == [expected]


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (
            lambda tmp_path, _monkeypatch: _warning_canonical_error(tmp_path, b"", 16),
            "evidence-warning-preamble",
        ),
        (
            lambda tmp_path, _monkeypatch: _warning_canonical_error(
                tmp_path, b"\xff", 16
            ),
            "evidence-warning-input",
        ),
        (
            lambda tmp_path, _monkeypatch: _warning_canonical_error(
                tmp_path, b"x" * 17, 16
            ),
            "evidence-warning-input",
        ),
        (
            lambda tmp_path, _monkeypatch: _warning_canonical_error(
                tmp_path,
                _warning_contents(
                    "missing module named 'example' - imported by client (optional)",
                    "not a PyInstaller warning record",
                ),
            ),
            "evidence-warning-record",
        ),
        (
            lambda tmp_path, monkeypatch: _warning_analysis_error(
                tmp_path,
                monkeypatch,
                _warning_contents(
                    "missing module named 'example' - imported by client (optional)"
                ),
                toolchain={},
            ),
            "evidence-warning-toolchain",
        ),
        (
            lambda tmp_path, monkeypatch: _warning_analysis_error(
                tmp_path,
                monkeypatch,
                _warning_contents(
                    "missing module named 'example' - imported by client invalid"
                ),
            ),
            "evidence-warning-importers",
        ),
        (
            lambda tmp_path, monkeypatch: _warning_analysis_error(
                tmp_path,
                monkeypatch,
                _warning_contents(
                    "missing module named 'example' - imported by client (optional),"
                ),
            ),
            "evidence-warning-importer-list",
        ),
        (
            lambda tmp_path, monkeypatch: _warning_analysis_error(
                tmp_path,
                monkeypatch,
                _warning_contents(
                    "missing module named 'example' - imported by client (unknown)"
                ),
            ),
            "evidence-warning-importer-qualifiers",
        ),
        (
            lambda tmp_path, monkeypatch: _warning_analysis_error(
                tmp_path,
                monkeypatch,
                _warning_contents(
                    "missing module named 'example' - imported by client (optional)"
                ),
                allowlist={},
            ),
            "evidence-warning-allowlist",
        ),
        (
            lambda tmp_path, monkeypatch: _warning_analysis_error(
                tmp_path,
                monkeypatch,
                _warning_contents(
                    "missing module named 'example' - imported by client (optional)"
                ),
                allowlist={
                    "schema_version": 1,
                    "targets": {
                        name: ([{}] if name == "linux-x64-ubuntu-22.04" else [])
                        for name in ci_qualify._evidence_policy._TARGET_NAMES
                    },
                },
            ),
            "evidence-warning-classification",
        ),
    ],
    ids=(
        "preamble",
        "utf8",
        "oversize",
        "record",
        "toolchain",
        "importers",
        "importer-list",
        "qualifiers",
        "allowlist",
        "classification",
    ),
)
def test_warning_failure_classifier_uses_original_warning_stacks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: Callable[..., BaseException],
    expected: str,
) -> None:
    assert _classify_failure(error(tmp_path, monkeypatch), "unknown") == expected


def test_warning_write_failure_keeps_existing_writer_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    error = _warning_analysis_error(
        tmp_path,
        monkeypatch,
        _warning_contents(
            "missing module named 'example' - imported by client (optional)"
        ),
        reject_warnings_write=True,
    )

    assert _classify_failure(error, "unknown") == "evidence-write"


def test_warning_missing_file_preserves_owned_input_code_over_os_cause(
    tmp_path: Path,
) -> None:
    missing = _minimal_artifact(tmp_path / "missing")
    error = _captured_exception(
        lambda: ci_qualify._evidence_policy._canonical_warnings(
            object(),
            replace(missing, pyinstaller_warning_file=tmp_path / "not-present"),
            1,
        )
    )

    assert _classify_failure(error, "unknown") == "evidence-warning-input"


@pytest.mark.parametrize(
    "supplied",
    [
        ci_qualify._evidence_policy.ArtifactEvidenceError(),
        ci_qualify._evidence_policy.ArtifactEvidenceError(
            "PyInstaller warning file is unavailable", "private-extra"
        ),
        ci_qualify._evidence_policy.ArtifactEvidenceError(7),
        ci_qualify._evidence_policy.ArtifactEvidenceError("x" * 129),
        ci_qualify._evidence_policy.ArtifactEvidenceError("private-unknown-warning"),
    ],
    ids=("no-arguments", "multiple-arguments", "non-string", "overlong", "unknown"),
)
def test_warning_descriptor_rejects_unapproved_argument_shapes(
    supplied: BaseException,
) -> None:
    assert _classify_failure(_warning_stack_error(supplied), "unknown") == (
        "evidence-warning-canonical"
    )


@pytest.mark.parametrize(
    "message",
    [
        _LengthPoisonString("PyInstaller warning file is unavailable"),
        _EqualityPoisonString("PyInstaller warning file is unavailable"),
    ],
    ids=("length", "equality"),
)
def test_warning_descriptor_rejects_string_subclasses_without_hooks(
    message: str,
) -> None:
    error = ci_qualify._evidence_policy.ArtifactEvidenceError(message)

    assert _classify_failure(_warning_stack_error(error), "unknown") == (
        "evidence-warning-canonical"
    )


def test_warning_descriptor_requires_exact_error_type() -> None:
    class _DerivedArtifactError(ci_qualify._evidence_policy.ArtifactEvidenceError):
        @property
        def args(self) -> object:
            raise AssertionError("ordinary exception arguments are forbidden")

        def __str__(self) -> str:
            raise AssertionError("exception text must not be formatted")

        def __repr__(self) -> str:
            raise AssertionError("exception details must not be formatted")

    error = _DerivedArtifactError("PyInstaller warning file is unavailable")

    assert _classify_failure(_warning_stack_error(error), "unknown") == (
        "evidence-warning-canonical"
    )


def test_later_known_owned_warning_cause_owns_its_descriptor(tmp_path: Path) -> None:
    outer = _captured_exception(
        lambda: ci_qualify._evidence_policy._canonical_warnings(
            object(),
            SimpleNamespace(pyinstaller_warning_file=tmp_path / "missing"),
            1,
        )
    )
    cause = _warning_stack_error(
        ci_qualify._evidence_policy.ArtifactEvidenceError(
            "PyInstaller warning preamble is invalid"
        )
    )
    _set_explicit_cause(outer, cause)

    assert _classify_failure(outer, "unknown") == "evidence-warning-preamble"


def test_later_unknown_owned_warning_cause_restores_broad_code(tmp_path: Path) -> None:
    outer = _captured_exception(
        lambda: ci_qualify._evidence_policy._canonical_warnings(
            object(),
            SimpleNamespace(pyinstaller_warning_file=tmp_path / "missing"),
            1,
        )
    )
    cause = _warning_stack_error(
        ci_qualify._evidence_policy.ArtifactEvidenceError("private-unknown-warning")
    )
    _set_explicit_cause(outer, cause)

    assert _classify_failure(outer, "unknown") == "evidence-warning-canonical"


def test_deeper_warning_helper_overrides_owned_descriptor(tmp_path: Path) -> None:
    outer = _captured_exception(
        lambda: ci_qualify._evidence_policy._canonical_warnings(
            object(),
            SimpleNamespace(pyinstaller_warning_file=tmp_path / "missing"),
            1,
        )
    )
    cause = _captured_exception(
        lambda: ci_qualify._evidence_policy._parse_qualifiers("unknown")
    )
    _set_explicit_cause(outer, cause)

    assert _classify_failure(outer, "unknown") == "evidence-warning-importer-qualifiers"


def test_warning_descriptor_obeys_existing_explicit_cause_cap() -> None:
    root = _warning_stack_error(
        ci_qualify._evidence_policy.ArtifactEvidenceError(
            "PyInstaller warning file is unavailable"
        )
    )
    for _index in range(7):
        wrapper = _PoisonError("private-warning-cause")
        _set_explicit_cause(wrapper, root)
        root = wrapper

    assert _classify_failure(root, "unknown") == "evidence-warning-input"
    overflow = _PoisonError("private-warning-overflow")
    _set_explicit_cause(overflow, root)
    assert _classify_failure(overflow, "unknown") == "unknown"


@pytest.mark.parametrize(
    "failure_code",
    [
        "evidence-supply-fields",
        "evidence-supply-hash",
        "evidence-supply-license",
        "evidence-supply-purl",
        "evidence-supply-reference",
        "evidence-supply-dependencies",
        "evidence-supply-payload-component",
        "evidence-supply-payload-component-fields",
        "evidence-supply-payload-component-file-hash",
        "evidence-supply-payload-component-package-identity",
        "evidence-supply-payload-component-purl-type",
        "evidence-supply-payload-component-runtime-identity",
        "evidence-supply-payload-component-version",
        "evidence-supply-payload-path",
        "evidence-supply-payload-file",
        "evidence-supply-payload-purl",
        "evidence-supply-payload-runtime-properties",
        "evidence-supply-payload-runtime-license",
        "evidence-supply-payload-vendor",
        "evidence-supply-properties",
        "evidence-warning-allowlist",
        "evidence-warning-canonical",
        "evidence-warning-classification",
        "evidence-warning-importer-list",
        "evidence-warning-importer-qualifiers",
        "evidence-warning-importers",
        "evidence-warning-input",
        "evidence-warning-preamble",
        "evidence-warning-record",
        "evidence-warning-toolchain",
    ],
)
def test_new_supply_failure_codes_write_only_the_closed_status_schema(
    tmp_path: Path, failure_code: ci_qualify._FailureCode
) -> None:
    canary_root = tmp_path / "private-status-canary"
    canary_root.mkdir(mode=0o700)
    request = _request(canary_root)
    request.public_evidence_dir.mkdir(mode=0o700)
    status = request.public_evidence_dir.stat()
    owner = ci_qualify._OwnedDirectory(
        request.public_evidence_dir, (status.st_dev, status.st_ino)
    )

    output = ci_qualify._write_status(
        owner, request, "failed", ("cleanup",), failure_code
    )
    raw = output.read_text(encoding="utf-8")

    assert json.loads(raw) == {
        "schema_version": 1,
        "target": "macos-x64",
        "status": "failed",
        "completed_stages": ["cleanup"],
        "completed_stage_count": 1,
        "failure_code": failure_code,
    }
    assert str(request.qualification_root) not in raw
    assert "private-status-canary" not in raw


@pytest.mark.parametrize(
    ("raiser", "expected"),
    (
        (
            ci_qualify._build._raise_pyinstaller_profile_failure,
            "build-pyinstaller-profile",
        ),
        (
            ci_qualify._build._raise_pyinstaller_runtime_metadata_failure,
            "build-pyinstaller-runtime-metadata",
        ),
        (
            ci_qualify._build._raise_pyinstaller_analysis_failure,
            "build-pyinstaller-analysis",
        ),
        (
            ci_qualify._build._raise_pyinstaller_data_filter_failure,
            "build-pyinstaller-data-filter",
        ),
        (ci_qualify._build._raise_pyinstaller_pyz_failure, "build-pyinstaller-pyz"),
        (ci_qualify._build._raise_pyinstaller_exe_failure, "build-pyinstaller-exe"),
        (
            ci_qualify._build._raise_pyinstaller_collect_failure,
            "build-pyinstaller-collect",
        ),
        (
            ci_qualify._build._raise_pyinstaller_isolated_child_failure,
            "build-pyinstaller-isolated-child",
        ),
        (
            ci_qualify._build._raise_pyinstaller_hook_import_failure,
            "build-pyinstaller-hook-import",
        ),
        (
            ci_qualify._build._raise_pyinstaller_python_library_failure,
            "build-pyinstaller-python-library",
        ),
        (
            ci_qualify._build._raise_pyinstaller_filesystem_missing_failure,
            "build-pyinstaller-filesystem-missing",
        ),
        (
            ci_qualify._build._raise_pyinstaller_filesystem_access_failure,
            "build-pyinstaller-filesystem-access",
        ),
        (
            ci_qualify._build._raise_pyinstaller_filesystem_capacity_failure,
            "build-pyinstaller-filesystem-capacity",
        ),
        (
            ci_qualify._build._raise_pyinstaller_recursion_failure,
            "build-pyinstaller-recursion",
        ),
        (
            ci_qualify._build._raise_pyinstaller_memory_failure,
            "build-pyinstaller-memory",
        ),
    ),
)
def test_pyinstaller_diagnostic_raisers_emit_closed_statuses(
    raiser: Callable[[], None], expected: str
) -> None:
    error = _captured_exception(raiser)

    status = _classify_failure(error, "unknown")

    assert status == expected
    assert status in ci_qualify._FAILURE_CODES


def test_shared_wheel_parser_retains_build_validation_semantics(tmp_path: Path) -> None:
    artifact = _minimal_artifact(tmp_path)
    request = BuildRequest(
        wheel=artifact.wheel,
        target=artifact.target,
        product_version="1.2.3",
        build_revision="build-1",
        source_commit="a" * 40,
        output_dir=tmp_path / "output",
        require_artifact_selftest=True,
    )

    error = _captured_exception(
        lambda: ci_qualify._model.validate_build_request(request)
    )

    assert _classify_failure(error, "unknown") == "build-validation"


def test_shared_wheel_parser_retains_snapshot_semantics(tmp_path: Path) -> None:
    artifact = _minimal_artifact(tmp_path)
    limits = ci_qualify.load_evidence_policy(ci_qualify._EVIDENCE_POLICY).limits

    error = _captured_exception(
        lambda: ci_qualify._artifact_filesystem.snapshot_payload(artifact, limits)
    )

    assert _classify_failure(error, "unknown") == "evidence-snapshot"


def test_link_failure_uses_neutral_semantics_from_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = _minimal_artifact(tmp_path)
    limits = ci_qualify.load_evidence_policy(ci_qualify._EVIDENCE_POLICY).limits
    snapshot = _unsafe_link_snapshot(artifact.payload_root)
    monkeypatch.setattr(
        ci_qualify._artifact_filesystem,
        "_walk_payload",
        lambda *_args: (list(snapshot.entries), 0),
    )

    error = _captured_exception(
        lambda: ci_qualify._artifact_filesystem.snapshot_payload(artifact, limits)
    )

    assert _classify_failure(error, "unknown") == "artifact-link-validation"


def test_link_failure_uses_neutral_semantics_from_archive_creation(
    tmp_path: Path,
) -> None:
    target = ci_qualify.load_target_spec(
        ci_qualify._TARGET_POLICY, "linux-x64-ubuntu-22.04"
    )
    policy = ci_qualify.load_evidence_policy(ci_qualify._EVIDENCE_POLICY)
    snapshot = _unsafe_link_snapshot(tmp_path)

    error = _captured_exception(
        lambda: ci_qualify._artifact_archive.create_archive_from_snapshot(
            snapshot, target, policy, tmp_path / "archive"
        )
    )

    assert _classify_failure(error, "unknown") == "artifact-link-validation"


def test_link_failure_uses_neutral_semantics_from_extraction(tmp_path: Path) -> None:
    archive = tmp_path / "artifact.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        member = tarfile.TarInfo("framework/Python")
        member.type = tarfile.SYMTYPE
        member.linkname = "missing"
        output.addfile(member)
    limits = ci_qualify.load_evidence_policy(ci_qualify._EVIDENCE_POLICY).limits

    error = _captured_exception(
        lambda: ci_qualify._artifact_archive.extract_archive_safely(
            archive, tmp_path / "extracted", limits
        )
    )

    assert _classify_failure(error, "unknown") == "artifact-link-validation"


def test_supply_input_failure_runs_through_generation_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = _minimal_artifact(tmp_path)
    snapshot = PayloadSnapshot(
        root=artifact.payload_root,
        entries=(),
        expanded_regular_bytes=0,
        executable_relative_path=PurePosixPath("servonaut"),
        marker={},
        build_provenance={"product_version": "1.2.3"},
        build_toolchain={
            "schema_version": 1,
            "python_implementation": "CPython",
            "python_version": "3.12.14",
            "spec_sha256": "a" * 64,
            "hooks_sha256": "b" * 64,
        },
        runtime_notice={
            "schema_version": 1,
            "runtime": "cpython",
            "python_implementation": "CPython",
            "python_version": "3.12.14",
            "license_id": "Python-2.0",
            "payload_path": "_internal/notices/CPython-LICENSE.txt",
            "sha256": "c" * 64,
        },
    )
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    (workspace / "syft-cache").mkdir(mode=0o700)
    (workspace / "syft-config").mkdir(mode=0o700)
    tool = tmp_path / "syft"
    tool.write_bytes(b"tool")
    (artifact.build_metadata_dir / "resolved").mkdir()
    monkeypatch.setattr(ci_qualify._sbom_normalize, "acquire_syft", lambda *_args: tool)

    def write_raw_scan(*args: object) -> None:
        raw_output = args[5]
        assert isinstance(raw_output, Path)
        raw_output.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(ci_qualify._sbom_normalize, "run_syft_scan", write_raw_scan)
    error = _captured_exception(
        lambda: ci_qualify._sbom_normalize.generate_supply_chain_evidence(
            snapshot,
            artifact,
            evidence,
            workspace,
            ci_qualify.load_evidence_policy(
                ci_qualify._EVIDENCE_POLICY
            ).limits.max_payload_entries,
        )
    )

    assert _classify_failure(error, "unknown") == "evidence-supply-environment"


def test_supply_normalization_failure_executes_original_normalizer() -> None:
    error = _captured_exception(
        lambda: ci_qualify._sbom_normalize._normalize_payload_sbom(
            {}, object(), "1.2.3", frozenset(), [], object(), 1
        )
    )

    assert _classify_failure(error, "unknown") == "evidence-supply-payload"


@pytest.mark.parametrize(
    ("family", "expected"),
    [
        ("fields", "evidence-supply-fields"),
        ("hash", "evidence-supply-hash"),
        ("license", "evidence-supply-license"),
        ("purl", "evidence-supply-purl"),
        ("reference", "evidence-supply-reference"),
        ("dependencies", "evidence-supply-dependencies"),
    ],
)
def test_neutral_supply_failures_use_same_code_from_both_real_normalizers(
    tmp_path: Path, family: str, expected: str
) -> None:
    payload_error = _payload_normalizer_error(tmp_path / "payload-case", family)
    python_error = _python_normalizer_error(tmp_path / "python-case", family)

    assert _classify_failure(payload_error, "unknown") == expected
    assert _classify_failure(python_error, "unknown") == expected


@pytest.mark.parametrize(
    ("family", "message", "expected"),
    [
        (
            "component-fields-type",
            "component type is invalid",
            "evidence-supply-payload-component-fields",
        ),
        (
            "component-fields-name",
            "component name is invalid",
            "evidence-supply-payload-component-fields",
        ),
        (
            "component-conflicting-file-hash",
            "component has conflicting hashes",
            "evidence-supply-payload-component-file-hash",
        ),
        (
            "component-file-hash",
            "payload SBOM file hash does not match snapshot",
            "evidence-supply-payload-component-file-hash",
        ),
        (
            "component-version",
            "Python payload component version is missing",
            "evidence-supply-payload-component-version",
        ),
        (
            "component-package-name",
            "package name is invalid",
            "evidence-supply-payload-component-package-identity",
        ),
        (
            "component-package-conflict",
            "payload component purl conflicts with package identity",
            "evidence-supply-payload-component-package-identity",
        ),
        (
            "component-purl-type",
            "payload component purl type is unsupported",
            "evidence-supply-payload-component-purl-type",
        ),
        (
            "component-runtime-identity",
            "embedded Python runtime component identity is invalid",
            "evidence-supply-payload-component-runtime-identity",
        ),
    ],
)
def test_payload_component_messages_use_closed_codes_from_real_normalizer(
    tmp_path: Path, family: str, message: str, expected: str
) -> None:
    error = _payload_normalizer_error(tmp_path, family)

    assert type(error) is ci_qualify._sbom_normalize.ArtifactEvidenceError
    assert BaseException.args.__get__(error) == (message,)
    assert _classify_failure(error, "unknown") == expected


def test_property_failure_uses_neutral_code_from_both_real_normalizers(
    tmp_path: Path,
) -> None:
    payload_error = _payload_normalizer_error(tmp_path / "payload-case", "properties")
    python_error = _python_normalizer_error(tmp_path / "python-case", "properties")

    assert _classify_failure(payload_error, "unknown") == "evidence-supply-properties"
    assert _classify_failure(python_error, "unknown") == "evidence-supply-properties"


@pytest.mark.parametrize(
    "supplied",
    [
        ci_qualify._sbom_normalize.ArtifactEvidenceError(),
        ci_qualify._sbom_normalize.ArtifactEvidenceError(
            "component type is invalid", "private-extra"
        ),
        ci_qualify._sbom_normalize.ArtifactEvidenceError(7),
        ci_qualify._sbom_normalize.ArtifactEvidenceError("x" * 129),
        ci_qualify._sbom_normalize.ArtifactEvidenceError("private-unknown-message"),
    ],
    ids=("no-arguments", "multiple-arguments", "non-string", "overlong", "unknown"),
)
def test_payload_component_descriptor_rejects_unapproved_argument_shapes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    supplied: BaseException,
) -> None:
    error = _payload_component_stack_error(tmp_path, monkeypatch, supplied)

    assert _classify_failure(error, "unknown") == "evidence-supply-payload-component"


@pytest.mark.parametrize(
    "message",
    [
        _LengthPoisonString("component type is invalid"),
        _EqualityPoisonString("component type is invalid"),
    ],
    ids=("length", "equality"),
)
def test_payload_component_descriptor_rejects_string_subclasses_without_hooks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    message: str,
) -> None:
    supplied = ci_qualify._sbom_normalize.ArtifactEvidenceError(message)
    error = _payload_component_stack_error(tmp_path, monkeypatch, supplied)

    assert _classify_failure(error, "unknown") == "evidence-supply-payload-component"


def test_payload_component_descriptor_requires_exact_error_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _DerivedArtifactError(ci_qualify._sbom_normalize.ArtifactEvidenceError):
        @property
        def args(self) -> object:
            raise AssertionError("ordinary exception arguments are forbidden")

        def __str__(self) -> str:
            raise AssertionError("exception text must not be formatted")

        def __repr__(self) -> str:
            raise AssertionError("exception details must not be formatted")

    error = _payload_component_stack_error(
        tmp_path,
        monkeypatch,
        _DerivedArtifactError("component type is invalid"),
    )

    assert _classify_failure(error, "unknown") == "evidence-supply-payload-component"


def test_payload_component_descriptor_uses_owning_explicit_cause(
    tmp_path: Path,
) -> None:
    cause = _payload_normalizer_error(tmp_path, "component-file-hash")
    outer = _PoisonError("private-component-wrapper")
    _set_explicit_cause(outer, cause)

    assert _classify_failure(outer, "unknown") == (
        "evidence-supply-payload-component-file-hash"
    )


def test_later_specific_cause_overrides_payload_component_descriptor(
    tmp_path: Path,
) -> None:
    broad = _payload_normalizer_error(tmp_path, "component-file-hash")
    specific = _captured_link_exception()
    _set_explicit_cause(broad, specific)

    assert _classify_failure(broad, "unknown") == "artifact-link-validation"


@pytest.mark.parametrize(
    ("outer_family", "cause_family", "expected"),
    [
        (
            "component-fields-type",
            "component-file-hash",
            "evidence-supply-payload-component-file-hash",
        ),
        (
            "component-file-hash",
            "component-purl-type",
            "evidence-supply-payload-component-purl-type",
        ),
    ],
)
def test_later_payload_component_cause_owns_its_distinct_known_code(
    tmp_path: Path,
    outer_family: str,
    cause_family: str,
    expected: str,
) -> None:
    outer = _payload_normalizer_error(tmp_path / "outer", outer_family)
    cause = _payload_normalizer_error(tmp_path / "cause", cause_family)
    _set_explicit_cause(outer, cause)

    assert _classify_failure(outer, "unknown") == expected


def test_later_unknown_payload_component_cause_restores_broad_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outer = _payload_normalizer_error(tmp_path / "outer", "component-file-hash")
    cause = _payload_component_stack_error(
        tmp_path / "cause",
        monkeypatch,
        ci_qualify._sbom_normalize.ArtifactEvidenceError(
            "private-unknown-component-message"
        ),
    )
    _set_explicit_cause(outer, cause)

    assert _classify_failure(outer, "unknown") == "evidence-supply-payload-component"


@pytest.mark.parametrize(
    ("family", "expected"),
    [
        (
            "payload-component",
            "evidence-supply-payload-component-file-hash",
        ),
        ("payload-path", "evidence-supply-payload-path"),
        ("payload-file", "evidence-supply-payload-file"),
        ("payload-purl", "evidence-supply-payload-purl"),
        (
            "payload-runtime-properties",
            "evidence-supply-payload-runtime-properties",
        ),
        ("payload-runtime-license", "evidence-supply-payload-runtime-license"),
        ("payload-vendor", "evidence-supply-payload-vendor"),
    ],
)
def test_payload_specific_failures_execute_real_payload_normalizer(
    tmp_path: Path, family: str, expected: str
) -> None:
    error = _payload_normalizer_error(tmp_path, family)

    assert _classify_failure(error, "unknown") == expected


def test_nested_reference_hash_failure_uses_deepest_neutral_code(
    tmp_path: Path,
) -> None:
    error = _payload_normalizer_error(tmp_path, "nested-reference-hash")

    assert _classify_failure(error, "unknown") == "evidence-supply-hash"


def test_runtime_purl_uses_neutral_code_only_for_malformed_purl(
    tmp_path: Path,
) -> None:
    malformed = _payload_normalizer_error(
        tmp_path / "malformed", "malformed-runtime-purl"
    )
    conflicting = _payload_normalizer_error(tmp_path / "conflicting", "payload-purl")

    assert _classify_failure(malformed, "unknown") == "evidence-supply-purl"
    assert _classify_failure(conflicting, "unknown") == "evidence-supply-payload-purl"


def test_windows_payload_resolver_failure_remains_deepest_link_code(
    tmp_path: Path,
) -> None:
    error = _payload_normalizer_error(tmp_path, "latent-windows-path")

    assert _classify_failure(error, "unknown") == "artifact-link-validation"


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        (
            lambda: ci_qualify._artifact_filesystem.snapshot_payload(
                object(), object()
            ),
            "evidence-snapshot",
        ),
        (
            lambda: ci_qualify._syft_tool.acquire_syft(
                Path("unused"), object(), Path("unused")
            ),
            "evidence-tool-acquisition",
        ),
        (
            lambda: ci_qualify._syft_tool._download(
                "http://invalid.example", Path("unused"), "0" * 64, object()
            ),
            "evidence-tool-download",
        ),
        (
            lambda: ci_qualify._syft_tool.run_syft_scan(
                Path("unused"),
                object(),
                object(),
                Path("unused"),
                "1.0.0",
                Path("unused"),
                Path("unused"),
            ),
            "evidence-tool-scan",
        ),
        (
            lambda: ci_qualify._sbom_normalize.generate_supply_chain_evidence(
                object(), object(), Path("unused"), Path("unused"), 1
            ),
            "evidence-supply-normalization",
        ),
        (
            lambda: ci_qualify._evidence_sanitize.write_public_json(
                Path("relative"), {}, forbidden_roots=(), max_bytes=1
            ),
            "evidence-write",
        ),
        (
            lambda: ci_qualify._native_inspect.inspect_native_payload(
                object(), object(), object(), object()
            ),
            "evidence-native-inspection",
        ),
        (
            lambda: ci_qualify._artifact_archive.create_archive_from_snapshot(
                object(), object(), object(), Path("unused")
            ),
            "archive",
        ),
        (
            lambda: ci_qualify._evidence_policy.enforce_policy_evidence(
                object(), object(), object()
            ),
            "evidence-policy",
        ),
    ],
)
def test_failure_classifier_uses_exact_project_code_objects(
    call: Callable[[], object], expected: str
) -> None:
    error = _captured_exception(call)

    assert _classify_failure(error, "unknown") == expected


def test_failure_classifier_uses_deepest_download_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = ci_qualify.load_target_spec(
        ci_qualify._TARGET_POLICY, "linux-x64-ubuntu-22.04"
    )
    cache = tmp_path / "cache"
    cache.mkdir(mode=0o700)

    class _FailingOpener:
        def open(self, *_args: object, **_kwargs: object) -> object:
            raise OSError("local-only download canary")

    monkeypatch.setattr(
        ci_qualify._syft_tool.urllib.request,
        "build_opener",
        lambda *_args: _FailingOpener(),
    )
    error = _captured_exception(
        lambda: ci_qualify._syft_tool.acquire_syft(
            ci_qualify._sbom_normalize._SYFT_POLICY, target, cache
        )
    )

    assert _classify_failure(error, "unknown") == "evidence-tool-download"


@pytest.mark.parametrize("phase", ["pre-archive", "post-archive"])
def test_failure_classifier_maps_policy_report_writes_at_deepest_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    rejected_name = "manifest.json" if phase == "pre-archive" else "sizes.json"
    (evidence / rejected_name).write_text("occupied", encoding="utf-8")
    private = tmp_path / "private"
    private.mkdir()
    if phase == "pre-archive":
        monkeypatch.setattr(
            ci_qualify._evidence_policy,
            "validate_toc_policy",
            lambda *_args: None,
        )
        monkeypatch.setattr(
            ci_qualify._evidence_policy,
            "inspect_native_payload",
            lambda *_args: [],
        )
        monkeypatch.setattr(
            ci_qualify._evidence_policy,
            "_manifest_payload",
            lambda *_args: {},
        )
        policy = SimpleNamespace(
            limits=SimpleNamespace(max_metadata_file_bytes=1024), native=object()
        )
        call = lambda: ci_qualify._evidence_policy.analyse_policy_evidence(
            SimpleNamespace(root=private),
            SimpleNamespace(
                target=object(),
                build_metadata_dir=private,
                wheel=private / "wheel.whl",
            ),
            policy,
            evidence,
        )
    else:
        manifest = evidence / "manifest.json"
        manifest.write_text('{"entries":[]}\n', encoding="utf-8")
        provenance = evidence / "dependency-provenance.json"
        provenance.write_text("{}\n", encoding="utf-8")
        archive_path = tmp_path / "artifact.tar.gz"
        archive_path.write_bytes(b"archive")
        pre = SimpleNamespace(manifest=manifest, private_roots=(private,))
        supply = SimpleNamespace(dependency_provenance=provenance)
        archive = SimpleNamespace(
            path=archive_path,
            output_root=tmp_path,
            archive_profile={},
            source_date_epoch=1,
            sha256="0" * 64,
        )
        target = ci_qualify.load_target_spec(
            ci_qualify._TARGET_POLICY, "linux-x64-ubuntu-22.04"
        )
        policy = SimpleNamespace(
            limits=SimpleNamespace(max_metadata_file_bytes=1024),
            archive_compression_level=9,
        )
        monkeypatch.setattr(
            ci_qualify._evidence_policy,
            "_valid_archive_profile",
            lambda *_args: True,
        )
        monkeypatch.setattr(
            ci_qualify._evidence_policy,
            "_validate_supply_chain_evidence",
            lambda *_args: None,
        )

        def read_report(path: Path, _maximum: int) -> object:
            if path == manifest:
                return {"entries": []}
            assert path == provenance
            return {
                "build": {"source_commit": "a" * 40, "wheel_sha256": "0" * 64},
                "toolchain": {},
            }

        monkeypatch.setattr(ci_qualify._evidence_policy, "_read_json", read_report)
        call = lambda: ci_qualify._evidence_policy.report_archive_policy(
            pre, supply, archive, target, policy, evidence
        )

    error = _captured_exception(call)

    assert _classify_failure(error, "unknown") == "evidence-write"


def test_policy_write_failure_status_never_exposes_private_details(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    calls: list[str] = []
    _install_successful_fakes(monkeypatch, request, calls)

    @contextmanager
    def reject_write(_artifact: object, evidence_dir: Path) -> object:
        (evidence_dir / "manifest.json").write_text("occupied", encoding="utf-8")
        ci_qualify._evidence_policy._write_public_report(
            evidence_dir / "manifest.json",
            {"note": "private-write-canary"},
            (request.wheel.parent,),
            ci_qualify.load_evidence_policy(ci_qualify._EVIDENCE_POLICY),
        )
        raise AssertionError("policy writer unexpectedly returned")
        yield None

    monkeypatch.setattr(
        ci_qualify._inspect_facade, "_collected_artifact_for_smoke", reject_write
    )

    result = qualify(request)
    status = result.public_status.read_text(encoding="utf-8")

    assert json.loads(status)["failure_code"] == "evidence-write"
    assert "private-write-canary" not in status
    assert str(request.qualification_root) not in status


def test_failure_classifier_distinguishes_version_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def reject_command(*_args: object, **_kwargs: object) -> bytes:
        raise _PoisonError("private-version-canary")

    monkeypatch.setattr(ci_qualify._syft_tool, "run_bounded_command", reject_command)
    config = tmp_path / "config"
    config.mkdir(mode=0o700)
    error = _captured_exception(
        lambda: ci_qualify._syft_tool._verify_syft_version(
            Path("unused"), object(), object(), config
        )
    )

    assert _classify_failure(error, "unknown") == "evidence-tool-version"


def test_failure_classifier_rejects_same_named_unrelated_function() -> None:
    def acquire_syft() -> None:
        raise _PoisonError("private-same-name-canary")

    error = _captured_exception(acquire_syft)

    assert _classify_failure(error, "unknown") == "unknown"


def test_failure_classifier_rejects_equal_but_distinct_code_object() -> None:
    original = ci_qualify._evidence_sanitize.write_public_json
    clone = FunctionType(
        original.__code__.replace(),
        original.__globals__,
        name=original.__name__,
        argdefs=original.__defaults__,
        closure=original.__closure__,
    )
    clone.__kwdefaults__ = original.__kwdefaults__
    assert clone.__code__ == original.__code__
    assert clone.__code__ is not original.__code__

    error = _captured_exception(
        lambda: clone(Path("relative"), {}, forbidden_roots=(), max_bytes=1)
    )

    assert _classify_failure(error, "unknown") == "unknown"


def test_failure_classifier_uses_base_slots_and_explicit_cause_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class _HostileException(Exception):
        @property
        def __traceback__(self) -> object:
            raise AssertionError("ordinary traceback access is forbidden")

        @property
        def __cause__(self) -> object:
            raise AssertionError("ordinary cause access is forbidden")

        def __eq__(self, _other: object) -> bool:
            raise AssertionError("exception equality is forbidden")

        def __hash__(self) -> int:
            raise AssertionError("exception hashing is forbidden")

        def __str__(self) -> str:
            raise AssertionError("exception formatting is forbidden")

        def __repr__(self) -> str:
            raise AssertionError("exception formatting is forbidden")

    def reject_command(*_args: object, **_kwargs: object) -> None:
        raise _HostileException()

    monkeypatch.setattr(ci_qualify._build, "_run", reject_command)
    cause = _captured_exception(
        lambda: ci_qualify._build._run_pyinstaller(
            Path("python"),
            tmp_path / "work",
            tmp_path / "dist",
            {},
            tmp_path,
            tmp_path / "profile.spec",
            30,
        )
    )
    outer = _HostileException()
    _set_explicit_cause(outer, cause)

    assert _classify_failure(outer, "build") == "build-pyinstaller"


def test_failure_classifier_uses_specific_later_cause() -> None:
    broad = _captured_exception(
        lambda: ci_qualify._artifact_filesystem.snapshot_payload(object(), object())
    )
    specific = _captured_link_exception()
    _set_explicit_cause(broad, specific)

    assert _classify_failure(broad, "unknown") == "artifact-link-validation"


def test_failure_classifier_finds_supply_substep_in_explicit_cause(
    tmp_path: Path,
) -> None:
    cause = _captured_exception(
        lambda: ci_qualify._sbom_normalize._load_environment(
            tmp_path / "missing-environment.json",
            SimpleNamespace(max_metadata_file_bytes=1024),
        )
    )
    outer = _PoisonError("private-supply-wrapper")
    _set_explicit_cause(outer, cause)

    assert _classify_failure(outer, "unknown") == "evidence-supply-environment"


def test_failure_classifier_maps_neutral_public_sanitization(
    tmp_path: Path,
) -> None:
    error = _captured_exception(
        lambda: ci_qualify._evidence_sanitize.encode_public_json(
            {"private_path": str(tmp_path)},
            "diagnostic.json",
            forbidden_roots=(tmp_path,),
            max_bytes=1024,
        )
    )

    assert _classify_failure(error, "unknown") == "evidence-public-sanitize"


def test_failure_classifier_ignores_implicit_context() -> None:
    context = _captured_link_exception()
    error = _PoisonError("private-context-canary")
    BaseException.__context__.__set__(error, context)

    assert BaseException.__context__.__get__(error) is context
    assert BaseException.__cause__.__get__(error) is None
    assert _classify_failure(error, "build") == "build"


@pytest.mark.skipif(
    not hasattr(__import__("builtins"), "ExceptionGroup"),
    reason="ExceptionGroup is unavailable before Python 3.11",
)
def test_failure_classifier_does_not_traverse_exception_groups() -> None:
    nested = _captured_link_exception()
    group_type = __import__("builtins").ExceptionGroup
    group = group_type("private-group-canary", [nested])

    assert _classify_failure(group, "build") == "build"


def test_failure_classifier_rejects_explicit_cause_cycle() -> None:
    first = _PoisonError("private-cycle-one")
    second = _PoisonError("private-cycle-two")
    _set_explicit_cause(first, second)
    _set_explicit_cause(second, first)

    assert _classify_failure(first, "build") == "unknown"


def test_failure_classifier_rejects_malformed_root() -> None:
    assert _classify_failure(None, "build") == "unknown"  # type: ignore[arg-type]


def test_failure_classifier_accepts_eight_nodes_and_rejects_ninth() -> None:
    mapped = _captured_link_exception()
    root = mapped
    for _index in range(7):
        wrapper = _PoisonError("private-bounded-cause")
        _set_explicit_cause(wrapper, root)
        root = wrapper
    assert _classify_failure(root, "build") == "artifact-link-validation"

    ninth = _PoisonError("private-overflow-cause")
    _set_explicit_cause(ninth, root)
    assert _classify_failure(ninth, "build") == "unknown"


def test_failure_classifier_applies_aggregate_frame_limit_across_causes() -> None:
    def recurse(remaining: int) -> None:
        if remaining:
            recurse(remaining - 1)
        else:
            raise _PoisonError("private-aggregate-overflow")

    first = _captured_exception(lambda: recurse(31))
    second = _captured_exception(lambda: recurse(31))
    _set_explicit_cause(first, second)

    assert _classify_failure(first, "build") == "unknown"


def test_failure_classifier_overflow_is_unknown() -> None:
    def recurse(remaining: int) -> None:
        if remaining:
            recurse(remaining - 1)
        else:
            raise _PoisonError("private-overflow-canary")

    error = _captured_exception(lambda: recurse(65))

    assert _classify_failure(error, "build") == "unknown"


@pytest.mark.parametrize(
    ("stage", "target", "expected"),
    [
        ("build", "macos-x64", "build"),
        ("archive", "macos-x64", "archive"),
        ("extract", "macos-x64", "extract"),
        ("native-smoke", "macos-x64", "native-smoke"),
        ("container-smoke", "linux-x64-ubuntu-22.04", "container-smoke"),
    ],
)
def test_qualify_uses_closed_outer_stage_fallbacks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    target: str,
    expected: str,
) -> None:
    request = _request(tmp_path, target=target)
    calls: list[str] = []
    _install_successful_fakes(monkeypatch, request, calls)

    def reject(*_args: object, **_kwargs: object) -> object:
        raise _PoisonError("private-stage-canary")

    if stage == "archive":

        @contextmanager
        def reject_collection(*_args: object, **_kwargs: object) -> object:
            raise _PoisonError("private-stage-canary")
            yield None

        monkeypatch.setattr(
            ci_qualify._inspect_facade,
            "_collected_artifact_for_smoke",
            reject_collection,
        )
    else:
        dependency = {
            "build": "build_standalone",
            "extract": "extract_archive_for_smoke",
            "native-smoke": "run_smoke",
            "container-smoke": "run_container_smoke",
        }[stage]
        monkeypatch.setattr(ci_qualify, dependency, reject)

    result = qualify(request)
    document = json.loads(result.public_status.read_text(encoding="utf-8"))

    assert result.status == "failed"
    assert document["failure_code"] == expected
    assert "enforce" not in calls
    assert "private-stage-canary" not in result.public_status.read_text(
        encoding="utf-8"
    )


def test_cleanup_failure_overrides_operation_and_public_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    calls: list[str] = []
    _install_successful_fakes(monkeypatch, request, calls)
    original = ci_qualify.run_smoke

    def leave_unknown(*args: object, **kwargs: object) -> object:
        result = original(*args, **kwargs)
        (request.public_evidence_dir / "unknown.json").write_text(
            '{"schema_version":1}\n', encoding="utf-8"
        )
        (request.qualification_root / "unowned").write_text("keep", encoding="utf-8")
        return result

    monkeypatch.setattr(ci_qualify, "run_smoke", leave_unknown)

    result = qualify(request)
    document = json.loads(result.public_status.read_text(encoding="utf-8"))

    assert result.status == "failed"
    assert document["failure_code"] == "cleanup"


def test_poison_exception_details_never_reach_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    calls: list[str] = []
    _install_successful_fakes(monkeypatch, request, calls)

    def reject(_request: object) -> object:
        raise _PoisonError(
            "token=private-value",
            str(request.qualification_root),
            "https://private.invalid/path",
        )

    monkeypatch.setattr(ci_qualify, "build_standalone", reject)

    result = qualify(request)
    status = result.public_status.read_text(encoding="utf-8")

    assert json.loads(status)["failure_code"] == "build"
    assert "private-value" not in status
    assert str(request.qualification_root) not in status
    assert "private.invalid" not in status


def test_explicit_build_cause_produces_only_refined_finite_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    calls: list[str] = []
    _install_successful_fakes(monkeypatch, request, calls)

    def reject_command(*_args: object, **_kwargs: object) -> None:
        raise _PoisonError(
            "token=private-build-value",
            str(request.qualification_root),
            "https://private.invalid/build",
        )

    def reject_build(_request: object) -> object:
        try:
            ci_qualify._build._run_pyinstaller(
                Path("python"),
                tmp_path / "work",
                tmp_path / "dist",
                {},
                tmp_path,
                tmp_path / "profile.spec",
                30,
            )
        except _PoisonError as error:
            raise BuildValidationError("generic build failure") from error
        raise AssertionError("build command unexpectedly returned")

    monkeypatch.setattr(ci_qualify._build, "_run", reject_command)
    monkeypatch.setattr(ci_qualify, "build_standalone", reject_build)

    result = qualify(request)
    status = result.public_status.read_text(encoding="utf-8")

    assert json.loads(status)["failure_code"] == "build-pyinstaller"
    assert "private-build-value" not in status
    assert str(request.qualification_root) not in status
    assert "private.invalid" not in status


def _smoke_stack_error(supplied: BaseException) -> BaseException:
    def fail_immediately(*_args: object, **_kwargs: object) -> None:
        raise supplied

    runner = FunctionType(
        smoke_artifact.run_smoke.__code__,
        {**smoke_artifact.run_smoke.__globals__, "_validate_request": fail_immediately},
        name=smoke_artifact.run_smoke.__name__,
    )
    return _captured_exception(lambda: runner(None, None))


def _require_exit_stack_error(supplied: BaseException) -> BaseException:
    def fail_immediately(*_args: object, **_kwargs: object) -> None:
        raise supplied

    exiter = FunctionType(
        smoke_artifact._require_exit.__code__,
        {**smoke_artifact._require_exit.__globals__, "_fail": fail_immediately},
        name=smoke_artifact._require_exit.__name__,
    )
    return _captured_exception(
        lambda: exiter(smoke_artifact._ProcessResult(1, b"", b"", 0.0), 0, "test")
    )


def test_native_smoke_closed_taxonomy_and_mappings_are_unique() -> None:
    literals = get_args(ci_qualify._FailureCode)
    assert len(literals) == len(set(literals))
    assert set(ci_qualify._FAILURE_CODES) == set(literals)
    assert len(ci_qualify._FAILURE_CODES) == len(literals)

    output_messages = [msg for msg, _ in ci_qualify._NATIVE_SMOKE_OUTPUT_FAILURE_CODES]
    assert len(output_messages) == len(set(output_messages))
    for _, code in ci_qualify._NATIVE_SMOKE_OUTPUT_FAILURE_CODES:
        assert code in ci_qualify._FAILURE_CODES

    exit_messages = [msg for msg, _ in ci_qualify._NATIVE_SMOKE_EXIT_FAILURE_CODES]
    assert len(exit_messages) == len(set(exit_messages))
    for _, code in ci_qualify._NATIVE_SMOKE_EXIT_FAILURE_CODES:
        assert code in ci_qualify._FAILURE_CODES

    for code in ci_qualify._NATIVE_SMOKE_COMMAND_FAILURE_CODES:
        assert code in ci_qualify._FAILURE_CODES

    semantic_codes = [
        code for code, _ in ci_qualify._NATIVE_SMOKE_SEMANTIC_FAILURE_CODES
    ]
    assert len(semantic_codes) == len(set(semantic_codes))
    existing_codes = {code for code, _ in ci_qualify._SEMANTIC_FAILURE_CODES}
    assert not (set(semantic_codes) & existing_codes)
    for code, failure_code in ci_qualify._NATIVE_SMOKE_SEMANTIC_FAILURE_CODES:
        assert isinstance(code, CodeType)
        assert failure_code in ci_qualify._FAILURE_CODES


def test_native_smoke_closed_identity_ledger_and_phase_gate() -> None:
    ledger = (
        smoke_artifact.load_smoke_policy,
        smoke_artifact._validate_request,
        smoke_artifact.isolated_child_environment,
        smoke_artifact.run_bounded_process,
        smoke_artifact._require_exit,
        smoke_artifact._decode,
        smoke_artifact.run_smoke,
        smoke_artifact._validate_selftest_success,
        smoke_artifact._validate_selftest_failure,
        smoke_artifact._prepare_selftest_caller,
        smoke_artifact._verify_selftest_caller,
        smoke_artifact._close_selftest_caller,
        smoke_artifact._load_claude_mcp_config,
        smoke_artifact._mcp_environment,
        smoke_mcp.run_mcp_smoke,
        smoke_artifact._write_transcript,
        smoke_artifact.assert_smoke,
    )
    mapped_codes = tuple(
        code for code, _ in ci_qualify._NATIVE_SMOKE_SEMANTIC_FAILURE_CODES
    )
    expected_codes = tuple(func.__code__ for func in ledger)
    assert len(mapped_codes) == 17
    assert len(expected_codes) == 17
    assert set(mapped_codes) == set(expected_codes)

    # Prove that every single helper in the ledger is subject to the phase gate
    for func in ledger:
        argcount = func.__code__.co_argcount + func.__code__.co_kwonlyargcount
        dummy_args = (None,) * func.__code__.co_argcount
        dummy_kwargs = {
            name: None
            for name in func.__code__.co_varnames[func.__code__.co_argcount : argcount]
        }
        f = FunctionType(func.__code__, {"__builtins__": __builtins__})
        error = _captured_exception(
            lambda f=f, a=dummy_args, k=dummy_kwargs: f(*a, **k)
        )
        assert _classify_failure(error, "container-smoke") == "container-smoke"
        res_native = _classify_failure(error, "native-smoke")
        assert res_native.startswith("native-smoke-")


def test_native_smoke_real_stack_cross_phase_regressions(tmp_path: Path) -> None:
    # 1. Policy boundary
    policy_error = _captured_exception(
        lambda: smoke_artifact.load_smoke_policy(tmp_path / "missing-policy.json")
    )
    assert _classify_failure(policy_error, "native-smoke") == "native-smoke-policy"
    assert _classify_failure(policy_error, "container-smoke") == "container-smoke"

    # 2. Exact selftest exit boundary
    exit_error = _captured_exception(
        lambda: smoke_artifact._require_exit(
            smoke_artifact._ProcessResult(1, b"", b"", 0.1), 0, "artifact selftest"
        )
    )
    assert _classify_failure(exit_error, "native-smoke") == "native-smoke-selftest"
    assert _classify_failure(exit_error, "container-smoke") == "container-smoke"

    # 3. Process / Decode boundary
    process_error = _captured_exception(
        lambda: smoke_artifact.run_bounded_process(
            [],
            environment={},
            working_directory=tmp_path,
            timeout_seconds=1,
            output_limit=10,
            argv_max_count=1,
        )
    )
    assert _classify_failure(process_error, "native-smoke") == "native-smoke-process"
    assert _classify_failure(process_error, "container-smoke") == "container-smoke"

    decode_error = _captured_exception(lambda: smoke_artifact._decode(b"\xff", "test"))
    assert _classify_failure(decode_error, "native-smoke") == "native-smoke-decode"
    assert _classify_failure(decode_error, "container-smoke") == "container-smoke"

    # 4. Caller isolation boundary
    caller_error = _captured_exception(
        lambda: smoke_artifact._prepare_selftest_caller(
            Path("relative"), Path("relative"), Path("relative")
        )
    )
    assert (
        _classify_failure(caller_error, "native-smoke")
        == "native-smoke-caller-isolation"
    )
    assert _classify_failure(caller_error, "container-smoke") == "container-smoke"

    # 5. MCP boundaries
    mcp_config_error = _captured_exception(
        lambda: smoke_artifact._load_claude_mcp_config(
            tmp_path / "missing-claude.json", Path("/bin/sh")
        )
    )
    assert (
        _classify_failure(mcp_config_error, "native-smoke")
        == "native-smoke-mcp-install"
    )
    assert _classify_failure(mcp_config_error, "container-smoke") == "container-smoke"

    mcp_smoke_error = _captured_exception(
        lambda: smoke_mcp.run_mcp_smoke(
            command=Path("relative"),
            args=[],
            environment={},
            working_directory=tmp_path,
            timeouts=smoke_mcp.MCPTimeouts(1.0, 1.0, 1.0, 1024, 1024),
        )
    )
    assert _classify_failure(mcp_smoke_error, "native-smoke") == "native-smoke-mcp"
    assert _classify_failure(mcp_smoke_error, "container-smoke") == "container-smoke"


def test_native_smoke_native_only_real_stacks(tmp_path: Path) -> None:
    policy = smoke_artifact.load_smoke_policy(ci_qualify._SMOKE_POLICY)

    request_error = _captured_exception(
        lambda: smoke_artifact._validate_request(object())  # type: ignore[arg-type]
    )
    assert _classify_failure(request_error, "native-smoke") == "native-smoke-request"

    env_error = _captured_exception(
        lambda: smoke_artifact.isolated_child_environment(Path("relative-home"))
    )
    assert _classify_failure(env_error, "native-smoke") == "native-smoke-environment"

    exit_error = _captured_exception(
        lambda: smoke_artifact._require_exit(
            smoke_artifact._ProcessResult(1, b"", b"", 0.1), 0, "arbitrary-exit"
        )
    )
    assert _classify_failure(exit_error, "native-smoke") == "native-smoke-exit"

    selftest_success_error = _captured_exception(
        lambda: smoke_artifact._validate_selftest_success(
            smoke_artifact._ProcessResult(0, b"{}", b"stderr", 0.1), policy
        )
    )
    assert (
        _classify_failure(selftest_success_error, "native-smoke")
        == "native-smoke-selftest"
    )

    selftest_failure_error = _captured_exception(
        lambda: smoke_artifact._validate_selftest_failure(
            smoke_artifact._ProcessResult(1, b"{}", b"stderr", 0.1), policy, ()
        )
    )
    assert (
        _classify_failure(selftest_failure_error, "native-smoke")
        == "native-smoke-selftest"
    )

    proof = smoke_artifact._CallerIsolationProof(
        tmp_path, (), tmp_path / "credential", None
    )
    verify_caller_error = _captured_exception(
        lambda: smoke_artifact._verify_selftest_caller(
            proof,
            smoke_artifact._ProcessResult(0, b"caller-isolation-credential", b"", 0.1),
        )
    )
    assert (
        _classify_failure(verify_caller_error, "native-smoke")
        == "native-smoke-caller-isolation"
    )

    mcp_env_error = _captured_exception(
        lambda: smoke_artifact._mcp_environment({"env": "not-a-dict"}, {})
    )
    assert (
        _classify_failure(mcp_env_error, "native-smoke") == "native-smoke-mcp-install"
    )

    transcript_path = tmp_path / "smoke-transcript.json"
    transcript_path.write_text("{}", encoding="utf-8")
    transcript_error = _captured_exception(
        lambda: smoke_artifact._write_transcript(tmp_path, {}, policy)
    )
    assert (
        _classify_failure(transcript_error, "native-smoke") == "native-smoke-transcript"
    )

    completeness_error = _captured_exception(
        lambda: smoke_artifact.assert_smoke(
            smoke_artifact.SmokeResult(Path("nonexistent"), {})
        )
    )
    assert (
        _classify_failure(completeness_error, "native-smoke")
        == "native-smoke-completeness"
    )


def _make_smoke_fixture_executable(root: Path, scenario: str) -> Path:
    exe = root / "servonaut"
    script = f"""#!{sys.executable}
import json, os, pathlib, sys
args = sys.argv[1:]
scenario = {scenario!r}

if args == ["--version"]:
    if scenario == "version-exit":
        sys.exit(1)
    if scenario == "version-mismatch":
        sys.stdout.write("servonaut wrong\\n")
        sys.exit(0)
    if scenario == "version-stderr":
        sys.stderr.write("version error\\n")
        sys.stdout.write("servonaut 9.8.7\\n")
        sys.exit(0)
    sys.stdout.write("servonaut 9.8.7\\n")
    sys.exit(0)

elif args == ["--help"]:
    if scenario == "help-exit":
        sys.exit(1)
    if scenario == "help-missing-option":
        sys.stdout.write("usage: servonaut --update\\n")
        sys.exit(0)
    if scenario == "help-exposes-selftest":
        sys.stdout.write("usage: servonaut --version --update --mcp --mcp-install --list-backups --_artifact-selftest\\n")
        sys.exit(0)
    if scenario == "help-stderr":
        sys.stderr.write("help error\\n")
        sys.stdout.write("usage: servonaut --version --update --mcp --mcp-install --list-backups\\n")
        sys.exit(0)
    sys.stdout.write("usage: servonaut --version --update --mcp --mcp-install --list-backups\\n")
    sys.exit(0)

elif args == ["--update"]:
    if scenario == "update-exit":
        sys.exit(1)
    if scenario == "update-lacks-guidance":
        sys.stdout.write("Current version: 9.8.7\\nNo guidance\\n")
        sys.exit(0)
    if scenario == "update-stderr":
        sys.stderr.write("update error\\n")
        sys.stdout.write("Current version: 9.8.7\\nAutomatic updates are not configured for this packaged Servonaut build.\\n")
        sys.exit(0)
    sys.stdout.write("Current version: 9.8.7\\nAutomatic updates are not configured for this packaged Servonaut build.\\n")
    sys.exit(0)

elif args == ["--list-backups"]:
    if scenario == "backups-exit":
        sys.exit(1)
    if scenario == "backups-not-empty":
        sys.stdout.write("some backup\\n")
        sys.exit(0)
    if scenario == "backups-stderr":
        sys.stderr.write("backup error\\n")
        sys.stdout.write("No local backups yet.\\n")
        sys.exit(0)
    sys.stdout.write("No local backups yet.\\n")
    sys.exit(0)

elif args == ["--artifact-smoke-invalid-option"]:
    if scenario == "bad-argument-exit":
        sys.stderr.write("unrecognized arguments: --artifact-smoke-invalid-option\\n")
        sys.exit(1)
    if scenario == "bad-argument-no-diag":
        sys.stderr.write("some other error\\n")
        sys.exit(2)
    sys.stderr.write("unrecognized arguments: --artifact-smoke-invalid-option\\n")
    sys.exit(2)

elif args == ["--mcp-install", "claude"]:
    if scenario == "mcp-install-exit":
        sys.exit(1)
    home = pathlib.Path.home()
    if scenario == "mcp-install-stderr":
        sys.stderr.write("mcp install error\\n")
    if scenario == "mcp-install-outside":
        (home / "outside.txt").write_text("leak")
    names = ["SSH_AUTH_SOCK", "BW_SESSION", "BWS_ACCESS_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "SERVONAUT_API_URL", "SERVONAUT_MCP_URL"]
    entry = {{"type":"stdio","command":str(pathlib.Path(sys.argv[0]).resolve()),"args":["--mcp"],"env":{{name:"${{" + name + ":-}}" for name in names}}}}
    (home / ".claude.json").write_text(json.dumps({{"mcpServers":{{"servonaut":entry}}}}))
    sys.exit(0)

elif args == ["--_artifact-selftest"]:
    request = json.loads(sys.stdin.read())
    token = os.environ.get("SERVONAUT_ARTIFACT_SELFTEST_TOKEN")
    if request.get("token") != token:
        if scenario == "invalid-selftest-exit":
            print(json.dumps({{"schema_version":1,"ok":False,"error":"authentication-failed"}}, separators=(",", ":")))
            sys.exit(0)
        print(json.dumps({{"schema_version":1,"ok":False,"error":"authentication-failed"}}, separators=(",", ":")))
        sys.exit(1)
    if scenario == "selftest-exit":
        sys.exit(1)
    if scenario == "selftest-left-home":
        tmp_dir = pathlib.Path.home() / "tmp"
        (tmp_dir / "servonaut-artifact-selftest-leaked").write_text("leak")
    print(json.dumps({{"schema_version":1,"ok":True,"check":"tui","runtime":{{"kind":"frozen-cli","marker":True}},"tui":{{"main":True,"sidebar":True,"adjacent":True,"exited":True}},"fixtures":{{"config":True,"cache":True}},"diagnostics":{{"metadata":True,"sdk":True,"crypto":True,"ca":True,"keyring":True}}}}, separators=(",", ":")))
    sys.exit(0)
"""
    exe.write_text(script, encoding="utf-8")
    exe.chmod(0o755)
    (root / "servonaut-runtime.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "distribution": "frozen-cli",
                "product_version": "9.8.7",
                "build_revision": "test",
                "console_helper": "servonaut",
                "desktop_child": None,
            }
        ),
        encoding="utf-8",
    )
    return exe


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ("version-mismatch", "native-smoke-version"),
        ("version-stderr", "native-smoke-version"),
        ("help-missing-option", "native-smoke-help"),
        ("help-exposes-selftest", "native-smoke-help"),
        ("help-stderr", "native-smoke-help"),
        ("update-lacks-guidance", "native-smoke-update"),
        ("update-stderr", "native-smoke-update"),
        ("backups-not-empty", "native-smoke-backups"),
        ("backups-stderr", "native-smoke-backups"),
        ("bad-argument-no-diag", "native-smoke-bad-argument"),
        ("mcp-install-stderr", "native-smoke-mcp-install"),
        ("mcp-install-outside", "native-smoke-mcp-install"),
        ("selftest-exceeds-policy", "native-smoke-selftest"),
        ("selftest-left-home", "native-smoke-cleanup"),
        ("version-exit", "native-smoke-version"),
        ("help-exit", "native-smoke-help"),
        ("update-exit", "native-smoke-update"),
        ("backups-exit", "native-smoke-backups"),
        ("bad-argument-exit", "native-smoke-bad-argument"),
        ("mcp-install-exit", "native-smoke-mcp-install"),
        ("selftest-exit", "native-smoke-selftest"),
        ("invalid-selftest-exit", "native-smoke-selftest"),
    ],
)
def test_native_smoke_generated_fixture_descriptors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scenario: str, expected: str
) -> None:
    policy = smoke_artifact.load_smoke_policy(ci_qualify._SMOKE_POLICY)
    payload = tmp_path / "extracted payload"
    payload.mkdir()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    exe = _make_smoke_fixture_executable(payload, scenario)
    req = smoke_artifact.SmokeRequest(payload, exe, "9.8.7", evidence)

    if scenario == "selftest-exceeds-policy":
        policy = replace(policy, selftest_stdin_max_bytes=10)
    elif scenario == "selftest-left-home":
        monkeypatch.setattr(
            smoke_artifact, "_verify_selftest_caller", lambda _p, _r: None
        )

    error = _captured_exception(lambda: smoke_artifact.run_smoke(req, policy))
    assert _classify_failure(error, "native-smoke") == expected


@pytest.mark.parametrize(
    "supplied",
    [
        smoke_artifact.ArtifactSmokeError(),
        smoke_artifact.ArtifactSmokeError("version wrote to stderr", "extra"),
        smoke_artifact.ArtifactSmokeError(42),
        smoke_artifact.ArtifactSmokeError("x" * 129),
        smoke_artifact.ArtifactSmokeError("unknown failure"),
        smoke_artifact.ArtifactSmokeError(
            _LengthPoisonString("version wrote to stderr")
        ),
        smoke_artifact.ArtifactSmokeError(
            _EqualityPoisonString("version wrote to stderr")
        ),
    ],
    ids=(
        "no-args",
        "multi-args",
        "non-string",
        "overlong",
        "unknown",
        "length-poison",
        "equality-poison",
    ),
)
def test_native_smoke_run_descriptor_rejects_unapproved_shapes(
    supplied: BaseException,
) -> None:
    assert _classify_failure(_smoke_stack_error(supplied), "native-smoke") == (
        "native-smoke-run"
    )


@pytest.mark.parametrize(
    "supplied",
    [
        smoke_artifact.ArtifactSmokeError(),
        smoke_artifact.ArtifactSmokeError(
            "version returned the wrong exit code", "extra"
        ),
        smoke_artifact.ArtifactSmokeError(42),
        smoke_artifact.ArtifactSmokeError("x" * 129),
        smoke_artifact.ArtifactSmokeError("unknown failure"),
        smoke_artifact.ArtifactSmokeError(
            _LengthPoisonString("version returned the wrong exit code")
        ),
        smoke_artifact.ArtifactSmokeError(
            _EqualityPoisonString("version returned the wrong exit code")
        ),
    ],
    ids=(
        "no-args",
        "multi-args",
        "non-string",
        "overlong",
        "unknown",
        "length-poison",
        "equality-poison",
    ),
)
def test_native_smoke_exit_descriptor_rejects_unapproved_shapes(
    supplied: BaseException,
) -> None:
    assert _classify_failure(_require_exit_stack_error(supplied), "native-smoke") == (
        "native-smoke-exit"
    )


def test_native_smoke_descriptor_requires_exact_error_type() -> None:
    class _DerivedSmokeError(smoke_artifact.ArtifactSmokeError):
        @property
        def args(self) -> object:
            raise AssertionError("ordinary exception arguments are forbidden")

        def __str__(self) -> str:
            raise AssertionError("exception text must not be formatted")

        def __repr__(self) -> str:
            raise AssertionError("exception details must not be formatted")

    run_err = _DerivedSmokeError("version wrote to stderr")
    assert _classify_failure(_smoke_stack_error(run_err), "native-smoke") == (
        "native-smoke-run"
    )

    exit_err = _DerivedSmokeError("version returned the wrong exit code")
    assert _classify_failure(_require_exit_stack_error(exit_err), "native-smoke") == (
        "native-smoke-exit"
    )


def test_native_smoke_cause_precedence_and_retention() -> None:
    # 1. Non-exact revisit of run_smoke preserves previously selected named command code
    outer = _smoke_stack_error(
        smoke_artifact.ArtifactSmokeError("version wrote to stderr")
    )
    non_exact_cause = _smoke_stack_error(_PoisonError("private-canary"))
    _set_explicit_cause(outer, non_exact_cause)
    assert _classify_failure(outer, "native-smoke") == "native-smoke-version"

    # 2. Exact owned unknown ArtifactSmokeError revisit restores native-smoke-run
    outer2 = _smoke_stack_error(
        smoke_artifact.ArtifactSmokeError("version wrote to stderr")
    )
    exact_unknown_cause = _smoke_stack_error(
        smoke_artifact.ArtifactSmokeError("unknown-failure")
    )
    _set_explicit_cause(outer2, exact_unknown_cause)
    assert _classify_failure(outer2, "native-smoke") == "native-smoke-run"

    # 3. Deeper helper cause (_decode) overrides outer run_smoke
    outer3 = _smoke_stack_error(
        smoke_artifact.ArtifactSmokeError("version wrote to stderr")
    )
    deeper = _captured_exception(lambda: smoke_artifact._decode(b"\xff", "test"))
    _set_explicit_cause(outer3, deeper)
    assert _classify_failure(outer3, "native-smoke") == "native-smoke-decode"

    # 4. At _require_exit: no descriptor preservation exception; synthetic foreign cause resolves to native-smoke-exit
    exit_outer = _require_exit_stack_error(
        smoke_artifact.ArtifactSmokeError("version returned the wrong exit code")
    )
    exit_cause = _require_exit_stack_error(_PoisonError("private-exit-cause"))
    _set_explicit_cause(exit_outer, exit_cause)
    assert _classify_failure(exit_outer, "native-smoke") == "native-smoke-exit"


def test_native_smoke_cloned_code_is_rejected() -> None:
    def fail_immediately(*_args: object, **_kwargs: object) -> None:
        raise smoke_artifact.ArtifactSmokeError("version wrote to stderr")

    cloned_code = smoke_artifact.run_smoke.__code__.replace()
    assert cloned_code == smoke_artifact.run_smoke.__code__
    assert cloned_code is not smoke_artifact.run_smoke.__code__

    runner = FunctionType(
        cloned_code,
        {**smoke_artifact.run_smoke.__globals__, "_validate_request": fail_immediately},
        name=smoke_artifact.run_smoke.__name__,
    )
    error = _captured_exception(lambda: runner(None, None))
    assert _classify_failure(error, "native-smoke") == "native-smoke"


def test_native_smoke_node_and_frame_caps() -> None:
    mapped = _smoke_stack_error(
        smoke_artifact.ArtifactSmokeError("version wrote to stderr")
    )
    root = mapped
    for _index in range(7):
        wrapper = _PoisonError("private-bounded-smoke-cause")
        _set_explicit_cause(wrapper, root)
        root = wrapper

    assert _classify_failure(root, "native-smoke") == "native-smoke-version"

    ninth = _PoisonError("private-overflow-smoke-cause")
    _set_explicit_cause(ninth, root)
    assert _classify_failure(ninth, "native-smoke") == "unknown"


def test_native_smoke_status_writer_sanitizes_canaries_and_verifies_schema(
    tmp_path: Path,
) -> None:
    root = tmp_path / "qualification"
    root.mkdir()
    public = root / "public"
    public.mkdir()
    req = QualificationRequest(
        wheel=root / "servonaut-9.8.7-py3-none-any.whl",
        wheel_sha256="0" * 64,
        target_name="windows-x64",
        product_version="9.8.7",
        build_revision="test-run",
        source_commit="a" * 40,
        checkout=ci_qualify._PROJECT_ROOT,
        qualification_root=root,
        public_evidence_dir=public,
        docker=None,
    )
    owned_pub = ci_qualify._OwnedDirectory(
        public, (public.stat().st_dev, public.stat().st_ino)
    )

    new_tokens = (
        "native-smoke-backups",
        "native-smoke-bad-argument",
        "native-smoke-caller-isolation",
        "native-smoke-cleanup",
        "native-smoke-completeness",
        "native-smoke-decode",
        "native-smoke-environment",
        "native-smoke-exit",
        "native-smoke-help",
        "native-smoke-mcp",
        "native-smoke-mcp-install",
        "native-smoke-policy",
        "native-smoke-process",
        "native-smoke-request",
        "native-smoke-run",
        "native-smoke-selftest",
        "native-smoke-transcript",
        "native-smoke-update",
        "native-smoke-version",
    )

    for token in new_tokens:
        status_file = public / ci_qualify._STATUS_NAME
        if status_file.exists():
            status_file.unlink()
        written = ci_qualify._write_status(
            owned_pub,
            req,
            "failed",
            ["build", "evidence", "archive", "extract"],
            token,  # type: ignore[arg-type]
        )
        content = written.read_text(encoding="utf-8")
        data = json.loads(content)
        assert set(data.keys()) == {
            "schema_version",
            "target",
            "status",
            "completed_stages",
            "completed_stage_count",
            "failure_code",
        }
        assert data["schema_version"] == 1
        assert data["target"] == "windows-x64"
        assert data["status"] == "failed"
        assert data["completed_stages"] == ["build", "evidence", "archive", "extract"]
        assert data["completed_stage_count"] == 4
        assert data["failure_code"] == token

        assert str(req.qualification_root) not in content
        for msg, _ in ci_qualify._NATIVE_SMOKE_OUTPUT_FAILURE_CODES:
            assert msg not in content
        for msg, _ in ci_qualify._NATIVE_SMOKE_EXIT_FAILURE_CODES:
            assert msg not in content
