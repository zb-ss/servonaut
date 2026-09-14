from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from types import FunctionType, SimpleNamespace, TracebackType

import pytest

from scripts.standalone_cli import ci_qualify
from scripts.standalone_cli.artifact_types import ArchiveOwner
from scripts.standalone_cli.ci_qualify import (
    QualificationError,
    QualificationRequest,
    _classify_failure,
    main,
    qualify,
)
from scripts.standalone_cli.model import BuildRequest


class _PoisonError(Exception):
    def __str__(self) -> str:
        raise AssertionError("exception text must not be formatted")

    def __repr__(self) -> str:
        raise AssertionError("exception details must not be formatted")


def _captured_traceback(call: Callable[[], object]) -> TracebackType:
    try:
        call()
    except Exception as error:  # noqa: BLE001 - controlled classification fixture
        assert error.__traceback__ is not None
        return error.__traceback__
    raise AssertionError("classification fixture did not raise")


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
        target_name=target,
        product_version="9.8.7",
        build_revision="run-1",
        source_commit="a" * 40,
        checkout=ci_qualify._PROJECT_ROOT,
        qualification_root=root.resolve(),
        public_evidence_dir=(root / "public evidence").resolve(),
        docker=docker.resolve() if docker else None,
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

    def fake_inspect(artifact: object, evidence_dir: Path) -> object:
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
        return SimpleNamespace(archive=archive, _archive_owner=owner)

    def fake_extract(_archive: Path, destination: Path) -> Path:
        calls.append("extract")
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
    monkeypatch.setattr(ci_qualify, "inspect_artifact", fake_inspect)
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


def test_failed_enforcement_never_extracts_or_smokes_and_still_writes_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    calls: list[str] = []
    _install_successful_fakes(monkeypatch, request, calls)

    def reject(_artifact: object, evidence_dir: Path) -> object:
        calls.append("evidence-rejected")
        (evidence_dir / "warning-candidates.json").write_text(
            '{"schema_version":1,"candidates":[]}\n', encoding="utf-8"
        )
        raise ValueError("private rejection detail")

    monkeypatch.setattr(ci_qualify, "inspect_artifact", reject)

    result = qualify(request)

    assert result.status == "failed"
    assert result.completed_stages == ("build", "cleanup")
    assert "extract" not in calls
    assert "native-smoke" not in calls
    status_text = result.public_status.read_text(encoding="utf-8")
    assert "private rejection detail" not in status_text
    assert str(request.qualification_root) not in status_text
    assert json.loads(status_text)["failure_code"] == "unknown"
    assert (request.public_evidence_dir / "warning-candidates.json").is_file()


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
    original = ci_qualify.inspect_artifact

    def write_unknown(artifact: object, evidence_dir: Path) -> object:
        result = original(artifact, evidence_dir)
        (evidence_dir / "raw-private.json").write_text(
            json.dumps(
                {
                    "private_exception": "supply failed at local input",
                    "private_path": str(request.qualification_root),
                }
            ),
            encoding="utf-8",
        )
        return result

    monkeypatch.setattr(ci_qualify, "inspect_artifact", write_unknown)

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
    original = ci_qualify.inspect_artifact

    def write_unknown_directory(artifact: object, evidence_dir: Path) -> object:
        result = original(artifact, evidence_dir)
        (evidence_dir / "unexpected").mkdir()
        return result

    monkeypatch.setattr(ci_qualify, "inspect_artifact", write_unknown_directory)

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
    original = ci_qualify.inspect_artifact

    def occupy_status(artifact: object, evidence_dir: Path) -> object:
        result = original(artifact, evidence_dir)
        (evidence_dir / "qualification-status.json").write_text(
            "foreign\n", encoding="utf-8"
        )
        return result

    monkeypatch.setattr(ci_qualify, "inspect_artifact", occupy_status)

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
    original = ci_qualify.inspect_artifact
    foreign = tmp_path / "foreign-status.json"
    foreign.write_text("foreign\n", encoding="utf-8")

    def link_status(artifact: object, evidence_dir: Path) -> object:
        result = original(artifact, evidence_dir)
        (evidence_dir / "qualification-status.json").symlink_to(foreign)
        return result

    monkeypatch.setattr(ci_qualify, "inspect_artifact", link_status)

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
                "http://invalid.example", Path("unused"), "0" * 64, 1, 1
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
                object(), object(), Path("unused"), Path("unused")
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
    traceback = _captured_traceback(call)

    assert _classify_failure(traceback, "unknown") == expected


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
    traceback = _captured_traceback(
        lambda: ci_qualify._syft_tool.acquire_syft(
            ci_qualify._sbom_normalize._SYFT_POLICY, target, cache
        )
    )

    assert _classify_failure(traceback, "unknown") == "evidence-tool-download"


@pytest.mark.parametrize("phase", ["pre-archive", "post-archive"])
def test_failure_classifier_maps_policy_report_writes_at_deepest_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    original_write_text = Path.write_text
    rejected_name = "manifest.json" if phase == "pre-archive" else "sizes.json"

    def reject_report_write(
        path: Path, data: str, *args: object, **kwargs: object
    ) -> int:
        if path.name == rejected_name:
            raise _PoisonError("private-policy-write-canary")
        return original_write_text(path, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", reject_report_write)
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
            object(), SimpleNamespace(target=object()), policy, evidence
        )
    else:
        manifest = evidence / "manifest.json"
        manifest.write_text('{"entries":[]}\n', encoding="utf-8")
        provenance = evidence / "dependency-provenance.json"
        provenance.write_text("{}\n", encoding="utf-8")
        archive_path = tmp_path / "artifact.tar.gz"
        archive_path.write_bytes(b"archive")
        pre = SimpleNamespace(manifest=manifest)
        supply = SimpleNamespace(dependency_provenance=provenance)
        archive = SimpleNamespace(
            path=archive_path,
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

    traceback = _captured_traceback(call)

    assert _classify_failure(traceback, "unknown") == "evidence-write"


def test_policy_write_failure_status_never_exposes_private_details(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    calls: list[str] = []
    _install_successful_fakes(monkeypatch, request, calls)

    def reject_write(_artifact: object, evidence_dir: Path) -> object:
        ci_qualify._evidence_policy._write_json(
            evidence_dir / "manifest.json", _PoisonError("private-write-canary")
        )
        raise AssertionError("policy writer unexpectedly returned")

    monkeypatch.setattr(ci_qualify, "inspect_artifact", reject_write)

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
    traceback = _captured_traceback(
        lambda: ci_qualify._syft_tool._verify_syft_version(
            Path("unused"), object(), object(), config
        )
    )

    assert _classify_failure(traceback, "unknown") == "evidence-tool-version"


def test_failure_classifier_rejects_same_named_unrelated_function() -> None:
    def acquire_syft() -> None:
        raise _PoisonError("private-same-name-canary")

    traceback = _captured_traceback(acquire_syft)

    assert _classify_failure(traceback, "unknown") == "unknown"


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

    traceback = _captured_traceback(
        lambda: clone(Path("relative"), {}, forbidden_roots=(), max_bytes=1)
    )

    assert _classify_failure(traceback, "unknown") == "unknown"


def test_failure_classifier_overflow_is_unknown() -> None:
    def recurse(remaining: int) -> None:
        if remaining:
            recurse(remaining - 1)
        else:
            raise _PoisonError("private-overflow-canary")

    traceback = _captured_traceback(lambda: recurse(65))

    assert _classify_failure(traceback, "build") == "unknown"


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

        class _ArchiveBoundaryFailure:
            @property
            def _archive_owner(self) -> object:
                raise _PoisonError("private-stage-canary")

        monkeypatch.setattr(
            ci_qualify,
            "inspect_artifact",
            lambda *_args, **_kwargs: _ArchiveBoundaryFailure(),
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
