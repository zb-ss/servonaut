"""License notices a desktop build takes from the source archives it compiles.

The archives are stand-ins served by a fake opener, so nothing here downloads.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from email.message import Message
from pathlib import Path, PurePosixPath

import pytest
from jsonschema import Draft202012Validator

import scripts.desktop_shell.build as desktop_build
from scripts.desktop_shell.model import load_desktop_build_policy, load_desktop_target_spec
from scripts.desktop_shell.source_notices import (
    SOURCE_NOTICE_POLICY_PATH,
    SourceArchive,
    SourceNotice,
    SourceNoticeError,
    SourceNoticePolicy,
    SourceNoticeRecord,
    load_source_notice_policy,
    require_locked_archives,
    stage_source_notices,
    validate_payload_source_notices,
    write_source_notice_metadata,
)

_LINUX = "linux-x64-ubuntu-22.04"
_SCHEMA = SOURCE_NOTICE_POLICY_PATH.with_name("source-notices.schema.json")
_TEXT = b"GNU LESSER GENERAL PUBLIC LICENSE\n"
_URL = "https://files.pythonhosted.org/packages/aa/demo-1.0.0.tar.gz"


def _archive_bytes(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class _Response:
    def __init__(self, body: bytes, url: str) -> None:
        self._body = io.BytesIO(body)
        self._url = url
        self.headers = Message()

    def read1(self, amount: int) -> bytes:
        return self._body.read(amount)

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


def _opener(body: bytes, requested: list[str]) -> object:
    def open_url(request: object, timeout: float) -> _Response:
        requested.append(request.full_url)  # type: ignore[attr-defined]
        return _Response(body, request.full_url)  # type: ignore[attr-defined]

    return open_url


def _policy(archive_sha256: str, text_sha256: str = hashlib.sha256(_TEXT).hexdigest()) -> SourceNoticePolicy:
    return SourceNoticePolicy(
        origin_host="files.pythonhosted.org",
        max_archive_bytes=1024 * 1024,
        max_expanded_bytes=1024 * 1024,
        download_timeout_seconds=10,
        socket_timeout_seconds=10,
        archives=(
            SourceArchive(
                distribution="demo",
                version="1.0.0",
                targets=frozenset({_LINUX}),
                url=_URL,
                sha256=archive_sha256,
                notices=(
                    SourceNotice(
                        PurePosixPath("demo-1.0.0/COPYING"),
                        PurePosixPath("_internal/notices/demo-COPYING.txt"),
                        text_sha256,
                    ),
                ),
            ),
        ),
    )


def _lock(archive_sha256: str, version: str = "1.0.0") -> str:
    return (
        f"demo=={version} ; sys_platform == 'linux' \\\n"
        f"    --hash=sha256:{'a' * 64} \\\n"
        f"    --hash=sha256:{archive_sha256}\n"
        "    # via -r requirements.in\n"
    )


def test_the_reviewed_policy_is_schema_valid_and_loads() -> None:
    raw = json.loads(SOURCE_NOTICE_POLICY_PATH.read_text(encoding="utf-8"))
    schema = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(raw)

    policy = load_source_notice_policy()

    assert set(policy.payload_notices(_LINUX)) == {
        "PyGObject-COPYING.txt",
        "pycairo-COPYING.txt",
        "pycairo-COPYING-LGPL-2.1.txt",
        "pycairo-COPYING-MPL-1.1.txt",
    }
    for other in ("windows-x64", "macos-x64", "macos-arm64"):
        assert policy.payload_notices(other) == {}


def test_the_reviewed_archives_are_the_ones_the_linux_lock_pins() -> None:
    policy = load_source_notice_policy()
    lock = load_desktop_target_spec(_LINUX).requirements_lock.read_text(encoding="utf-8")

    require_locked_archives(policy.for_target(_LINUX), lock)
    assert {archive.distribution for archive in policy.for_target(_LINUX)} == {
        "pycairo",
        "pygobject",
    }


@pytest.mark.parametrize(
    ("lock", "message"),
    [
        (_lock("b" * 64, version="1.0.1"), "not the one the target lock pins"),
        (_lock("c" * 64), "not the one the target lock pins"),
        ("other==1.0.0 \\\n    --hash=sha256:" + "b" * 64 + "\n", "does not pin demo"),
    ],
)
def test_an_archive_the_lock_does_not_pin_is_refused(lock: str, message: str) -> None:
    with pytest.raises(SourceNoticeError, match=message):
        require_locked_archives(_policy("b" * 64).archives, lock)


def test_notices_are_extracted_from_the_pinned_archive(tmp_path: Path) -> None:
    body = _archive_bytes({"demo-1.0.0/COPYING": _TEXT, "demo-1.0.0/setup.py": b"x"})
    digest = hashlib.sha256(body).hexdigest()
    staging, work = tmp_path / "notices", tmp_path / "work"
    staging.mkdir()
    work.mkdir()
    requested: list[str] = []

    records = stage_source_notices(
        _policy(digest), _LINUX, _lock(digest), staging, work, opener=_opener(body, requested)
    )

    assert requested == [_URL]
    assert (staging / "demo-COPYING.txt").read_bytes() == _TEXT
    assert records == (
        SourceNoticeRecord(
            "demo",
            "1.0.0",
            digest,
            PurePosixPath("_internal/notices/demo-COPYING.txt"),
            hashlib.sha256(_TEXT).hexdigest(),
        ),
    )
    assert list(work.iterdir()) == []  # the archive is not kept


def test_a_changed_license_text_is_refused_and_not_staged(tmp_path: Path) -> None:
    body = _archive_bytes({"demo-1.0.0/COPYING": b"a different text\n"})
    digest = hashlib.sha256(body).hexdigest()
    staging, work = tmp_path / "notices", tmp_path / "work"
    staging.mkdir()
    work.mkdir()

    with pytest.raises(SourceNoticeError, match="does not match its reviewed text"):
        stage_source_notices(
            _policy(digest), _LINUX, _lock(digest), staging, work, opener=_opener(body, [])
        )
    assert list(staging.iterdir()) == []


def test_an_archive_that_differs_from_its_pin_is_refused(tmp_path: Path) -> None:
    body = _archive_bytes({"demo-1.0.0/COPYING": _TEXT})
    pinned = "b" * 64
    staging, work = tmp_path / "notices", tmp_path / "work"
    staging.mkdir()
    work.mkdir()

    with pytest.raises(SourceNoticeError, match="checksum does not match"):
        stage_source_notices(
            _policy(pinned), _LINUX, _lock(pinned), staging, work, opener=_opener(body, [])
        )


def test_targets_without_source_archives_download_nothing(tmp_path: Path) -> None:
    requested: list[str] = []

    records = stage_source_notices(
        _policy("b" * 64), "macos-arm64", "", tmp_path, tmp_path, opener=_opener(b"", requested)
    )

    assert records == ()
    assert requested == []


def test_payload_copies_must_match_their_records(tmp_path: Path) -> None:
    notices = tmp_path / "_internal" / "notices"
    notices.mkdir(parents=True)
    record = SourceNoticeRecord(
        "demo", "1.0.0", "b" * 64, PurePosixPath("_internal/notices/demo-COPYING.txt"),
        hashlib.sha256(_TEXT).hexdigest(),
    )

    with pytest.raises(SourceNoticeError, match="missing: demo-COPYING.txt"):
        validate_payload_source_notices(tmp_path, (record,), 1024)
    (notices / "demo-COPYING.txt").write_bytes(b"tampered\n")
    with pytest.raises(SourceNoticeError, match="invalid: demo-COPYING.txt"):
        validate_payload_source_notices(tmp_path, (record,), 1024)
    (notices / "demo-COPYING.txt").write_bytes(_TEXT)
    validate_payload_source_notices(tmp_path, (record,), 1024)


def test_metadata_records_where_each_notice_came_from(tmp_path: Path) -> None:
    record = SourceNoticeRecord(
        "demo", "1.0.0", "b" * 64, PurePosixPath("_internal/notices/demo-COPYING.txt"), "c" * 64
    )

    write_source_notice_metadata(tmp_path / "source-notices.json", (record,))

    assert json.loads((tmp_path / "source-notices.json").read_text()) == {
        "schema_version": 1,
        "notices": [
            {
                "distribution": "demo",
                "version": "1.0.0",
                "source_archive_sha256": "b" * 64,
                "payload_path": "_internal/notices/demo-COPYING.txt",
                "sha256": "c" * 64,
            }
        ],
    }


def _write_policy(tmp_path: Path, **archive_changes: object) -> Path:
    raw = json.loads(SOURCE_NOTICE_POLICY_PATH.read_text(encoding="utf-8"))
    raw["archives"][0].update(archive_changes)
    path = tmp_path / "source-notices.json"
    path.write_text(json.dumps(raw))
    return path


@pytest.mark.parametrize(
    "changes",
    [
        {"url": "https://example.invalid/pycairo-1.29.1.tar.gz"},
        {"url": "http://files.pythonhosted.org/packages/pycairo-1.29.1.tar.gz"},
        {"url": "https://files.pythonhosted.org/packages/other-1.29.1.tar.gz"},
        {"targets": ["linux-x64-ubuntu-24.04"]},
        {"targets": []},
        {"sha256": "not-a-digest"},
        {"notices": [{"member": "../COPYING", "payload_path": "_internal/notices/x.txt", "sha256": "0" * 64}]},
        {"notices": [{"member": "pycairo-1.29.1/COPYING", "payload_path": "notices/x.txt", "sha256": "0" * 64}]},
        {"distribution": "zzz-last"},
    ],
)
def test_a_malformed_policy_is_refused(tmp_path: Path, changes: dict[str, object]) -> None:
    with pytest.raises(SourceNoticeError):
        load_source_notice_policy(_write_policy(tmp_path, **changes))


def test_the_build_stages_source_notices_only_where_the_target_has_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, Path]] = []

    def stage(policy: object, target_name: str, lock_text: str, staging: Path, work: Path) -> tuple[()]:
        calls.append((target_name, work))
        assert "pygobject==3.48.2" in lock_text
        return ()

    monkeypatch.setattr(desktop_build, "stage_source_notices", stage)
    context = desktop_build._BuildContext(
        python=Path("py"), environment={}, working_directory=tmp_path,
        policy=load_desktop_build_policy(),
    )

    for name in ("windows-x64", "macos-x64", "macos-arm64", _LINUX):
        desktop_build._stage_source_notices(
            context, load_desktop_target_spec(name), tmp_path / "notices"
        )

    assert calls == [(_LINUX, tmp_path / "source-archives")]
