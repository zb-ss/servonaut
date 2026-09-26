"""Tests for the shared tar-archive safety helper."""

from __future__ import annotations

import io
from pathlib import Path
import tarfile

import pytest

from servonaut.utils.archive_safety import (
    UnsafeArchiveError,
    extract_tar_safely,
    tar_member_rejection,
)


def _member(name: str, kind: bytes = tarfile.REGTYPE, linkname: str = "") -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = linkname
    return info


@pytest.mark.parametrize(
    ("member", "reason"),
    [
        (_member("/etc/passwd"), "absolute path"),
        (_member("C:/Windows/evil.dll"), "drive letter"),
        (_member("model/../../escape"), "parent-directory traversal"),
        (_member("model\\..\\escape"), "parent-directory traversal"),
        (_member("link", tarfile.SYMTYPE, "voices.bin"), "link member"),
        (_member("hard", tarfile.LNKTYPE, "voices.bin"), "link member"),
        (_member("fifo", tarfile.FIFOTYPE), "special file"),
        (_member("dev", tarfile.CHRTYPE), "special file"),
    ],
)
def test_unsafe_members_are_rejected(member: tarfile.TarInfo, reason: str) -> None:
    assert tar_member_rejection(member) == reason


@pytest.mark.parametrize("name", ["model/voices.bin", "./model/tokens.txt", "espeak-ng-data"])
def test_plain_members_are_accepted(name: str) -> None:
    assert tar_member_rejection(_member(name)) == ""
    assert tar_member_rejection(_member(name, tarfile.DIRTYPE)) == ""


def test_one_bad_member_extracts_nothing(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        good = tarfile.TarInfo("model/voices.bin")
        good.size = 2
        tar.addfile(good, io.BytesIO(b"ok"))
        tar.addfile(_member("model/link", tarfile.SYMTYPE, "voices.bin"))
    buf.seek(0)

    with tarfile.open(fileobj=buf) as tar:
        with pytest.raises(UnsafeArchiveError, match="link member"):
            extract_tar_safely(tar, tmp_path / "dest")
    assert not (tmp_path / "dest").exists()


def test_in_tree_symlink_is_rejected_even_without_the_data_filter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delattr(tarfile, "data_filter", raising=False)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.addfile(_member("inner", tarfile.SYMTYPE, "."))
    buf.seek(0)
    with tarfile.open(fileobj=buf) as tar:
        with pytest.raises(UnsafeArchiveError):
            extract_tar_safely(tar, tmp_path / "dest")
