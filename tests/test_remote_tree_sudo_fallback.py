"""Tests for RemoteTree's directory listing + sudo fallback.

EFS / NFS shares and other root-owned mounts are commonly unreadable by the
login user; RemoteTree retries the listing once with non-interactive sudo on a
permission error. These tests pin that behaviour by mocking the SSH subprocess.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from servonaut.widgets.remote_tree import RemoteTree


_LS_OUTPUT = (
    "total 8\n"
    "drwxr-xr-x 3 root root 4096 Jan  1 00:00 .\n"
    "drwxr-xr-x 3 root root 4096 Jan  1 00:00 ..\n"
    "drwxr-xr-x 2 root root 4096 Jan  1 00:00 shared\n"
    "-rw-r--r-- 1 root root   12 Jan  1 00:00 note.txt\n"
)


def _make_tree() -> RemoteTree:
    ssh = MagicMock()
    ssh.get_key_path.return_value = "/key.pem"
    ssh.discover_key.return_value = None
    ssh.build_ssh_command.side_effect = lambda **kw: ["ssh", "host", kw["remote_command"]]
    instance = {"id": "i-1", "name": "web", "public_ip": "192.0.2.1", "ssh_key": "/key.pem"}
    return RemoteTree(
        instance=instance,
        ssh_service=ssh,
        connection_service=MagicMock(),
        username="ec2-user",
        scan_paths=["/mnt/efs"],
    )


def _completed(returncode: int, stdout: str = "", stderr: str = ""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_plain_ls_success_parses_entries():
    tree = _make_tree()
    with patch("servonaut.widgets.remote_tree.subprocess.run",
               return_value=_completed(0, _LS_OUTPUT)) as run:
        entries = tree._fetch_directory_contents("/mnt/efs")
    assert run.call_count == 1  # no sudo retry when the first ls succeeds
    names = {e["name"] for e in entries}
    assert names == {"shared", "note.txt"}


def test_permission_denied_retries_with_sudo():
    tree = _make_tree()
    calls = []

    def _run(cmd, **kw):
        calls.append(cmd[-1])  # the remote_command
        if cmd[-1].startswith("sudo -n"):
            return _completed(0, _LS_OUTPUT)
        return _completed(2, stderr="ls: cannot open directory '/mnt/efs': Permission denied")

    with patch("servonaut.widgets.remote_tree.subprocess.run", side_effect=_run):
        entries = tree._fetch_directory_contents("/mnt/efs")

    assert len(calls) == 2
    assert calls[0].startswith("ls -la")
    assert calls[1].startswith("sudo -n ls -la")
    assert {e["name"] for e in entries} == {"shared", "note.txt"}


def test_permission_denied_and_sudo_unavailable_raises_original():
    tree = _make_tree()

    def _run(cmd, **kw):
        if cmd[-1].startswith("sudo -n"):
            # sudo -n with no passwordless sudo fails fast, never prompts.
            return _completed(1, stderr="sudo: a password is required")
        return _completed(2, stderr="ls: cannot open directory '/mnt/efs': Permission denied")

    with patch("servonaut.widgets.remote_tree.subprocess.run", side_effect=_run):
        with pytest.raises(RuntimeError) as exc:
            tree._fetch_directory_contents("/mnt/efs")
    # The user-facing error is the original permission message, not the sudo one.
    assert "Permission denied" in str(exc.value)


def test_non_permission_error_does_not_try_sudo():
    tree = _make_tree()
    calls = []

    def _run(cmd, **kw):
        calls.append(cmd[-1])
        return _completed(2, stderr="ls: cannot access '/mnt/efs': No such file or directory")

    with patch("servonaut.widgets.remote_tree.subprocess.run", side_effect=_run):
        with pytest.raises(RuntimeError) as exc:
            tree._fetch_directory_contents("/mnt/efs")
    assert len(calls) == 1  # no sudo retry for a non-permission failure
    assert "No such file" in str(exc.value)


def test_timeout_surfaces_as_timeout():
    import subprocess as _sp
    tree = _make_tree()
    with patch("servonaut.widgets.remote_tree.subprocess.run",
               side_effect=_sp.TimeoutExpired(cmd="ssh", timeout=30)):
        with pytest.raises(RuntimeError) as exc:
            tree._fetch_directory_contents("/mnt/efs")
    assert "timed out" in str(exc.value).lower()
