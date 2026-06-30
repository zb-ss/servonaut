"""Tests for :class:`servonaut.services.bw_session_service.BwSessionService`.

The ``bw`` subprocess is fully mocked (``subprocess.run`` + ``shutil.which``).
Security pins assert the master password and session key NEVER reach argv and are
only ever passed through ``env=``.
"""

from __future__ import annotations

import asyncio
import json
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

import pytest

from servonaut.services.bw_errors import (
    BwCliMissingError,
    BwListError,
    BwSessionMissingError,
    BwUnauthenticatedError,
    BwUnlockFailedError,
)
from servonaut.services.bw_session_service import (
    BwAuthState,
    BwItemSummary,
    BwSessionService,
)

# A neutral, non-secret session key shape for tests (never a real key).
FAKE_SESSION = "fake-session-key-AAAA=="
MASTER_PW = "correct horse battery staple"


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0) -> CompletedProcess:  # type: ignore[type-arg]
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _status_json(state: str) -> str:
    return json.dumps({"serverUrl": None, "userEmail": "user@example.com", "status": state})


def _ssh_item(item_id: str, name: str, folder_id: str = "fld-1") -> dict:
    """A native SSH-key item (type 5) — includes a privateKey we must NOT surface."""
    return {
        "id": item_id,
        "name": name,
        "type": 5,
        "folderId": folder_id,
        "sshKey": {
            "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET\n-----END-----",
            "publicKey": "ssh-ed25519 AAAA",
            "keyFingerprint": "SHA256:abc",
        },
    }


def _login_item(item_id: str, name: str, username: str, folder_id: str = "fld-1") -> dict:
    return {
        "id": item_id,
        "name": name,
        "type": 1,
        "folderId": folder_id,
        "login": {"username": username, "password": "hunter2"},
    }


# ---------------------------------------------------------------------------
# status()
# ---------------------------------------------------------------------------


class TestStatus:
    def test_not_installed_when_bw_absent(self):
        with patch("shutil.which", return_value=None):
            state = _run(BwSessionService().status())
        assert state is BwAuthState.NOT_INSTALLED

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("unlocked", BwAuthState.UNLOCKED),
            ("locked", BwAuthState.LOCKED),
            ("unauthenticated", BwAuthState.UNAUTHENTICATED),
        ],
    )
    def test_maps_each_state(self, raw, expected):
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout=_status_json(raw))
        ):
            state = _run(BwSessionService().status())
        assert state is expected

    def test_unknown_state_is_unauthenticated(self):
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout=_status_json("weird"))
        ):
            state = _run(BwSessionService().status())
        assert state is BwAuthState.UNAUTHENTICATED

    def test_non_json_is_unauthenticated(self):
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout="not json")
        ):
            state = _run(BwSessionService().status())
        assert state is BwAuthState.UNAUTHENTICATED

    def test_timeout_is_unauthenticated(self):
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", side_effect=TimeoutExpired(cmd="bw", timeout=20)
        ):
            state = _run(BwSessionService().status())
        assert state is BwAuthState.UNAUTHENTICATED


# ---------------------------------------------------------------------------
# unlock()
# ---------------------------------------------------------------------------


class TestUnlock:
    def test_success_captures_session(self):
        svc = BwSessionService()
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout=FAKE_SESSION + "\n")
        ):
            _run(svc.unlock(MASTER_PW))
        assert svc.session() == FAKE_SESSION
        assert svc.is_unlocked() is True

    def test_password_never_on_argv_and_passed_via_env(self):
        svc = BwSessionService()
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout=FAKE_SESSION)
        ) as mock_run:
            _run(svc.unlock(MASTER_PW))
        argv = mock_run.call_args.args[0]
        assert MASTER_PW not in argv
        assert all(MASTER_PW not in str(tok) for tok in argv)
        assert "--passwordenv" in argv
        env = mock_run.call_args.kwargs["env"]
        assert env["BW_MASTERPW"] == MASTER_PW

    def test_bad_password_raises(self):
        svc = BwSessionService()
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run",
            return_value=_completed(stderr="Invalid master password.", returncode=1),
        ):
            with pytest.raises(BwUnlockFailedError):
                _run(svc.unlock("wrong"))
        assert svc.session() is None

    def test_logged_out_raises_unauthenticated(self):
        svc = BwSessionService()
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run",
            return_value=_completed(stderr="You are not logged in.", returncode=1),
        ):
            with pytest.raises(BwUnauthenticatedError):
                _run(svc.unlock(MASTER_PW))

    def test_empty_session_output_raises(self):
        svc = BwSessionService()
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout="   ")
        ):
            with pytest.raises(BwUnlockFailedError):
                _run(svc.unlock(MASTER_PW))

    def test_missing_cli_raises(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(BwCliMissingError):
                _run(BwSessionService().unlock(MASTER_PW))

    def test_lock_drops_session(self):
        svc = BwSessionService()
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout=FAKE_SESSION)
        ):
            _run(svc.unlock(MASTER_PW))
        svc.lock()
        assert svc.session() is None
        assert svc.is_unlocked() is False


# ---------------------------------------------------------------------------
# ensure_servonaut_folder()
# ---------------------------------------------------------------------------


class TestEnsureFolder:
    def test_returns_existing_folder_id(self):
        svc = BwSessionService()
        svc._session = FAKE_SESSION
        folders = json.dumps([{"id": "fld-1", "name": "Servonaut"}, {"id": "fld-2", "name": "Other"}])
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout=folders)
        ) as mock_run:
            folder_id = _run(svc.ensure_servonaut_folder())
        assert folder_id == "fld-1"
        # only the list call — no create
        assert mock_run.call_count == 1
        # session injected via env, never argv
        env = mock_run.call_args.kwargs["env"]
        assert env["BW_SESSION"] == FAKE_SESSION
        assert FAKE_SESSION not in mock_run.call_args.args[0]

    def test_creates_folder_when_absent(self):
        svc = BwSessionService()
        svc._session = FAKE_SESSION
        list_result = _completed(stdout=json.dumps([{"id": "fld-2", "name": "Other"}]))
        create_result = _completed(stdout=json.dumps({"id": "fld-new", "name": "Servonaut"}))
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", side_effect=[list_result, create_result]
        ) as mock_run:
            folder_id = _run(svc.ensure_servonaut_folder())
        assert folder_id == "fld-new"
        assert mock_run.call_count == 2
        create_argv = mock_run.call_args_list[1].args[0]
        assert create_argv[:3] == ["/usr/bin/bw", "create", "folder"] or create_argv[1:3] == [
            "create",
            "folder",
        ]

    def test_locked_session_raises(self):
        svc = BwSessionService()  # no session set
        with patch("shutil.which", return_value="/usr/bin/bw"):
            with pytest.raises(BwSessionMissingError):
                _run(svc.ensure_servonaut_folder())


# ---------------------------------------------------------------------------
# list_items()
# ---------------------------------------------------------------------------


class TestListItems:
    def test_filters_to_ssh_items(self):
        svc = BwSessionService()
        svc._session = FAKE_SESSION
        items = json.dumps(
            [
                _ssh_item("ssh-1", "prod web key"),
                _login_item("login-1", "db password", "dbuser"),
                _ssh_item("ssh-2", "bastion key"),
            ]
        )
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout=items)
        ):
            summaries = _run(svc.list_items(folder_id="fld-1", ssh_only=True))
        assert {s.id for s in summaries} == {"ssh-1", "ssh-2"}
        assert all(s.has_ssh_key for s in summaries)

    def test_ssh_only_false_returns_all(self):
        svc = BwSessionService()
        svc._session = FAKE_SESSION
        items = json.dumps([_ssh_item("ssh-1", "key"), _login_item("login-1", "pw", "u")])
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout=items)
        ):
            summaries = _run(svc.list_items(ssh_only=False))
        assert {s.id for s in summaries} == {"ssh-1", "login-1"}

    def test_summary_never_carries_private_key(self):
        svc = BwSessionService()
        svc._session = FAKE_SESSION
        items = json.dumps([_ssh_item("ssh-1", "key")])
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout=items)
        ):
            summaries = _run(svc.list_items())
        summary = summaries[0]
        # No attribute nor repr leaks the private key body.
        assert "privateKey" not in repr(summary)
        assert "SECRET" not in repr(summary)
        assert not hasattr(summary, "sshKey")

    def test_search_and_folder_appended_to_argv(self):
        svc = BwSessionService()
        svc._session = FAKE_SESSION
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout="[]")
        ) as mock_run:
            _run(svc.list_items(folder_id="fld-9", search="bastion"))
        argv = mock_run.call_args.args[0]
        assert "--folderid" in argv and "fld-9" in argv
        assert "--search" in argv and "bastion" in argv
        # session must travel by env, not argv
        assert FAKE_SESSION not in argv
        assert mock_run.call_args.kwargs["env"]["BW_SESSION"] == FAKE_SESSION

    def test_locked_raises(self):
        svc = BwSessionService()
        with patch("shutil.which", return_value="/usr/bin/bw"):
            with pytest.raises(BwSessionMissingError):
                _run(svc.list_items())

    def test_malformed_json_raises_list_error(self):
        svc = BwSessionService()
        svc._session = FAKE_SESSION
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout="not json")
        ):
            with pytest.raises(BwListError):
                _run(svc.list_items())


class TestSummaryMapping:
    def test_login_item_username_preserved(self):
        summary = BwSessionService._to_summary(_login_item("l-1", "name", "alice"))
        assert summary.username == "alice"
        assert summary.has_ssh_key is False

    def test_ssh_item_detected_by_type(self):
        item = {"id": "x", "name": "k", "type": 5}
        summary = BwSessionService._to_summary(item)
        assert summary.has_ssh_key is True

    def test_ssh_item_detected_by_sshkey_presence(self):
        item = {"id": "x", "name": "k", "type": 0, "sshKey": {"publicKey": "ssh-ed25519 AAAA"}}
        summary = BwSessionService._to_summary(item)
        assert summary.has_ssh_key is True
        assert isinstance(summary, BwItemSummary)
