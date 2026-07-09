"""Tests for :class:`servonaut.services.bw_session_service.BwSessionService`.

The ``bw`` subprocess is fully mocked (``subprocess.run`` + ``shutil.which``).
Security pins assert the master password and session key NEVER reach argv and are
only ever passed through ``env=``.
"""

from __future__ import annotations

import asyncio
import base64
import json
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

import pytest

from tests._key_fixtures import openssh_armor
from servonaut.services.bw_errors import (
    BwCliMissingError,
    BwCreateError,
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
            "privateKey": openssh_armor("FAKEKEYBODY"),
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

    def test_held_session_injected_via_env_never_argv(self):
        # Without BW_SESSION, `bw status` reports "locked" even while a valid
        # session exists — every status-gated action would re-prompt for the
        # master password. The held session must ride the child env.
        svc = BwSessionService()
        svc._session = FAKE_SESSION
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout=_status_json("unlocked"))
        ) as mock_run:
            state = _run(svc.status())
        assert state is BwAuthState.UNLOCKED
        env = mock_run.call_args.kwargs["env"]
        assert env["BW_SESSION"] == FAKE_SESSION
        argv = mock_run.call_args.args[0]
        assert all(FAKE_SESSION not in str(tok) for tok in argv)

    def test_no_session_reports_ambient_state(self):
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout=_status_json("locked"))
        ) as mock_run:
            state = _run(BwSessionService().status())
        assert state is BwAuthState.LOCKED
        env = mock_run.call_args.kwargs["env"]
        assert env.get("BW_SESSION") != FAKE_SESSION


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

    def test_create_folder_payload_travels_via_stdin_not_argv(self):
        svc = BwSessionService()
        svc._session = FAKE_SESSION
        list_result = _completed(stdout="[]")
        create_result = _completed(stdout=json.dumps({"id": "fld-new", "name": "Servonaut"}))
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", side_effect=[list_result, create_result]
        ) as mock_run:
            _run(svc.ensure_servonaut_folder())
        create_call = mock_run.call_args_list[1]
        argv = create_call.args[0]
        encoded = create_call.kwargs["input"]
        # The payload is exactly the argv-free stdin channel.
        assert argv == ["bw", "create", "folder"]
        assert encoded not in argv
        decoded = json.loads(base64.b64decode(encoded))
        assert decoded == {"name": "Servonaut"}

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

    def test_fingerprint_populated_from_ssh_key(self):
        summary = BwSessionService._to_summary(_ssh_item("ssh-1", "key"))
        assert summary.fingerprint == "SHA256:abc"
        # The summary must stay secret-free even with the fingerprint on board.
        assert "SECRET" not in repr(summary)

    def test_fingerprint_defaults_to_none(self):
        assert BwSessionService._to_summary(_login_item("l-1", "n", "u")).fingerprint is None
        item = {"id": "x", "name": "k", "type": 5, "sshKey": {"publicKey": "ssh-ed25519 AAAA"}}
        assert BwSessionService._to_summary(item).fingerprint is None


# ---------------------------------------------------------------------------
# create_ssh_key_item()
# ---------------------------------------------------------------------------

# Neutral test fixture — never a real key.
FAKE_PRIVATE_KEY = openssh_armor("FAKEKEYBODY")
FAKE_PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE test@example"
FAKE_FINGERPRINT = "SHA256:FaKeFingerprint000000000000000000000000000"


class TestCreateSshKeyItem:
    def _svc(self) -> BwSessionService:
        svc = BwSessionService()
        svc._session = FAKE_SESSION
        return svc

    def test_success_pipes_payload_via_stdin(self):
        svc = self._svc()
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run",
            return_value=_completed(stdout=json.dumps({"id": "item-new", "name": "web-1 key"})),
        ) as mock_run:
            item_id = _run(
                svc.create_ssh_key_item(
                    name="web-1 key",
                    private_key=FAKE_PRIVATE_KEY,
                    public_key=FAKE_PUBLIC_KEY,
                    key_fingerprint=FAKE_FINGERPRINT,
                )
            )
        assert item_id == "item-new"

        argv = mock_run.call_args.args[0]
        encoded = mock_run.call_args.kwargs["input"]
        assert argv == ["bw", "create", "item"]
        # The encoded payload and the raw key must NEVER appear on argv.
        assert encoded not in argv
        assert all(FAKE_PRIVATE_KEY not in str(tok) for tok in argv)
        # Decoded stdin payload matches the bw type-5 contract.
        decoded = json.loads(base64.b64decode(encoded))
        assert decoded == {
            "type": 5,
            "name": "web-1 key",
            "notes": None,
            "folderId": None,
            "sshKey": {
                "privateKey": FAKE_PRIVATE_KEY,
                "publicKey": FAKE_PUBLIC_KEY,
                "keyFingerprint": FAKE_FINGERPRINT,
            },
        }
        # Session travels via env, never argv.
        assert mock_run.call_args.kwargs["env"]["BW_SESSION"] == FAKE_SESSION
        assert FAKE_SESSION not in argv

    def test_folder_id_included_in_payload(self):
        svc = self._svc()
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout=json.dumps({"id": "item-2"}))
        ) as mock_run:
            _run(
                svc.create_ssh_key_item(
                    name="key",
                    private_key=FAKE_PRIVATE_KEY,
                    public_key=FAKE_PUBLIC_KEY,
                    key_fingerprint=FAKE_FINGERPRINT,
                    folder_id="fld-7",
                )
            )
        decoded = json.loads(base64.b64decode(mock_run.call_args.kwargs["input"]))
        assert decoded["folderId"] == "fld-7"

    def test_nonzero_exit_raises_create_error_without_key_material(self):
        svc = self._svc()
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run",
            return_value=_completed(stderr="Invalid item type.", returncode=1),
        ):
            with pytest.raises(BwCreateError) as excinfo:
                _run(
                    svc.create_ssh_key_item(
                        name="key",
                        private_key=FAKE_PRIVATE_KEY,
                        public_key=FAKE_PUBLIC_KEY,
                        key_fingerprint=FAKE_FINGERPRINT,
                    )
                )
        # The user-facing message never embeds the payload or the key body.
        assert "FAKEKEYBODY" not in str(excinfo.value)
        assert FAKE_PRIVATE_KEY not in str(excinfo.value)
        # Raw stderr is never excerpted either — a future bw version could
        # echo part of the parsed stdin request (which carries the key).
        assert "Invalid item type" not in str(excinfo.value)

    def test_locked_session_stderr_is_classified(self):
        svc = self._svc()
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run",
            return_value=_completed(stderr="Vault is locked.", returncode=1),
        ):
            with pytest.raises(BwSessionMissingError):
                _run(
                    svc.create_ssh_key_item(
                        name="key",
                        private_key=FAKE_PRIVATE_KEY,
                        public_key=FAKE_PUBLIC_KEY,
                        key_fingerprint=FAKE_FINGERPRINT,
                    )
                )

    @pytest.mark.parametrize("stdout", ["not json", "{}", json.dumps({"name": "no id here"})])
    def test_malformed_stdout_raises_create_error(self, stdout):
        svc = self._svc()
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout=stdout)
        ):
            with pytest.raises(BwCreateError):
                _run(
                    svc.create_ssh_key_item(
                        name="key",
                        private_key=FAKE_PRIVATE_KEY,
                        public_key=FAKE_PUBLIC_KEY,
                        key_fingerprint=FAKE_FINGERPRINT,
                    )
                )

    def test_no_session_raises_before_subprocess(self):
        svc = BwSessionService()  # locked — no session
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run"
        ) as mock_run:
            with pytest.raises(BwSessionMissingError):
                _run(
                    svc.create_ssh_key_item(
                        name="key",
                        private_key=FAKE_PRIVATE_KEY,
                        public_key=FAKE_PUBLIC_KEY,
                        key_fingerprint=FAKE_FINGERPRINT,
                    )
                )
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# sync_now()
# ---------------------------------------------------------------------------


class TestSyncNow:
    def test_success_runs_bw_sync_with_session_env(self):
        svc = BwSessionService()
        svc._session = FAKE_SESSION
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout="Syncing complete.")
        ) as mock_run:
            _run(svc.sync_now())
        argv = mock_run.call_args.args[0]
        assert argv == ["bw", "sync"]
        assert mock_run.call_args.kwargs["env"]["BW_SESSION"] == FAKE_SESSION

    def test_nonzero_exit_is_swallowed(self):
        svc = BwSessionService()
        svc._session = FAKE_SESSION
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stderr="boom", returncode=1)
        ):
            _run(svc.sync_now())  # must not raise

    def test_subprocess_failure_is_swallowed(self):
        svc = BwSessionService()
        svc._session = FAKE_SESSION
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", side_effect=TimeoutExpired(cmd="bw", timeout=20)
        ):
            _run(svc.sync_now())  # must not raise

    def test_locked_session_is_swallowed(self):
        svc = BwSessionService()  # no session at all
        _run(svc.sync_now())  # must not raise
