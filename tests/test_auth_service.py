"""Tests for AuthService."""
from __future__ import annotations

import asyncio
import json
import os
import stat
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.services.auth_service import AuthService, AuthToken, AUTH_FILE


def run(coro):
    """Run a coroutine synchronously (no pytest-asyncio required)."""
    return asyncio.run(coro)


@pytest.fixture
def auth_service(tmp_path, monkeypatch):
    """AuthService with temp auth file."""
    auth_file = tmp_path / "auth.json"
    monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
    return AuthService()


@pytest.fixture
def authenticated_service(tmp_path, monkeypatch):
    """AuthService with a valid token pre-loaded."""
    auth_file = tmp_path / "auth.json"
    token_data = {
        "access_token": "test-access-token",
        "refresh_token": "test-refresh-token",
        "expires_at": time.time() + 3600,
        "plan": "solo",
        "entitlements": {
            "plan": "solo",
            "features": {
                "config_sync": True,
                "premium_ai": True,
                "gcp_support": True,
                "azure_support": True,
            },
        },
        "entitlements_fetched_at": time.time(),
    }
    auth_file.write_text(json.dumps(token_data))
    monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
    return AuthService()


class TestAuthServiceBasic:
    def test_unauthenticated_by_default(self, auth_service):
        assert not auth_service.is_authenticated
        assert auth_service.plan == "free"
        assert auth_service.access_token is None

    def test_has_feature_when_unauthenticated(self, auth_service):
        assert not auth_service.has_feature("config_sync")

    def test_authenticated_state(self, authenticated_service):
        assert authenticated_service.is_authenticated
        assert authenticated_service.plan == "solo"
        assert authenticated_service.access_token == "test-access-token"

    def test_has_feature_when_authenticated(self, authenticated_service):
        assert authenticated_service.has_feature("config_sync")
        assert authenticated_service.has_feature("premium_ai")
        assert not authenticated_service.has_feature("team_workspace")

    def test_has_feature_against_real_staging_payload(self, tmp_path, monkeypatch):
        """Regression: gates broke when staging started shipping flat
        entitlements alongside numeric quotas. Pin the real shape so a
        future "simplification" of the merge can't silently re-hide
        Memory Sync from a paying user.
        """
        staging_payload = {
            "config_snapshots": 30,
            "ai_requests_per_day": 50,
            "mcp_connections": 1,
            "team_members": 0,
            "ovh_mcp_operations": 50,
            "memory_sync": 1,
            "memory_drift": 1,
            "memory_digest": 1,
        }
        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "access_token": "stg",
            "refresh_token": "stg-r",
            "expires_at": time.time() + 3600,
            "plan": "solo",
            "entitlements": staging_payload,
            "entitlements_fetched_at": time.time(),
        }))
        monkeypatch.setattr(
            "servonaut.services.auth_service.AUTH_FILE", auth_file
        )
        svc = AuthService()
        assert svc.has_feature("memory_sync")
        assert svc.has_feature("memory_drift")
        assert svc.has_feature("memory_digest")
        # Plan-default fallback still applies for keys the backend
        # didn't enumerate (config_sync isn't in this payload).
        assert svc.has_feature("config_sync")
        # Numeric quotas (>1) must NOT be promoted to features.
        assert not svc.has_feature("config_snapshots")
        assert not svc.has_feature("ai_requests_per_day")

    def test_get_status_unauthenticated(self, auth_service):
        status = auth_service.get_status()
        assert not status["authenticated"]
        assert status["plan"] == "free"

    def test_get_status_authenticated(self, authenticated_service):
        status = authenticated_service.get_status()
        assert status["authenticated"]
        assert status["plan"] == "solo"


class TestAuthTokenPersistence:
    def test_token_saved_and_loaded(self, tmp_path, monkeypatch):
        auth_file = tmp_path / "auth.json"
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)

        svc = AuthService()
        svc._token = AuthToken(
            access_token="abc",
            refresh_token="def",
            expires_at=time.time() + 3600,
            plan="solo",
        )
        svc._save_token()

        assert auth_file.exists()
        data = json.loads(auth_file.read_text())
        assert data["access_token"] == "abc"

        # Load in new instance
        svc2 = AuthService()
        assert svc2._token.access_token == "abc"

    def test_locally_expired_access_token_still_authenticated(
        self, tmp_path, monkeypatch
    ):
        """Local 1h access-token TTL must NOT flip the session to logged-out.

        The server is the source of truth — the 401-retry-refresh path heals
        a stale access_token transparently. Returning False here is the bug
        that caused users to be kicked out mid-session even though their
        refresh_token was still valid (servonaut-web-backend confirmed on
        agent-bus thread 0ab60c52).
        """
        auth_file = tmp_path / "auth.json"
        token_data = {
            "access_token": "expired-locally-but-server-doesnt-know-yet",
            "refresh_token": "still-valid",
            "expires_at": time.time() - 100,
            "plan": "solo",
            "entitlements": {},
            "entitlements_fetched_at": 0,
        }
        auth_file.write_text(json.dumps(token_data))
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
        svc = AuthService()
        assert svc.is_authenticated, (
            "Locally-expired access_token must still report authenticated; "
            "the 401-retry path is responsible for refreshing it transparently."
        )
        # access_token property must hand out the (stale) token so APIClient
        # actually sends a request — that request will 401 and trigger the
        # refresh. Returning None here would skip the Authorization header
        # entirely and short-circuit the whole flow.
        assert svc.access_token == "expired-locally-but-server-doesnt-know-yet"

    def test_no_refresh_token_means_not_authenticated(
        self, tmp_path, monkeypatch
    ):
        """Without a refresh_token there is no way to heal a stale session."""
        auth_file = tmp_path / "auth.json"
        token_data = {
            "access_token": "lonely-access-token",
            "refresh_token": "",
            "expires_at": time.time() + 3600,
            "plan": "solo",
            "entitlements": {},
            "entitlements_fetched_at": 0,
        }
        auth_file.write_text(json.dumps(token_data))
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
        svc = AuthService()
        assert not svc.is_authenticated

    def test_corrupt_auth_file(self, tmp_path, monkeypatch):
        auth_file = tmp_path / "auth.json"
        auth_file.write_text("not json")
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
        svc = AuthService()
        assert not svc.is_authenticated


class TestAuthTokenFilePermissions:
    """auth.json holds bearer + refresh tokens; on-disk mode must be 0600."""

    def test_saved_file_is_mode_0600(self, tmp_path, monkeypatch):
        auth_file = tmp_path / "auth.json"
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
        svc = AuthService()
        svc._token = AuthToken(
            access_token="a", refresh_token="r",
            expires_at=time.time() + 3600, plan="solo",
        )
        svc._save_token()
        mode = auth_file.stat().st_mode & 0o777
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"

    def test_startup_fixup_rechmods_world_readable_file(self, tmp_path, monkeypatch):
        auth_file = tmp_path / "auth.json"
        token_data = {
            "access_token": "a", "refresh_token": "r",
            "expires_at": time.time() + 3600, "plan": "solo",
            "entitlements": {}, "entitlements_fetched_at": 0,
        }
        auth_file.write_text(json.dumps(token_data))
        os.chmod(auth_file, 0o644)
        assert (auth_file.stat().st_mode & 0o777) == 0o644

        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
        AuthService()  # triggers _load_token -> _ensure_secure_mode

        assert (auth_file.stat().st_mode & 0o777) == 0o600

    def test_atomic_write_leaves_no_tmp_file_on_success(self, tmp_path, monkeypatch):
        auth_file = tmp_path / "auth.json"
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
        svc = AuthService()
        svc._token = AuthToken(
            access_token="a", refresh_token="r",
            expires_at=time.time() + 3600, plan="solo",
        )
        svc._save_token()
        tmp = auth_file.with_suffix(auth_file.suffix + ".tmp")
        assert not tmp.exists(), "tmp file should have been replaced"
        assert auth_file.exists()

    def test_interrupted_write_preserves_original_file(self, tmp_path, monkeypatch):
        """Failure during write must not clobber the previous good token."""
        auth_file = tmp_path / "auth.json"
        # Seed a known-good token file first.
        good = {
            "access_token": "keep-me", "refresh_token": "keep-me-too",
            "expires_at": time.time() + 3600, "plan": "solo",
            "entitlements": {}, "entitlements_fetched_at": 0,
        }
        auth_file.write_text(json.dumps(good))
        os.chmod(auth_file, 0o600)
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)

        svc = AuthService()
        svc._token = AuthToken(
            access_token="NEW", refresh_token="NEW-REF",
            expires_at=time.time() + 3600, plan="solo",
        )
        # Force os.replace to blow up mid-save; original file must survive.
        with patch("servonaut.services.auth_service.os.replace",
                   side_effect=OSError("boom")):
            svc._save_token()

        data = json.loads(auth_file.read_text())
        assert data["access_token"] == "keep-me"
        tmp = auth_file.with_suffix(auth_file.suffix + ".tmp")
        # tmp may or may not exist depending on where OSError was raised; the
        # invariant we care about is that the live file wasn't partially written.


class TestAuthServiceLogout:
    def test_logout_clears_token(self, authenticated_service, tmp_path, monkeypatch):
        auth_file = tmp_path / "auth.json"
        # Re-save so the file exists
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
        authenticated_service._save_token()

        with patch("servonaut.services.auth_service.HAS_HTTPX", False):
            run(authenticated_service.logout())

        assert not authenticated_service.is_authenticated
        assert authenticated_service._token is None


class TestAuthTokenForwardCompatSkew:
    """Risk §3 — protect against a downgraded CLI seeing surplus keys on disk.

    A user who downgrades binaries may have a ``~/.servonaut/auth.json`` written
    by a newer build with extra fields. The naive ``AuthToken(**data)`` call
    raises ``TypeError`` and would wipe their session on every startup. The
    defensive path filters unknown keys and reloads.
    """

    def test_load_token_drops_unknown_keys(self, tmp_path, monkeypatch):
        auth_file = tmp_path / "auth.json"
        # A "future" payload with a key this CLI version doesn't recognise.
        future_data = {
            "access_token": "abc",
            "refresh_token": "def",
            "expires_at": time.time() + 3600,
            "plan": "solo",
            "entitlements": {},
            "entitlements_fetched_at": 0,
            # Surplus key — must NOT cause a crash.
            "future_field_we_havent_added_yet": "some-value",
            "another_unknown_thing": 42,
        }
        auth_file.write_text(json.dumps(future_data))
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)

        # Should not raise — the surplus keys are silently dropped.
        svc = AuthService()
        assert svc.is_authenticated
        assert svc._token.access_token == "abc"
        assert svc._token.plan == "solo"

    def test_allow_dangerous_ai_tools_propagated(self, tmp_path, monkeypatch):
        """Entitlements payload with the F4 flag → cached on AuthToken + property."""
        auth_file = tmp_path / "auth.json"
        token_data = {
            "access_token": "abc",
            "refresh_token": "def",
            "expires_at": time.time() + 3600,
            "plan": "teams",
            "entitlements": {},
            "entitlements_fetched_at": 0,
        }
        auth_file.write_text(json.dumps(token_data))
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)

        svc = AuthService()
        # Apply a fake entitlements payload (flat shape, current backend).
        svc._apply_entitlements({
            "plan": "teams",
            "premium_ai": True,
            "allow_dangerous_ai_tools": True,
        })
        assert svc.has_dangerous_ai_tools is True
        # Toggle off — property must reflect.
        svc._apply_entitlements({
            "plan": "teams",
            "premium_ai": True,
            "allow_dangerous_ai_tools": False,
        })
        assert svc.has_dangerous_ai_tools is False
        # Unauthenticated → property is False even if the cache says True.
        svc._apply_entitlements({
            "plan": "teams",
            "premium_ai": True,
            "allow_dangerous_ai_tools": True,
        })
        svc._token = None
        assert svc.has_dangerous_ai_tools is False

    def test_premium_ai_was_active_tracks_transitions(self, tmp_path, monkeypatch):
        """Risk §5 — was_active snapshots the prior current value before write.

        Sequence we care about:
        1. First fetch with premium_ai=true: was_active should be False (no
           prior entitlements) → caller sees the False→True activation edge.
        2. Second fetch with premium_ai=true: was_active becomes True (matches
           the prior state) → caller sees no edge.
        3. Third fetch with premium_ai=false: was_active is True, current is
           False → caller observes the True→False lapse edge.
        """
        auth_file = tmp_path / "auth.json"
        token_data = {
            "access_token": "abc",
            "refresh_token": "def",
            "expires_at": time.time() + 3600,
            "plan": "free",
            "entitlements": {},
            "entitlements_fetched_at": 0,
        }
        auth_file.write_text(json.dumps(token_data))
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)

        svc = AuthService()

        # 1) First-time activation. Prior entitlements were empty → was_active
        #    snapshots False. The new payload sets premium_ai=True.
        svc._apply_entitlements({
            "plan": "solo",
            "premium_ai": True,
        })
        assert svc._token.premium_ai_was_active is False
        assert svc.has_feature("premium_ai") is True

        # 2) Second fetch — same value. was_active should now be True
        #    (snapshotted from step 1's current state).
        svc._apply_entitlements({
            "plan": "solo",
            "premium_ai": True,
        })
        assert svc._token.premium_ai_was_active is True
        assert svc.has_feature("premium_ai") is True

        # 3) Lapse — premium_ai flips to False. was_active is the prior True,
        #    current is False, so a consumer observes (True && !current) ==
        #    "lapsed" edge.
        svc._apply_entitlements({
            "plan": "free",
            "premium_ai": False,
        })
        assert svc._token.premium_ai_was_active is True
        assert svc.has_feature("premium_ai") is False


# ---------------------------------------------------------------------------
# B3 — await_post_topup_refresh blocks inline for the one-shot CLI
# ---------------------------------------------------------------------------


def test_post_topup_refresh_in_oneshot_loop_blocks_inline():
    """B3 — ``await_post_topup_refresh`` actually awaits the entitlements
    fetch.

    The TUI variant ``schedule_post_topup_refresh`` creates +30s/+60s
    tasks via :func:`asyncio.create_task`; in a one-shot CLI invocation
    those tasks die when ``asyncio.run`` exits. This new method blocks
    until the fetch lands so the CLI process can guarantee the refresh
    completed before exit.

    We monkey the wait_seconds down to ~0 so the test runs fast.
    """

    async def _exercise() -> int:
        auth = AuthService.__new__(AuthService)
        auth._token = AuthToken(
            access_token="fake",
            refresh_token="fake_refresh",
            expires_at=2 ** 31,
            plan="solo",
        )
        fetch = AsyncMock(return_value=None)
        auth.fetch_entitlements = fetch  # type: ignore[method-assign]

        captured: list = []
        await auth.await_post_topup_refresh(
            progress_callback=captured.append,
            wait_seconds=0.0,
        )
        # Fetch was awaited exactly once.
        assert fetch.await_count == 1
        # Progress callback was called for each lifecycle stage.
        assert any("Waiting" in s for s in captured)
        assert any("Refreshing" in s for s in captured)
        return fetch.await_count

    count = run(_exercise())
    assert count == 1


def test_await_post_topup_refresh_swallows_fetch_failures():
    """B3 — a failing fetch_entitlements does NOT crash the CLI.

    ``await_post_topup_refresh`` must log the failure but return
    cleanly so the user's CLI process exits 0 and the next
    ``servonaut ai quota`` invocation can recover.
    """

    async def _exercise() -> None:
        auth = AuthService.__new__(AuthService)
        auth._token = AuthToken(
            access_token="fake",
            refresh_token="fake_refresh",
            expires_at=2 ** 31,
            plan="solo",
        )
        auth.fetch_entitlements = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("network down"),
        )
        await auth.await_post_topup_refresh(wait_seconds=0.0)

    # Expectation: returns without raising.
    run(_exercise())


# ---------------------------------------------------------------------------
# Refresh-race + smart failure classification
# (servonaut-web-backend agent-bus thread 0ab60c52)
# ---------------------------------------------------------------------------


class _FakeResponse:
    """Bare-minimum httpx.Response stand-in for refresh_token unit tests."""

    def __init__(self, status_code: int, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict:
        return self._payload


def _seed_authed_service(tmp_path, monkeypatch, refresh_token_value="R0"):
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(
        json.dumps({
            "access_token": "A0",
            "refresh_token": refresh_token_value,
            "expires_at": time.time() - 1,  # locally expired by design
            "plan": "solo",
            "entitlements": {},
            "entitlements_fetched_at": 0,
        })
    )
    monkeypatch.setattr(
        "servonaut.services.auth_service.AUTH_FILE", auth_file
    )
    return AuthService(), auth_file


def test_refresh_skips_network_when_disk_already_rotated(tmp_path, monkeypatch):
    """Concurrent-refresh dedup: if another task rotated while we waited
    for the lock, adopt the disk token without hitting the network.

    This is the exact race servonaut-web-backend pointed at: two parallel
    401-retries each call refresh with the same R_0; without the lock +
    disk re-read, the second one would present a now-revoked token and
    get 400 invalid_grant, killing the session.
    """
    svc, auth_file = _seed_authed_service(tmp_path, monkeypatch, "R0")

    # Simulate another task having already rotated to R_1 / A_1 on disk.
    auth_file.write_text(json.dumps({
        "access_token": "A1",
        "refresh_token": "R1",
        "expires_at": time.time() + 3600,
        "plan": "solo",
        "entitlements": {},
        "entitlements_fetched_at": 0,
    }))

    network_called = {"count": 0}

    def _fail_if_called(*_args, **_kwargs):
        network_called["count"] += 1
        raise AssertionError(
            "refresh_token must NOT hit the network when disk already shows "
            "a newer refresh_token than the one we presented"
        )

    with patch(
        "servonaut.services.auth_service.httpx.AsyncClient",
        side_effect=_fail_if_called,
    ):
        ok = run(svc.refresh_token())

    assert ok is True
    assert svc._token.access_token == "A1"
    assert svc._token.refresh_token == "R1"
    assert network_called["count"] == 0


def test_refresh_invalid_grant_sets_revoked_flag(tmp_path, monkeypatch):
    """400 invalid_grant means the refresh_token is genuinely dead.

    The sticky flag flips ``is_authenticated`` to False, which tells the
    UI to prompt for re-login rather than spin on doomed retries.
    """
    svc, _ = _seed_authed_service(tmp_path, monkeypatch, "R0")

    fake_client = MagicMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.post = AsyncMock(return_value=_FakeResponse(
        400, {"error": {"code": "invalid_grant", "message": "revoked"}},
    ))

    with patch(
        "servonaut.services.auth_service.httpx.AsyncClient",
        return_value=fake_client,
    ):
        ok = run(svc.refresh_token())

    assert ok is False
    assert svc._refresh_grant_revoked is True
    assert svc.is_authenticated is False
    # Sanity: the token wasn't preemptively cleared — file lifecycle is
    # owned by validate_token / logout. refresh_token only sets the flag.
    assert svc._token is not None


def test_refresh_429_is_transient_keeps_session(tmp_path, monkeypatch):
    """Per-IP rate limiter returns 429 under burst; that must NOT log the
    user out. The token stays usable; the next 401-retry will try again.
    """
    svc, _ = _seed_authed_service(tmp_path, monkeypatch, "R0")

    fake_client = MagicMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.post = AsyncMock(return_value=_FakeResponse(
        429, {"error": {"code": "rate_limited", "message": "slow down"}},
    ))

    with patch(
        "servonaut.services.auth_service.httpx.AsyncClient",
        return_value=fake_client,
    ):
        ok = run(svc.refresh_token())

    assert ok is False
    assert svc._refresh_grant_revoked is False
    assert svc.is_authenticated is True


def test_refresh_5xx_is_transient_keeps_session(tmp_path, monkeypatch):
    """Symfony fault → 5xx must NOT log the user out."""
    svc, _ = _seed_authed_service(tmp_path, monkeypatch, "R0")

    fake_client = MagicMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.post = AsyncMock(return_value=_FakeResponse(503))

    with patch(
        "servonaut.services.auth_service.httpx.AsyncClient",
        return_value=fake_client,
    ):
        ok = run(svc.refresh_token())

    assert ok is False
    assert svc._refresh_grant_revoked is False
    assert svc.is_authenticated is True


def test_refresh_network_error_is_transient_keeps_session(tmp_path, monkeypatch):
    """Connection error → keep credentials; user reconnects later."""
    svc, _ = _seed_authed_service(tmp_path, monkeypatch, "R0")

    fake_client = MagicMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.post = AsyncMock(side_effect=RuntimeError("connection refused"))

    with patch(
        "servonaut.services.auth_service.httpx.AsyncClient",
        return_value=fake_client,
    ):
        ok = run(svc.refresh_token())

    assert ok is False
    assert svc._refresh_grant_revoked is False
    assert svc.is_authenticated is True


def test_refresh_success_clears_revoked_flag(tmp_path, monkeypatch):
    """A successful refresh after a transient blip clears any stale flag."""
    svc, _ = _seed_authed_service(tmp_path, monkeypatch, "R0")
    # Pretend a prior call set the flag (e.g. a 401 from /oauth/refresh
    # during a server hiccup) — the next good response must clear it.
    svc._refresh_grant_revoked = True

    fake_client = MagicMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.post = AsyncMock(return_value=_FakeResponse(200, {
        "access_token": "A1",
        "refresh_token": "R1",
        "expires_in": 3600,
        "email": "user@example.com",
    }))

    with patch(
        "servonaut.services.auth_service.httpx.AsyncClient",
        return_value=fake_client,
    ):
        ok = run(svc.refresh_token())

    assert ok is True
    assert svc._refresh_grant_revoked is False
    assert svc._token.access_token == "A1"
    assert svc._token.refresh_token == "R1"


def test_concurrent_refresh_serialises_under_lock(tmp_path, monkeypatch):
    """Two parallel refresh_token() calls must not both hit the wire.

    Lock semantics: caller A wins the race, does the network call,
    persists (A_1, R_1) to disk. Caller B then sees the disk has moved
    on and short-circuits without a network round-trip — exactly the
    fix the backend recommended.
    """
    svc, _ = _seed_authed_service(tmp_path, monkeypatch, "R0")

    call_count = {"count": 0}
    entered = asyncio.Event()
    proceed = asyncio.Event()

    async def _slow_post(*_args, **_kwargs):
        call_count["count"] += 1
        entered.set()
        # Hold the network call open until the test releases us, so the
        # second caller is guaranteed to be parked on the lock.
        await proceed.wait()
        return _FakeResponse(200, {
            "access_token": "A1",
            "refresh_token": "R1",
            "expires_in": 3600,
        })

    fake_client = MagicMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.post = AsyncMock(side_effect=_slow_post)

    async def _exercise() -> tuple[bool, bool]:
        with patch(
            "servonaut.services.auth_service.httpx.AsyncClient",
            return_value=fake_client,
        ):
            a = asyncio.create_task(svc.refresh_token())
            await entered.wait()  # A is now inside the network call
            b = asyncio.create_task(svc.refresh_token())
            # Give B a chance to reach the lock and park.
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            proceed.set()  # release A
            return await a, await b

    a_ok, b_ok = run(_exercise())
    assert a_ok is True and b_ok is True
    # Critical: only ONE network call, not two.
    assert call_count["count"] == 1, (
        f"expected exactly 1 network refresh under the lock, got "
        f"{call_count['count']} — the lock or dedup is broken"
    )
    assert svc._token.refresh_token == "R1"
