"""Journey: a command-line session outlives its access token.

``servonaut ai quota`` with an expired access token refreshes it (the
refresh token rotates and the new pair is saved) and retries; the next
expiry is healed with the rotated refresh token, which proves it was kept.
The quota reads the same in plain and JSON form, including the capped
states. ``ai conversations list`` shows the chat history. Signed out, both
point the user at ``servonaut login``.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness.account import read_session

pytestmark = [pytest.mark.e2e_pr]


def _statuses(fake_cloud, path):
    return [r["status"] for r in fake_cloud.requests(path)]


def test_quota_heals_expired_tokens_and_rotates_the_session(journey, fake_cloud, cli, account_home):
    home = account_home("cli-session")
    first_refresh = fake_cloud.tokens()[1]

    fresh = cli(home, "ai", "quota", "--json")
    assert fresh.returncode == 0, fresh.describe()
    assert json.loads(fresh.stdout)["tokens_used"] == 1200
    assert fake_cloud.requests("/api/oauth/refresh") == []

    fake_cloud.expire_access_token()
    healed = cli(home, "ai", "quota", "--json")
    assert healed.returncode == 0, healed.describe()
    assert json.loads(healed.stdout)["tokens_limit"] == 500000
    assert _statuses(fake_cloud, "/api/entitlements")[-2:] == [401, 200]
    assert _statuses(fake_cloud, "/api/oauth/refresh") == [200]
    saved = read_session(home.home)
    assert saved["refresh_token"] == fake_cloud.tokens()[1] != first_refresh

    # The service accepts only the rotated refresh token, so healing a
    # second expiry proves the CLI kept it.
    fake_cloud.configure(
        quota={**fake_cloud.entitlements()["quota"], "soft_capped": True},
    )
    fake_cloud.expire_access_token()
    plain = cli(home, "ai", "quota")
    assert plain.returncode == 0, plain.describe()
    assert _statuses(fake_cloud, "/api/oauth/refresh") == [200, 200]
    lines = plain.stdout.splitlines()
    assert lines[0].startswith("Tokens remaining: ")
    assert "Status: downgraded to faster model" in lines
    assert "Rate limits: 30 req/min, 60000 tokens/min" in lines

    out = cli(home, "logout")
    assert out.returncode == 0, out.describe()
    assert read_session(home.home) is None
    assert len(fake_cloud.requests("/api/oauth/revoke")) == 1


def test_conversation_history(journey, fake_cloud, cli, account_home):
    fake_cloud.account.configure(
        conversations=[
            {
                "id": "conv-e2e-1",
                "title": "Disk usage on web-1",
                "status": "active",
                "created_at": "2030-01-01T09:00:00+00:00",
                "updated_at": "2030-01-01T09:05:00+00:00",
                "message_count": 4,
                "last_model": "",
            },
            {
                "id": "conv-e2e-2",
                "title": "Old question",
                "status": "archived",
                "created_at": "2029-12-01T09:00:00+00:00",
                "updated_at": "2029-12-01T09:05:00+00:00",
                "message_count": 2,
                "last_model": "",
            },
        ]
    )
    home = account_home("cli-history")

    listed = cli(home, "ai", "conversations", "list")
    assert listed.returncode == 0, listed.describe()
    assert "conv-e2e-1" in listed.stdout and "Disk usage on web-1" in listed.stdout
    assert "conv-e2e-2" not in listed.stdout

    archived = cli(home, "ai", "conversations", "list", "--status", "archived", "--json")
    assert [c["id"] for c in json.loads(archived.stdout)] == ["conv-e2e-2"]


def test_signed_out_account_commands_ask_for_login(journey, fake_cloud, cli, account_home):
    home = account_home("cli-signed-out", signed_in=False)
    for args in (("ai", "quota"), ("ai", "conversations", "list")):
        result = cli(home, *args)
        assert result.returncode == 2, result.describe()
        assert "servonaut login" in result.stderr
    assert fake_cloud.requests() == []
