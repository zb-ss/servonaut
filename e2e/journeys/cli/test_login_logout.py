"""Journey: sign in and out from the command line with the device flow.

``servonaut login`` runs as a real child process against FakeCloud over TLS:
it prints the verification URL and code, keeps polling through "pending" and
"slow down" answers, and stores the session in ``auth.json`` (owner-only
permissions). ``ai quota --json`` then reads the entitlements with that
session, and ``logout`` revokes it and deletes the file. An expired device
code ends the attempt with an error and no session.
"""

from __future__ import annotations

import json
import stat

import pytest

from e2e.harness.bootstrap import load_guard
from e2e.harness.fake_cloud.state import USER_CODE

pytestmark = [pytest.mark.e2e_pr]


def _auth_file(sandbox):
    return sandbox.home / ".servonaut" / "auth.json"


def test_login_quota_and_logout(journey, fake_cloud, cli):
    sandbox = journey.new_sandbox()
    fake_cloud.configure(token_outcomes=["pending", "pending", "slow_down", "success"])

    login = cli(sandbox, "login", "--no-browser")
    assert login.returncode == 0, login.describe()
    assert f"{fake_cloud.url}/device" in login.stdout
    assert USER_CODE in login.stdout
    assert "Signed in successfully (plan: solo)" in login.stdout
    assert journey.shims.calls("browser") == []

    auth_file = _auth_file(sandbox)
    assert stat.S_IMODE(auth_file.stat().st_mode) == 0o600
    session = json.loads(auth_file.read_text())
    assert session["plan"] == "solo"
    assert session["user_id"] == 4242

    polls = fake_cloud.requests("/api/oauth/token")
    assert [p["status"] for p in polls] == [400, 400, 400, 200]
    assert fake_cloud.requests("/api/entitlements")[-1]["bearer_ok"]

    quota = cli(sandbox, "ai", "quota", "--json")
    assert quota.returncode == 0, quota.describe()
    assert json.loads(quota.stdout)["tokens_limit"] == 500000

    logout = cli(sandbox, "logout")
    assert logout.returncode == 0, logout.describe()
    assert "Signed out" in logout.stdout
    assert not auth_file.exists()
    revoke = fake_cloud.requests("/api/oauth/revoke")
    assert len(revoke) == 1
    assert revoke[0]["body"]["token"] == "<redacted>"  # never logged in clear

    again = cli(sandbox, "logout")
    assert again.returncode == 0, again.describe()
    assert "Not signed in" in again.stdout

    # None of the child processes tried to reach anything but FakeCloud.
    assert load_guard().read_log(journey.guard_log) == []


def test_expired_device_code_ends_without_a_session(journey, fake_cloud, cli):
    sandbox = journey.new_sandbox()
    fake_cloud.configure(token_outcomes=["expired"])

    login = cli(sandbox, "login")
    assert login.returncode == 1, login.describe()
    assert "Sign-in was not completed" in login.stderr
    assert not _auth_file(sandbox).exists()
    # Without --no-browser the verification page is offered to the browser.
    opened = [call.argv[-1] for call in journey.shims.calls("browser")]
    assert opened == [f"{fake_cloud.url}/device?user_code={USER_CODE}"]
