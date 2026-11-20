"""Self-tests for FakeCloud's client-version policy and HTTP 426 gate.

Verifies the FakeCloud contract that the TUI, CLI, MCP, and relay journeys
rely on:

* ``GET /api/v1/client/version-policy`` is unauthenticated, returns
  ``Cache-Control``, reflects ``FakeCloud.set_client_version_policy`` /
  ``configure``, and resets to ``mode="off"`` on ``FakeCloud.reset()``.
* ``mode="off"`` and ``mode="log"`` never refuse clients below the floor;
  ``mode="enforce"`` refuses gated routes with HTTP 426,
  ``Upgrade: servonaut/<min>``, and the ``client_update_required`` envelope.
* PEP 440 ordering governs comparison (``99.0.0rc1 < 99.0.0``,
  ``99.0.0+local >= 99.0.0``), ``User-Agent`` works as fallback, and missing
  or unparseable versions are allowed per contract.
* Only the contract's API prefixes are gated. Sign-in, policy discovery,
  relay status, hosted MCP, and other routes bypass the version gate.
"""

from __future__ import annotations

import httpx
import pytest

from e2e.harness.fake_cloud.control import CONTROL_PREFIX
from e2e.harness.fake_cloud.routes_ai import CONVERSATIONS_PATH
from e2e.harness.fake_cloud.routes_pypi import PYPI_JSON_PATH
from servonaut.services.version_policy import (
    DEFAULT_UPDATE_URL,
    VERSION_POLICY_PATH,
    VersionPolicyClient,
)

pytestmark = [pytest.mark.e2e_pr]
OLD_CLIENT = "1.0.0; channel=stable; kind=cli"


def _client(fake_cloud, *, headers: dict[str, str] | None = None) -> httpx.Client:
    return httpx.Client(base_url=fake_cloud.url, headers=headers or {}, timeout=10)


def test_version_policy_endpoint_entitlements_and_reset(fake_cloud):
    access, _ = fake_cloud.tokens()
    with _client(fake_cloud) as client:
        default_resp = client.get(VERSION_POLICY_PATH)
        assert default_resp.status_code == 200
        assert "max-age=" in default_resp.headers.get("cache-control", "")
        default_doc = default_resp.json()
        assert default_doc["mode"] == "off"
        assert default_doc["minimum_version"] is None
        assert default_doc["update_url"] == DEFAULT_UPDATE_URL

        fake_cloud.set_client_version_policy(
            mode="enforce",
            minimum_version="99.0.0",
            upcoming={"minimum_version": "100.0.0", "effective_at": "2030-06-01T00:00:00Z"},
            latest={"stable": "99.1.0", "rc": "99.2.0rc1"},
            update_hints={"pipx": "pipx upgrade servonaut"},
        )
        enforced_resp = client.get(VERSION_POLICY_PATH)
        assert enforced_resp.status_code == 200
        enforced_doc = enforced_resp.json()
        assert enforced_doc["mode"] == "enforce"
        assert enforced_doc["minimum_version"] == "99.0.0"
        assert enforced_doc["upcoming"] == {
            "minimum_version": "100.0.0",
            "effective_at": "2030-06-01T00:00:00Z",
        }
        assert enforced_doc["latest"] == {"stable": "99.1.0", "rc": "99.2.0rc1"}
        assert enforced_doc["update_hints"] == {"pipx": "pipx upgrade servonaut"}

        ents = client.get(
            "/api/entitlements",
            headers={
                "Authorization": f"Bearer {access}",
                "X-Servonaut-Client": "1.0.0; channel=stable; kind=cli",
            },
        )
        assert ents.status_code == 200
        assert ents.json()["client_version_policy"] == enforced_doc

        fake_cloud.reset()
        after_reset = client.get(VERSION_POLICY_PATH).json()
        assert after_reset["mode"] == "off"
        assert after_reset["minimum_version"] is None

    with pytest.raises(ValueError, match="client_version_mode"):
        fake_cloud.configure(client_version_mode="invalid")
    with pytest.raises(ValueError, match="client_minimum_version"):
        fake_cloud.configure(client_minimum_version="not-a-version")


def test_modes_and_pep440_boundaries(fake_cloud):
    fake_cloud.configure(plan="teams")
    access, _ = fake_cloud.tokens()
    auth = {"Authorization": f"Bearer {access}"}
    old_headers = {**auth, "X-Servonaut-Client": OLD_CLIENT}
    latest = {"stable": "99.1.0", "rc": "99.2.0rc1"}

    with _client(fake_cloud) as client:
        for mode in ("off", "log"):
            fake_cloud.set_client_version_policy(mode=mode, minimum_version="99.0.0")
            resp = client.get(CONVERSATIONS_PATH, headers=old_headers)
            assert resp.status_code == 200, (mode, resp.text)
            logged = fake_cloud.requests(CONVERSATIONS_PATH)[-1]
            assert logged["client_header"] == OLD_CLIENT
            assert logged.get("below_minimum", False) is (mode == "log")

        fake_cloud.set_client_version_policy(
            mode="enforce", minimum_version="99.0.0", latest=latest,
        )
        refused = client.get(CONVERSATIONS_PATH, headers=old_headers)
        assert refused.status_code == 426
        assert refused.headers.get("upgrade") == "servonaut/99.0.0"
        assert refused.headers.get("cache-control") == "no-store"
        assert refused.json() == {"error": {
            "code": "client_update_required",
            "http": 426,
            "message": (
                "This version of Servonaut (1.0.0) is too old for team and cloud features. "
                f"Update to 99.0.0 or later: {DEFAULT_UPDATE_URL}"
            ),
            "details": {
                "client_version": "1.0.0",
                "minimum_version": "99.0.0",
                "latest_version": "99.1.0",
                "channel": "stable",
                "update_url": DEFAULT_UPDATE_URL,
            },
            "retry_after_seconds": None,
        }}

        rc_below = client.get(
            CONVERSATIONS_PATH,
            headers={**auth, "X-Servonaut-Client": "99.0.0rc1; channel=rc; kind=cli"},
        )
        assert rc_below.status_code == 426
        details = rc_below.json()["error"]["details"]
        assert details["channel"] == "rc" and details["latest_version"] == "99.1.0"

        for allowed_header in (
            "99.0.0; channel=stable; kind=cli",
            "99.0.0+local.1; channel=stable; kind=cli",
            "99.1.0; channel=stable; kind=cli",
            "unparseable-version",
        ):
            ok = client.get(CONVERSATIONS_PATH, headers={**auth, "X-Servonaut-Client": allowed_header})
            assert ok.status_code == 200, (allowed_header, ok.text)

        no_header = client.get(CONVERSATIONS_PATH, headers={**auth, "User-Agent": "custom-probe/1"})
        assert no_header.status_code == 200

        fake_cloud.set_client_version_policy(
            mode="enforce", minimum_version="99.0.0", latest={"stable": None, "rc": "99.2.0rc1"},
        )
        ua_old = client.get(CONVERSATIONS_PATH, headers={**auth, "User-Agent": "servonaut-cli/1.0.0"})
        assert ua_old.status_code == 426
        assert ua_old.json()["error"]["details"]["latest_version"] is None


@pytest.mark.parametrize(("index_version", "latest"), [
    ("99.2.0", {"stable": "99.2.0", "rc": None}),
    ("99.2.0rc1", {"stable": None, "rc": "99.2.0rc1"}),
])
def test_release_candidate_is_not_reported_as_latest_stable(fake_cloud, index_version, latest):
    fake_cloud.configure(pypi_version=index_version)
    fake_cloud.set_client_version_policy(mode="enforce", minimum_version="99.0.0")
    with _client(fake_cloud, headers={"X-Servonaut-Client": OLD_CLIENT}) as client:
        policy = client.get(VERSION_POLICY_PATH)
        refused = client.get(CONVERSATIONS_PATH)
    assert policy.status_code == 200 and policy.json()["latest"] == latest
    assert refused.status_code == 426
    assert refused.json()["error"]["details"]["latest_version"] == latest["stable"]


@pytest.mark.parametrize("path", [
    "/api/v1/teams/ops",
    "/api/v1/vault/ssh-ca",
    "/api/v1/vaults",
    "/api/v1/me/instances/fixture",
    "/api/v1/me/credential-bindings",
    "/api/ai/conversations",
    "/api/v1/findings",
    "/api/v1/ssh-ca/status",
    "/api/v1/memory",
    "/api/cli/mercure-token",
    "/api/cli/status/other",
])
def test_each_gated_prefix_refuses_an_old_client(fake_cloud, path):
    fake_cloud.set_client_version_policy(mode="enforce", minimum_version="99.0.0")
    with _client(fake_cloud, headers={"X-Servonaut-Client": OLD_CLIENT}) as client:
        response = client.get(path)
    assert response.status_code == 426
    assert response.json()["error"]["code"] == "client_update_required"


@pytest.mark.parametrize(("path", "status"), [
    ("/api/v1/me", 200),
    ("/api/cli/status", 200),
    ("/api/v1/health", 404),
    ("/api/bug-report", 404),
    ("/api/entitlements", 200),
    (VERSION_POLICY_PATH, 200),
    ("/api/v1/teams", 200),
    ("/api/v1/vault", 404),
    ("/api/v1/me/instances", 200),
    ("/api/ai", 404),
    ("/api/cli", 404),
    ("/api/unrelated", 404),
    ("/mcp/nonexistent", 404),
    ("/download", 404),
    (PYPI_JSON_PATH, 200),
    (f"{CONTROL_PREFIX}requests", 200),
])
def test_version_gate_leaves_other_routes_alone(fake_cloud, path, status):
    fake_cloud.configure(plan="teams")
    access, _ = fake_cloud.tokens()
    fake_cloud.set_client_version_policy(mode="enforce", minimum_version="99.0.0")
    with _client(fake_cloud, headers={
        "Authorization": f"Bearer {access}", "X-Servonaut-Client": OLD_CLIENT,
    }) as client:
        response = client.get(path)
    assert response.status_code == status


def test_sign_in_bug_reports_and_hosted_mcp_remain_available_under_enforce(fake_cloud):
    access, refresh = fake_cloud.tokens()
    fake_cloud.set_client_version_policy(mode="enforce", minimum_version="99.0.0")
    old_headers = {
        "Authorization": f"Bearer {access}",
        "X-Servonaut-Client": "1.0.0; channel=stable; kind=cli",
    }

    with _client(fake_cloud) as client:
        assert client.post(
            "/api/v1/bug-reports", headers=old_headers, json={"title": "Example report"},
        ).status_code == 201
        initialized = client.post(
            "/mcp", headers=old_headers,
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        )
        assert initialized.status_code == 200
        assert client.post("/api/oauth/device", headers=old_headers, json={}).status_code == 200
        assert client.post("/api/oauth/token", headers=old_headers, json={}).status_code == 200
        refreshed = client.post(
            "/api/oauth/refresh", headers=old_headers, json={"refresh_token": refresh},
        )
        assert refreshed.status_code == 200
        new_access = refreshed.json()["access_token"]
        assert client.post(
            "/api/oauth/revoke", headers=old_headers, json={"token": new_access},
        ).status_code == 200

def test_log_mode_marks_only_gated_requests_from_old_clients(fake_cloud):
    fake_cloud.configure(plan="teams")
    access, _ = fake_cloud.tokens()
    fake_cloud.set_client_version_policy(mode="log", minimum_version="99.0.0")
    auth = {"Authorization": f"Bearer {access}"}
    with _client(fake_cloud, headers=auth) as client:
        for path, headers, below_minimum in (
            ("/api/v1/me", {"X-Servonaut-Client": OLD_CLIENT}, False),
            (CONVERSATIONS_PATH, {"X-Servonaut-Client": OLD_CLIENT}, True),
            (CONVERSATIONS_PATH, {"User-Agent": "servonaut/1.0.0"}, True),
            (CONVERSATIONS_PATH, {"X-Servonaut-Client": "99.0.0"}, False),
            (CONVERSATIONS_PATH, {"X-Servonaut-Client": "unparseable-version"}, False),
        ):
            response = client.get(path, headers=headers)
            assert response.status_code == 200
            assert fake_cloud.requests(path)[-1].get("below_minimum", False) is below_minimum


@pytest.mark.asyncio
async def test_version_policy_client_fetches_and_caches_from_fake_cloud(fake_cloud, tmp_path):
    fake_cloud.set_client_version_policy(
        mode="enforce",
        minimum_version="99.0.0",
        update_hints={"pipx": "pipx upgrade servonaut"},
    )
    cache_path = tmp_path / "version-policy.json"
    client = VersionPolicyClient(cache_path=cache_path)

    policy = await client.fetch(force_refresh=True)
    assert policy is not None
    assert policy.mode == "enforce"
    assert policy.minimum_version == "99.0.0"
    assert policy.update_hints == {"pipx": "pipx upgrade servonaut"}
    assert cache_path.is_file()

    reqs = fake_cloud.requests(VERSION_POLICY_PATH)
    assert len(reqs) == 1
    assert reqs[0]["status"] == 200
    assert reqs[0]["authorization"] is None
    assert reqs[0]["client_header"]
