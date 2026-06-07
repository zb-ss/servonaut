"""Joint server↔CLI end-to-end tests for the secrets-management feature.

THIS FILE IS A SKIP-BY-DEFAULT SKELETON. The constants in
:class:`StagingBundle` are neutral placeholders; the gated test bodies
only run when the corresponding env vars point at a seeded staging
environment. With no env vars set (e.g. in CI) every gated test
auto-skips and only :class:`TestSkeletonPlumbing` executes.

Two test surfaces, two markers (see ``tests/conftest.py`` for the
auto-skip plumbing):

- :class:`TestJointE2E5_ContractHandshake` — pinned by
  ``@pytest.mark.requires_e2e_oauth``. Hits a real staging
  endpoint with a service-account OAuth bearer, verifies the CLI
  fetches the team's :class:`SecretsConfig`, parses it, and the
  resolver flips :class:`SSHService` from
  :class:`LocalProvider` to :class:`BitwardenProvider` with the
  right project_id + token_env_var. bws subprocess is STUBBED here
  — we're validating the contract between server and CLI, not bws.

- :class:`TestFullE2E3_RealStackSmoke` — pinned by
  ``@pytest.mark.requires_e2e_bws + requires_e2e_hetzner``
  (additive on top of the OAuth marker). Real bws subprocess +
  real Hetzner provisioning. Pre-prod smoke; nightly cron only.

Operational notes:

- The OAuth token in :data:`StagingBundle.oauth_token` rotates on a
  fixed cadence; rotation is handled out of band and this file's
  constants don't change.
- All credentials read from env vars, never hardcoded. The
  ``StagingBundle.from_env()`` helper produces a tidy bundle
  object the tests destructure from.

To run the gated tests against a seeded staging environment, set the
``SERVONAUT_E2E_*`` env vars described in ``StagingBundle.from_env``.
Everything else is wire-format-driven and shouldn't need a touch.
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Bundle defaults — neutral placeholders, overridable by env var
# ---------------------------------------------------------------------------

# The seeded team slug. Overridable via SERVONAUT_E2E_TEAM_SLUG so a
# staging seed can use a different slug — the rest of the file is
# wire-format-driven.
SEEDED_TEAM_SLUG = "example-team"

# Seeded Bitwarden project UUID — also overridable from the env. Compared
# to the value the server returns in the 200 body so a future server-side
# project rotation is observable in CI.
SEEDED_BWS_PROJECT_ID = "example-bws-project-uuid"

# Env var the team config tells the CLI to look in for the BWS access
# token. Matches DEFAULT_TOKEN_ENV_VAR on the CLI side; pinned here
# so a future server-side override surfaces in CI.
SEEDED_TOKEN_ENV_VAR = "BWS_ACCESS_TOKEN"

# Name of the SSH key stored in the seeded BWS project. Only the BWS
# path uses this; the contract test (E2E #5) doesn't touch real bws.
SEEDED_KEY_NAME = "e2e-test-key"

# Staging API base — overridable by env var so a developer can point
# the tests at a local dev instance without editing this file.
STAGING_API_BASE = os.environ.get(
    "SERVONAUT_E2E_API_BASE",
    "https://staging.example.com",
)


@dataclass(frozen=True)
class StagingBundle:
    """Concrete credentials + URLs collected from env vars at test time.

    Lifecycle:
        - Env vars set by CI (secret store) or nightly-cron runner.
        - :meth:`from_env` reads them once per test invocation.
        - Frozen dataclass so tests can't accidentally mutate state
          that should round-trip identically across cases.

    Basic auth note:
        A staging deployment may sit behind a site-wide basic_auth gate
        with a narrow public allowlist. If the
        ``/api/v1/teams/<slug>/secrets-config`` path is NOT in that
        allowlist, the request needs basic_auth credentials in
        addition to the OAuth Bearer. We thread them through
        :data:`basic_auth` for that case.
    """

    api_base: str
    team_slug: str
    oauth_token: str
    basic_auth: Optional[str]
    bws_project_id: str
    bws_token_env_var: str
    bws_token: Optional[str]
    hetzner_token: Optional[str]
    seeded_secret_name: str

    @classmethod
    def from_env(cls) -> "StagingBundle":
        """Read every env var the bundle depends on.

        Caller is responsible for ensuring the right markers are on
        the test so unset vars cause an auto-skip BEFORE we get here.
        Trips a defensive AssertionError if a required env var is
        somehow missing — preferable to a confusing failure mid-test.
        """
        oauth = os.environ.get("SERVONAUT_E2E_OAUTH_TOKEN", "")
        assert oauth, (
            "SERVONAUT_E2E_OAUTH_TOKEN must be set — marker auto-skip "
            "should have prevented this point being reached."
        )
        return cls(
            api_base=STAGING_API_BASE,
            team_slug=os.environ.get(
                "SERVONAUT_E2E_TEAM_SLUG", SEEDED_TEAM_SLUG,
            ),
            oauth_token=oauth,
            basic_auth=os.environ.get("SERVONAUT_E2E_BASIC_AUTH"),
            bws_project_id=os.environ.get(
                "SERVONAUT_E2E_BWS_PROJECT_ID", SEEDED_BWS_PROJECT_ID,
            ),
            bws_token_env_var=os.environ.get(
                "SERVONAUT_E2E_BWS_TOKEN_ENV_VAR", SEEDED_TOKEN_ENV_VAR,
            ),
            bws_token=os.environ.get("SERVONAUT_E2E_BWS_TOKEN"),
            hetzner_token=os.environ.get("SERVONAUT_E2E_HETZNER_TOKEN"),
            seeded_secret_name=SEEDED_KEY_NAME,
        )

    @property
    def api_base_with_auth(self) -> str:
        """``api_base`` ready to point :class:`APIClient` at.

        When the staging endpoint is fronted by a basic_auth gate that
        accepts any ``Authorization`` header, the Bearer alone passes
        and we must NOT url-embed basic auth — httpx would parse it into
        an ``Authorization: Basic`` header that overrides our Bearer,
        and the app would then see no Bearer and reject with 403.

        So: send Bearer alone via :meth:`APIClient._get_headers`.
        ``basic_auth`` is still captured on the bundle in case a future
        gateway policy tightens — we'd then thread it via a
        non-conflicting mechanism (e.g. ``Proxy-Authorization`` or a
        custom bypass header).
        """
        return self.api_base


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Test surface 1 — joint contract handshake (E2E #5)
# ---------------------------------------------------------------------------


@pytest.mark.requires_e2e_oauth
class TestJointE2E5_ContractHandshake:
    """The single most valuable test in this file.

    Validates that:
    1. CLI's :meth:`APIClient.get_team_secrets_config` against the
       real staging endpoint returns a parseable JSON body.
    2. The body's shape matches the locked contract.
    3. :class:`SecretsConfig.from_wire` accepts it.
    4. :meth:`AuthService.apply_secrets_config` persists it.
    5. :func:`resolve_secret_provider` flips
       :class:`SSHService` from :class:`LocalProvider` to
       :class:`BitwardenProvider` with the right project_id +
       token_env_var.

    What this test does NOT do:
    - Run bws (the subprocess is mocked).
    - Touch Hetzner.
    - Validate the SSH-into-real-server flow (that's E2E #3 below).

    Failure-mode taxonomy worth pinning so a future failure surface
    points at the right side:
    - 200 with wrong shape → wire-format drift (server side ships).
    - 401/403 → service-account token expired or scope revoked.
    - 404 → seed command didn't run / team got wiped.
    - 5xx → staging incident; this isn't a CLI bug.
    """

    def test_endpoint_returns_locked_contract_shape(self, tmp_path, monkeypatch):
        """End-to-end: real staging endpoint → CLI parses → resolver
        instantiates the right provider.

        Validates the server-side contract against the CLI parser. The
        402 / 403 / 404 paths are covered by unit tests; this test is
        specifically the 200 success path with a live wire payload.
        """
        bundle = StagingBundle.from_env()

        from servonaut.services.api_client import APIClient
        from servonaut.services.auth_service import AuthService, AuthToken
        from servonaut.services.entitlement_guard import EntitlementGuard
        from servonaut.services.secret_provider_resolver import (
            fetch_and_apply_secrets_config,
            resolve_secret_provider,
        )
        from servonaut.services.bitwarden_provider import BitwardenProvider

        # Build an isolated AuthService backed by a tmp auth.json so
        # this test can never trample a developer's real session.
        auth_file = tmp_path / "auth.json"
        monkeypatch.setattr(
            "servonaut.services.auth_service.AUTH_FILE", auth_file,
        )
        # Point APIClient at the staging base. Bearer alone passes the
        # gateway's basic_auth gate; basic auth is layered only as a
        # defensive fallback against a future policy tightening.
        monkeypatch.setenv("SERVONAUT_API_URL", bundle.api_base_with_auth)

        auth = AuthService()
        # Seed an in-memory token containing the staging OAuth bearer
        # and a Teams-tier plan so the entitlement gate opens. We
        # bypass the device-flow because we already have the token.
        import time as _time
        auth._token = AuthToken(
            access_token=bundle.oauth_token,
            # ``is_authenticated`` requires both access_token AND
            # refresh_token to be truthy (the v2.9.1 server-source-of-
            # truth fix). Refresh isn't exercised here; any non-empty
            # placeholder unblocks the gate.
            refresh_token="e2e-not-exercised-here",
            expires_at=_time.time() + 3600,
            plan="teams",
            entitlements={"plan": "teams", "secrets_management": True},
            entitlements_fetched_at=_time.time(),
        )

        guard = EntitlementGuard(auth)
        api = APIClient(auth)

        # 1. Fetch the real config from staging.
        ok = _run(fetch_and_apply_secrets_config(
            auth, api, slug=bundle.team_slug,
        ))
        assert ok, (
            "fetch_and_apply_secrets_config must succeed against the seeded "
            "team. If this assertion fails, check (a) OAuth token "
            "expiry, (b) any basic_auth policy on the endpoint, "
            "(c) staging-side seed health."
        )

        # 2. Parsed cache shape matches the locked contract.
        cfg = auth.cached_secrets_config()
        assert cfg.provider == "bitwarden", (
            f"server returned provider={cfg.provider!r}, expected 'bitwarden' "
            f"(the seed sets up Bitwarden, not Local)"
        )
        assert cfg.config.get("project_id") == bundle.bws_project_id, (
            f"project_id drift: server={cfg.config.get('project_id')!r}, "
            f"seed={bundle.bws_project_id!r}"
        )
        assert cfg.config.get("token_env_var") == bundle.bws_token_env_var
        # updated_at is an ATOM datetime in the server response.
        assert cfg.updated_at, "updated_at must be non-empty on a 200"

        # 3. Resolver flips to BitwardenProvider with the right args.
        provider = resolve_secret_provider(auth, guard)
        assert isinstance(provider, BitwardenProvider), (
            f"resolver returned {type(provider).__name__}, expected "
            f"BitwardenProvider for a team configured with provider=bitwarden"
        )
        assert provider.project_id == bundle.bws_project_id
        assert provider._token_env_var == bundle.bws_token_env_var

    def test_response_body_includes_team_slug_matching_url(self, tmp_path, monkeypatch):
        """Pin the additive ``team_slug`` echo as a frozen contract.

        The server includes an additive ``team_slug`` field in the
        response body. This test is a separate explicit assertion
        (rather than rolled into
        ``test_endpoint_returns_locked_contract_shape``) so a future
        regression names the new field specifically in the failure
        message — a future debugger sees ``team_slug`` verbatim and
        knows exactly which contract slot drifted.

        Failure mode taxonomy if this trips:

        - Field absent → server-side regression dropped the echo;
          the cached ``active_team_slug()`` path stops working
          silently. Operator wants to know.
        - Field present but mismatched → server-side slug-mapping
          bug. The CLI's WARNING-log handler catches this at runtime
          via ``fetch_and_apply_secrets_config``; this test pins it
          at the contract boundary.

        Belt-and-braces: the unit test in
        ``test_secrets_followups.py::TestSlugConsistencyWarning`` already
        pins the mismatch handling in isolation. This test pins the
        positive contract case against the real wire.
        """
        bundle = StagingBundle.from_env()

        from servonaut.services.api_client import APIClient
        from servonaut.services.auth_service import AuthService, AuthToken

        auth_file = tmp_path / "auth.json"
        monkeypatch.setattr(
            "servonaut.services.auth_service.AUTH_FILE", auth_file,
        )
        monkeypatch.setenv("SERVONAUT_API_URL", bundle.api_base_with_auth)

        auth = AuthService()
        import time as _time
        auth._token = AuthToken(
            access_token=bundle.oauth_token,
            refresh_token="e2e-not-exercised-here",
            expires_at=_time.time() + 3600,
            plan="teams",
            entitlements={"plan": "teams", "secrets_management": True},
            entitlements_fetched_at=_time.time(),
        )

        api = APIClient(auth)
        # Use the raw get_team_secrets_config (not the apply wrapper) so
        # we inspect the wire payload directly without the typed parser
        # dropping the field.
        payload = _run(api.get_team_secrets_config(slug=bundle.team_slug))
        assert payload is not None, (
            "Seeded team must return 200 with a payload — bundle / "
            "OAuth token may have rotated."
        )
        assert "team_slug" in payload, (
            "Additive contract regression: response body missing the "
            "team_slug echo. If it's gone, the CLI's cached "
            "active_team_slug() path silently falls back to list_teams "
            "bootstrap. Check the recent server-side changes."
        )
        assert payload["team_slug"] == bundle.team_slug, (
            f"team_slug echo mismatch: server returned "
            f"{payload['team_slug']!r}, URL slug was {bundle.team_slug!r}. "
            "Server-side slug-mapping inconsistency — the runtime WARNING "
            "in fetch_and_apply_secrets_config catches this for ops "
            "visibility, but the contract bound here is now broken."
        )

    def test_404_falls_back_to_local_provider(self, tmp_path, monkeypatch):
        """A team slug that doesn't have a config row on staging
        returns 404; the api_client.get_team_secrets_config wrapper
        translates that to None, fetch_and_apply clears the cache,
        and the resolver returns LocalProvider.

        Verifies the unhappy path against the live endpoint —
        complements the unit test
        TestGetTeamSecretsConfig404::test_404_with_envelope_returns_none
        which mocks the response.

        NB: the server collapses an unknown slug into a 403 to prevent
        enumeration. Since our service-account token is a MEMBER of the
        seeded team only, an unknown slug from this token's POV may
        surface as 404 (no-config-on-existing-team) or 403 (token not a
        member of slug-that-doesn't-exist). The test accepts EITHER
        outcome — both cause the same caller-side fallback to
        LocalProvider.
        """
        bundle = StagingBundle.from_env()

        from servonaut.services.api_client import APIClient, ForbiddenError
        from servonaut.services.auth_service import AuthService, AuthToken
        from servonaut.services.entitlement_guard import EntitlementGuard
        from servonaut.services.secret_provider_resolver import (
            fetch_and_apply_secrets_config,
            resolve_secret_provider,
        )
        from servonaut.services.secret_provider import LocalProvider

        auth_file = tmp_path / "auth.json"
        monkeypatch.setattr(
            "servonaut.services.auth_service.AUTH_FILE", auth_file,
        )
        # NOT monkeypatching LOCAL_PROVIDER_ROOT — the resolver's
        # fallback ``LocalProvider()`` constructs against the default
        # ``~/.servonaut/secrets.json``, which the production path
        # guard expects to live under ``~/.servonaut/`` (the real one).
        # We only ``isinstance`` the result; no actual file IO happens
        # so the test stays hermetic regardless.
        monkeypatch.setenv("SERVONAUT_API_URL", bundle.api_base_with_auth)

        auth = AuthService()
        import time as _time
        auth._token = AuthToken(
            access_token=bundle.oauth_token,
            # is_authenticated requires both tokens truthy
            # (v2.9.1 server-source-of-truth fix); refresh isn't
            # exercised in this test.
            refresh_token="e2e-not-exercised-here",
            expires_at=_time.time() + 3600,
            plan="teams",
            entitlements={"plan": "teams", "secrets_management": True},
            entitlements_fetched_at=_time.time(),
        )
        # Seed a stale Bitwarden cache that we EXPECT fetch to clear.
        auth.apply_secrets_config({
            "provider": "bitwarden",
            "config": {
                "project_id": "stale-project-id",
                "token_env_var": "BWS_ACCESS_TOKEN",
            },
            "updated_at": "2026-01-01T00:00:00Z",
        })
        assert auth.is_secrets_cache_present()

        guard = EntitlementGuard(auth)
        api = APIClient(auth)

        # Use a slug that's RFC1035-valid but won't have a config row.
        nonexistent_slug = "nonexistent-team-for-e2e-404-pin"
        ok = _run(fetch_and_apply_secrets_config(
            auth, api, slug=nonexistent_slug,
        ))
        assert ok, "fetch_and_apply must report success on both 404 and 403"

        # Cache cleared regardless of which classification fired.
        assert not auth.is_secrets_cache_present(), (
            "404 (or membership 403) must clear the stale cache"
        )

        # Resolver now hands out LocalProvider — the safe fallback.
        provider = resolve_secret_provider(auth, guard)
        assert isinstance(provider, LocalProvider)

    def test_403_when_token_lacks_team_membership(self):
        """A token scoped to a different team must 403, not 404 —
        the server collapses unknown-slug into 403 to prevent
        enumeration. CLI surfaces :class:`ForbiddenError`.

        Needs a SECOND service-account token that ISN'T a member of the
        seeded team. The test below is wired to read
        SERVONAUT_E2E_OAUTH_TOKEN_NONMEMBER if present; otherwise it
        auto-skips. Unit test
        TestGetTeamSecretsConfig403::test_403_raises_forbidden
        already pins the wire format, so this is belt+braces.
        """
        nonmember = os.environ.get("SERVONAUT_E2E_OAUTH_TOKEN_NONMEMBER", "")
        if not nonmember:
            pytest.skip(
                "Optional: set SERVONAUT_E2E_OAUTH_TOKEN_NONMEMBER to a "
                "service-account OAuth token that is NOT a member of "
                "the seeded team. Unit test "
                "TestGetTeamSecretsConfig403::test_403_raises_forbidden "
                "already pins the wire format; this test is a live "
                "verification only."
            )
        # The full live test follows the same shape as
        # test_endpoint_returns_locked_contract_shape; left as
        # an explicit TODO when the second token is wired in.
        pytest.skip(
            "Bundle includes a single OAuth token (the team member). "
            "When a non-member companion token is provisioned, fill in "
            "the live assertion: fetch must raise ForbiddenError."
        )


# ---------------------------------------------------------------------------
# Test surface 2 — full-stack real-bws + real-Hetzner smoke (E2E #3)
# ---------------------------------------------------------------------------


@pytest.mark.requires_e2e_oauth
@pytest.mark.requires_e2e_bws
@pytest.mark.requires_e2e_hetzner
class TestFullE2E3_RealStackSmoke:
    """The expensive cell of the test pyramid.

    Runs the full secrets-management round-trip:
    1. CLI fetches team config from staging (real OAuth).
    2. Resolver instantiates :class:`BitwardenProvider`.
    3. :meth:`SSHService.discover_key_async` is called with the
       seeded key name; bws is invoked for real against the
       Bitwarden project.
    4. The private key blob round-trips back to a temp file at
       0600.
    5. We use it to SSH into a freshly-provisioned Hetzner test
       server (cleaned up after).

    Skipped by default; runs in the nightly cron only. NOT a gate
    for staging deploy.

    Cost reality check: each run provisions + tears down a Hetzner
    instance (cents per run depending on type), well within a
    smoke-testing budget.
    """

    def test_end_to_end_ssh_using_bws_supplied_key(self):
        """Resolve → fetch BWS-stored private key → SSH into Hetzner.

        TODO: fill in once a seeded staging environment is wired. Needs:
        - Hetzner test server type + region pinned (cheapest = cx22
          / hel1 currently).
        - Tear-down on finally (regardless of test outcome).
        - 30s timeout on the SSH connect.
        """
        pytest.skip(
            "Full-stack E2E pending a seeded staging environment. Costs "
            "cents per run; gated on three env vars by design."
        )


# ---------------------------------------------------------------------------
# Skeleton self-check — pins the test plumbing so a future refactor of
# the conftest skip mechanism trips a clear regression here.
# ---------------------------------------------------------------------------


class TestSkeletonPlumbing:
    """These tests run on EVERY pytest invocation, including in CI
    with no env vars set. They validate that the marker plumbing
    works without actually exercising any of the gated test bodies.
    """

    def test_staging_bundle_constants_are_strings(self):
        # Defensive: if a future edit accidentally drops one of the
        # bundle constants, CI tells us before staging deploy.
        assert isinstance(SEEDED_TEAM_SLUG, str) and SEEDED_TEAM_SLUG
        assert isinstance(SEEDED_KEY_NAME, str) and SEEDED_KEY_NAME
        assert isinstance(STAGING_API_BASE, str) and STAGING_API_BASE.startswith(
            ("http://", "https://"),
        )

    def test_marker_names_match_conftest_catalogue(self):
        """The marker names this file references MUST exist in the
        conftest env-var catalogue. Renaming a marker without
        updating both sides should trip here, not at run-time."""
        from tests.conftest import E2E_MARKER_ENV_VARS
        # All three markers used in this file are catalogued.
        assert "requires_e2e_oauth" in E2E_MARKER_ENV_VARS
        assert "requires_e2e_bws" in E2E_MARKER_ENV_VARS
        assert "requires_e2e_hetzner" in E2E_MARKER_ENV_VARS

    def test_staging_bundle_seeded_slug_passes_cli_slug_regex(self):
        """The slug the CLI sends must satisfy
        :class:`APIClient`'s own validation regex — caught
        client-side before any network call. The server-side TeamSlug
        grammar is a strict subset; verifying here too is belt +
        braces."""
        from servonaut.services.api_client import _TEAM_SLUG_RE
        assert _TEAM_SLUG_RE.match(SEEDED_TEAM_SLUG), (
            f"Seeded slug {SEEDED_TEAM_SLUG!r} doesn't match CLI's "
            "team-slug regex — ensure the seeded slug conforms before "
            "wiring the bundle, NOT after."
        )
