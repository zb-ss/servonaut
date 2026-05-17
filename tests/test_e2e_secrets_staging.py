"""Joint web↔CLI end-to-end tests for the secrets-management feature.

THIS FILE IS SKELETON-MODE until servonaut-dev posts the seeded
staging bundle on agent-bus thread ``secrets-management-kickoff``.
The constants in :class:`StagingBundle` are placeholders; the
moment the bundle lands, fill them in and the tests run.

Two test surfaces, two markers (see ``tests/conftest.py`` for the
auto-skip plumbing):

- :class:`TestJointE2E5_ContractHandshake` — pinned by
  ``@pytest.mark.requires_e2e_oauth``. Hits the real staging
  endpoint with a service-account OAuth bearer, verifies the CLI
  fetches the team's :class:`SecretsConfig`, parses it, and the
  resolver flips :class:`SSHService` from
  :class:`LocalProvider` to :class:`BitwardenProvider` with the
  right project_id + token_env_var. bws subprocess is STUBBED here
  — we're validating the contract between web and CLI, not bws.

- :class:`TestFullE2E3_RealStackSmoke` — pinned by
  ``@pytest.mark.requires_e2e_bws + requires_e2e_hetzner``
  (additive on top of the OAuth marker). Real bws subprocess +
  real Hetzner provisioning. Pre-prod smoke; nightly cron only.

Operational notes:

- The OAuth token in :data:`StagingBundle.oauth_token_env_var`
  rotates every 7 days. servonaut-dev ships
  ``bin/console app:e2e-secrets:seed --rotate-token`` for easy
  rotation; this file's constants don't change.
- All credentials read from env vars, never hardcoded. The
  ``StagingBundle.from_env()`` helper produces a tidy bundle
  object the tests destructure from.

When you fill in the placeholders:
- :data:`StagingBundle.team_slug` — the seeded team slug
- :data:`StagingBundle.bws_project_id` — the Bitwarden project ID
- :data:`StagingBundle.seeded_secret_name` — the SSH key stored in
  BWS for E2E #3 (servonaut-dev suggested ``e2e-secrets-hetzner-key``)

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
# Bundle skeleton — filled in when servonaut-dev posts on the bus
# ---------------------------------------------------------------------------

# The seeded team slug, locked on agent-bus thread
# ``secrets-management-kickoff``. If servonaut-dev posts a different
# slug, update this single constant — the rest of the file is
# wire-format-driven.
SEEDED_TEAM_SLUG = "cli-integration-test-team"

# Name of the SSH key stored in the seeded BWS project. Proposed by
# servonaut-dev for E2E #3. Only the BWS path uses this; the contract
# (E2E #5) doesn't touch real bws.
SEEDED_KEY_NAME = "e2e-secrets-hetzner-key"

# Staging API base — overridable by env var so a developer can point
# the tests at a local dev instance without editing this file.
STAGING_API_BASE = os.environ.get(
    "SERVONAUT_E2E_API_BASE",
    "https://staging.servonaut.dev",
)


@dataclass(frozen=True)
class StagingBundle:
    """Concrete credentials + URLs collected from env vars at test time.

    Lifecycle:
        - Env vars set by CI (secret store) or nightly-cron runner.
        - :meth:`from_env` reads them once per test invocation.
        - Frozen dataclass so tests can't accidentally mutate state
          that should round-trip identically across cases.
    """

    api_base: str
    team_slug: str
    oauth_token: str
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
            team_slug=SEEDED_TEAM_SLUG,
            oauth_token=oauth,
            bws_token=os.environ.get("SERVONAUT_E2E_BWS_TOKEN"),
            hetzner_token=os.environ.get("SERVONAUT_E2E_HETZNER_TOKEN"),
            seeded_secret_name=SEEDED_KEY_NAME,
        )


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
    - 200 with wrong shape → wire-format drift (web side ships).
    - 401/403 → service-account token expired or scope revoked.
    - 404 → seed command didn't run / team got wiped.
    - 5xx → staging incident; this isn't a CLI bug.
    """

    def test_endpoint_returns_locked_contract_shape(self):
        """End-to-end: real staging endpoint → CLI parses → resolver
        instantiates the right provider.

        TODO(servonaut): fill in once bundle lands. Skeleton below
        shows the intended shape so the test exists but is marked
        explicitly pending.
        """
        pytest.skip(
            "Step 7 staging bundle not yet posted; this test runs once "
            "servonaut-dev publishes {slug, oauth_token, bws_project_id} "
            "on agent-bus thread secrets-management-kickoff and the "
            "test body is filled in. Marker auto-skip will pick this up "
            "automatically once the env vars are set."
        )

        # ---- the intended shape below this line ----
        # bundle = StagingBundle.from_env()
        #
        # # Construct a real APIClient pointed at staging with the
        # # service-account OAuth bearer.
        # from servonaut.services.api_client import APIClient
        # from servonaut.services.auth_service import AuthService
        # from servonaut.services.entitlement_guard import EntitlementGuard
        # from servonaut.services.secret_provider_resolver import (
        #     resolve_secret_provider,
        #     fetch_and_apply_secrets_config,
        # )
        # from servonaut.services.bitwarden_provider import BitwardenProvider
        #
        # # Set the API base for this test only.
        # with patch.dict(os.environ, {"SERVONAUT_API_URL": bundle.api_base}):
        #     auth = _build_test_auth_service(oauth_token=bundle.oauth_token)
        #     guard = EntitlementGuard(auth)
        #     api = APIClient(auth)
        #
        #     # 1. Fetch the real config.
        #     ok = _run(fetch_and_apply_secrets_config(
        #         auth, api, slug=bundle.team_slug,
        #     ))
        #     assert ok, "fetch_and_apply must succeed against the seeded team"
        #
        #     # 2. Parsed cache shape matches the locked contract.
        #     cfg = auth.cached_secrets_config()
        #     assert cfg.provider == "bitwarden"
        #     assert cfg.config["project_id"]  # non-empty
        #     assert cfg.config.get("token_env_var") == "BWS_ACCESS_TOKEN"
        #     assert cfg.updated_at  # non-empty ATOM datetime
        #
        #     # 3. Resolver flips to BitwardenProvider with the right args.
        #     provider = resolve_secret_provider(auth, guard)
        #     assert isinstance(provider, BitwardenProvider)
        #     assert provider.project_id == cfg.config["project_id"]

    def test_404_falls_back_to_local_provider(self):
        """If the seeded team is missing (deletion drift), fetch
        returns None and the resolver hands out LocalProvider.

        TODO(servonaut): fill in once bundle lands.
        """
        pytest.skip(
            "Pending staging bundle; see test_endpoint_returns_locked_contract_shape."
        )

    def test_403_when_token_lacks_team_membership(self):
        """A token scoped to a different team must 403, not 404 —
        the server collapses unknown-slug into 403 to prevent
        enumeration. CLI surfaces :class:`ForbiddenError`.

        TODO(servonaut): needs a SECOND service-account token from
        servonaut-dev — one that ISN'T a member of the seeded team.
        Optional; the unit test in test_secrets_config_api_client.py
        already pins the wire format.
        """
        pytest.skip(
            "Pending staging bundle + second service-account token "
            "(non-member). Skip is intentional — the unit test "
            "TestGetTeamSecretsConfig403::test_403_raises_forbidden "
            "already pins the wire format."
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
    instance (~€0.01 / run depending on type). Nightly cadence is
    £3/year, well within "smoke testing budget".
    """

    def test_end_to_end_ssh_using_bws_supplied_key(self):
        """Resolve → fetch BWS-stored private key → SSH into Hetzner.

        TODO(servonaut): fill in once bundle lands. Needs:
        - Hetzner test server type + region pinned (cheapest = cx22
          / hel1 currently).
        - Tear-down on finally (regardless of test outcome).
        - 30s timeout on the SSH connect.
        """
        pytest.skip(
            "Full-stack E2E pending staging bundle. Costs cents per "
            "run; gated on three env vars by design."
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
        client-side before any network call. servonaut-dev
        confirmed the server-side TeamSlug grammar is a strict
        subset; verifying here too is belt + braces."""
        from servonaut.services.api_client import _TEAM_SLUG_RE
        assert _TEAM_SLUG_RE.match(SEEDED_TEAM_SLUG), (
            f"Seeded slug {SEEDED_TEAM_SLUG!r} doesn't match CLI's "
            "team-slug regex — coordinate with servonaut-dev before "
            "the bundle drops, NOT after."
        )
