"""Instance references: ids, names and ``account/name`` across accounts."""

from __future__ import annotations

import pytest

from servonaut.utils.instance_resolver import (
    AmbiguousInstanceError,
    describe_candidate,
    display_name,
    match_instances,
    qualified_reference,
    resolve_unique,
)

PROD_WEB = {"id": "i-0aaa", "name": "web-1", "account": "prod", "account_qualified": True}
STAGING_WEB = {"id": "i-0bbb", "name": "web-1", "account": "staging", "account_qualified": True}
HETZNER_WEB = {"id": "42", "name": "web-1", "is_hetzner": True, "account": "hetzner"}
CUSTOM_EDGE = {"id": "custom-edge", "name": "edge", "is_custom": True}
OVH_CLOUD = {
    "id": "0123456789abcdef0123456789abcdef/5b1d", "name": "db-1",
    "is_ovh": True, "account": "eu", "account_qualified": True,
}
UNNAMED = {"id": "i-0ccc", "name": "", "account": "prod", "account_qualified": True}
FLEET = [PROD_WEB, STAGING_WEB, HETZNER_WEB, CUSTOM_EDGE, OVH_CLOUD, UNNAMED]


class TestDisplay:
    def test_rows_of_a_provider_with_several_accounts_show_their_account(self):
        assert display_name(PROD_WEB) == "prod/web-1"
        assert display_name(UNNAMED) == "prod/i-0ccc"

    def test_single_account_rows_show_their_plain_name(self):
        assert display_name(HETZNER_WEB) == "web-1"
        assert display_name(CUSTOM_EDGE) == "edge"

    def test_qualified_references(self):
        assert qualified_reference(HETZNER_WEB) == "hetzner/web-1"
        assert qualified_reference(CUSTOM_EDGE) == "custom/edge"
        assert qualified_reference(UNNAMED) == "prod/i-0ccc"

    def test_candidate_description_names_the_provider(self):
        assert describe_candidate(PROD_WEB) == "prod/web-1 (i-0aaa, AWS)"
        assert describe_candidate(CUSTOM_EDGE) == "custom/edge (custom-edge, custom)"


class TestResolution:
    @pytest.mark.parametrize(
        "reference, expected",
        [
            ("i-0bbb", STAGING_WEB),
            ("I-0BBB", STAGING_WEB),
            ("prod/web-1", PROD_WEB),
            ("STAGING/WEB-1", STAGING_WEB),
            ("prod/i-0aaa", PROD_WEB),
            ("hetzner/web-1", HETZNER_WEB),
            ("custom/edge", CUSTOM_EDGE),
            ("edge", CUSTOM_EDGE),
            ("db-1", OVH_CLOUD),
            # An OVH Public Cloud id carries a "/" of its own.
            ("0123456789abcdef0123456789abcdef/5b1d", OVH_CLOUD),
            ("eu/0123456789abcdef0123456789abcdef/5b1d", OVH_CLOUD),
            ("eu/db-1", OVH_CLOUD),
        ],
    )
    def test_references_that_pick_one_server(self, reference, expected):
        assert resolve_unique(reference, FLEET) is expected

    def test_a_shared_name_is_refused_with_every_candidate(self):
        with pytest.raises(AmbiguousInstanceError) as caught:
            resolve_unique("web-1", FLEET)
        error = caught.value
        assert {c["id"] for c in error.candidates} == {"i-0aaa", "i-0bbb", "42"}
        message = str(error)
        for ref in ("prod/web-1", "staging/web-1", "hetzner/web-1"):
            assert ref in message

    @pytest.mark.parametrize("reference", ["", "   ", "nope", "prod/nope", "nope/web-1", "/web-1"])
    def test_references_that_pick_nothing(self, reference):
        assert resolve_unique(reference, FLEET) is None

    def test_a_custom_server_named_like_a_qualified_reference_is_not_shadowed(self):
        lookalike = {"id": "custom-x", "name": "prod/web-1", "is_custom": True}
        matches = match_instances("prod/web-1", FLEET + [lookalike])
        assert {m["id"] for m in matches} == {"i-0aaa", "custom-x"}

    def test_an_unnamed_server_never_matches_an_empty_reference(self):
        assert match_instances("", [UNNAMED]) == []
