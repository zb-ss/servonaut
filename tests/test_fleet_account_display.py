"""Fleet UX with several accounts: names, search, rules, SSH defaults, demo mode."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from servonaut.config.schema import AppConfig, OVHAccount
from servonaut.services.connection_service import ConnectionService
from servonaut.services.redaction_service import RedactionService
from servonaut.services.report_scrubber import InventoryScrubber
from servonaut.utils.match_utils import matches_conditions
from servonaut.widgets.instance_table import _name_cell, _search_fields

QUALIFIED = {"id": "42", "name": "web-1", "is_hetzner": True, "provider": "hetzner",
             "account": "archive", "account_qualified": True}
SINGLE = {"id": "43", "name": "web-2", "is_hetzner": True, "provider": "hetzner",
          "account": "hetzner"}


class TestNameCell:
    def test_a_provider_with_several_accounts_shows_account_slash_name(self):
        cell = _name_cell(QUALIFIED, 32)
        assert cell.plain == "archive/web-1"
        # The account part is dimmed; the server name keeps the default style.
        assert [(span.start, span.end, str(span.style)) for span in cell.spans] == [
            (0, len("archive/"), "dim")
        ]

    def test_a_single_account_provider_shows_the_plain_name(self):
        assert _name_cell(SINGLE, 32).plain == "web-2"
        assert _name_cell({"name": ""}, 32).plain == "-"

    def test_long_qualified_names_are_cut_with_an_ellipsis(self):
        row = dict(QUALIFIED, account="a" * 30)
        assert _name_cell(row, 32).cell_len == 32


class TestSearch:
    def test_the_account_label_is_searchable_when_it_is_shown(self):
        assert "archive" in _search_fields(QUALIFIED)

    def test_a_label_that_is_not_shown_is_not_searchable(self):
        # Users with one account per provider search exactly as before.
        assert _search_fields({"name": "x", "account": "aws"}) == ["x"]
        assert _search_fields(dict(SINGLE, account="eu-archive")) == ["web-2", "43", "hetzner"]


class TestMatchConditions:
    def test_account_condition(self):
        assert matches_conditions(QUALIFIED, {"account": "Archive"})
        assert not matches_conditions(QUALIFIED, {"account": "prod"})
        assert not matches_conditions({"id": "c", "is_custom": True}, {"account": "archive"})

    def test_provider_condition_is_unchanged(self):
        # An exact match, as before: a dormant rule must not start matching.
        assert matches_conditions(QUALIFIED, {"provider": "hetzner"})
        assert not matches_conditions({"id": "i-1"}, {"provider": "aws"})


class TestOVHConnectionDefaults:
    def _service(self, config: AppConfig) -> ConnectionService:
        return ConnectionService(SimpleNamespace(get=lambda: config))

    def test_each_ovh_account_uses_its_own_key_and_username(self):
        config = AppConfig()
        config.ovh.default_ssh_key = "~/.ssh/primary"
        config.ovh.default_username = "ubuntu"
        config.ovh.accounts = [OVHAccount(label="ca", default_ssh_key="~/.ssh/ca",
                                          default_username="debian")]
        service = self._service(config)
        row = {"id": "vps-1", "is_ovh": True, "public_ip": "9.9.9.9", "provider_type": "vps"}

        primary = service.resolve_ovh_connection(dict(row, account="ovh"))
        extra = service.resolve_ovh_connection(dict(row, account="CA"))
        assert (primary["key_path"], primary["username"]) == ("~/.ssh/primary", "ubuntu")
        assert (extra["key_path"], extra["username"]) == ("~/.ssh/ca", "debian")

    def test_an_extra_account_without_defaults_inherits_the_provider_ones(self):
        config = AppConfig()
        config.ovh.default_ssh_key = "~/.ssh/primary"
        config.ovh.accounts = [OVHAccount(label="ca")]
        result = self._service(config).resolve_ovh_connection(
            {"id": "vps-1", "is_ovh": True, "account": "ca", "provider_type": "vps"}
        )
        assert result["key_path"] == "~/.ssh/primary"


class TestDemoMode:
    def test_account_labels_get_stable_distinct_stand_ins(self):
        redaction = RedactionService()
        first = redaction.redact_account_label("acme-eu")
        assert first not in ("acme-eu", "")
        assert redaction.redact_account_label("ACME-EU") == first
        assert redaction.redact_account_label(first) == first  # idempotent
        assert redaction.redact_account_label("acme-us") != first

    def test_a_real_label_is_never_mistaken_for_a_stand_in(self):
        redaction = RedactionService()
        # Every word a stand-in could be, used as real labels.
        from servonaut.services.redaction_service import _ACCOUNT_LABELS

        redaction.register_account_labels(["acme-eu", *_ACCOUNT_LABELS])
        stand_in = redaction.redact_account_label("acme-eu")
        assert stand_in.lower() not in {w.lower() for w in _ACCOUNT_LABELS}
        for word in _ACCOUNT_LABELS:
            assert redaction.redact_account_label(word) != word
        shown = {redaction.redact_account_label(w) for w in ["acme-eu", *_ACCOUNT_LABELS]}
        assert len(shown) == len(_ACCOUNT_LABELS) + 1  # never two accounts on one stand-in

    def test_provider_defaults_and_environment_words_stay(self):
        redaction = RedactionService()
        for label in ("aws", "hetzner", "ovh", "prod", "staging"):
            assert redaction.redact_account_label(label) == label

    def test_rows_hide_their_account_and_account_id(self):
        redaction = RedactionService()
        row = dict(QUALIFIED, account="acme-eu", account_id="123456789012")
        redaction.redact_instance(row)
        assert row["account"] != "acme-eu"
        assert row["account_id"] == "000000000000"

    def test_reports_hide_account_labels_and_profiles_from_the_config(self):
        from dataclasses import asdict

        from servonaut.config.schema import AWSAccount, HetznerAccount

        config = AppConfig()
        config.aws.accounts = [AWSAccount(label="acme-prod", profile="acme-admin")]
        config.hetzner.accounts = [HetznerAccount(label="acme-eu", api_token="$T")]
        scrubber = InventoryScrubber.from_inventory([], asdict(config))
        text = scrubber.replace_known("acme-eu: timeout; profile acme-admin; acme-prod")
        for real in ("acme-eu", "acme-admin", "acme-prod"):
            assert real not in text

    def test_notifications_hide_labels_of_accounts_without_servers(self):
        redaction = RedactionService()
        scrubber = InventoryScrubber.for_fleet(redaction, [], accounts=["acme-eu", "aws"])
        text = scrubber.replace_known("Hetzner refresh failed: acme-eu: token refused")
        assert "acme-eu" not in text
        assert redaction.redact_account_label("acme-eu") in text

    def test_qualified_names_in_messages_are_scrubbed_part_by_part(self):
        redaction = RedactionService()
        scrubber = InventoryScrubber.for_fleet(
            redaction, [dict(QUALIFIED, account="acme-eu", name="shop-db")]
        )
        text = scrubber.replace_known("matches acme-eu/shop-db (42, Hetzner)")
        assert "acme-eu" not in text and "shop-db" not in text


class TestDuplicateAccountNotice:
    def test_the_same_account_twice_is_reported_once(self):
        from servonaut.screens.instance_list import InstanceListScreen

        app = MagicMock()
        inventory = SimpleNamespace(duplicate_accounts={"old-profile": "aws"})
        app.provider_inventory.return_value = inventory
        screen = InstanceListScreen()
        with patch.object(InstanceListScreen, "app", new=property(lambda self: app)):
            screen._report_duplicate_accounts("aws")
            screen._report_duplicate_accounts("aws")
        assert app.notify.call_count == 1
        message = app.notify.call_args.args[0]
        assert "'old-profile'" in message and "'aws'" in message
        assert app.notify.call_args.kwargs["markup"] is False
