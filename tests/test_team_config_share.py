"""Tests for the team-config sanitise / apply helpers (v1)."""
from __future__ import annotations

from servonaut.config.schema import (
    AppConfig,
    ConnectionProfile,
    ConnectionRule,
    CustomServer,
    ScanRule,
)
from servonaut.services.team_config_apply import apply_team_config
from servonaut.services.team_config_subset import (
    SHAREABLE_SUBSET_VERSION,
    build_shareable_subset,
    diff_against_local,
)


def _seeded_config() -> AppConfig:
    cfg = AppConfig()
    cfg.connection_profiles = [
        ConnectionProfile(name="prod-bastion", bastion_host="bastion.example.com",
                          bastion_user="operator", bastion_key="/home/operator/.ssh/bastion_key"),
        ConnectionProfile(name="staging", username="ec2-user"),
    ]
    cfg.connection_rules = [
        ConnectionRule(name="prod-rule", match_conditions={"name_contains": "prod"}, profile_name="prod-bastion"),
    ]
    cfg.scan_rules = [
        ScanRule(name="nginx-logs", match_conditions={"name_contains": "web"},
                 scan_paths=["/var/log/nginx"]),
    ]
    cfg.custom_servers = [
        CustomServer(name="db-1", host="10.0.0.1", username="ubuntu",
                     ssh_key="/home/operator/.ssh/db_key", port=22),
        CustomServer(name="cache-1", host="10.0.0.2", username="root", port=22),
    ]
    return cfg


_ALL_SERVERS = ("db-1", "cache-1")


class TestBuildShareableSubset:
    def test_includes_the_four_shareable_sections(self):
        payload, summary = build_shareable_subset(_seeded_config(), custom_servers=_ALL_SERVERS)
        assert payload["subset_version"] == SHAREABLE_SUBSET_VERSION
        assert summary == {
            "connection_profiles": 2,
            "connection_rules": 1,
            "scan_rules": 1,
            "custom_servers": 2,
            "stripped_paths": 2,  # bastion_key + custom_server ssh_key
        }

    def test_strips_bastion_key_local_path(self):
        payload, _ = build_shareable_subset(_seeded_config(), custom_servers=_ALL_SERVERS)
        profile_with_bastion = next(
            p for p in payload["connection_profiles"] if p["name"] == "prod-bastion"
        )
        assert profile_with_bastion["bastion_key"] == ""

    def test_strips_custom_server_ssh_key_local_path(self):
        payload, _ = build_shareable_subset(_seeded_config(), custom_servers=_ALL_SERVERS)
        db_server = next(s for s in payload["custom_servers"] if s["name"] == "db-1")
        assert db_server["ssh_key"] == ""
        cache_server = next(s for s in payload["custom_servers"] if s["name"] == "cache-1")
        assert cache_server["ssh_key"] == ""

    def test_does_NOT_include_credential_or_personal_sections(self):
        payload, _ = build_shareable_subset(_seeded_config(), custom_servers=_ALL_SERVERS)
        # The four shareable keys + subset_version marker — nothing else.
        assert set(payload.keys()) == {
            "subset_version",
            "connection_profiles",
            "connection_rules",
            "scan_rules",
            "custom_servers",
        }
        # No AI/cloud/credential keys must leak.
        for forbidden in ("ai", "openai_api_key", "gcp", "azure", "ovh", "hetzner",
                          "relay", "mcp", "command_history_path", "terminal_emulator",
                          "ip_ban_configs"):
            assert forbidden not in payload

    def test_internal_strip_marker_not_present_in_final_payload(self):
        payload, _ = build_shareable_subset(_seeded_config(), custom_servers=_ALL_SERVERS)
        for section in ("connection_profiles", "custom_servers"):
            for entry in payload[section]:
                assert "_stripped" not in entry, "_stripped marker leaked to wire format"


class TestCustomServerSelection:
    """Only the custom servers the caller names are shared."""

    def test_only_the_named_servers_are_sent(self):
        payload, summary = build_shareable_subset(_seeded_config(), custom_servers=["cache-1"])
        assert [s["name"] for s in payload["custom_servers"]] == ["cache-1"]
        assert summary["custom_servers"] == 1
        # Profiles and rules still go out whole.
        assert [p["name"] for p in payload["connection_profiles"]] == ["prod-bastion", "staging"]
        assert summary["connection_rules"] == 1 and summary["scan_rules"] == 1

    def test_no_server_named_sends_none(self):
        payload, summary = build_shareable_subset(_seeded_config(), custom_servers=[])
        assert payload["custom_servers"] == []
        assert summary["custom_servers"] == 0
        assert summary["connection_profiles"] == 2

    def test_stripped_paths_count_only_what_is_sent(self):
        # db-1 has a key path, cache-1 has none; the bastion key is always sent (stripped).
        _payload, without_db = build_shareable_subset(_seeded_config(), custom_servers=["cache-1"])
        _payload, with_db = build_shareable_subset(_seeded_config(), custom_servers=["db-1"])
        assert without_db["stripped_paths"] == 1
        assert with_db["stripped_paths"] == 2

    def test_names_not_in_the_config_are_ignored(self):
        payload, summary = build_shareable_subset(_seeded_config(), custom_servers=["gone", "db-1"])
        assert [s["name"] for s in payload["custom_servers"]] == ["db-1"]
        assert summary["custom_servers"] == 1

    def test_the_selection_is_required(self):
        import pytest

        with pytest.raises(TypeError):
            build_shareable_subset(_seeded_config())  # type: ignore[call-arg]

    def test_a_partial_push_applies_cleanly_on_the_receiving_side(self):
        payload, _ = build_shareable_subset(_seeded_config(), custom_servers=["db-1"])
        member = AppConfig()
        member.custom_servers = [CustomServer(name="own-box", host="10.9.9.9")]
        diff = diff_against_local(member, payload)
        assert diff["custom_servers"] == {"local": 1, "remote": 1, "after": 1}

        apply_team_config(member, payload)
        [server] = member.custom_servers
        assert (server.name, server.host, server.username, server.ssh_key) == ("db-1", "10.0.0.1", "ubuntu", "")
        assert [p.name for p in member.connection_profiles] == ["prod-bastion", "staging"]
        assert [r.profile_name for r in member.connection_rules] == ["prod-bastion"]
        assert [r.name for r in member.scan_rules] == ["nginx-logs"]


class TestApplyTeamConfig:
    def test_replaces_each_section_wholesale(self):
        local = _seeded_config()
        remote = {
            "connection_profiles": [{"name": "team-prod", "bastion_host": "team.example.com"}],
            "connection_rules": [{"name": "rule-a", "match_conditions": {"region": "eu-west-2"}, "profile_name": "team-prod"}],
            "scan_rules": [{"name": "auth-logs", "match_conditions": {}, "scan_paths": ["/var/log/auth.log"]}],
            "custom_servers": [{"name": "team-db", "host": "team-db.example.com", "username": "root", "port": 22}],
        }
        apply_team_config(local, remote)
        assert [p.name for p in local.connection_profiles] == ["team-prod"]
        assert [r.name for r in local.connection_rules] == ["rule-a"]
        assert [r.name for r in local.scan_rules] == ["auth-logs"]
        assert [s.name for s in local.custom_servers] == ["team-db"]
        assert isinstance(local.connection_profiles[0], ConnectionProfile)
        assert isinstance(local.custom_servers[0], CustomServer)

    def test_drops_unknown_keys_for_forward_compat(self):
        local = _seeded_config()
        remote = {
            "connection_profiles": [{
                "name": "future-profile",
                "bastion_host": "x.example.com",
                "future_field_we_dont_understand": "shrug",
            }],
            "connection_rules": [],
            "scan_rules": [],
            "custom_servers": [],
        }
        apply_team_config(local, remote)
        assert local.connection_profiles[0].name == "future-profile"
        # The unknown key is silently dropped — no exception.

    def test_skips_malformed_entries_keeps_going(self):
        local = _seeded_config()
        remote = {
            # ScanRule requires both `name` and `match_conditions` — entry 2 is missing match_conditions.
            "scan_rules": [
                {"name": "good", "match_conditions": {}, "scan_paths": []},
                {"name": "broken"},  # missing required match_conditions
            ],
            "connection_profiles": [],
            "connection_rules": [],
            "custom_servers": [],
        }
        apply_team_config(local, remote)
        assert [r.name for r in local.scan_rules] == ["good"]

    def test_empty_remote_clears_local_sections(self):
        # Replace-whole-section semantics: empty list on remote = clear local.
        local = _seeded_config()
        apply_team_config(local, {
            "connection_profiles": [],
            "connection_rules": [],
            "scan_rules": [],
            "custom_servers": [],
        })
        assert local.connection_profiles == []
        assert local.connection_rules == []
        assert local.scan_rules == []
        assert local.custom_servers == []


class TestDiffAgainstLocal:
    def test_diff_reports_local_remote_after_per_section(self):
        local = _seeded_config()
        remote = {
            "connection_profiles": [{"name": "p1"}, {"name": "p2"}, {"name": "p3"}, {"name": "p4"}],
            "connection_rules": [],
            "scan_rules": [{"name": "s1", "match_conditions": {}}],
            "custom_servers": [],
        }
        diff = diff_against_local(local, remote)
        # local had 2 profiles, 1 rule, 1 scan_rule, 2 custom_servers
        assert diff["connection_profiles"] == {"local": 2, "remote": 4, "after": 4}
        assert diff["connection_rules"] == {"local": 1, "remote": 0, "after": 0}
        assert diff["scan_rules"] == {"local": 1, "remote": 1, "after": 1}
        assert diff["custom_servers"] == {"local": 2, "remote": 0, "after": 0}


class TestPullKeepsYourOwnKeyPaths:
    """A push never carries key paths; a pull keeps the member's own for the same entry."""

    @staticmethod
    def _member() -> AppConfig:
        member = AppConfig()
        member.connection_profiles = [
            ConnectionProfile(name="prod-bastion", bastion_host="Bastion.example.com", bastion_key="~/.ssh/jump"),
        ]
        member.custom_servers = [CustomServer(name="db-1", host="10.0.0.1", ssh_key="~/.ssh/db")]
        return member

    def test_a_pushed_config_keeps_the_members_own_paths(self):
        payload, _ = build_shareable_subset(_seeded_config(), custom_servers=_ALL_SERVERS)
        member = self._member()

        assert diff_against_local(member, payload)["kept_key_paths"] == 2
        assert apply_team_config(member, payload) == 2

        assert [(p.name, p.bastion_key) for p in member.connection_profiles] == [
            ("prod-bastion", "~/.ssh/jump"), ("staging", None),
        ]
        assert [(s.name, s.ssh_key) for s in member.custom_servers] == [("db-1", "~/.ssh/db"), ("cache-1", "")]

    def test_an_entry_new_to_the_member_stays_without_a_path(self):
        member = AppConfig()
        payload, _ = build_shareable_subset(_seeded_config(), custom_servers=_ALL_SERVERS)

        assert apply_team_config(member, payload) == 0
        assert all(not p.bastion_key for p in member.connection_profiles)
        assert all(not s.ssh_key for s in member.custom_servers)

    def test_a_renamed_entry_gets_no_path(self):
        remote = {
            "connection_profiles": [{"name": "prod-jump", "bastion_host": "bastion.example.com", "bastion_key": ""}],
            "custom_servers": [{"name": "db-primary", "host": "10.0.0.1", "ssh_key": ""}],
        }
        member = self._member()

        assert diff_against_local(member, remote)["kept_key_paths"] == 0
        apply_team_config(member, remote)
        assert member.connection_profiles[0].bastion_key == ""
        assert member.custom_servers[0].ssh_key == ""

    def test_a_path_never_follows_an_entry_to_another_machine(self):
        # A key offered to the wrong host only fails, and tells that host the key exists.
        remote = {
            "connection_profiles": [{"name": "prod-bastion", "bastion_host": "new-bastion.example.com"}],
            "custom_servers": [{"name": "db-1", "host": "10.0.0.9"}],
        }
        member = self._member()

        assert apply_team_config(member, remote) == 0
        assert not member.connection_profiles[0].bastion_key
        assert not member.custom_servers[0].ssh_key

    def test_a_path_in_the_payload_is_not_replaced(self):
        remote = {"connection_profiles": [
            {"name": "prod-bastion", "bastion_host": "bastion.example.com", "bastion_key": "~/.ssh/team-jump"},
        ]}
        member = self._member()

        assert apply_team_config(member, remote) == 0
        assert member.connection_profiles[0].bastion_key == "~/.ssh/team-jump"

