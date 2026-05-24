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
                          bastion_user="zoltan", bastion_key="/home/zoltan/.ssh/bastion_key"),
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
                     ssh_key="/home/zoltan/.ssh/db_key", port=22),
        CustomServer(name="cache-1", host="10.0.0.2", username="root", port=22),
    ]
    return cfg


class TestBuildShareableSubset:
    def test_includes_the_four_shareable_sections(self):
        payload, summary = build_shareable_subset(_seeded_config())
        assert payload["subset_version"] == SHAREABLE_SUBSET_VERSION
        assert summary == {
            "connection_profiles": 2,
            "connection_rules": 1,
            "scan_rules": 1,
            "custom_servers": 2,
            "stripped_paths": 2,  # bastion_key + custom_server ssh_key
        }

    def test_strips_bastion_key_local_path(self):
        payload, _ = build_shareable_subset(_seeded_config())
        profile_with_bastion = next(
            p for p in payload["connection_profiles"] if p["name"] == "prod-bastion"
        )
        assert profile_with_bastion["bastion_key"] == ""

    def test_strips_custom_server_ssh_key_local_path(self):
        payload, _ = build_shareable_subset(_seeded_config())
        db_server = next(s for s in payload["custom_servers"] if s["name"] == "db-1")
        assert db_server["ssh_key"] == ""
        cache_server = next(s for s in payload["custom_servers"] if s["name"] == "cache-1")
        assert cache_server["ssh_key"] == ""

    def test_does_NOT_include_credential_or_personal_sections(self):
        payload, _ = build_shareable_subset(_seeded_config())
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
        payload, _ = build_shareable_subset(_seeded_config())
        for section in ("connection_profiles", "custom_servers"):
            for entry in payload[section]:
                assert "_stripped" not in entry, "_stripped marker leaked to wire format"


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
