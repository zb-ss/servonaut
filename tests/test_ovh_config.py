"""Tests for OVHConfig schema and its integration with AppConfig."""

from __future__ import annotations

import dataclasses
import json

import pytest

from servonaut.config.schema import AppConfig, OVHConfig


# ---------------------------------------------------------------------------
# OVHConfig
# ---------------------------------------------------------------------------

class TestOVHConfigDefaults:

    def test_enabled_is_false_by_default(self):
        cfg = OVHConfig()
        assert cfg.enabled is False

    def test_endpoint_defaults_to_ovh_eu(self):
        cfg = OVHConfig()
        assert cfg.endpoint == "ovh-eu"

    def test_auth_fields_default_to_empty_string(self):
        cfg = OVHConfig()
        assert cfg.application_key == ""
        assert cfg.application_secret == ""
        assert cfg.consumer_key == ""
        assert cfg.client_id == ""
        assert cfg.client_secret == ""

    def test_include_flags_all_true_by_default(self):
        cfg = OVHConfig()
        assert cfg.include_dedicated is True
        assert cfg.include_vps is True
        assert cfg.include_cloud is True

    def test_cloud_project_ids_empty_list_by_default(self):
        cfg = OVHConfig()
        assert cfg.cloud_project_ids == []

    def test_cloud_project_ids_mutable_default_independent(self):
        cfg1 = OVHConfig()
        cfg2 = OVHConfig()
        cfg1.cloud_project_ids.append("proj-1")
        assert cfg2.cloud_project_ids == []

    def test_ovh_audit_path_default(self):
        cfg = OVHConfig()
        assert cfg.ovh_audit_path == "~/.servonaut/ovh_audit.json"

    def test_cost_alert_threshold_default(self):
        cfg = OVHConfig()
        assert cfg.cost_alert_threshold == 0.0

    def test_cost_alert_currency_default(self):
        cfg = OVHConfig()
        assert cfg.cost_alert_currency == "EUR"


class TestOVHConfigCustomValues:

    def test_enabled_can_be_set(self):
        cfg = OVHConfig(enabled=True)
        assert cfg.enabled is True

    def test_endpoint_ca_variant(self):
        cfg = OVHConfig(endpoint="ovh-ca")
        assert cfg.endpoint == "ovh-ca"

    def test_endpoint_us_variant(self):
        cfg = OVHConfig(endpoint="ovh-us")
        assert cfg.endpoint == "ovh-us"

    def test_three_key_auth_fields(self):
        cfg = OVHConfig(
            application_key="my-app-key",
            application_secret="my-app-secret",
            consumer_key="my-consumer-key",
        )
        assert cfg.application_key == "my-app-key"
        assert cfg.application_secret == "my-app-secret"
        assert cfg.consumer_key == "my-consumer-key"

    def test_oauth2_auth_fields(self):
        cfg = OVHConfig(
            client_id="my-client-id",
            client_secret="my-client-secret",
        )
        assert cfg.client_id == "my-client-id"
        assert cfg.client_secret == "my-client-secret"

    def test_cloud_project_ids_with_values(self):
        cfg = OVHConfig(cloud_project_ids=["proj-a", "proj-b"])
        assert cfg.cloud_project_ids == ["proj-a", "proj-b"]

    def test_include_dedicated_false(self):
        cfg = OVHConfig(include_dedicated=False)
        assert cfg.include_dedicated is False

    def test_include_vps_false(self):
        cfg = OVHConfig(include_vps=False)
        assert cfg.include_vps is False

    def test_include_cloud_false(self):
        cfg = OVHConfig(include_cloud=False)
        assert cfg.include_cloud is False

    def test_env_var_syntax_stored_as_is(self):
        """$ENV_VAR syntax must be preserved; resolution happens at runtime."""
        cfg = OVHConfig(application_secret="$OVH_APP_SECRET")
        assert cfg.application_secret == "$OVH_APP_SECRET"

    def test_file_secret_syntax_stored_as_is(self):
        cfg = OVHConfig(consumer_key="file:/run/secrets/ovh_consumer_key")
        assert cfg.consumer_key == "file:/run/secrets/ovh_consumer_key"

    def test_all_fields_can_be_set_at_once(self):
        cfg = OVHConfig(
            enabled=True,
            endpoint="ovh-eu",
            application_key="ak",
            application_secret="as",
            consumer_key="ck",
            client_id="cid",
            client_secret="cs",
            cloud_project_ids=["p1", "p2"],
            include_dedicated=True,
            include_vps=False,
            include_cloud=True,
        )
        assert cfg.enabled is True
        assert cfg.cloud_project_ids == ["p1", "p2"]
        assert cfg.include_vps is False

    def test_new_fields_can_be_set(self):
        cfg = OVHConfig(
            ovh_audit_path="/tmp/audit.json",
            cost_alert_threshold=100.0,
            cost_alert_currency="USD",
        )
        assert cfg.ovh_audit_path == "/tmp/audit.json"
        assert cfg.cost_alert_threshold == 100.0
        assert cfg.cost_alert_currency == "USD"


class TestOVHConfigSerialization:

    def test_asdict_contains_all_fields(self):
        cfg = OVHConfig(
            enabled=True,
            endpoint="ovh-eu",
            application_key="ak",
            application_secret="as",
            consumer_key="ck",
        )
        d = dataclasses.asdict(cfg)
        assert d["enabled"] is True
        assert d["endpoint"] == "ovh-eu"
        assert d["application_key"] == "ak"
        assert d["application_secret"] == "as"
        assert d["consumer_key"] == "ck"
        assert d["client_id"] == ""
        assert d["client_secret"] == ""
        assert d["cloud_project_ids"] == []
        assert d["include_dedicated"] is True
        assert d["include_vps"] is True
        assert d["include_cloud"] is True
        assert d["ovh_audit_path"] == "~/.servonaut/ovh_audit.json"
        assert d["cost_alert_threshold"] == 0.0
        assert d["cost_alert_currency"] == "EUR"

    def test_new_fields_roundtrip_via_asdict(self):
        original = OVHConfig(
            ovh_audit_path="/custom/audit.json",
            cost_alert_threshold=50.0,
            cost_alert_currency="USD",
        )
        d = dataclasses.asdict(original)
        restored = OVHConfig(**d)
        assert restored.ovh_audit_path == original.ovh_audit_path
        assert restored.cost_alert_threshold == original.cost_alert_threshold
        assert restored.cost_alert_currency == original.cost_alert_currency

    def test_roundtrip_via_asdict(self):
        original = OVHConfig(
            enabled=True,
            endpoint="ovh-ca",
            application_key="key",
            cloud_project_ids=["proj-1"],
            include_vps=False,
        )
        d = dataclasses.asdict(original)
        restored = OVHConfig(**d)
        assert restored.enabled == original.enabled
        assert restored.endpoint == original.endpoint
        assert restored.application_key == original.application_key
        assert restored.cloud_project_ids == original.cloud_project_ids
        assert restored.include_vps == original.include_vps

    def test_json_serializable(self):
        cfg = OVHConfig(enabled=True, cloud_project_ids=["proj-1"])
        d = dataclasses.asdict(cfg)
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        assert parsed["enabled"] is True
        assert parsed["cloud_project_ids"] == ["proj-1"]


# ---------------------------------------------------------------------------
# AppConfig integration
# ---------------------------------------------------------------------------

class TestAppConfigOVHIntegration:

    def test_app_config_has_ovh_field(self):
        config = AppConfig()
        assert hasattr(config, "ovh")
        assert isinstance(config.ovh, OVHConfig)

    def test_app_config_ovh_defaults_to_disabled(self):
        config = AppConfig()
        assert config.ovh.enabled is False

    def test_app_config_ovh_mutable_default_independent(self):
        config1 = AppConfig()
        config2 = AppConfig()
        config1.ovh.cloud_project_ids.append("proj-test")
        assert config2.ovh.cloud_project_ids == []

    def test_app_config_with_custom_ovh(self):
        ovh_cfg = OVHConfig(
            enabled=True,
            endpoint="ovh-ca",
            application_key="mykey",
            cloud_project_ids=["proj-a"],
        )
        config = AppConfig(ovh=ovh_cfg)
        assert config.ovh.enabled is True
        assert config.ovh.endpoint == "ovh-ca"
        assert config.ovh.cloud_project_ids == ["proj-a"]

    def test_app_config_serialization_includes_ovh(self):
        config = AppConfig(ovh=OVHConfig(enabled=True, endpoint="ovh-us"))
        d = dataclasses.asdict(config)
        assert "ovh" in d
        assert d["ovh"]["enabled"] is True
        assert d["ovh"]["endpoint"] == "ovh-us"

    def test_app_config_roundtrip_with_ovh(self):
        original = AppConfig(
            ovh=OVHConfig(
                enabled=True,
                endpoint="ovh-eu",
                application_key="ak",
                application_secret="$OVH_SECRET",
                cloud_project_ids=["proj-1", "proj-2"],
                include_dedicated=False,
            )
        )
        d = dataclasses.asdict(original)
        # Simulate config manager deserialization
        ovh_data = d.pop("ovh", {})
        restored_ovh = OVHConfig(**ovh_data)
        d["ovh"] = restored_ovh
        restored = AppConfig(**d)

        assert restored.ovh.enabled is True
        assert restored.ovh.endpoint == "ovh-eu"
        assert restored.ovh.application_key == "ak"
        assert restored.ovh.application_secret == "$OVH_SECRET"
        assert restored.ovh.cloud_project_ids == ["proj-1", "proj-2"]
        assert restored.ovh.include_dedicated is False
        assert restored.ovh.include_vps is True  # default preserved

    def test_app_config_without_ovh_uses_default(self):
        """Deserializing config JSON without 'ovh' key falls back to OVHConfig()."""
        # Simulate raw config dict that predates OVH support
        raw = dataclasses.asdict(AppConfig())
        del raw["ovh"]

        ovh_data = raw.pop("ovh", {})
        raw["ovh"] = OVHConfig(**ovh_data) if ovh_data else OVHConfig()

        config = AppConfig(**raw)
        assert config.ovh.enabled is False
        assert config.ovh.endpoint == "ovh-eu"


# ---------------------------------------------------------------------------
# Config manager OVH deserialization
# ---------------------------------------------------------------------------

class TestConfigManagerOVHDeserialization:
    """Test that ConfigManager correctly deserializes OVH config from JSON."""

    @pytest.fixture
    def config_manager(self, tmp_path):
        from servonaut.config.manager import ConfigManager
        manager = ConfigManager()
        manager._config_path = tmp_path / "config.json"
        return manager

    def test_ovh_config_round_trip_via_manager(self, config_manager):
        original = AppConfig(
            ovh=OVHConfig(
                enabled=True,
                endpoint="ovh-ca",
                application_key="my-app-key",
                cloud_project_ids=["proj-1"],
                include_vps=False,
            )
        )
        config_manager.save(original)
        config_manager._config = None
        loaded = config_manager.load()

        assert loaded.ovh.enabled is True
        assert loaded.ovh.endpoint == "ovh-ca"
        assert loaded.ovh.application_key == "my-app-key"
        assert loaded.ovh.cloud_project_ids == ["proj-1"]
        assert loaded.ovh.include_vps is False
        assert loaded.ovh.include_dedicated is True

    def test_manager_loads_default_ovh_when_key_absent(self, config_manager, tmp_path):
        """Loading a config.json without 'ovh' key uses OVHConfig defaults."""
        raw = {
            "version": 2,
            "default_key": "",
            "default_username": "ec2-user",
        }
        config_manager._config_path.write_text(json.dumps(raw))
        loaded = config_manager.load()

        assert isinstance(loaded.ovh, OVHConfig)
        assert loaded.ovh.enabled is False

    def test_manager_ovh_with_all_auth_fields(self, config_manager):
        original = AppConfig(
            ovh=OVHConfig(
                enabled=True,
                endpoint="ovh-eu",
                application_key="ak",
                application_secret="$OVH_APP_SECRET",
                consumer_key="ck",
                client_id="cid",
                client_secret="$OVH_CLIENT_SECRET",
            )
        )
        config_manager.save(original)
        config_manager._config = None
        loaded = config_manager.load()

        assert loaded.ovh.application_secret == "$OVH_APP_SECRET"
        assert loaded.ovh.consumer_key == "ck"
        assert loaded.ovh.client_id == "cid"
        assert loaded.ovh.client_secret == "$OVH_CLIENT_SECRET"

    def test_manager_ovh_cloud_project_ids_round_trip(self, config_manager):
        original = AppConfig(
            ovh=OVHConfig(cloud_project_ids=["proj-a", "proj-b", "proj-c"])
        )
        config_manager.save(original)
        config_manager._config = None
        loaded = config_manager.load()

        assert loaded.ovh.cloud_project_ids == ["proj-a", "proj-b", "proj-c"]
