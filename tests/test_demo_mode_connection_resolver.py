"""Demo mode keeps rendering the redacted row but connects to the real one.

``ServonautApp.connection_instance`` maps a redacted row back to the
pre-redaction snapshot by its fake id; ``real_instance_id`` does the same
for bare ids. The memory layer resolves on entry so fake ids never become
directory names, index keys or sync-queue keys. Neutral fixtures only.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from servonaut.app import ServonautApp
from servonaut.services.redaction_service import RedactionService


REAL_ROW = {
    "id": "i-0abc123def456789a", "name": "web-prod-7", "public_ip": "9.9.9.9",
    "private_ip": "10.0.0.7", "region": "eu-west-1", "type": "t3.micro",
    "state": "running", "key_name": "prod-key",
}


def _demo_app(rows):
    """A stand-in with exactly the attributes the resolver methods read."""
    import copy
    svc = RedactionService()
    pristine = copy.deepcopy(rows)
    redacted = copy.deepcopy(rows)
    svc.redact_instances(redacted)
    app = SimpleNamespace(demo_mode=True, redaction_service=svc,
                          _instances_pristine=pristine, instances=redacted)
    app.real_instance_id = lambda i: ServonautApp.real_instance_id(app, i)
    app.connection_instance = lambda inst: ServonautApp.connection_instance(app, inst)
    return app


class TestRedactionServiceInverse:
    def test_real_instance_id_round_trip(self) -> None:
        svc = RedactionService()
        for real in ("i-0abc123def456789a", "custom-web-1", "12345678",
                     "vps-1a2b3c4d.vps.corp-example.net"):
            fake = svc.redact_instance_id(real)
            assert svc.real_instance_id(fake) == real

    def test_unknown_and_empty_pass_through(self) -> None:
        svc = RedactionService()
        assert svc.real_instance_id("i-unknown") == "i-unknown"
        assert svc.real_instance_id("") == ""


class TestAppResolver:
    def test_outside_demo_mode_returns_the_same_object(self) -> None:
        app = SimpleNamespace(demo_mode=False, redaction_service=None, _instances_pristine=None)
        row = dict(REAL_ROW)
        assert ServonautApp.connection_instance(app, row) is row
        assert ServonautApp.real_instance_id(app, "i-x") == "i-x"

    def test_demo_row_resolves_to_pristine_copy(self) -> None:
        app = _demo_app([REAL_ROW])
        shown = app.instances[0]
        assert shown["id"] != REAL_ROW["id"]
        assert shown["public_ip"] != REAL_ROW["public_ip"]
        real = app.connection_instance(shown)
        assert real == REAL_ROW
        assert real is not app._instances_pristine[0], "callers must get a copy"
        assert app.real_instance_id(shown["id"]) == REAL_ROW["id"]

    def test_unknown_row_falls_back_to_itself(self) -> None:
        app = _demo_app([REAL_ROW])
        stray = {"id": "i-notinsnapshot", "public_ip": "192.0.2.9"}
        assert app.connection_instance(stray) is stray


class TestMemoryStoreResolver:
    def test_fake_id_lands_under_the_real_directory(self, tmp_path) -> None:
        from servonaut.services.memory.store import MemoryStore

        store = MemoryStore(root=tmp_path)
        store.set_instance_id_resolver(lambda i: {"i-fake": "i-real"}.get(i, i))
        assert store._instance_dir("i-fake", "aws") == store._instance_dir("i-real", "aws")
        assert "i-fake" not in str(store._instance_dir("i-fake", "aws"))
        store.update_index("i-fake", "web-prod-7", "aws", ["os"])
        index = json.loads((tmp_path / "index.json").read_text())
        assert "i-real" in index["instances"]
        assert "i-fake" not in index["instances"]
        assert store.get_index_entry("i-fake") is not None

    def test_identity_without_a_resolver(self, tmp_path) -> None:
        from servonaut.services.memory.store import MemoryStore

        store = MemoryStore(root=tmp_path)
        assert "i-real" in str(store._instance_dir("i-real", "aws"))


class TestMemoryServiceResolver:
    def _service(self):
        from servonaut.services.memory.service import MemoryService

        config = MagicMock()
        config.enabled = True
        config.redaction_enabled = True
        store = MagicMock()
        svc = MemoryService(config=config, store=store)
        return svc, config, store

    def test_wires_dict_and_id_resolvers(self) -> None:
        svc, _, store = self._service()
        svc.set_instance_resolver(lambda d: {"id": "i-real", "name": "web-prod-7"},
                                  lambda i: "i-real")
        store.set_instance_id_resolver.assert_called_once()
        assert svc._resolve_id("i-fake") == "i-real"
        assert svc._resolve_instance({"id": "i-fake"}) == {"id": "i-real", "name": "web-prod-7"}

    def test_non_dict_and_non_str_results_are_ignored(self) -> None:
        svc, _, _ = self._service()
        svc.set_instance_resolver(lambda d: None, lambda i: 42)
        assert svc._resolve_id("i-fake") == "i-fake"
        assert svc._resolve_instance({"id": "i-fake"}) == {"id": "i-fake"}

    def test_is_memory_disabled_checks_the_real_id_and_name(self) -> None:
        svc, config, _ = self._service()
        config.is_instance_disabled.return_value = False
        svc.set_instance_resolver(lambda d: {"id": "i-real", "name": "web-prod-7"}, lambda i: "i-real")
        svc.is_memory_disabled("i-fake", "api-staging-3")
        config.is_instance_disabled.assert_called_once_with("i-real", "web-prod-7")

    def test_store_calls_receive_the_real_id(self) -> None:
        svc, _, store = self._service()
        svc.set_instance_resolver(None, lambda i: {"i-fake": "i-real"}.get(i, i))
        svc.get_all_modules("i-fake", "aws")
        args = store.get_all_modules.call_args.args
        assert args[0] == "i-real"


class TestInstanceListSshConnect:
    def test_connects_to_the_real_host_but_names_the_fake_row(self) -> None:
        from servonaut.screens.instance_list import InstanceListScreen

        screen = object.__new__(InstanceListScreen)
        app = _demo_app([REAL_ROW])
        shown = app.instances[0]
        mock_app = MagicMock()
        mock_app.demo_mode = True
        mock_app.connection_instance = app.connection_instance
        mock_app.real_instance_id = app.real_instance_id
        mock_app.connection_service.resolve_profile.return_value = None
        mock_app.connection_service.get_target_host.side_effect = lambda inst, profile: inst.get("public_ip")
        mock_app.connection_service.get_extra_options.return_value = []
        mock_app.ssh_service.get_key_path.return_value = "/tmp/prod-key.pem"
        mock_app.ssh_service.build_ssh_command.return_value = ["ssh", "9.9.9.9"]
        mock_app.terminal_service.launch_ssh_in_terminal.return_value = True
        mock_app.config_manager.get.return_value.default_username = "ubuntu"

        with patch.object(type(screen), "app", new_callable=lambda: property(lambda self: mock_app)):
            with patch.object(screen, "_get_selected_running_instance", return_value=shown), \
                    patch.object(screen, "_maybe_show_memory_prompt") as prompt:
                screen.action_ssh_connect()

        host_arg = mock_app.connection_service.get_target_host.call_args.args[0]
        assert host_arg["public_ip"] == "9.9.9.9", "connection must use the real record"
        assert mock_app.ssh_service.get_key_path.call_args.args[0] == REAL_ROW["id"]
        toast = mock_app.notify.call_args.args[0]
        assert shown["name"] in toast and REAL_ROW["name"] not in toast
        prompt.assert_called_once_with(shown)


class TestProviderRefreshKeepsPristineInStep:
    def test_replace_pristine_rows_swaps_provider_rows(self) -> None:
        from servonaut.screens.instance_list import InstanceListScreen

        screen = object.__new__(InstanceListScreen)
        mock_app = MagicMock()
        mock_app._instances_pristine = [
            {"id": "i-1", "name": "aws-1"},
            {"id": "old-vps", "name": "old", "is_ovh": True},
        ]
        fresh = [{"id": "vps-new.vps.corp-example.net", "name": "new", "is_ovh": True}]
        with patch.object(type(screen), "app", new_callable=lambda: property(lambda self: mock_app)):
            screen._replace_pristine_rows("is_ovh", fresh)
        ids = [i["id"] for i in mock_app._instances_pristine]
        assert ids == ["i-1", "vps-new.vps.corp-example.net"]
        assert mock_app._instances_pristine[1] is not fresh[0], "snapshot must be a copy"


class TestToolBridgeTargetResolution:
    def test_relay_target_is_mapped_when_a_resolver_is_installed(self) -> None:
        from servonaut.services.ai_tool_bridge import AIToolBridge
        from servonaut.services.relay_listener import CommandType

        bridge = object.__new__(AIToolBridge)
        bridge.instance_id_resolver = lambda i: {"i-fake": "i-real"}.get(i, i)
        bridge._default_ttl_seconds = 30
        call = SimpleNamespace(
            name="run_command", tool_call_id="tc-1", conversation_id="conv-1",
            args={"instance_id": "i-fake", "command": "uptime"},
        )
        request = bridge._build_command_request(call, CommandType.RUN_COMMAND)
        assert request.target_server_id == "i-real"

    def test_identity_without_a_resolver(self) -> None:
        from servonaut.services.ai_tool_bridge import AIToolBridge
        from servonaut.services.relay_listener import CommandType

        bridge = object.__new__(AIToolBridge)
        bridge._default_ttl_seconds = 30
        call = SimpleNamespace(
            name="run_command", tool_call_id="tc-1", conversation_id="conv-1",
            args={"instance_id": "i-real", "command": "uptime"},
        )
        assert bridge._build_command_request(call, CommandType.RUN_COMMAND).target_server_id == "i-real"


class TestIpv6RuleLeavesClockTimesAlone:
    def test_clock_times_and_durations_survive(self) -> None:
        svc = RedactionService()
        assert svc.scrub_stream("Sep  2 19:15:03 web1 sshd[12]: Accepted") == "Sep  2 19:15:03 web1 sshd[12]: Accepted"
        assert svc.scrub_stream(" 19:15:03 up 55 days, load average: 0.00") == " 19:15:03 up 55 days, load average: 0.00"
        assert svc.scrub_stream("took 1:23:45") == "took 1:23:45"

    def test_addresses_are_still_redacted(self) -> None:
        svc = RedactionService()
        assert "2001:db8::1" in svc.scrub_stream("2001:db8:85a3:0:0:8a2e:370:7334")
        assert "2001:db8::1" in svc.scrub_stream("fd12:3456:789a:1:2:3:4:5")
        assert "2001:0:0:1" not in svc.scrub_stream("2001:0:0:1:2:3:4:5")


class TestAuthoredValuesPassThrough:
    """What the operator types while recording renders as typed."""

    def test_authored_fields_survive_redaction(self) -> None:
        svc = RedactionService()
        svc.keep_as_authored("cache-blue-4", "192.0.2.10", "deploy", "~/.ssh/deploy-key", "web-servers")
        row = {"id": "custom-cache-blue-4", "name": "cache-blue-4", "public_ip": "192.0.2.10",
               "private_ip": "192.0.2.10", "username": "deploy", "ssh_key": "~/.ssh/deploy-key",
               "provider": "Hetzner", "group": "web-servers", "region": "Hetzner", "is_custom": True}
        svc.redact_instance(row)
        assert row["name"] == "cache-blue-4"
        assert row["public_ip"] == "192.0.2.10"
        assert row["username"] == "deploy"
        assert row["ssh_key"] == "~/.ssh/deploy-key"
        assert row["group"] == "web-servers"
        assert row["id"] != "custom-cache-blue-4", "ids are always hashed"

    def test_unauthored_values_are_still_replaced(self) -> None:
        svc = RedactionService()
        assert svc.redact_name("web-prod-7") != "web-prod-7"
        assert svc.redact_username("alice") != "alice"
        assert svc.redact_key_name("~/.ssh/acme_deploy") != "~/.ssh/acme_deploy"
        assert svc.redact_group("acme-clients") != "acme-clients"

    def test_provider_labels_from_the_pool_stay_true(self) -> None:
        svc = RedactionService()
        assert svc.redact_provider("OVH") == "OVH"
        assert svc.redact_provider("Hetzner") == "Hetzner"
        assert svc.redact_provider("ExampleHost") != "ExampleHost"

    def test_save_marks_typed_values_as_authored(self) -> None:
        from servonaut.screens.custom_servers import CustomServersScreen

        screen = object.__new__(CustomServersScreen)
        mock_app = MagicMock()
        mock_app.demo_mode = True
        mock_app.redaction_service = RedactionService()
        mock_app.custom_server_service.update_server.return_value = True
        values = {"#input_name": "cache-blue-4", "#input_host": "192.0.2.10", "#input_username": "deploy",
                  "#input_ssh_key": "", "#input_port": "22", "#input_provider": "Hetzner", "#input_group": "web-servers"}
        widgets = {}

        def _query_one(selector, widget_type=None):
            w = widgets.setdefault(str(selector), MagicMock())
            if str(selector) in values:
                w.value = values[str(selector)]
            else:
                w.text = ""
            return w

        with patch.object(type(screen), "app", new_callable=lambda: property(lambda self: mock_app)):
            with patch.object(screen, "query_one", side_effect=_query_one), \
                    patch.object(screen, "_populate_table"), patch.object(screen, "_refresh_app_instances"), \
                    patch.object(screen, "_hide_form"):
                screen._save_server()
        assert mock_app.redaction_service.redact_name("cache-blue-4") == "cache-blue-4"
        assert mock_app.redaction_service.redact_group("web-servers") == "web-servers"


class TestCustomServersRefreshRedacts:
    def test_saved_rows_are_redacted_and_snapshotted(self) -> None:
        from servonaut.screens.custom_servers import CustomServersScreen

        screen = object.__new__(CustomServersScreen)
        svc = RedactionService()
        mock_app = MagicMock()
        mock_app.demo_mode = True
        mock_app.redaction_service = svc
        mock_app.instances = [{"id": "i-1", "name": "aws-1"}]
        mock_app._instances_pristine = [{"id": "i-1", "name": "aws-1"}]
        raw = {"id": "custom-acme-web-1", "name": "acme-web-1", "public_ip": "9.9.9.9",
               "private_ip": "9.9.9.9", "is_custom": True}
        mock_app.custom_server_service.list_as_instances.return_value = [raw]
        with patch.object(type(screen), "app", new_callable=lambda: property(lambda self: mock_app)):
            screen._refresh_app_instances()
        shown = [i for i in mock_app.instances if i.get("is_custom")][0]
        assert shown["name"] != "acme-web-1" and shown["public_ip"] != "9.9.9.9"
        kept = [i for i in mock_app._instances_pristine if i.get("is_custom")][0]
        assert kept["name"] == "acme-web-1" and kept is not raw


class TestPaletteNavigation:
    def test_every_target_is_a_sidebar_button(self) -> None:
        import re
        from pathlib import Path
        import servonaut.widgets.sidebar as sidebar_module

        source = Path(sidebar_module.__file__).read_text(encoding="utf-8")
        sidebar_ids = set(re.findall(r'"(nav_[a-z0-9_]+)"', source))
        for _, target_id, _ in ServonautApp._PALETTE_NAVIGATION:
            assert target_id in sidebar_ids, target_id

    def test_commands_post_navigation_messages(self) -> None:
        from servonaut.widgets.sidebar import Sidebar

        app = object.__new__(ServonautApp)
        app.ovh_service = None
        app.hetzner_service = None
        posted = []
        app.post_message = lambda message: posted.append(message)
        with patch("textual.app.App.get_system_commands", return_value=iter(())):
            commands = list(ServonautApp.get_system_commands(app, None))
        titles = [c.title for c in commands]
        assert "Go to Custom Servers" in titles
        assert not any(t.startswith("Go to OVH") or t.startswith("Go to Hetzner") for t in titles)
        next(c for c in commands if c.title == "Go to Custom Servers").callback()
        assert isinstance(posted[0], Sidebar.NavigationRequested)
        assert posted[0].target_id == "nav_custom_servers"


class TestCustomServersRemoveToast:
    def test_toast_names_the_fake_row_in_demo_mode(self) -> None:
        from servonaut.screens.custom_servers import CustomServersScreen

        screen = object.__new__(CustomServersScreen)
        mock_app = MagicMock()
        mock_app.demo_mode = True
        mock_app.redaction_service = RedactionService()
        server = SimpleNamespace(name="acme-web-1")
        mock_app.custom_server_service.list_servers.return_value = [server]
        mock_app.custom_server_service.remove_server.return_value = True
        table = MagicMock()
        table.cursor_row = 0
        with patch.object(type(screen), "app", new_callable=lambda: property(lambda self: mock_app)):
            with patch.object(screen, "query_one", return_value=table), \
                    patch.object(screen, "_populate_table"), patch.object(screen, "_refresh_app_instances"):
                screen.action_remove_server()
        mock_app.custom_server_service.remove_server.assert_called_once_with("acme-web-1")
        toast = mock_app.notify.call_args.args[0]
        assert "acme-web-1" not in toast
        assert mock_app.redaction_service.redact_name("acme-web-1") in toast
