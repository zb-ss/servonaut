"""The AWS switch in Settings → AWS (``aws.enabled``) is honoured.

Switched off, no AWS server is listed or fetched, the AWS sidebar section and
agent tools go away and every AWS surface says why. Someone who switched it
off back when it changed nothing is told once that their AWS servers are
hidden.
"""
from __future__ import annotations

import asyncio
import dataclasses
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App, ComposeResult
from textual.screen import Screen

from servonaut.app import ServonautApp
from servonaut.config.accounts import AWS_SWITCHED_OFF, aws_enabled
from servonaut.config.schema import AppConfig, AWSConfig
from servonaut.mcp.tool_schemas import TOOL_SCHEMAS, mcp_tool_list
from servonaut.services.accounts import AccountRegistry
from servonaut.widgets.sidebar import Sidebar

AWS_TOOLS = sorted(name for name, spec in TOOL_SCHEMAS.items() if spec.get("required_service") == "aws")


def _config(*, enabled: bool, notice_shown: bool = False) -> AppConfig:
    return AppConfig(aws=AWSConfig(enabled=enabled, off_notice_shown=notice_shown))


def test_aws_is_on_by_default():
    assert aws_enabled(AppConfig()) is True
    assert AppConfig().aws.off_notice_shown is False


class TestRegistry:
    def test_switched_off_aws_has_no_inventory(self):
        registry = AccountRegistry(_config(enabled=False))
        assert registry.fleet("aws") is None

    def test_its_services_stay_built_for_code_that_holds_one(self):
        registry = AccountRegistry(_config(enabled=False))
        assert registry.default_service("aws") is not None

    def test_switched_on_aws_has_its_inventory(self):
        assert AccountRegistry(_config(enabled=True)).fleet("aws") is not None


class TestAgentTools:
    def test_the_aws_tools_cover_ec2_cloudwatch_cloudtrail_waf_and_rds(self):
        assert {"aws_call", "aws_stop_instance", "cloudwatch_top_ips",
                "cloudtrail_lookup_events", "waf_rate_rule_set", "rds_metrics"} <= set(AWS_TOOLS)
        assert "list_instances" not in AWS_TOOLS
        assert "run_command" not in AWS_TOOLS

    def test_switched_off_the_tool_list_leaves_them_out(self):
        listed = {tool.name for tool in mcp_tool_list(have_aws=False)}
        assert not listed & set(AWS_TOOLS)
        assert "list_instances" in listed
        assert set(AWS_TOOLS) <= {tool.name for tool in mcp_tool_list(have_aws=True)}

    @staticmethod
    def _tools(enabled: bool):
        from servonaut.mcp.tools import ServonautTools

        tools = ServonautTools.__new__(ServonautTools)
        manager = MagicMock()
        manager.get.return_value = _config(enabled=enabled)
        tools._config_manager = manager
        tools._audit = MagicMock()
        return tools

    def test_a_call_while_switched_off_is_refused_and_audited(self):
        tools = self._tools(enabled=False)
        assert tools.refusal("aws_stop_instance") == f"Error: {AWS_SWITCHED_OFF}"
        args = tools._audit.log.call_args.args
        assert args[0] == "aws_stop_instance" and args[3] is False and args[4] == "aws_switched_off"

    def test_other_tools_and_a_switched_on_aws_are_never_refused(self):
        assert self._tools(enabled=False).refusal("list_instances") is None
        assert self._tools(enabled=True).refusal("aws_stop_instance") is None

    def test_the_mcp_dispatcher_answers_with_the_refusal(self):
        from servonaut.mcp.server import _dispatch_tool

        tools = self._tools(enabled=False)
        tools.aws_stop_instance = AsyncMock(return_value="stopped")
        [content] = asyncio.run(_dispatch_tool(tools, "aws_stop_instance", {"instance_id": "i-1"}))
        assert content.text == f"Error: {AWS_SWITCHED_OFF}"
        tools.aws_stop_instance.assert_not_awaited()

    def test_aws_object_storage_is_refused_with_the_reason(self):
        tools = self._tools(enabled=False)
        tools._aws_object_storage_service = MagicMock()
        assert tools._get_object_storage("aws") is None
        assert tools._s3_unavailable("s3_list_buckets", "aws", {}) == f"Error: {AWS_SWITCHED_OFF}"


class TestOneTimeNote:
    @staticmethod
    def _app(config: AppConfig, cached: int):
        manager = MagicMock()
        state = {"config": config}
        manager.get.side_effect = lambda: state["config"]
        manager.update.side_effect = lambda **kw: state.update(
            config=dataclasses.replace(state["config"], **kw),
        )
        accounts = MagicMock()
        accounts.cached_aws_servers.return_value = cached
        return SimpleNamespace(config_manager=manager, accounts=accounts, notify=MagicMock()), state

    def test_says_once_how_many_aws_servers_are_hidden(self):
        app, state = self._app(_config(enabled=False), cached=7)
        ServonautApp._note_aws_switched_off(app)
        ServonautApp._note_aws_switched_off(app)

        app.notify.assert_called_once()
        assert app.notify.call_args.args[0] == (
            "AWS is switched off in Settings, so 7 AWS servers are hidden. "
            "Switch it on in Settings → AWS to list them again."
        )
        assert state["config"].aws.off_notice_shown is True

    @pytest.mark.parametrize("config,cached", [
        (_config(enabled=True), 7),
        (_config(enabled=False), 0),
        (_config(enabled=False, notice_shown=True), 7),
    ])
    def test_stays_quiet_otherwise(self, config, cached):
        app, _ = self._app(config, cached)
        ServonautApp._note_aws_switched_off(app)
        app.notify.assert_not_called()


class _SidebarScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Sidebar()


class _Host(App):
    def __init__(self, config: AppConfig) -> None:
        super().__init__()
        self.config_manager = MagicMock()
        self.config_manager.get.return_value = config

    def on_mount(self) -> None:
        self.push_screen(_SidebarScreen())


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", [True, False])
async def test_the_sidebar_shows_aws_only_while_it_is_switched_on(enabled: bool) -> None:
    app = _Host(_config(enabled=enabled))
    async with app.run_test(size=(100, 40)) as pilot:
        await pilot.pause()
        assert app.screen.query_one("#section_aws").display is enabled


def test_the_ai_chat_dispatcher_answers_with_the_refusal():
    from servonaut.services.chat_tools import ChatToolExecutor

    tools = TestAgentTools._tools(enabled=False)
    tools.aws_list_regions = AsyncMock(return_value="regions")
    result = asyncio.run(ChatToolExecutor(tools, guard_level="standard").execute("aws_list_regions", {}))
    assert result == f"Error: {AWS_SWITCHED_OFF}"
    tools.aws_list_regions.assert_not_awaited()
