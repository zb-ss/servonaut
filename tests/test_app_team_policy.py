"""The TUI's team agent rules: one refresher, shared by every agent surface."""
from __future__ import annotations

import inspect
from unittest.mock import MagicMock

from servonaut.app import ServonautApp
from servonaut.services import team_policy
from servonaut.services.team_policy import team_policy_store
from servonaut.services.team_policy_refresh import TeamPolicyRefresher

from tests._team_policy_fixtures import envelope, response, team_id_for, team_row, trust_test_key


def _app(tmp_path) -> ServonautApp:
    app = ServonautApp(config_path=tmp_path / "config.json")
    app._init_services()
    return app


def test_the_app_owns_one_refresher_over_the_process_store(tmp_path):
    app = _app(tmp_path)

    assert isinstance(app.team_policy, TeamPolicyRefresher)
    assert app.team_policy.store is team_policy_store()
    # The agents' tools (AI chat, MCP in the TUI) fetch with the same one.
    assert app.servonaut_tools.team_policy is app.team_policy


def test_rules_saved_on_this_device_apply_from_the_start(tmp_path):
    trust_test_key()
    store = team_policy_store()
    store.apply_response(team_row("ops-team"), response(envelope(team_id_for("ops-team"))))

    # A new process: a new store over the same file.
    team_policy._default_store = None
    app = _app(tmp_path)

    assert app.team_policy.store is not store
    assert app.team_policy.store.state_path == store.state_path
    status = app.team_policy.store.status("ops-team")
    assert status is not None and status.problem is None


def test_signed_out_no_team_rules_are_fetched(tmp_path):
    app = _app(tmp_path)
    app.team_service = MagicMock()
    app.auth_service = MagicMock(is_authenticated=False)
    assert app._signed_in_team_service() is None

    app.auth_service.is_authenticated = True
    assert app._signed_in_team_service() is app.team_service


def test_rules_are_fetched_in_a_worker_of_their_own(tmp_path):
    app = _app(tmp_path)
    app.run_worker = MagicMock()
    teams = [team_row("ops-team")]

    app.refresh_team_policies(teams)

    work = app.run_worker.call_args.args[0]
    assert inspect.iscoroutine(work)
    work.close()
    assert app.run_worker.call_args.kwargs["group"] == "team_policy"
    assert app.run_worker.call_args.kwargs["exit_on_error"] is False


def test_the_hosted_ai_relay_asks_the_same_refresher(tmp_path):
    app = _app(tmp_path)
    app.auth_service = MagicMock(is_authenticated=True)
    app.run_worker = MagicMock(side_effect=lambda work, **_kw: work.close() if hasattr(work, "close") else None)
    app.init_paid_services()

    relay = getattr(app, "ai_relay_executors", None)
    assert relay is not None
    assert relay._team_policy is app.team_policy


def test_the_hosted_ai_relay_finds_team_servers_through_the_vault(tmp_path):
    app = _app(tmp_path)
    app.auth_service = MagicMock(is_authenticated=True)
    app.run_worker = MagicMock(side_effect=lambda work, **_kw: work.close() if hasattr(work, "close") else None)
    app.init_paid_services()

    # Without it Servonaut AI's tool calls in the TUI found no team's shared
    # server, so the team's rules were never reached.
    assert app.ai_relay_executors._vault_runtime is app.vault_command_service
