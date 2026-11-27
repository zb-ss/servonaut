"""The SCP screen uses a server's Bitwarden key and names it when the login is refused."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.widgets import Input, Static

from servonaut.screens.path_picker import RemotePathPickerModal
from servonaut.screens.scp_transfer import SCPTransferScreen
from servonaut.services.scp_service import SCPService
from servonaut.services.ssh_credentials import VaultLeaseCache
from tests._async_bounds import wait_until
from tests._bw_fixtures import key_provider, no_ref_provider, unavailable_provider
from tests.test_workspace_server_screens import _ServerWorkspaceApp

LOCKED_NOTICE = (
    "Bitwarden is locked, so this server's Bitwarden key was not used. "
    "Unlock it under Settings > Bitwarden SSH and retry."
)
REFUSAL = "deploy@web-1: Permission denied (publickey)."
SIGN_IN = "Could not sign in to the server. Check the connection settings."


def _lease(tmp_path, certificate: bool = False):
    agent = tmp_path / "agent.sock"
    agent.touch()
    return SimpleNamespace(
        source="vault",
        identity_agent=str(agent),
        identity_file=str(tmp_path / "key.pub"),
        certificate_path=str(tmp_path / "key-cert.pub") if certificate else None,
        known_hosts_path=str(tmp_path / "known_hosts"),
        login_user="deploy",
        target_host="192.0.2.10",
        target_port=2222,
    )


def _vault_runtime(lease):
    runtime = MagicMock()
    runtime.agent_key_ttl_seconds = 3600
    runtime.resolve_ssh = AsyncMock(return_value=lease)
    return runtime


def _case_app(case: str, tmp_path) -> _ServerWorkspaceApp:
    app = _ServerWorkspaceApp(False)
    app.scp_service = SCPService()
    app.vault_lease_cache = VaultLeaseCache()
    if case == "key_file":
        app.instances[0].update(is_custom=True, provider="custom", ssh_key="/keys/web-1")
    elif case == "vault":
        app.vault_command_service = _vault_runtime(_lease(tmp_path))
    elif case == "ca":
        app.vault_command_service = _vault_runtime(_lease(tmp_path, certificate=True))
    return app


async def _options(app, screen):
    return await screen._resolved_transfer_options(app.instances[0])


@pytest.mark.asyncio
class TestUnchangedWithoutBitwardenRef:
    @pytest.mark.parametrize("case", ["key_file", "no_key", "vault", "ca"])
    async def test_options_and_argv_do_not_change(self, tmp_path, case):
        app = _case_app(case, tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            screen = SCPTransferScreen(app.instances[0])
            await app.push_screen(screen)
            await pilot.pause()
            assert not hasattr(app, "bw_ssh_keys") or app.bw_ssh_keys is None
            before = await _options(app, screen)
            before_argv = screen._command_for(before, "/tmp/local.txt", "/srv/x")
            before_target = screen._host_key_target

            provider = no_ref_provider()
            app.bw_ssh_keys = provider
            after = await _options(app, screen)

            assert after == before
            assert screen._command_for(after, "/tmp/local.txt", "/srv/x") == before_argv
            assert screen._host_key_target == before_target
            assert screen._bw_key_reason is None
            if case == "key_file":
                assert before["key_path"] == "/keys/web-1"
                assert "-i" in before_argv and "/keys/web-1" in before_argv
                assert set(before) == {"host", "username", "key_path", "proxy_args", "port", "extra_options"}


@pytest.mark.asyncio
class TestBitwardenKey:
    async def test_the_bitwarden_key_reaches_the_options_and_the_argv(self, tmp_path):
        app = _case_app("key_file", tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            screen = SCPTransferScreen(app.instances[0])
            await app.push_screen(screen)
            await pilot.pause()
            app.bw_ssh_keys = key_provider("/tmp/bw-test")
            options = await _options(app, screen)
            assert options["key_path"] == "/tmp/bw-test"
            assert "key_source" not in options and "bw_key_unavailable" not in options
            assert "bw_item_id" not in options
            argv = screen._command_for(options, "/tmp/local.txt", "/srv/x")
            assert "/tmp/bw-test" in argv
            assert screen._bw_key_reason is None

    async def test_an_unreadable_key_keeps_the_previous_options_and_remembers_why(self, tmp_path):
        app = _case_app("key_file", tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            screen = SCPTransferScreen(app.instances[0])
            await app.push_screen(screen)
            await pilot.pause()
            plain = await _options(app, screen)
            app.bw_ssh_keys = unavailable_provider()
            options = await _options(app, screen)
            assert options == plain
            assert screen._bw_key_reason == "BwSessionMissingError"

    async def test_a_vault_lease_wins_over_the_bitwarden_key(self, tmp_path):
        app = _case_app("vault", tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            screen = SCPTransferScreen(app.instances[0])
            await app.push_screen(screen)
            await pilot.pause()
            plain = await _options(app, screen)
            provider = key_provider()
            app.bw_ssh_keys = provider
            options = await _options(app, screen)
            assert options == plain
            assert options["key_path"] != "/tmp/bw-test"
            assert options["identity_agent"]
            provider.apply.assert_not_awaited()


@pytest.mark.asyncio
class TestRefusedLoginNamesTheBitwardenCause:
    @pytest.mark.parametrize("reason, expected", [("BwSessionMissingError", LOCKED_NOTICE), (None, SIGN_IN)])
    async def test_browser_preparation(self, reason, expected):
        app = _ServerWorkspaceApp(False)
        async with app.run_test(size=(100, 30)) as pilot:
            screen = SCPTransferScreen(app.instances[0])
            await app.push_screen(screen)
            await pilot.pause()

            async def prepare(conn):
                from servonaut.services.remote_paths import RemoteCommandError

                screen._bw_key_reason = reason
                raise RemoteCommandError(REFUSAL, 255)

            screen._resolved_transfer_options = prepare
            await pilot.click("#remote_path_browse")
            await wait_until(lambda: screen._status_message == expected and not screen.query_one("#remote_path_input", Input).disabled)
            assert screen.query_one("#remote_path_browse").disabled is False
            assert expected in str(screen.query_one("#status_output", Static).content)

    async def test_an_unrelated_browser_error_keeps_its_message(self):
        app = _ServerWorkspaceApp(False)
        async with app.run_test(size=(100, 30)) as pilot:
            screen = SCPTransferScreen(app.instances[0])
            await app.push_screen(screen)
            await pilot.pause()
            screen._bw_key_reason = "BwSessionMissingError"
            screen.on_worker_state_changed(SimpleNamespace(worker=SimpleNamespace(
                name="scp_browse", is_finished=True, error=RuntimeError("operation timed out"),
            )))
            assert screen._status_message == "The server took too long to respond. Try again."

    def _finish(self, screen, **worker):
        base = dict(name="scp_transfer", is_finished=True, is_cancelled=False, error=None, result=None)
        base.update(worker)
        screen._transfer_worker = SimpleNamespace(**base)
        screen._host_key_target = None
        screen.on_worker_state_changed(SimpleNamespace(worker=screen._transfer_worker))

    @pytest.mark.parametrize("reason, expected", [
        ("BwSessionMissingError", LOCKED_NOTICE),
        (None, REFUSAL + "\nscp: Connection closed"),
    ])
    async def test_failed_transfer(self, reason, expected):
        app = _ServerWorkspaceApp(False)
        async with app.run_test(size=(100, 30)) as pilot:
            screen = SCPTransferScreen(app.instances[0])
            await app.push_screen(screen)
            await pilot.pause()
            screen._bw_key_reason = reason
            self._finish(screen, result=(255, "", REFUSAL + "\nscp: Connection closed"))
            assert screen._status_prefix == "Transfer failed:"
            assert screen._status_message == expected

    async def test_a_transfer_worker_error_is_named(self):
        app = _ServerWorkspaceApp(False)
        async with app.run_test(size=(100, 30)) as pilot:
            screen = SCPTransferScreen(app.instances[0])
            await app.push_screen(screen)
            await pilot.pause()
            from servonaut.services.remote_paths import RemoteCommandError

            screen._bw_key_reason = "BwSessionMissingError"
            self._finish(screen, error=RemoteCommandError(REFUSAL, 255))
            assert screen._status_message == LOCKED_NOTICE

    @pytest.mark.parametrize("error_kind", ["plain", "remote_exit_2"])
    async def test_refusal_words_without_ssh_s_own_failure_are_not_a_refusal(self, error_kind):
        """A remote error naming ssh's refusal (a file name, say) gets no Bitwarden text."""
        from servonaut.services.remote_paths import RemoteCommandError

        app = _ServerWorkspaceApp(False)
        async with app.run_test(size=(100, 30)) as pilot:
            screen = SCPTransferScreen(app.instances[0])
            await app.push_screen(screen)
            await pilot.pause()
            screen._bw_key_reason = "BwSessionMissingError"
            error = RuntimeError(REFUSAL) if error_kind == "plain" else RemoteCommandError(REFUSAL, 2)
            self._finish(screen, error=error)
            assert "Bitwarden" not in screen._status_message

    async def test_a_transfer_exit_2_with_refusal_words_is_not_a_refusal(self):
        app = _ServerWorkspaceApp(False)
        async with app.run_test(size=(100, 30)) as pilot:
            screen = SCPTransferScreen(app.instances[0])
            await app.push_screen(screen)
            await pilot.pause()
            screen._bw_key_reason = "BwSessionMissingError"
            self._finish(screen, result=(2, "", REFUSAL))
            assert "Bitwarden" not in screen._status_message

    async def test_a_refusal_text_not_on_its_own_line_is_not_a_refusal(self):
        app = _ServerWorkspaceApp(False)
        async with app.run_test(size=(100, 30)) as pilot:
            screen = SCPTransferScreen(app.instances[0])
            await app.push_screen(screen)
            await pilot.pause()
            screen._bw_key_reason = "BwSessionMissingError"
            self._finish(screen, result=(1, "", "scp: /srv/" + REFUSAL + ": No such file"))
            assert "Bitwarden" not in screen._status_message

    async def test_a_successful_transfer_shows_no_bitwarden_text(self):
        app = _ServerWorkspaceApp(False)
        async with app.run_test(size=(100, 30)) as pilot:
            screen = SCPTransferScreen(app.instances[0])
            await app.push_screen(screen)
            await pilot.pause()
            screen._bw_key_reason = "BwSessionMissingError"
            self._finish(screen, result=(0, "", ""))
            assert "Bitwarden" not in screen._status_message
            assert "completed successfully" in screen._status_message


@pytest.mark.asyncio
class TestRefusedBitwardenKeyIsDropped:
    def _provider(self, key_path):
        provider = key_provider(key_path)

        async def apply(conn, instance):
            return {**conn, "key_path": key_path, "key_source": "bw_personal",
                    "bw_item_id": "33333333-3333-4333-8333-333333333333"}

        provider.apply.side_effect = apply
        provider.key_refused = MagicMock()
        return provider

    async def test_a_refused_transfer_drops_the_key_and_the_next_one_reads_it_again(self, tmp_path):
        app = _case_app("key_file", tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            screen = SCPTransferScreen(app.instances[0])
            await app.push_screen(screen)
            await pilot.pause()
            provider = self._provider("/tmp/bw-test")
            app.bw_ssh_keys = provider
            options = await _options(app, screen)
            assert "bw_item_id" not in options and "key_source" not in options
            screen._transfer_worker = SimpleNamespace(
                name="scp_transfer", is_finished=True, is_cancelled=False, error=None,
                result=(255, "", REFUSAL),
            )
            screen._host_key_target = None
            screen.on_worker_state_changed(SimpleNamespace(worker=screen._transfer_worker))
            provider.key_refused.assert_called_once()
            refused = provider.key_refused.call_args.args[0]
            assert refused["bw_item_id"] == "33333333-3333-4333-8333-333333333333"
            await _options(app, screen)
            assert provider.apply.await_count == 2

    async def test_a_working_transfer_drops_nothing(self, tmp_path):
        app = _case_app("key_file", tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            screen = SCPTransferScreen(app.instances[0])
            await app.push_screen(screen)
            await pilot.pause()
            provider = self._provider("/tmp/bw-test")
            app.bw_ssh_keys = provider
            await _options(app, screen)
            screen._transfer_worker = SimpleNamespace(
                name="scp_transfer", is_finished=True, is_cancelled=False, error=None,
                result=(0, "", ""),
            )
            screen._host_key_target = None
            screen.on_worker_state_changed(SimpleNamespace(worker=screen._transfer_worker))
            provider.key_refused.assert_not_called()
