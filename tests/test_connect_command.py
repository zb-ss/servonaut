"""Tests for the `servonaut connect` CLI subcommand."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import servonaut.main as main_module
from servonaut.main import _relay_status, _relay_stop, _relay_run_foreground


# ---------------------------------------------------------------------------
# --status flag: no PID file
# ---------------------------------------------------------------------------

class TestRelayStatus:
    def test_no_pid_file_prints_not_running(self, tmp_path, capsys, monkeypatch):
        pid_file = tmp_path / "relay.pid"
        monkeypatch.setattr(main_module, "_RELAY_PID_FILE", pid_file)
        _relay_status()
        out = capsys.readouterr().out
        assert "not running" in out.lower()

    def test_no_pid_file_does_not_raise(self, tmp_path, monkeypatch):
        pid_file = tmp_path / "relay.pid"
        monkeypatch.setattr(main_module, "_RELAY_PID_FILE", pid_file)
        _relay_status()  # must not raise

    def test_stale_pid_file_prints_not_running(self, tmp_path, capsys, monkeypatch):
        pid_file = tmp_path / "relay.pid"
        # Use a PID that does not exist (PID 1 always exists, but 999999 likely not)
        pid_file.write_text("999999")
        monkeypatch.setattr(main_module, "_RELAY_PID_FILE", pid_file)
        # Simulate ProcessLookupError for kill(999999, 0)
        with patch("os.kill", side_effect=ProcessLookupError):
            _relay_status()
        out = capsys.readouterr().out
        assert "not running" in out.lower()

    def test_running_pid_prints_running(self, tmp_path, capsys, monkeypatch):
        pid_file = tmp_path / "relay.pid"
        my_pid = os.getpid()
        pid_file.write_text(str(my_pid))
        monkeypatch.setattr(main_module, "_RELAY_PID_FILE", pid_file)
        # os.kill(my_pid, 0) succeeds because this process exists
        _relay_status()
        out = capsys.readouterr().out
        assert "running" in out.lower()
        assert str(my_pid) in out

    def test_invalid_pid_file_content_handled(self, tmp_path, capsys, monkeypatch):
        pid_file = tmp_path / "relay.pid"
        pid_file.write_text("not-a-pid\n")
        monkeypatch.setattr(main_module, "_RELAY_PID_FILE", pid_file)
        _relay_status()  # must not raise
        out = capsys.readouterr().out
        assert out.strip()  # some output emitted


# ---------------------------------------------------------------------------
# --stop flag: no PID file
# ---------------------------------------------------------------------------

class TestRelayStop:
    def test_no_pid_file_prints_message(self, tmp_path, capsys, monkeypatch):
        pid_file = tmp_path / "relay.pid"
        monkeypatch.setattr(main_module, "_RELAY_PID_FILE", pid_file)
        _relay_stop()
        out = capsys.readouterr().out
        assert "no relay listener" in out.lower() or "pid file" in out.lower()

    def test_no_pid_file_does_not_raise(self, tmp_path, monkeypatch):
        pid_file = tmp_path / "relay.pid"
        monkeypatch.setattr(main_module, "_RELAY_PID_FILE", pid_file)
        _relay_stop()  # must not raise

    def test_valid_pid_sends_sigterm(self, tmp_path, capsys, monkeypatch):
        pid_file = tmp_path / "relay.pid"
        pid_file.write_text("12345")
        monkeypatch.setattr(main_module, "_RELAY_PID_FILE", pid_file)
        with patch("os.kill") as mock_kill:
            _relay_stop()
        import signal as _signal
        mock_kill.assert_called_once_with(12345, _signal.SIGTERM)

    def test_valid_pid_removes_pid_file(self, tmp_path, monkeypatch):
        pid_file = tmp_path / "relay.pid"
        pid_file.write_text("12345")
        monkeypatch.setattr(main_module, "_RELAY_PID_FILE", pid_file)
        with patch("os.kill"):
            _relay_stop()
        assert not pid_file.exists()

    def test_stale_pid_cleans_up_file(self, tmp_path, capsys, monkeypatch):
        pid_file = tmp_path / "relay.pid"
        pid_file.write_text("999999")
        monkeypatch.setattr(main_module, "_RELAY_PID_FILE", pid_file)
        with patch("os.kill", side_effect=ProcessLookupError):
            _relay_stop()
        assert not pid_file.exists()
        out = capsys.readouterr().out
        assert "not found" in out.lower() or "stale" in out.lower()

    def test_invalid_pid_content_cleans_up_file(self, tmp_path, capsys, monkeypatch):
        pid_file = tmp_path / "relay.pid"
        pid_file.write_text("garbage")
        monkeypatch.setattr(main_module, "_RELAY_PID_FILE", pid_file)
        _relay_stop()
        assert not pid_file.exists()


# ---------------------------------------------------------------------------
# HTTPS enforcement in _relay_run_foreground
# ---------------------------------------------------------------------------

class TestHTTPSEnforcement:
    """_relay_run_foreground must call sys.exit for non-HTTPS URLs."""

    def _make_relay_config(self, base_url="", mercure_url=""):
        from servonaut.config.schema import RelayConfig
        return RelayConfig(base_url=base_url, mercure_url=mercure_url)

    def _make_app_config(self, relay_cfg):
        from servonaut.config.schema import AppConfig
        return AppConfig(relay=relay_cfg)

    def _run_with_config(self, base_url, mercure_url, env_overrides=None):
        """
        Invoke _relay_run_foreground with a mocked ConfigManager and environment,
        expecting sys.exit to be raised. Returns the SystemExit exception.

        ConfigManager is imported locally inside _relay_run_foreground, so we
        patch it at its origin module path.
        """
        from servonaut.config.schema import AppConfig, RelayConfig
        relay_cfg = RelayConfig(base_url=base_url, mercure_url=mercure_url)
        config = AppConfig(relay=relay_cfg)

        config_manager = MagicMock()
        config_manager.get.return_value = config

        env = {
            "SERVONAUT_RELAY_TOKEN": "tok-abc",
            "SERVONAUT_USER_ID": "user-1",
        }
        if env_overrides:
            env.update(env_overrides)

        with patch("servonaut.config.manager.ConfigManager", return_value=config_manager), \
             patch.dict(os.environ, env, clear=False):
            with pytest.raises(SystemExit) as exc_info:
                _relay_run_foreground()
        return exc_info.value

    def test_http_base_url_causes_exit(self):
        exc = self._run_with_config(
            base_url="http://app.example.com",
            mercure_url="https://hub.example.com/.well-known/mercure",
        )
        assert exc.code != 0

    def test_http_mercure_url_causes_exit(self):
        exc = self._run_with_config(
            base_url="https://app.example.com",
            mercure_url="http://hub.example.com/.well-known/mercure",
        )
        assert exc.code != 0

    def test_both_http_causes_exit(self):
        exc = self._run_with_config(
            base_url="http://app.example.com",
            mercure_url="http://hub.example.com/.well-known/mercure",
        )
        assert exc.code != 0

    def test_missing_token_causes_exit(self):
        """Missing SERVONAUT_RELAY_TOKEN must also cause sys.exit."""
        from servonaut.config.schema import AppConfig, RelayConfig
        relay_cfg = RelayConfig(
            base_url="https://app.example.com",
            mercure_url="https://hub.example.com/.well-known/mercure",
        )
        config = AppConfig(relay=relay_cfg)
        config_manager = MagicMock()
        config_manager.get.return_value = config

        env = {"SERVONAUT_USER_ID": "user-1"}
        with patch("servonaut.config.manager.ConfigManager", return_value=config_manager), \
             patch.dict(os.environ, env, clear=False):
            os.environ.pop("SERVONAUT_RELAY_TOKEN", None)
            with pytest.raises(SystemExit):
                _relay_run_foreground()

    def test_missing_user_id_causes_exit(self):
        """Missing SERVONAUT_USER_ID must also cause sys.exit."""
        from servonaut.config.schema import AppConfig, RelayConfig
        relay_cfg = RelayConfig(
            base_url="https://app.example.com",
            mercure_url="https://hub.example.com/.well-known/mercure",
        )
        config = AppConfig(relay=relay_cfg)
        config_manager = MagicMock()
        config_manager.get.return_value = config

        env = {"SERVONAUT_RELAY_TOKEN": "tok-abc"}
        with patch("servonaut.config.manager.ConfigManager", return_value=config_manager), \
             patch.dict(os.environ, env, clear=False):
            os.environ.pop("SERVONAUT_USER_ID", None)
            with pytest.raises(SystemExit):
                _relay_run_foreground()

    def test_missing_base_url_config_causes_exit(self):
        """Empty relay.base_url must cause sys.exit."""
        from servonaut.config.schema import AppConfig, RelayConfig
        relay_cfg = RelayConfig(
            base_url="",
            mercure_url="https://hub.example.com/.well-known/mercure",
        )
        config = AppConfig(relay=relay_cfg)
        config_manager = MagicMock()
        config_manager.get.return_value = config

        env = {
            "SERVONAUT_RELAY_TOKEN": "tok-abc",
            "SERVONAUT_USER_ID": "user-1",
        }
        with patch("servonaut.config.manager.ConfigManager", return_value=config_manager), \
             patch.dict(os.environ, env, clear=False):
            with pytest.raises(SystemExit):
                _relay_run_foreground()

    def test_missing_mercure_url_config_causes_exit(self):
        """Empty relay.mercure_url must cause sys.exit."""
        from servonaut.config.schema import AppConfig, RelayConfig
        relay_cfg = RelayConfig(
            base_url="https://app.example.com",
            mercure_url="",
        )
        config = AppConfig(relay=relay_cfg)
        config_manager = MagicMock()
        config_manager.get.return_value = config

        env = {
            "SERVONAUT_RELAY_TOKEN": "tok-abc",
            "SERVONAUT_USER_ID": "user-1",
        }
        with patch("servonaut.config.manager.ConfigManager", return_value=config_manager), \
             patch.dict(os.environ, env, clear=False):
            with pytest.raises(SystemExit):
                _relay_run_foreground()


# ---------------------------------------------------------------------------
# _run_connect dispatch
# ---------------------------------------------------------------------------

class TestRunConnect:
    def test_status_flag_calls_relay_status(self, monkeypatch):
        import argparse
        args = argparse.Namespace(stop=False, status=True, bg=False, debug=False)
        with patch.object(main_module, "_relay_status") as mock_status:
            main_module._run_connect(args)
        mock_status.assert_called_once()

    def test_stop_flag_calls_relay_stop(self):
        import argparse
        args = argparse.Namespace(stop=True, status=False, bg=False, debug=False)
        with patch.object(main_module, "_relay_stop") as mock_stop:
            main_module._run_connect(args)
        mock_stop.assert_called_once()

    def test_bg_flag_calls_start_background(self):
        import argparse
        args = argparse.Namespace(stop=False, status=False, bg=True, debug=False)
        with patch.object(main_module, "_relay_start_background") as mock_bg:
            main_module._run_connect(args)
        mock_bg.assert_called_once()

    def test_no_flags_calls_run_foreground(self):
        import argparse
        args = argparse.Namespace(stop=False, status=False, bg=False, debug=False)
        with patch.object(main_module, "_relay_run_foreground") as mock_fg:
            main_module._run_connect(args)
        mock_fg.assert_called_once()
