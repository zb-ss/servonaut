"""``servonaut --config <path>`` must actually be used by the TUI."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from servonaut.config.manager import ConfigManager, CONFIG_PATH


def test_config_manager_reads_and_writes_the_given_file(tmp_path) -> None:
    path = tmp_path / "recording.json"
    path.write_text(json.dumps({"version": 4, "default_username": "deploy"}))
    manager = ConfigManager(config_path=path)
    assert manager._config_path == path
    assert manager.get().default_username == "deploy"


def test_config_manager_defaults_to_the_home_file() -> None:
    assert ConfigManager()._config_path == CONFIG_PATH


def test_app_passes_the_path_to_its_config_manager(tmp_path) -> None:
    from servonaut.app import ServonautApp

    app = ServonautApp(config_path=tmp_path / "recording.json")
    assert app._config_path == tmp_path / "recording.json"


def test_main_forwards_the_flag(tmp_path) -> None:
    from servonaut import main as main_module

    fake_app = MagicMock()
    with patch("servonaut.app.ServonautApp", return_value=fake_app) as cls, \
            patch("servonaut.utils.native_stderr.redirect_native_stderr"), \
            patch.object(main_module, "_setup_logging", return_value=None), \
            patch("sys.argv", ["servonaut", "--config", str(tmp_path / "recording.json"), "--debug"]):
        main_module.main()
    assert cls.call_args.kwargs["config_path"] == tmp_path / "recording.json"
    fake_app.run.assert_called_once()
