"""Regression: team config push/pull must read config via config_manager.

These forms previously read ``getattr(self.app, "config", None)`` — but the app
exposes ``config_manager``, not ``config``, so the lookup was always ``None`` and
the forms always errored with "Local config not available." This guards that the
config is now resolved through ``config_manager.get()``.
"""

from unittest.mock import MagicMock, PropertyMock, patch

from servonaut.screens.team_management import TeamManagementScreen


def _summary():
    return {
        "connection_profiles": 0,
        "connection_rules": 0,
        "scan_rules": 0,
        "custom_servers": 0,
        "stripped_paths": 0,
    }


def test_push_config_form_resolves_config_via_config_manager():
    screen = TeamManagementScreen.__new__(TeamManagementScreen)
    screen.query_one = MagicMock()
    screen.notify = MagicMock()

    sentinel_config = object()
    mock_app = MagicMock()
    mock_app.config_manager.get.return_value = sentinel_config

    with patch.object(TeamManagementScreen, "app", new_callable=PropertyMock, return_value=mock_app), \
         patch("servonaut.services.team_config_subset.build_shareable_subset",
               return_value=({}, _summary())) as bss:
        screen._show_push_config_form()

    # The form got PAST the None-guard (no error notify) and used the config
    # returned by config_manager.get() — proving the dead self.app.config read
    # is gone.
    mock_app.config_manager.get.assert_called_once()
    bss.assert_called_once_with(sentinel_config)
    # No "Local config not available." error was raised.
    for call in screen.notify.call_args_list:
        assert "not available" not in str(call)
