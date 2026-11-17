"""Navigation visibility belongs to one running application."""

from servonaut.app import ServonautApp


def test_workspace_preferences_are_owned_by_each_app() -> None:
    first, second = ServonautApp(), ServonautApp()
    assert first.workspace_state.navigation_visible
    first.workspace_state.navigation_visible = False
    assert second.workspace_state.navigation_visible
    assert first.workspace_state is not second.workspace_state


def test_workspace_actions_are_inert_before_the_first_screen_mounts() -> None:
    app = ServonautApp()
    assert app.screen_stack == []
    assert app.check_action("focus_navigation", ()) is False
    assert app.check_action("toggle_navigation", ()) is False
    app.action_focus_navigation()
    app.action_toggle_navigation()
    assert app.workspace_state.navigation_visible
