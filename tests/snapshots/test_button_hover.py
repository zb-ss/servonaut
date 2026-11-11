"""Hovering a button brightens its frame; it never underlines the words.

Walks the screens that can be mounted with the real stylesheets, hovers every
enabled button and compares it with its idle look. Link-style controls
(``LinkButton``, the sidebar entries and the header links) are underlined on
purpose and are skipped. A compact button has no frame, so its hover cue is a
background tint instead.
"""

from __future__ import annotations

from typing import Any, List

import pytest
from textual.widgets import Button, DataTable

from servonaut.widgets.link_button import LinkButton

from . import _geometry, test_screens as screens
from . import test_memory_bulk_share as bulk
from . import test_memory_family as family
from . import test_memory_share as share
from . import test_teams as teams

_EXEMPT_ANCESTORS = ("Sidebar", "WorkspaceControls", "SafeHeader")
# Menus: their rows are checked by the menu hover tests.
_EXEMPT_IDS = ("settings-nav-list",)


def _tested_buttons(screen: Any) -> List[Button]:
    found = []
    for button in screen.query(Button):
        # A focused button already shows the keyboard cue; hover adds nothing to compare.
        if button.has_class("-current-view") or button.has_class("--chosen") or isinstance(button, LinkButton) or button.disabled or not button.display or button.has_focus:
            continue
        if any(
            type(a).__name__ in _EXEMPT_ANCESTORS or isinstance(a, DataTable) or a.id in _EXEMPT_IDS
            for a in button.ancestors
        ):
            continue
        region = button.region
        if region.height == 0 or not screen.region.contains_region(region):
            continue
        # Another widget (a docked bar, a popup) may cover it: the pointer would not reach it.
        centre = region.center
        if screen.get_widget_at(*centre)[0] is not button:
            continue
        found.append(button)
    return found


def _look(button: Button) -> tuple:
    styles = button.styles
    # (frame colour, background, text colour, underlined, reversed, frame style)
    return (
        styles.border_top[1], styles.background, styles.color,
        bool(styles.text_style.underline), bool(styles.text_style.reverse), styles.border_top[0],
    )


async def hover_problems(pilot: Any) -> List[str]:
    screen = pilot.app.screen
    buttons = _tested_buttons(screen)
    await pilot.hover(screen, offset=(0, screen.size.height - 1))
    await pilot.pause()
    idle = {id(b): _look(b) for b in buttons}
    problems = []
    for button in buttons:
        await pilot.hover(button)
        await pilot.pause(0.05)
        if not button.mouse_hover:
            # The test pointer did not reach it (a clipped scroll area): nothing to compare.
            continue
        now = _look(button)
        name = f"{type(button).__name__}#{button.id or '-'}[{button.variant}]"
        if now[3]:
            problems.append(f"{name} underlines its words on hover")
        before = idle[id(button)]
        # A button with no frame (compact, or a bare text control) shows hover by its fill.
        compact = button.has_class("-textual-compact") or before[5] in ("", "none", "blank", "hidden")
        if compact and before[1].a > 0.9:
            continue  # a chosen chip or tab is already filled
        changed = (
            (now[1] != before[1] or now[4] != before[4]) if compact
            else (now[0] != before[0] or now[5] != before[5] or now[4] != before[4])
        )
        if not changed:
            problems.append(
                f"{name} shows no hover cue ({'background' if compact else 'frame'}): {before} -> {now}"
            )
    return problems


def _scenario_check(scenario: Any, size: str, name: str) -> None:
    result: List[str] = []

    async def run(pilot: Any) -> None:
        await scenario(pilot)
        result.extend(await hover_problems(pilot))

    _geometry.run(run, size, lambda pilot: None, name=f"hover-{name}")
    assert not result, "\n".join(r.split(": (")[0] for r in result)


_SCENARIOS = {
    "fleet": screens._fleet,
    "server_actions": screens._server_actions,
    "server_actions_custom": screens._server_actions_of(screens._harness.CUSTOM_SERVERS[0].name),
    "custom_servers": screens._custom_servers,
    "ip_ban": screens._ip_ban_configured,
    "findings": family._findings,
    "share_form": share._shared_form,
    "bulk_form": bulk._bulk_form,
    "teams": teams._agent_rules_card(teams._RULES),
}


@pytest.mark.parametrize("size", ["160x50", "100x30"])
@pytest.mark.parametrize("name", list(_SCENARIOS))
def test_hover_brightens_the_frame_and_never_underlines(name: str, size: str) -> None:
    _scenario_check(_SCENARIOS[name], size, name)


def test_every_variant_of_every_button_class_hovers_cleanly() -> None:
    """Plain and action buttons, every variant, framed and compact."""
    from textual.screen import Screen
    from textual.widgets import Button as TextualButton

    from servonaut.widgets.action_button import ActionButton

    variants = ("default", "primary", "success", "warning", "error")

    class _Matrix(Screen):
        def compose(self):
            for variant in variants:
                yield TextualButton(f"plain {variant}", variant=variant, id=f"plain_{variant}")
                yield ActionButton(f"action {variant}", "k", role=variant if variant in (
                    "default", "primary", "warning", "error") else "default",
                    id=f"action_{variant}")
                yield ActionButton(f"compact {variant}", "k", compact=True, id=f"compact_{variant}")

    async def scenario(pilot: Any) -> None:
        pilot.app.push_screen(_Matrix())
        await pilot.pause()
        await pilot.pause()

    _scenario_check(scenario, "160x50", "matrix")


def test_vault_action_rail_hovers_without_underline() -> None:
    import asyncio

    from servonaut.screens.vault import VaultScreen
    from tests._async_bounds import wait_until
    from tests.test_vault_screen import _StyledVaultHost
    from tests.test_vault_workspace_views import _Service

    from . import _harness
    from .test_vault_short_layout import _ready

    app = _StyledVaultHost(_Service(local=True))
    result: List[str] = []

    async def main() -> None:
        async with app.run_test(size=_harness.SIZES["160x50"]) as pilot:
            screen = app.screen
            await wait_until(lambda: isinstance(screen, VaultScreen) and _ready(screen))
            result.extend(await hover_problems(pilot))

    asyncio.run(main())
    assert not result, "\n".join(r.split(": (")[0] for r in result)


def _settings_panel_ids() -> list:
    from servonaut.screens.settings.registry import PANELS

    return [panel.id for panel in PANELS]


@pytest.mark.parametrize("size", ["160x50", "100x30"])
@pytest.mark.parametrize("panel_id", _settings_panel_ids())
def test_settings_panels_hover_cleanly_in_dark_light_and_terminal_themes(panel_id: str, size: str) -> None:
    result: List[str] = []

    async def scenario(pilot: Any) -> None:
        pilot.app.open_settings_screen(panel_id)
        screen = await screens._harness.wait_for_screen(pilot, "SettingsScreen")
        await screens._harness.wait_until(
            pilot,
            lambda: screen._current_panel() is not None and screen._current_panel()._loaded
            and not screen._current_panel()._settling,
            f"the {panel_id} panel to settle",
        )
        for theme in ("servonaut", "servonaut-light", "ansi-dark"):
            pilot.app.theme = theme
            await pilot.pause(0.2)
            result.extend(f"{theme}: {problem}" for problem in await hover_problems(pilot))

    _geometry.run(scenario, size, lambda pilot: None, name=f"hover-settings-{panel_id}")
    assert not result, "\n".join(r.split(": (")[0] for r in result)
