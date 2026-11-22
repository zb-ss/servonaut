"""Hovering a button brightens its frame; it never underlines the words.

Walks the screens that can be mounted with the real stylesheets, hovers every
enabled button and compares it with its idle look. Link-style controls
(``LinkButton``, the sidebar entries and the header links) are underlined on
purpose and are skipped. A compact button has no frame, so its hover cue is a
background tint instead.

A button that has a frame never fills its background on hover: the fill is drawn
in whole cells, so it shows as square corners outside the round frame. A
disabled button looks the same hovered as idle.
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


def _tested_buttons(screen: Any, *, disabled: bool = False) -> List[Button]:
    found = []
    for button in screen.query(Button):
        # A focused button already shows the keyboard cue; hover adds nothing to compare.
        if button.has_class("-current-view") or button.has_class("--chosen") or isinstance(button, LinkButton) or not button.display or button.has_focus:
            continue
        if button.disabled and not disabled:
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


def _is_framed(look: tuple, button: Button) -> bool:
    return not button.has_class("-textual-compact") and look[5] not in ("", "none", "blank", "hidden")


def _painted_background(button: Button) -> tuple:
    """What is drawn behind the button, tints and transparency resolved."""
    return tuple(button.background_colors)


async def hover_problems(pilot: Any) -> List[str]:
    screen = pilot.app.screen
    buttons = _tested_buttons(screen)
    await pilot.hover(screen, offset=(0, screen.size.height - 1))
    await pilot.pause()
    idle = {id(b): _look(b) for b in buttons}
    idle_paint = {id(b): _painted_background(b) for b in buttons}
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
        if _is_framed(before, button) and _painted_background(button) != idle_paint[id(button)]:
            problems.append(f"{name} fills behind its frame on hover: {idle_paint[id(button)]} -> {_painted_background(button)}")
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


async def disabled_problems(pilot: Any) -> List[str]:
    """Every button, disabled, looks the same hovered as idle."""
    screen = pilot.app.screen
    from servonaut.widgets.action_button import ActionButton

    # Chrome that is never disabled in practice (chips, nav rows, bare text
    # controls) has its own hover fill and is not forced into this state.
    buttons = [
        b for b in _tested_buttons(screen, disabled=True)
        if b.disabled or isinstance(b, ActionButton)
        or (_is_framed(_look(b), b) and not b.has_class("fleet-chip"))
    ]
    was_disabled = {id(b): b.disabled for b in buttons}
    for button in buttons:
        button.disabled = True
    await pilot.pause()
    await pilot.hover(screen, offset=(0, screen.size.height - 1))
    await pilot.pause()
    problems = []
    try:
        idle = {id(b): (_look(b), _painted_background(b)) for b in buttons}
        for button in buttons:
            await pilot.hover(button)
            await pilot.pause(0.05)
            if not button.mouse_hover:
                continue
            now = (_look(button), _painted_background(button))
            if now != idle[id(button)]:
                name = f"{type(button).__name__}#{button.id or '-'}[{button.variant}]"
                problems.append(f"disabled {name} changes on hover: {idle[id(button)]} -> {now}")
    finally:
        for button in buttons:
            button.disabled = was_disabled[id(button)]
        await pilot.pause()
    return problems


def _scenario_check(scenario: Any, size: str, name: str) -> None:
    result: List[str] = []

    async def run(pilot: Any) -> None:
        await scenario(pilot)
        result.extend(await hover_problems(pilot))
        result.extend(await disabled_problems(pilot))

    _geometry.run(run, size, lambda pilot: None, name=f"hover-{name}")
    assert not result, "\n".join(result)


def _modal_over_fleet(build: Any, screen_name: str) -> Any:
    """Push a dialog built by *build* over the fleet and wait for it."""

    async def scenario(pilot: Any) -> None:
        pilot.app.push_screen(build())
        screen = await screens._harness.wait_for_screen(pilot, screen_name)
        await pilot.pause(0.3)
        # Dialogs load their lists in a worker; give it a moment to finish.
        await pilot.pause(0.3)
        assert screen is pilot.app.screen

    return scenario


def _bulk_delete_dialog() -> Any:
    from servonaut.screens.bulk_action import BulkActionModal, BulkPreset

    return BulkActionModal(
        "Delete vault keys", "Delete selected keys from this vault only.",
        [(f"k{n}", f"key-{n}") for n in range(1, 6)],
        action_label="Delete", confirm_text="DELETE",
        preset=BulkPreset("Select duplicates", ("k1", "k2")),
    )


def _vault_import_dialog() -> Any:
    from pathlib import Path
    from unittest.mock import AsyncMock, MagicMock

    from servonaut.screens.vault_import_modal import VaultImportModal

    service = MagicMock()
    service.stored_keys = AsyncMock(return_value={})
    return VaultImportModal(service, "vault-1", Path("/nonexistent-ssh-dir"))


def _bw_key_import_dialog() -> Any:
    from pathlib import Path
    from unittest.mock import MagicMock

    from servonaut.screens.bw_key_import import BwKeyImportModal

    return BwKeyImportModal(Path("/nonexistent-ssh-dir"), session_service=MagicMock())


def _path_picker_dialog() -> Any:
    from pathlib import Path

    from servonaut.screens.path_picker import LocalPathPickerModal

    return LocalPathPickerModal(str(Path.home()), source=True)


def _scp_confirm_dialog(kind: str) -> Any:
    from servonaut.screens.scp_folder_confirm import SCPFolderConfirmModal

    return lambda: SCPFolderConfirmModal(target="/srv/app/releases", kind=kind)


async def _updates_actions(pilot: Any) -> None:
    """The Updates panel with every action shown: the idle state hides them all."""
    pilot.app.open_settings_screen("updates")
    screen = await screens._harness.wait_for_screen(pilot, "SettingsScreen")
    await screens._harness.wait_until(
        pilot,
        lambda: screen._current_panel() is not None and screen._current_panel()._loaded
        and not screen._current_panel()._settling,
        "the updates panel to settle",
    )
    for button in screen.query(Button):
        if button.id and button.id.startswith("updates_btn_"):
            button.display = True
            button.disabled = False
    await pilot.pause()


_SCENARIOS = {
    "settings_updates_actions": _updates_actions,
    "bulk_delete_keys": _modal_over_fleet(_bulk_delete_dialog, "BulkActionModal"),
    "vault_import": _modal_over_fleet(_vault_import_dialog, "VaultImportModal"),
    "bw_key_import": _modal_over_fleet(_bw_key_import_dialog, "BwKeyImportModal"),
    "path_picker": _modal_over_fleet(_path_picker_dialog, "LocalPathPickerModal"),
    "scp_folder_confirm": _modal_over_fleet(_scp_confirm_dialog("directory"), "SCPFolderConfirmModal"),
    "scp_folder_unchecked": _modal_over_fleet(_scp_confirm_dialog("unknown"), "SCPFolderConfirmModal"),
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
            result.extend(await disabled_problems(pilot))

    asyncio.run(main())
    assert not result, "\n".join(result)


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
            result.extend(f"{theme}: {problem}" for problem in await disabled_problems(pilot))

    _geometry.run(scenario, size, lambda pilot: None, name=f"hover-settings-{panel_id}")
    assert not result, "\n".join(result)
