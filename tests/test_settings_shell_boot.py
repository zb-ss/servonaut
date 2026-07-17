"""Headless boot smoke for the master/detail settings shell.

Mounts the real :class:`SettingsScreen`, asserts all registered panels mount
(no placeholder fallbacks), then switches between several panels to confirm the
active/inactive display toggling works without runtime errors.

This is the functional gate for the settings refactor: ``import`` smoke proves
the modules load, but only a live Textual boot proves the panels compose, load
from config, and switch cleanly.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from textual.app import App

from servonaut.config.schema import AppConfig
from servonaut.screens.settings.registry import PANELS
from servonaut.styles import CSS_FILES


class _SettingsBootApp(App):
    """Minimal host that mounts the real SettingsScreen with a real config."""

    CSS_PATH = CSS_FILES

    def __init__(self) -> None:
        super().__init__()
        self._config = AppConfig()
        self.config_manager = MagicMock()
        self.config_manager.get = MagicMock(return_value=self._config)
        # Services are accessed via getattr(..., None) in the panels; leaving
        # them unset exercises the not-configured branches.
        self.auth_service = MagicMock()
        self.auth_service.is_authenticated = False
        self.auth_service.has_feature = MagicMock(return_value=False)

    def on_mount(self) -> None:
        from servonaut.screens.settings import SettingsScreen

        self.push_screen(SettingsScreen())


@pytest.mark.asyncio
async def test_only_the_initial_panel_is_built_on_open():
    """Opening settings builds ONE panel, not the whole catalog.

    Performance guard: mounting every panel up front cost ~4 s before the
    screen could paint (each mount re-applies the stylesheet against a growing
    tree). Panels must stay lazy — built on first selection.
    """
    app = _SettingsBootApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        screen = app.screen
        assert list(screen._panels.keys()) == [PANELS[0].id]
        # Nav buttons are spec-driven, so every panel is still reachable.
        for spec in PANELS:
            assert screen.query_one(f"#navbtn_{spec.id}") is not None


@pytest.mark.asyncio
async def test_all_panels_build_no_placeholders():
    """Every registry panel builds as a real panel — no placeholder fallback.

    Panels are lazy now, so force each one through the shell's own build path
    rather than relying on open to have mounted them.
    """
    app = _SettingsBootApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        screen = app.screen
        for spec in PANELS:
            screen._ensure_content(spec.id)
        await pilot.pause()
        # The shell records successfully-built panels keyed by id.
        assert set(screen._panels.keys()) == {spec.id for spec in PANELS}
        assert len(screen._panels) == len(PANELS)
        # No placeholder widgets were mounted (those signal a broken factory).
        placeholders = screen.query(".panel-unavailable")
        assert len(placeholders) == 0


@pytest.mark.asyncio
async def test_panels_are_built_once_and_cached():
    """Revisiting a panel reuses the instance — no rebuild cost, no state loss."""
    app = _SettingsBootApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        screen = app.screen

        screen._switch_to("aws")
        await pilot.pause()
        first_instance = screen._panels["aws"]

        screen._switch_to("mcp")
        await pilot.pause()
        screen._switch_to("aws")
        await pilot.pause()

        assert screen._panels["aws"] is first_instance
        assert first_instance.display is True


@pytest.mark.asyncio
async def test_switch_three_panels():
    """Switching panels toggles display and the active nav highlight cleanly."""
    app = _SettingsBootApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        screen = app.screen

        # The first registry panel is active by default.
        first_id = PANELS[0].id
        assert screen._active_id == first_id
        assert screen._panels[first_id].display is True

        for target in ("aws", "mcp", "memory"):
            screen._switch_to(target)
            await pilot.pause()
            assert screen._active_id == target
            assert screen._panels[target].display is True
            # All other panels are hidden.
            for pid, panel in screen._panels.items():
                if pid != target:
                    assert panel.display is False
            # The active nav button carries the highlight class.
            nav_btn = screen.query_one(f"#navbtn_{target}")
            assert "--active" in nav_btn.classes


@pytest.mark.asyncio
async def test_save_dock_stays_on_screen_for_tall_panels():
    """Tall panels keep the per-panel Save dock within the visible screen.

    Regression guard: panels with more fields than fit on screen (aws, mcp,
    memory, log_viewer, scan, gcp, azure, ovh) must scroll their form body
    internally so the Save button never slides off the bottom. Each panel wraps
    its rows in a ``.panel-body`` (1fr scroll) with the title pinned above and
    the status row + Save dock pinned below.
    """
    tall = ("scan", "aws", "ovh", "gcp", "azure", "log_viewer", "mcp", "memory")
    app = _SettingsBootApp()
    async with app.run_test(size=(140, 42)) as pilot:
        await pilot.pause()
        screen = app.screen
        screen_h = app.size.height
        for target in tall:
            screen._switch_to(target)
            await pilot.pause()
            await pilot.pause()
            panel = screen._panels[target]
            # The scrollable body wrapper must exist (exactly one per panel).
            assert len(panel.query(".panel-body")) == 1, f"{target}: no panel-body"
            save = panel.query_one(f"#save_{target}")
            region = save.region
            assert region.height > 0, f"{target}: save dock not laid out"
            assert region.y >= 0 and region.bottom <= screen_h, (
                f"{target}: Save dock off-screen "
                f"(region={region}, screen_h={screen_h})"
            )


@pytest.mark.asyncio
async def test_nav_sections_collapsible_and_search_aware():
    """Nav groups are collapsible (only the active group expanded), and search
    re-expands groups with matches while hiding groups without."""
    app = _SettingsBootApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        await pilot.pause()
        screen = app.screen
        sections = screen._sections
        assert len(sections) >= 5  # one per group
        # Initially only the first group (active panel's group) is expanded.
        expanded = [g for g, s in sections.items() if not s.collapsed]
        assert len(expanded) == 1

        # Switching to a panel in another group expands that group only.
        screen._switch_to("aws")
        await pilot.pause()
        assert sections["Cloud Providers"].collapsed is False
        assert sections["General"].collapsed is True

        # Search must surface a match even though its group could be collapsed:
        # the group is shown + expanded, non-matching groups are hidden.
        screen._apply_filter("hetzner")
        await pilot.pause()
        assert sections["Cloud Providers"].display is True
        assert sections["Cloud Providers"].collapsed is False
        assert sections["General"].display is False
        assert screen.query_one("#navbtn_hetzner").display is True

        # Clearing restores all groups, only the active group expanded.
        screen._apply_filter("")
        await pilot.pause()
        assert all(s.display for s in sections.values())
        assert sections["Cloud Providers"].collapsed is False
        assert sections["General"].collapsed is True


@pytest.mark.asyncio
async def test_preview_panels_show_banner_and_nav_tag():
    """Scaffolded providers (GCP/Azure) carry a preview banner + nav tag.

    The nav tag is spec-driven so it is asserted before the panel is built;
    the banner needs the panel, so it is built on demand first.
    """
    from servonaut.screens.settings.widgets import PreviewBanner

    app = _SettingsBootApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        await pilot.pause()
        screen = app.screen
        for pid in ("gcp", "azure"):
            # Nav tag is available without building the panel.
            assert "preview" in str(screen.query_one(f"#navbtn_{pid}").label).lower()
            screen._ensure_content(pid)
            await pilot.pause()
            assert len(screen._panels[pid].query(PreviewBanner)) == 1
        # A live provider is NOT tagged.
        assert "preview" not in str(screen.query_one("#navbtn_aws").label).lower()


@pytest.mark.asyncio
async def test_search_filters_nav_buttons():
    """Typing in the search box hides non-matching nav buttons."""
    app = _SettingsBootApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        screen = app.screen
        screen._apply_filter("hetzner")
        await pilot.pause()
        assert screen.query_one("#navbtn_hetzner").display is True
        assert screen.query_one("#navbtn_aws").display is False
        # Clearing the filter restores all buttons.
        screen._apply_filter("")
        await pilot.pause()
        assert screen.query_one("#navbtn_aws").display is True
