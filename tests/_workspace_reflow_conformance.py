"""Shared native workspace assertions with explicit per-screen adapters."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from unittest.mock import Mock, patch

from textual.pilot import Pilot
from textual.widget import Widget
from textual.widgets import Button, TextArea
from textual.widgets.text_area import Selection

from servonaut.app import ServonautApp
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests.test_fleet_workspace_layout import _open_chat
from tests.test_workspace_pilot import _click
from tests.test_workspace_reflow import _painted


@dataclass(frozen=True)
class BoundarySample:
    """Pin a qualified native width and its separately qualified policy flags."""

    size: tuple[int, int]
    native_content_width: int
    expected_replace: bool
    expected_content_narrow: bool


@dataclass(frozen=True)
class ReflowCase:
    name: str
    app_factory: Callable[[bool], ServonautApp]
    open_screen: Callable[[ServonautApp, Pilot], Awaitable[WorkspaceScreen]]
    ready: Callable[[WorkspaceScreen], Awaitable[None]]
    primary_focus_selector: str
    essential_targets: tuple[str, ...]
    seed_state: Callable[[WorkspaceScreen], None]
    state: Callable[[WorkspaceScreen], object]
    painted_targets: tuple[tuple[str, str], ...]
    boundaries: Mapping[
        tuple[str, bool], tuple[BoundarySample, BoundarySample, BoundarySample]
    ] | None = None

    def boundary_samples(
        self, kind: str, navigation_visible: bool,
    ) -> tuple[BoundarySample, BoundarySample, BoundarySample]:
        if self.boundaries is None or (kind, navigation_visible) not in self.boundaries:
            raise AssertionError(f"{self.name} needs qualified native {kind} samples")
        return self.boundaries[kind, navigation_visible]


async def open_case(
    case: ReflowCase, app: ServonautApp, pilot: Pilot,
) -> WorkspaceScreen:
    screen = await case.open_screen(app, pilot)
    await case.ready(screen)
    await pilot.pause()
    await wait_until(lambda: app.focused is screen.query_one(case.primary_focus_selector))
    assert app.focused is screen.query_one(case.primary_focus_selector)
    assert screen.query_one("#main-layout").has_class("workspace-chat-layout")
    assert len(screen.query(".workspace-content")) == 1
    case.seed_state(screen)
    await pilot.pause()
    return screen


def content(screen: WorkspaceScreen) -> Widget:
    body = screen.query_one(".workspace-content")
    assert body.parent is screen.query_one("#main-layout")
    return body


def _match_button_label_rows(
    expected: tuple[str, ...], painted: tuple[str, ...],
) -> tuple[int, tuple[int, ...]]:
    """Match every native-wrapped row, allowing only ASCII alignment margins."""
    for start in range(len(painted) - len(expected) + 1):
        outside = painted[:start] + painted[start + len(expected):]
        if any(row.strip(" ") for row in outside):
            continue
        columns = []
        for fragment, row in zip(expected, painted[start:]):
            # Plain-terminal themes paint the cap's edges as reversed spaces.
            variants = (fragment, fragment.replace("\u2590", " ").replace("\u258c", " "))
            for column in range(len(row) - len(fragment) + 1):
                if any(
                    row == " " * column + variant + " " * (len(row) - column - len(variant))
                    for variant in variants
                ):
                    columns.append(column)
                    break
            else:
                break
        if len(columns) == len(expected):
            return start, tuple(columns)
    raise AssertionError(f"Full button label rows missing or reordered: {expected!r}; paint={painted!r}")


def assert_button_label_painted(app: ServonautApp, button: Button) -> None:
    """Require the complete label in final paint, including hard/soft wraps."""
    from rich.cells import cell_len

    region = button.content_region
    width = region.width - 2 * button.styles.line_pad
    assert width > 0 and region.height > 0
    # Unlimited-height fold predicts all glyphs; clipped/ellipsis output must
    # not become the expected label merely because the widget is too small.
    expected = tuple(line.plain for line in button.label.without_spans.wrap(width, overflow="fold"))
    assert len(expected) <= region.height, (expected, region)
    assert app.screen.region.contains_region(region)
    strips = app.screen._compositor.render_strips()
    painted = tuple(strips[y].crop(region.x, region.right).text for y in range(region.y, region.bottom))
    start, columns = _match_button_label_rows(expected, painted)
    for line, (fragment, column) in enumerate(zip(expected, columns), start=start):
        left = region.x + cell_len(painted[line][:column])
        for x in range(left, left + cell_len(fragment)):
            hit = app.get_widget_at(x, region.y + line)[0]
            assert hit is button or button in hit.ancestors


async def wait_button_label_painted(app: ServonautApp, button: Button) -> None:
    """Wait, bounded, for a button's label and hit region to catch up after reflow."""
    failure: AssertionError | None = None

    def holds() -> bool:
        nonlocal failure
        try:
            assert_button_label_painted(app, button)
        except AssertionError as error:
            failure = error
            return False
        return True

    try:
        await wait_until(holds)
    except asyncio.TimeoutError:
        raise failure or AssertionError("button label did not paint") from None


def assert_controls(app: ServonautApp, screen: WorkspaceScreen) -> None:
    selectors = ["#workspace_navigation", "#workspace_chat"]
    if screen.query(ChatPanel):
        selectors.append("#workspace_chat_end")
    for selector in selectors:
        button = screen.query_one(selector, Button)
        assert screen.region.contains_region(button.region)
        assert app.get_widget_at(*button.region.center)[0] is button
        assert_button_label_painted(app, button)


def assert_layout(app: ServonautApp, screen: WorkspaceScreen) -> None:
    row, body = screen.query_one("#main-layout"), content(screen)
    sidebar = screen.query_one(Sidebar)
    panels = list(screen.query(ChatPanel))
    panel = panels[0] if panels else None
    is_open = panel is not None and not panel._collapsed
    navigation_width = sidebar.outer_size.width if sidebar.display else 0
    available = row.content_region.width - navigation_width
    assert body.is_attached
    assert screen.has_class("-chat-open") is is_open
    if not is_open:
        assert body.display and not screen.has_class("-chat-replace")
        assert body.outer_size.width == available
    else:
        assert panel.parent is row
        assert panel.region.width > 0
        if screen.has_class("-chat-replace"):
            assert not body.display
            assert panel.outer_size.width == available
        else:
            assert body.display and body.region.width > 0
            assert body.region.right <= panel.region.x
            assert body.outer_size.width + panel.outer_size.width == available
    assert_controls(app, screen)


async def settled_layout(app: ServonautApp, screen: WorkspaceScreen) -> None:
    """Run ``assert_layout`` once the layout has caught up with the last change.

    A resize or toggle is applied on later loop turns, so a single pause can
    be too short on a loaded machine. Wait, bounded, for the very assertions
    of ``assert_layout`` to hold; if they never do, the last failure is raised.
    """
    failure: AssertionError | None = None

    def holds() -> bool:
        nonlocal failure
        try:
            assert_layout(app, screen)
        except AssertionError as error:
            failure = error
            return False
        return True

    try:
        await wait_until(holds)
    except asyncio.TimeoutError:
        raise failure or AssertionError("layout did not settle") from None


@contextmanager
def one_layout_transition(screen: WorkspaceScreen) -> Iterator[None]:
    with patch.object(screen, "set_class", Mock(wraps=screen.set_class)) as changes:
        yield
    for name in ("-chat-open", "-chat-replace", "-content-narrow", "-chat-compact"):
        calls = [call for call in changes.call_args_list if name in call.args[1:]]
        assert len(calls) <= 1, (name, calls)


async def open_chat(
    app: ServonautApp, pilot: Pilot, screen: WorkspaceScreen,
) -> ChatPanel:
    with one_layout_transition(screen):
        panel = await _open_chat(app, pilot)
        await settled_layout(app, screen)
    return panel


async def collapse_chat(
    app: ServonautApp, pilot: Pilot, screen: WorkspaceScreen,
) -> None:
    with one_layout_transition(screen):
        await pilot.press("f2")
        await pilot.pause()
        await wait_until(lambda: not screen.has_class("-chat-replace"))
        await settled_layout(app, screen)


async def assert_essential_targets(
    case: ReflowCase, app: ServonautApp, pilot: Pilot, screen: WorkspaceScreen,
) -> None:
    body = content(screen)
    assert body.display
    for selector in case.essential_targets:
        target = screen.query_one(selector)
        target.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        assert target.region.width > 0 and target.region.height > 0
        assert body.region.x <= target.region.x
        assert target.region.x < target.region.right <= body.region.right
        assert screen.region.contains(*target.region.center)
        hit = app.get_widget_at(*target.region.center)[0]
        assert hit is target or target in hit.ancestors
        if isinstance(target, Button):
            await wait_button_label_painted(app, target)
    for selector, text in case.painted_targets:
        target = screen.query_one(selector)
        target.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        await wait_until(lambda t=target, expected=text: expected in _painted(app, t))
        assert text in _painted(app, target)


async def tab_to(pilot: Pilot, target: Widget) -> None:
    for _ in range(len(pilot.app.screen.focus_chain) + 1):
        if pilot.app.focused is target:
            return
        await pilot.press("tab")
    raise AssertionError(f"Tab must reach {target!r}")


async def preserve_native_state(
    case: ReflowCase, app: ServonautApp, pilot: Pilot, screen: WorkspaceScreen,
) -> None:
    baseline = case.state(screen)
    panel = await open_chat(app, pilot, screen)
    editor = panel.query_one("#chat-input", TextArea)
    editor.load_text("Keep this café Ω draft")
    editor.selection = Selection((0, 5), (0, 14))
    selection = editor.selection
    document = editor.document
    if content(screen).display:
        closed_width = screen.query_one("#main-layout").content_region.width
        assert closed_width - content(screen).outer_size.width == panel.outer_size.width
    with one_layout_transition(screen):
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        await settled_layout(app, screen)
    assert case.state(screen) == baseline
    assert editor.document is document
    assert editor.selection == selection
    with one_layout_transition(screen):
        await pilot.resize_terminal(160, 50)
        await pilot.pause()
        await settled_layout(app, screen)
    await collapse_chat(app, pilot, screen)
    await wait_until(lambda: app.focused is screen.query_one(case.primary_focus_selector))
    assert editor.document is document and editor.text == "Keep this café Ω draft"
    assert editor.selection == selection
    assert panel._collapsed and panel.is_attached
    assert case.state(screen) == baseline
    for visible in (True, False):
        with one_layout_transition(screen):
            await _click(pilot, "#workspace_navigation")
            await pilot.pause()
            await wait_until(lambda: screen.query_one(Sidebar).display is visible)
            await settled_layout(app, screen)
        assert screen.query_one(Sidebar).display is visible
        assert case.state(screen) == baseline
    for selector in case.essential_targets:
        target = screen.query_one(selector)
        await tab_to(pilot, target)
        assert app.focused is target
    await assert_essential_targets(case, app, pilot, screen)


async def assert_visibility_combinations(
    case: ReflowCase,
    app: ServonautApp,
    pilot: Pilot,
    screen: WorkspaceScreen,
    *,
    include_collapsed: bool = False,
    targets_check: Callable[
        [ReflowCase, ServonautApp, Pilot, WorkspaceScreen], Awaitable[None]
    ] = assert_essential_targets,
    after_state: Callable[
        [ServonautApp, Pilot, WorkspaceScreen, bool, bool], Awaitable[None]
    ] | None = None,
    after_targets: Callable[
        [ServonautApp, Pilot, WorkspaceScreen], Awaitable[None]
    ] | None = None,
) -> None:
    """Verify the four (navigation_visible, chat_open) states in one app run."""
    baseline = case.state(screen)
    size = (app.size.width, app.size.height)

    async def check_state(navigation_visible: bool, chat_open: bool) -> None:
        await settled_layout(app, screen)
        assert_layout(app, screen)
        assert screen.query_one(Sidebar).display is navigation_visible
        assert case.state(screen) == baseline
        if chat_open and size == (160, 50) and not navigation_visible:
            assert content(screen).display
        if after_state is not None:
            await after_state(app, pilot, screen, navigation_visible, chat_open)
        if content(screen).display:
            entry_scroll = content(screen).scroll_y
            await targets_check(case, app, pilot, screen)
            if after_targets is not None:
                await after_targets(app, pilot, screen)
            if content(screen).scroll_y != entry_scroll:
                content(screen).scroll_to(y=entry_scroll, animate=False, immediate=True)
                await pilot.pause()
        assert case.state(screen) == baseline
        assert app._exception is None

    await check_state(False, False)

    panel = await open_chat(app, pilot, screen)
    await check_state(False, True)

    if include_collapsed:
        await collapse_chat(app, pilot, screen)
        assert panel._collapsed and panel.is_attached
        await check_state(False, False)
        await open_chat(app, pilot, screen)

    await _click(pilot, "#workspace_navigation")
    await pilot.pause()
    await wait_until(lambda: screen.query_one(Sidebar).display is True)
    await check_state(True, True)

    await collapse_chat(app, pilot, screen)
    assert panel._collapsed and panel.is_attached
    await check_state(True, False)


async def assert_qualified_boundaries(
    case: ReflowCase,
    app: ServonautApp,
    pilot: Pilot,
    screen: WorkspaceScreen,
    navigation_visible: bool,
    *,
    kinds: tuple[str, ...] = ("chat-min", "content-narrow"),
    check_replaced_width: bool = True,
    check_single_transition: bool = True,
    targets_check: Callable[
        [ReflowCase, ServonautApp, Pilot, WorkspaceScreen], Awaitable[None]
    ] = assert_essential_targets,
    after_targets: Callable[
        [ServonautApp, Pilot, WorkspaceScreen], Awaitable[None]
    ] | None = None,
) -> None:
    """Walk both boundary triples in one app run per navigation state."""
    sample_groups = [
        (kind, case.boundary_samples(kind, navigation_visible))
        for kind in kinds
    ]
    baseline = case.state(screen)
    await open_chat(app, pilot, screen)
    for kind, samples in sample_groups:
        threshold = (
            screen.CHAT_MIN_CONTENT_WIDTH if kind == "chat-min"
            else screen.CONTENT_NARROW_WIDTH
        )
        assert [sample.native_content_width for sample in samples] == [
            threshold - 1, threshold, threshold + 1,
        ]
        for sample in samples:
            if check_single_transition:
                with one_layout_transition(screen):
                    await pilot.resize_terminal(*sample.size)
                    await pilot.pause()
                    await wait_until(
                        lambda s=sample: screen.has_class("-chat-replace") is s.expected_replace
                        and screen.has_class("-content-narrow") is s.expected_content_narrow
                    )
                    await settled_layout(app, screen)
            else:
                await pilot.resize_terminal(*sample.size)
                await pilot.pause()
                await wait_until(
                    lambda s=sample: screen.has_class("-chat-replace") is s.expected_replace
                    and screen.has_class("-content-narrow") is s.expected_content_narrow
                )
                await settled_layout(app, screen)
            assert screen.has_class("-chat-replace") is sample.expected_replace
            assert screen.has_class("-content-narrow") is sample.expected_content_narrow
            assert_layout(app, screen)
            if sample.expected_replace:
                if check_replaced_width:
                    with patch.object(screen, "CHAT_MIN_CONTENT_WIDTH", 1):
                        screen.apply_workspace_state()
                        await pilot.pause()
                        await wait_until(
                            lambda s=sample: content(screen).region.width == s.native_content_width
                        )
                        assert content(screen).region.width == sample.native_content_width
                    screen.apply_workspace_state()
                    await pilot.pause()
                    await wait_until(
                        lambda s=sample: screen.has_class("-chat-replace") is s.expected_replace
                        and screen.has_class("-content-narrow") is s.expected_content_narrow
                        and not content(screen).display
                    )
                    assert screen.has_class("-chat-replace") is sample.expected_replace
                    assert screen.has_class("-content-narrow") is sample.expected_content_narrow
                    assert not content(screen).display
                    await settled_layout(app, screen)
            else:
                await wait_until(
                    lambda s=sample: content(screen).region.width == s.native_content_width
                )
                assert content(screen).region.width == sample.native_content_width
                entry_scroll = content(screen).scroll_y
                await targets_check(case, app, pilot, screen)
                if after_targets is not None:
                    await after_targets(app, pilot, screen)
                if content(screen).scroll_y != entry_scroll:
                    content(screen).scroll_to(y=entry_scroll, animate=False, immediate=True)
                    await pilot.pause()
            assert case.state(screen) == baseline
