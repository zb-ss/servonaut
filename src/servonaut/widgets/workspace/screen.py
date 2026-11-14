"""Opt-in attachment for screens with permanent workspace controls."""

from __future__ import annotations

from fractions import Fraction

from textual import events
from textual.binding import Binding
from textual.css.scalar import Scalar
from textual.geometry import Size
from textual.screen import Screen
from textual.widget import Widget

from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace.controls import WorkspaceControls


# Default chrome uses up to 19 rows; retain six rows for the transcript.
_CHAT_COMPACT_HEIGHT = 25


def _column_width(
    scalars: tuple[Scalar | None, Scalar | None, Scalar | None],
    size: Size,
    viewport: Size,
) -> Fraction | None:
    """Resolve declared column constraints without depending on its region."""
    width, minimum, maximum = scalars
    if width is None or any(
        scalar is not None and (scalar.is_auto or scalar.is_fraction)
        for scalar in scalars
    ):
        return None
    resolved = width.resolve(size, viewport)
    if minimum is not None:
        resolved = max(resolved, minimum.resolve(size, viewport))
    if maximum is not None:
        resolved = min(resolved, maximum.resolve(size, viewport))
    return max(Fraction(0), resolved)


class WorkspaceNotificationSpace(Widget):
    """Keep a stable, nonfocusable dock for the native notification rack."""


class WorkspaceScreen(Screen):
    """Apply session preferences without changing screen-stack ownership."""

    # Below this many columns the navigation collapses by itself.
    NAVIGATION_AUTO_HIDE_WIDTH = 110
    # Below this many rows the notification lane and toast rack are two rows
    # instead of four (class ``-lane-compact``, styled in workspace.tcss).
    NOTIFICATION_LANE_COMPACT_HEIGHT = 36

    CHAT_REFLOW = False
    CHAT_MIN_CONTENT_WIDTH: int | None = None
    CONTENT_NARROW_WIDTH: int | None = None

    def __init__(
        self, name: str | None = None, id: str | None = None,
        classes: str | None = None,
    ) -> None:
        if self.CHAT_REFLOW:
            self._reflow_thresholds()
        super().__init__(name=name, id=id, classes=classes)
        self._chat_column_panel: Widget | None = None
        self._chat_column_scalars: tuple[
            Scalar | None, Scalar | None, Scalar | None,
        ] | None = None

    async def on_mount(self) -> None:
        self._sync_notification_lane()
        if not any(isinstance(child, WorkspaceNotificationSpace) for child in self.children):
            await self.mount(WorkspaceNotificationSpace())

    def _sync_notification_lane(self, height: int | None = None) -> None:
        """Use the two-row lane on short terminals, from the terminal's own height."""
        rows = self.app.size.height if height is None else height
        self.set_class(rows < self.NOTIFICATION_LANE_COMPACT_HEIGHT, "-lane-compact")

    def _reflow_thresholds(self) -> tuple[int, int]:
        minimum, narrow = self.CHAT_MIN_CONTENT_WIDTH, self.CONTENT_NARROW_WIDTH
        if minimum is None or narrow is None or minimum <= 0 or narrow <= 0:
            raise ValueError(
                f"{type(self).__name__} requires positive CHAT_MIN_CONTENT_WIDTH "
                "and CONTENT_NARROW_WIDTH when CHAT_REFLOW is enabled"
            )
        return minimum, narrow

    def chat_host(self) -> Widget:
        """Opted-in screens place chat beside mounted content in their row."""
        return self.query_one("#main-layout") if self.CHAT_REFLOW else self

    def navigation_width_class(self) -> str:
        """"narrow" below the auto-hide width, otherwise "wide"."""
        return "narrow" if self.app.size.width < self.NAVIGATION_AUTO_HIDE_WIDTH else "wide"

    def navigation_should_show(self) -> bool:
        """An explicit choice made in this width class, else the automatic rule."""
        width_class = self.navigation_width_class()
        state = getattr(self.app, "workspace_state", None)
        if state is not None and state.navigation_choice_class == width_class:
            return state.navigation_visible
        return width_class == "wide"

    def expire_stale_navigation_choice(self) -> None:
        """Forget an explicit choice once the terminal is in the other width class."""
        state = getattr(self.app, "workspace_state", None)
        if state is None or state.navigation_choice_class is None:
            return
        if state.navigation_choice_class != self.navigation_width_class():
            state.navigation_choice_class = None
            state.navigation_visible = True

    def workspace_sidebar(self) -> Sidebar:
        """Set visibility before the first layout, including on a new screen."""
        sidebar = Sidebar()
        sidebar.display = self.navigation_should_show()
        return sidebar

    def apply_workspace_state(self) -> None:
        sidebar = next(iter(self.query(Sidebar)), None)
        if sidebar is None:
            return
        self.expire_stale_navigation_choice()
        if not sidebar.navigation_mode:
            sidebar.display = self.navigation_should_show()
        self.sync_workspace_controls()

    def sync_workspace_controls(self) -> None:
        if self.CHAT_REFLOW:
            self._sync_chat_layout()
            panel = next(iter(self.query("#chat-panel")), None)
            if panel is not None and not panel._collapsed:
                self.call_after_refresh(self._focus_chat_if_content_hidden)
        for controls in self.query(WorkspaceControls):
            controls.sync_state()

    def on_resize(self, event: events.Resize) -> None:
        self._sync_notification_lane(event.size.height)
        self.call_after_refresh(self.apply_workspace_state)
        if self.CHAT_REFLOW:
            self.call_after_refresh(self.sync_workspace_controls)

    def _sync_chat_layout(self) -> None:
        minimum, narrow = self._reflow_thresholds()
        row = next(iter(self.query("#main-layout")), None)
        if row is None or not row.content_region.width:
            return
        panel = next(iter(self.query("#chat-panel")), None)
        is_open = panel is not None and not panel._collapsed
        self._set_layout_class("-chat-open", is_open)
        self._set_layout_class(
            "-chat-compact",
            is_open and 0 < row.content_region.height < _CHAT_COMPACT_HEIGHT,
        )
        available = self._available_content_width(row, panel if is_open else None)
        if available is None:
            return
        self._set_layout_class(
            "-chat-replace", is_open and available < minimum,
        )
        self._set_layout_class("-content-narrow", available < narrow)
        if panel is None:
            self._chat_column_panel = None
            self._chat_column_scalars = None

    def _set_layout_class(self, name: str, enabled: bool) -> None:
        if self.has_class(name) != enabled:
            self.set_class(enabled, name)

    def _available_content_width(
        self, row: Widget, panel: Widget | None,
    ) -> Fraction | None:
        size, viewport = row.content_region.size, self.app.size
        available = Fraction(size.width)
        sidebar = next(iter(self.query(Sidebar)), None)
        if sidebar is not None and sidebar.display:
            styles = sidebar.styles
            width = _column_width(
                (styles.width, styles.min_width, styles.max_width),
                size - styles.margin.totals, viewport,
            )
            if width is None:
                return None
            available -= width + styles.margin.width
        if panel is not None:
            width = self._chat_column_width(row, panel)
            if width is None:
                return None
            available -= width + panel.styles.margin.width
        return max(Fraction(0), available)

    def _chat_column_width(self, row: Widget, panel: Widget) -> Fraction | None:
        if panel is not self._chat_column_panel:
            # A new panel must capture column rules, never replacement's 1fr.
            if self.has_class("-chat-replace"):
                self.remove_class("-chat-replace")
                self.call_after_refresh(self.sync_workspace_controls)
                return None
            styles = panel.styles
            scalars = (styles.width, styles.min_width, styles.max_width)
            width = _column_width(
                scalars, row.content_region.size - styles.margin.totals, self.app.size,
            )
            if width is None:
                return None
            self._chat_column_panel, self._chat_column_scalars = panel, scalars
        assert self._chat_column_scalars is not None
        return _column_width(
            self._chat_column_scalars,
            row.content_region.size - panel.styles.margin.totals, self.app.size,
        )

    def _focus_chat_if_content_hidden(self) -> None:
        """Resizing must not leave keyboard focus inside the hidden column."""
        if (not self.CHAT_REFLOW or not self.is_attached or not self.app.screen_stack
                or self.app.screen is not self or not self.has_class("-chat-replace")
                or any(rail.navigation_mode for rail in self.query(Sidebar))):
            return
        panel = next(iter(self.query("#chat-panel")), None)
        if panel is None or panel._collapsed:
            return
        content = self.query_one(".workspace-content")
        focused = self.focused
        if focused is None or focused is content or content in focused.ancestors:
            panel.focus_input()

    def prepare_chat_hide(self, previous: Widget | None) -> bool:
        """Reveal opted-in content before restoring focus after layout settles."""
        if not self.CHAT_REFLOW:
            return False
        self._sync_chat_layout()
        self.call_after_refresh(self._restore_chat_content_focus, previous)
        return True

    def restore_navigation_focus(self, previous: Widget | None) -> bool:
        """Settle the rail's width before testing the remembered focus target."""
        if not self.CHAT_REFLOW:
            return False
        if not self.is_attached or not self.app.screen_stack:
            return True
        self._sync_chat_layout()
        if self.app.screen is not self:
            # Preserve this screen's origin without focusing or scrolling
            # the modal or screen that now owns keyboard input.
            if (previous is not None and previous.is_attached
                    and previous.screen is self and previous.focusable
                    and Sidebar._in_layout(previous)):
                self.set_focus(previous, scroll_visible=False)
        else:
            self.call_after_refresh(self._restore_chat_content_focus, previous)
        return True

    def _restore_chat_content_focus(self, previous: Widget | None) -> None:
        if (not self.is_attached or not self.app.screen_stack
                or self.app.screen is not self
                or any(rail.navigation_mode for rail in self.query(Sidebar))):
            return
        # Widget.focus queues native focus; revealed content need not be painted yet.
        if (previous is not None and previous.is_attached
                and previous.screen is self and previous.focusable
                and Sidebar._in_layout(previous)):
            previous.focus()
            return
        panel = next(iter(self.query("#chat-panel")), None)
        if panel is not None and not panel._collapsed and self.has_class("-chat-replace"):
            panel.focus_input()
            return
        if self.AUTO_FOCUS:
            for widget in self.query(self.AUTO_FOCUS):
                if (widget.focusable and widget.region and Sidebar._in_layout(widget)
                        and (panel is None or panel not in widget.ancestors)):
                    widget.focus()
                    return
        self.focus_next()

    def on_screen_resume(self) -> None:
        self.apply_workspace_state()

    def on_screen_suspend(self) -> None:
        for sidebar in self.query(Sidebar):
            sidebar.exit_navigation_mode()

    def on_descendant_focus(self) -> None:
        self.call_after_refresh(self.sync_workspace_controls)

    def on_descendant_blur(self) -> None:
        self.call_after_refresh(self.sync_workspace_controls)

    @property
    def navigation_focused(self) -> bool:
        sidebar = next(iter(self.query(Sidebar)), None)
        return bool(sidebar and sidebar.navigation_mode and sidebar.has_focus_within)

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if self.navigation_focused and action != "focus_search":
            for binding in self.BINDINGS:
                binding = binding if isinstance(binding, Binding) else Binding(*binding)
                if binding.action == action:
                    if binding.key == "space" or (
                        len(binding.key) == 1 and binding.key.isprintable()
                    ):
                        return None
        return super().check_action(action, parameters)
