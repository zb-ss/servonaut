"""Drive the real Servonaut TUI the way a user does, and observe it.

:func:`tui_session` boots the real ``ServonautApp`` (real CSS, real service
wiring) under Textual's ``run_test`` and yields a :class:`TuiDriver`. The
driver presses keys and clicks visible widgets, waits on conditions rather
than fixed delays, and reads what a user can see: the screen stack, toasts,
widget text and the rendered screen.

If the journey raises while the app is still running, the driver saves an
SVG screenshot and ``state.json`` before the app shuts down.
"""

from __future__ import annotations

import asyncio
import io
import json
import re
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Callable, ContextManager, Optional, TypeVar, Union

from rich.console import Console
from textual.css.query import NoMatches
from textual.notifications import Notify
from textual.widget import Widget
from textual.widgets import Button, DataTable, Input, RichLog

T = TypeVar("T")

DEFAULT_SIZE = (160, 50)
SMALL_SIZE = (80, 24)
DEFAULT_TIMEOUT = 20.0


class JourneyTimeout(AssertionError):
    """A condition a journey waited for never became true."""


@dataclass(frozen=True)
class Toast:
    """One notification as the app raised it.

    ``markup`` says whether Textual renders ``message`` as markup. A toast
    that carries text from a server, a file or the user must have it False,
    or brackets in that text would be interpreted.
    """

    severity: str
    message: str
    markup: bool


def reset_app_class_state() -> None:
    """Give each in-process app fresh session containers.

    ``ServonautApp`` declares some mutable containers at class level, so two
    app instances in one process would share them. Resetting them here keeps
    journeys independent whether or not the class still declares them.
    """
    from servonaut.app import ServonautApp

    for name, factory in (
        ("instances", list),
        ("memory_first_connect_seen", set),
        ("memory_annotations_pulled_seen", set),
    ):
        if name in ServonautApp.__dict__:
            setattr(ServonautApp, name, factory())


class TuiDriver:
    """User-level operations and observations on a running app."""

    def __init__(
        self,
        app: Any,
        pilot: Any,
        notifications: list[Any],
        artifact_dir: Path,
        opened_screens: Optional[list[str]] = None,
    ) -> None:
        self.app = app
        self.pilot = pilot
        self._notifications = notifications
        self._opened_screens = opened_screens if opened_screens is not None else []
        self.artifact_dir = artifact_dir

    # ------------------------------------------------------------------
    # Observation
    # ------------------------------------------------------------------

    @property
    def screen(self) -> Any:
        return self.app.screen

    def stack_names(self) -> list[str]:
        return [type(screen).__name__ for screen in self.app.screen_stack]

    def screen_name(self) -> str:
        return type(self.app.screen).__name__

    def opened_screens(self) -> list[str]:
        """Every screen pushed so far, oldest first, including closed ones."""
        return list(self._opened_screens)

    def focused_id(self) -> Optional[str]:
        focused = self.app.focused
        return focused.id if focused is not None else None

    def find(self, selector: Union[str, type], expect_type: Optional[type] = None) -> list[Widget]:
        """All matches on every screen in the stack, active screen first.

        ``app.query`` only sees the default screen, so walk the stack.
        """
        found: list[Widget] = []
        for screen in reversed(self.app.screen_stack):
            query = screen.query(selector)
            found.extend(query.results(expect_type) if expect_type else query)
        return found

    def find_one(self, selector: Union[str, type], expect_type: Optional[type] = None) -> Any:
        matches = self.find(selector, expect_type)
        if not matches:
            raise NoMatches(f"no widget matches {selector!r} on any screen")
        return matches[0]

    def on_screen(self, selector: Union[str, type], expect_type: Optional[type] = None) -> Any:
        """The single match on the active screen."""
        if expect_type is None:
            return self.app.screen.query_one(selector)
        return self.app.screen.query_one(selector, expect_type)

    def toasts(self) -> list[tuple[str, str]]:
        """Every notification shown so far, as (severity, message), oldest first."""
        return [(n.severity, str(n.message)) for n in self._notifications]

    def toast_records(self) -> list[Toast]:
        """Every notification shown so far, with its markup flag, oldest first."""
        return [Toast(n.severity, str(n.message), bool(n.markup)) for n in self._notifications]

    def rendered_text(self) -> str:
        """Plain text of the screen as it is currently drawn.

        Textual has no public plain-text export (``export_screenshot`` gives
        SVG), so this mirrors that method with its private compositor and
        background-screen attributes. Keep all private use here.
        """
        width, height = self.app.size
        console = Console(
            width=width,
            height=height,
            file=io.StringIO(),
            force_terminal=True,
            color_system="truecolor",
            record=True,
            legacy_windows=False,
            safe_box=False,
        )
        with self._as_the_app():
            update = self.app.screen._compositor.render_update(
                full=True, screen_stack=self.app._background_screens, simplify=True
            )
            console.print(update)
        return console.export_text()

    def _as_the_app(self) -> ContextManager[None]:
        """Run a render the way the app's own tasks do, as Textual's active app.

        A widget not drawn since its last change is rendered on the spot,
        and Textual looks the app up from a context variable to do it. Under
        ``run_test`` the journey already runs with that set; under the
        desktop host the app has tasks of its own and the journey does not.
        """
        return self.app._context()

    @staticmethod
    def log_text(widget: RichLog) -> str:
        """The plain text written to a RichLog so far."""
        return "\n".join(line.text for line in widget.lines)

    def is_reachable(self, widget: Widget) -> bool:
        """True when neither *widget* nor any ancestor is hidden."""
        node: Any = widget
        while node is not None and node is not self.app:
            if not node.display or node.styles.visibility == "hidden":
                return False
            node = node.parent
        return True

    def state(self) -> dict[str, Any]:
        """Diagnostics for a failure artifact."""
        state: dict[str, Any] = {
            "stack": self.stack_names(),
            "opened_screens": self.opened_screens(),
            "focused": self.focused_id(),
            "toasts": self.toasts(),
            "exception": repr(getattr(self.app, "_exception", None)),
        }
        try:
            state["instances"] = [i.get("name") for i in (self.app.instances or [])]
        except Exception as exc:  # noqa: BLE001 - diagnostics only
            state["instances"] = repr(exc)
        return state

    # ------------------------------------------------------------------
    # Waiting
    # ------------------------------------------------------------------

    def _crash(self) -> Optional[BaseException]:
        return getattr(self.app, "_exception", None)

    async def wait_until(
        self,
        predicate: Callable[[], T],
        *,
        timeout: float = DEFAULT_TIMEOUT,
        desc: str = "condition",
    ) -> T:
        """Poll *predicate* between frames until it is truthy; return its value."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            crash = self._crash()
            if crash is not None:
                raise crash
            try:
                value = predicate()
            except NoMatches:
                value = None  # type: ignore[assignment]
            if value:
                return value
            if loop.time() >= deadline:
                raise JourneyTimeout(
                    f"timed out after {timeout:.0f}s waiting for {desc}; "
                    f"stack={self.stack_names()} toasts={self.toasts()[-5:]}"
                )
            await self.pilot.pause(0.02)

    async def settle(self, frames: int = 3) -> None:
        """Let queued messages and after-refresh callbacks run (no wall-clock wait)."""
        for _ in range(frames):
            await self.pilot.pause()
            crash = self._crash()
            if crash is not None:
                raise crash

    async def wait_for_screen(self, name: str, *, timeout: float = DEFAULT_TIMEOUT) -> Any:
        """Wait until the active screen is *name* and has finished mounting."""
        await self.wait_until(
            lambda: self.screen_name() == name and self.app.screen.is_mounted,
            timeout=timeout,
            desc=f"screen {name}",
        )
        await self.pilot.pause()
        return self.app.screen

    async def wait_for_screen_opened(self, name: str, *, timeout: float = DEFAULT_TIMEOUT) -> None:
        """Wait until a *name* screen has been pushed, even if it closed again.

        For a screen that closes on its own after a short time: on a busy
        machine it can open and close between two looks at the stack.
        """
        await self.wait_until(
            lambda: name in self._opened_screens, timeout=timeout, desc=f"screen {name} opened"
        )

    async def wait_for_widget(
        self,
        selector: Union[str, type],
        expect_type: Optional[type] = None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> Any:
        """The match for *selector* on the active screen, once it is mounted.

        A screen can mount part of its content after it becomes active, for
        example a card it rebuilds when its state changes: the card joins the
        screen at once, the buttons inside it a few frames later. This waits
        until the match exists and has finished mounting. It does not wait
        for a layout pass to give it a place on screen; :meth:`click` does.
        """

        def mounted() -> Optional[list[Any]]:
            widget = self.on_screen(selector, expect_type)
            return [widget] if widget.is_mounted else None

        found = await self.wait_until(
            mounted, timeout=timeout, desc=f"{selector} mounted on {self.screen_name()}"
        )
        return found[0]

    async def wait_for_text(self, *needles: str, timeout: float = DEFAULT_TIMEOUT) -> str:
        """Wait until the drawn screen shows every one of *needles*; return it.

        Widget state runs ahead of the screen: a table holds its new rows
        before it has sized its columns for them, so a name can be in the
        table yet still cut short on screen. Checks of what the user sees
        wait for the drawing, not for the data behind it.
        """
        missing = list(needles)

        def drawn() -> Optional[str]:
            text = self.rendered_text()
            missing[:] = [needle for needle in needles if needle not in text]
            return None if missing else text

        try:
            return await self.wait_until(drawn, timeout=timeout, desc="text on screen")
        except JourneyTimeout as exc:
            raise JourneyTimeout(f"{exc}; not drawn: {missing}") from None

    async def wait_for_toast(
        self,
        pattern: str,
        *,
        severity: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> str:
        """Wait for a notification whose message matches *pattern* (a regex)."""
        regex = re.compile(pattern)

        def match() -> Optional[str]:
            for level, message in self.toasts():
                if regex.search(message) and (severity is None or level == severity):
                    return message
            return None

        return await self.wait_until(match, timeout=timeout, desc=f"toast /{pattern}/")

    async def wait_for_toast_record(
        self,
        pattern: str,
        *,
        severity: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> Toast:
        """:meth:`wait_for_toast`, returning the whole :class:`Toast` (with ``markup``)."""
        regex = re.compile(pattern)

        def match() -> Optional[Toast]:
            for toast in self.toast_records():
                if regex.search(toast.message) and severity in (None, toast.severity):
                    return toast
            return None

        return await self.wait_until(match, timeout=timeout, desc=f"toast /{pattern}/")

    # ------------------------------------------------------------------
    # Input
    # ------------------------------------------------------------------

    async def press(self, *keys: str) -> None:
        await self.pilot.press(*keys)

    async def type(self, text: str) -> None:
        """Type *text* into the focused widget, one key per character."""
        await self.pilot.press(*text)

    async def click(self, target: Union[str, Widget]) -> None:
        """Click the middle of a visible widget on the active screen.

        A selector is waited for (see :meth:`wait_for_widget`), the way a
        user waits for a button to appear; a hidden widget fails at once.
        The click waits for the widget to be scrolled into view and laid
        out, so it lands on the widget rather than where it will be. A
        button ignores clicks while its short "pressed" highlight is
        showing, exactly as it would a real double click, so a second click
        on the same button waits for the highlight to clear first.
        """
        widget = await self.wait_for_widget(target) if isinstance(target, str) else target
        if not self.is_reachable(widget):
            raise AssertionError(f"{widget!r} is hidden, so a user cannot click it")
        if isinstance(widget, Button):
            await self.wait_until(
                lambda: not widget.has_class("-active"), desc=f"{widget!r} ready for a click"
            )
        widget.scroll_visible(animate=False, immediate=True)
        await self.pilot.pause()
        region = await self.wait_until(
            lambda: widget.region if widget.region.area else None,
            desc=f"{widget!r} laid out on screen",
        )
        offset = (max(region.width // 2, 0), max(region.height // 2, 0))
        landed = await self.pilot.click(widget, offset=offset)
        if not landed:
            raise AssertionError(f"click on {widget!r} landed on another widget")

    async def fill(self, selector: str, text: str) -> None:
        """Focus an input on the active screen, clear it and type *text*."""
        field = await self.wait_for_widget(selector, Input)
        await self.click(field)
        await self.wait_until(lambda: field.has_focus, desc=f"focus on {selector}")
        field.clear()
        await self.type(text)
        await self.wait_until(lambda: field.value == text, desc=f"{selector} == {text!r}")

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def nav_button(self, nav_id: str) -> Button:
        """The sidebar button *nav_id* on the active screen."""
        return self.on_screen(f"#{nav_id}", Button)

    def nav_reachable(self, nav_id: str) -> bool:
        """True when the button exists and is not hidden by gating.

        A button inside a collapsed section counts as reachable: the user can
        expand the section.
        """
        from servonaut.widgets.sidebar_section import SidebarSection

        try:
            button = self.nav_button(nav_id)
        except NoMatches:
            return False
        node: Any = button
        while node is not None and node is not self.app:
            if isinstance(node, SidebarSection):
                return self.is_reachable(node) and button.display
            node = node.parent
        return self.is_reachable(button)

    async def nav(self, nav_id: str) -> None:
        """Press a sidebar button like a user: expand its section, then click it."""
        from servonaut.widgets.sidebar_section import SidebarSection

        if not self.nav_reachable(nav_id):
            raise AssertionError(f"sidebar button {nav_id} is not available to the user")
        button = self.nav_button(nav_id)
        section = next(
            (node for node in button.ancestors if isinstance(node, SidebarSection)), None
        )
        if section is not None and section.collapsed:
            header = section.query_one("Button.section-header", Button)
            await self.click(header)
            await self.wait_until(lambda: not section.collapsed, desc=f"section of {nav_id}")
        await self.click(button)

    async def palette(self, query: str, *, choose: Optional[str] = None) -> None:
        """Run a command-palette entry: ctrl+p, type *query*, pick *choose*."""
        await self.press("ctrl+p")
        await self.wait_for_screen("CommandPalette")
        await self.type(query)
        wanted = choose or query
        from textual.command import CommandList

        command_list = self.on_screen(CommandList)

        def highlighted() -> bool:
            index = command_list.highlighted
            if index is None:
                return False
            prompt = command_list.get_option_at_index(index).prompt
            text = getattr(prompt, "plain", str(prompt))
            return text.startswith(wanted)

        await self.wait_until(highlighted, desc=f"palette entry {wanted!r}")
        await self.press("enter")
        await self.wait_until(lambda: self.screen_name() != "CommandPalette", desc="palette closed")

    async def focus_instance_table(self) -> Any:
        from servonaut.widgets.instance_table import InstanceTable

        table = self.on_screen(InstanceTable)
        if not table.has_focus:
            await self.click(table)
            await self.wait_until(lambda: table.has_focus, desc="instance table focus")
        return table

    async def select_instance(self, name: str) -> dict:
        """Move the fleet table's cursor to the row named *name* with the keyboard."""
        table = await self.focus_instance_table()
        rows = [row[1] for row in self.table_rows(type(table))]
        if name not in rows:
            raise AssertionError(f"{name!r} is not in the fleet table (rows: {rows})")
        target = rows.index(name)
        for _ in range(len(rows) + 1):
            if table.cursor_row == target:
                break
            await self.press("down" if table.cursor_row < target else "up")
        selected = table.get_selected_instance()
        assert selected is not None and selected.get("name") == name, selected
        return selected

    async def wait_and_select_instance(
        self, name: str, *, timeout: float = DEFAULT_TIMEOUT
    ) -> dict:
        """Wait until the fleet table lists *name*, then select it (see select_instance)."""
        from servonaut.widgets.instance_table import InstanceTable

        await self.wait_until(
            lambda: name in [row[1] for row in self.table_rows(InstanceTable)],
            timeout=timeout,
            desc=f"{name} in the fleet table",
        )
        return await self.select_instance(name)

    def table_rows(self, selector: Union[str, type]) -> list[list[str]]:
        """Plain-text cells of a DataTable on the active screen."""
        table = self.on_screen(selector)
        assert isinstance(table, DataTable)
        rows = []
        for row_key in table.rows:
            cells = table.get_row(row_key)
            rows.append([getattr(cell, "plain", str(cell)) for cell in cells])
        return rows

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------

    def capture(self, label: str = "failure") -> None:
        """Save ``<label>.svg`` and ``state.json`` into the artifact folder."""
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        try:
            with self._as_the_app():
                svg = self.app.export_screenshot(title=f"servonaut e2e: {label}")
            (self.artifact_dir / f"{label}.svg").write_text(svg, encoding="utf-8")
        except Exception as exc:  # noqa: BLE001 - diagnostics only
            (self.artifact_dir / f"{label}.svg.error.txt").write_text(repr(exc), encoding="utf-8")
        (self.artifact_dir / "state.json").write_text(
            json.dumps(self.state(), indent=2, default=str), encoding="utf-8"
        )


def _record_pushed_screens(app: Any) -> list[str]:
    """Note the name of every screen *app* pushes; returns the live list.

    Wraps this app instance's ``push_screen`` (not the class), so a screen
    that opens and closes between two polls is still seen to have opened.
    """
    opened: list[str] = []
    push_screen = app.push_screen

    def recording_push_screen(screen: Any, *args: Any, **kwargs: Any) -> Any:
        opened.append(screen if isinstance(screen, str) else type(screen).__name__)
        return push_screen(screen, *args, **kwargs)

    app.push_screen = recording_push_screen
    return opened


@asynccontextmanager
async def tui_session(
    artifact_dir: Path,
    *,
    size: tuple[int, int] = DEFAULT_SIZE,
    wait_for_fleet: bool = True,
) -> AsyncIterator[TuiDriver]:
    """Boot the real app and yield a driver; capture artifacts on failure."""
    from servonaut.app import ServonautApp
    from servonaut.runtime import detect_runtime

    reset_app_class_state()
    notifications: list[Any] = []

    def hook(message: Any) -> None:
        if isinstance(message, Notify):
            notifications.append(message.notification)

    app = ServonautApp(runtime_layout=detect_runtime())
    opened = _record_pushed_screens(app)
    async with app.run_test(size=size, notifications=True, message_hook=hook) as pilot:
        driver = TuiDriver(app, pilot, notifications, artifact_dir, opened)
        try:
            if wait_for_fleet:
                await driver.wait_for_screen("InstanceListScreen")
            yield driver
        except BaseException:
            driver.capture("failure")
            raise
