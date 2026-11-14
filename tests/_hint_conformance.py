"""Check that an action button's key hint is a real binding that does what the click does."""

from __future__ import annotations

from typing import Any

from textual.pilot import Pilot
from textual.screen import Screen

from servonaut.widgets.action_button import ActionButton

_KEY_NAMES = {"esc": "escape", "F5": "f5"}


class _Done:
    """Awaitable that finishes at once, so a stub works whether it is awaited or not."""

    def __await__(self):
        return iter(())


def binding_key(hint: str) -> str:
    return _KEY_NAMES.get(hint, hint)


def bound_actions(screen: Screen) -> dict[str, str]:
    """The screen's bindings as {key: action name}."""
    return {key: binding.action for key, binding in screen._bindings.key_to_bindings.items()
            for binding in binding[:1]}


def record_actions(screen: Screen, calls: list[str]) -> None:
    """Replace every ``action_*`` of *screen* by a recorder that does nothing else."""
    for name in dir(type(screen)):
        if name.startswith("action_") and callable(getattr(type(screen), name)):
            def stub(*args: Any, _name: str = name, **kwargs: Any) -> _Done:
                calls.append(_name.removeprefix("action_"))
                return _Done()
            setattr(screen, name, stub)


async def assert_hints_match_bindings(
    pilot: Pilot, screen: Screen, calls: list[str], handovers: dict[str, str] | None = None,
) -> int:
    """For each enabled button with a key hint: the key is bound, and key and click agree.

    *handovers* names the actions that pass on to a per-tab variant.
    Returns how many buttons had their click and key compared.
    """
    compared = 0
    bindings = bound_actions(screen)
    for button in screen.query(ActionButton):
        key = button._key
        if not key or button.disabled or not button.region.width:
            continue  # no hint, disabled, or on a tab that is not shown
        name = binding_key(key)
        assert key in button.label.plain, f"{button.id}: the hint {key!r} is not shown at this size"
        assert name in bindings, f"{button.id}: hint {key!r} is not a binding"
        calls.clear()
        button.press()
        await pilot.pause()
        by_click = list(calls)
        calls.clear()
        screen.set_focus(None)  # a focused input would take the key as text
        await pilot.press(name)
        await pilot.pause()
        by_key = list(calls)
        if by_click:
            assert by_key and by_click[0] == (handovers or {}).get(by_key[0], by_key[0]), (
                f"{button.id}: click {by_click} but key {by_key}"
            )
            compared += 1
    return compared
