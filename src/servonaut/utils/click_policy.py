"""Which click actions drawn text may run.

A click on drawn text runs the ``@click`` action in the text's style. Text from
outside the app (a server name, an API field) must not be able to name an
action, so the app runs a style action only for the ones Textual's own widgets
attach to what they draw (the tab bar range action exists in a renderable, but
no widget sets it):

* a Markdown link (``link``), on a Markdown block;
* the scroll bar grab and track actions, on a scroll bar.

The app's own markup has no click action. Everything else, however it is
spelled, is ignored.
"""
from __future__ import annotations

from typing import Any, FrozenSet, Tuple, Type

from textual import actions
from textual.scrollbar import ScrollBar
from textual.widgets._markdown import MarkdownBlock

_ALLOWED: Tuple[Tuple[Type[Any], FrozenSet[str]], ...] = (
    (MarkdownBlock, frozenset({"link"})),
    (ScrollBar, frozenset({"grab", "scroll_up", "scroll_down"})),
)


def _action_name(action: Any) -> str | None:
    """The bare action name from a style's action (a string, or name and arguments)."""
    if isinstance(action, tuple) and len(action) == 2:
        action = action[0]
    if not isinstance(action, str):
        return None
    try:
        namespace, name, _arguments = actions.parse(action)
    except Exception:  # noqa: BLE001 - an action that does not parse is refused
        return None
    return None if namespace else name


def click_action_allowed(action: Any, widget: Any) -> bool:
    """Whether a style action of text drawn by *widget* may run."""
    name = _action_name(action)
    if name is None:
        return False
    return any(isinstance(widget, kind) and name in names for kind, names in _ALLOWED)
