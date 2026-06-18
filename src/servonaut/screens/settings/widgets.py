"""Reusable form widgets shared across settings panels.

- :class:`EnvVarInput` — an ``Input`` that, when the value starts with ``$``,
  shows a hint reading ``↳ $NAME → set`` / ``↳ $NAME → MISSING`` derived from
  ``os.environ``. The resolved secret value is NEVER printed.
- :class:`StringListEditor` — add/remove rows of plain strings.
- :class:`KeyValueEditor` — add/remove ``key → value`` rows for ``Dict[str, str]``
  (or ``Dict[str, int]`` with ``value_is_int=True``).
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Static


class EnvVarInput(Vertical):
    """Container that wraps an ``Input`` plus an env-var resolution hint.

    When the value starts with ``$`` (e.g. ``$AWS_SECRET_ACCESS_KEY``) the hint
    Static below the field shows only the variable NAME and whether
    ``os.environ`` has it set or missing — never the resolved value. Plain
    (non-``$``) values show no hint, so this is safe for any secret field that
    supports ``$ENV_VAR`` / ``file:`` syntax.

    This is a small ``Vertical`` container — NOT a bare ``Input`` — because an
    ``Input`` is a single-line leaf widget that does not lay out composed
    children, so a hint composed into one would render at zero size and stay
    invisible. The container holds a real ``Input`` and the hint as siblings,
    and proxies :pyattr:`value` / :pyattr:`password` through to the inner input
    so panel code (``query_one(..., EnvVarInput).value``) keeps working.
    """

    DEFAULT_CSS = """
    EnvVarInput {
        height: auto;
        width: 1fr;
    }
    EnvVarInput > Input { width: 1fr; }
    EnvVarInput > .envvar-hint {
        height: auto;
        color: $text-muted;
        padding: 0 0 0 1;
    }
    EnvVarInput > .envvar-hint.envvar-missing { color: $error; }
    EnvVarInput > .envvar-hint.envvar-set { color: $success; }
    """

    def __init__(
        self,
        value: str = "",
        *,
        placeholder: str = "",
        password: bool = False,
        id: Optional[str] = None,
        classes: Optional[str] = None,
        name: Optional[str] = None,
    ) -> None:
        super().__init__(id=id, classes=classes, name=name)
        self._input = Input(
            value=value,
            placeholder=placeholder,
            password=password,
        )
        self._hint = Static("", classes="envvar-hint")

    def compose(self) -> ComposeResult:
        """Yield the inner Input and the hint Static as siblings."""
        yield self._input
        yield self._hint

    def on_mount(self) -> None:
        """Render the initial hint from the loaded value."""
        self._update_hint()

    # ------------------------------------------------------------------
    # Proxy properties so callers treat EnvVarInput like an Input
    # ------------------------------------------------------------------

    @property
    def value(self) -> str:
        """Return the inner input's current value."""
        return self._input.value

    @value.setter
    def value(self, new_value: str) -> None:
        self._input.value = new_value
        self._update_hint()

    @property
    def password(self) -> bool:
        """Return whether the inner input masks its value."""
        return self._input.password

    @password.setter
    def password(self, masked: bool) -> None:
        self._input.password = masked

    def focus(self, scroll_visible: bool = True) -> "EnvVarInput":
        """Focus the inner input (so validation cues can focus the field)."""
        self._input.focus(scroll_visible)
        return self

    # ------------------------------------------------------------------
    # Hint rendering
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Refresh the hint whenever the inner input's value changes."""
        if event.input is self._input:
            self._update_hint()

    def _update_hint(self) -> None:
        value = (self.value or "").strip()
        if not value.startswith("$"):
            self._hint.update("")
            self._hint.remove_class("envvar-missing", "envvar-set")
            return
        name = value[1:].strip()
        is_set = bool(name) and name in os.environ
        state = "set" if is_set else "MISSING"
        self._hint.remove_class("envvar-missing", "envvar-set")
        self._hint.add_class("envvar-set" if is_set else "envvar-missing")
        self._hint.update(escape(f"↳ ${name} → {state}"))


class PreviewBanner(Static):
    """Non-dismissible notice for a scaffolded-but-not-live settings feature.

    Use at the top of a panel whose config persists but whose underlying
    integration isn't wired up yet, so the user knows saving stores their
    settings for later rather than activating anything now.
    """

    DEFAULT_CSS = """
    PreviewBanner {
        height: auto;
        border: round $warning;
        background: $warning 10%;
        color: $text;
        padding: 0 1;
        margin: 0 0 1 0;
    }
    """

    def __init__(self, feature: str, **kwargs) -> None:
        message = (
            f"[b]Preview[/b] — {escape(feature)} isn't live yet. You can save "
            "settings here so they're ready, but instances aren't fetched into "
            "the fleet yet."
        )
        super().__init__(message, **kwargs)


class StringListEditor(Vertical):
    """Add/remove editor for a list of plain strings.

    Exposes :meth:`get_values` / :meth:`set_values`. Generalises the legacy
    scan-paths add/remove UX so list-backed panels stay DRY.
    """

    DEFAULT_CSS = """
    StringListEditor { height: auto; }
    /* The rows container must size to its content, not grab a 1fr share
       (Textual's Vertical default), which would expand and push the add row
       off-screen. */
    StringListEditor .list-rows { height: auto; }
    StringListEditor .list-row {
        height: auto;
        margin: 0 0 1 0;
    }
    StringListEditor .list-row Input { width: 1fr; }
    StringListEditor .list-remove { width: 5; min-width: 5; }
    StringListEditor .list-add-row { height: auto; }
    /* The add row's input must flex (1fr) so the "+ Add" button keeps its width
       and stays on-screen — without this the input goes full-width and pushes
       the button off the right edge. */
    StringListEditor .list-add-row Input { width: 1fr; }
    StringListEditor .list-add { width: auto; min-width: 9; }
    """

    def __init__(self, *, placeholder: str = "value", **kwargs) -> None:
        super().__init__(**kwargs)
        self._placeholder = placeholder
        self._rows = Vertical(classes="list-rows")
        self._new = Input(placeholder=placeholder, classes="list-new")
        # Values set before the rows container is mounted are buffered here and
        # flushed in on_mount — set_values() is routinely called from a panel's
        # load() before this widget (or a dynamically-mounted parent card) has
        # finished mounting, when mounting into _rows would raise.
        self._pending: Optional[List[str]] = None

    def compose(self) -> ComposeResult:
        """Yield the value rows container and the add row."""
        yield self._rows
        yield Horizontal(
            self._new,
            Button("+ Add", classes="list-add"),
            classes="list-add-row",
        )

    def on_mount(self) -> None:
        """Flush any values buffered before the rows container was mounted."""
        if self._pending is not None:
            values, self._pending = self._pending, None
            self.set_values(values)

    def set_values(self, values: List[str]) -> None:
        """Replace all rows with *values* (buffered until the rows mount)."""
        if not self._rows.is_mounted:
            self._pending = list(values)
            return
        self._rows.remove_children()
        for value in values:
            self._rows.mount(self._make_row(value))

    def get_values(self) -> List[str]:
        """Return the current non-empty values in row order.

        While values set via :meth:`set_values` are still buffered (rows not
        yet mounted), the buffered values are returned so dirty-tracking
        compares like with like. Rows whose ``Input`` child has not finished
        mounting yet are skipped rather than raising.
        """
        if self._pending is not None:
            return [v.strip() for v in self._pending if v.strip()]
        out: List[str] = []
        for row in self._rows.query(".list-row"):
            inputs = list(row.query(Input))
            if not inputs:
                continue
            value = inputs[0].value.strip()
            if value:
                out.append(value)
        return out

    def _make_row(self, value: str) -> Horizontal:
        return Horizontal(
            Input(value=value, placeholder=self._placeholder),
            Button("✕", classes="list-remove"),
            classes="list-row",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle the add and per-row remove buttons."""
        if "list-add" in event.button.classes:
            event.stop()
            value = self._new.value.strip()
            if value:
                self._rows.mount(self._make_row(value))
                self._new.value = ""
        elif "list-remove" in event.button.classes:
            event.stop()
            row = event.button.parent
            if row is not None:
                row.remove()


class KeyValueEditor(Vertical):
    """Add/remove editor for a ``Dict[str, str]`` (or ``Dict[str, int]``).

    Exposes :meth:`get_map` / :meth:`set_map`. When ``value_is_int=True`` the
    values are validated and coerced to ``int`` in :meth:`get_map` (raising
    ``ValueError`` on a non-integer value so the panel can surface it).
    """

    DEFAULT_CSS = """
    KeyValueEditor { height: auto; }
    /* Size the rows container to content, not a 1fr share (see StringListEditor). */
    KeyValueEditor .kv-rows { height: auto; }
    KeyValueEditor .kv-row {
        height: auto;
        margin: 0 0 1 0;
    }
    KeyValueEditor .kv-row Input { width: 1fr; }
    KeyValueEditor .kv-sep { width: 3; min-width: 3; content-align: center middle; }
    KeyValueEditor .kv-remove { width: 5; min-width: 5; }
    KeyValueEditor .kv-add-row { height: auto; }
    /* Both add-row inputs flex so the separator, value field and "+ Add" button
       stay on-screen instead of being pushed off the right edge. */
    KeyValueEditor .kv-add-row Input { width: 1fr; }
    KeyValueEditor .kv-add { width: auto; min-width: 9; }
    """

    def __init__(
        self,
        *,
        key_placeholder: str = "key",
        value_placeholder: str = "value",
        value_is_int: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._key_placeholder = key_placeholder
        self._value_placeholder = value_placeholder
        self._value_is_int = value_is_int
        self._rows = Vertical(classes="kv-rows")
        self._new_key = Input(placeholder=key_placeholder, classes="kv-new-key")
        self._new_value = Input(placeholder=value_placeholder, classes="kv-new-value")
        # Mapping set before the rows container is mounted is buffered here and
        # flushed in on_mount (see StringListEditor for the same rationale).
        self._pending: Optional[Dict[str, object]] = None

    def compose(self) -> ComposeResult:
        """Yield the key/value rows container and the add row."""
        yield self._rows
        yield Horizontal(
            self._new_key,
            Static("→", classes="kv-sep"),
            self._new_value,
            Button("+ Add", classes="kv-add"),
            classes="kv-add-row",
        )

    def on_mount(self) -> None:
        """Flush any mapping buffered before the rows container was mounted."""
        if self._pending is not None:
            mapping, self._pending = self._pending, None
            self.set_map(mapping)

    def set_map(self, mapping: Dict[str, object]) -> None:
        """Replace all rows with *mapping* (buffered until the rows mount)."""
        if not self._rows.is_mounted:
            self._pending = dict(mapping)
            return
        self._rows.remove_children()
        for key, value in mapping.items():
            self._rows.mount(self._make_row(str(key), str(value)))

    def get_map(self) -> Dict[str, object]:
        """Return the current non-empty key/value pairs in row order.

        While the mapping set via :meth:`set_map` is still buffered (rows not
        yet mounted), the buffered pairs are returned so dirty-tracking compares
        like with like.

        Raises:
            ValueError: When ``value_is_int`` and a value is not an integer.
        """
        if self._pending is not None:
            return self._coerce_pending(self._pending)
        out: Dict[str, object] = {}
        for row in self._rows.query(".kv-row"):
            inputs = list(row.query(Input))
            # Rows mid-mount (queried in the same frame as set_map) have not
            # attached their Input children yet — skip rather than IndexError.
            if len(inputs) < 2:
                continue
            key = inputs[0].value.strip()
            raw_value = inputs[1].value.strip()
            if not key:
                continue
            if self._value_is_int:
                try:
                    out[key] = int(raw_value)
                except ValueError as exc:
                    raise ValueError(
                        f"Value for '{key}' must be an integer (got '{raw_value}')"
                    ) from exc
            else:
                out[key] = raw_value
        return out

    def _coerce_pending(self, pending: Dict[str, object]) -> Dict[str, object]:
        """Apply the same key-skip + int-coercion rules as the mounted path."""
        out: Dict[str, object] = {}
        for raw_key, raw_value in pending.items():
            key = str(raw_key).strip()
            value = str(raw_value).strip()
            if not key:
                continue
            if self._value_is_int:
                try:
                    out[key] = int(value)
                except ValueError as exc:
                    raise ValueError(
                        f"Value for '{key}' must be an integer (got '{value}')"
                    ) from exc
            else:
                out[key] = value
        return out

    def _make_row(self, key: str, value: str) -> Horizontal:
        return Horizontal(
            Input(value=key, placeholder=self._key_placeholder),
            Static("→", classes="kv-sep"),
            Input(value=value, placeholder=self._value_placeholder),
            Button("✕", classes="kv-remove"),
            classes="kv-row",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle the add and per-row remove buttons."""
        if "kv-add" in event.button.classes:
            event.stop()
            key = self._new_key.value.strip()
            if key:
                self._rows.mount(self._make_row(key, self._new_value.value.strip()))
                self._new_key.value = ""
                self._new_value.value = ""
        elif "kv-remove" in event.button.classes:
            event.stop()
            row = event.button.parent
            if row is not None:
                row.remove()
