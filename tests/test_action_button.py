"""ActionButton: one label style, roles, a compact form, literal text."""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult

from servonaut.styles import CSS_FILES
from servonaut.widgets.action_button import ActionButton, ActionRow, action_label


class _Host(App[None]):
    CSS_PATH = CSS_FILES

    def compose(self) -> ComposeResult:
        yield ActionButton("Browse files", "1", id="plain", short="Browse")
        yield ActionButton("Verify SSH", id="nokey")
        yield ActionButton("Go", role="primary", id="primary")
        yield ActionButton("Careful", role="warning", id="warning")
        yield ActionButton("Delete", role="error", id="error")
        yield ActionButton("[b]bold[/b] [@click=app.bell]x", "[x]", id="hostile")


def test_label_is_words_then_a_muted_key_hint() -> None:
    label = action_label("Browse files", "1")
    assert label.plain == "Browse files  1"
    assert [(span.start, span.end, str(span.style)) for span in label.spans] == [(14, 15, "$text-muted")]


def test_label_without_a_key_has_no_hint() -> None:
    label = action_label("Verify SSH")
    assert label.plain == "Verify SSH" and not label.spans


def test_hostile_text_stays_literal() -> None:
    label = action_label("[b]x[/b] [@click=app.bell]y", "[k]")
    assert label.plain == "[b]x[/b] [@click=app.bell]y  [k]"
    assert [str(span.style) for span in label.spans] == ["$text-muted"]


@pytest.mark.asyncio
@pytest.mark.parametrize("button_id,role_class", [
    ("plain", None), ("primary", "-primary"), ("warning", "-warning"), ("error", "-error"),
])
async def test_roles_map_to_variant_classes(button_id, role_class) -> None:
    async with _Host().run_test(size=(80, 30)) as pilot:
        button = pilot.app.query_one(f"#{button_id}", ActionButton)
        for name in ("-primary", "-warning", "-error"):
            assert button.has_class(name) is (name == role_class)


@pytest.mark.asyncio
async def test_set_role_and_set_text_update_the_button() -> None:
    async with _Host().run_test(size=(80, 30)) as pilot:
        button = pilot.app.query_one("#nokey", ActionButton)
        button.set_role("error")
        button.set_text("Verify host", "v")
        await pilot.pause()
        assert button.has_class("-error")
        assert button.label.plain == "Verify host  v"


@pytest.mark.asyncio
async def test_compact_is_one_row_borderless_and_uses_the_short_words() -> None:
    async with _Host().run_test(size=(80, 40)) as pilot:
        button = pilot.app.query_one("#plain", ActionButton)
        await pilot.pause()
        assert button.region.height == 3 and button.label.plain == "Browse files  1"
        button.compact = True
        await pilot.pause()
        assert button.region.height == 1 and button.label.plain == "Browse   1"
        button.compact = False
        await pilot.pause()
        assert button.region.height == 3 and button.label.plain == "Browse files  1"


@pytest.mark.asyncio
async def test_hostile_label_renders_literally() -> None:
    async with _Host().run_test(size=(80, 40)) as pilot:
        button = pilot.app.query_one("#hostile", ActionButton)
        await pilot.pause()
        rows = pilot.app.screen._compositor.render_strips()
        text = "\n".join(
            rows[y].crop(button.region.x, button.region.right).text
            for y in range(button.region.y, button.region.bottom)
        )
        assert "[b]bold[/b]" in text


class _RowHost(App[None]):
    CSS_PATH = CSS_FILES

    def compose(self) -> ComposeResult:
        with ActionRow(id="row"):
            yield ActionButton("Use vault key", "u", short="Vault key", id="a")
            yield ActionButton("Verify SSH", "v", id="b")
            yield ActionButton("Scan results", "5", short="Scan", id="c")


@pytest.mark.asyncio
@pytest.mark.parametrize("width,labels,wrapped", [
    (80, ["Use vault key  u", "Verify SSH  v", "Scan results  5"], False),
    (56, ["Vault key  u", "Verify SSH  v", "Scan  5"], False),
    (46, ["Vault key", "Verify SSH", "Scan"], False),
    (30, ["Vault key", "Verify SSH", "Scan"], True),
])
async def test_row_saves_space_in_order_and_never_clips(width, labels, wrapped) -> None:
    app = _RowHost()
    async with app.run_test(size=(width, 20)) as pilot:
        row = app.query_one("#row", ActionRow)
        for _ in range(6):
            await pilot.pause()
        assert [b.label.plain for b in row.query(ActionButton)] == labels
        assert row.has_class("-wrap") is wrapped
        for button in row.query(ActionButton):
            assert row.region.contains_region(button.region), button.id
            assert button.content_size.width >= button.label.cell_length


def test_set_text_can_replace_the_short_words_too() -> None:
    button = ActionButton("Scan all servers", "s", short="Scan all")
    button.set_text("Scan all servers (3)", short="Scan all (3)")
    assert button._label(False, True).plain == "Scan all servers (3)  s"
    assert button._label(True, True).plain == "Scan all (3)   s"
