"""Tests for :class:`servonaut.screens.bw_dir_picker.BwDirPickerModal`.

Covers the dirs-only tree filter (hidden dirs kept), the Select validation
(invalid path warns and stays open; valid dir dismisses the Path), the cancel
semantics, and a ``run_test`` pilot smoke that the container renders centered
with the ``~/.ssh`` prefill.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from servonaut.screens.bw_dir_picker import BwDirPickerModal, _DirsOnlyTree


def test_modal_optional_path_typed():
    bases = [str(b) for b in getattr(BwDirPickerModal, "__orig_bases__", [])]
    assert any("Path" in b for b in bases)


def test_escape_binding_present():
    keys = [b.key for b in BwDirPickerModal.BINDINGS]
    assert "escape" in keys


def test_filter_paths_keeps_dirs_including_hidden(tmp_path):
    (tmp_path / "plain_dir").mkdir()
    (tmp_path / ".ssh").mkdir()  # hidden dirs MUST be kept — ~/.ssh is one
    (tmp_path / "some_file").write_text("x")

    # filter_paths is stateless — call it unbound to avoid constructing a
    # DirectoryTree outside a running app (its path watcher needs an event loop).
    kept = list(_DirsOnlyTree.filter_paths(MagicMock(), tmp_path.iterdir()))
    names = {p.name for p in kept}
    assert names == {"plain_dir", ".ssh"}


class TestSelect:
    def _screen(self, input_value: str):
        screen = BwDirPickerModal()
        screen.query_one = MagicMock(return_value=SimpleNamespace(value=input_value))
        screen.dismiss = MagicMock()
        app = MagicMock()
        patcher = patch.object(type(screen), "app", property(lambda self: app))
        patcher.start()
        screen._test_patcher = patcher
        screen._test_app = app
        return screen

    def test_valid_directory_dismisses_path(self, tmp_path):
        screen = self._screen(str(tmp_path))
        try:
            screen.action_select()
        finally:
            screen._test_patcher.stop()
        screen.dismiss.assert_called_once_with(tmp_path)

    def test_expanduser_applied(self):
        screen = self._screen("~")
        try:
            screen.action_select()
        finally:
            screen._test_patcher.stop()
        screen.dismiss.assert_called_once_with(Path.home())

    def test_invalid_path_warns_and_stays_open(self, tmp_path):
        screen = self._screen(str(tmp_path / "does-not-exist"))
        try:
            screen.action_select()
        finally:
            screen._test_patcher.stop()
        screen.dismiss.assert_not_called()
        kwargs = screen._test_app.notify.call_args.kwargs
        assert kwargs.get("markup") is False
        assert kwargs.get("severity") == "warning"

    def test_unknown_user_tilde_warns_and_stays_open(self):
        # Path('~nosuchuser/...').expanduser() raises RuntimeError — it must
        # land on the warning path, never escape the action (app teardown).
        screen = self._screen("~nosuchuser_xyz/.ssh")
        try:
            screen.action_select()
        finally:
            screen._test_patcher.stop()
        screen.dismiss.assert_not_called()
        kwargs = screen._test_app.notify.call_args.kwargs
        assert kwargs.get("markup") is False
        assert kwargs.get("severity") == "warning"

    def test_empty_path_warns(self):
        screen = self._screen("")
        try:
            screen.action_select()
        finally:
            screen._test_patcher.stop()
        screen.dismiss.assert_not_called()
        assert screen._test_app.notify.called

    def test_cancel_dismisses_none(self):
        screen = BwDirPickerModal()
        screen.dismiss = MagicMock()
        screen.action_cancel()
        screen.dismiss.assert_called_once_with(None)


def test_tree_click_updates_input():
    screen = BwDirPickerModal()
    fake_input = SimpleNamespace(value="old")
    screen.query_one = MagicMock(return_value=fake_input)
    screen.on_directory_tree_directory_selected(SimpleNamespace(path=Path("/srv/keys")))
    assert fake_input.value == str(Path("/srv/keys"))


class TestDemoMode:
    """Demo-mode redaction: tree labels go through scrub_stream; the path
    Input (whose value doubles as the functional selection, so it cannot be
    scrubbed) stays in ``~``-relative form — never the literal
    ``/home/<username>`` prefix."""

    def _screen_with_app(self, demo: bool):
        screen = BwDirPickerModal()
        app = SimpleNamespace(
            demo_mode=demo,
            redaction_service=MagicMock() if demo else None,
            notify=MagicMock(),
        )
        patcher = patch.object(type(screen), "app", property(lambda self: app))
        patcher.start()
        return screen, app, patcher

    def test_display_path_home_relative_in_demo_mode(self):
        import os

        screen, _app, patcher = self._screen_with_app(True)
        try:
            assert screen._display_path(Path.home() / ".ssh") == "~" + os.sep + ".ssh"
            assert screen._display_path(Path.home()) == "~"
            # Outside home there is nothing home-relative to strip.
            assert screen._display_path(Path("/srv/keys")) == str(Path("/srv/keys"))
        finally:
            patcher.stop()

    def test_display_path_unchanged_outside_demo_mode(self):
        screen, _app, patcher = self._screen_with_app(False)
        try:
            assert screen._display_path(Path.home() / ".ssh") == str(
                Path.home() / ".ssh"
            )
        finally:
            patcher.stop()

    def test_demo_display_path_roundtrips_through_expanduser(self):
        """The demo form must stay functional — expanduser() restores it."""
        screen, _app, patcher = self._screen_with_app(True)
        try:
            display = screen._display_path(Path.home() / ".ssh")
        finally:
            patcher.stop()
        assert Path(display).expanduser() == Path.home() / ".ssh"

    def test_tree_click_demo_mode_updates_input_home_relative(self):
        import os

        screen, _app, patcher = self._screen_with_app(True)
        fake_input = SimpleNamespace(value="old")
        screen.query_one = MagicMock(return_value=fake_input)
        try:
            screen.on_directory_tree_directory_selected(
                SimpleNamespace(path=Path.home() / "projects")
            )
        finally:
            patcher.stop()
        assert fake_input.value == "~" + os.sep + "projects"

    def test_detached_screen_treated_as_non_demo(self):
        """No attached app (unit-test construction) must never crash — it
        just means demo scrubbing is off."""
        screen = BwDirPickerModal()
        assert screen._demo_scrub_active() is False


def test_dirs_only_tree_render_label_uses_scrubber():
    """The label scrubber is display-only: the rendered text is scrubbed
    while the node's real label (and path data) stay untouched. The home
    node is special-cased to '~' (its label is the bare local username,
    which scrub_stream cannot recognise)."""
    from rich.style import Style
    from rich.text import Text

    calls = []

    def scrub(text: str) -> str:
        calls.append(text)
        return "SCRUBBED"

    # __new__ skips DirectoryTree.__init__ (needs a running app); render_label
    # only touches _scrub and the node, so the bare instance is sufficient.
    tree = _DirsOnlyTree.__new__(_DirsOnlyTree)
    tree._scrub = scrub

    with patch(
        "servonaut.screens.bw_dir_picker.DirectoryTree.render_label",
        side_effect=lambda node, base, style: node._label.copy(),
    ):
        # Ordinary directory node → scrubbed.
        node = SimpleNamespace(
            _label=Text("client-project"),
            data=SimpleNamespace(path=Path("/srv/client-project")),
        )
        rendered = tree.render_label(node, Style(), Style())
        assert calls == ["client-project"]
        assert rendered.plain == "SCRUBBED"
        # Node label restored after the swap-render-restore dance.
        assert node._label.plain == "client-project"

        # Home node → '~', scrubber not consulted.
        home_node = SimpleNamespace(
            _label=Text(Path.home().name),
            data=SimpleNamespace(path=Path.home()),
        )
        rendered_home = tree.render_label(home_node, Style(), Style())
        assert rendered_home.plain == "~"
        assert calls == ["client-project"]


@pytest.mark.asyncio
async def test_pilot_demo_mode_scrubs_tree_root_and_prefills_tilde():
    import os

    from rich.style import Style
    from textual.app import App
    from textual.widgets import Input

    from servonaut.screens.bw_dir_picker import _DirsOnlyTree as DirsTree
    from servonaut.styles import CSS_FILES

    class _FakeRedactor:
        def scrub_stream(self, text: str) -> str:
            return "DEMOSCRUBBED"

    class _Host(App):
        CSS_PATH = CSS_FILES
        demo_mode = True

        def on_mount(self) -> None:
            self.redaction_service = _FakeRedactor()
            self.push_screen(BwDirPickerModal())

    app = _Host()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await pilot.pause()
        # Input prefill is ~-relative, not the literal expanded home path.
        dir_input = app.screen.query_one("#bw_dir_input", Input)
        assert dir_input.value == "~" + os.sep + ".ssh"
        # Tree root is the home dir — its label (the bare local username)
        # renders as '~', never the real name.
        tree = app.screen.query_one("#bw_dir_tree", DirsTree)
        root_label = tree.render_label(tree.root, Style(), Style())
        assert Path.home().name not in root_label.plain
        assert root_label.plain.endswith("~")
        # Child directory labels go through the scrubber.
        children = tree.root.children
        if children:  # home dir always has subdirs in practice; guard for CI
            child_label = tree.render_label(children[0], Style(), Style())
            assert "DEMOSCRUBBED" in child_label.plain


@pytest.mark.asyncio
async def test_pilot_renders_prefilled_and_centered():
    from textual.app import App
    from textual.widgets import Input

    from servonaut.styles import CSS_FILES

    class _Host(App):
        CSS_PATH = CSS_FILES

        def on_mount(self) -> None:
            self.push_screen(BwDirPickerModal())

    app = _Host()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await pilot.pause()
        dir_input = app.screen.query_one("#bw_dir_input", Input)
        assert dir_input.value == str(Path.home() / ".ssh")

        region = app.screen.query_one("#bw_dir_picker_container").region
        assert abs(region.x - (120 - region.width) // 2) <= 1
        assert abs(region.y - (40 - region.height) // 2) <= 1
