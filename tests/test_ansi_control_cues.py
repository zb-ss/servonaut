"""ANSI control references and overflow hints preserve native input behavior."""

from __future__ import annotations

import json

import pytest
from textual.app import App, ComposeResult
from textual.geometry import Region
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static, Switch

from servonaut.screens.instance_list import FleetChip
from servonaut.styles import CSS_FILES
from servonaut.styles.themes import SERVONAUT_THEMES
from servonaut.widgets.dialogs import DialogActions, DialogBody, DialogFrame, DialogNotificationSpace
from tests._async_bounds import wait_until
from tests.test_ansi_chat_dialog_contrast import _NativeStateDialog, _painted_glyphs
from tests.test_memory_dialogs_presentation import _active_palette, _assert_colour_mode, _colour_fixture
from tests.test_native_switch_visibility import _ControlsHost, _cell, _isolated_services, _settle
from tests.test_navigation_dialog_contrast import _contrast, _paint_colours
from tests.test_settings_presentation import _tab_to
from tests.test_workspace_pilot import _UnpilotedScreen


SIZES = [(100, 30), (160, 50)]
THEMES = ['ansi-dark', 'ansi-light']


@pytest.fixture(autouse=True)
def _qualified_colour_mode(monkeypatch) -> None:
    _colour_fixture(monkeypatch)


class _CueDialog(ModalScreen[None]):
    AUTO_FOCUS = '#cue-cancel'
    BINDINGS = [('escape', 'cancel', 'Cancel')]

    def __init__(self, severity: str) -> None:
        super().__init__(classes='dialog-screen')
        self.severity = severity

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static('Review local details'),
            body=DialogBody(Static('\n'.join(f'Detail {index:02d}' for index in range(80)), markup=False)),
            actions=DialogActions(Button('Cancel', id='cue-cancel'), Button('Keep', id='cue-keep')),
            severity=self.severity, size='large', id='cue-frame',
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == 'cue-cancel':
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


def _palette(app) -> tuple[object, dict]:
    _assert_colour_mode(app)
    assert not app.console.no_color
    palette = _active_palette(app)
    assert palette is app.ansi_theme
    assert palette is app._textual_ansi_themes[0 if app.current_theme.dark else 1]
    return palette, {
        'theme': app.current_theme.name, 'dark': app.current_theme.dark,
        'basis': 'real ServonautApp active palette',
        'default_foreground': list(palette.foreground_color),
        'default_background': list(palette.background_color),
        'ansi_colours': [list(palette.ansi_colors[index]) for index in range(16)],
        'colour_system': app.console.color_system, 'no_color': app.no_color,
    }


def _pixel(app, x: int, y: int, palette) -> dict:
    glyph, style = _cell(app, x, y)
    fg, bg = _paint_colours(style, palette)
    return {'glyph': glyph, 'style': str(style), 'foreground': list(fg),
            'background': list(bg), 'contrast': _contrast(fg, bg)}


def _edges(app, widget, palette) -> dict:
    r = widget.region
    return {name: _pixel(app, x, y, palette) for name, x, y in (
        ('top', r.x + r.width // 2, r.y),
        ('bottom', r.x + r.width // 2, r.bottom - 1),
        ('left', r.x, r.y + r.height // 2),
        ('right', r.right - 1, r.y + r.height // 2),
    )}


def _switch_sample(app, switch: Switch, palette) -> dict:
    r = switch.content_region
    assert (switch.region.width, switch.region.height) == (10, 3)
    assert (r.width, r.height) == (4, 1)
    assert app.screen.region.contains_region(switch.region)
    cells = [_pixel(app, x, r.y, palette) for x in range(r.x, r.right)]
    assert all(cell['glyph'] == ' ' for cell in cells)
    assert all(app.get_widget_at(x, r.y)[0] is switch for x in range(r.x, r.right))
    thumb, track = ((2, 3), (0, 1)) if switch.value else ((0, 1), (2, 3))
    assert cells[thumb[0]]['background'] == cells[thumb[1]]['background']
    assert cells[track[0]]['background'] == cells[track[1]]['background']
    surround = _pixel(app, r.x - 1, r.y, palette)['background']
    fill = cells[thumb[0]]['background']
    track_fill = cells[track[0]]['background']
    return {'id': switch.id, 'value': switch.value, 'focused': switch.has_focus,
            'disabled': switch.disabled, 'region': list(switch.region),
            'content_region': list(r), 'cells': cells, 'edges': _edges(app, switch, palette),
            'thumb_cells': thumb, 'track_cells': track,
            'thumb_track': _contrast(fill, track_fill), 'thumb_surround': _contrast(fill, surround)}


def _label(app, widget, literal: str, palette) -> list[dict]:
    glyphs = _painted_glyphs(widget, literal)
    return [{'glyph': char, 'style': str(style),
             'foreground': list(_paint_colours(style, palette)[0]),
             'background': list(_paint_colours(style, palette)[1]),
             'underline': bool(style.underline),
             'contrast': _contrast(*_paint_colours(style, palette))}
            for char, style in glyphs]


def _button_sample(app, button: Button, literal: str, palette) -> dict:
    edges = _edges(app, button, palette)
    r = button.region
    outside = {
        'top': (r.x + r.width // 2, r.y - 1),
        'bottom': (r.x + r.width // 2, r.bottom),
        'left': (r.x - 1, r.y + r.height // 2),
        'right': (r.right, r.y + r.height // 2),
    }
    for name, cell in edges.items():
        surround = _pixel(app, *outside[name], palette)['background']
        # A visible solid fill can define the boundary without a separate stroke.
        stroke = _contrast(cell['foreground'], surround) if cell['glyph'].strip() else 1
        cell['reference_contrast'] = max(stroke, _contrast(cell['background'], surround))
        cell['surround'] = surround
    return {'id': button.id, 'region': list(r), 'edges': edges,
            'glyphs': _label(app, button, literal, palette)}


async def _ordinary_origin(app, pilot):
    # Model a real caller above the default screen; preserve root Back policy.
    screen = _UnpilotedScreen()
    await app.push_screen(screen)
    await pilot.pause()
    origin = screen.query_one(Input)
    origin.focus()
    await pilot.pause()
    return screen, origin


@pytest.mark.asyncio
@pytest.mark.parametrize('theme', THEMES)
@pytest.mark.parametrize('size', SIZES)
@pytest.mark.parametrize('focused', [False, True], ids=['blur', 'focus'])
async def test_native_control_reference_and_input_contract(theme, size, focused, record_property) -> None:
    app = _ControlsHost(theme)
    failures = []
    observations = []
    async with app.run_test(size=size) as pilot:
        palette, basis = _palette(app)
        origin = app.screen.query_one('#before', Input)
        for control_id in ('off', 'on'):
            switch = app.screen.query_one('#' + control_id, Switch)
            await _settle(pilot, switch)
            outer = switch.region
            await pilot.hover(origin)
            await _tab_to(pilot, switch if focused else origin)
            await pilot.pause()
            assert switch.has_focus is focused and not switch.mouse_hover
            row = _switch_sample(app, switch, palette)
            observations.append(row)
            for edge in ('top', 'bottom'):
                pixel = row['edges'][edge]
                if not pixel['glyph'].strip() or pixel['contrast'] < 3:
                    failures.append([control_id, edge, 'reference', pixel])
            if min(row['thumb_track'], row['thumb_surround']) < 3:
                failures.append([control_id, 'thumb', row])
            assert switch.region == outer
        # Native input must preserve both positions, callback counts and shape.
        off = app.screen.query_one('#off', Switch)
        geometry = off.region, off.content_region
        start = len(app.changes)
        await _tab_to(pilot, off)
        await pilot.press('space')
        await _settle(pilot, off)
        assert off.value
        await pilot.press('enter')
        await _settle(pilot, off)
        assert not off.value
        assert await pilot.click(off)
        await _settle(pilot, off)
        assert off.value
        await pilot.press('space')
        await _settle(pilot, off)
        assert not off.value
        assert [(widget.id, value) for widget, value in app.changes[start:]] == [
            ('off', True), ('off', False), ('off', True), ('off', False),
        ]
        assert (off.region, off.content_region) == geometry
        origin.focus()
        await pilot.pause()
        for control_id in ('disabled-off', 'disabled-on'):
            disabled = app.screen.query_one('#' + control_id, Switch)
            value, count = disabled.value, len(app.changes)
            disabled.focus()
            await pilot.pause()
            assert not disabled.has_focus
            assert await pilot.click(disabled)
            await pilot.pause()
            assert disabled.value is value and len(app.changes) == count
            observations.append(_switch_sample(app, disabled, palette))
            # Disabled is AA-exempt; retain its visible thumb and no-op behavior.
            row = observations[-1]
            assert row['thumb_track'] > 1
        dialog = _CueDialog('warning')
        results = []
        origin_screen, origin_input = await _ordinary_origin(app, pilot)
        await app.push_screen(dialog, results.append)
        await pilot.pause()
        button = dialog.query_one('#cue-cancel', Button)
        body = dialog.query_one(DialogBody)
        await pilot.hover(body)
        await _tab_to(pilot, button if focused else dialog.query_one('#cue-keep', Button))
        await pilot.pause()
        assert button.has_focus is focused and not button.mouse_hover
        assert button.region.height == 3 and app.get_widget_at(*button.region.center)[0] is button
        row = _button_sample(app, button, 'Cancel', palette)
        observations.append(row)
        for edge, pixel in row['edges'].items():
            if pixel['reference_contrast'] < 3:
                failures.append(['button', edge, pixel])
        if min(g['contrast'] for g in row['glyphs']) < 4.5:
            failures.append(['button', 'text', row['glyphs']])
        assert await pilot.click(button)
        await wait_until(lambda: results == [None] and app.screen is not dialog)
        assert app.screen is origin_screen and app.focused is origin_input
        assert app._exception is None
        record_property('native_cues', json.dumps({'basis': basis, 'size': size,
                        'focused': focused, 'observations': observations, 'failures': failures}))
    assert not failures, json.dumps(failures)


@pytest.mark.asyncio
@pytest.mark.parametrize('theme', THEMES)
@pytest.mark.parametrize('size', SIZES)
@pytest.mark.parametrize('severity', ['neutral', 'warning'])
async def test_actual_overflow_hint_has_readable_complete_glyphs(theme, size, severity, record_property) -> None:
    app = _ControlsHost(theme)
    async with app.run_test(size=size) as pilot:
        palette, basis = _palette(app)
        dialog = _CueDialog(severity)
        results = []
        origin_screen, origin_input = await _ordinary_origin(app, pilot)
        await app.push_screen(dialog, results.append)
        await pilot.pause()
        frame, body = dialog.query_one(DialogFrame), dialog.query_one(DialogBody)
        await wait_until(lambda: body.allow_vertical_scroll and frame.border_subtitle == 'Scroll for all details')
        await pilot.pause()
        literal = 'Scroll for all details'
        glyphs = []
        for y in range(frame.region.y, frame.region.bottom):
            strip = dialog._compositor.render_strips()[y].crop(frame.region.x, frame.region.right)
            offset = strip.text.find(literal)
            if offset < 0:
                continue
            for x in range(frame.region.x + offset, frame.region.x + offset + len(literal)):
                pixel = _pixel(app, x, y, palette)
                glyphs.append(pixel)
                assert app.get_widget_at(x, y)[0] is frame
            break
        assert ''.join(cell['glyph'] for cell in glyphs) == literal
        actions = [dialog.query_one('#cue-cancel', Button), dialog.query_one('#cue-keep', Button)]
        positions = [button.region for button in actions]
        for button in actions:
            assert frame.content_region.contains_region(button.region)
            assert app.get_widget_at(*button.region.center)[0] is button
        await _tab_to(pilot, body)
        await pilot.press('end')
        await pilot.pause()
        assert body.scroll_y == body.max_scroll_y and body.scroll_y > 0
        assert [button.region for button in actions] == positions
        assert all(app.get_widget_at(*button.region.center)[0] is button for button in actions)
        await pilot.press('escape')
        await wait_until(lambda: results == [None] and app.screen is not dialog)
        assert app.screen is origin_screen and app.focused is origin_input
        assert app._exception is None
        record_property('overflow_cue', json.dumps({'basis': basis, 'size': size,
                        'severity': severity, 'glyphs': glyphs,
                        'action_regions': [list(region) for region in positions]}))
        assert min(cell['contrast'] for cell in glyphs) >= 4.5


def _pressed_signature(row: dict) -> tuple:
    return (
        [(glyph['foreground'], glyph['background']) for glyph in row['glyphs']],
        [(pixel['glyph'], pixel['foreground'], pixel['background'])
         for pixel in row['edges'].values()],
    )


@pytest.mark.asyncio
@pytest.mark.parametrize('theme', THEMES)
@pytest.mark.parametrize('variant', ['default', 'primary', 'success'])
async def test_native_action_hover_press_and_disabled_adjacency(theme, variant, record_property) -> None:
    app = _ControlsHost(theme)
    observations, failures = [], []
    async with app.run_test(size=(100, 30)) as pilot:
        palette, basis = _palette(app)
        origin_screen, origin_input = await _ordinary_origin(app, pilot)
        dialog = _NativeStateDialog(variant)
        results = []
        await app.push_screen(dialog, results.append)
        await pilot.pause()
        button = dialog.query_one('#state-action', Button)
        origin = dialog.query_one('#state-input', Input)
        outer = button.region
        for state in ('disabled-rest', 'disabled-hover'):
            await pilot.hover(button if state.endswith('hover') else origin)
            button.focus()
            await pilot.pause()
            assert button.disabled and app.focused is origin
            assert button.styles.opacity == 0.5
            assert await pilot.click(button)
            await pilot.pause()
            assert dialog.pressed == [] and app.focused is origin
            row = _button_sample(app, button, 'Continue', palette)
            row['state'] = state
            observations.append(row)
            assert all(glyph['foreground'] != glyph['background'] for glyph in row['glyphs'])
            assert all(not glyph['underline'] for glyph in row['glyphs'])
        await pilot.press('tab')
        assert app.focused is dialog.query_one('#state-cancel', Button)
        button.disabled = False
        for state in ('rest', 'hover', 'focus', 'focus-hover'):
            if state in ('rest', 'hover'):
                origin.focus()
            else:
                await _tab_to(pilot, button)
            await pilot.hover(button if state.endswith('hover') else origin)
            await pilot.pause()
            assert button.has_focus is state.startswith('focus')
            assert button.mouse_hover is state.endswith('hover')
            row = _button_sample(app, button, 'Continue', palette)
            row['state'] = state
            observations.append(row)
            if min(glyph['contrast'] for glyph in row['glyphs']) < 4.5:
                failures.append([state, 'text', row['glyphs']])
            if min(pixel['reference_contrast'] for pixel in row['edges'].values()) < 3:
                failures.append([state, 'reference', row['edges']])
            assert button.region == outer
            assert app.get_widget_at(*button.region.center)[0] is button
        # Hold the native transient state only long enough to observe its paint.
        button.active_effect_duration = 10
        before = observations[-1]
        assert await pilot.click(button)
        await pilot.pause()
        assert button.has_class('-active') and dialog.pressed == ['state-action']
        row = _button_sample(app, button, 'Continue', palette)
        row['state'] = 'native-active'
        observations.append(row)
        if min(glyph['contrast'] for glyph in row['glyphs']) < 4.5:
            failures.append(['native-active', 'text', row['glyphs']])
        if _pressed_signature(row) == _pressed_signature(before):
            failures.append(['native-active', 'missing pressed cue'])
        assert button.region == outer and results == []
        await pilot.press('escape')
        await wait_until(lambda: results == [False] and app.screen is origin_screen)
        await wait_until(lambda: app.focused is origin_input)
        assert app._exception is None
        record_property('action_adjacency', json.dumps({
            'basis': basis, 'variant': variant, 'observations': observations,
            'failures': failures,
        }))
    assert not failures, json.dumps(failures)


class _ChipHost(App):
    CSS_PATH = CSS_FILES

    def __init__(self) -> None:
        super().__init__()
        for theme in SERVONAUT_THEMES:
            self.register_theme(theme)

    def compose(self) -> ComposeResult:
        yield Button('Holder', id='chip_holder')
        yield FleetChip('state', 'all', 'All')
        yield FleetChip('state', 'running', 'Running')


def _chip_style(chip: Button) -> tuple[bool, bool, bool]:
    styles = [segment.style for strip in chip.render_lines(Region(0, 0, chip.size.width, chip.size.height))
              for segment in strip if segment.text.strip() and segment.style]
    return (any(s.bold for s in styles), any(s.underline for s in styles), any(s.reverse for s in styles))


@pytest.mark.parametrize('theme', THEMES)
@pytest.mark.parametrize('chosen', [True, False])
@pytest.mark.asyncio
async def test_a_focused_fleet_chip_differs_from_an_idle_one(theme: str, chosen: bool) -> None:
    app = _ChipHost()
    app.theme = theme
    async with app.run_test(size=(60, 12)) as pilot:
        chip = app.query_one('#chip_state_all', Button)
        chip.set_class(chosen, '--chosen')
        app.query_one('#chip_holder').focus()
        await pilot.pause()
        idle = _chip_style(chip)
        chip.focus()
        await pilot.pause()
        assert _chip_style(chip) != idle
