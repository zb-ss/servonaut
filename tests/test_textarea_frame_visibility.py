"""Native blurred editor frames preserve visible extent and document state."""

from __future__ import annotations

import json

import pytest
from textual.widgets import TextArea

from tests.test_ansi_control_cues import _edges, _pixel
from tests.test_editor_selection_contrast import (
    DRAFT,
    TARGETS,
    _Host,
    _active_palette,
    _assert_colour_mode,
    _isolated_boundaries,  # noqa: F401 -- existing hermetic autouse fixture
    _mount_target,
    _painted_glyphs,
    _select_with_keys,
    clipboard,  # noqa: F401 -- native clipboard seam
    manager,  # noqa: F401 -- real isolated ConfigManager
    services,  # noqa: F401 -- real service API fakes
)
from tests.test_navigation_dialog_contrast import _contrast, _paint_colours
from tests.test_settings_presentation import _tab_to


ROUTES = ('copy-mode', 'text-editor', 'custom-servers', 'bug-report')


def _document_state(editor: TextArea) -> tuple:
    return (editor.document, editor.text, editor.selection,
            editor.read_only, editor.soft_wrap, editor.show_line_numbers)


def _sample(app, editor: TextArea, palette, stage: str, text: str) -> dict:
    """Sample actual edge cues, literal paint and native hit ownership."""
    region = editor.region
    content = editor.content_region
    assert app.screen.region.contains_region(region)
    assert region.contains_region(content) and content.width > 0 and content.height > 0
    assert app.get_widget_at(*content.center)[0] is editor
    edges = _edges(app, editor, palette)
    points = {
        'top': ((region.x + region.width // 2, region.y),
                (region.x + region.width // 2, region.y - 1)),
        'bottom': ((region.x + region.width // 2, region.bottom - 1),
                   (region.x + region.width // 2, region.bottom)),
        'left': ((region.x, region.y + region.height // 2),
                 (region.x - 1, region.y + region.height // 2)),
        'right': ((region.right - 1, region.y + region.height // 2),
                  (region.right, region.y + region.height // 2)),
    }
    for edge, (point, outside) in points.items():
        assert app.screen.region.contains(*outside)
        assert app.get_widget_at(*point)[0] is editor
        surround = _pixel(app, *outside, palette)['background']
        cell = edges[edge]
        stroke = _contrast(cell['foreground'], surround) if cell['glyph'].strip() else 1
        cell['surround'] = surround
        cell['reference_contrast'] = max(stroke, _contrast(cell['background'], surround))
    glyphs = []
    if text:
        for line in text.splitlines():
            for char, style in _painted_glyphs(editor, line):
                fg, bg = _paint_colours(style, palette)
                glyphs.append({'glyph': char, 'style': str(style),
                               'foreground': list(fg), 'background': list(bg),
                               'contrast': _contrast(fg, bg)})
    else:
        assert editor.text == '' and editor.selected_text == ''
    return {'stage': stage, 'id': editor.id, 'focused': editor.has_focus,
            'disabled': editor.disabled, 'read_only': editor.read_only,
            'region': list(region), 'content_region': list(content),
            'scroll_offset': list(editor.scroll_offset),
            'border_kinds': [getattr(editor.styles, 'border_' + edge)[0]
                             for edge in ('top', 'right', 'bottom', 'left')],
            'text': editor.text, 'selection': repr(editor.selection),
            'edges': edges, 'glyphs': glyphs}


@pytest.mark.asyncio
@pytest.mark.parametrize('target', ROUTES)
@pytest.mark.parametrize('theme', ('ansi-dark', 'ansi-light'))
@pytest.mark.parametrize('filled', (False, True), ids=('empty', 'filled'))
async def test_enabled_blurred_native_editor_extent(
    manager, services, clipboard, tmp_path, record_property,
    target: str, theme: str, filled: bool,
) -> None:
    app = _Host(navigation_visible=False)
    manager.get().theme = theme
    app.config_manager = manager
    app.ai_analysis_service = services.analysis
    app.bug_report_service = services.reports
    app.custom_server_service = services.servers
    app.theme = theme
    clipboard.succeeds = False
    persisted = (tmp_path / 'config.json').read_bytes()
    rows, failures, results = [], [], []
    text = DRAFT if filled else ''
    evidence = {'target': target, 'theme': theme,
                'filled': filled, 'samples': rows, 'failures': failures}
    try:
        async with app.run_test(size=(160, 50)) as pilot:
            _assert_colour_mode(app)
            palette = _active_palette(app)
            evidence['palette'] = {
                'basis': 'actual real ServonautApp app.ansi_theme',
                'default_foreground': list(palette.foreground_color),
                'default_background': list(palette.background_color),
                'ansi_colours': [list(palette.ansi_colors[i]) for i in range(16)],
                'colour_system': app.console.color_system, 'no_color': app.no_color,
            }
            screen, _ = await _mount_target(app, pilot, target, services, results)
            editor = screen.query_one('#' + TARGETS[target], TextArea)
            editor.load_text(text)
            await pilot.pause()
            await _tab_to(pilot, editor)
            await pilot.pause()
            assert app.focused is editor and editor.read_only is (target == 'copy-mode')
            if filled:
                await _select_with_keys(editor, pilot)
            # Native focus scrolls may still animate after Pilot.pause.
            await pilot.wait_for_scheduled_animations()
            # Freeze positions only after native focus has revealed the field.
            state = _document_state(editor)
            geometry = editor.region, editor.content_region, editor.scroll_offset
            service_calls = [list(mock.mock_calls) for mock in
                             (services.analysis, services.reports, services.servers)]
            rows.append(_sample(app, editor, palette, 'focused', text))
            assert rows[-1]['border_kinds'] == ['tall'] * 4
            if editor.read_only:
                await pilot.press('x')
                await pilot.pause()
                assert _document_state(editor) == state and app.screen is screen
            screen.set_focus(None, scroll_visible=False)
            await pilot.hover(offset=(0, 0))
            await pilot.pause()
            assert not editor.has_focus and not editor.mouse_hover
            assert _document_state(editor) == state
            assert (editor.region, editor.content_region, editor.scroll_offset) == geometry
            blurred = _sample(app, editor, palette, 'blurred-enabled', text)
            rows.append(blurred)
            for edge, cell in blurred['edges'].items():
                if not cell['glyph'].strip() or cell['reference_contrast'] < 3:
                    failures.append({'edge': edge, 'cell': cell})
            # Disabled is exempt from enabled contrast thresholds. Preserve
            # its native refusal/document state and record paint separately.
            editor.disabled = True
            await pilot.pause()
            editor.focus()
            await pilot.pause()
            assert not editor.has_focus
            before_clipboard = list(clipboard.calls), app.clipboard
            r = editor.content_region
            assert await pilot.click(editor, offset=(r.x - editor.region.x + 1,
                                                     r.y - editor.region.y))
            await pilot.pause()
            assert not editor.has_focus and _document_state(editor) == state
            assert (list(clipboard.calls), app.clipboard) == before_clipboard
            assert (editor.region, editor.content_region, editor.scroll_offset) == geometry
            rows.append(_sample(app, editor, palette, 'disabled', text))
            editor.disabled = False
            await _tab_to(pilot, editor)
            await pilot.pause()
            assert editor.has_focus and _document_state(editor) == state
            assert (editor.region, editor.content_region, editor.scroll_offset) == geometry
            rows.append(_sample(app, editor, palette, 'focused-restored', text))
            assert rows[-1]['edges'] == rows[0]['edges']
            assert results == [] and app._exception is None
            assert service_calls == [list(mock.mock_calls) for mock in
                                     (services.analysis, services.reports, services.servers)]
            assert (tmp_path / 'config.json').read_bytes() == persisted
    finally:
        record_property('native_textarea_blur_cues', json.dumps(evidence, sort_keys=True))
    assert not failures, json.dumps(failures, sort_keys=True)
