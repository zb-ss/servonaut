"""Log option labels retain literal paths, trusted markers and raw results."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from rich.cells import cell_len
from rich.style import Style
from rich.errors import MarkupError as RichMarkupError
from textual.dom import NoScreen
from textual.markup import MarkupError
from textual.widgets import Input, OptionList

from servonaut.screens import log_picker as log_module
from servonaut.screens.log_picker import LogPickerModal
from tests._async_bounds import wait_until
from tests.test_basic_dialogs import BasicDialogHost
from tests.test_log_dialogs_presentation import INSTANCE, _assert_framed, _open, _service


PATHS = {
    'available': '/var/log/literal[/b]a\\.log',
    'custom': '/srv/app/[red]literal[/red]\\',
    'discovered': '/srv/app/[bold]literal[/bold]\\tail.log',
}


def _path_picker(kind: str):
    path = PATHS[kind]
    service = _service()
    service.get_custom_paths.return_value = [path] if kind == 'custom' else []
    classify = Mock(return_value='compressed')
    picker = LogPickerModal(
        available_logs=[path] if kind == 'available' else [],
        discovered_logs=[path] if kind == 'discovered' else [],
        current_log=path, classify_fn=classify, instance=dict(INSTANCE),
        log_viewer_service=service,
    )
    prefix = {'available': 'avail:', 'custom': 'custom:', 'discovered': 'disc:'}[kind]
    suffix = {'available': ' ●', 'custom': ' [saved] ●', 'discovered': ' [zip]'}[kind]
    return picker, service, classify, prefix + path, path + suffix


async def _ready_picker(app, pilot, picker, results):
    await _open(app, pilot, picker, results)
    await wait_until(lambda: bool(picker.query('#log_picker_search')))
    field = picker.query_one('#log_picker_search', Input)
    await wait_until(lambda: app.focused is field)
    _assert_framed(app, picker, '#log_picker_search', '#log_picker_list', '#log_picker_cancel')
    return field, picker.query_one('#log_picker_list', OptionList)


def _capture_paint(app, picker, snapshots: list, phase: str) -> dict:
    entry = {'phase': phase, 'option_map': dict(picker._option_map),
             'picker_attached': picker.is_attached}
    if app._exception is not None:
        entry['app_exception'] = {'type': type(app._exception).__name__,
                                  'message': str(app._exception)}
    options = next(iter(picker.query('#log_picker_list')), None)
    if options is not None:
        region = options.content_region
        entry['region'] = [region.x, region.y, region.width, region.height]
        entry['raw_options'] = [{'id': option.id, 'prompt': str(option.prompt)}
                                for option in options.options]
        try:
            strips = options.screen._compositor.render_strips()
            entry['rows'] = [strips[y].crop(region.x, region.right).text
                             for y in range(max(0, region.y), min(len(strips), region.bottom))]
        except (MarkupError, RichMarkupError, NoScreen) as error:
            # Diagnostic capture must preserve, rather than replace, the real failure.
            entry['paint_error'] = {'type': type(error).__name__, 'message': str(error)}
    snapshots.append(entry)
    return entry


def _label_paint(app, picker, options: OptionList, label: str, snapshots: list) -> dict:
    """Capture actual paint before asserting the literal label or native hits."""
    snapshot = _capture_paint(app, picker, snapshots, 'before-label-assertion')
    region = options.content_region
    assert options.screen.region.contains_region(region)
    strips = options.screen._compositor.render_strips()
    for y in range(region.y, region.bottom):
        row = strips[y].crop(region.x, region.right)
        start = row.text.find(label)
        if start < 0:
            continue
        offset, glyphs = 0, []
        for segment in row:
            stop = offset + len(segment.text)
            if offset < start + len(label) and stop > start:
                part = segment.text[max(0, start - offset):start + len(label) - offset]
                glyphs.extend((glyph, segment.style or Style()) for glyph in part)
            offset = stop
        assert ''.join(glyph for glyph, _ in glyphs) == label
        x = region.x + cell_len(row.text[:start])
        for glyph, _ in glyphs:
            if glyph.strip():
                assert app.get_widget_at(x, y)[0] is options
            x += cell_len(glyph)
        if label.endswith('●'):
            assert glyphs[-1][1].bold, 'Current-log marker retains its bold cue'
        return {'label': label, 'position': [region.x + start, y],
                'glyphs': [[glyph, str(style)] for glyph, style in glyphs]}
    pytest.fail(f'Literal path/markers missing: {label!r}; actual paint: {snapshot!r}')


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ('available', 'custom', 'discovered'))
async def test_log_picker_paints_literal_path_and_returns_raw_option(
    kind: str, record_property,
) -> None:
    app = BasicDialogHost()
    picker, service, classify, option_id, label = _path_picker(kind)
    path, results, observations, snapshots = PATHS[kind], [], [], []
    source = Path(log_module.__file__)
    provenance = {'file': str(source), 'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}
    try:
        async with app.run_test(size=(100, 30)) as pilot:
            try:
                origin = app.query_one('#origin', Input)
                origin.focus()
                search, options = await _ready_picker(app, pilot, picker, results)
                assert picker._option_map[option_id] == path
                assert options.get_option(option_id).id == option_id
                observations.append(_label_paint(app, picker, options, label, snapshots))
                await pilot.press(*'literal')
                await wait_until(lambda: set(picker._option_map) == {option_id})
                await pilot.pause()
                assert search.value == 'literal' and options.get_option(option_id).id == option_id
                observations.append(_label_paint(app, picker, options, label, snapshots))
                # Use the real OptionList event, not the modal's dispatcher.
                await pilot.press('down')
                await wait_until(lambda: app.focused is options)
                assert options.highlighted == options.get_option_index(option_id)
                observations.append(_label_paint(app, picker, options, label, snapshots))
                await pilot.press('enter')
                await wait_until(lambda: app.screen is not picker)
                assert results == [path] and app.focused is origin
                service.get_custom_paths.assert_called_once_with(INSTANCE['id'])
                if kind == 'discovered':
                    assert classify.called
                    assert all(call.args == (path,) and not call.kwargs for call in classify.call_args_list)
                else:
                    classify.assert_not_called()
                # Escape returns None so the caller can resume without selecting a path.
                cancelled, read_service, _, _, _ = _path_picker(kind)
                await _ready_picker(app, pilot, cancelled, results)
                await pilot.press('escape')
                await wait_until(lambda: app.screen is not cancelled and results == [path, None])
                assert results == [path, None] and app.focused is origin and app._exception is None
                read_service.get_custom_paths.assert_called_once_with(INSTANCE['id'])
            finally:
                _capture_paint(app, picker, snapshots, 'before-run-test-teardown')
    finally:
        record_property('literal-option-paint', json.dumps({
            'kind': kind, 'raw_option_id': option_id, 'raw_result': path,
            'source': provenance, 'observations': observations, 'paint_snapshots': snapshots,
        }, sort_keys=True))
