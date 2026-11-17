"""Native confirmation copy and analysis status preserve readable literal text."""
from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import create_autospec

import pytest
from rich.cells import cell_len
from rich.style import Style
from textual.pilot import Pilot
from textual.widgets import Button, Input, Static, TextArea

from servonaut.screens import ai_analysis as analysis_module
from servonaut.screens.ai_analysis import AIAnalysisScreen
from servonaut.screens.log_picker import AddPathModal, LogPickerModal
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.services.log_viewer_service import LogViewerService
from servonaut.services.redaction_service import RedactionService
from servonaut.services.ssh_service import SSHService
from servonaut.styles.themes import SERVONAUT_ANSI_DARK, SERVONAUT_ANSI_LIGHT, is_servonaut_theme
from servonaut.widgets.dialogs import DialogActions, DialogFrame
from tests._async_bounds import wait_until
from tests.test_ansi_chat_dialog_contrast import _glyph_evidence, _painted_glyphs
from tests.test_editor_selection_contrast import (
    DRAFT, _Host, _assert_colour_mode, _isolated_boundaries,
    manager, services,
)
from tests.test_selection_copy import _Clipboard, _drag, clipboard
from tests.test_navigation_dialog_contrast import _contrast, _paint_colours


THEMES = ('servonaut', 'servonaut-light', 'ansi-dark', 'ansi-light')
COSTS = ((0.012345, '$0.0123', 'example-model'),
         (0, 'free (local)', 'example-model'),
         (None, 'pricing unavailable', 'example-model'),
         (0.012345, '$0.0123', 'model[X[/b]\\'))
STATUS = {
    'idle': 'Text loaded. Press Analyze or F5 to start.',
    'warning': 'No readable log files found on this server.',
    'error': 'Error: Local analysis failed.',
}


def _observe(app: _Host, widget: Static, expected: str) -> dict[str, Any]:
    """Read final compositor cells and hit ownership without altering scroll."""
    assert widget.render().plain == expected
    region = widget.content_region
    assert region.width > 0 and region.height > 0
    assert app.screen.region.contains_region(region)
    palette = app.ansi_theme
    pair = ((SERVONAUT_ANSI_DARK, SERVONAUT_ANSI_LIGHT)
            if is_servonaut_theme(app.theme) else app._textual_ansi_themes)
    assert palette is pair[0 if app.current_theme.dark else 1]
    evidence, painted = [], []
    strips = app.screen._compositor.render_strips()
    for y in range(region.y, region.bottom):
        row = strips[y].crop(region.x, region.right)
        painted.append(row.text)
        x = region.x
        for segment in row:
            for glyph in segment.text:
                if glyph.strip():
                    assert app.get_widget_at(x, y)[0] is widget
                    entry = _glyph_evidence(glyph, segment.style or Style(), app.theme,
                                            dark=app.current_theme.dark)
                    # Reuse reviewed symbolic/SGR evidence, but resolve the gate
                    # against the actual product palette for this exact theme.
                    fg, bg = _paint_colours(segment.style or Style(), palette)
                    entry['palettes']['matching'] = {
                        'foreground': fg.hex, 'background': bg.hex,
                        'contrast': _contrast(fg, bg),
                    }
                    entry['gate_palette_basis'] = 'actual app.ansi_theme'
                    evidence.append(entry)
                x += cell_len(glyph)
    assert ' '.join(expected.split()) in ' '.join(' '.join(painted).split())
    assert evidence
    return {'theme': app.theme, 'theme_dark': app.current_theme.dark,
            'id': widget.id, 'plain': expected, 'glyphs': evidence,
            'region': [region.x, region.y, region.width, region.height],
            'palette_foreground': list(palette.foreground_color),
            'palette_background': list(palette.background_color)}


def _failures(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{'theme': row['theme'], 'id': row['id'], 'plain': row['plain'],
             'minimum': min(g['palettes']['matching']['contrast'] for g in row['glyphs'])}
            for row in rows
            if min(g['palettes']['matching']['contrast'] for g in row['glyphs']) < 4.5]


def _emit_assert(record_property: Callable, rows: list[dict[str, Any]]) -> None:
    record_property('copy-glyph-records', json.dumps(rows, sort_keys=True))
    assert not _failures(rows), json.dumps(_failures(rows), sort_keys=True)


async def _tab_to(pilot: Pilot, target: Button) -> None:
    for _ in range(len(target.screen.focus_chain) + 1):
        if target.app.focused is target:
            return
        await pilot.press('tab')
    pytest.fail(f'Native Tab did not reach {target.id}')


def _button_exposed(app: _Host, target: Button) -> None:
    region = target.region
    assert target.visible and region.width > 0 and region.height > 0
    assert app.screen.region.contains_region(region)
    assert target.screen.query_one(DialogFrame).content_region.contains_region(region)
    for y in range(region.y, region.bottom):
        for x in range(region.x, region.right):
            assert app.get_widget_at(x, y)[0] is target
    label = 'Continue' if target.id == 'btn_confirm' else 'Cancel'
    assert ''.join(glyph for glyph, _ in _painted_glyphs(target, label)) == label


def _app(manager: Any, services: Any, theme: str) -> _Host:
    assert services.analysis.estimate_tokens.return_value == 7
    assert services.analysis.chunk_text.return_value == [DRAFT]
    manager.get().theme = theme
    app = _Host(navigation_visible=False)
    app.config_manager = manager
    app.ai_analysis_service = services.analysis
    app.bug_report_service = services.reports
    app.custom_server_service = services.servers
    app.theme = theme
    return app


def _confirmation(severity: str) -> ConfirmActionScreen:
    return ConfirmActionScreen(
        title='Review server', description='Review [bold]web-1[/bold].',
        consequences=['Remove [italic]stored files[/italic].'],
        confirm_text='a[X', action_label='Continue', severity=severity,
    )


def _confirm_copy(app: _Host, screen: ConfirmActionScreen) -> list[dict[str, Any]]:
    consequence = screen.query_one('.consequence_item', Static)
    rows = [_observe(app, screen.query_one('#modal_title', Static), 'Review server'),
            _observe(app, consequence, '  • Remove stored files.')]
    warning = ('This action CANNOT be undone.' if screen._severity == 'danger'
               else 'Please review carefully before proceeding.')
    rows.append(_observe(app, screen.query_one('#severity_message', Static), warning))
    # Emphasis and trusted markup remain real rendered properties, not plain text alone.
    for ident in ('modal_title', 'severity_message'):
        value = next(row for row in rows if row['id'] == ident)
        assert all(g['bold'] for g in value['glyphs'])
    rendered = consequence.render()
    assert any(str(s.style) == 'italic' and
               rendered.plain[s.start:s.end] == 'stored files' for s in rendered.spans)
    assert screen.query_one('#modal_description', Static).render().plain == 'Review web-1.'
    assert screen.query_one('#confirm_prompt', Static).render().plain == 'Type "a[X" to confirm:'
    assert screen.query_one(DialogFrame).has_class('dialog-' + screen._severity)
    assert screen.query_one('#btn_confirm', Button).variant == (
        'error' if screen._severity == 'danger' else 'warning')
    return rows


@pytest.mark.asyncio
@pytest.mark.parametrize('theme', THEMES)
@pytest.mark.parametrize('severity', ('warning', 'danger'))
@pytest.mark.parametrize('size', ((100, 30), (160, 50)))
async def test_confirmation_copy_keeps_severity_and_exact_native_result(
    manager, services, tmp_path: Path, record_property, theme, severity, size,
) -> None:
    app = _app(manager, services, theme)
    persisted = (tmp_path / 'config.json').read_bytes()
    results, rows = [], []
    async with app.run_test(size=size) as pilot:
        _assert_colour_mode(app)
        origin, origin_focus = app.screen, app.focused
        screen = _confirmation(severity)
        await app.push_screen(screen, callback=results.append)
        await pilot.pause()
        rows.extend(_confirm_copy(app, screen))
        field = screen.query_one('#confirm_input', Input)
        button = screen.query_one('#btn_confirm', Button)
        assert app.focused is field and button.disabled
        await pilot.press(*'A[X')
        assert field.value == 'A[X' and button.disabled
        await pilot.press(*(['backspace'] * 3), *'a[X')
        await pilot.pause()
        assert field.value == 'a[X' and not button.disabled
        for item in screen.query_one(DialogActions).query(Button):
            _button_exposed(app, item)
        await _tab_to(pilot, button)
        await pilot.press('enter')
        await wait_until(lambda: app.screen is origin and results == [True])
        assert app.focused is origin_focus
        second = _confirmation(severity)
        await app.push_screen(second, callback=results.append)
        await pilot.pause()
        if size == (100, 30):
            await pilot.press('escape')
        else:
            cancel = second.query_one('#btn_cancel', Button)
            await _tab_to(pilot, cancel)
            _button_exposed(app, cancel)
            assert await pilot.click(cancel)
        await wait_until(lambda: app.screen is origin and results == [True, False])
        assert app.focused is origin_focus and app._exception is None
    services.analysis.analyze_text.assert_not_awaited()
    assert (tmp_path / 'config.json').read_bytes() == persisted
    _emit_assert(record_property, rows)


def _result(services: Any, cost: float | None, model: str) -> None:
    services.analysis.analyze_text.side_effect = None
    services.analysis.analyze_text.return_value = {
        'content': DRAFT, 'model': model, 'input_tokens': 7, 'output_tokens': 6,
        'tokens_used': 13, 'estimated_cost': cost,
    }


async def _complete(app: _Host, pilot: Pilot, screen: AIAnalysisScreen,
                    services: Any, cost: float | None, model: str) -> None:
    _result(services, cost, model)
    previous = services.analysis.analyze_text.await_count
    # F5 is the screen's real binding; focus the input so copied output stays stable.
    screen.query_one('#ai_text_input', TextArea).focus()
    await pilot.press('f5')
    await wait_until(lambda: services.analysis.analyze_text.await_count == previous + 1
                     and not screen.query_one('#btn_analyze', Button).disabled)
    await pilot.pause()
    services.analysis.analyze_text.assert_awaited_with(DRAFT, system_prompt='')
    assert screen.query_one('#ai_output', TextArea).text == DRAFT
    assert screen._output_text == DRAFT


def _metadata(app: _Host, screen: AIAnalysisScreen, price: str, model: str) -> list[dict]:
    return [_observe(app, screen.query_one('#ai_status', Static),
                     'Analysis complete. Select text to copy.'),
            _observe(app, screen.query_one('#ai_cost_info', Static),
                     f'Tokens: 7 in / 6 out (13 total)  Model: {model}  Est. cost: {price}'),
            _observe(app, screen.query_one('#ai_token_estimate', Static), 'Input: ~7 tokens')]


@pytest.mark.asyncio
@pytest.mark.parametrize('theme', THEMES)
@pytest.mark.parametrize('cost,price,model', COSTS)
async def test_analysis_metadata_preserves_service_output_and_exact_cost(
    manager, services, clipboard: _Clipboard, tmp_path: Path, record_property,
    theme, cost, price, model,
) -> None:
    app = _app(manager, services, theme)
    screen = AIAnalysisScreen(text=DRAFT)
    persisted = (tmp_path / 'config.json').read_bytes()
    results = []
    async with app.run_test(size=(160, 50)) as pilot:
        _assert_colour_mode(app)
        await app.push_screen(screen, callback=results.append)
        await pilot.pause()
        source = screen.query_one('#ai_text_input', TextArea)
        before = source.document, source.text, source.selection, source.scroll_offset
        await _complete(app, pilot, screen, services, cost, model)
        assert services.analysis.analyze_text.await_count == 1
        assert before == (source.document, source.text, source.selection, source.scroll_offset)
        rows = _metadata(app, screen, price, model)
        output = screen.query_one('#ai_output', TextArea)
        document, scroll = output.document, output.scroll_offset
        clipboard.calls.clear()
        await _drag(pilot, output, (0, 0), (len(DRAFT.splitlines()[1]), 1))
        assert output.selected_text == DRAFT
        assert clipboard.calls == [DRAFT]
        assert output.document is document and output.text == DRAFT
        assert output.scroll_offset == scroll and source.document is before[0]
        assert results == [] and app._exception is None
    assert (tmp_path / 'config.json').read_bytes() == persisted
    _emit_assert(record_property, rows)


async def _status_path(app: _Host, pilot: Pilot, screen: AIAnalysisScreen,
                       services: Any, kind: str, logs: Any) -> str:
    if kind == 'idle':
        services.analysis.analyze_text.assert_not_awaited()
        logs.probe_log_paths.assert_not_awaited()
    elif kind == 'warning':
        before = logs.probe_log_paths.await_count
        assert await pilot.click(screen.query_one('#btn_fetch_logs', Button))
        await wait_until(lambda: logs.probe_log_paths.await_count == before + 1
                         and not screen.query_one('#btn_fetch_logs', Button).disabled)
        logs._resolve_connection.assert_called_with(
            screen._instance, app.ssh_service, app.connection_service)
        logs.probe_log_paths.assert_awaited_with(
            screen._instance, app.ssh_service, app.connection_service, rows=app.instances)
        logs.scan_log_directories.assert_not_awaited()
        services.analysis.analyze_text.assert_not_awaited()
    else:
        services.analysis.analyze_text.side_effect = RuntimeError('Local analysis failed.')
        focus_before = app.focused
        await pilot.press('f5')
        await wait_until(lambda: not screen.query_one('#btn_analyze', Button).disabled
                         and screen.query_one('#ai_status', Static).render().plain == STATUS[kind])
        services.analysis.analyze_text.assert_awaited_with(DRAFT, system_prompt='')
        assert app.focused is focus_before
    await pilot.pause()
    return STATUS[kind]


def _logs() -> Any:
    logs = create_autospec(LogViewerService, instance=True, spec_set=True)
    logs._resolve_connection.return_value = {'host': '192.0.2.10'}
    logs.probe_log_paths.return_value = []
    return logs


@pytest.mark.asyncio
@pytest.mark.parametrize('theme', THEMES)
@pytest.mark.parametrize('kind', ('idle', 'warning', 'error'))
async def test_analysis_native_nonresult_status_is_measured_without_side_effects(
    manager, services, tmp_path: Path, record_property, theme, kind,
) -> None:
    app = _app(manager, services, theme)
    logs = _logs()
    app.log_viewer_service = logs
    screen = AIAnalysisScreen(text=DRAFT, instance=app.instances[0])
    persisted = (tmp_path / 'config.json').read_bytes()
    async with app.run_test(size=(160, 50)) as pilot:
        _assert_colour_mode(app)
        await app.push_screen(screen)
        await pilot.pause()
        editor = screen.query_one('#ai_text_input', TextArea)
        before = editor.document, editor.text, editor.selection, editor.scroll_offset
        text = await _status_path(app, pilot, screen, services, kind, logs)
        rows = [_observe(app, screen.query_one('#ai_status', Static), text),
                _observe(app, screen.query_one('#ai_token_estimate', Static), 'Input: ~7 tokens')]
        assert before == (editor.document, editor.text, editor.selection, editor.scroll_offset)
        assert screen.query_one('#ai_output', TextArea).text == '' and screen._output_text == ''
        assert screen.query_one('#ai_cost_info', Static).render().plain == ''
        assert app.screen is screen and app._exception is None
    assert (tmp_path / 'config.json').read_bytes() == persisted
    _emit_assert(record_property, rows)


@pytest.mark.asyncio
@pytest.mark.timeout(300)  # Registry loop; prior comparable native diagnostic took ~100s.
async def test_registered_themes_measure_copy_on_actual_active_palette(
    manager, services, tmp_path: Path, record_property,
) -> None:
    app = _app(manager, services, 'servonaut')
    logs = _logs()
    app.log_viewer_service = logs
    names = tuple(sorted(app.available_themes))
    rows = []
    persisted = (tmp_path / 'config.json').read_bytes()
    try:
        async with app.run_test(size=(160, 50)) as pilot:
            _assert_colour_mode(app)
            origin = app.screen
            for name in names:
                manager.get().theme = name
                app.theme = name
                await pilot.pause()
                assert app.current_theme.name == name
                for severity in ('warning', 'danger'):
                    dialog = _confirmation(severity)
                    await app.push_screen(dialog)
                    await pilot.pause()
                    rows.extend(_confirm_copy(app, dialog))
                    await pilot.press('escape')
                    await wait_until(lambda: app.screen is origin)
                services.analysis.analyze_text.reset_mock()
                logs.probe_log_paths.reset_mock()
                screen = AIAnalysisScreen(text=DRAFT, instance=app.instances[0])
                await app.push_screen(screen)
                await pilot.pause()
                for kind in ('idle', 'warning', 'error'):
                    text = await _status_path(app, pilot, screen, services, kind, logs)
                    rows.extend([_observe(app, screen.query_one('#ai_status', Static), text),
                                 _observe(app, screen.query_one('#ai_token_estimate', Static),
                                          'Input: ~7 tokens')])
                for cost, price, model in COSTS[:3]:
                    await _complete(app, pilot, screen, services, cost, model)
                    rows.extend(_metadata(app, screen, price, model))
                await pilot.press('escape')
                await wait_until(lambda: app.screen is origin)
            assert app._exception is None
    finally:
        record_property('registry-names', json.dumps(names))
        record_property('copy-glyph-records', json.dumps(rows, sort_keys=True))
    assert (tmp_path / 'config.json').read_bytes() == persisted
    assert len(rows) == len(names) * 21
    assert not _failures(rows), json.dumps(_failures(rows), sort_keys=True)


SAFE_LOG_PATH = '/var/log/app.log'
LITERAL_LOG_PATH = '/var/log/a[X[/b]\\'
LITERAL_FAILURE = 'Failed RAW [X[/b]\\'
LOG_CONTENT = 'first [literal] line\nsecond line'


def _fetch_services(app: _Host, monkeypatch, *, demo: bool = False):
    logs = _logs()
    logs.probe_log_paths.return_value = [SAFE_LOG_PATH]
    logs.scan_log_directories.return_value = []
    logs.classify_log_file.return_value = 'active'
    logs.get_tail_command.return_value = 'tail fixture'
    logs.resolve_connection.return_value = {
        'host': '192.0.2.10', 'username': 'operator', 'key_path': None,
        'proxy_args': [], 'port': 22, 'extra_options': [],
    }
    ssh = create_autospec(SSHService, instance=True, spec_set=True)
    ssh.build_ssh_command.return_value = ['ssh', 'fixture-host']
    run = create_autospec(analysis_module.run_ssh_subprocess, spec_set=True)
    run.return_value = (b'', b'')
    monkeypatch.setattr(analysis_module, 'run_ssh_subprocess', run)
    app.log_viewer_service, app.ssh_service = logs, ssh
    redactor = None
    if demo:
        redactor = create_autospec(RedactionService, instance=True, spec_set=True)
        redactor.real_instance_id.side_effect = lambda value: value

        def scrub(text, *, honour_kill_switch=True):
            assert honour_kill_switch
            return text.replace('RAW', 'masked')

        redactor.scrub_stream.side_effect = scrub
        app._instances_pristine = [dict(row) for row in app.instances]
        app.redaction_service = redactor
    return logs, ssh, run, redactor


async def _choose_log(pilot: Pilot, app: _Host, *, custom: bool = False) -> None:
    await wait_until(lambda: isinstance(app.screen, LogPickerModal))
    picker = app.screen
    await wait_until(lambda: bool(picker.query('#log_picker_search')))
    search = picker.query_one('#log_picker_search', Input)
    await wait_until(lambda: app.focused is search)
    assert app.focused is search
    if custom:
        await pilot.press(*'custom')
        await wait_until(lambda: set(picker._option_map) == {'action:add_path'})
        await pilot.press('enter')
        await wait_until(lambda: isinstance(app.screen, AddPathModal))
        field = app.screen.query_one('#add_path_input', Input)
        await wait_until(lambda: app.focused is field)
        await pilot.press(*LITERAL_LOG_PATH, 'enter')
    else:
        await pilot.press('enter')


def _fetch_call_contract(app, screen, logs, ssh, run, path):
    rows = [dict(row) for row in (app._instances_pristine if app.demo_mode else app.instances)]
    logs.resolve_connection.assert_awaited_once_with(
        screen._instance, ssh, app.connection_service, team_rows=[], rows=rows)
    logs.classify_log_file.assert_called_once_with(path)
    logs.get_tail_command.assert_called_once_with(path, num_lines=200, follow=False)
    logs.get_read_command.assert_not_called()
    ssh.build_ssh_command.assert_called_once_with(
        host='192.0.2.10', username='operator', key_path=None, proxy_args=[],
        remote_command='tail fixture', port=22, extra_options=[])
    run.assert_awaited_once_with(['ssh', 'fixture-host'], timeout=30)


@pytest.mark.asyncio
async def test_log_fetch_status_pending_and_literal_path_success(
    manager, services, monkeypatch, tmp_path: Path, record_property,
) -> None:
    app = _app(manager, services, 'ansi-light')
    logs, ssh, run, _ = _fetch_services(app, monkeypatch)
    probe_started, release_probe = asyncio.Event(), asyncio.Event()
    fetch_started, release_fetch = asyncio.Event(), asyncio.Event()

    async def probe(instance, ssh_service, connection_service, *, team_rows=(), rows=None, runner=None):
        probe_started.set()
        await release_probe.wait()
        return [SAFE_LOG_PATH]

    async def resolve(instance, ssh_service, connection_service, *, team_rows=(), rows=None):
        fetch_started.set()
        await release_fetch.wait()
        return logs.resolve_connection.return_value

    logs.probe_log_paths.side_effect, logs.resolve_connection.side_effect = probe, resolve
    run.return_value = (LOG_CONTENT.encode(), b'')
    screen = AIAnalysisScreen(text=DRAFT, instance=app.instances[0])
    persisted = (tmp_path / 'config.json').read_bytes()
    rows = []
    async with app.run_test(size=(160, 50)) as pilot:
        _assert_colour_mode(app)
        await app.push_screen(screen)
        await pilot.pause()
        editor = screen.query_one('#ai_text_input', TextArea)
        before = editor.document, editor.text, editor.selection, editor.scroll_offset
        assert await pilot.click(screen.query_one('#btn_fetch_logs', Button))
        await wait_until(probe_started.is_set)
        rows.append(_observe(app, screen.query_one('#ai_status', Static), 'Probing available logs...'))
        assert screen.query_one('#btn_fetch_logs', Button).disabled
        assert before == (editor.document, editor.text, editor.selection, editor.scroll_offset)
        release_probe.set()
        await _choose_log(pilot, app, custom=True)
        await wait_until(fetch_started.is_set)
        assert app.screen is screen
        rows.append(_observe(app, screen.query_one('#ai_status', Static),
                             f'Fetching {LITERAL_LOG_PATH}...'))
        assert screen.query_one('#btn_fetch_logs', Button).disabled
        assert before == (editor.document, editor.text, editor.selection, editor.scroll_offset)
        release_fetch.set()
        await wait_until(lambda: not screen.query_one('#btn_fetch_logs', Button).disabled)
        await pilot.pause()
        expected = f'Fetched 2 lines from {LITERAL_LOG_PATH}. Press Analyze to send to AI.'
        rows.append(_observe(app, screen.query_one('#ai_status', Static), expected))
        rendered = screen.query_one('#ai_status', Static).render()
        assert any(str(span.style) == 'bold' and rendered.plain[span.start:span.end] == 'Analyze'
                   for span in rendered.spans)
        assert editor.text == LOG_CONTENT and screen._raw_text == LOG_CONTENT
        assert not editor.read_only and screen._filter_pattern == ''
        assert screen.query_one('#ai_output', TextArea).text == '' and screen._output_text == ''
        _fetch_call_contract(app, screen, logs, ssh, run, LITERAL_LOG_PATH)
        services.analysis.analyze_text.assert_not_awaited()
        assert app._exception is None
    assert (tmp_path / 'config.json').read_bytes() == persisted
    _emit_assert(record_property, rows)


@pytest.mark.asyncio
async def test_log_fetch_status_probe_error_is_literal_after_demo_scrub(
    manager, services, monkeypatch, tmp_path: Path, record_property,
) -> None:
    app = _app(manager, services, 'nord')
    logs, ssh, run, redactor = _fetch_services(app, monkeypatch, demo=True)
    started, release = asyncio.Event(), asyncio.Event()

    async def probe(instance, ssh_service, connection_service, *, team_rows=(), rows=None, runner=None):
        started.set()
        await release.wait()
        raise RuntimeError(LITERAL_FAILURE)

    logs.probe_log_paths.side_effect = probe
    screen = AIAnalysisScreen(text=DRAFT, instance=app.instances[0])
    persisted = (tmp_path / 'config.json').read_bytes()
    async with app.run_test(size=(160, 50)) as pilot:
        _assert_colour_mode(app)
        app.demo_mode = True
        await app.push_screen(screen)
        await pilot.pause()
        editor = screen.query_one('#ai_text_input', TextArea)
        before = editor.document, editor.text, editor.selection, editor.scroll_offset
        assert await pilot.click(screen.query_one('#btn_fetch_logs', Button))
        await wait_until(started.is_set)
        release.set()
        await wait_until(lambda: not screen.query_one('#btn_fetch_logs', Button).disabled)
        await pilot.pause()
        rows = [_observe(app, screen.query_one('#ai_status', Static),
                         'Error: ' + LITERAL_FAILURE.replace('RAW', 'masked'))]
        assert before == (editor.document, editor.text, editor.selection, editor.scroll_offset)
        assert screen.query_one('#ai_output', TextArea).text == '' and screen._output_text == ''
        redactor.scrub_stream.assert_called_once_with(LITERAL_FAILURE)
        logs.resolve_connection.assert_not_awaited()
        ssh.build_ssh_command.assert_not_called()
        run.assert_not_awaited()
        services.analysis.analyze_text.assert_not_awaited()
        assert app.screen is screen and app._exception is None
        # The adjacent no-address outcome must not start another external probe.
        logs._resolve_connection.return_value = {'host': ''}
        previous = logs.probe_log_paths.await_count
        assert await pilot.click(screen.query_one('#btn_fetch_logs', Button))
        await wait_until(lambda: not screen.query_one('#btn_fetch_logs', Button).disabled
                         and screen.query_one('#ai_status', Static).render().plain ==
                         'No IP address available for this instance.')
        rows.append(_observe(app, screen.query_one('#ai_status', Static),
                             'No IP address available for this instance.'))
        assert logs.probe_log_paths.await_count == previous
        assert before == (editor.document, editor.text, editor.selection, editor.scroll_offset)
        run.assert_not_awaited()
    assert (tmp_path / 'config.json').read_bytes() == persisted
    _emit_assert(record_property, rows)


@pytest.mark.asyncio
@pytest.mark.parametrize('outcome', ('stderr', 'fetch-error', 'timeout', 'empty', 'success-demo'))
async def test_log_fetch_status_fetch_outcome_preserves_raw_operation_and_display(
    manager, services, monkeypatch, tmp_path: Path, record_property, outcome,
) -> None:
    app = _app(manager, services, 'catppuccin-frappe' if outcome == 'timeout' else 'ansi-light')
    logs, ssh, run, redactor = _fetch_services(app, monkeypatch, demo=True)
    started, release = asyncio.Event(), asyncio.Event()

    async def resolve(instance, ssh_service, connection_service, *, team_rows=(), rows=None):
        started.set()
        await release.wait()
        if outcome == 'fetch-error':
            raise RuntimeError(LITERAL_FAILURE)
        return logs.resolve_connection.return_value

    logs.resolve_connection.side_effect = resolve
    raw_content = 'RAW first [literal] line\nsecond line'
    if outcome == 'stderr':
        run.return_value = (b'', LITERAL_FAILURE.encode())
        expected = 'No logs fetched. ' + LITERAL_FAILURE.replace('RAW', 'masked')
    elif outcome == 'timeout':
        run.side_effect = asyncio.TimeoutError()
        expected = 'Timed out fetching logs from server.'
    elif outcome == 'fetch-error':
        expected = 'Error: ' + LITERAL_FAILURE.replace('RAW', 'masked')
    elif outcome == 'empty':
        expected = 'Log file is empty or not readable.'
    else:
        run.return_value = (raw_content.encode(), b'')
        expected = f'Fetched 2 lines from {SAFE_LOG_PATH}. Press Analyze to send to AI.'
    screen = AIAnalysisScreen(text=DRAFT, instance=app.instances[0])
    persisted = (tmp_path / 'config.json').read_bytes()
    rows = []
    async with app.run_test(size=(160, 50)) as pilot:
        _assert_colour_mode(app)
        app.demo_mode = True
        await app.push_screen(screen)
        await pilot.pause()
        editor = screen.query_one('#ai_text_input', TextArea)
        before = editor.document, editor.text, editor.selection, editor.scroll_offset
        assert await pilot.click(screen.query_one('#btn_fetch_logs', Button))
        await _choose_log(pilot, app)
        await wait_until(started.is_set)
        assert app.screen is screen
        rows.append(_observe(app, screen.query_one('#ai_status', Static), f'Fetching {SAFE_LOG_PATH}...'))
        assert before == (editor.document, editor.text, editor.selection, editor.scroll_offset)
        assert screen.query_one('#btn_fetch_logs', Button).disabled
        release.set()
        await wait_until(lambda: not screen.query_one('#btn_fetch_logs', Button).disabled)
        await pilot.pause()
        rows.append(_observe(app, screen.query_one('#ai_status', Static), expected))
        if outcome == 'success-demo':
            assert editor.text == raw_content.replace('RAW', 'masked')
            assert screen._raw_text == editor.text
            redactor.scrub_stream.assert_any_call(raw_content)
            redactor.scrub_stream.assert_any_call(SAFE_LOG_PATH)
        else:
            assert before == (editor.document, editor.text, editor.selection, editor.scroll_offset)
        if outcome in ('stderr', 'fetch-error'):
            redactor.scrub_stream.assert_called_once_with(LITERAL_FAILURE)
        if outcome == 'fetch-error':
            logs.resolve_connection.assert_awaited_once()
            ssh.build_ssh_command.assert_not_called()
            run.assert_not_awaited()
        else:
            _fetch_call_contract(app, screen, logs, ssh, run, SAFE_LOG_PATH)
        assert screen.query_one('#ai_output', TextArea).text == '' and screen._output_text == ''
        services.analysis.analyze_text.assert_not_awaited()
        assert app._exception is None
    assert (tmp_path / 'config.json').read_bytes() == persisted
    _emit_assert(record_property, rows)
