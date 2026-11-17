"""Scoped CSS coverage requires real registration, ancestry and constructors."""

import ast

import pytest

from tests import test_css_id_coverage as guard


_IMPORTS = '''
from pathlib import Path
from servonaut.styles import CSS_FILES as _APP_CSS_FILES
from servonaut.widgets.workspace import WorkspaceScreen
from servonaut.widgets.busy_indicator import BusyIndicator
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Static, DataTable
'''
_VAULT = _IMPORTS + '''
class VaultScreen(WorkspaceScreen):
    def compose(self):
        with Horizontal(id="vault_actions"):
            with Vertical():
                yield Button("Create", id="vault_create")
'''
_VAULT_CSS = 'VaultScreen #vault_actions Button { min-width: 0; }'


def _ids(source, css, *, extra="", busy=""):
    return guard._audited_style_ids(ast.parse(source), css, extra, busy)


@pytest.mark.parametrize("composition", ["with", "positional"])
def test_known_scoped_ancestor_and_constructor_are_covered(composition):
    source = _VAULT
    if composition == "positional":
        source = _IMPORTS + '''
class VaultScreen(WorkspaceScreen):
    def compose(self):
        yield Horizontal(Vertical(Button("Create", id="vault_create")), id="vault_actions")
'''
    assert "vault_create" in _ids(source, _VAULT_CSS)


@pytest.mark.parametrize("css", [
    "", "Button { height: 3; }", "VaultScreen #vault_actions Button {}",
    "VaultScreen #vault_actions Button { /* only a comment */ }",
    "/* " + _VAULT_CSS + " */",
    "OtherScreen #vault_actions Button { height: 3; }",
    "VaultScreen #vault_actions_extra Button { height: 3; }",
    "VaultScreen #vault_actions > Button { height: 3; }",
])
def test_absent_empty_commented_wrong_owner_prefix_or_combinator_is_not_coverage(css):
    assert "vault_create" not in _ids(_VAULT, css)


@pytest.mark.parametrize("source", [
    _VAULT.replace('id="vault_actions"', 'id="other_actions"'),
    _VAULT.replace("class VaultScreen", "class OtherScreen"),
    _VAULT.replace('yield Button("Create", id="vault_create")',
                   'yield unknown(Button("Create", id="vault_create"))'),
    _VAULT.replace('yield Button("Create", id="vault_create")',
                   'yield Horizontal(callback=Button("Create", id="vault_create"))'),
    _VAULT.replace('yield Button("Create", id="vault_create")',
                   'yield Horizontal([Button("Create", id="vault_create")])'),
    _VAULT.replace('yield Button("Create", id="vault_create")',
                   'button = Button("Create", id="vault_create")'),
    _VAULT.replace('with Horizontal(id="vault_actions"):',
                   'with Horizontal(id="vault_actions"), Vertical():'),
    _VAULT + '\nplain = Vertical(id="vault_create")\n',
    _VAULT + '\nforwarded = unknown(input_id="vault_create")\n',
    _VAULT + '\ndef builder(Button):\n    pass\n',
    _VAULT + '\nButton = unknown\n',
    _VAULT.replace("from textual.widgets import Button, Static, DataTable",
                   "from other.widgets import Button, Static, DataTable"),
])
def test_changed_ancestry_unknown_factory_duplicate_or_constructor_shadow_fails(source):
    assert "vault_create" not in _ids(source, _VAULT_CSS)


def test_class_token_requires_real_widget_owning_screen_and_ancestor():
    source = _IMPORTS + '''
class ServerActionsScreen(WorkspaceScreen):
    def compose(self):
        yield Vertical(Static("Stats", id="live_stats", classes="sa-section"), id="sa-detail")
'''
    css = '#sa-detail .sa-section { height: auto; }'
    assert "live_stats" in _ids(source, css)
    assert "live_stats" not in _ids(source.replace('classes="sa-section"', 'classes="sa-section-extra"'), css)
    assert "live_stats" not in _ids(source.replace('id="sa-detail"', 'id="other"'), css)
    assert "live_stats" not in _ids(source.replace("class ServerActionsScreen", "class OtherScreen"), css)


def _memory_source(owner, *, registered=True):
    registration = '    CSS_PATH = [*_APP_CSS_FILES, Path(__file__).parent.parent / "memory_screen.tcss"]\n'
    return _IMPORTS + f'class {owner}(WorkspaceScreen):\n' + (registration if registered else "") + '''
    def compose(self):
        yield Container(id="memory-actions")
'''


def test_extra_stylesheet_requires_each_real_owner_registration(tmp_path, monkeypatch):
    screens = tmp_path / "screens"
    screens.mkdir()
    monkeypatch.setattr(guard, "SCREENS_DIR", screens)
    (tmp_path / "memory_screen.tcss").write_text(
        'MemoryScreen #memory-actions, FleetMemoryScreen #memory-actions { height: auto; }'
    )
    memory = screens / "memory.py"
    fleet = screens / "fleet_memory.py"
    memory.write_text(_memory_source("MemoryScreen"))
    fleet.write_text(_memory_source("FleetMemoryScreen"))
    assert "memory-actions" in guard._shared_scoped_style_ids("")
    # Fleet registration of the same file must not rescue Memory's lost one.
    memory.write_text(_memory_source("MemoryScreen", registered=False))
    assert "memory-actions" not in guard._shared_scoped_style_ids("")
    memory.write_text(_memory_source("MemoryScreen"))
    (tmp_path / "memory_screen.tcss").write_text('FleetMemoryScreen #memory-actions { height: auto; }')
    assert "memory-actions" not in guard._shared_scoped_style_ids("")
    (tmp_path / "memory_screen.tcss").unlink()
    with pytest.raises(FileNotFoundError):
        guard._shared_scoped_style_ids("")


def test_unregistered_sheet_or_path_alias_shadow_cannot_supply_coverage(tmp_path, monkeypatch):
    screens = tmp_path / "screens"
    screens.mkdir()
    monkeypatch.setattr(guard, "SCREENS_DIR", screens)
    (tmp_path / "memory_screen.tcss").write_text('MemoryScreen #memory-actions { height: auto; }')
    memory = screens / "memory.py"
    memory.write_text(_memory_source("MemoryScreen", registered=False))
    assert "memory-actions" not in guard._shared_scoped_style_ids("")
    memory.write_text(_memory_source("MemoryScreen") + '\ndef builder(Path):\n    pass\n')
    assert "memory-actions" not in guard._shared_scoped_style_ids("")


def test_scoped_coverage_does_not_hide_cross_file_unproved_id(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, "SCREENS_DIR", tmp_path)
    (tmp_path / "vault.py").write_text(_VAULT)
    assert "vault_create" in guard._shared_scoped_style_ids(_VAULT_CSS)
    for quote in ('"', "'"):
        (tmp_path / "plain.py").write_text(f'plain = unknown(input_id={quote}vault_create{quote})\n')
        assert "vault_create" not in guard._shared_scoped_style_ids(_VAULT_CSS)


_SYNC = _IMPORTS + '''
class MemorySyncSetupScreen(WorkspaceScreen):
    def _kv_row(self, label, value, *, value_id=None):
        return Horizontal(Static(label), Static(value, id=value_id, classes="msync_kv_value"))

    def _build_status_card(self):
        actions_children = [Button("Base", id="existing")]
        if True:
            actions_children.append(Button("Remember", id="msync_btn_remember"))
        return Horizontal(*actions_children, classes="msync_card_actions msync_configured_actions")

    def compose(self):
        yield self._kv_row("Last", "value", value_id="msync_last_sync_value")
'''
_SYNC_CSS = '''
MemorySyncSetupScreen .msync_kv_value { height: auto; }
MemorySyncSetupScreen .msync_configured_actions Button { width: 1fr; }
'''


@pytest.mark.parametrize("annotated", [False, True])
def test_named_sync_forwarding_and_local_action_list_are_covered(annotated):
    source = _SYNC.replace("actions_children =", "actions_children: list =", 1) if annotated else _SYNC
    assert {"msync_last_sync_value", "msync_btn_remember"} <= _ids(source, _SYNC_CSS)


@pytest.mark.parametrize("change", [
    lambda source: source.replace('classes="msync_kv_value"', 'classes="other"'),
    lambda source: source.replace('id=value_id', 'id=other_id'),
    lambda source: source.replace('*, value_id=None', '*, other_id=None'),
    lambda source: source.replace('yield self._kv_row(', 'yield unknown('),
    lambda source: source + '\nforwarded = unknown(value_id="msync_last_sync_value")\n',
    lambda source: source.replace('yield self._kv_row(', 'self._kv_row = unknown\n        yield self._kv_row('),
])
def test_sync_value_contract_cannot_hide_forwarding_or_constructor_changes(change):
    assert "msync_last_sync_value" not in _ids(change(_SYNC), _SYNC_CSS)
    assert "msync_last_sync_value" not in _ids(_SYNC, _SYNC_CSS.replace(
        'MemorySyncSetupScreen .msync_kv_value { height: auto; }', ''
    ))


@pytest.mark.parametrize("change", [
    lambda source: source.replace('msync_card_actions msync_configured_actions', 'other'),
    lambda source: source.replace('return Horizontal(*actions_children',
                                  'leaked = actions_children\n        return Horizontal(*actions_children'),
    lambda source: source.replace('return Horizontal(*actions_children',
                                  'actions_children = []\n        return Horizontal(*actions_children'),
    lambda source: source.replace('actions_children.append(Button(', 'unknown.append(Button('),
    lambda source: source.replace('Button("Remember"', 'unknown("Remember"'),
])
def test_sync_action_list_must_reach_its_known_style_without_escape(change):
    assert "msync_btn_remember" not in _ids(change(_SYNC), _SYNC_CSS)
    assert "msync_btn_remember" not in _ids(_SYNC, _SYNC_CSS.replace(
        'MemorySyncSetupScreen .msync_configured_actions Button { width: 1fr; }', ''
    ))


def test_busy_indicator_requires_known_component_and_active_idle_rules():
    source = _IMPORTS + '''
class TeamManagementScreen(WorkspaceScreen):
    def compose(self):
        yield BusyIndicator(id="team_list_busy")
'''
    css = 'BusyIndicator { display: none; }\nBusyIndicator.-active { display: block; }'
    assert "team_list_busy" in _ids(source, "", busy=css)
    assert "team_list_busy" not in _ids(source.replace('yield BusyIndicator(', 'yield Static('), "", busy=css)
    assert "team_list_busy" not in _ids(source, "", busy='BusyIndicator { display: none; }')
    assert "team_list_busy" not in _ids(source + '\ndef builder(BusyIndicator):\n    pass\n', "", busy=css)


def test_global_refresh_exception_is_bound_to_its_exact_constructor_parent_and_owner():
    source = _IMPORTS + '''
class DbCoverageScreen(WorkspaceScreen):
    def compose(self):
        yield Horizontal(Button("Refresh", id="db_cov_refresh"), classes="db-filter-row")
'''
    css = 'Button { height: 3; }\nDbCoverageScreen .db-filter-row { height: 3; }'
    assert "db_cov_refresh" in _ids(source, css)
    for changed in (
        source.replace('classes="db-filter-row"', 'classes="other"'),
        source.replace('id="db_cov_refresh"', 'id="unrelated_button"'),
        source.replace('Button("Refresh"', 'Static("Refresh"'),
        source.replace('class DbCoverageScreen', 'class OtherScreen'),
        source + '\nplain = Button("Other", id="db_cov_refresh")\n',
    ):
        assert not _ids(changed, css)
    assert "db_cov_refresh" not in _ids(source, 'Button { height: 3; }')



def _memory_textarea_source(owner="MemoryScreen", *, alias=False, registered=True):
    source = _memory_source(owner, registered=registered)
    imported = "TextArea as RecordReader" if alias else "TextArea"
    constructor = "RecordReader" if alias else "TextArea"
    return source.replace(
        "from textual.widgets import Button, Static, DataTable",
        f"from textual.widgets import Button, Static, DataTable, {imported}",
    ).replace(
        'yield Container(id="memory-actions")',
        f'yield {constructor}("", id="memory-record-detail")',
    )


@pytest.mark.parametrize("owner,filename", [
    ("MemoryScreen", "memory.py"), ("FleetMemoryScreen", "fleet_memory.py"),
])
@pytest.mark.parametrize("alias", [False, True])
def test_declared_extra_css_covers_real_textarea_and_import_alias(
    tmp_path, monkeypatch, owner, filename, alias,
):
    screens = tmp_path / "screens"
    screens.mkdir()
    monkeypatch.setattr(guard, "SCREENS_DIR", screens)
    (screens / filename).write_text(_memory_textarea_source(owner, alias=alias))
    sheet = tmp_path / "memory_screen.tcss"
    sheet.write_text(f"{owner} #memory-record-detail {{ min-height: 6; }}")
    assert "memory-record-detail" in guard._shared_scoped_style_ids("")
    # Removing the author declaration must expose the previously covered ID.
    sheet.write_text("")
    assert "memory-record-detail" not in guard._shared_scoped_style_ids("")
    sheet.unlink()
    with pytest.raises(FileNotFoundError):
        guard._shared_scoped_style_ids("")


@pytest.mark.parametrize("css", [
    "", "TextArea { min-height: 6; }",
    "MemoryScreen #memory-record-detail {}",
    "MemoryScreen #memory-record-detail { /* declaration removed */ }",
    "/* MemoryScreen #memory-record-detail { min-height: 6; } */",
    "OtherScreen #memory-record-detail { min-height: 6; }",
    "FleetMemoryScreen #memory-record-detail { min-height: 6; }",
    "MemoryScreen #memory-record-detail-extra { min-height: 6; }",
])
def test_extra_textarea_requires_its_exact_nonempty_owner_id_rule(tmp_path, monkeypatch, css):
    screens = tmp_path / "screens"
    screens.mkdir()
    monkeypatch.setattr(guard, "SCREENS_DIR", screens)
    (screens / "memory.py").write_text(_memory_textarea_source())
    (tmp_path / "memory_screen.tcss").write_text(css)
    assert "memory-record-detail" not in guard._shared_scoped_style_ids("")


@pytest.mark.parametrize("case", [
    "unregistered", "wrong-owner", "wrong-filename", "wrong-path", "path-shadow",
    "bundle-shadow", "foreign-constructor", "missing-constructor-import",
    "constructor-shadow", "alias-shadow", "unproved-duplicate",
])
def test_extra_textarea_keeps_registration_path_and_constructor_guards(tmp_path, monkeypatch, case):
    screens = tmp_path / "screens"
    screens.mkdir()
    monkeypatch.setattr(guard, "SCREENS_DIR", screens)
    source = _memory_textarea_source(alias=case == "alias-shadow", registered=case != "unregistered")
    filename = "other.py" if case == "wrong-filename" else "memory.py"
    if case == "wrong-owner":
        source = source.replace("class MemoryScreen", "class OtherScreen")
    elif case == "wrong-path":
        source = source.replace(' / "memory_screen.tcss"', ' / "other.tcss"')
    elif case == "path-shadow":
        source += '\ndef builder(Path):\n    pass\n'
    elif case == "bundle-shadow":
        source += '\n_APP_CSS_FILES = []\n'
    elif case == "foreign-constructor":
        source = source.replace(
            "from textual.widgets import Button, Static, DataTable, TextArea",
            "from textual.widgets import Button, Static, DataTable\nfrom other.widgets import TextArea",
        )
    elif case == "missing-constructor-import":
        source = source.replace(
            "from textual.widgets import Button, Static, DataTable, TextArea",
            "from textual.widgets import Button, Static, DataTable",
        )
    elif case == "constructor-shadow":
        source += '\ndef builder(TextArea):\n    pass\n'
    elif case == "alias-shadow":
        source += '\nRecordReader = unknown\n'
    elif case == "unproved-duplicate":
        source += '\nforwarded = unknown(input_id="memory-record-detail")\n'
    (screens / filename).write_text(source)
    (tmp_path / "memory_screen.tcss").write_text(
        "MemoryScreen #memory-record-detail { min-height: 6; }"
    )
    assert "memory-record-detail" not in guard._shared_scoped_style_ids("")
