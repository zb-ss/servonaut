"""Settings in demo mode: identifiers shown as stand-ins, real values saved.

Every panel listed with ``DEMO_REDACTED_FIELDS`` is loaded with real,
identifying values; in demo mode none of them may be on screen, and saving
the panel must write the real values back unchanged. A value the user types
always wins, even when it equals the stand-in, and survives a toggle.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

import pytest
from textual.widgets import Input

from tests.test_demo_mode_toggle_redraw import _app, _open, _settle

ROLE_ARN = "arn:aws:iam::123456789012:role/acme-read"  # leak-guard:allow fabricated ARN
MUTATE_ARN = "arn:aws:iam::123456789012:role/acme-write"  # leak-guard:allow fabricated ARN
SUBSCRIPTION = "0acme000-0000-4000-8000-000000000001"  # leak-guard:allow fabricated id

# Local files the app writes to: a temp directory, not a fixture to redact
# (path redaction itself is covered by the redaction tests).
LOCAL = "{local}"

CONFIG: Dict[str, Any] = {
    "default_username": "acmeops",
    "default_key": "~/.ssh/acme_default_key",
    "ovh": {
        "enabled": False,
        "client_id": "acme-oauth-client",
        "default_ssh_key": "~/.ssh/acme_ovh_key",
        "default_username": "acmeovh",
        "cloud_project_ids": ["0acme000000000000000000000000001"],
        "ovh_audit_path": f"{LOCAL}/ovh_audit.json",
        "object_storage": {"endpoint_url": "https://s3.acme-corp.example"},
    },
    "hetzner": {
        "default_hetzner_ssh_key": "acme-laptop",
        "default_local_ssh_key": "~/.ssh/acme_hz_key",
        "default_username": "acmehz",
        "cache_path": f"{LOCAL}/hz_cache.json",
        "audit_path": f"{LOCAL}/hz_audit.jsonl",
        "object_storage": {"endpoint_url": "https://hz.acme-corp.example"},
    },
    "aws": {
        "cache_path": f"{LOCAL}/aws_cache.json",
        "audit_path": f"{LOCAL}/aws_audit.jsonl",
        "object_storage": {"endpoint_url": "https://minio.acme-corp.example", "region": "eu-west-1"},
        "control_plane_role_arn": ROLE_ARN,
        "control_plane_role_arns": {"123456789012": ROLE_ARN},
        "control_plane_external_id": "acme-external-7f3a",
        "control_plane_mutate_role_arn": MUTATE_ARN,
        "control_plane_mutate_role_arns": {"123456789012": MUTATE_ARN},
    },
    "gcp": {"project_ids": ["acme-prod-4711"], "credentials_path": "~/keys/acme-sa.json"},
    "azure": {"subscription_ids": [SUBSCRIPTION], "resource_groups": ["acme-rg"]},
    "relay": {
        "base_url": "https://relay.acme-corp.example",
        "mercure_url": "https://relay.acme-corp.example/.well-known/mercure",
    },
    "mcp": {"audit_path": f"{LOCAL}/mcp_audit.jsonl"},
    "ai_provider": {"base_url": "http://gpu.acme-corp.example:11434"},
    "keyword_store_path": f"{LOCAL}/keywords.json",
    "command_history_path": f"{LOCAL}/history.json",
    "chat_history_path": f"{LOCAL}/chats",
}
# Substrings that identify the account: none may be shown in demo mode.
IDENTIFYING = (
    "acme", "123456789012", "0acme000",
)


def _deep_merge(base: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _settings_app(tmp_path: Path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    config_path = Path(app._config_path)
    local = tmp_path / "local"
    local.mkdir()
    extra = json.loads(json.dumps(CONFIG).replace(LOCAL, str(local)))
    config_path.write_text(
        json.dumps(_deep_merge(json.loads(config_path.read_text()), extra)),
        encoding="utf-8",
    )
    return app


def _redacted_panels(screen) -> List[Any]:
    from servonaut.screens.settings.registry import PANELS

    panels = []
    for spec in PANELS:
        panel = screen._ensure_content(spec.id)
        if getattr(panel, "DEMO_REDACTED_FIELDS", None):
            panels.append(panel)
    return panels


def _texts(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield str(item)
    elif isinstance(value, list):
        yield from (str(item) for item in value)
    else:
        yield str(value)


def _persist(panel) -> None:
    if panel.PANEL_ID == "bw_ssh":
        panel.collect()  # saves through the API: validation is the local part
        return
    panel.persist()


def _saved(app) -> Dict[str, Any]:
    return dataclasses.asdict(app.config_manager.get())


@pytest.mark.asyncio
async def test_every_redacted_field_hides_identifiers_and_saves_the_real_value(
    tmp_path, monkeypatch
) -> None:
    app = _settings_app(tmp_path, monkeypatch)
    async with app.run_test(headless=True, size=(200, 60)) as pilot:
        await _settle(pilot)
        screen = await _open(pilot, "nav_settings", "SettingsScreen")
        panels = _redacted_panels(screen)
        await _settle(pilot)
        bw = next(p for p in panels if p.PANEL_ID == "bw_ssh")
        bw._bw_ssh_config = {"config": {
            "vault_url": "https://vault.acme-corp.example",
            "default_collection_id": SUBSCRIPTION,
        }}
        bw._show_form()
        before = _saved(app)
        assert len(panels) >= 10, [p.PANEL_ID for p in panels]

        app.action_toggle_demo()
        await _settle(pilot)
        shown = {
            f"{panel.PANEL_ID}.{field}": list(_texts(panel._read_field(field)))
            for panel in panels for field in panel.DEMO_REDACTED_FIELDS
        }
        leaks = {
            where: value for where, values in shown.items() for value in values
            if any(marker in value for marker in IDENTIFYING)
        }
        assert leaks == {}
        for panel in panels:
            assert not panel.is_dirty(), panel.PANEL_ID
            _persist(panel)
        after = _saved(app)
        changed = {
            f"{section}.{key}": (before[section][key], after[section][key])
            for section in before if isinstance(before[section], dict)
            for key in before[section] if before[section][key] != after[section][key]
        }
        assert changed == {}
        assert after == before
        assert bw.collect() == {
            "vault_url": "https://vault.acme-corp.example",
            "default_collection_id": SUBSCRIPTION,
        }


async def _type_into(pilot, field: Input, text: str) -> None:
    field.focus()
    await pilot.pause()
    field.value = ""
    await pilot.press(*text)
    await _settle(pilot)


@pytest.mark.asyncio
async def test_a_typed_value_wins_even_when_it_equals_the_stand_in(
    tmp_path, monkeypatch
) -> None:
    app = _settings_app(tmp_path, monkeypatch)
    async with app.run_test(headless=True, size=(200, 60)) as pilot:
        await _settle(pilot)
        app.action_toggle_demo()
        await _settle(pilot)
        screen = await _open(pilot, "nav_settings", "SettingsScreen")
        general = screen._panels["general"]
        field = general.query_one("#general_username", Input)
        stand_in = field.value
        assert stand_in != "acmeops"

        await _type_into(pilot, field, stand_in)
        assert general.is_dirty()
        general.persist()
        assert app.config_manager.get().default_username == stand_in


@pytest.mark.asyncio
async def test_an_edit_survives_switching_demo_mode(tmp_path, monkeypatch) -> None:
    app = _settings_app(tmp_path, monkeypatch)
    async with app.run_test(headless=True, size=(200, 60)) as pilot:
        await _settle(pilot)
        app.action_toggle_demo()
        await _settle(pilot)
        screen = await _open(pilot, "nav_settings", "SettingsScreen")
        general = screen._panels["general"]
        await _type_into(pilot, general.query_one("#general_default_key", Input), "~/.ssh/new_key")

        app.action_toggle_demo()  # off: the typed value, not the old key
        await _settle(pilot)
        assert general.query_one("#general_default_key", Input).value == "~/.ssh/new_key"
        app.action_toggle_demo()  # on again: shown as a stand-in, still the edit
        await _settle(pilot)
        assert general.query_one("#general_default_key", Input).value != "~/.ssh/new_key"
        assert general.is_dirty()
        general.persist()
        saved = app.config_manager.get()
        assert saved.default_key == "~/.ssh/new_key"
        assert saved.default_username == "acmeops", "untouched fields keep the real value"
