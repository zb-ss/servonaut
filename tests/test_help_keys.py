"""The help screen lists the keys that are really bound, as they are bound.

Its key tables are built from the screens' BINDINGS; these tests make sure
every binding is listed, in the case it is bound in, and that no key the
prose mentions is one that nothing binds.
"""

from __future__ import annotations

import re

import pytest
from textual.binding import Binding

from servonaut.app import ServonautApp
from servonaut.screens.command_overlay import CommandOverlay
from servonaut.screens.fleet_memory import FleetMemoryScreen
from servonaut.screens.help import binding_rows, build_help_text, key_label
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.log_viewer import LogViewerScreen
from servonaut.screens.server_actions import ServerActionsScreen

# Screens whose keys the help tables list.
_TABLED = (InstanceListScreen, ServerActionsScreen, LogViewerScreen, CommandOverlay, ServonautApp)
# Screens the help's prose mentions keys of.
_MENTIONED = _TABLED + (FleetMemoryScreen,)


def _keys(owner) -> list:
    keys = []
    for binding in owner.BINDINGS:
        binding = binding if isinstance(binding, Binding) else Binding(*binding)
        keys.extend(key.strip() for key in binding.key.split(","))
    return keys


@pytest.fixture(scope="module")
def help_text() -> str:
    return build_help_text()


@pytest.mark.parametrize("owner", _TABLED, ids=lambda owner: owner.__name__)
def test_every_binding_is_listed(owner, help_text: str) -> None:
    missing = [key for key in _keys(owner) if f"`{key_label(key)}`" not in help_text]
    assert not missing, f"{owner.__name__} keys missing from the help: {missing}"


def test_the_fleet_keys_are_listed_in_the_case_they_are_bound(help_text: str) -> None:
    fleet = help_text.split("## Instance List", 1)[1].split("\n## ", 1)[0]
    for key in ("s", "b", "c", "t", "l", "a", "r", "y", "o", "m", "k", "v", "D"):
        assert f"| `{key}` |" in fleet or f"/ `{key}` |" in fleet, key
    for wrong in ("`S`", "`B`", "`R`", "`Y`", "`d`"):
        assert wrong not in fleet, wrong


def test_every_single_key_the_help_mentions_is_bound(help_text: str) -> None:
    bound = {key for owner in _MENTIONED for key in _keys(owner)}
    mentioned = set(re.findall(r"`([A-Za-z0-9])`", help_text))
    assert mentioned <= bound, f"not bound anywhere: {sorted(mentioned - bound)}"


@pytest.mark.parametrize(
    ("key", "label"),
    [
        ("s", "s"),
        ("D", "D"),
        ("slash", "/"),
        ("question_mark", "?"),
        ("escape", "Esc"),
        ("enter", "Enter"),
        ("f2", "F2"),
        ("ctrl+r", "Ctrl+R"),
        ("ctrl+shift+d", "Ctrl+Shift+D"),
    ],
)
def test_key_labels(key: str, label: str) -> None:
    assert key_label(key) == label


def test_keys_of_one_action_share_a_row_described_by_the_tooltip() -> None:
    rows = binding_rows([
        Binding("enter", "open", "Open", tooltip="Open the thing"),
        Binding("o", "open", "Open"),
        Binding("x", "close", "Close"),
    ])
    assert rows == [("`Enter` / `o`", "Open the thing"), ("`x`", "Close")]
