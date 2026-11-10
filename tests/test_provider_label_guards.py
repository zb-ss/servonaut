"""Provider, storage, vault and log screens keep one button style and theme colours.

A key hint belongs in the button's quiet hint (``ActionButton``), never in
brackets inside the label; a ``1.`` prefix is the same mistake. Colours come
from the theme, so a named colour in markup or a style would ignore the user's
theme.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src" / "servonaut"

BUTTON_SCREENS = (
    "screens/bw_vault_manager.py",
    "screens/backup_restore.py",
    "screens/snapshot_manager.py",
    "screens/ovh_ssh_keys.py",
    "screens/hetzner_ssh_keys.py",
    "screens/ai_conversations_screen.py",
    "screens/object_storage.py",
    "screens/vault_auto_bind.py",
)
COLOUR_FILES = BUTTON_SCREENS + (
    "screens/fleet_memory.py",
    "screens/log_viewer.py",
    "screens/ovh_manager.py",
    "screens/hetzner_manager.py",
    "screens/aws_manager.py",
    "widgets/command_output.py",
    "screens/command_overlay.py",
    "screens/ai_topup_modal.py",
)

_NAMED = "red|green|yellow|blue|cyan|magenta|white|black|orange|purple|grey|gray"
# A button label ending in a bracketed key: "Refresh (r)", "Delete (F5)".
BRACKET_LABEL = re.compile(r"""(?:Button|ActionButton)\(\s*["'][^"']*\s\([A-Za-z0-9]{1,5}\)["']""")
NUMBER_PREFIX = re.compile(r"""(?:Button|ActionButton)\(\s*["']\d+\.\s""")
NAMED_MARKUP = re.compile(rf"\[(?:/)?(?:bold |dim |italic |underline )*(?:{_NAMED})\]")
NAMED_STYLE = re.compile(rf"""(?:style|color)\s*=\s*["'](?:(?:bold|dim|italic)\s+)*(?:{_NAMED})["']""")
HEAVY_BORDER = re.compile(r"\bborder\s*:\s*(?:heavy|thick|double|solid|tall|wide|outer)\b")


def _source(relative: str) -> str:
    return (SRC / relative).read_text(encoding="utf-8")


@pytest.mark.parametrize("relative", BUTTON_SCREENS)
def test_buttons_have_no_bracketed_key_or_number_prefix(relative: str) -> None:
    source = _source(relative)
    assert not BRACKET_LABEL.findall(source)
    assert not NUMBER_PREFIX.findall(source)


@pytest.mark.parametrize("relative", COLOUR_FILES)
def test_colours_come_from_the_theme(relative: str) -> None:
    source = _source(relative)
    assert not NAMED_MARKUP.findall(source)
    assert not NAMED_STYLE.findall(source)


def test_top_up_dialog_borders_are_rounded() -> None:
    assert not HEAVY_BORDER.findall(_source("screens/ai_topup_modal.py"))
    assert not HEAVY_BORDER.findall((SRC / "styles/screens/ai_choice_dialogs.tcss").read_text(encoding="utf-8"))
