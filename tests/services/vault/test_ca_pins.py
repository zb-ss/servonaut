"""CA trust anchors must never be loaded from attacker-controlled filesystem objects."""

from __future__ import annotations

import os

import pytest

from servonaut.services.vault.ca_pins import CaPinMismatchError, CaPinStore, CaPins


PINS = CaPins("SHA256:user", "SHA256:host")


def test_refuses_symlinked_pin_file_without_following_it(tmp_path):
    target = tmp_path / "attacker-pins.json"
    target.write_text('{"format": 1, "teams": {}}', encoding="utf-8")
    pin_path = tmp_path / "ca_pins.json"
    pin_path.symlink_to(target)

    with pytest.raises(CaPinMismatchError, match="real private file"):
        CaPinStore(pin_path).verify_or_pin("team", PINS)
    assert target.read_text(encoding="utf-8") == '{"format": 1, "teams": {}}'


def test_refuses_group_readable_pin_file(tmp_path):
    pin_path = tmp_path / "ca_pins.json"
    pin_path.write_text('{"format": 1, "teams": {}}', encoding="utf-8")
    os.chmod(pin_path, 0o640)

    with pytest.raises(CaPinMismatchError, match="ownership or permissions"):
        CaPinStore(pin_path).verify_or_pin("team", PINS)


def test_creates_owner_only_regular_pin_file(tmp_path):
    pin_path = tmp_path / "private" / "ca_pins.json"
    CaPinStore(pin_path).verify_or_pin("team", PINS)

    assert pin_path.is_file() and not pin_path.is_symlink()
    assert pin_path.stat().st_mode & 0o777 == 0o600
    assert pin_path.parent.stat().st_mode & 0o777 == 0o700
