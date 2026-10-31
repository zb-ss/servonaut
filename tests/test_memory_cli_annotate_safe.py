"""``memory annotate`` edits a private copy and writes back only if the notes are unchanged."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import MagicMock

from servonaut.cli.memory import _cmd_annotate
from tests.test_memory_cli import _fake_config, _make_args, _make_inst, _make_memory_service

IID = "i-abc123"


def _editor(tmp_path: Path, monkeypatch, body: str) -> Path:
    script = tmp_path / "fake-editor.sh"
    script.write_text("#!/bin/sh\n" + body + "\n")
    script.chmod(0o755)
    monkeypatch.setenv("VISUAL", str(script))
    return script


def _run(tmp_path, monkeypatch, body, existing="original\n", sync=None):
    service = _make_memory_service(tmp_path / "mem")
    if existing:
        service.write_annotations(IID, existing, "custom")
    notes = service._store.get_annotations_path(IID, "custom")
    _editor(tmp_path, monkeypatch, body.replace("NOTES", str(notes)))
    rc = _cmd_annotate(_make_args(memory_command="annotate", instance=IID), _fake_config(),
                       service, _make_inst(), sync=sync)
    return rc, service, notes


def test_the_editor_gets_a_private_copy_not_the_notes_file(tmp_path, monkeypatch):
    record = tmp_path / "seen"
    rc, service, notes = _run(
        tmp_path, monkeypatch,
        f'echo "$1" > {record}; stat -c %a "$1" >> {record}; printf "edited\\n" > "$1"',
    )
    path, mode = record.read_text().split()
    assert Path(path) != notes and mode == "600"
    assert not Path(path).exists()          # the copy is removed afterwards
    assert rc == 0 and service.read_annotations(IID, "custom") == "edited\n"


def test_a_change_made_meanwhile_is_not_overwritten_and_the_edit_is_kept(tmp_path, monkeypatch, capsys):
    rc, service, notes = _run(
        tmp_path, monkeypatch, 'printf "other writer\\n" > NOTES; printf "my edit\\n" > "$1"'
    )
    assert rc != 0
    assert service.read_annotations(IID, "custom") == "other writer\n"
    drafts = list(notes.parent.glob("annotations.unsaved-*.md"))
    assert [d.read_text() for d in drafts] == ["my edit\n"]
    err = capsys.readouterr().err
    assert drafts[0].name in err and "/home/" not in err.replace(os.path.expanduser("~"), "~")


def test_the_sync_enqueue_happens_only_after_a_successful_write(tmp_path, monkeypatch):
    sync = MagicMock()
    sync.is_configured = True
    rc, service, _ = _run(tmp_path, monkeypatch, 'printf "other\\n" > NOTES; printf "mine\\n" > "$1"', sync=sync)
    assert rc != 0
    sync.enqueue_annotations.assert_not_called()
    sync2 = MagicMock()
    sync2.is_configured = True
    rc, service, _ = _run(tmp_path / "b", monkeypatch, 'printf "mine\\n" > "$1"', sync=sync2)
    assert rc == 0
    assert sync2.enqueue_annotations.call_args.args[1] == "mine\n"


def test_an_unchanged_edit_writes_nothing_and_succeeds(tmp_path, monkeypatch):
    rc, service, notes = _run(tmp_path, monkeypatch, "true")
    assert rc == 0 and service.read_annotations(IID, "custom") == "original\n"
    assert stat.S_IMODE(notes.stat().st_mode) == 0o600
