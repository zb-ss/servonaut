"""`servonaut memory pull` pulls BOTH annotations and findings for an instance."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from servonaut.cli.memory import _cmd_pull_annotations

_INST = {"id": "web-1", "name": "web-1", "provider": "custom"}


def _sync(*, ann="updated", fnd="updated", configured=True):
    s = MagicMock()
    s.is_configured = configured
    s.pull_annotations = AsyncMock(return_value=ann)
    s.pull_findings = AsyncMock(return_value=fnd)
    return s


def test_pull_invokes_both_annotations_and_findings():
    sync = _sync()
    rc = _cmd_pull_annotations(MagicMock(), MagicMock(), MagicMock(), _INST, sync)
    assert rc == 0
    sync.pull_annotations.assert_awaited_once_with("web-1", "web-1", "custom")
    sync.pull_findings.assert_awaited_once_with("web-1", "web-1", "custom")


def test_pull_not_configured_skips_both():
    sync = _sync(configured=False)
    rc = _cmd_pull_annotations(MagicMock(), MagicMock(), MagicMock(), _INST, sync)
    assert rc != 0
    sync.pull_annotations.assert_not_awaited()
    sync.pull_findings.assert_not_awaited()


def test_pull_opt_out_on_either_surfaces_exit_code():
    sync = _sync(ann="updated", fnd="opt_out")
    rc = _cmd_pull_annotations(MagicMock(), MagicMock(), MagicMock(), _INST, sync)
    # opt_out / unavailable apply account-wide → non-success exit even if the
    # other surface updated.
    assert rc != 0
    sync.pull_findings.assert_awaited_once()
