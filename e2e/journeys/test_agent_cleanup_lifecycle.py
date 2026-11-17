"""Journey teardown owns agents abandoned by a crashed application."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from e2e.harness import agent_cleanup
from e2e.harness.bootstrap import REPO_ROOT, load_guard

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd]


@pytest.mark.parametrize("ending, status", [("success", 0), ("failure", 1), ("interrupt", 2)])
@pytest.mark.parametrize("keep", [False, True], ids=["removed", "kept"])
def test_vault_journey_teardown_stops_unclosed_agent(e2e_ctx, ending, status, keep):
    repo = REPO_ROOT
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(repo), str(repo / "src")]),
           "SERVONAUT_E2E_KEEP": str(int(keep))}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", f"e2e/probes/agent_lifecycle.py::test_{ending}", "-q", "-s"],
        cwd=repo, env=env, capture_output=True, text=True, timeout=90, check=False,
    )
    line = next((line for line in result.stdout.splitlines() if line.startswith("AGENT_PROBE ")), None)
    assert line is not None, result.stdout + result.stderr
    record = json.loads(line.removeprefix("AGENT_PROBE "))
    root = Path(record["root"])
    assert root != e2e_ctx.root
    assert root.parent == e2e_ctx.root.parent
    assert root.name.startswith("servonaut-e2e-")
    try:
        assert record["started"] is not None, result.stdout + result.stderr
        assert Path(record["implementation"]) == repo / "src/servonaut/services/vault/ssh_agent.py"
        assert result.returncode == status, result.stdout + result.stderr
        assert agent_cleanup.process_identity(record["pid"], record["executable"], record["socket"]) is None, (
            result.stdout + result.stderr
        )
        assert Path(record["root"]).exists() == keep
    finally:
        # The child explicitly reported this launch; never scan other runs.
        agent_cleanup._stop_record(record)
        # The nested run owns a separate default root outside this journey.
        with load_guard().suspended():
            shutil.rmtree(root, ignore_errors=True)
