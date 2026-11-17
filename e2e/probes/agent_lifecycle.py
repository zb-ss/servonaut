"""Explicit subprocess probe for the agent-cleanup regression tests.

The filename deliberately avoids pytest's test_*.py collection pattern:
failure and interruption are inputs whose exit status the parent verifies.
"""

import json
import subprocess
import sys

import pytest

from e2e.harness.agent_cleanup import process_identity
from e2e.harness.sshd import find_openssh

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd]


@pytest.fixture(autouse=True)
def unclosed_agent(journey, sshd):
    # A crashed application cannot run PrivateSshAgent's atexit fallback.
    # The surrounding journey must collect its orphan independently.
    child = subprocess.run([sys.executable, "-c", """
import json, os
import servonaut.services.vault.ssh_agent as module
agent = module.PrivateSshAgent.start()
print(json.dumps({'pid': agent.pid, 'socket': str(agent.socket_path),
                  'implementation': module.__file__}), flush=True)
os._exit(17)
"""], capture_output=True, text=True, timeout=30, check=False)
    assert child.returncode == 17, child.stdout + child.stderr
    record = json.loads(child.stdout)
    executable = find_openssh()["ssh-agent"]
    print("AGENT_PROBE " + json.dumps({
        **record, "executable": executable,
        "started": process_identity(record["pid"], executable, record["socket"]),
        "root": str(journey.ctx.root),
    }), flush=True)
    # No application cleanup: teardown must own even an abandoned agent.


def test_success():
    pass


def test_failure():
    raise RuntimeError("exercise failed journey teardown")


def test_interrupt():
    raise KeyboardInterrupt("exercise interrupted journey teardown")
