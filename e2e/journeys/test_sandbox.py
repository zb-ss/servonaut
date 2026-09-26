"""The sandbox itself: allowlisted environment, guards, import-time paths.

If any of these fails, no journey result can be trusted.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from e2e.harness import canary
from e2e.harness.bootstrap import CHILD_SITE_DIR, SANDBOX_USER, is_within, load_guard
from e2e.harness.processes import require_armed

pytestmark = [pytest.mark.e2e_pr]

GUARD = load_guard()

# Variables that would connect a journey to the developer's real accounts,
# or route requests past the socket guard.
_MUST_BE_ABSENT = (
    "AWS_PROFILE",
    "SSH_AUTH_SOCK",
    "BW_SESSION",
    "BWS_ACCESS_TOKEN",
    "HCLOUD_TOKEN",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "GITHUB_TOKEN",
    "SERVONAUT_RELAY_TOKEN",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


def _run_child(journey, code: str, **env_changes: str) -> tuple[subprocess.CompletedProcess, int]:
    """Run *code* in a guarded Python child; return the result and its pid."""
    sandbox = journey.new_sandbox(f"probe-{uuid.uuid4().hex[:8]}")
    env = {**journey.child_env(sandbox), **env_changes}
    with subprocess.Popen(
        [sys.executable, "-c", code],
        env=env,
        cwd=sandbox.base,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as process:
        stdout, stderr = process.communicate(timeout=60)
    completed = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
    return completed, process.pid


def _take_child_records(journey) -> list[dict]:
    recorded = GUARD.read_log(journey.guard_log)
    journey.guard_log.unlink(missing_ok=True)
    return recorded


def test_environment_is_an_allowlist(e2e_ctx, journey):
    assert is_within(os.environ["HOME"], e2e_ctx.root)
    assert is_within(os.environ["TMPDIR"], e2e_ctx.root)
    assert os.environ["PATH"] == str(journey.shims.directory)
    assert os.environ["PYTHON_KEYRING_BACKEND"] == "keyring.backends.null.Keyring"
    assert os.environ["USER"] == os.environ["LOGNAME"] == SANDBOX_USER
    present = [name for name in _MUST_BE_ABSENT if name in os.environ]
    assert present == []


def test_no_real_terminal_ssh_or_agent_is_reachable(journey):
    from servonaut.services.terminal_service import TerminalService

    for name, _style in TerminalService.LINUX_TERMINALS:
        found = shutil.which(name)
        assert found is None or is_within(found, journey.shims.directory), name
    for tool in ("ssh", "scp", "ssh-add", "ssh-agent"):
        assert is_within(shutil.which(tool), journey.shims.directory), tool
    # Automatic detection can only ever find the fake terminal.
    assert TerminalService(preferred="auto").detect_terminal() == "xterm"


def test_network_guard_refuses_non_loopback_and_allows_loopback():
    with pytest.raises(OSError):
        socket.create_connection(("9.9.9.9", 443), timeout=1)
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo("example.com", 443)
    with pytest.raises(OSError):
        socket.gethostbyaddr("9.9.9.9")
    with pytest.raises(OSError):
        socket.getnameinfo(("1.1.1.1", 53), 0)
    for address in (f"/tmp/servonaut-e2e-{uuid.uuid4().hex}.sock", "\0e2e-abstract"):
        with socket.socket(socket.AF_UNIX) as unix, pytest.raises(OSError):
            unix.connect(address)
    recorded = GUARD.violations()
    GUARD.clear()
    assert [entry["kind"] for entry in recorded] == [
        "connect",
        "resolve",
        "reverse lookup",
        "reverse lookup",
        "connect",
        "connect",
    ]

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    with socket.create_connection(listener.getsockname(), timeout=1):
        pass
    listener.close()
    assert GUARD.violations() == []


def test_filesystem_guard_protects_real_home_and_outside_writes(e2e_ctx):
    if e2e_ctx.protected_dirs:
        protected = Path(e2e_ctx.protected_dirs[0]) / ".servonaut" / "config.json"
        with pytest.raises(PermissionError):
            protected.read_text()
    outside = Path("/tmp") / f"servonaut-e2e-guard-{uuid.uuid4().hex}"
    with pytest.raises(PermissionError):
        outside.write_text("must not be written")
    assert not outside.exists()
    kinds = {entry["kind"] for entry in GUARD.violations()}
    GUARD.clear()
    assert kinds == {"filesystem"}


def test_a_link_in_the_root_can_be_removed_but_not_written_through(journey):
    # The link is inside the test root; its target is outside both the root
    # and the checkout, so a guard regression could only create a stray file.
    target = Path(os.path.realpath(Path("/tmp") / f"servonaut-e2e-link-{uuid.uuid4().hex}"))
    link = journey.directory / "outside-link"
    link.symlink_to(target)
    with pytest.raises(PermissionError):
        link.write_text("must not be written")
    assert not target.exists()
    link.unlink()
    assert not link.is_symlink()
    recorded = GUARD.violations()
    GUARD.clear()
    assert [entry["target"] for entry in recorded] == [f"open {target}"]


def test_program_starts_are_limited_to_the_fake_tools():
    with pytest.raises(PermissionError):
        subprocess.run(["/usr/bin/env"], check=False)
    with pytest.raises(PermissionError):
        os.system("true")
    recorded = GUARD.violations()
    GUARD.clear()
    assert [entry["kind"] for entry in recorded] == ["spawn", "spawn"]
    # The fake tools themselves may run.
    assert subprocess.run(["ssh-add", "-l"], check=False, capture_output=True).returncode == 2


def test_child_processes_are_guarded_and_report_armed(journey):
    probe = (
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('8.8.8.8', 53), timeout=1)\n"
        "except OSError as exc:\n"
        "    print(type(exc).__name__)\n"
    )
    completed, pid = _run_child(journey, probe)
    assert completed.stdout.strip() == "NetworkEscapeError", completed.stderr
    require_armed(journey.armed_log, pid=pid)
    assert [entry["target"] for entry in _take_child_records(journey)] == ["8.8.8.8:53"]


def test_http_clients_in_children_are_caught(journey):
    probe = (
        "import httpx, urllib.request\n"
        "for fetch in (lambda: httpx.get('https://pypi.org/simple/servonaut/', timeout=5),\n"
        "              lambda: urllib.request.urlopen('https://pypi.org/pypi/servonaut/json',\n"
        "                                             timeout=5)):\n"
        "    try:\n"
        "        fetch()\n"
        "        print('reached')\n"
        "    except Exception as exc:\n"
        "        print('refused')\n"
    )
    completed, _pid = _run_child(journey, probe)
    assert completed.stdout.split() == ["refused", "refused"], completed.stderr
    recorded = _take_child_records(journey)
    assert [(entry["kind"], entry["target"]) for entry in recorded] == [
        ("resolve", "pypi.org"),
        ("resolve", "pypi.org"),
    ]


def test_children_cannot_start_other_programs(journey):
    probe = (
        "import subprocess\n"
        "try:\n"
        "    subprocess.run(['/usr/bin/env'], check=False)\n"
        "except PermissionError:\n"
        "    print('refused')\n"
    )
    completed, _pid = _run_child(journey, probe)
    assert completed.stdout.strip() == "refused", completed.stderr
    assert [entry["kind"] for entry in _take_child_records(journey)] == ["spawn"]


def test_a_child_whose_guard_cannot_load_stops(journey):
    # A copy of the child hook that cannot find the guard next to it.
    broken_site = journey.directory / "broken" / "site"
    broken_site.mkdir(parents=True)
    shutil.copyfile(CHILD_SITE_DIR / "sitecustomize.py", broken_site / "sitecustomize.py")
    completed, pid = _run_child(journey, "print('ran unguarded')", PYTHONPATH=str(broken_site))
    assert completed.returncode == 70
    assert "ran unguarded" not in completed.stdout
    assert "could not be installed" in completed.stderr
    with pytest.raises(AssertionError):
        require_armed(journey.armed_log, pid=pid)


def test_every_import_time_path_is_inside_the_test_root(e2e_ctx):
    canary.import_all_modules()
    assert canary.import_time_path_problems(e2e_ctx) == []
    assert canary.critical_path_problems(e2e_ctx) == []
    # Importing Servonaut must not touch the network, the real home or
    # start any program.
    assert GUARD.violations() == []


def test_artifact_scrub_masks_credentials_and_keeps_json_valid():
    import json

    from e2e.harness.artifacts import scrub

    line = json.dumps({
        "authorization": None, "token": 12345, "access_token": "fake-access",
        "url": "https://api.example.com/x?code=fake-device-code", "ok": True,
    })
    scrubbed = scrub(line)

    parsed = json.loads(scrubbed)
    assert parsed["authorization"] is None
    assert parsed["token"] == parsed["access_token"] == "<redacted>"
    assert "fake-device-code" not in scrubbed and "fake-access" not in scrubbed


def test_children_see_module_constants_redirected_to_the_fakes(journey, fake_cloud):
    code = "import servonaut.services.update_service as u\nprint(u.PYPI_URL)\n"
    completed, _pid = _run_child(journey, code)
    assert completed.stdout.strip() == fake_cloud.pypi_json_url, completed.stderr


def test_a_redirect_to_a_missing_constant_stops_the_child(journey):
    redirects = {"servonaut.services.update_service": {"NO_SUCH_URL": "https://127.0.0.1:9"}}
    completed, _pid = _run_child(
        journey,
        "import servonaut.services.update_service\nprint('imported')\n",
        SERVONAUT_E2E_REDIRECTS=json.dumps(redirects),
    )
    assert completed.returncode == 70
    assert "imported" not in completed.stdout
    assert "does not exist" in completed.stderr

