"""Shared steps of the packaged journeys: install, the user's home, the TUI.

:func:`seed` has an *installed* release write the home (see
``e2e/harness/release_scripts/seed_home.py``), so an upgrade journey starts
from files in exactly the format that release saves. Everything comes from
the neutral inventory in ``e2e/harness/fleet.py``.
"""

from __future__ import annotations

import json
import re
import stat
from pathlib import Path
from typing import Any

from e2e.harness import fleet
from e2e.harness.bootstrap import HARNESS_DIR, Sandbox
from e2e.harness.installs import Installs, VenvInstall
from e2e.harness.processes import CliResult, require_armed
from e2e.harness.shims import TERMINAL
from e2e.harness.terminal import TerminalRun, run_in_terminal

SEED_SCRIPT = HARNESS_DIR / "release_scripts" / "seed_home.py"
# The files an upgrade must carry over, relative to ~/.servonaut.
USER_FILES = ("config.json", "cache.json", "keywords.json", "command_history.json")
# An API key given as an environment reference, the form the settings accept.
AI_KEY_REFERENCE = "$E2E_PROVIDER_KEY"
SAVED_COMMAND = ("disk", "df -h")
HISTORY = ("uptime", "df -h")


def ok(result: CliResult) -> CliResult:
    assert result.returncode == 0, result.describe()
    return result


def pip_install_current(
    journey: Any, installs: Installs, wheel: Path, version: str
) -> tuple[Sandbox, VenvInstall]:
    """A fresh home and ``pip install servonaut`` (the checkout's wheel) into a new venv."""
    sandbox = journey.new_sandbox()
    installs.offer(wheel, version=version)
    venv = installs.venv(sandbox)
    ok(venv.pip(sandbox, "install", "servonaut"))
    return sandbox, venv


def reported_version(install: Any, sandbox: Sandbox) -> str:
    """What ``servonaut --version`` says, as the bare version."""
    output = ok(install.run(sandbox, "--version")).stdout.strip()
    assert output.startswith("servonaut "), output
    return output[len("servonaut "):]


def spec(api_url: str) -> dict[str, Any]:
    """What the user has configured and collected.

    The relay points at *api_url* the way the app derives it on its own, so a
    first launch has no reason to rewrite the config.
    """
    from servonaut.services.relay_manager import derive_relay_urls

    base_url, mercure_url = derive_relay_urls(api_url)
    web = fleet.WEB_1
    return {
        "settings": {"default_username": "ops", "terminal_emulator": TERMINAL},
        "sections": {
            "ai_provider": {"provider": "anthropic", "api_key": AI_KEY_REFERENCE},
            "relay": {"base_url": base_url, "mercure_url": mercure_url},
        },
        "custom_servers": [
            {
                "name": web.name,
                "host": web.host,
                "username": web.username,
                "port": web.port,
                "ssh_key": web.ssh_key,
                "provider": web.provider,
                "group": web.group,
                "tags": {"role": "web"},
            }
        ],
        "connection_profiles": [
            {
                "name": fleet.BASTION_PROFILE,
                "bastion_host": fleet.BASTION_1.public_ip,
                "bastion_user": fleet.BASTION_USER,
                "username": fleet.BASTION_USER,
            }
        ],
        "fleet": fleet.cache_rows(),
        "scan_results": {
            fleet.APP_1.instance_id: [
                {
                    "source": "command:uptime",
                    "content": "up 3 days",
                    "timestamp": "2026-01-01T00:00:00",
                }
            ]
        },
        "history": [[fleet.APP_1.instance_id, command] for command in HISTORY],
        "saved_commands": [list(SAVED_COMMAND)],
    }


def seed(installs: Installs, sandbox: Sandbox, python: Path, **changes: Any) -> dict[str, Any]:
    """Have the release installed at *python* write the home; return its summary."""
    data = spec(installs.fake_cloud.url)
    data["settings"].update(changes)
    spec_path = sandbox.base / "seed-spec.json"
    spec_path.write_text(json.dumps(data), encoding="utf-8")
    result = installs.runner().run(sandbox, [str(python), str(SEED_SCRIPT), str(spec_path)])
    assert result.returncode == 0, result.describe()
    return json.loads(result.stdout.strip().splitlines()[-1])


def data_dir(sandbox: Sandbox) -> Path:
    return sandbox.home / ".servonaut"


def backups_dir(sandbox: Sandbox) -> Path:
    return data_dir(sandbox) / "backups"


def config_backups(sandbox: Sandbox) -> list[Path]:
    """Every config backup in the home, including any left beside the config."""
    found = [*data_dir(sandbox).glob("config*.bak*"), *backups_dir(sandbox).glob("*.json")]
    return sorted(path for path in found if path.is_file())


# A row of ``servonaut --list-backups``: number, time, size, kind, path.
_LISTED_ROW = re.compile(
    r"^\s*(\d+)\s+\S+ \S+\s+\S+ K?B\s+(on save|pre-upgrade(?: v\d+)?)\s+(\S+)$",
    re.MULTILINE,
)


def listed_backups(install: Any, sandbox: Sandbox) -> list[tuple[str, Path]]:
    """What ``servonaut --list-backups`` shows, newest first: (kind, path)."""
    listing = ok(install.run(sandbox, "--list-backups")).stdout
    rows = _LISTED_ROW.findall(listing)
    assert [int(number) for number, _, _ in rows] == list(range(1, len(rows) + 1)), listing
    return [(kind, Path(path)) for _, kind, path in rows]


def backup_of(sandbox: Sandbox, content: bytes) -> Path:
    """The one backup that holds *content*."""
    matches = [path for path in config_backups(sandbox) if path.read_bytes() == content]
    assert len(matches) == 1, config_backups(sandbox)
    return matches[0]


def is_private(path: Path) -> bool:
    """Only the owner may read or write *path* (it can hold credentials)."""
    return stat.S_IMODE(path.stat().st_mode) == 0o600


def snapshot(sandbox: Sandbox) -> dict[str, bytes]:
    """The user's files, byte for byte."""
    return {name: (data_dir(sandbox) / name).read_bytes() for name in USER_FILES}


def read_config(sandbox: Sandbox) -> dict[str, Any]:
    return json.loads((data_dir(sandbox) / "config.json").read_text(encoding="utf-8"))


def changed_values(old: Any, new: Any, path: str = "") -> list[str]:
    """Every value of *old* that *new* no longer holds, as dotted paths.

    Keys *new* adds are fine; keys it drops or values it changes are listed.
    """
    if isinstance(old, dict) and isinstance(new, dict):
        out = []
        for key, value in old.items():
            where = f"{path}.{key}" if path else key
            if key not in new:
                out.append(f"{where} (removed)")
            else:
                out.extend(changed_values(value, new[key], where))
        return out
    if isinstance(old, list) and isinstance(new, list) and len(old) == len(new):
        out = []
        for index, (before, after) in enumerate(zip(old, new)):
            out.extend(changed_values(before, after, f"{path}[{index}]"))
        return out
    return [] if old == new else [path]


def boot_tui(installs: Installs, sandbox: Sandbox, console: Path, names: list[str]) -> TerminalRun:
    """Launch the installed TUI, wait until every name in *names* is on screen, quit."""
    run = run_in_terminal(
        [str(console)],
        env=installs.env(sandbox),
        cwd=sandbox.base,
        until=lambda text: all(name in text for name in names),
        description=f"{', '.join(names)} in the installed TUI",
    )
    assert run.returncode == 0, run.text[-2000:]
    require_armed(installs.armed_log, pid=run.pid)
    return run


def fleet_names() -> list[str]:
    """What the fleet table shows for the seeded home: AWS hosts and web-1."""
    return [host.name for host in fleet.AWS_FLEET] + [fleet.WEB_1.name]
