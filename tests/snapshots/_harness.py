"""Deterministic state for the screenshot tests.

The tests run the real :class:`~servonaut.app.ServonautApp` with its real
stylesheets. Everything a screen could draw differently from one run to the
next is pinned here instead:

- the fleet is fixed neutral data (generic names, sequential ids, RFC 1918
  private addresses and well-known public resolver addresses only);
- configuration, the AWS instance cache and one server's memory are written
  through the application's own schema and store, into an empty home;
- the OVH and Hetzner compute services are replaced by stand-ins that list a
  fixed inventory and never call a provider;
- the wall clock is frozen by the fixtures in ``conftest.py``, so cache and
  memory ages always read the same;
- animations are off and text cursors do not blink.

This module has no ``test_`` prefix and is not collected.
"""

from __future__ import annotations

import asyncio
import copy
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from servonaut.app import ServonautApp
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig, CustomServer
from servonaut.services.cache_service import CacheService, timestamp_fields
from servonaut.services.memory.provider import instance_provider
from servonaut.services.memory.store import MemoryStore

# Every snapshot is taken at this instant (see the ``frozen_clock`` fixture).
FROZEN_NOW = datetime(2026, 3, 2, 9, 30, tzinfo=timezone.utc)

# The version the sidebar shows. Pinned so a release bump does not change
# every snapshot.
PINNED_VERSION = "0.0.0"

# Terminal sizes: a roomy desktop terminal and a narrow one.
SIZES: Dict[str, tuple[int, int]] = {"160x50": (160, 50), "100x30": (100, 30)}

# How long a scenario may wait for the app to reach the state it captures.
_WAIT_SECONDS = 20.0


# ---------------------------------------------------------------------------
# Fleet
# ---------------------------------------------------------------------------


def _aws_row(
    name: str,
    number: int,
    state: str,
    instance_type: str,
    region: str,
    private_ip: str,
    public_ip: Optional[str] = None,
) -> dict:
    """An EC2 instance as ``AWSService`` stores it in the instance cache."""
    return {
        "id": f"i-{number:017d}",
        "name": name,
        "type": instance_type,
        "state": state,
        "public_ip": public_ip,
        "private_ip": private_ip,
        "region": region,
        "key_name": "deploy-key",
    }


AWS_ROWS: List[dict] = [
    _aws_row("app-1", 1, "running", "t3.micro", "us-east-1", "10.0.1.21"),
    _aws_row("db-1", 2, "stopped", "t3.small", "eu-west-1", "10.0.2.31"),
    _aws_row("bastion-1", 3, "running", "t3.nano", "us-east-1", "10.0.0.10", "9.9.9.9"),
]

CUSTOM_SERVERS: List[CustomServer] = [
    CustomServer(
        name="web-1",
        host="10.0.0.11",
        username="deploy",
        ssh_key="~/.ssh/web1_ed25519",
        port=2222,
        provider="colo",
        group="web",
    ),
]

OVH_ROWS: List[dict] = [
    {
        "id": "vps-00000001.example.test",
        "name": "mail-1",
        "type": "vps-value-1-2-40",
        "state": "running",
        "public_ip": "9.9.9.10",
        "private_ip": "",
        "region": "os-gra7",
        "key_name": "",
        "provider": "OVH",
        "provider_type": "vps",
        "is_ovh": True,
        "ram_gb": 2,
    },
    {
        "id": "0e0e0000000000000000000000000001/batch-0001",
        "name": "batch-1",
        "type": "b3-8",
        "state": "stopped",
        "public_ip": "",
        "private_ip": "10.0.3.10",
        "region": "GRA7",
        "key_name": "",
        "provider": "OVH",
        "provider_type": "cloud",
        "is_ovh": True,
    },
]

HETZNER_ROWS: List[dict] = [
    {
        "id": "4200001",
        "name": "cache-1",
        "type": "cx23",
        "state": "running",
        "public_ip": "9.9.9.11",
        "private_ip": "",
        "region": "fsn1",
        "key_name": "",
        "provider": "hetzner",
        "is_hetzner": True,
        "username": "root",
        "ssh_key": "",
    },
]

# A second Hetzner project; its "cache-1" shares a name with the first one's.
HETZNER_ARCHIVE_ROWS: List[dict] = [
    {
        "id": "4200002",
        "name": "cache-1",
        "type": "cx23",
        "state": "running",
        "public_ip": "9.9.9.12",
        "private_ip": "",
        "region": "nbg1",
        "key_name": "",
        "provider": "hetzner",
        "is_hetzner": True,
        "username": "root",
        "ssh_key": "",
    },
    {
        "id": "4200003",
        "name": "worker-1",
        "type": "cx33",
        "state": "stopped",
        "public_ip": "",
        "private_ip": "10.0.4.10",
        "region": "nbg1",
        "key_name": "",
        "provider": "hetzner",
        "is_hetzner": True,
        "username": "root",
        "ssh_key": "",
    },
]

# The server whose memory is seeded, and the one the per-server screens open.
FOCUS_SERVER = AWS_ROWS[0]

# Fleet-table order: AWS cache, custom servers, OVH, Hetzner (see on_mount).
FLEET_NAMES: List[str] = (
    [row["name"] for row in AWS_ROWS]
    + [server.name for server in CUSTOM_SERVERS]
    + [row["name"] for row in OVH_ROWS]
    + [row["name"] for row in HETZNER_ROWS]
)

_MEMORY_MODULES: Dict[str, Dict[str, Any]] = {
    "os": {
        "id": "debian",
        "pretty_name": "Debian GNU/Linux 12 (bookworm)",
        "version_id": "12",
        "kernel": "6.1.0-18-amd64",
        "arch": "x86_64",
    },
    "runtimes": {"python": "Python 3.11.2", "node": "v20.11.1", "php": None},
    "services": {"enabled_units": ["cron.service", "nginx.service", "ssh.service"]},
    "web_stack": {"nginx": "1.22.1", "nginx_sites_enabled": ["default"]},
}


# ---------------------------------------------------------------------------
# CloudWatch
# ---------------------------------------------------------------------------

CLOUDWATCH_REGION = "us-east-1"
CLOUDWATCH_GROUP = "aws-waf-logs-web"

# (client address, WAF action, request path, how many requests). The widest
# IPv4 address a table can hold is included, so a snapshot shows whether the
# Top IPs columns still fit.
_WAF_REQUESTS = [
    ("149.112.112.112", "BLOCK", "/wp-login.php", 4),
    ("9.9.9.9", "ALLOW", "/", 3),
    ("9.9.9.9", "BLOCK", "/xmlrpc.php", 1),
    ("1.1.1.1", "BLOCK", "/.env", 2),
    ("8.8.8.8", "ALLOW", "/health", 2),
]


def cloudwatch_events() -> List[dict]:
    """WAF log events as ``CloudWatchService.get_log_events`` returns them."""
    events: List[dict] = []
    stamp = FROZEN_NOW.replace(tzinfo=None) - timedelta(minutes=30)
    for address, action, path, count in _WAF_REQUESTS:
        for _ in range(count):
            record = {
                "action": action,
                "httpRequest": {"clientIp": address, "uri": path, "httpMethod": "GET"},
            }
            events.append(
                {
                    "timestamp": stamp,
                    "log_stream": "waf-stream-1",
                    "message": json.dumps(record),
                }
            )
            stamp += timedelta(seconds=7)
    return events


# ---------------------------------------------------------------------------
# Seeding (writes through the application's own schema and stores)
# ---------------------------------------------------------------------------


def seed_home() -> None:
    """Write the config, the AWS instance cache and one server's memory.

    Must run inside the frozen clock: the cache is five minutes old and the
    memory two hours old, relative to :data:`FROZEN_NOW`.
    """
    config = AppConfig(custom_servers=copy.deepcopy(CUSTOM_SERVERS))
    ConfigManager().save(config)

    cache_path = CacheService.CACHE_PATH
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        **timestamp_fields(FROZEN_NOW - timedelta(minutes=5)),
        "instances": copy.deepcopy(AWS_ROWS),
    }
    cache_path.write_text(json.dumps(document, indent=2), encoding="utf-8")

    _seed_memory(FOCUS_SERVER, FROZEN_NOW - timedelta(hours=2))


def _seed_memory(host: dict, probed_at: datetime) -> None:
    """Store module snapshots for *host* exactly as a probe would."""
    store = MemoryStore()
    provider = instance_provider(host)
    stamp = probed_at.isoformat()
    for module, observed in _MEMORY_MODULES.items():
        store.save_module(
            host["id"],
            module,
            {
                "module": module,
                "instance_id": host["id"],
                "probed_at": stamp,
                "ttl_seconds": 86400,
                "sudo_used": False,
                "truncated": False,
                "partial": False,
                "observed": dict(observed),
                "declared": {},
                "raw_output": "",
            },
            provider,
        )
    store.update_index(host["id"], host["name"], provider, list(_MEMORY_MODULES))


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


class StaticProviderService:
    """Stand-in for the OVH or Hetzner compute service: a fixed inventory.

    Implements what the fleet table uses. The cache always counts as fresh,
    so the app never tries to refresh it.
    """

    last_fetch_error: Optional[str] = None
    last_fetch_partial = False

    def __init__(self, rows: List[dict]) -> None:
        self._rows = rows

    def get_cached_instances(self) -> List[dict]:
        return copy.deepcopy(self._rows)

    def is_cache_fresh(self) -> bool:
        return True

    async def fetch_instances_cached(self, force_refresh: bool = False) -> List[dict]:
        del force_refresh
        return copy.deepcopy(self._rows)


class SnapshotApp(ServonautApp):
    """The real app, with the provider compute services pinned and no animation."""

    def __init__(self, *, demo: bool = False) -> None:
        super().__init__()
        self.animation_level = "none"
        self.demo_mode = demo

    def _init_services(self) -> None:
        super()._init_services()
        self.ovh_service = StaticProviderService(OVH_ROWS)
        self.hetzner_service = StaticProviderService(HETZNER_ROWS)

    def provider_inventory(self, provider: str):
        # The fleet table reads every provider through its inventory; OVH and
        # Hetzner serve the pinned rows, AWS its (patched) real account.
        if provider == "ovh":
            return self.ovh_service
        if provider == "hetzner":
            return self.hetzner_service
        return super().provider_inventory(provider)

    def provider_available(self, provider: str) -> bool:
        # OVH and Hetzner are the pinned stand-ins, not registry accounts.
        if provider in ("ovh", "hetzner"):
            return getattr(self, f"{provider}_service", None) is not None
        return super().provider_available(provider)


class MultiAccountSnapshotApp(SnapshotApp):
    """The same fleet with a second Hetzner project ("archive")."""

    def _init_services(self) -> None:
        from servonaut.config.accounts import AccountRef
        from servonaut.services.accounts import AccountBinding, AccountFleet

        super()._init_services()
        self._hetzner_projects = AccountFleet("hetzner", [
            AccountBinding(AccountRef("hetzner", "hetzner", True), self.hetzner_service),
            AccountBinding(
                AccountRef("hetzner", "archive", False),
                StaticProviderService(HETZNER_ARCHIVE_ROWS),
            ),
        ])

    def provider_inventory(self, provider: str):
        if provider == "hetzner":
            return self._hetzner_projects
        return super().provider_inventory(provider)


MULTI_ACCOUNT_FLEET_SIZE = len(FLEET_NAMES) + len(HETZNER_ARCHIVE_ROWS)


# ---------------------------------------------------------------------------
# Driving
# ---------------------------------------------------------------------------


async def wait_until(pilot: Any, predicate: Callable[[], Any], desc: str) -> Any:
    """Poll *predicate* between frames until it is truthy; return its value."""
    deadline = asyncio.get_running_loop().time() + _WAIT_SECONDS
    while True:
        try:
            value = predicate()
        except Exception:  # noqa: BLE001 - the screen is still being built
            value = None
        if value:
            return value
        if asyncio.get_running_loop().time() > deadline:
            stack = [type(screen).__name__ for screen in pilot.app.screen_stack]
            raise AssertionError(f"timed out waiting for {desc} (screens: {stack})")
        await pilot.pause(0.02)


async def wait_for_screen(pilot: Any, name: str) -> Any:
    """Wait until the active screen is *name* and has mounted, then settle focus."""
    app = pilot.app
    await wait_until(
        pilot,
        lambda: type(app.screen).__name__ == name and app.screen.is_mounted,
        f"screen {name}",
    )
    await pilot.pause()
    await settle_focus(pilot)
    return app.screen


async def settle_focus(pilot: Any) -> None:
    """Move focus off a widget that can no longer take it.

    A screen focuses its first focusable widget as it opens. The sidebar's
    scroll container is focusable until the sidebar finishes mounting, so,
    depending on start-up timing, the screen can end up focused on it
    instead of on its own first control. That timing differs between
    Python versions, so the harness completes the move to the first control
    the screen offers.
    """
    app = pilot.app
    focused = app.focused
    if focused is None or focused.focusable:
        return
    chain = app.screen.focus_chain
    app.set_focus(chain[0] if chain else None)
    await pilot.pause()


async def wait_for_fleet(pilot: Any, rows: Optional[int] = None) -> None:
    """Wait until the fleet table lists every seeded server (or *rows* rows)."""
    from servonaut.widgets.instance_table import InstanceTable

    await wait_for_screen(pilot, "InstanceListScreen")
    table = pilot.app.screen.query_one(InstanceTable)
    expected = len(FLEET_NAMES) if rows is None else rows
    await wait_until(pilot, lambda: table.row_count == expected, "the fleet table")


async def select_fleet_row(pilot: Any, name: str) -> None:
    """Move the fleet table's cursor to the server named *name*."""
    from servonaut.widgets.instance_table import InstanceTable

    table = pilot.app.screen.query_one(InstanceTable)
    table.focus()
    table.move_cursor(row=FLEET_NAMES.index(name))
    await pilot.pause()


def freeze_cursors(app: Any) -> None:
    """Stop text cursors blinking, so a capture never lands mid-blink."""
    from textual.widgets import Input, TextArea

    for screen in app.screen_stack:
        for widget in screen.query("Input, TextArea"):
            if isinstance(widget, (Input, TextArea)):
                widget.cursor_blink = False
