"""Journey: demo mode keeps every real identifier off the screen.

Demo mode exists so the TUI can be recorded, screenshotted or shared. With
servers from AWS, custom hosts, Hetzner Cloud and OVHcloud loaded, a tour of
every sidebar destination (with the OVH DNS records), every Settings panel,
the actions screen of each kind of server and the help screen must never show
a real server name, instance id, IP address, hostname, DNS name or SSH key
name, neither on screen (including table cells too wide to draw in full, and
form fields) nor in a notification. That holds whether demo mode is on from
launch (``--demo``) or switched on with ctrl+shift+d, and switching it off
again brings the real data back. The same tour with demo mode off must find
those identifiers, so a clean tour means hidden, not missing.
"""

from __future__ import annotations

import re
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Iterable

import pytest
from textual.widget import Widget
from textual.widgets import Button, DataTable, Input

from e2e.harness import fleet
from e2e.harness.fake_providers.ovh import NIC_HANDLE
from e2e.harness.known_bugs import ProductBug, known_bug
from e2e.harness.pilot import TuiDriver

# Each tour visits dozens of screens; the limit leaves room on a busy runner.
pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio, pytest.mark.timeout(180)]

# Wide enough that most table columns draw in full; cells are checked in
# full anyway.
DEMO_SIZE = (200, 60)

# A custom server added by host name rather than address.
FILES_1 = fleet.CustomHost(
    name="files-1", host="files-1.e2e.test", username="deploy", port=22, ssh_key="~/.ssh/e2e_files1"
)
# OVH account data the provider screens list.
DNS_ZONE = "e2e-zone.test"
DNS_SUB_DOMAIN = "e2e-portal"
DNS_CNAME_TARGET = "e2e-origin.e2e.test"
REVERSE_HOST = "mx-e2e.e2e.test"
OVH_ACCOUNT_KEY = "e2e-workstation"
OVH_PROJECT_KEY = "e2e-deploy-key"
OVH_VOLUME = "e2e-data-vol"
OVH_VPS_SNAPSHOT = "e2e-snap-mail"
OVH_CLOUD_SNAPSHOT = "e2e-image-batch"
DEFAULT_KEY = "~/.ssh/e2e_default"
APP_1_KEY = "~/.ssh/e2e_app1"
HETZNER_KEY_NAME = "e2e-laptop"

# Every screen the sidebar reaches for a signed-out user with both providers
# configured, and the screen it opens.
SIDEBAR_TOUR = {
    "nav_list": "InstanceListScreen",
    "nav_custom_servers": "CustomServersScreen",
    "nav_keys": "KeyManagementScreen",
    "nav_memory": "FleetMemoryScreen",
    "nav_memory_sync": "MemorySyncSetupScreen",
    "nav_secrets": "SecretsScreen",
    "nav_bw_vault": "BwVaultManagerScreen",
    "nav_findings": "FindingsScreen",
    "nav_settings": "SettingsScreen",
    "nav_aws_manage": "AWSManagerScreen",
    "nav_aws_s3": "ObjectStorageScreen",
    "nav_cloudwatch": "CloudWatchBrowserScreen",
    "nav_ip_ban": "IPBanScreen",
    "nav_cloudtrail": "CloudTrailBrowserScreen",
    "nav_ovh_manage": "OVHManagerScreen",
    "nav_ovh_dns": "OVHDNSScreen",
    "nav_ovh_ips": "OVHIPManagementScreen",
    "nav_ovh_storage": "OVHStorageScreen",
    "nav_ovh_billing": "OVHBillingScreen",
    "nav_ovh_ssh_keys": "OVHSSHKeysScreen",
    "nav_hetzner_manage": "HetznerManagerScreen",
    "nav_hetzner_ssh_keys": "HetznerSSHKeysScreen",
    "nav_login": "LoginScreen",
    "nav_bug_report": "BugReportConsentModal",
}
# Rows in the fleet: 4 AWS, 2 custom, 2 Hetzner, 5 OVH.
FLEET_SIZE = 13
# Names shown when demo mode is off, one per kind of server.
REAL_NAMES = ("app-1", "web-1", "files-1", "cache-1", "mail-1", "batch-1", "storage-1.e2e.test")


class DemoModeLeak(ProductBug):
    """A real identifier was visible while demo mode was on."""


# ---------------------------------------------------------------------------
# What must stay hidden
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Secret:
    label: str
    value: str
    pattern: re.Pattern[str]


def _is_ip(value: str) -> bool:
    return re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value) is not None


def _secret(label: str, value: str) -> Secret:
    escaped = re.escape(value)
    if _is_ip(value):
        pattern = rf"(?<![\d.]){escaped}(?!\.?\d)"
    else:
        # A whole token: not part of a longer name, and not the start of one
        # of demo mode's own fake host names (``cache-1.example.com``).
        pattern = rf"(?<![\w.-]){escaped}(?![\w-])(?!\.example\.com)"
    return Secret(label, value, re.compile(pattern))


def _secrets(moto_ids: dict[str, str]) -> list[Secret]:
    values: list[tuple[str, str]] = []
    for host in fleet.AWS_FLEET:
        values += [
            (f"{host.name} name", host.name),
            (f"{host.name} cached id", host.instance_id),
            (f"{host.name} id", moto_ids[host.name]),
            (f"{host.name} private ip", host.private_ip or ""),
            (f"{host.name} public ip", host.public_ip or ""),
        ]
    values.append(("AWS key pair", fleet.APP_1.key_name))
    for custom in (fleet.WEB_1, FILES_1):
        values += [
            (f"{custom.name} name", custom.name),
            (f"{custom.name} id", f"custom-{custom.name}"),
            (f"{custom.name} host", custom.host),
            (f"{custom.name} key", custom.ssh_key.rsplit("/", 1)[-1]),
        ]
    for server in fleet.HETZNER_FLEET:
        values += [
            (f"{server.name} name", server.name),
            (f"{server.name} id", str(server.server_id)),
            (f"{server.name} ip", server.public_ip or ""),
        ]
    for vps in fleet.OVH_VPS_FLEET:
        values += [
            (f"{vps.display_name} name", vps.display_name),
            (f"{vps.display_name} service", vps.service_name),
            *((f"{vps.display_name} ip", ip) for ip in vps.ips),
        ]
    for dedicated in fleet.OVH_DEDICATED_FLEET:
        values += [
            (f"{dedicated.reverse} service", dedicated.service_name),
            (f"{dedicated.reverse} name", dedicated.reverse),
            *((f"{dedicated.reverse} ip", ip) for ip in dedicated.ips),
        ]
    for cloud in fleet.OVH_CLOUD_FLEET:
        values += [
            (f"{cloud.name} name", cloud.name),
            (f"{cloud.name} id", cloud.instance_id),
            (f"{cloud.name} id prefix", cloud.instance_id[:13]),
            (f"{cloud.name} public ip", cloud.public_ip or ""),
            (f"{cloud.name} private ip", cloud.private_ip or ""),
        ]
    values += [
        ("OVH project id", fleet.OVH_PROJECT_ID),
        ("OVH account handle", NIC_HANDLE),
        ("default key", DEFAULT_KEY.rsplit("/", 1)[-1]),
        ("per-instance key", APP_1_KEY.rsplit("/", 1)[-1]),
        ("Hetzner project key", HETZNER_KEY_NAME),
        ("DNS zone", DNS_ZONE),
        ("DNS sub-domain", DNS_SUB_DOMAIN),
        ("DNS target", DNS_CNAME_TARGET),
        ("reverse DNS", REVERSE_HOST),
        ("OVH account key", OVH_ACCOUNT_KEY),
        ("OVH project key", OVH_PROJECT_KEY),
        ("OVH volume", OVH_VOLUME),
        ("OVH VPS snapshot", OVH_VPS_SNAPSHOT),
        ("OVH cloud snapshot", OVH_CLOUD_SNAPSHOT),
    ]
    # Provider credentials: never shown in clear, demo mode or not.
    config = SeederConfig
    values += [
        ("Hetzner token", config.hetzner_token),
        ("OVH application secret", config.ovh_application_secret),
        ("OVH consumer key", config.ovh_consumer_key),
    ]
    return [_secret(label, value) for label, value in values if value]


class SeederConfig:
    """Credential values ``HomeSeeder`` writes (see e2e/harness/seed.py)."""

    hetzner_token = "hz-fake-token"
    ovh_application_secret = "as-fake"
    ovh_consumer_key = "ck-fake"


@dataclass(frozen=True)
class Leak:
    label: str
    where: str
    detail: str

    def __str__(self) -> str:
        return f"{self.label} in {self.where}: {self.detail}"


def _find_leaks(secrets: Iterable[Secret], texts: dict[str, str]) -> list[Leak]:
    leaks = []
    for where, text in texts.items():
        for secret in secrets:
            match = secret.pattern.search(text)
            if match:
                start = max(match.start() - 30, 0)
                context = text[start:match.end() + 30].replace("\n", " ")
                leaks.append(Leak(secret.label, where, f"...{context.strip()}..."))
    return leaks


# ---------------------------------------------------------------------------
# What the user can see
# ---------------------------------------------------------------------------


def _cell_text(cell: Any) -> str:
    return getattr(cell, "plain", None) or str(cell)


def _visible_texts(t: TuiDriver, where: str) -> dict[str, str]:
    """The drawn screen, every table cell and form field, and every notification."""
    screen = t.app.screen
    texts = {f"{where} (screen)": t.rendered_text()}
    cells = []
    for table in screen.query(DataTable):
        if not t.is_reachable(table):
            continue
        for column in table.columns.values():
            cells.append(_cell_text(column.label))
        for row_key in table.rows:
            cells.extend(_cell_text(cell) for cell in table.get_row(row_key))
    texts[f"{where} (table cells)"] = "\n".join(cells)
    # A masked field shows dots; its value is not on screen.
    texts[f"{where} (form fields)"] = "\n".join(
        field.value
        for field in screen.query(Input)
        if t.is_reachable(field) and not field.password
    )
    # The driver records every notification; titles are not in toasts().
    texts["notifications"] = "\n".join(
        f"{n.title}: {n.message}" for n in t._notifications  # noqa: SLF001 - own harness
    )
    return texts


def _screen_workers_done(t: TuiDriver) -> bool:
    """True when no worker started by the active screen is still running."""
    screen = t.app.screen

    def owned(node: Any) -> bool:
        if node is screen:
            return True
        try:
            return isinstance(node, Widget) and node.screen is screen
        except Exception:  # noqa: BLE001 - a detached widget belongs to no screen
            return False

    return all(worker.is_finished for worker in t.app.workers if owned(worker.node))


class Tour:
    """Visits screens and collects every leak instead of stopping at the first."""

    def __init__(self, t: TuiDriver, secrets: list[Secret]) -> None:
        self.t = t
        self.secrets = secrets
        self.leaks: list[Leak] = []
        self.visited: list[str] = []

    async def check(self, where: str) -> None:
        await self.t.wait_until(
            lambda: _screen_workers_done(self.t), timeout=10, desc=f"{where} to finish loading"
        )
        await self.t.settle()
        self.visited.append(where)
        for leak in _find_leaks(self.secrets, _visible_texts(self.t, where)):
            if leak not in self.leaks:
                self.leaks.append(leak)

    def assert_clean(self, *, except_known: Iterable[tuple[str, str]] = ()) -> None:
        """Fail on any leak other than the known ones, given as (label, screen)."""
        known = set(except_known)
        new = [
            leak for leak in self.leaks
            if not any(leak.label == label and leak.where.startswith(where) for label, where in known)
        ]
        if new:
            raise DemoModeLeak(
                f"{len(new)} real identifier(s) visible in demo mode:\n  "
                + "\n  ".join(map(str, new))
            )


# ---------------------------------------------------------------------------
# The world and the tour
# ---------------------------------------------------------------------------


def _seed_world(seed: Any, moto: Any, providers: Any) -> list[Secret]:
    from servonaut.config.schema import CustomServer

    customs = [
        CustomServer(
            name=host.name, host=host.host, username=host.username,
            port=host.port, ssh_key=host.ssh_key,
        )
        for host in (fleet.WEB_1, FILES_1)
    ]
    seed.config(
        hetzner=seed.hetzner_config(),
        ovh=seed.ovh_config(),
        custom_servers=customs,
        default_key=DEFAULT_KEY,
        instance_keys={fleet.APP_1.instance_id: APP_1_KEY},
    )
    # A stale cache: the fleet shows at once and every provider refreshes,
    # so provider rows arrive after start-up, as they do for a user.
    seed.cache(fleet.cache_rows(), fresh=False)
    moto_ids = moto.seed_fleet(fleet.AWS_FLEET)
    fleet.seed_provider_fleet(providers)
    providers.hetzner.seed_ssh_key(HETZNER_KEY_NAME, "ssh-ed25519 AAAAC3NzaE2E e2e-laptop")
    _seed_ovh_account(providers.ovh)
    return _secrets(moto_ids)


def _seed_ovh_account(ovh: Any) -> None:
    """DNS, IPs, firewall, keys, storage and snapshots for the OVH screens."""
    from e2e.harness.fake_providers.ovh import SeedDnsRecord, SeedFirewallRule

    mail = fleet.OVH_VPS_MAIL_1
    mail_ip = mail.ips[0]
    ovh.seed_dns_zone(DNS_ZONE, [
        SeedDnsRecord("A", DNS_SUB_DOMAIN, mail_ip),
        SeedDnsRecord("CNAME", "www", f"{DNS_CNAME_TARGET}."),
    ])
    ovh.seed_ip_block(
        f"{mail_ip}/32", routed_to=mail.service_name, reverse={mail_ip: f"{REVERSE_HOST}."}
    )
    ovh.seed_firewall(mail_ip, rules=[
        SeedFirewallRule(0, "permit", "tcp", port="22", source=f"{fleet.HZ_CACHE_1.public_ip}/32"),
    ])
    ovh.seed_account_ssh_key(OVH_ACCOUNT_KEY, "ssh-ed25519 AAAAC3NzaE2E workstation")
    ovh.seed_project_ssh_key(fleet.OVH_PROJECT_ID, OVH_PROJECT_KEY, "ssh-ed25519 AAAAC3NzaE2E deploy")
    ovh.seed_volume(
        fleet.OVH_PROJECT_ID, OVH_VOLUME, 50, attached_to=[fleet.OVH_BATCH_1.instance_id]
    )
    ovh.seed_vps_snapshot(mail.service_name, OVH_VPS_SNAPSHOT)
    ovh.seed_cloud_snapshot(fleet.OVH_PROJECT_ID, OVH_CLOUD_SNAPSHOT)


async def _wait_for_fleet(t: TuiDriver) -> None:
    await t.wait_for_toast(r"Hetzner refreshed: 2 instances")
    await t.wait_for_toast(r"OVH refreshed: 5 instances")
    await t.wait_for_toast(r"Refreshed: 4 instances")
    await t.wait_until(
        lambda: len(t.table_rows("InstanceTable")) == FLEET_SIZE, desc="the whole fleet"
    )


# Every kind of server the fleet table can hold; each has its own actions screen.
SERVER_KINDS = {
    "aws", "custom-ip", "custom-hostname", "hetzner", "ovh-vps", "ovh-dedicated", "ovh-cloud",
}


def _kind(instance: dict) -> str:
    if instance.get("is_custom"):
        # A custom server's host is carried in its address fields.
        host = str(instance.get("public_ip") or "")
        return "custom-hostname" if re.search(r"[a-z]", host) else "custom-ip"
    if instance.get("is_hetzner"):
        return "hetzner"
    if instance.get("is_ovh"):
        return f"ovh-{instance.get('provider_type')}"
    return "aws"


async def _tour_server_actions(tour: Tour) -> None:
    """Open the actions screen of one server of every kind in the fleet table."""
    t = tour.t
    await t.nav("nav_list")
    await t.wait_for_screen("InstanceListScreen")
    seen: set[str] = set()
    for index in range(FLEET_SIZE):
        table = await t.focus_instance_table()
        await t.wait_until(lambda: table.row_count == FLEET_SIZE, desc="fleet rows")
        while table.cursor_row != index:
            await t.press("down" if table.cursor_row < index else "up")
        kind = _kind(table.get_selected_instance())
        if kind in seen:
            continue
        seen.add(kind)
        await t.press("enter")
        await t.wait_for_screen("ServerActionsScreen")
        await tour.check(f"server actions ({kind})")
        await t.press("escape")
        await t.wait_for_screen("InstanceListScreen")
    assert seen == SERVER_KINDS, seen


async def _tour_settings(tour: Tour, only: Iterable[str] = ()) -> None:
    """Open every Settings panel (or just the panels in *only*)."""
    from servonaut.widgets.sidebar_section import SidebarSection

    t = tour.t
    await t.nav("nav_settings")
    await t.wait_for_screen("SettingsScreen")
    panels = [
        button.id for button in t.app.screen.query(Button)
        if (button.id or "").startswith("navbtn_") and button.display
    ]
    assert len(panels) > 10, panels
    wanted = {f"navbtn_{panel}" for panel in only}
    for panel in panels:
        if wanted and panel not in wanted:
            continue
        button = t.on_screen(f"#{panel}", Button)
        section = next(node for node in button.ancestors if isinstance(node, SidebarSection))
        if section.collapsed:
            await t.click(section.query_one("Button.section-header", Button))
            await t.wait_until(lambda: not section.collapsed, desc=f"section of {panel}")
        await t.click(button)
        await t.wait_until(
            lambda: t.on_screen(f"#{panel}").has_class("--active"), desc=f"{panel} shown"
        )
        await tour.check(f"settings {panel[len('navbtn_'):]}")


async def _open_first_dns_zone(tour: Tour) -> None:
    """Choose the zone on the DNS screen, so its records are listed too."""
    t = tour.t
    zones = t.on_screen("#domains_table", DataTable)
    await t.wait_until(lambda: zones.row_count == 1, desc="the DNS zone listed")
    await t.click(zones)
    await t.wait_until(lambda: zones.has_focus, desc="zone table focus")
    await t.press("enter")
    records = t.on_screen("#records_table", DataTable)
    await t.wait_until(lambda: records.row_count == 2, desc="the zone's records")
    await tour.check("OVH DNS records")


async def _tour_sidebar(tour: Tour) -> None:
    t = tour.t
    await tour.check("fleet table")
    for nav_id, screen_name in SIDEBAR_TOUR.items():
        await t.nav(nav_id)
        await t.wait_for_screen(screen_name)
        await tour.check(screen_name)
        if screen_name == "OVHDNSScreen":
            await _open_first_dns_zone(tour)
        if screen_name == "BugReportConsentModal":
            await t.press("escape")
            await t.wait_until(
                lambda: "BugReportScreen" not in t.stack_names(), desc="bug report closed"
            )
    await t.nav("nav_list")
    await t.wait_for_screen("InstanceListScreen")
    await t.focus_instance_table()
    await t.press("question_mark")
    await t.wait_for_screen("HelpScreen")
    await tour.check("help")
    await t.press("escape")
    await t.wait_for_screen("InstanceListScreen")


@asynccontextmanager
async def _demo_session(tui: Any, seed: Any, moto: Any, providers: Any, monkeypatch: Any):
    """The app started as ``servonaut --demo`` would, with the whole fleet loaded."""
    from servonaut.app import ServonautApp

    secrets = _seed_world(seed, moto, providers)
    # What `--demo` sets before the app starts.
    monkeypatch.setattr(ServonautApp, "demo_mode", True)
    async with tui(size=DEMO_SIZE) as t:
        await _wait_for_fleet(t)
        assert "DEMO" in t.rendered_text()
        yield Tour(t, secrets)


# Leaks this suite knows about; each has its own known-bug journey below.
# Listed as (secret label, where) so any other leak still fails the tours.
KNOWN_SETTINGS_LEAKS = (
    ("default key", "settings general"),
    # Settings opens on its General panel.
    ("default key", "SettingsScreen"),
    ("OVH project id", "settings ovh"),
)
KNOWN_DNS_LEAKS = (("DNS sub-domain", "OVH DNS records"),)
KNOWN_LEAKS = KNOWN_SETTINGS_LEAKS + KNOWN_DNS_LEAKS


def _only(leaks: list[Leak], known: Iterable[tuple[str, str]]) -> list[Leak]:
    known = tuple(known)
    return [
        leak for leak in leaks
        if any(leak.label == label and leak.where.startswith(where) for label, where in known)
    ]


# ---------------------------------------------------------------------------
# Journeys
# ---------------------------------------------------------------------------


async def test_demo_flag_sidebar_tour_shows_no_real_identifier(
    tui, seed, moto, providers, monkeypatch
):
    async with _demo_session(tui, seed, moto, providers, monkeypatch) as tour:
        await _tour_sidebar(tour)
        # Every destination, the DNS records, the fleet table and help.
        assert len(tour.visited) == len(SIDEBAR_TOUR) + 3
        tour.assert_clean(except_known=KNOWN_LEAKS)


async def test_demo_flag_server_actions_show_no_real_identifier(
    tui, seed, moto, providers, monkeypatch
):
    async with _demo_session(tui, seed, moto, providers, monkeypatch) as tour:
        await _tour_server_actions(tour)
        tour.assert_clean()


async def test_demo_flag_settings_panels_show_no_new_real_identifier(
    tui, seed, moto, providers, monkeypatch
):
    async with _demo_session(tui, seed, moto, providers, monkeypatch) as tour:
        await _tour_settings(tour)
        tour.assert_clean(except_known=KNOWN_SETTINGS_LEAKS)


# With demo mode off, the same tour must find each of these on screen: proof
# that the tours above look where the data is, rather than passing vacuously.
SEEN_WITHOUT_DEMO_MODE = {
    "app-1 name", "app-1 id", "app-1 private ip", "AWS key pair",
    "web-1 name", "web-1 host", "files-1 host", "files-1 key",
    "cache-1 name", "cache-1 id", "cache-1 ip",
    "mail-1 name", "mail-1 service", "mail-1 ip",
    "storage-1.e2e.test name", "storage-1.e2e.test ip",
    "batch-1 name", "batch-1 id", "batch-1 public ip", "OVH project id",
    "default key", "per-instance key", "Hetzner project key",
    "DNS zone", "DNS sub-domain", "DNS target", "reverse DNS",
    "OVH project key", "OVH volume",
}


async def test_tours_see_real_identifiers_without_demo_mode(tui, seed, moto, providers):
    secrets = _seed_world(seed, moto, providers)

    async with tui(size=DEMO_SIZE) as t:
        await _wait_for_fleet(t)
        tour = Tour(t, secrets)
        await _tour_sidebar(tour)
        await _tour_server_actions(tour)
    seen = {leak.label for leak in tour.leaks}
    assert SEEN_WITHOUT_DEMO_MODE <= seen, sorted(SEEN_WITHOUT_DEMO_MODE - seen)
    # Credentials stay masked even with demo mode off.
    assert not seen & {"Hetzner token", "OVH application secret", "OVH consumer key"}


@known_bug(
    "Settings > General shows the default SSH key path and Settings > OVHcloud shows "
    "the Public Cloud project id in clear while demo mode is on",
    raises=DemoModeLeak,
)
async def test_demo_flag_settings_hide_key_path_and_ovh_project(
    tui, seed, moto, providers, monkeypatch
):
    async with _demo_session(tui, seed, moto, providers, monkeypatch) as tour:
        await _tour_settings(tour, only=("general", "ovh"))
        tour.leaks = _only(tour.leaks, KNOWN_SETTINGS_LEAKS)
        tour.assert_clean()


@known_bug(
    "OVH DNS records show a single-label sub-domain (e.g. a customer or project "
    "name) in clear in demo mode: redact_host only recognises dotted host names",
    raises=DemoModeLeak,
)
async def test_demo_flag_dns_records_hide_sub_domains(tui, seed, moto, providers, monkeypatch):
    async with _demo_session(tui, seed, moto, providers, monkeypatch) as tour:
        await tour.t.nav("nav_ovh_dns")
        await tour.t.wait_for_screen("OVHDNSScreen")
        await _open_first_dns_zone(tour)
        tour.leaks = _only(tour.leaks, KNOWN_DNS_LEAKS)
        tour.assert_clean()


# Screens that hold fleet, provider or key data, visited after the switch.
TOGGLE_TOUR = {
    "nav_custom_servers": "CustomServersScreen",
    "nav_keys": "KeyManagementScreen",
    "nav_aws_manage": "AWSManagerScreen",
    "nav_ovh_manage": "OVHManagerScreen",
    "nav_ovh_ssh_keys": "OVHSSHKeysScreen",
    "nav_hetzner_manage": "HetznerManagerScreen",
    "nav_hetzner_ssh_keys": "HetznerSSHKeysScreen",
}


async def test_demo_toggle_hides_then_restores_real_data(tui, seed, moto, providers):
    secrets = _seed_world(seed, moto, providers)

    async with tui(size=DEMO_SIZE) as t:
        await _wait_for_fleet(t)
        real_rows = sorted(map(tuple, t.table_rows("InstanceTable")))
        shown = t.rendered_text()
        for name in REAL_NAMES:
            assert name in shown, name
        assert fleet.HZ_CACHE_1.public_ip in shown

        # Switched on mid-session: data loaded before the switch is hidden too.
        await t.press("ctrl+shift+d")
        await t.wait_for_toast("Demo mode ON")
        await t.wait_until(
            lambda: sorted(map(tuple, t.table_rows("InstanceTable"))) != real_rows,
            desc="the fleet table redrawn with demo values",
        )
        tour = Tour(t, secrets)
        await tour.check("fleet table")
        await _tour_server_actions(tour)
        for nav_id, screen_name in TOGGLE_TOUR.items():
            await t.nav(nav_id)
            await t.wait_for_screen(screen_name)
            await tour.check(screen_name)
        tour.assert_clean()

        # Switched off: the real fleet comes back, row for row.
        await t.nav("nav_list")
        await t.wait_for_screen("InstanceListScreen")
        await t.press("ctrl+shift+d")
        await t.wait_for_toast("Demo mode OFF")
        await t.wait_until(
            lambda: sorted(map(tuple, t.table_rows("InstanceTable"))) == real_rows,
            desc="the real fleet rows back",
        )
        shown = t.rendered_text()
        for name in REAL_NAMES:
            assert name in shown, name
        # Provider screens show real data again too.
        await t.nav("nav_hetzner_manage")
        await t.wait_for_screen("HetznerManagerScreen")
        await t.wait_until(
            lambda: fleet.HZ_CACHE_1.name in t.rendered_text(), desc="real Hetzner names"
        )
        await t.nav("nav_ovh_manage")
        await t.wait_for_screen("OVHManagerScreen")
        await t.wait_until(
            lambda: fleet.OVH_VPS_MAIL_1.display_name in t.rendered_text(), desc="real OVH names"
        )


@known_bug(
    "Switching demo mode on redraws only the fleet table, Fleet Memory, the log viewer "
    "and OVH Billing; any other screen open at that moment keeps showing real names, "
    "ids, addresses and key names until the user leaves it",
    raises=DemoModeLeak,
)
async def test_demo_toggle_redacts_the_screen_that_is_open(tui, seed, moto, providers):
    secrets = _seed_world(seed, moto, providers)

    async with tui(size=DEMO_SIZE) as t:
        await _wait_for_fleet(t)
        tour = Tour(t, secrets)
        for nav_id, screen_name in TOGGLE_TOUR.items():
            await t.nav(nav_id)
            await t.wait_for_screen(screen_name)
            await t.wait_until(lambda: _screen_workers_done(t), desc=f"{screen_name} loaded")
            await t.press("ctrl+shift+d")
            await t.wait_for_toast("Demo mode ON")
            await tour.check(f"{screen_name} after switching demo mode on")
            await t.press("ctrl+shift+d")
            await t.wait_for_toast("Demo mode OFF")
            # Real data is expected again from here on.
            t._notifications.clear()  # noqa: SLF001 - own harness
            tour.leaks = [leak for leak in tour.leaks if leak.where != "notifications"]
        tour.assert_clean()


class DemoBadgeNotUpdated(ProductBug):
    """The status bar's DEMO badge does not follow the ctrl+shift+d toggle."""


@known_bug(
    "Toggling demo mode refreshes status bars through app.query(), which does not "
    "reach widgets on screens, so the DEMO badge does not appear until the screen "
    "is rebuilt",
    raises=DemoBadgeNotUpdated,
)
async def test_demo_toggle_shows_the_demo_badge(tui, seed, providers):
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)

    async with tui() as t:
        await t.wait_until(lambda: t.table_rows("InstanceTable"), desc="fleet rows")
        assert "DEMO" not in t.rendered_text()
        await t.press("ctrl+shift+d")
        await t.wait_for_toast("Demo mode ON")
        await t.wait_until(
            lambda: fleet.APP_1.name not in t.rendered_text(), desc="fleet redrawn"
        )
        await t.settle()
        if "DEMO" not in t.rendered_text():
            raise DemoBadgeNotUpdated("no DEMO badge after switching demo mode on")



class DemoActionTargetsFakeId(ProductBug):
    """In demo mode a provider call names the fake id shown, not the real server."""


@known_bug(
    "In demo mode the actions screen of an OVH VPS asks OVH for the reverse DNS of the "
    "row's demo-mode id and address instead of the real VPS, so the lookup fails",
    raises=DemoActionTargetsFakeId,
)
async def test_demo_flag_ovh_vps_actions_use_the_real_vps(tui, seed, moto, providers, monkeypatch):
    async with _demo_session(tui, seed, moto, providers, monkeypatch) as tour:
        t = tour.t
        table = await t.focus_instance_table()
        while _kind(table.get_selected_instance()) != "ovh-vps":
            assert table.cursor_row < FLEET_SIZE - 1, "no OVH VPS row"
            await t.press("down")
        await t.press("enter")
        await t.wait_for_screen("ServerActionsScreen")
        lookup = await t.wait_until(
            lambda: providers.requests("ovh", method="GET", path=r"/vps/[^/]+/ips/[^/]+"),
            desc="the reverse DNS lookup",
        )
    asked = lookup[0]["api_path"]
    real = {f"/vps/{vps.service_name}/ips/{ip}" for vps in fleet.OVH_VPS_FLEET for ip in vps.ips}
    if asked not in real:
        raise DemoActionTargetsFakeId(f"asked OVH for {asked}")
