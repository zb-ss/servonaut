"""The Auto-bind screen reviews and binds vault keys named like the servers."""
from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
from textual.app import App
from textual.widgets import Button, Checkbox, DataTable, Select, Static

from servonaut.screens import vault_auto_bind
from servonaut.screens.vault_auto_bind import (
    AutoBindFetchConfirmModal,
    VaultAutoBindReviewModal,
    VaultAutoBindScreen,
)
from servonaut.services.vault.auto_bind import (
    FETCHED,
    HOST_KEY_MISMATCH,
    AutoBindRow,
    KeyMatch,
)
from servonaut.services.vault.errors import VaultUserError
from servonaut.styles import CSS_FILES
from tests._async_bounds import wait_until

PERSONAL_VAULT = "11111111-1111-4111-8111-111111111111"
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

SERVERS = [
    {"id": "i-web1", "name": "web-1", "key_name": "web-1", "public_ip": "198.51.100.1"},
    {"id": "i-web2", "name": "web-2", "public_ip": "198.51.100.2"},
    {"id": "i-db", "name": "db-1", "public_ip": "198.51.100.3"},
    {"id": "i-bound", "name": "cache-1", "public_ip": "198.51.100.4"},
]


class _Service:
    def __init__(self, *, keys=None, vaults=None, fail_bind=(), records_new=True) -> None:
        self.keys = keys if keys is not None else [
            {"item_id": "k1", "label": "web-1 · SHA256:a", "name": "web-1.pem", "fingerprint": "SHA256:a"},
            {"item_id": "k2", "label": "web-2 · SHA256:b", "name": "web-2", "fingerprint": "SHA256:b"},
            {"item_id": "k4", "label": "cache-1 · SHA256:d", "name": "cache-1", "fingerprint": "SHA256:d"},
        ]
        self.vaults = vaults if vaults is not None else [
            {"vault_id": PERSONAL_VAULT, "label": "Personal", "kind": "personal"},
        ]
        self.fail_bind = set(fail_bind)
        self.records_new = records_new
        self.binds: list[dict[str, Any]] = []
        self.key_calls: list[dict[str, Any]] = []
        self.visits: list[str] = []

    def records_new_host_keys(self) -> bool:
        return self.records_new

    async def visit_for_host_key(self, instance, login=None, known_hosts_path=None):
        self.visits.append(instance["id"])
        if known_hosts_path:
            with open(known_hosts_path, "a") as f:
                f.write(f"{instance.get('public_ip') or instance['id']} {HOST_KEY}\n")
        return None

    async def vault_choices(self, *, team=None):
        return self.vaults

    async def list_vaults(self):
        return self.vaults

    async def ssh_key_choices(self, **kwargs):
        self.key_calls.append(kwargs)
        return self.keys

    def ssh_destination(self, instance):
        return instance.get("public_ip"), 22

    def ssh_login(self, instance):
        return "ubuntu"

    async def personal_binding(self, instance):
        return {"source": "servonaut_vault"} if instance["id"] == "i-bound" else None

    async def bind_personal(self, **kwargs):
        if kwargs["instance_id"] in self.fail_bind:
            raise VaultUserError("this server already has a vault key")
        self.binds.append(kwargs)
        return {"source": "servonaut_vault"}

    async def bind(self, **kwargs):
        server = kwargs.get("server") or kwargs.get("instance_id")
        if server in self.fail_bind:
            raise VaultUserError("already has a team key: left alone")
        self.binds.append(kwargs)
        return {
            "source": "servonaut_vault",
            "valid": True,
            "signature": "sig",
            "credential_binding": {
                "source": "servonaut_vault",
                "valid": True,
                "signature": "sig",
                "vault_item_id": kwargs.get("item_id"),
            },
        }


class _Host(App):
    CSS_PATH = CSS_FILES

    def __init__(self, service: _Service, instances=None) -> None:
        self.vault_command_service = service
        self.vault_available = True
        self.instances = list(SERVERS if instances is None else instances)
        self._instances_pristine = list(self.instances)
        super().__init__()

    def redact_display_text(self, text: str) -> str:
        if not getattr(self, "demo_mode", False) or getattr(self, "redaction_service", None) is None:
            return text
        from servonaut.services.report_scrubber import InventoryScrubber
        scrubber = InventoryScrubber.for_fleet(self.redaction_service, self._instances_pristine or [])
        return self.redaction_service.scrub_stream(scrubber.replace_known(text))

    def on_mount(self) -> None:
        self.push_screen(VaultAutoBindScreen())


@pytest.fixture(autouse=True)
def _trusted(monkeypatch):
    """This computer trusts a host key for every server but web-2."""
    monkeypatch.setattr(
        vault_auto_bind, "plan_auto_bind",
        _with_host_keys(vault_auto_bind.plan_auto_bind, {"i-web1": [HOST_KEY], "i-bound": [HOST_KEY]}),
    )


def _with_host_keys(plan, trusted):
    async def planned(service, instances, keys, **kwargs):
        inner_host_keys_for = kwargs.pop("host_keys_for", None)

        def lookup(instance, host, port):
            if instance.get("id") in trusted:
                return trusted[instance["id"]]
            if inner_host_keys_for is not None:
                return inner_host_keys_for(instance, host, port)
            return []

        return await plan(
            service,
            instances,
            keys,
            host_keys_for=lookup,
            **kwargs,
        )
    return planned


def _rows(app) -> list[tuple[str, ...]]:
    table = app.screen.query_one("#auto_bind_table", DataTable)
    return [tuple(str(cell) for cell in table.get_row(key)) for key in table.rows]


def _status(app) -> str:
    return str(app.screen.query_one("#auto_bind_status", Static).render())


@pytest.mark.asyncio
async def test_the_review_lists_each_server_with_its_key_or_why_not() -> None:
    service = _Service()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: _rows(app))
        rows = _rows(app)
        assert rows[0] == ("[x]", "web-1", "ready", "web-1.pem", "key pair", "ubuntu", "198.51.100.1")
        statuses = {row[1]: row[2] for row in rows}
        assert statuses == {
            "web-1": "ready", "cache-1": "has a vault key", "web-2": "no trusted host key", "db-1": "no matching key",
        }
        # Every key name is read, not just the first page of them.
        assert service.key_calls == [{"vault_id": PERSONAL_VAULT, "name_limit": None}]
        assert "1 of 4 servers can get a vault key" in _status(app)
        detail = str(app.screen.query_one("#auto_bind_detail", Static).render())
        assert "web-1: Ready to bind" in detail and "SHA256:" in detail
        # Another row's full reason shows when it is highlighted.
        app.screen.query_one("#auto_bind_table", DataTable).move_cursor(row=2)
        await wait_until(lambda: "press f (Fetch host keys)" in str(app.screen.query_one("#auto_bind_detail", Static).render()))


@pytest.mark.asyncio
async def test_nothing_is_bound_until_the_fingerprints_are_confirmed() -> None:
    service = _Service()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: _rows(app))
        apply = app.screen.query_one("#auto_bind_apply", Button)
        assert str(apply.label) == "Bind selected (1)" and not apply.disabled

        apply.press()
        await pilot.pause()
        assert service.binds == []
        assert "tick the box" in _status(app)

        app.screen.query_one("#auto_bind_trust", Checkbox).value = True
        apply.press()
        await wait_until(lambda: "Bound vault keys to 1 of 1" in _status(app))

    (bound,) = service.binds
    assert (bound["instance_id"], bound["item_id"], bound["hostname"], bound["login"]) == ("i-web1", "k1", "198.51.100.1", "ubuntu")
    assert bound["host_keys"] == [HOST_KEY] and bound["replace_existing"] is False


@pytest.mark.asyncio
async def test_a_row_can_be_left_out_and_a_failure_shows_on_its_row() -> None:
    service = _Service(fail_bind={"i-web1"})
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: _rows(app))
        table = app.screen.query_one("#auto_bind_table", DataTable)
        table.focus()
        table.move_cursor(row=0)
        await pilot.press("space")
        await wait_until(lambda: _rows(app)[0][0] == "[ ]")
        assert app.screen.query_one("#auto_bind_apply", Button).disabled
        await pilot.press("space")
        await wait_until(lambda: _rows(app)[0][0] == "[x]")

        app.screen.query_one("#auto_bind_trust", Checkbox).value = True
        app.screen.query_one("#auto_bind_apply", Button).press()
        await wait_until(lambda: "failed" in _status(app))
        assert _rows(app)[0][2] == "binding failed"
        assert "Binding failed (this server already has a vault key)" in str(
            app.screen.query_one("#auto_bind_detail", Static).render()
        )


@pytest.mark.asyncio
async def test_without_a_personal_vault_or_keys_it_says_what_to_do() -> None:
    app = _Host(_Service(vaults=[{"vault_id": "t", "label": "Ops", "kind": "team"}]))
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: "no personal vault" in _status(app))
        assert app.screen.query_one("#auto_bind_apply", Button).disabled

    app = _Host(_Service(keys=[]))
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: "no SSH key yet" in _status(app))


@pytest.mark.asyncio
async def test_team_servers_are_not_offered() -> None:
    shared = {"id": "s1", "name": "web-1", "is_shared": True, "hostname": "web.example.test"}
    app = _Host(_Service(), instances=[shared])
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: "no servers of your own" in _status(app))


@pytest.mark.asyncio
async def test_the_review_fits_a_narrow_terminal() -> None:
    app = _Host(_Service())
    async with app.run_test(size=(100, 30)) as pilot:
        await wait_until(lambda: _rows(app))
        await pilot.pause()
        screen = app.screen.region
        for selector in (
            "#auto_bind_vault_select",
            "#auto_bind_table",
            "#auto_bind_trust",
            "#auto_bind_apply",
            "#auto_bind_back",
            "#auto_bind_fetch_keys",
        ):
            region = app.screen.query_one(selector).region
            assert region.width > 0 and region.height > 0 and screen.contains_region(region), (selector, region)


@pytest.mark.asyncio
async def test_fetch_button_enabled_and_disabled_reasons() -> None:
    # 1. Enabled when servers lack host keys
    app1 = _Host(_Service())
    async with app1.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: _rows(app1))
        btn1 = app1.screen.query_one("#auto_bind_fetch_keys", Button)
        assert not btn1.disabled

    # 2. Disabled when records_new_host_keys is False
    app2 = _Host(_Service(records_new=False))
    async with app2.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: _rows(app2))
        btn2 = app2.screen.query_one("#auto_bind_fetch_keys", Button)
        assert btn2.disabled
        assert "ssh.host_key_checking = yes" in (btn2.tooltip or "")

    # 3. Disabled when no servers need host keys fetched
    app3 = _Host(_Service(), instances=[SERVERS[0]])
    async with app3.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: _rows(app3))
        btn3 = app3.screen.query_one("#auto_bind_fetch_keys", Button)
        assert btn3.disabled
        assert "None of the servers need a host key fetched" in (btn3.tooltip or "")


@pytest.mark.asyncio
async def test_fetch_action_opens_confirm_modal_and_fetches(monkeypatch) -> None:
    async def fake_fetch(service, rows, on_progress=None, accounts=None):
        for r in rows:
            r.status = FETCHED
            r.host_keys = [HOST_KEY]
            r.verified = False
            r.verification_source = "trusted by this computer"

    monkeypatch.setattr(vault_auto_bind, "fetch_host_keys_for_rows", fake_fetch)

    app = _Host(_Service())
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: _rows(app))
        web2_idx = next(i for i, r in enumerate(app.screen._rows) if r.instance["name"] == "web-2")
        # web-2 is initially NO_HOST_KEYS and not selected
        assert not any("fetched" in cell for row in _rows(app) for cell in row)
        assert web2_idx not in app.screen._selected

        # Press 'f' to fetch host keys
        await pilot.press("f")
        await wait_until(lambda: isinstance(app.screen, AutoBindFetchConfirmModal))

        # Confirm connection
        await pilot.click("#auto_bind_confirm_yes")
        await wait_until(lambda: "Fetched host keys for 1 of 1 servers" in _status(app))

        # web-2 is now fetched and selected
        rows = _rows(app)
        statuses = {row[1]: row[2] for row in rows}
        assert statuses["web-2"] == "fetched: check fingerprint"
        assert web2_idx in app.screen._selected


@pytest.mark.asyncio
async def test_host_key_mismatch_row_is_never_selectable(monkeypatch) -> None:
    async def fake_fetch(service, rows, on_progress=None, accounts=None):
        for r in rows:
            r.status = HOST_KEY_MISMATCH
            r.mismatch_detail = "different key than AWS recorded"

    monkeypatch.setattr(vault_auto_bind, "fetch_host_keys_for_rows", fake_fetch)

    app = _Host(_Service())
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: _rows(app))
        web2_idx = next(i for i, r in enumerate(app.screen._rows) if r.instance["name"] == "web-2")
        await pilot.press("f")
        await wait_until(lambda: isinstance(app.screen, AutoBindFetchConfirmModal))
        await pilot.click("#auto_bind_confirm_yes")
        await wait_until(lambda: "1 failed or mismatched" in _status(app))

        # Select all should NOT select the mismatch row
        await pilot.click("#auto_bind_all")
        assert web2_idx not in app.screen._selected

        # Direct selection attempt should also be rejected
        app.screen.query_one("#auto_bind_table", DataTable).move_cursor(row=web2_idx)
        app.screen.action_toggle_row()
        assert web2_idx not in app.screen._selected


@pytest.mark.asyncio
async def test_review_modal_blocks_bind_until_tick_unless_verified() -> None:
    # 1. Unverified row blocks confirm until tick
    unverified_row = AutoBindRow(
        instance={"id": "i-web2", "name": "web-2"},
        status=FETCHED,
        match=KeyMatch(item_id="k2", name="web-2", matched_by="server name"),
        host="198.51.100.2",
        port=22,
        login="ubuntu",
        host_keys=[HOST_KEY],
        verified=False,
    )

    class _ModalHost(App):
        CSS_PATH = CSS_FILES

        def __init__(self, rows):
            self.rows = rows
            super().__init__()

        def on_mount(self):
            self.push_screen(
                VaultAutoBindReviewModal(
                    self.rows,
                    server_name_fn=lambda r: r.instance.get("name", ""),
                    scrub_fn=lambda s: str(s),
                )
            )

    app1 = _ModalHost([unverified_row])
    async with app1.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: isinstance(app1.screen, VaultAutoBindReviewModal))
        confirm_btn = app1.screen.query_one("#vault_auto_bind_review_confirm", Button)
        checkbox = app1.screen.query_one("#vault_auto_bind_review_use_trusted", Checkbox)

        assert confirm_btn.disabled
        assert not checkbox.value

        # Tick checkbox -> confirm is enabled
        checkbox.value = True
        await pilot.pause()
        assert not confirm_btn.disabled

        # Untick checkbox -> confirm is disabled again
        checkbox.value = False
        await pilot.pause()
        assert confirm_btn.disabled

    # 2. Verified row enables confirm immediately
    verified_row = AutoBindRow(
        instance={"id": "i-web1", "name": "web-1"},
        status=FETCHED,
        match=KeyMatch(item_id="k1", name="web-1", matched_by="server name"),
        host="198.51.100.1",
        port=22,
        login="ubuntu",
        host_keys=[HOST_KEY],
        verified=True,
        verification_source="verified by AWS console output",
    )

    app2 = _ModalHost([verified_row])
    async with app2.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: isinstance(app2.screen, VaultAutoBindReviewModal))
        confirm_btn = app2.screen.query_one("#vault_auto_bind_review_confirm", Button)
        checkbox = app2.screen.query_one("#vault_auto_bind_review_use_trusted", Checkbox)

        assert not confirm_btn.disabled
        assert checkbox.value


@pytest.mark.asyncio
async def test_review_modal_fits_narrow_terminal() -> None:
    reason = "not verified: the console output no longer holds the first-boot host keys"
    row = AutoBindRow(
        instance={"id": "i-web1", "name": "web-1"},
        status=FETCHED,
        match=KeyMatch(item_id="k1", name="web-1", matched_by="server name"),
        host="198.51.100.1",
        port=22,
        login="ubuntu",
        host_keys=[HOST_KEY],
        verified=False,
        verification_source=reason,
    )

    class _ModalHost(App):
        CSS_PATH = CSS_FILES

        def on_mount(self):
            self.push_screen(
                VaultAutoBindReviewModal(
                    [row],
                    server_name_fn=lambda r: r.instance.get("name", ""),
                    scrub_fn=lambda s: str(s),
                )
            )

    app = _ModalHost()
    async with app.run_test(size=(100, 30)) as pilot:
        await wait_until(lambda: isinstance(app.screen, VaultAutoBindReviewModal))
        await pilot.pause()
        screen = app.screen.region
        for selector in (
            "#auto_bind_review_container",
            "#auto_bind_review_scroll",
            "#vault_auto_bind_review_use_trusted",
            "#vault_auto_bind_review_cancel",
            "#vault_auto_bind_review_confirm",
        ):
            region = app.screen.query_one(selector).region
            assert region.width > 0 and region.height > 0 and screen.contains_region(region), (selector, region)

        source_widget = app.screen.query_one(".auto_bind_review_source", Static)
        source_text = str(source_widget.render())
        assert "Verification:" in source_text
        assert "Source:" not in source_text
        assert reason in source_text
        for line in source_text.splitlines():
            assert line.startswith("  ")

        # The reason wraps inside the review scroll rather than clipping/overflowing horizontally
        rendered_lines = [
            "".join(segment.text for segment in source_widget.render_line(y))
            for y in range(source_widget.region.height)
        ]
        full_rendered = " ".join(rendered_lines)
        assert "the console output no longer holds the first-boot" in full_rendered
        assert "host keys" in full_rendered

        svg = app.export_screenshot()
        assert "first-boot" in svg
        assert "host&#160;keys" in svg or "host keys" in svg


@pytest.mark.asyncio
async def test_team_vault_picker_filters_administered_vaults() -> None:
    vaults = [
        {"vault_id": PERSONAL_VAULT, "label": "Personal", "kind": "personal"},
        {
            "vault_id": "tv-1",
            "kind": "team",
            "team": {"slug": "devs", "role": "admin"},
            "my_grant": {"sealed_key": "s1"},
        },
        {
            "vault_id": "tv-2",
            "kind": "team",
            "team": {"slug": "ops", "role": "owner"},
            "my_grant": {"sealed_key": "s2"},
        },
        {
            "vault_id": "tv-3",
            "kind": "team",
            "team": {"slug": "marketing", "role": "member"},
            "my_grant": {"sealed_key": "s3"},
        },
        {
            "vault_id": "tv-4",
            "kind": "team",
            "team": {"slug": "sales", "role": "admin"},
            "my_grant": None,
        },
        {
            "vault_id": "tv-5",
            "kind": "team",
            "team": {"slug": "support", "role": "admin"},  # stray role: "admin" on vault
            "my_grant": {"sealed_key": "s5"},
        },
        {
            "vault_id": "tv-6",
            "kind": "team",
            "team": {"slug": "viewers", "role": "viewer"},
            "my_grant": {"sealed_key": "s6"},
        },
    ]
    instances = [
        {"id": "i-own", "name": "web-own", "public_ip": "198.51.100.1"},
        {"id": "s-devs", "name": "dev-box", "hostname": "198.51.100.2", "is_shared": True, "team_slug": "devs", "team_role": "admin"},
        {"id": "s-ops", "name": "ops-box", "hostname": "198.51.100.3", "is_shared": True, "team_slug": "ops", "team_role": "owner"},
        {"id": "s-mkt", "name": "mkt-box", "hostname": "198.51.100.4", "is_shared": True, "team_slug": "marketing", "team_role": "member"},
        {"id": "s-sup", "name": "sup-box", "hostname": "198.51.100.5", "is_shared": True, "team_slug": "support", "team_role": "member"},
        {"id": "s-view", "name": "view-box", "hostname": "198.51.100.6", "is_shared": True, "team_slug": "viewers", "team_role": "viewer"},
    ]
    service = _Service(vaults=vaults)
    app = _Host(service, instances=instances)
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: _rows(app))
        select = app.screen.query_one("#auto_bind_vault_select", Select)
        option_values = [opt[1] for opt in select._options]
        assert "personal" in option_values
        assert "team:devs" in option_values
        assert "team:ops" in option_values
        assert "team:marketing" not in option_values
        assert "team:sales" not in option_values
        assert "team:support" not in option_values
        assert "team:viewers" not in option_values
        assert select.value == "personal"


@pytest.mark.asyncio
async def test_switching_vault_picker_loads_team_shared_servers() -> None:
    vaults = [
        {"vault_id": PERSONAL_VAULT, "label": "Personal", "kind": "personal"},
        {
            "vault_id": "tv-1",
            "kind": "team",
            "team": {"slug": "devs", "role": "admin"},
            "my_grant": {"sealed_key": "s1"},
        },
    ]
    instances = [
        {"id": "i-own", "name": "web-own", "public_ip": "198.51.100.1"},
        {"id": "s-shared", "name": "dev-box", "hostname": "198.51.100.2", "is_shared": True, "team_slug": "devs", "team_role": "admin", "login": "ubuntu"},
    ]
    keys_personal = [{"item_id": "k1", "label": "web-own", "name": "web-own.pem", "fingerprint": "SHA256:1"}]
    keys_team = [{"item_id": "k2", "label": "dev-box", "name": "dev-box.pem", "fingerprint": "SHA256:2"}]

    class _TeamService(_Service):
        async def ssh_key_choices(self, *, vault_id, name_limit=None):
            if vault_id == "tv-1":
                return keys_team
            return keys_personal

    service = _TeamService(vaults=vaults)
    app = _Host(service, instances=instances)
    async with app.run_test(size=(160, 50)) as pilot:
        # Initially personal vault loads own servers
        await wait_until(lambda: any("web-own" in r for r in _rows(app)))
        assert not any("dev-box" in r for r in _rows(app))

        # Switch to team vault
        select = app.screen.query_one("#auto_bind_vault_select", Select)
        select.value = "team:devs"
        await pilot.pause()

        # Now team shared servers load
        await wait_until(lambda: any("dev-box" in r for r in _rows(app)))
        assert not any("web-own" in r for r in _rows(app))


@pytest.mark.asyncio
async def test_demo_mode_scrubs_team_name_everywhere() -> None:
    from servonaut.services.redaction_service import RedactionService
    vaults = [
        {"vault_id": PERSONAL_VAULT, "label": "Personal", "kind": "personal"},
        {
            "vault_id": "tv-1",
            "kind": "team",
            "team": {"slug": "secret-team"},
            "my_grant": {"sealed_key": "s1"},
        },
    ]
    instances = [
        {"id": "i-own", "name": "web-own", "public_ip": "198.51.100.2"},
        {
            "id": "s-1",
            "name": "shared-1",
            "hostname": "198.51.100.1",
            "is_shared": True,
            "team_slug": "secret-team",
            "team_role": "admin",
            "team_name": "Top Secret Engineering",
            "login": "ubuntu",
        },
    ]
    keys = [
        {"item_id": "k0", "label": "web-own", "name": "web-own.pem", "fingerprint": "SHA256:0"},
        {"item_id": "k1", "label": "shared-1", "name": "shared-1.pem", "fingerprint": "SHA256:1"},
    ]
    service = _Service(vaults=vaults, keys=keys)
    app = _Host(service, instances=instances)
    app.demo_mode = True
    app.redaction_service = RedactionService()

    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: _rows(app))
        select = app.screen.query_one("#auto_bind_vault_select", Select)
        for opt in app.screen._vault_options:
            label_str = str(opt[0])
            assert "Top Secret Engineering" not in label_str

        select.value = "team:secret-team"
        await pilot.pause()
        await wait_until(lambda: app.screen._team == "secret-team" and not app.screen._busy.is_busy)
        intro = str(app.screen.query_one("#auto_bind_intro", Static).render())
        assert "Top Secret Engineering" not in intro

        modal = VaultAutoBindReviewModal(
            [AutoBindRow(instance=instances[0], status=FETCHED, verified=True)],
            server_name_fn=app.screen._server_name,
            scrub_fn=app.screen.scrub_for_display,
            team="secret-team",
            team_name="Top Secret Engineering",
        )
        app.push_screen(modal)
        await pilot.pause()
        await wait_until(lambda: bool(app.screen.query("#auto_bind_review_team_note")))
        note = str(app.screen.query_one("#auto_bind_review_team_note", Static).render())
        assert "Top Secret Engineering" not in note


@pytest.mark.asyncio
async def test_team_review_modal_shows_team_note() -> None:
    row = AutoBindRow(
        instance={"id": "s-1", "name": "dev-box"},
        status=FETCHED,
        match=KeyMatch(item_id="k1", name="dev-box", matched_by="server name"),
        host="198.51.100.1",
        port=22,
        login="ubuntu",
        host_keys=[HOST_KEY],
        verified=True,
    )

    class _ModalHost(App):
        CSS_PATH = CSS_FILES

        def on_mount(self):
            self.push_screen(
                VaultAutoBindReviewModal(
                    [row],
                    server_name_fn=lambda r: r.instance.get("name", ""),
                    scrub_fn=lambda s: str(s),
                    team="devs",
                )
            )

    app = _ModalHost()
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: isinstance(app.screen, VaultAutoBindReviewModal))
        note = app.screen.query_one("#auto_bind_review_team_note", Static)
        assert "Everyone in devs will connect with these keys." in str(note.render())


@pytest.mark.asyncio
async def test_fetch_progress_reports_1_of_2_then_2_of_2_never_3_of_2() -> None:
    from servonaut.services.vault.auto_bind import NO_HOST_KEYS, AutoBindRow
    calls = []
    service = _Service()
    rows = [
        AutoBindRow(instance=SERVERS[0], status=NO_HOST_KEYS, host="198.51.100.1", port=22, login="ubuntu"),
        AutoBindRow(instance=SERVERS[1], status=NO_HOST_KEYS, host="198.51.100.2", port=22, login="ubuntu"),
    ]
    app = _Host(service, instances=SERVERS[:2])
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        orig_say = screen._busy.say
        def spy_say(job, msg):
            calls.append(msg)
            return orig_say(job, msg)
        screen._busy.say = spy_say
        await screen._run_fetch_host_keys(rows)
        assert any("1 of 2" in c for c in calls)
        assert any("2 of 2" in c for c in calls)
        assert not any("3 of 2" in c for c in calls)


@pytest.mark.asyncio
async def test_team_slug_does_not_mangle_key_name_containing_slug() -> None:
    from servonaut.services.redaction_service import RedactionService

    vaults = [
        {"vault_id": PERSONAL_VAULT, "label": "Personal", "kind": "personal"},
        {
            "vault_id": "tv-ops",
            "kind": "team",
            "team": {"slug": "ops"},
            "my_grant": {"sealed_key": "s1"},
        },
    ]
    instances = [
        {"id": "i-own", "name": "web-own", "public_ip": "198.51.100.2"},
        {
            "id": "s-1",
            "name": "ops-box",
            "hostname": "198.51.100.1",
            "is_shared": True,
            "team_slug": "ops",
            "team_role": "admin",
            "login": "ubuntu",
        },
    ]
    service = _Service(vaults=vaults)
    app = _Host(service, instances=instances)

    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: _rows(app))
        screen = app.screen

        # Outside demo mode: key name is untouched
        assert screen.scrub_for_display("ops-deploy.pem") == "ops-deploy.pem"

        # In demo mode: display_text handles it without corrupting the key name with bare substring replacement
        app.demo_mode = True
        app.redaction_service = RedactionService()
        shown = screen.scrub_for_display("ops-deploy.pem")
        assert shown == "ops-deploy.pem"


@pytest.mark.asyncio
async def test_toggle_demo_mode_on_after_loading_team_mode() -> None:
    from servonaut.services.redaction_service import RedactionService
    vaults = [
        {"vault_id": PERSONAL_VAULT, "label": "Personal", "kind": "personal"},
        {
            "vault_id": "tv-1",
            "kind": "team",
            "team": {"slug": "secret-team"},
            "my_grant": {"sealed_key": "s1"},
        },
    ]
    instances = [
        {"id": "i-own", "name": "web-own", "public_ip": "198.51.100.2"},
        {
            "id": "s-1",
            "name": "shared-1",
            "hostname": "198.51.100.1",
            "is_shared": True,
            "team_slug": "secret-team",
            "team_role": "admin",
            "team_name": "Top Secret Engineering",
            "login": "ubuntu",
        },
    ]
    keys = [
        {"item_id": "k0", "label": "web-own", "name": "web-own.pem", "fingerprint": "SHA256:0"},
        {"item_id": "k1", "label": "shared-1", "name": "shared-1.pem", "fingerprint": "SHA256:1"},
    ]
    service = _Service(vaults=vaults, keys=keys)
    app = _Host(service, instances=instances)
    app.demo_mode = False

    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: _rows(app))
        select = app.screen.query_one("#auto_bind_vault_select", Select)
        select.value = "team:secret-team"
        await pilot.pause()
        await wait_until(lambda: app.screen._team == "secret-team" and not app.screen._busy.is_busy)

        # Before demo mode: real name is present
        assert any("Top Secret Engineering" in opt[0] for opt in app.screen._vault_options)
        intro = str(app.screen.query_one("#auto_bind_intro", Static).render())
        assert "Top Secret Engineering" in intro

        # Toggle demo mode on
        app.demo_mode = True
        app.redaction_service = RedactionService()
        app.screen.refresh_after_demo_toggle()
        await pilot.pause()

        # After toggle: real name is gone from options, intro, and status
        assert not any("Top Secret Engineering" in opt[0] for opt in app.screen._vault_options)
        intro_scrubbed = str(app.screen.query_one("#auto_bind_intro", Static).render())
        assert "Top Secret Engineering" not in intro_scrubbed
        status = str(app.screen.query_one("#auto_bind_status", Static).render())
        assert "Top Secret Engineering" not in status

        # Selection is preserved
        assert select.value == "team:secret-team"


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_picker_label_one_line_high_for_20_char_team(size: tuple[int, int]) -> None:
    from textual.widgets._select import SelectCurrent

    team_name_20 = "12345678901234567890"  # 20 chars
    vaults = [
        {"vault_id": PERSONAL_VAULT, "label": "Personal", "kind": "personal"},
        {
            "vault_id": "tv-1",
            "kind": "team",
            "team": {"slug": "twenty-team"},
            "my_grant": {"sealed_key": "s1"},
        },
    ]
    instances = [
        {"id": "i-own", "name": "web-own", "public_ip": "198.51.100.2"},
        {
            "id": "s-1",
            "name": "twenty-box",
            "hostname": "198.51.100.1",
            "is_shared": True,
            "team_slug": "twenty-team",
            "team_role": "admin",
            "team_name": team_name_20,
            "login": "ubuntu",
        },
    ]
    service = _Service(vaults=vaults)
    app = _Host(service, instances=instances)
    async with app.run_test(size=size) as pilot:
        await wait_until(lambda: _rows(app))
        opt_labels = [opt[0] for opt in app.screen._vault_options]
        expected_label = f"Team vault: {team_name_20} (binds for everyone in it)"
        assert expected_label in opt_labels
        select = app.screen.query_one("#auto_bind_vault_select", Select)
        select.value = "team:twenty-team"
        await pilot.pause()
        current = select.query_one(SelectCurrent)
        assert current.size.height == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, 3])
async def test_team_status_wording_when_none_can_get_key(count: int) -> None:
    vaults = [
        {"vault_id": PERSONAL_VAULT, "label": "Personal", "kind": "user"},
        {
            "vault_id": "tv-1",
            "kind": "team",
            "team": {"slug": "ops-team"},
            "my_grant": {"sealed_key": "s1"},
        },
    ]
    instances = [
        {
            "id": f"s-{i}",
            "name": f"shared-{i}",
            "hostname": f"198.51.100.{i}",
            "is_shared": True,
            "team_slug": "ops-team",
            "team_role": "admin",
            "team_name": "Ops Core Team",
            "login": "ubuntu",
        }
        for i in range(1, count + 1)
    ]
    # No matching keys for shared-*
    keys_team = [{"item_id": "k-other", "label": "other", "name": "other.pem", "fingerprint": "SHA256:x"}]
    service = _Service(vaults=vaults, keys=keys_team)
    app = _Host(service, instances=instances)
    async with app.run_test(size=(160, 50)) as pilot:
        select = app.screen.query_one("#auto_bind_vault_select", Select)
        select.value = "team:ops-team"
        await wait_until(lambda: app.screen._team == "ops-team" and not app.screen._busy.is_busy)
        status = _status(app)
        if count == 1:
            assert status == "The 1 shared server of Ops Core Team can't get a vault key automatically: see its status."
        else:
            assert status == f"None of the {count} shared servers of Ops Core Team can get a vault key automatically: see each status."

        # Demo mode scrubs the team name
        from servonaut.services.redaction_service import RedactionService

        app.demo_mode = True
        app.redaction_service = RedactionService()
        app.screen.refresh_after_demo_toggle()
        demo_status = _status(app)
        assert "Ops Core Team" not in demo_status
        if count == 1:
            assert "can't get a vault key automatically" in demo_status
        else:
            assert "can get a vault key automatically" in demo_status


@pytest.mark.asyncio
async def test_compact_layout_at_100x30_with_twelve_rows() -> None:
    instances = [
        {"id": f"i-{i}", "name": f"srv-{i}", "public_ip": f"198.51.100.{i}"}
        for i in range(12)
    ]
    service = _Service()
    app = _Host(service, instances=instances)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = app.screen
        await wait_until(lambda: len(screen._rows) == 12)
        assert screen.has_class("-short")
        assert screen.has_class("-narrow")

        intro = screen.query_one("#auto_bind_intro", Static)
        assert intro.size.height == 0 or not intro.visible

        select = screen.query_one("#auto_bind_vault_select", Select)
        assert select.visible and select.size.height == 1

        table = screen.query_one("#auto_bind_table", DataTable)
        assert table.visible and table.size.height >= 8

        status = screen.query_one("#auto_bind_status", Static)
        assert status.visible and status.size.height >= 1

        actions = screen.query_one("#auto_bind_actions")
        assert actions.visible
        for btn in actions.query(Button):
            assert btn.visible and btn.size.height >= 1


@pytest.mark.asyncio
async def test_team_auto_bind_bind_and_reload_shows_has_team_key(monkeypatch) -> None:
    monkeypatch.setattr(
        vault_auto_bind, "plan_auto_bind",
        _with_host_keys(vault_auto_bind.plan_auto_bind, {"s-1": [HOST_KEY]}),
    )
    vaults = [
        {"vault_id": PERSONAL_VAULT, "label": "Personal", "kind": "personal"},
        {
            "vault_id": "tv-1",
            "kind": "team",
            "team": {"slug": "ops-team"},
            "my_grant": {"sealed_key": "s1"},
        },
    ]
    instances = [
        {
            "id": "s-1",
            "name": "shared-1",
            "hostname": "198.51.100.1",
            "is_shared": True,
            "team_slug": "ops-team",
            "team_role": "admin",
            "login_user": "ubuntu",
        },
    ]
    keys = [{"item_id": "k1", "label": "shared-1", "name": "shared-1.pem", "fingerprint": "SHA256:1"}]
    service = _Service(vaults=vaults, keys=keys)
    app = _Host(service, instances=instances)
    async with app.run_test(size=(160, 50)) as pilot:
        select = app.screen.query_one("#auto_bind_vault_select", Select)
        select.value = "team:ops-team"
        await wait_until(lambda: app.screen._team == "ops-team" and not app.screen._busy.is_busy)

        # Before binding: server is ready and selected
        rows = _rows(app)
        assert any(row[1] == "shared-1" and row[2] == "ready" for row in rows)
        apply_btn = app.screen.query_one("#auto_bind_apply", Button)
        assert not apply_btn.disabled

        # Pin and bind
        app.screen.query_one("#auto_bind_trust", Checkbox).value = True
        apply_btn.press()
        await wait_until(lambda: len(service.binds) == 1)
        await wait_until(lambda: not app.screen._busy.is_busy)

        # In-memory shared row was updated with returned binding
        assert app.instances[0].get("credential_binding") is not None

        # Reload the review
        app.screen.action_reload()
        await wait_until(lambda: any(row[1] == "shared-1" and row[2] == "has a team key" for row in _rows(app)))

        # After reload: shows "has a team key" and is not selectable
        rows_after = _rows(app)
        assert any(row[1] == "shared-1" and row[2] == "has a team key" for row in rows_after)
        apply_btn_after = app.screen.query_one("#auto_bind_apply", Button)
        assert apply_btn_after.disabled


@pytest.mark.asyncio
async def test_team_auto_bind_fresh_read_preserves_real_team_role() -> None:
    vaults = [
        {"vault_id": PERSONAL_VAULT, "label": "Personal", "kind": "personal"},
        {
            "vault_id": "tv-1",
            "kind": "team",
            "team": {"slug": "leadership-team"},
            "my_grant": {"sealed_key": "s1"},
        },
    ]
    instances = [
        {
            "id": "s-1",
            "name": "leader-box",
            "hostname": "198.51.100.1",
            "is_shared": True,
            "team_slug": "leadership-team",
            "team_role": "owner",
            "team_name": "Leadership Team",
            "login_user": "ubuntu",
        },
    ]
    keys = [{"item_id": "k1", "label": "leader-box", "name": "leader-box.pem", "fingerprint": "SHA256:1"}]
    service = _Service(vaults=vaults, keys=keys)
    app = _Host(service, instances=instances)
    async with app.run_test(size=(160, 50)) as pilot:
        select = app.screen.query_one("#auto_bind_vault_select", Select)
        select.value = "team:leadership-team"
        await wait_until(lambda: app.screen._team == "leadership-team" and not app.screen._busy.is_busy)

        # The planned rows carry the team's real role ("owner"), not a fabricated "admin"
        assert len(app.screen._rows) == 1
        assert app.screen._rows[0].instance.get("team_role") == "owner"


@pytest.mark.asyncio
async def test_team_auto_bind_matches_shared_server_through_own_server_key_pair() -> None:
    vaults = [
        {"vault_id": PERSONAL_VAULT, "label": "Personal", "kind": "personal"},
        {
            "vault_id": "tv-1",
            "kind": "team",
            "team": {"slug": "ops-team"},
            "my_grant": {"sealed_key": "s1"},
        },
    ]
    own_instance = {
        "id": "i-own1",
        "name": "edge-1",
        "key_name": "ops-key",
        "public_ip": "198.51.100.1",
    }
    shared_instance = {
        "id": "s-1",
        "instance_id": "i-own1",
        "name": "server-1",
        "hostname": "198.51.100.1",
        "is_shared": True,
        "team_slug": "ops-team",
        "team_role": "owner",
        "team_name": "Ops Team",
        "login_user": "ubuntu",
    }
    keys = [{"item_id": "k1", "label": "ops-key", "name": "ops-key.pem", "fingerprint": "SHA256:1"}]
    service = _Service(vaults=vaults, keys=keys)
    app = _Host(service, instances=[own_instance, shared_instance])
    team_svc = AsyncMock()
    team_svc.list_shared_servers = AsyncMock(return_value=[shared_instance])
    app.team_service = team_svc

    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: _rows(app))
        select = app.screen.query_one("#auto_bind_vault_select", Select)
        select.value = "team:ops-team"
        await wait_until(lambda: app.screen._team == "ops-team" and not app.screen._busy.is_busy)

        assert len(app.screen._rows) == 1
        row = app.screen._rows[0]
        assert row.match is not None
        assert row.match.name == "ops-key.pem"
        assert row.match.matched_by == "key pair"






@pytest.mark.asyncio
async def test_a_configured_key_file_matches_first_and_a_missing_one_is_noted(tmp_path) -> None:
    from types import SimpleNamespace

    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat,
    )

    from servonaut.services.vault.crypto import ssh_public_fingerprint

    def key_file(name: str) -> str:
        key = ed25519.Ed25519PrivateKey.generate()
        (tmp_path / name).write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
        public = key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
        return ssh_public_fingerprint(public)

    in_vault = key_file("web-1-new.pem")
    key_file("cache-old.pem")
    service = _Service(keys=[
        {"item_id": "k1", "label": "web-1", "name": "web-1.pem", "fingerprint": "SHA256:a"},
        {"item_id": "k9", "label": "copy", "name": "deploy copy", "fingerprint": in_vault},
    ])
    service.config = SimpleNamespace(instance_keys={
        "i-web1": str(tmp_path / "web-1-new.pem"),
        "i-db": str(tmp_path / "cache-old.pem"),
    })
    app = _Host(service)
    async with app.run_test(size=(160, 50)):
        await wait_until(lambda: _rows(app))
        rows = {row[1]: row for row in _rows(app)}
        assert rows["web-1"][3:5] == ("deploy copy", "configured key")
        table = app.screen.query_one("#auto_bind_table", DataTable)
        table.move_cursor(row=[row[1] for row in _rows(app)].index("db-1"))
        await wait_until(lambda: "Note: The key file set for this server (cache-old.pem) is not in this vault" in str(
            app.screen.query_one("#auto_bind_detail", Static).render()
        ))


@pytest.mark.asyncio
async def test_the_detail_says_where_the_login_comes_from() -> None:
    class _Sourced(_Service):
        def ssh_login_source(self, instance):
            return "ec2-user", "default username"

    app = _Host(_Sourced())
    async with app.run_test(size=(160, 50)):
        await wait_until(lambda: _rows(app))
        detail = lambda: str(app.screen.query_one("#auto_bind_detail", Static).render())  # noqa: E731
        await wait_until(lambda: "Login: ec2-user (from default username)" in detail())
        assert "Note: The login ec2-user is only the default username" in detail()


@pytest.mark.asyncio
@pytest.mark.parametrize("vault, shared_rows, reason", [
    ({"my_grant": None}, True, "Ops: your access to its vault is not granted yet"),
    ({"my_grant": {"version": 1}}, False,
     "Ops: no shared servers are listed (open the team on the Teams screen)"),
    ({"my_grant": {"version": 1}}, True, "Ops: only a team owner or admin can bind its keys"),
])
async def test_without_an_offered_vault_it_says_why_each_team_vault_is_not_offered(
    vault, shared_rows, reason,
) -> None:
    # Regression: it only said "no personal vault" although a team vault existed.
    team_vault = {"vault_id": "t", "label": "Ops", "kind": "team", "team": {"slug": "ops", "name": "Ops"}, **vault}
    rows = [{
        "id": "s1", "name": "web-1", "is_shared": True, "team_slug": "ops", "team_name": "Ops",
        "team_role": "member", "hostname": "web.example.test",
    }] if shared_rows else []
    app = _Host(_Service(vaults=[team_vault]), instances=rows)
    async with app.run_test(size=(160, 50)):
        await wait_until(lambda: "no personal vault" in _status(app))
        assert f"Team vaults not offered: {reason}." in _status(app)


@pytest.mark.asyncio
async def test_a_failed_auto_bind_is_logged_once_per_server(caplog: pytest.LogCaptureFixture) -> None:
    service = _Service(fail_bind={"i-web1"})
    app = _Host(service)
    caplog.set_level("WARNING", logger=vault_auto_bind.__name__)
    async with app.run_test(size=(160, 50)):
        await wait_until(lambda: _rows(app))
        app.screen.query_one("#auto_bind_trust", Checkbox).value = True
        app.screen.query_one("#auto_bind_apply", Button).press()
        await wait_until(lambda: "failed" in _status(app))

    lines = [r.getMessage() for r in caplog.records if r.name == vault_auto_bind.__name__ and r.levelname == "WARNING"]
    assert lines == ["Vault key binding failed for web-1: this server already has a vault key"]
    assert HOST_KEY.split()[1] not in lines[0]
