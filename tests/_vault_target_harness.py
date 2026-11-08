"""A fake vault service and a host app for driving the Vault screen headlessly.

Three vaults are listed: a personal one, a team the user administers and a
team the user has no key for yet. Every service call is recorded so a test
can say which vault an action reached.
"""

from __future__ import annotations

from typing import Any, Optional

from textual.app import App
from textual.widgets import Button, DataTable

from servonaut.screens.vault import VaultScreen
from tests._async_bounds import wait_until

VAULT_A = "11111111-1111-4111-8111-111111111111"
VAULT_B = "22222222-2222-4222-8222-222222222222"
VAULT_C = "33333333-3333-4333-8333-333333333333"
NAMES = {VAULT_A: "A (Personal)", VAULT_B: "B (Platform team)", VAULT_C: "C (Waiting team)"}


def short(vault_id: Optional[str]) -> str:
    return NAMES.get(vault_id or "", str(vault_id))


class FakeVaultService:
    def __init__(self, *, names: Optional[dict] = None, members: Optional[list] = None,
                 device_names: Optional[list] = None) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.names = names or {}
        self.members = members
        self.device_names = device_names

    def _rec(self, name: str, **kwargs: Any) -> None:
        self.calls.append((name, kwargs))

    def targets(self, *names: str) -> list[str]:
        return [f"{n}->{short(kw.get('vault_id'))}" for n, kw in self.calls if n in names]

    def calls_named(self, name: str) -> list[dict]:
        return [kw for n, kw in self.calls if n == name]

    def drain_device_pending_events(self) -> list:
        return []

    async def status(self) -> dict:
        return {
            "remote": {"identity": {"identity_id": "i", "trust_status": "confirmed"}},
            "local_identity": "local-fp", "fingerprint": "local-fp",
        }

    def can_create_personal_vault(self) -> bool:
        return False

    async def list_vaults(self) -> list:
        rows = [
            ("A", VAULT_A, "personal", "Personal", {"version": 1}, 2),
            ("B", VAULT_B, "team", "Platform team", {"version": 1}, 3),
            ("C", VAULT_C, "team", "Waiting team", {"version": 1}, 0),
        ]
        return [
            {"vault_id": vid, "kind": kind, "name": self.names.get(key, name), "my_role": "admin",
             "my_grant": grant, "counts": {"items": items, "open_exposures": 0}}
            for key, vid, kind, name, grant, items in rows
        ]

    async def list_items(self, *, vault_id: str, **kw: Any) -> dict:
        self._rec("list_items", vault_id=vault_id)
        return {"data": [
            {"item_id": f"{vault_id[:2]}-k{n}", "type": "ssh_key", "revision": 1,
             "public_fingerprint": f"SHA256:fp{n}"} for n in (1, 2, 3)
        ]}

    async def ssh_key_choices(self, *, vault_id: str, **kw: Any) -> list:
        return [{"item_id": f"{vault_id[:2]}-k{n}", "name": f"Key {n}"} for n in (1, 2, 3)]

    async def list_devices(self) -> list:
        names = self.device_names or ["work laptop", "build box", "old box"]
        return [
            {"device_id": "d-1", "name": names[0], "platform": "linux", "status": "active"},
            {"device_id": "d-2", "name": names[1], "platform": "linux", "status": "pending"},
            {"device_id": "d-3", "name": names[2], "platform": "linux", "status": "revoked"},
        ]

    async def get_vault(self, *, vault_id: str, **kw: Any) -> dict:
        self._rec("get_vault", vault_id=vault_id)
        return {"roster": self.members or [
            {"user_id": "u-1", "display_name": f"Owner of {vault_id[:2]}", "role": "owner",
             "status": "active", "identity": {"fingerprint": "SHA256:o"}},
            {"user_id": "u-2", "display_name": f"Pending of {vault_id[:2]}", "role": "member",
             "status": "pending", "identity": {"fingerprint": "SHA256:m"}},
        ]}

    async def list_exposures(self, *, vault_id: str, **kw: Any) -> dict:
        self._rec("list_exposures", vault_id=vault_id)
        return {"data": [
            {"exposure_id": "e-1", "item_id": f"{vault_id[:2]}-k1", "subject": "Deploy key", "reason": "shared"},
            {"exposure_id": "e-2", "item_id": f"{vault_id[:2]}-k2", "subject": "Spare key", "reason": "shared"},
        ]}

    async def rotate(self, *, vault_id: str, **kw: Any) -> str:
        self._rec("rotate", vault_id=vault_id)
        return "ok"

    async def process_grants(self, *, vault_id: str, approval: Any, **kw: Any) -> list:
        self._rec("process_grants", vault_id=vault_id)
        approved = await approval(
            {"user_id": "u-2", "display_name": f"Pending of {vault_id[:2]}", "email": "pat@example.invalid"},
            "11111 22222 33333", False,
        )
        self._rec("grant_decision", vault_id=vault_id, approved=approved)
        return [{"accepted": [1] if approved else [], "skipped": []}]

    async def show_item(self, *, vault_id: str, item_id: str, reveal: bool, **kw: Any) -> dict:
        self._rec("show_item", vault_id=vault_id, item_id=item_id)
        return {"item_id": item_id, "plaintext": {"value": "PLAINTEXT-VALUE"}}

    async def approve_device(self, *, device_id: str, confirmation: Any, **kw: Any) -> dict:
        self._rec("approve_device", device_id=device_id)
        return {"approved": await confirmation("12345 67890 11111")}

    async def resolve_exposure(self, **kw: Any) -> str:
        self._rec("resolve_exposure", **kw)
        return "ok"

    async def rotate_ssh_key(self, **kw: Any) -> dict:
        self._rec("rotate_ssh_key", **kw)
        return {"hosts": [], "rotated": True}


class VaultHost(App):
    def __init__(self, service: Any) -> None:
        self.vault_command_service = service
        self.vault_available = True
        super().__init__()

    def action_toggle_navigation(self) -> None:
        pass

    def action_toggle_chat(self) -> None:
        pass

    def on_mount(self) -> None:
        self.push_screen(VaultScreen())


def vault_screen(app: App) -> VaultScreen:
    for screen in app.screen_stack:
        if isinstance(screen, VaultScreen):
            return screen
    raise AssertionError("the vault screen is not open")


async def ready(app: App, pilot: Any) -> VaultScreen:
    await wait_until(
        lambda: isinstance(app.screen, VaultScreen) and app.screen._identity_state == "ready"
        and not app.screen._busy_work and app.screen.query_one("#vault_table", DataTable).row_count >= 3
    )
    await pilot.pause()
    return app.screen


async def settle(app: App, pilot: Any) -> None:
    screen = vault_screen(app)
    await wait_until(lambda: not screen._busy_work)
    await pilot.pause()
    await pilot.pause()


async def press(app: App, pilot: Any, button_id: str) -> None:
    button = vault_screen(app).query_one(f"#{button_id}", Button)
    button.post_message(Button.Pressed(button))
    await settle(app, pilot)


async def move_cursor(app: App, pilot: Any, row: int) -> None:
    vault_screen(app).query_one("#vault_table", DataTable).move_cursor(row=row)
    await pilot.pause()
    await pilot.pause()
