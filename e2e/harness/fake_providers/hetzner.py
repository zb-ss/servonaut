"""Hetzner Cloud API stand-in (the subset Servonaut calls), under ``/hetzner/v1``.

Response bodies follow the public API reference closely enough for the
``hcloud`` SDK to build its models: servers, server actions, SSH keys,
server types, locations, images and actions. Every action completes at
once (``status: success``), and a created server is ``running`` straight
away, so no journey waits on the SDK's polling.

Each project answers one API token, as a real project does: the primary
project answers :data:`PRIMARY_TOKEN` (the token ``HomeSeeder.hetzner_config``
writes) and :meth:`HetznerProjects.add` creates further projects with their
own tokens. A request with any other token is refused with 401.

Journeys seed a project through its :class:`HetznerState` and read back what
the product changed; the request log in ``FakeProviders`` records the calls
with the label of the project each one reached.
"""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from aiohttp import web

from e2e.harness.fake_providers.accounts import ACCOUNT, bearer_token

PREFIX = "/hetzner/v1"
CREATED_AT = "2026-01-05T10:00:00+00:00"
# The primary project, as the product labels it when nothing renames it.
PRIMARY_LABEL = "hetzner"
PRIMARY_TOKEN = "hz-fake-token"
# Ids the fake hands out (servers, SSH keys) start here in the primary
# project; each further project gets its own range, because ids are unique
# across all of Hetzner, not per project.
_FIRST_ID = 9000001
_ID_RANGE = 100000
# Action ids follow the same ranges, this far below.
_ACTION_ID_OFFSET = 2000000

# Hetzner's own vocabulary: public taxonomy, not anybody's infrastructure.
LOCATIONS = (
    {"id": 1, "name": "fsn1", "description": "Falkenstein DC Park 1", "country": "DE",
     "city": "Falkenstein", "latitude": 50.47612, "longitude": 12.370071,
     "network_zone": "eu-central"},
    {"id": 2, "name": "nbg1", "description": "Nuremberg DC Park 1", "country": "DE",
     "city": "Nuremberg", "latitude": 49.452102, "longitude": 11.076665,
     "network_zone": "eu-central"},
    {"id": 3, "name": "hel1", "description": "Helsinki DC Park 1", "country": "FI",
     "city": "Helsinki", "latitude": 60.169855, "longitude": 24.938379,
     "network_zone": "eu-central"},
)


def _price(location: str, hourly: str, monthly: str) -> dict:
    return {
        "location": location,
        "price_hourly": {"net": hourly, "gross": hourly},
        "price_monthly": {"net": monthly, "gross": monthly},
        "included_traffic": 21990232555520,
        "price_per_tb_traffic": {"net": "1.0000000000", "gross": "1.1900000000"},
    }


SERVER_TYPES = (
    {"id": 101, "name": "cx23", "description": "CX23", "cores": 2, "memory": 4.0, "disk": 40,
     "deprecated": False, "prices": [_price("fsn1", "0.0060000000", "3.7900000000")],
     "storage_type": "local", "cpu_type": "shared", "architecture": "x86", "deprecation": None},
    {"id": 102, "name": "cx32", "description": "CX32", "cores": 4, "memory": 8.0, "disk": 80,
     "deprecated": False, "prices": [_price("fsn1", "0.0110000000", "6.8000000000")],
     "storage_type": "local", "cpu_type": "shared", "architecture": "x86", "deprecation": None},
    {"id": 103, "name": "cax11", "description": "CAX11", "cores": 2, "memory": 4.0, "disk": 40,
     "deprecated": False, "prices": [_price("fsn1", "0.0060000000", "3.7900000000")],
     "storage_type": "local", "cpu_type": "shared", "architecture": "arm", "deprecation": None},
)

IMAGES = (
    {"id": 201, "type": "system", "status": "available", "name": "ubuntu-22.04",
     "description": "Ubuntu 22.04", "image_size": None, "disk_size": 5, "created": CREATED_AT,
     "created_from": None, "bound_to": None, "os_flavor": "ubuntu", "os_version": "22.04",
     "rapid_deploy": True, "protection": {"delete": False}, "deprecated": None,
     "deleted": None, "labels": {}, "architecture": "x86"},
    {"id": 202, "type": "system", "status": "available", "name": "debian-12",
     "description": "Debian 12", "image_size": None, "disk_size": 5, "created": CREATED_AT,
     "created_from": None, "bound_to": None, "os_flavor": "debian", "os_version": "12",
     "rapid_deploy": True, "protection": {"delete": False}, "deprecated": None,
     "deleted": None, "labels": {}, "architecture": "x86"},
    {"id": 203, "type": "system", "status": "available", "name": "ubuntu-24.04",
     "description": "Ubuntu 24.04", "image_size": None, "disk_size": 5, "created": CREATED_AT,
     "created_from": None, "bound_to": None, "os_flavor": "ubuntu", "os_version": "24.04",
     "rapid_deploy": True, "protection": {"delete": False}, "deprecated": None,
     "deleted": None, "labels": {}, "architecture": "arm"},
)

# Server actions the fake accepts, and the status each one leaves behind.
POWER_ACTIONS = {
    "poweron": "running",
    "poweroff": "off",
    "shutdown": "off",
    "reboot": "running",
    "reset": "running",
}


def token_for(label: str) -> str:
    """The placeholder API token of the project labelled *label*."""
    return PRIMARY_TOKEN if label == PRIMARY_LABEL else f"{PRIMARY_TOKEN}-{label}"


@dataclass(frozen=True)
class SeedServer:
    """A server to put in the fake project before a journey starts."""

    server_id: int
    name: str
    status: str  # Hetzner vocabulary: running, off, initializing, ...
    server_type: str
    location: str
    public_ip: Optional[str]
    labels: tuple[tuple[str, str], ...] = ()


class HetznerState:
    """One fake project: servers, SSH keys and the actions taken on them.

    *label* names the project in the request log; *token* is the only API
    token it answers; *first_id* starts the ids the project hands out.
    """

    def __init__(
        self, label: str = PRIMARY_LABEL, token: str = PRIMARY_TOKEN, first_id: int = _FIRST_ID
    ) -> None:
        self.label = label
        self.token = token
        self._first_id = first_id
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self.servers: dict[int, dict] = {}
            self.ssh_keys: dict[int, dict] = {}
            self.actions: dict[int, dict] = {}
            self.created_payloads: list[dict] = []
            self._ids = itertools.count(self._first_id)
            self._action_ids = itertools.count(self._first_id - _ACTION_ID_OFFSET)
            # Set to an API error code (e.g. "unauthorized") to fail every
            # call made with this project's token.
            self.fail_with: Optional[str] = None

    # ------------------------------------------------------------------
    # Seeding
    # ------------------------------------------------------------------

    def seed_servers(self, servers: Iterable[SeedServer]) -> None:
        with self._lock:
            for seed in servers:
                self.servers[seed.server_id] = _server_json(
                    seed.server_id,
                    seed.name,
                    seed.status,
                    _find(SERVER_TYPES, seed.server_type),
                    _find(LOCATIONS, seed.location),
                    seed.public_ip,
                    dict(seed.labels),
                )

    def seed_ssh_key(self, name: str, public_key: str, key_id: Optional[int] = None) -> dict:
        with self._lock:
            key_id = key_id or next(self._ids)
            key = _ssh_key_json(key_id, name, public_key)
            self.ssh_keys[key_id] = key
            return key

    # ------------------------------------------------------------------
    # Reads for assertions
    # ------------------------------------------------------------------

    def server(self, server_id: int) -> Optional[dict]:
        with self._lock:
            return self.servers.get(server_id)

    def server_named(self, name: str) -> Optional[dict]:
        with self._lock:
            return next((s for s in self.servers.values() if s["name"] == name), None)

    def key_named(self, name: str) -> Optional[dict]:
        with self._lock:
            return next((k for k in self.ssh_keys.values() if k["name"] == name), None)

    # ------------------------------------------------------------------
    # Mutations (called by the routes)
    # ------------------------------------------------------------------

    def _action(self, command: str, resource_id: int, resource_type: str = "server") -> dict:
        action_id = next(self._action_ids)
        action = {
            "id": action_id,
            "command": command,
            "status": "success",
            "progress": 100,
            "started": CREATED_AT,
            "finished": CREATED_AT,
            "resources": [{"id": resource_id, "type": resource_type}],
            "error": None,
        }
        self.actions[action_id] = action
        return action


class HetznerProjects:
    """Every fake project, found by the API token a request carries."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.primary = HetznerState()
        self._extra: dict[str, HetznerState] = {}

    def reset(self) -> None:
        """Forget the extra projects and empty the primary one."""
        with self._lock:
            self._extra.clear()
        self.primary.label, self.primary.token = PRIMARY_LABEL, PRIMARY_TOKEN
        self.primary.reset()

    def add(self, label: str, token: Optional[str] = None) -> HetznerState:
        """A further, empty project answering *token* (default :func:`token_for`)."""
        token = token or token_for(label)
        with self._lock:
            if any(p.label == label or p.token == token for p in self._all()):
                raise ValueError(f"the Hetzner fake already has a project like {label!r}")
            first_id = _FIRST_ID + _ID_RANGE * (len(self._extra) + 1)
            project = HetznerState(label, token, first_id)
            self._extra[label] = project
            return project

    def get(self, label: str) -> HetznerState:
        with self._lock:
            for project in self._all():
                if project.label == label:
                    return project
        raise KeyError(f"the Hetzner fake has no project {label!r}")

    def for_token(self, token: Optional[str]) -> Optional[HetznerState]:
        with self._lock:
            return next((p for p in self._all() if token and p.token == token), None)

    def _all(self) -> list[HetznerState]:
        return [self.primary, *self._extra.values()]


def _find(items: Iterable[dict], name: str) -> dict:
    for item in items:
        if item["name"] == name:
            return item
    raise KeyError(f"the Hetzner fake has no {name!r}")


def _server_json(
    server_id: int,
    name: str,
    status: str,
    server_type: dict,
    location: dict,
    public_ip: Optional[str],
    labels: dict,
    image: Optional[dict] = None,
) -> dict:
    ipv4 = (
        {"id": server_id + 500000, "ip": public_ip, "blocked": False, "dns_ptr": ""}
        if public_ip
        else None
    )
    return {
        "id": server_id,
        "name": name,
        "status": status,
        "created": CREATED_AT,
        "public_net": {"ipv4": ipv4, "ipv6": None, "floating_ips": [], "firewalls": []},
        "private_net": [],
        "server_type": server_type,
        # The API reports the location at the top level; the nested
        # datacenter object is deprecated but still sent.
        "location": location,
        "datacenter": {
            "id": location["id"],
            "name": f"{location['name']}-dc1",
            "description": location["description"],
            "location": location,
            "server_types": {"supported": [], "available": [], "available_for_migration": []},
        },
        "image": image or IMAGES[0],
        "iso": None,
        "rescue_enabled": False,
        "locked": False,
        "backup_window": None,
        "outgoing_traffic": 0,
        "ingoing_traffic": 0,
        "included_traffic": 21990232555520,
        "protection": {"delete": False, "rebuild": False},
        "labels": labels,
        "volumes": [],
        "load_balancers": [],
        "primary_disk_size": server_type["disk"],
        "placement_group": None,
    }


def _ssh_key_json(key_id: int, name: str, public_key: str) -> dict:
    return {
        "id": key_id,
        "name": name,
        "fingerprint": ":".join(f"{(key_id + i) % 256:02x}" for i in range(16)),
        "public_key": public_key,
        "labels": {},
        "created": CREATED_AT,
    }


def error_response(status: int, code: str, message: str) -> web.Response:
    return web.json_response(
        {"error": {"code": code, "message": message, "details": {}}}, status=status
    )


def _page(key: str, items: list) -> dict:
    return {
        key: items,
        "meta": {
            "pagination": {
                "page": 1,
                "per_page": max(len(items), 25),
                "previous_page": None,
                "next_page": None,
                "last_page": 1,
                "total_entries": len(items),
            }
        },
    }


def _by_id_or_name(items: Iterable[dict], ref: Any) -> Optional[dict]:
    for item in items:
        if item["id"] == ref or item["name"] == ref or str(item["id"]) == str(ref):
            return item
    return None


def add_routes(app: web.Application, projects: HetznerProjects) -> None:
    """Register the Hetzner routes on *app*."""

    def authenticated(handler: Any) -> Any:
        """Run *handler* for the project the request's token belongs to."""

        async def wrapper(request: web.Request) -> web.StreamResponse:
            state = projects.for_token(bearer_token(request))
            if state is None:
                return error_response(401, "unauthorized", "unable to authenticate")
            request[ACCOUNT] = state.label
            if state.fail_with:
                return error_response(401, state.fail_with, "unable to authenticate")
            return await handler(request, state)

        return wrapper

    async def list_servers(request: web.Request, state: HetznerState) -> web.Response:
        name = request.query.get("name")
        with state._lock:
            servers = [s for s in state.servers.values() if name is None or s["name"] == name]
        return web.json_response(_page("servers", servers))

    async def get_server(request: web.Request, state: HetznerState) -> web.Response:
        with state._lock:
            server = state.servers.get(int(request.match_info["server_id"]))
        if server is None:
            return error_response(404, "not_found", "server not found")
        return web.json_response({"server": server})

    async def create_server(request: web.Request, state: HetznerState) -> web.Response:
        body = await request.json()
        with state._lock:
            if any(s["name"] == body.get("name") for s in state.servers.values()):
                return error_response(409, "uniqueness_error", "server name is already used")
            server_type = _by_id_or_name(SERVER_TYPES, body.get("server_type"))
            image = _by_id_or_name(IMAGES, body.get("image"))
            location = _by_id_or_name(LOCATIONS, body.get("location") or "fsn1")
            if server_type is None or image is None or location is None:
                return error_response(422, "invalid_input", "unknown server type, image or location")
            missing = [
                ref for ref in body.get("ssh_keys") or []
                if _by_id_or_name(state.ssh_keys.values(), ref) is None
            ]
            if missing:
                return error_response(422, "invalid_input", "unknown ssh key")
            server_id = next(state._ids)
            server = _server_json(
                server_id,
                body["name"],
                "running",
                server_type,
                location,
                # A fresh address from the documentation range: nothing real.
                f"192.0.2.{server_id % 200 + 20}",
                body.get("labels") or {},
                image,
            )
            state.servers[server_id] = server
            state.created_payloads.append(body)
            action = state._action("create_server", server_id)
        return web.json_response(
            {"server": server, "action": action, "next_actions": [], "root_password": None},
            status=201,
        )

    async def delete_server(request: web.Request, state: HetznerState) -> web.Response:
        server_id = int(request.match_info["server_id"])
        with state._lock:
            if state.servers.pop(server_id, None) is None:
                return error_response(404, "not_found", "server not found")
            action = state._action("delete_server", server_id)
        return web.json_response({"action": action})

    async def server_action(request: web.Request, state: HetznerState) -> web.Response:
        server_id = int(request.match_info["server_id"])
        verb = request.match_info["verb"]
        if verb not in POWER_ACTIONS:
            return error_response(404, "not_found", f"action {verb} not provided by the fake")
        with state._lock:
            server = state.servers.get(server_id)
            if server is None:
                return error_response(404, "not_found", "server not found")
            server["status"] = POWER_ACTIONS[verb]
            action = state._action(f"{verb}_server", server_id)
        return web.json_response({"action": action}, status=201)

    async def get_action(request: web.Request, state: HetznerState) -> web.Response:
        with state._lock:
            action = state.actions.get(int(request.match_info["action_id"]))
        if action is None:
            return error_response(404, "not_found", "action not found")
        return web.json_response({"action": action})

    async def list_ssh_keys(request: web.Request, state: HetznerState) -> web.Response:
        name = request.query.get("name")
        with state._lock:
            keys = [k for k in state.ssh_keys.values() if name is None or k["name"] == name]
        return web.json_response(_page("ssh_keys", keys))

    async def get_ssh_key(request: web.Request, state: HetznerState) -> web.Response:
        with state._lock:
            key = state.ssh_keys.get(int(request.match_info["key_id"]))
        if key is None:
            return error_response(404, "not_found", "ssh key not found")
        return web.json_response({"ssh_key": key})

    async def create_ssh_key(request: web.Request, state: HetznerState) -> web.Response:
        body = await request.json()
        with state._lock:
            if any(k["name"] == body.get("name") for k in state.ssh_keys.values()):
                return error_response(409, "uniqueness_error", "SSH key with the same name already exists")
            if any(k["public_key"] == body.get("public_key") for k in state.ssh_keys.values()):
                return error_response(409, "uniqueness_error", "SSH key with the same fingerprint already exists")
            key_id = next(state._ids)
            key = _ssh_key_json(key_id, body["name"], body["public_key"])
            state.ssh_keys[key_id] = key
        return web.json_response({"ssh_key": key}, status=201)

    async def delete_ssh_key(request: web.Request, state: HetznerState) -> web.Response:
        with state._lock:
            if state.ssh_keys.pop(int(request.match_info["key_id"]), None) is None:
                return error_response(404, "not_found", "ssh key not found")
        return web.Response(status=204)

    def static_list(key: str, items: tuple) -> Any:
        async def handler(request: web.Request, state: HetznerState) -> web.Response:
            selected = list(items)
            for field in ("type", "architecture", "name"):
                wanted = request.query.getall(field, [])
                if wanted:
                    selected = [item for item in selected if str(item.get(field)) in wanted]
            return web.json_response(_page(key, selected))

        return handler

    routes: list[tuple[str, str, Any]] = [
        ("GET", "/servers", list_servers),
        ("POST", "/servers", create_server),
        ("GET", "/servers/{server_id:\\d+}", get_server),
        ("DELETE", "/servers/{server_id:\\d+}", delete_server),
        ("POST", "/servers/{server_id:\\d+}/actions/{verb}", server_action),
        ("GET", "/actions/{action_id:\\d+}", get_action),
        ("GET", "/ssh_keys", list_ssh_keys),
        ("POST", "/ssh_keys", create_ssh_key),
        ("GET", "/ssh_keys/{key_id:\\d+}", get_ssh_key),
        ("DELETE", "/ssh_keys/{key_id:\\d+}", delete_ssh_key),
        ("GET", "/server_types", static_list("server_types", SERVER_TYPES)),
        ("GET", "/locations", static_list("locations", LOCATIONS)),
        ("GET", "/images", static_list("images", IMAGES)),
    ]
    for method, path, handler in routes:
        app.router.add_route(method, f"{PREFIX}{path}", authenticated(handler))
