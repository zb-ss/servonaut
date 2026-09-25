"""OVHcloud API stand-in (the subset Servonaut calls), under ``/ovh/1.0``.

python-ovh signs every request; the fake accepts any signature and answers
``/auth/time`` so the client can compute its clock delta. Resources live in
:class:`OvhState`: VPS (with their IP details, snapshot and backup options),
dedicated servers, Public Cloud projects (instances, flavors, images,
regions, SSH keys, snapshots and volumes), VPS reinstall images and upgrade
plans, DNS zones and records, IP blocks
(reverse DNS and firewall), account SSH keys, and bills. Tasks complete at
once. Error bodies use the API's ``{"message": ...}`` shape, which python-ovh
turns into its typed exceptions.

Journeys seed an account through the ``seed_*`` methods and read back what
the product changed; ``FakeProviders.requests("ovh", ...)`` records the calls.
"""

from __future__ import annotations

import itertools
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

from aiohttp import web

PREFIX = "/ovh/1.0"
CREATED_AT = "2026-01-05T10:00:00+00:00"
# Account handle for GET /me. Deliberately no e-mail address.
NIC_HANDLE = "ee00000-ovh"
# Deterministic namespace for runtime-generated UUIDs (no UUID literals in
# committed fixtures).
_UUID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "servonaut-e2e.test")

VPS_ACTIONS = {"start": "running", "stop": "stopped", "reboot": "running"}
CLOUD_ACTIONS = {"start": "ACTIVE", "stop": "SHUTOFF", "reboot": "ACTIVE"}
_NOT_FOUND = "The requested object does not exist"


def runtime_uuid(label: str) -> str:
    """A stable UUID derived from *label*, built at run time."""
    return str(uuid.uuid5(_UUID_NAMESPACE, label))


@dataclass(frozen=True)
class SeedVps:
    service_name: str  # the API id, hostname-shaped
    display_name: str
    state: str  # running | stopped | installing | ...
    model: str
    zone: str
    ips: tuple[str, ...]


@dataclass(frozen=True)
class SeedDedicated:
    service_name: str
    reverse: str
    state: str  # ok | hacked | ...
    datacenter: str
    ips: tuple[str, ...]
    os: str = "debian12_64"


@dataclass(frozen=True)
class SeedCloudInstance:
    name: str
    status: str  # ACTIVE | SHUTOFF | BUILD | ...
    region: str
    public_ip: Optional[str]
    private_ip: Optional[str] = None
    flavor: str = "b3-8"

    @property
    def instance_id(self) -> str:
        return runtime_uuid(f"cloud-instance:{self.name}")


@dataclass(frozen=True)
class SeedDnsRecord:
    field_type: str  # A, AAAA, CNAME, MX, TXT, ...
    sub_domain: str  # "" for the zone apex
    target: str
    ttl: int = 3600


@dataclass(frozen=True)
class SeedFirewallRule:
    sequence: int
    action: str  # permit | deny
    protocol: str  # tcp | udp | icmp
    port: Optional[str] = None  # destination port, e.g. "22"
    source: Optional[str] = None  # CIDR, None = any


@dataclass(frozen=True)
class SeedBill:
    bill_id: str
    date: str  # ISO date
    amount: float
    currency: str = "EUR"


@dataclass
class CloudProject:
    project_id: str
    description: str
    instances: dict[str, dict] = field(default_factory=dict)
    ssh_keys: dict[str, dict] = field(default_factory=dict)
    snapshots: dict[str, dict] = field(default_factory=dict)
    volumes: dict[str, dict] = field(default_factory=dict)


FLAVORS = (
    {"name": "b3-8", "vcpus": 2, "ram": 8, "disk": 50, "type": "ovh.ssd.gen",
     "osType": "linux", "available": True, "region": "GRA7",
     "monthly": {"text": "25.00 EUR", "currencyCode": "EUR"}},
    {"name": "d2-2", "vcpus": 1, "ram": 2, "disk": 25, "type": "ovh.ssd.eg",
     "osType": "linux", "available": True, "region": "GRA7",
     "monthly": {"text": "5.00 EUR", "currencyCode": "EUR"}},
)
IMAGES = (
    {"name": "Ubuntu 24.04", "type": "linux", "status": "active", "region": "GRA7",
     "visibility": "public", "size": 3.5, "minDisk": 0, "minRam": 0, "user": "ubuntu"},
    {"name": "Debian 12", "type": "linux", "status": "active", "region": "GRA7",
     "visibility": "public", "size": 2.5, "minDisk": 0, "minRam": 0, "user": "debian"},
)
REGIONS = ("GRA7", "SBG5")
# What any fake VPS can be reinstalled with, or upgraded to.
VPS_IMAGES = (
    {"name": "Debian 12", "os": "linux"},
    {"name": "Ubuntu 24.04", "os": "linux"},
)
VPS_UPGRADES = (
    {"name": "vps-value-2-4-80", "vcores": 2, "memory": 4096, "disk": 80,
     "price": "12.00 EUR"},
)


def vps_image_id(name: str) -> str:
    """The id the fake gives the VPS reinstall image *name*."""
    return runtime_uuid(f"vps-image:{name}")


def flavor_id(name: str) -> str:
    """The id the fake gives the Public Cloud flavor *name*."""
    flavor = next(f for f in FLAVORS if f["name"] == name)
    return runtime_uuid(f"{flavor['type']}:{name}")


def image_id(name: str) -> str:
    """The id the fake gives the Public Cloud image *name*."""
    image = next(i for i in IMAGES if i["name"] == name)
    return runtime_uuid(f"{image['type']}:{name}")


class OvhState:
    """The fake OVH account."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self.vps: dict[str, dict] = {}
            self.dedicated: dict[str, dict] = {}
            self.projects: dict[str, CloudProject] = {}
            self.zones: dict[str, dict[int, dict]] = {}
            self.ip_blocks: dict[str, dict] = {}
            # block -> {ip: reverse hostname}
            self.reverses: dict[str, dict[str, str]] = {}
            # ip on firewall -> {"enabled": bool, "rules": {sequence: rule}}
            self.firewalls: dict[str, dict] = {}
            self.account_ssh_keys: dict[str, dict] = {}
            self.bills: dict[str, dict] = {}
            self.usage_current: dict = {}
            self.usage_forecast: dict = {}
            self.tasks: list[dict] = []
            self._task_ids = itertools.count(88000001)
            self._record_ids = itertools.count(5000001)
            # Set to an OVH errorCode (e.g. "INVALID_CREDENTIAL") to refuse
            # every authenticated call with 403.
            self.fail_with: Optional[str] = None

    # ------------------------------------------------------------------
    # Seeding: servers
    # ------------------------------------------------------------------

    def seed_vps(self, items: Iterable[SeedVps]) -> None:
        with self._lock:
            for seed in items:
                self.vps[seed.service_name] = {
                    "detail": {
                        "name": seed.service_name,
                        "displayName": seed.display_name,
                        "state": seed.state,
                        "zone": seed.zone,
                        "model": {"name": seed.model, "memory": 4096, "disk": 80,
                                  "vcore": 2, "offer": "VPS", "version": "2019v1"},
                        "netbootMode": "local",
                        "offerType": "cloud",
                        "memoryLimit": 4096,
                        "vcore": 2,
                        "cluster": "",
                        "slaMonitoring": False,
                        "monitoringIpBlocks": [],
                        "keymap": None,
                    },
                    "ips": list(seed.ips),
                    "reverse": {},
                    "snapshot": None,
                    "backup": {"schedule": None, "state": "disabled", "rotation": 7},
                }

    def seed_dedicated(self, items: Iterable[SeedDedicated]) -> None:
        with self._lock:
            for seed in items:
                self.dedicated[seed.service_name] = {
                    "detail": {
                        "name": seed.service_name,
                        "serverId": 100000 + len(self.dedicated),
                        "reverse": seed.reverse,
                        "state": seed.state,
                        "datacenter": seed.datacenter,
                        "os": seed.os,
                        "ip": seed.ips[0] if seed.ips else None,
                        "rack": "E2E01",
                        "monitoring": True,
                        "professionalUse": False,
                        "supportLevel": "pro",
                        "commercialRange": "advance",
                        "bootId": 1,
                    },
                    "specs": {
                        "description": "ADVANCE-1",
                        "numberOfProcessors": 1,
                        "coresPerProcessor": 8,
                        "numberOfCores": 8,
                        "memorySize": {"unit": "MB", "value": 65536},
                        "processorName": "fake-cpu",
                    },
                    "ips": list(seed.ips),
                }

    def seed_cloud_project(
        self, project_id: str, instances: Iterable[SeedCloudInstance], description: str = "e2e"
    ) -> CloudProject:
        with self._lock:
            project = self.projects.setdefault(project_id, CloudProject(project_id, description))
            for seed in instances:
                project.instances[seed.instance_id] = _cloud_instance_json(
                    seed.instance_id, seed.name, seed.status, seed.region,
                    seed.public_ip, seed.private_ip, seed.flavor,
                )
            return project

    def seed_vps_reverse(self, service_name: str, ip: str, reverse: str) -> None:
        """Reverse DNS of one VPS address (``GET /vps/{name}/ips/{ip}``)."""
        with self._lock:
            self.vps[service_name]["reverse"][ip] = reverse

    def seed_vps_snapshot(self, service_name: str, description: str = "") -> str:
        """Give a VPS its (single) snapshot; returns the snapshot id."""
        with self._lock:
            snapshot_id = runtime_uuid(f"vps-snapshot:{service_name}")
            self.vps[service_name]["snapshot"] = {
                "id": snapshot_id,
                "description": description,
                "creationDate": CREATED_AT,
                "region": "os-gra7",
            }
            return snapshot_id

    def seed_project_ssh_key(self, project_id: str, name: str, public_key: str) -> str:
        """Register an SSH key with a Public Cloud project; returns its id."""
        with self._lock:
            key_id = _key_id(name)
            self.projects[project_id].ssh_keys[key_id] = _project_key_json(key_id, name, public_key)
            return key_id

    def seed_cloud_snapshot(self, project_id: str, name: str, region: str = "GRA7") -> str:
        """A Public Cloud instance snapshot (an image); returns its id."""
        with self._lock:
            snapshot_id = runtime_uuid(f"cloud-snapshot:{name}")
            self.projects[project_id].snapshots[snapshot_id] = {
                "id": snapshot_id, "name": name, "region": region, "status": "active",
                "creationDate": CREATED_AT, "size": 2.5, "type": "linux",
                "visibility": "private", "minDisk": 50,
            }
            return snapshot_id

    def seed_volume(
        self, project_id: str, name: str, size_gb: int, region: str = "GRA7",
        attached_to: Iterable[str] = (),
    ) -> str:
        """A Public Cloud block-storage volume; returns its id."""
        with self._lock:
            volume_id = runtime_uuid(f"volume:{name}")
            self.projects[project_id].volumes[volume_id] = {
                "id": volume_id, "name": name, "size": size_gb, "region": region,
                "status": "in-use" if attached_to else "available",
                "type": "classic", "description": "", "bootable": False,
                "attachedTo": list(attached_to), "creationDate": CREATED_AT,
            }
            return volume_id

    # ------------------------------------------------------------------
    # Seeding: DNS, IPs, keys, billing
    # ------------------------------------------------------------------

    def seed_dns_zone(self, zone: str, records: Iterable[SeedDnsRecord] = ()) -> list[int]:
        """A DNS zone with *records*; returns the record ids in order."""
        with self._lock:
            table = self.zones.setdefault(zone, {})
            ids = []
            for seed in records:
                record_id = next(self._record_ids)
                table[record_id] = {
                    "id": record_id, "zone": zone, "fieldType": seed.field_type,
                    "subDomain": seed.sub_domain, "target": seed.target, "ttl": seed.ttl,
                }
                ids.append(record_id)
            return ids

    def seed_ip_block(
        self,
        block: str,
        *,
        ip_type: str = "failover",
        routed_to: Optional[str] = None,
        reverse: Optional[Mapping[str, str]] = None,
    ) -> None:
        """An IP block (``1.0.0.1/32``) with its routing and reverse DNS."""
        with self._lock:
            self.ip_blocks[block] = {
                "ip": block,
                "type": ip_type,
                "routedTo": {"serviceName": routed_to} if routed_to else None,
                "country": "fr",
                "description": None,
                "canBeTerminated": ip_type == "failover",
                "organisationId": None,
            }
            self.reverses[block] = dict(reverse or {})

    def seed_firewall(
        self, ip: str, *, enabled: bool = True, rules: Iterable[SeedFirewallRule] = ()
    ) -> None:
        """The OVH network firewall in front of *ip*, with its rules."""
        with self._lock:
            self.firewalls[ip] = {
                "enabled": enabled,
                "rules": {rule.sequence: _rule_json(ip, _rule_body(rule)) for rule in rules},
            }

    def seed_account_ssh_key(self, name: str, public_key: str, default: bool = False) -> None:
        """An SSH key on the account itself (``/me/sshKey``)."""
        with self._lock:
            self.account_ssh_keys[name] = {"keyName": name, "key": public_key, "default": default}

    def seed_bills(self, bills: Iterable[SeedBill]) -> None:
        with self._lock:
            for bill in bills:
                price = {"value": bill.amount, "currencyCode": bill.currency,
                         "text": f"{bill.amount:.2f} {bill.currency}"}
                self.bills[bill.bill_id] = {
                    "billId": bill.bill_id, "date": f"{bill.date}T00:00:00+00:00",
                    "priceWithTax": price, "priceWithoutTax": price,
                    "tax": {"value": 0.0, "currencyCode": bill.currency, "text": "0.00"},
                    "pdfUrl": "", "url": "", "orderId": 1,
                }

    def set_usage(self, current: float, forecast: float, currency: str = "EUR") -> None:
        """Current and forecast consumption for the month."""
        with self._lock:
            for target, value in ((self.usage_current, current), (self.usage_forecast, forecast)):
                target.clear()
                target.update({
                    "beginDate": "2026-09-01", "endDate": "2026-09-30",
                    "lastUpdate": CREATED_AT,
                    "price": {"value": value, "currencyCode": currency},
                })

    # ------------------------------------------------------------------
    # Reads for assertions
    # ------------------------------------------------------------------

    def vps_state(self, service_name: str) -> str:
        with self._lock:
            return self.vps[service_name]["detail"]["state"]

    def vps_snapshot(self, service_name: str) -> Optional[dict]:
        with self._lock:
            return self.vps[service_name]["snapshot"]

    def cloud_instance(self, project_id: str, instance_id: str) -> Optional[dict]:
        with self._lock:
            return self.projects[project_id].instances.get(instance_id)

    def dns_records(self, zone: str) -> list[dict]:
        with self._lock:
            return [dict(record) for record in self.zones[zone].values()]

    def reverse_of(self, block: str, ip: str) -> Optional[str]:
        with self._lock:
            return self.reverses.get(block, {}).get(ip)

    def firewall(self, ip: str) -> dict:
        with self._lock:
            state = self.firewalls[ip]
            return {"enabled": state["enabled"], "rules": dict(state["rules"])}

    def project_ssh_keys(self, project_id: str) -> list[dict]:
        with self._lock:
            return list(self.projects[project_id].ssh_keys.values())

    # ------------------------------------------------------------------
    # Helpers for the routes
    # ------------------------------------------------------------------

    def task(self, function: str) -> dict:
        task = {
            "id": next(self._task_ids),
            "function": function,
            "state": "done",
            "progress": 100,
            "startDate": CREATED_AT,
            "doneDate": CREATED_AT,
            "lastUpdate": CREATED_AT,
            "comment": None,
        }
        self.tasks.append(task)
        return task


def _key_id(name: str) -> str:
    # Project SSH-key ids are opaque strings; derive one from the name.
    return runtime_uuid(f"ssh-key:{name}").replace("-", "")[:24]


def _project_key_json(key_id: str, name: str, public_key: str) -> dict:
    return {
        "id": key_id,
        "name": name,
        "publicKey": public_key,
        "fingerPrint": ":".join(f"{b:02x}" for b in uuid.UUID(runtime_uuid(name)).bytes),
        "regions": list(REGIONS),
    }


def _rule_body(rule: SeedFirewallRule) -> dict:
    body: dict[str, Any] = {
        "sequence": rule.sequence, "action": rule.action, "protocol": rule.protocol,
    }
    if rule.port:
        body["destinationPort"] = rule.port
    if rule.source:
        body["source"] = rule.source
    return body


def _rule_json(ip: str, body: Mapping[str, Any]) -> dict:
    port = body.get("destinationPort")
    return {
        "sequence": int(body["sequence"]),
        "action": body["action"],
        "protocol": body["protocol"],
        "source": body.get("source") or "any",
        "destination": f"{ip}/32",
        "destinationPort": f"eq {port}" if port else None,
        "sourcePort": None,
        "state": "ok",
        "fragments": None,
        "tcpOption": None,
        "creationDate": CREATED_AT,
        "rule": f"{body['action']} {body['protocol']}",
    }


def _cloud_instance_json(
    instance_id: str,
    name: str,
    status: str,
    region: str,
    public_ip: Optional[str],
    private_ip: Optional[str],
    flavor: str,
) -> dict:
    addresses = []
    if public_ip:
        addresses.append({"ip": public_ip, "type": "public", "version": 4,
                          "networkId": runtime_uuid("net:ext"), "gatewayIp": None})
    if private_ip:
        addresses.append({"ip": private_ip, "type": "private", "version": 4,
                          "networkId": runtime_uuid("net:priv"), "gatewayIp": None})
    return {
        "id": instance_id,
        "name": name,
        "ipAddresses": addresses,
        "flavorId": flavor,
        "imageId": runtime_uuid(f"image:{IMAGES[0]['name']}"),
        "sshKeyId": None,
        "created": CREATED_AT,
        "region": region,
        "monthlyBilling": None,
        "status": status,
        "planCode": f"{flavor}.consumption",
        "operationIds": [],
        "currentMonthOutgoingTraffic": None,
    }


def error_response(status: int, message: str, error_code: Optional[str] = None) -> web.Response:
    body: dict[str, Any] = {"message": message}
    if error_code:
        body["errorCode"] = error_code
    return web.json_response(body, status=status)


def _not_found() -> web.Response:
    return error_response(404, _NOT_FOUND)


def add_routes(app: web.Application, state: OvhState) -> None:  # noqa: C901 - a route table
    """Register the OVH routes on *app*."""

    def guarded(handler: Any) -> Any:
        """Refuse every authenticated call while ``state.fail_with`` is set."""

        async def wrapper(request: web.Request) -> web.StreamResponse:
            if state.fail_with:
                return error_response(403, "This credential is not valid", state.fail_with)
            return await handler(request)

        return wrapper

    def ok(payload: Any) -> web.Response:
        return web.json_response(payload)

    async def body_of(request: web.Request) -> dict:
        # read() is cached: the logging middleware has usually consumed the
        # stream already, so can_read_body is no guide here.
        raw = await request.read()
        return json.loads(raw) if raw else {}

    async def auth_time(request: web.Request) -> web.Response:
        return ok(int(time.time()))

    async def me(request: web.Request) -> web.Response:
        return ok({"nichandle": NIC_HANDLE, "firstname": "E2E", "name": "Account",
                   "country": "FR", "currency": {"code": "EUR", "symbol": "EURO"},
                   "ovhSubsidiary": "FR", "state": "complete"})

    # ---- VPS --------------------------------------------------------------

    def _vps(request: web.Request) -> Optional[dict]:
        return state.vps.get(request.match_info["name"])

    async def list_vps(request: web.Request) -> web.Response:
        with state._lock:
            return ok(sorted(state.vps))

    async def get_vps(request: web.Request) -> web.Response:
        with state._lock:
            vps = _vps(request)
            return ok(vps["detail"]) if vps else _not_found()

    async def vps_ips(request: web.Request) -> web.Response:
        with state._lock:
            vps = _vps(request)
            return ok(vps["ips"]) if vps else _not_found()

    async def vps_ip_detail(request: web.Request) -> web.Response:
        ip = request.match_info["ip"]
        with state._lock:
            vps = _vps(request)
            if vps is None or ip not in vps["ips"]:
                return _not_found()
            return ok({"ipAddress": ip, "reverse": vps["reverse"].get(ip), "type": "primary",
                       "version": "v6" if ":" in ip else "v4", "gateway": None,
                       "macAddress": None, "geolocation": "fr"})

    async def vps_set_reverse(request: web.Request) -> web.Response:
        ip = request.match_info["ip"]
        body = await body_of(request)
        with state._lock:
            vps = _vps(request)
            if vps is None or ip not in vps["ips"]:
                return _not_found()
            vps["reverse"][ip] = body.get("reverse")
        return ok(None)

    async def vps_action(request: web.Request) -> web.Response:
        verb = request.match_info["verb"]
        with state._lock:
            vps = _vps(request)
            if vps is None:
                return _not_found()
            vps["detail"]["state"] = VPS_ACTIONS[verb]
            return ok(state.task(f"{verb}VM"))

    async def vps_snapshot(request: web.Request) -> web.Response:
        with state._lock:
            vps = _vps(request)
            if vps is None or vps["snapshot"] is None:
                return _not_found()
            return ok(vps["snapshot"])

    async def vps_delete_snapshot(request: web.Request) -> web.Response:
        with state._lock:
            vps = _vps(request)
            if vps is None or vps["snapshot"] is None:
                return _not_found()
            vps["snapshot"] = None
            return ok(state.task("deleteSnapshot"))

    async def vps_create_snapshot(request: web.Request) -> web.Response:
        body = await body_of(request)
        with state._lock:
            vps = _vps(request)
            if vps is None:
                return _not_found()
            if vps["snapshot"] is not None:
                return error_response(409, "A snapshot already exists for this VPS")
            vps["snapshot"] = {
                "id": runtime_uuid(f"vps-snapshot:{request.match_info['name']}"),
                "description": body.get("description") or "",
                "creationDate": CREATED_AT,
                "region": "os-gra7",
            }
            return ok(state.task("createSnapshot"))

    async def vps_revert_snapshot(request: web.Request) -> web.Response:
        with state._lock:
            vps = _vps(request)
            snapshot = vps["snapshot"] if vps else None
            if snapshot is None or snapshot["id"] != request.match_info["snapshot_id"]:
                return _not_found()
            return ok(state.task("revertSnapshot"))

    async def vps_backup(request: web.Request) -> web.Response:
        with state._lock:
            vps = _vps(request)
            return ok(vps["backup"]) if vps else _not_found()

    async def vps_images(request: web.Request) -> web.Response:
        with state._lock:
            if _vps(request) is None:
                return _not_found()
        return ok([vps_image_id(image["name"]) for image in VPS_IMAGES])

    async def vps_image(request: web.Request) -> web.Response:
        for image in VPS_IMAGES:
            if vps_image_id(image["name"]) == request.match_info["image_id"]:
                return ok({"id": request.match_info["image_id"], **image})
        return _not_found()

    async def vps_reinstall(request: web.Request) -> web.Response:
        body = await body_of(request)
        with state._lock:
            vps = _vps(request)
            if vps is None:
                return _not_found()
            if body.get("imageId") not in {vps_image_id(i["name"]) for i in VPS_IMAGES}:
                return error_response(400, "Invalid image")
            vps["detail"]["state"] = "installing"
            return ok(state.task("reinstallVm"))

    async def vps_upgrades(request: web.Request) -> web.Response:
        with state._lock:
            if _vps(request) is None:
                return _not_found()
        return ok([dict(model) for model in VPS_UPGRADES])

    async def vps_change(request: web.Request) -> web.Response:
        body = await body_of(request)
        with state._lock:
            vps = _vps(request)
            if vps is None:
                return _not_found()
            if body.get("model") not in {m["name"] for m in VPS_UPGRADES}:
                return error_response(400, "Invalid model")
            vps["detail"]["model"]["name"] = body["model"]
            return ok(state.task("changeModel"))

    def service_infos(kind: str) -> Any:
        async def handler(request: web.Request) -> web.Response:
            with state._lock:
                table = state.vps if kind == "vps" else state.dedicated
                name = request.match_info["name"]
                if name not in table:
                    return _not_found()
            return ok({"domain": name, "status": "ok", "creation": "2025-01-05",
                       "expiration": "2027-01-05", "renew": {"automatic": True}})

        return handler

    # ---- Dedicated --------------------------------------------------------

    def _dedicated(request: web.Request) -> Optional[dict]:
        return state.dedicated.get(request.match_info["name"])

    async def list_dedicated(request: web.Request) -> web.Response:
        with state._lock:
            return ok(sorted(state.dedicated))

    def dedicated_part(part: str) -> Any:
        async def handler(request: web.Request) -> web.Response:
            with state._lock:
                server = _dedicated(request)
                return ok(server[part]) if server else _not_found()

        return handler

    async def dedicated_reboot(request: web.Request) -> web.Response:
        with state._lock:
            if _dedicated(request) is None:
                return _not_found()
            return ok(state.task("hardReboot"))

    # ---- Public Cloud -------------------------------------------------------

    def _project(request: web.Request) -> Optional[CloudProject]:
        return state.projects.get(request.match_info["project_id"])

    async def list_projects(request: web.Request) -> web.Response:
        with state._lock:
            return ok(sorted(state.projects))

    async def get_project(request: web.Request) -> web.Response:
        with state._lock:
            project = _project(request)
            if project is None:
                return _not_found()
            return ok({"project_id": project.project_id, "projectName": project.description,
                       "description": project.description, "status": "ok",
                       "planCode": "project.2018", "creationDate": CREATED_AT})

    async def list_instances(request: web.Request) -> web.Response:
        with state._lock:
            project = _project(request)
            return ok(list(project.instances.values())) if project else _not_found()

    async def get_instance(request: web.Request) -> web.Response:
        with state._lock:
            project = _project(request)
            instance = project.instances.get(request.match_info["instance_id"]) if project else None
            return ok(instance) if instance else _not_found()

    async def delete_instance(request: web.Request) -> web.Response:
        with state._lock:
            project = _project(request)
            if project is None or project.instances.pop(
                request.match_info["instance_id"], None
            ) is None:
                return _not_found()
        return ok(None)

    async def instance_action(request: web.Request) -> web.Response:
        verb = request.match_info["verb"]
        with state._lock:
            project = _project(request)
            instance = project.instances.get(request.match_info["instance_id"]) if project else None
            if instance is None:
                return _not_found()
            instance["status"] = CLOUD_ACTIONS[verb]
        return ok(None)

    async def instance_snapshot(request: web.Request) -> web.Response:
        body = await body_of(request)
        name = body.get("snapshotName") or ""
        with state._lock:
            project = _project(request)
            instance = project.instances.get(request.match_info["instance_id"]) if project else None
            if instance is None:
                return _not_found()
            snapshot_id = runtime_uuid(f"cloud-snapshot:{name}")
            project.snapshots[snapshot_id] = {
                "id": snapshot_id, "name": name, "region": instance["region"],
                "status": "queued", "creationDate": CREATED_AT, "size": 0,
                "type": "linux", "visibility": "private", "minDisk": 50,
            }
        return ok(None)

    async def create_instance(request: web.Request) -> web.Response:
        body = await body_of(request)
        with state._lock:
            project = _project(request)
            if project is None:
                return _not_found()
            instance_id = runtime_uuid(f"cloud-instance:{body.get('name')}")
            instance = _cloud_instance_json(
                instance_id, body.get("name", ""), "BUILD", body.get("region", ""),
                None, None, str(body.get("flavorId", "")),
            )
            project.instances[instance_id] = instance
            return ok(instance)

    def static_list(items: tuple) -> Any:
        async def handler(request: web.Request) -> web.Response:
            if _project(request) is None:
                return _not_found()
            region = request.query.get("region")
            out = []
            for item in items:
                if region and item.get("region") not in (None, region):
                    continue
                entry = dict(item)
                entry["id"] = runtime_uuid(f"{entry.get('type')}:{entry['name']}")
                out.append(entry)
            return ok(out)

        return handler

    async def list_regions(request: web.Request) -> web.Response:
        return ok(list(REGIONS))

    def project_collection(attribute: str) -> Any:
        async def handler(request: web.Request) -> web.Response:
            with state._lock:
                project = _project(request)
                if project is None:
                    return _not_found()
                return ok(list(getattr(project, attribute).values()))

        return handler

    async def add_project_key(request: web.Request) -> web.Response:
        body = await body_of(request)
        with state._lock:
            project = _project(request)
            if project is None:
                return _not_found()
            name = body.get("name", "")
            if any(k["name"] == name for k in project.ssh_keys.values()):
                return error_response(409, "An SSH key with this name already exists")
            key = _project_key_json(_key_id(name), name, body.get("publicKey", ""))
            project.ssh_keys[key["id"]] = key
            return ok(key)

    def delete_project_item(attribute: str, key: str) -> Any:
        async def handler(request: web.Request) -> web.Response:
            with state._lock:
                project = _project(request)
                if project is None or getattr(project, attribute).pop(
                    request.match_info[key], None
                ) is None:
                    return _not_found()
            return ok(None)

        return handler

    async def cloud_usage(request: web.Request) -> web.Response:
        if _project(request) is None:
            return _not_found()
        return ok({"hourlyUsage": {"instance": [], "storage": []},
                   "monthlyUsage": {"instance": []}})

    # ---- DNS --------------------------------------------------------------

    def _zone(request: web.Request) -> Optional[dict[int, dict]]:
        return state.zones.get(request.match_info["zone"])

    async def list_zones(request: web.Request) -> web.Response:
        with state._lock:
            return ok(sorted(state.zones))

    async def get_zone(request: web.Request) -> web.Response:
        zone = request.match_info["zone"]
        with state._lock:
            if zone not in state.zones:
                return _not_found()
        return ok({"name": zone, "dnssecSupported": True, "hasDnsAnycast": False,
                   "nameServers": [f"ns1.{zone}", f"ns2.{zone}"], "lastUpdate": CREATED_AT})

    async def list_records(request: web.Request) -> web.Response:
        field_type = request.query.get("fieldType")
        sub_domain = request.query.get("subDomain")
        with state._lock:
            records = _zone(request)
            if records is None:
                return _not_found()
            return ok([
                record_id for record_id, record in records.items()
                if (field_type is None or record["fieldType"] == field_type)
                and (sub_domain is None or record["subDomain"] == sub_domain)
            ])

    async def get_record(request: web.Request) -> web.Response:
        with state._lock:
            records = _zone(request)
            record = records.get(int(request.match_info["record_id"])) if records else None
            return ok(record) if record else _not_found()

    async def create_record(request: web.Request) -> web.Response:
        body = await body_of(request)
        zone = request.match_info["zone"]
        with state._lock:
            records = _zone(request)
            if records is None:
                return _not_found()
            record_id = next(state._record_ids)
            record = {"id": record_id, "zone": zone, "fieldType": body.get("fieldType"),
                      "subDomain": body.get("subDomain") or "", "target": body.get("target"),
                      "ttl": body.get("ttl", 3600)}
            records[record_id] = record
            return ok(record)

    async def update_record(request: web.Request) -> web.Response:
        body = await body_of(request)
        with state._lock:
            records = _zone(request)
            record = records.get(int(request.match_info["record_id"])) if records else None
            if record is None:
                return _not_found()
            for key in ("subDomain", "target", "ttl"):
                if key in body:
                    record[key] = body[key]
        return ok(None)

    async def delete_record(request: web.Request) -> web.Response:
        with state._lock:
            records = _zone(request)
            if records is None or records.pop(int(request.match_info["record_id"]), None) is None:
                return _not_found()
        return ok(None)

    async def refresh_zone(request: web.Request) -> web.Response:
        with state._lock:
            if _zone(request) is None:
                return _not_found()
        return ok(None)

    # ---- IPs: blocks, reverse DNS, firewall ---------------------------------

    async def list_ip_blocks(request: web.Request) -> web.Response:
        with state._lock:
            return ok(sorted(state.ip_blocks))

    async def get_ip_block(request: web.Request) -> web.Response:
        with state._lock:
            block = state.ip_blocks.get(request.match_info["block"])
            return ok(block) if block else _not_found()

    async def move_ip(request: web.Request) -> web.Response:
        body = await body_of(request)
        with state._lock:
            block = state.ip_blocks.get(request.match_info["block"])
            if block is None:
                return _not_found()
            block["routedTo"] = {"serviceName": body.get("to")}
            return ok(state.task("genericMoveFloatingIp"))

    async def list_reverse(request: web.Request) -> web.Response:
        with state._lock:
            reverses = state.reverses.get(request.match_info["block"])
            return ok(sorted(reverses)) if reverses is not None else _not_found()

    async def get_reverse(request: web.Request) -> web.Response:
        ip = request.match_info["ip"]
        with state._lock:
            host = state.reverses.get(request.match_info["block"], {}).get(ip)
            return ok({"ipReverse": ip, "reverse": host}) if host else _not_found()

    async def set_reverse(request: web.Request) -> web.Response:
        body = await body_of(request)
        with state._lock:
            reverses = state.reverses.get(request.match_info["block"])
            if reverses is None:
                return _not_found()
            reverses[body["ipReverse"]] = body["reverse"]
            return ok({"ipReverse": body["ipReverse"], "reverse": body["reverse"]})

    async def delete_reverse(request: web.Request) -> web.Response:
        with state._lock:
            reverses = state.reverses.get(request.match_info["block"])
            if reverses is None or reverses.pop(request.match_info["ip"], None) is None:
                return _not_found()
        return ok(None)

    def _firewall(request: web.Request) -> Optional[dict]:
        return state.firewalls.get(request.match_info["ip"])

    async def get_firewall(request: web.Request) -> web.Response:
        ip = request.match_info["ip"]
        with state._lock:
            firewall = _firewall(request)
            if firewall is None:
                return _not_found()
            return ok({"ipOnFirewall": ip, "enabled": firewall["enabled"], "state": "ok"})

    async def toggle_firewall(request: web.Request) -> web.Response:
        body = await body_of(request)
        with state._lock:
            firewall = _firewall(request)
            if firewall is None:
                return _not_found()
            firewall["enabled"] = bool(body.get("enabled"))
        return ok(None)

    async def list_rules(request: web.Request) -> web.Response:
        with state._lock:
            firewall = _firewall(request)
            return ok(sorted(firewall["rules"])) if firewall else _not_found()

    async def get_rule(request: web.Request) -> web.Response:
        with state._lock:
            firewall = _firewall(request)
            rule = firewall["rules"].get(int(request.match_info["sequence"])) if firewall else None
            return ok(rule) if rule else _not_found()

    async def add_rule(request: web.Request) -> web.Response:
        body = await body_of(request)
        ip = request.match_info["ip"]
        with state._lock:
            firewall = _firewall(request)
            if firewall is None:
                return _not_found()
            sequence = int(body.get("sequence", -1))
            if sequence in firewall["rules"]:
                return error_response(409, "A rule with this sequence already exists")
            rule = _rule_json(ip, body)
            firewall["rules"][sequence] = rule
            return ok(rule)

    async def delete_rule(request: web.Request) -> web.Response:
        with state._lock:
            firewall = _firewall(request)
            if firewall is None or firewall["rules"].pop(
                int(request.match_info["sequence"]), None
            ) is None:
                return _not_found()
        return ok(None)

    # ---- Account SSH keys and billing ----------------------------------------

    async def list_account_keys(request: web.Request) -> web.Response:
        with state._lock:
            return ok(sorted(state.account_ssh_keys))

    async def get_account_key(request: web.Request) -> web.Response:
        with state._lock:
            key = state.account_ssh_keys.get(request.match_info["key_name"])
            return ok(key) if key else _not_found()

    async def list_bills(request: web.Request) -> web.Response:
        with state._lock:
            return ok(sorted(state.bills))

    async def get_bill(request: web.Request) -> web.Response:
        with state._lock:
            bill = state.bills.get(request.match_info["bill_id"])
            return ok(bill) if bill else _not_found()

    def usage(which: str) -> Any:
        async def handler(request: web.Request) -> web.Response:
            with state._lock:
                return ok(dict(getattr(state, which)))

        return handler

    routes: list[tuple[str, str, Any]] = [
        # VPS
        ("GET", "/vps", list_vps),
        ("GET", "/vps/{name}", get_vps),
        ("GET", "/vps/{name}/ips", vps_ips),
        ("GET", "/vps/{name}/ips/{ip}", vps_ip_detail),
        ("PUT", "/vps/{name}/ips/{ip}", vps_set_reverse),
        ("POST", "/vps/{name}/{verb:start|stop|reboot}", vps_action),
        ("GET", "/vps/{name}/snapshot", vps_snapshot),
        ("DELETE", "/vps/{name}/snapshot", vps_delete_snapshot),
        ("POST", "/vps/{name}/createSnapshot", vps_create_snapshot),
        ("POST", "/vps/{name}/snapshot/{snapshot_id}/revert", vps_revert_snapshot),
        ("GET", "/vps/{name}/automatedBackup", vps_backup),
        ("GET", "/vps/{name}/availableImages", vps_images),
        ("GET", "/vps/{name}/availableImages/{image_id}", vps_image),
        ("POST", "/vps/{name}/reinstall", vps_reinstall),
        ("GET", "/vps/{name}/availableUpgrade", vps_upgrades),
        ("POST", "/vps/{name}/change", vps_change),
        ("GET", "/vps/{name}/serviceInfos", service_infos("vps")),
        # Dedicated
        ("GET", "/dedicated/server", list_dedicated),
        ("GET", "/dedicated/server/{name}", dedicated_part("detail")),
        ("GET", "/dedicated/server/{name}/specifications/hardware", dedicated_part("specs")),
        ("GET", "/dedicated/server/{name}/ips", dedicated_part("ips")),
        ("POST", "/dedicated/server/{name}/reboot", dedicated_reboot),
        ("GET", "/dedicated/server/{name}/serviceInfos", service_infos("dedicated")),
        # Public Cloud
        ("GET", "/cloud/project", list_projects),
        ("GET", "/cloud/project/{project_id}", get_project),
        ("GET", "/cloud/project/{project_id}/instance", list_instances),
        ("POST", "/cloud/project/{project_id}/instance", create_instance),
        ("GET", "/cloud/project/{project_id}/instance/{instance_id}", get_instance),
        ("DELETE", "/cloud/project/{project_id}/instance/{instance_id}", delete_instance),
        ("POST", "/cloud/project/{project_id}/instance/{instance_id}/{verb:start|stop|reboot}",
         instance_action),
        ("POST", "/cloud/project/{project_id}/instance/{instance_id}/snapshot",
         instance_snapshot),
        ("GET", "/cloud/project/{project_id}/flavor", static_list(FLAVORS)),
        ("GET", "/cloud/project/{project_id}/image", static_list(IMAGES)),
        ("GET", "/cloud/project/{project_id}/region", list_regions),
        ("GET", "/cloud/project/{project_id}/sshkey", project_collection("ssh_keys")),
        ("POST", "/cloud/project/{project_id}/sshkey", add_project_key),
        ("DELETE", "/cloud/project/{project_id}/sshkey/{key_id}",
         delete_project_item("ssh_keys", "key_id")),
        ("GET", "/cloud/project/{project_id}/snapshot", project_collection("snapshots")),
        ("DELETE", "/cloud/project/{project_id}/snapshot/{snapshot_id}",
         delete_project_item("snapshots", "snapshot_id")),
        ("GET", "/cloud/project/{project_id}/volume", project_collection("volumes")),
        ("DELETE", "/cloud/project/{project_id}/volume/{volume_id}",
         delete_project_item("volumes", "volume_id")),
        ("GET", "/cloud/project/{project_id}/usage/current", cloud_usage),
        # DNS
        ("GET", "/domain/zone", list_zones),
        ("GET", "/domain/zone/{zone}", get_zone),
        ("GET", "/domain/zone/{zone}/record", list_records),
        ("POST", "/domain/zone/{zone}/record", create_record),
        ("GET", "/domain/zone/{zone}/record/{record_id:\\d+}", get_record),
        ("PUT", "/domain/zone/{zone}/record/{record_id:\\d+}", update_record),
        ("DELETE", "/domain/zone/{zone}/record/{record_id:\\d+}", delete_record),
        ("POST", "/domain/zone/{zone}/refresh", refresh_zone),
        # IPs (blocks arrive percent-encoded; aiohttp matches and decodes them)
        ("GET", "/ip", list_ip_blocks),
        ("GET", "/ip/{block}", get_ip_block),
        ("POST", "/ip/{block}/move", move_ip),
        ("GET", "/ip/{block}/reverse", list_reverse),
        ("POST", "/ip/{block}/reverse", set_reverse),
        ("GET", "/ip/{block}/reverse/{ip}", get_reverse),
        ("DELETE", "/ip/{block}/reverse/{ip}", delete_reverse),
        ("GET", "/ip/{block}/firewall/{ip}", get_firewall),
        ("PUT", "/ip/{block}/firewall/{ip}", toggle_firewall),
        ("GET", "/ip/{block}/firewall/{ip}/rule", list_rules),
        ("POST", "/ip/{block}/firewall/{ip}/rule", add_rule),
        ("GET", "/ip/{block}/firewall/{ip}/rule/{sequence:\\d+}", get_rule),
        ("DELETE", "/ip/{block}/firewall/{ip}/rule/{sequence:\\d+}", delete_rule),
        # Account
        ("GET", "/me", me),
        ("GET", "/me/sshKey", list_account_keys),
        ("GET", "/me/sshKey/{key_name}", get_account_key),
        ("GET", "/me/bill", list_bills),
        ("GET", "/me/bill/{bill_id}", get_bill),
        ("GET", "/me/consumption/usage/current", usage("usage_current")),
        ("GET", "/me/consumption/usage/forecast", usage("usage_forecast")),
    ]
    app.router.add_get(f"{PREFIX}/auth/time", auth_time)
    for method, path, handler in routes:
        app.router.add_route(method, f"{PREFIX}{path}", guarded(handler))
