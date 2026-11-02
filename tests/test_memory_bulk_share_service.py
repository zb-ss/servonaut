"""Sharing many servers' memory with one team: the batch service.

The team memory service is real, so the routes and their order are the real
ones; only the HTTP boundary and the owner's stored envelopes are faked.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import nacl.public
import pytest

import servonaut.services.memory.crypto as crypto_module
from servonaut.config.schema import MemoryConfig
from servonaut.services.api_client import APIClient, APIError, RateLimitedError
from servonaut.services.memory.bulk_share import (
    ALREADY_SHARED,
    BulkMemoryShareService,
    FAILED,
    ID_NOT_ACCEPTED,
    KEY_RACE,
    MEMORY_OFF,
    MemorySyncLockedError,
    NEVER_PROBED,
    NO_SNAPSHOT,
    NOT_SENT,
    RATE_LIMITED,
    SAME_SETTINGS,
    SHARED,
    SKIPPED,
    ShareTarget,
    UNRESOLVED,
    UPDATED,
    memory_sync_accepts,
)
from servonaut.services.memory.interfaces import MemoryNotFound
from servonaut.services.memory.team_service import (
    KeyChangedError,
    TeamMemoryService,
    UnusableMemberKeyError,
)

SLUG = "team-a"
GRANT_PATH = f"/api/v1/teams/{SLUG}/memory/grant"
KEYS_PATH = f"/api/v1/memory/keys/team/{SLUG}"


def _member(user_id: int, name: str, role: str = "member", **extra: Any) -> Dict[str, Any]:
    pub = bytes(nacl.public.PrivateKey.generate().public_key)
    return {
        "user_id": user_id, "fingerprint": crypto_module.fingerprint(pub),
        "public_key_b64": base64.b64encode(pub).decode(), "role": role, "name": name,
        **extra,
    }


def _grant(instance_id: str, grant_id: str = "g-1", **extra: Any) -> Dict[str, Any]:
    return {
        "id": grant_id, "instance_id": instance_id, "required_role": "member",
        "modules": ["os", "logs"], "status": "active", "granted_by_user_id": 1,
        "created_at": "2026-10-01T10:00:00Z", "revoked_at": None, **extra,
    }


def _rate_limited(retry_after: Optional[str] = None) -> RateLimitedError:
    headers = {"retry-after": retry_after} if retry_after is not None else {}
    return RateLimitedError(code="rate_limited", message="slow down", status=429,
                            response_headers=headers)


class _Backend:
    """The service routes a batch uses, with a call log and scripted refusals."""

    def __init__(self, *, members: List[Dict[str, Any]], live: Optional[List[Dict[str, Any]]] = None,
                 stored: Optional[Dict[str, List[str]]] = None) -> None:
        self.members = members
        self.live = live or []
        # instance id -> the modules the service holds for it; absent = 404.
        self.stored = stored if stored is not None else {}
        self.calls: List[str] = []
        self.posted: List[Dict[str, Any]] = []
        # instance id -> errors the next grant POSTs for it raise, in order.
        self.post_errors: Dict[str, List[Exception]] = {}
        self.pending: Dict[str, List[Dict[str, Any]]] = {}
        self.api = MagicMock(spec=APIClient)
        self.api.get.side_effect = self._get
        self.api.post.side_effect = self._post
        self.api.delete.side_effect = self._delete

    async def _get(self, path: str, **_kw: Any) -> Dict[str, Any]:
        self.calls.append(f"GET {path}")
        if path == KEYS_PATH:
            return {"members": self.members}
        return {"instances": [
            {"grant": g, "instance": {"instance_id": g["instance_id"]}, "readable_modules": ["os"]}
            for g in self.live
        ]}

    async def _post(self, path: str, **kw: Any) -> Dict[str, Any]:
        body = kw.get("json") or {}
        self.calls.append(f"POST {path} {body.get('instance_id', '')}".rstrip())
        queued = self.post_errors.get(body.get("instance_id", ""), [])
        if queued:
            raise queued.pop(0)
        self.posted.append(body)
        return _grant(body["instance_id"], grant_id=f"g-{body['instance_id']}",
                      required_role=body["required_role"], modules=body["modules"],
                      pending_recipients=self.pending.get(body["instance_id"], []))

    async def _delete(self, path: str, **_kw: Any) -> Dict[str, Any]:
        self.calls.append(f"DELETE {path}")
        grant_id = path.rsplit("/", 1)[1]
        found = next(g for g in self.live if g["id"] == grant_id)
        return {**found, "status": "revoked", "revoked_at": "2026-10-02T10:00:00Z"}

    def writes(self) -> List[str]:
        return [c for c in self.calls if not c.startswith("GET")]


def _owner() -> Any:
    private = nacl.public.PrivateKey.generate()
    km = MagicMock()
    km.user_id = 1
    km.private_key, km.public_key = bytes(private), bytes(private.public_key)
    return km


def _retrieval(backend: _Backend, owner: Any) -> MagicMock:
    """The owner's own envelopes: one data key sealed to the owner per module."""

    async def modules(instance_id: str) -> Dict[str, Any]:
        backend.calls.append(f"GET /api/v1/memory/{instance_id}")
        if instance_id not in backend.stored:
            raise MemoryNotFound("access_revoked")
        return {"modules": list(backend.stored[instance_id])}

    async def raw(_instance_id: str, module: str) -> Dict[str, Any]:
        env = crypto_module.encrypt_envelope(
            b"{}", self_public_key=owner.public_key, self_user_id=owner.user_id).to_dict()
        return {"id": f"e-{module}", "wrapped_dek": env["dek_wraps"][0]["wrapped_dek"]}

    retrieval = MagicMock()
    retrieval.list_instance_modules.side_effect = modules
    retrieval.get_module_envelope_raw.side_effect = raw
    return retrieval


class _Sleeps:
    def __init__(self) -> None:
        self.waits: List[float] = []

    async def __call__(self, seconds: float) -> None:
        self.waits.append(seconds)


def _service(backend: _Backend, *, config: Optional[MemoryConfig] = None, locked: bool = False,
             pins: Any = None):
    owner = _owner()
    team = TeamMemoryService(
        api_client=backend.api, auth_service=MagicMock(has_feature=MagicMock(return_value=True)),
        crypto=crypto_module, key_store_provider=lambda: None if locked else owner,
        retrieval_service=_retrieval(backend, owner),
        pin_store_provider=(lambda: pins) if pins is not None else None,
    )
    sleeps = _Sleeps()
    cfg = config or MemoryConfig()
    return BulkMemoryShareService(team, waits=cfg.team_wrap_wait, sleep=sleeps), sleeps


def _targets(*ids: str, **flags: Any) -> List[ShareTarget]:
    return [ShareTarget(instance_id=i, label=f"name-{i}", **flags) for i in ids]


@pytest.mark.asyncio
async def test_member_keys_are_fetched_once_for_the_whole_batch():
    backend = _Backend(members=[_member(2, "Kim")],
                       stored={"web-1": ["os"], "web-2": ["os"], "web-3": ["logs"]})
    service, _ = _service(backend)
    report = await service.share(SLUG, "member", ["os", "logs"], _targets("web-1", "web-2", "web-3"))
    assert [o.status for o in report.outcomes] == [SHARED, SHARED, SHARED]
    assert backend.calls.count(f"GET {KEYS_PATH}") == 1
    assert [p["instance_id"] for p in backend.posted] == ["web-1", "web-2", "web-3"]
    # Every grant carries the member's wraps: one per stored, selected module.
    assert all(len(p["wraps"]) == 1 for p in backend.posted)


@pytest.mark.asyncio
async def test_the_existing_shares_are_read_once_for_the_whole_batch():
    backend = _Backend(members=[_member(2, "Kim")], stored={"web-1": ["os"], "web-2": ["os"]})
    service, _ = _service(backend)
    await service.share(SLUG, "member", ["os"], _targets("web-1", "web-2"))
    assert backend.calls.count(f"GET /api/v1/teams/{SLUG}/memory") == 1


@pytest.mark.asyncio
async def test_a_changed_key_refuses_the_whole_batch_and_sends_nothing():
    backend = _Backend(members=[_member(2, "Kim"), _member(3, "Lee", key_changed=True)],
                       stored={"web-1": ["os"], "web-2": ["os"]})
    service, _ = _service(backend)
    with pytest.raises(KeyChangedError) as caught:
        await service.share(SLUG, "member", ["os"], _targets("web-1", "web-2"))
    assert caught.value.names == ["Lee"]
    assert backend.writes() == []
    # Refused before any server was looked at, too.
    assert not any(c.startswith("GET /api/v1/memory/web") for c in backend.calls)


@pytest.mark.asyncio
async def test_a_changed_key_below_the_chosen_role_does_not_refuse_the_batch():
    backend = _Backend(members=[_member(2, "Kim", "admin"), _member(3, "Lee", "viewer", key_changed=True)],
                       stored={"web-1": ["os"]})
    service, _ = _service(backend)
    report = await service.share(SLUG, "admin", ["os"], _targets("web-1"))
    assert report.outcomes[0].status == SHARED


@pytest.mark.asyncio
async def test_an_unusable_member_key_refuses_the_batch():
    member = _member(2, "Kim")
    member["fingerprint"] = "0" * 64  # well formed, but not this key's
    backend = _Backend(members=[member], stored={"web-1": ["os"]})
    service, _ = _service(backend)
    with pytest.raises(UnusableMemberKeyError):
        await service.share(SLUG, "member", ["os"], _targets("web-1"))
    assert backend.writes() == []


@pytest.mark.asyncio
async def test_a_locked_memory_key_refuses_the_batch_before_anything_is_read():
    backend = _Backend(members=[_member(2, "Kim")], stored={"web-1": ["os"]})
    service, _ = _service(backend, locked=True)
    with pytest.raises(MemorySyncLockedError):
        await service.share(SLUG, "member", ["os"], _targets("web-1"))
    assert backend.calls == []


@pytest.mark.asyncio
async def test_no_modules_is_refused():
    backend = _Backend(members=[], stored={"web-1": ["os"]})
    service, _ = _service(backend)
    with pytest.raises(ValueError):
        await service.share(SLUG, "member", [], _targets("web-1"))
    assert backend.calls == []


@pytest.mark.asyncio
async def test_servers_already_shared_are_reported_and_left_alone_by_default():
    backend = _Backend(members=[_member(2, "Kim")], live=[_grant("web-1")],
                       stored={"web-1": ["os"], "web-2": ["os"]})
    service, _ = _service(backend)
    report = await service.share(SLUG, "viewer", ["os"], _targets("web-1", "web-2"))
    assert [o.status for o in report.outcomes] == [ALREADY_SHARED, SHARED]
    assert backend.writes() == [f"POST {GRANT_PATH} web-2"]


@pytest.mark.asyncio
async def test_update_existing_reshares_them_with_the_new_settings():
    backend = _Backend(members=[_member(2, "Kim")], live=[_grant("web-1")],
                       stored={"web-1": ["os"], "web-2": ["os"]})
    service, _ = _service(backend)
    report = await service.share(SLUG, "viewer", ["os"], _targets("web-1", "web-2"),
                                 update_existing=True)
    assert [o.status for o in report.outcomes] == [UPDATED, SHARED]
    assert backend.writes() == [
        f"DELETE {GRANT_PATH}/g-1", f"POST {GRANT_PATH} web-1", f"POST {GRANT_PATH} web-2",
    ]
    assert backend.posted[0]["required_role"] == "viewer"
    assert backend.posted[0]["modules"] == ["os"]


@pytest.mark.asyncio
async def test_update_existing_leaves_a_share_that_already_has_these_settings():
    backend = _Backend(members=[_member(2, "Kim")], live=[_grant("web-1")], stored={"web-1": ["os"]})
    service, _ = _service(backend)
    report = await service.share(SLUG, "member", ["logs", "os"], _targets("web-1"),
                                 update_existing=True)
    assert report.outcomes[0].status == ALREADY_SHARED
    assert report.outcomes[0].reason == SAME_SETTINGS
    assert backend.writes() == []


@pytest.mark.asyncio
async def test_a_rate_limit_waits_as_asked_within_the_budget_then_goes_on():
    backend = _Backend(members=[_member(2, "Kim")], stored={"web-1": ["os"], "web-2": ["os"]})
    backend.post_errors["web-1"] = [_rate_limited("7")]
    service, sleeps = _service(backend, config=MemoryConfig(team_wrap_max_wait_seconds=10.0))
    report = await service.share(SLUG, "member", ["os"], _targets("web-1", "web-2"))
    assert sleeps.waits == [7.0]
    assert [o.status for o in report.outcomes] == [SHARED, SHARED]


@pytest.mark.asyncio
async def test_a_rate_limit_without_retry_after_waits_the_configured_pause():
    backend = _Backend(members=[_member(2, "Kim")], stored={"web-1": ["os"]})
    backend.post_errors["web-1"] = [_rate_limited()]
    service, sleeps = _service(backend, config=MemoryConfig(team_wrap_retry_seconds=3.0))
    report = await service.share(SLUG, "member", ["os"], _targets("web-1"))
    assert sleeps.waits == [3.0]
    assert report.outcomes[0].status == SHARED


@pytest.mark.asyncio
async def test_a_wait_longer_than_the_budget_stops_the_rest_and_counts_them():
    backend = _Backend(members=[_member(2, "Kim")],
                       stored={"web-1": ["os"], "web-2": ["os"], "web-3": ["os"]})
    backend.post_errors["web-2"] = [_rate_limited("120")]
    service, sleeps = _service(backend, config=MemoryConfig(team_wrap_max_wait_seconds=30.0))
    report = await service.share(SLUG, "member", ["os"], _targets("web-1", "web-2", "web-3"))
    assert sleeps.waits == []  # never waits longer than the budget
    assert [o.status for o in report.outcomes] == [SHARED, NOT_SENT, NOT_SENT]
    assert report.not_sent == 2
    assert report.retry_after == 120.0
    assert all(o.reason == RATE_LIMITED for o in report.outcomes[1:])
    assert f"POST {GRANT_PATH} web-3" not in backend.calls


@pytest.mark.asyncio
async def test_a_rate_limit_that_persists_after_the_retry_stops_the_rest():
    backend = _Backend(members=[_member(2, "Kim")],
                       stored={"web-1": ["os"], "web-2": ["os"], "web-3": ["os"]})
    backend.post_errors["web-1"] = [_rate_limited("2"), _rate_limited("2")]
    service, sleeps = _service(backend)
    report = await service.share(SLUG, "member", ["os"], _targets("web-1", "web-2", "web-3"))
    assert sleeps.waits == [2.0]  # one retry, never a loop
    assert [o.status for o in report.outcomes] == [NOT_SENT, NOT_SENT, NOT_SENT]
    assert backend.writes() == [f"POST {GRANT_PATH} web-1"] * 2


@pytest.mark.asyncio
async def test_servers_that_need_no_request_are_still_reported_after_a_stop():
    backend = _Backend(members=[_member(2, "Kim")], live=[_grant("web-3")],
                       stored={"web-1": ["os"], "web-3": ["os"]})
    backend.post_errors["web-1"] = [_rate_limited("999")]
    service, _ = _service(backend)
    targets = _targets("web-1") + _targets("vps-1.example.net") + _targets("web-3")
    report = await service.share(SLUG, "member", ["os"], targets)
    assert [o.status for o in report.outcomes] == [NOT_SENT, SKIPPED, ALREADY_SHARED]


@pytest.mark.asyncio
async def test_one_failure_does_not_stop_the_others():
    backend = _Backend(members=[_member(2, "Kim")], stored={"web-1": ["os"], "web-2": ["os"]})
    backend.post_errors["web-1"] = [APIError(code="server_error", message="boom", status=500)]
    service, _ = _service(backend)
    report = await service.share(SLUG, "member", ["os"], _targets("web-1", "web-2"))
    assert [o.status for o in report.outcomes] == [FAILED, SHARED]
    assert "500" in report.outcomes[0].detail


@pytest.mark.asyncio
async def test_skip_reasons_cover_ids_snapshots_probing_and_opt_out():
    backend = _Backend(members=[_member(2, "Kim")], stored={"web-1": ["os"]})
    service, _ = _service(backend)
    targets = [
        ShareTarget("vps-1.example.net", "vps-1"),
        ShareTarget("web-2", "web-2", probed=True),  # probed here, never uploaded
        ShareTarget("web-3", "web-3", probed=False),  # probed nowhere
        ShareTarget("web-4", "web-4", memory_off=True),
        ShareTarget("i-stand-in", "web-5", resolved=False),
        ShareTarget("web-1", "web-1"),
    ]
    report = await service.share(SLUG, "member", ["os"], targets)
    got = [(o.target.label, o.status, o.reason) for o in report.outcomes]
    assert got == [
        ("vps-1", SKIPPED, ID_NOT_ACCEPTED),
        ("web-2", SKIPPED, NO_SNAPSHOT),
        ("web-3", SKIPPED, NEVER_PROBED),
        ("web-4", SKIPPED, MEMORY_OFF),
        ("web-5", SKIPPED, UNRESOLVED),
        ("web-1", SHARED, ""),
    ]
    # A dotted id, an opted-out server and a stand-in are never sent anywhere.
    assert not any("vps-1.example.net" in c or "web-4" in c or "stand-in" in c for c in backend.calls)
    assert backend.writes() == [f"POST {GRANT_PATH} web-1"]


@pytest.mark.asyncio
async def test_a_server_probed_elsewhere_is_shared_even_if_never_probed_here():
    backend = _Backend(members=[_member(2, "Kim")], stored={"web-1": ["os"]})
    service, _ = _service(backend)
    report = await service.share(SLUG, "member", ["os"], _targets("web-1", probed=False))
    assert report.outcomes[0].status == SHARED


@pytest.mark.asyncio
async def test_a_key_that_changes_during_the_batch_stops_the_rest():
    from servonaut.services.api_client import InsufficientWrapsError

    backend = _Backend(members=[_member(2, "Kim")], stored={"web-1": ["os"], "web-2": ["os"]})
    backend.post_errors["web-1"] = [InsufficientWrapsError(
        code="insufficient_wraps", message="missing", status=422,
        details={"missing": [{"envelope_id": "e-os", "recipient_user_id": 2}]})]
    service, _ = _service(backend)
    report = await service.share(SLUG, "member", ["os"], _targets("web-1", "web-2"))
    assert [(o.status, o.reason) for o in report.outcomes] == [(FAILED, KEY_RACE), (NOT_SENT, KEY_RACE)]
    assert f"POST {GRANT_PATH} web-2" not in backend.calls


@pytest.mark.asyncio
async def test_progress_is_reported_after_every_server_in_order():
    backend = _Backend(members=[], stored={"web-1": ["os"]})
    service, _ = _service(backend)
    seen: List[tuple] = []
    await service.share(SLUG, "member", ["os"], _targets("web-1", "vps-1.example.net"),
                        on_progress=lambda i, total, o: seen.append((i, total, o.status)))
    assert seen == [(1, 2, SHARED), (2, 2, SKIPPED)]


@pytest.mark.asyncio
async def test_members_without_a_memory_key_are_listed_once():
    waiting = {"user_id": 9, "name": "Pat", "role": "member", "reason": "no_memory_key"}
    backend = _Backend(members=[_member(2, "Kim")], stored={"web-1": ["os"], "web-2": ["os"]})
    backend.pending = {"web-1": [waiting], "web-2": [waiting]}
    service, _ = _service(backend)
    report = await service.share(SLUG, "member", ["os"], _targets("web-1", "web-2"))
    assert [p["name"] for p in report.pending] == ["Pat"]


@pytest.mark.parametrize(
    ("instance_id", "accepted"),
    [("i-0123456789abcdef0", True), ("web-1", True), ("vps-1.example.net", False),
     ("", False), ("fleet", False), ("a" * 129, False)],
)
def test_memory_sync_accepts_only_the_ids_it_can_store(instance_id: str, accepted: bool):
    assert memory_sync_accepts(instance_id) is accepted


def test_the_rate_limit_settings_fall_back_when_they_are_unusable():
    cfg = MemoryConfig(team_wrap_retry_seconds=float("nan"), team_wrap_max_wait_seconds=-1)
    defaults = MemoryConfig()
    assert cfg.team_wrap_wait() == (defaults.team_wrap_retry_seconds, defaults.team_wrap_max_wait_seconds)
