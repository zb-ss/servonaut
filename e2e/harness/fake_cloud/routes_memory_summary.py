"""Hosted AI summaries of a server's memory: provider info, consent, dispatch, result.

``GET /api/v1/memory/ai-provider-info`` describes the provider. The consent
call (``POST /summary/{id}/consent``) answers 201 with the module set and the
id of the newest envelope of each module (``envelope_ids``). The dispatch
(``POST /summary/{id}``) carries exactly one of two bodies: the per-envelope
data keys (``envelope_keys``) or the Memory Sync passphrase. The fake runs the
job at once: it opens the stored ciphertext with the data keys, and either seals
a Markdown result to the caller's public key or records the job as failed.
``GET /summary/{id}/latest`` answers the result, a ``pending`` status or
``status: "failed"``.

Controls for journeys: :meth:`SummaryCloud.hide_envelope_ids` (an older service
that does not list them), :meth:`SummaryCloud.force_stale_once`,
:meth:`SummaryCloud.set_pending_polls` and the custody switches of
:class:`~e2e.harness.fake_cloud.routes_memory.MemoryCloud`.
"""

from __future__ import annotations

import base64
import binascii
import copy
import datetime as dt
import json
import threading
import uuid
from typing import Any, Callable, Optional

from aiohttp import web
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import nacl.exceptions
import nacl.public

from e2e.harness.fake_cloud.control import CONTROL_PREFIX
from e2e.harness.fake_cloud.routes_auth import bearer_ok, json_body, unauthorized
from e2e.harness.fake_cloud.routes_memory import MEMORY, MemoryCloud, _refusal
from e2e.harness.fake_cloud.state import ScenarioStore

MODES = ("server_60s", "client", "off")
CONSENT_TTL_SECONDS = 300
PROVIDER_INFO = {
    "provider_name": "Example AI provider",
    "retention_days": 30,
    "retention_text": "The provider keeps prompts and answers for 30 days.",
    "supports_zdr": False,
}
FAILURE_REASON = "dek_invalid"


def _parse_timestamp(value: Optional[str]) -> Optional[dt.datetime]:
    """An RFC 3339 timestamp, or ``None`` for anything else (such as an envelope id)."""
    if not isinstance(value, str) or "T" not in value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _invalid(field: str, message: str) -> tuple[int, dict[str, Any]]:
    return _refusal(422, "validation_failed", message, field=field)


def _dek(value: Any) -> Optional[bytes]:
    """A data key as sent: base64 of exactly 32 bytes."""
    if not isinstance(value, str):
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if len(raw) == 32 else None


class SummaryCloud:
    """Thread-safe state of the hosted-summary routes."""

    def __init__(self, memory: MemoryCloud, user_id: Callable[[], int]) -> None:
        self._memory = memory
        self._user_id = user_id
        self._lock = threading.RLock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._consents: dict[str, dict[str, Any]] = {}
            self._jobs: list[dict[str, Any]] = []
            self._hide_envelope_ids = False
            self._stale_once = 0
            self._pending_polls = 0

    # -- controls and observations -----------------------------------------

    def hide_envelope_ids(self, hidden: bool = True) -> None:
        """Model an older service: the consent answer has no ``envelope_ids``."""
        with self._lock:
            self._hide_envelope_ids = bool(hidden)

    def force_stale_once(self, times: int = 1) -> None:
        """The next *times* dispatches with data keys answer 409 ``stale_envelopes``."""
        with self._lock:
            self._stale_once = int(times)

    def set_pending_polls(self, polls: int) -> None:
        """Each new job answers ``pending`` to this many ``/latest`` reads before its result."""
        with self._lock:
            self._pending_polls = int(polls)

    def jobs(self) -> list[dict[str, Any]]:
        """Jobs so far, oldest first, without result ciphertext."""
        with self._lock:
            return [{k: v for k, v in job.items() if k != "result"} for job in copy.deepcopy(self._jobs)]

    # -- operations ----------------------------------------------------------

    def consent(self, instance_id: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        mode = body.get("mode")
        if mode not in MODES:
            return _invalid("mode", "mode must be server_60s, client or off")
        if body.get("provider_ack") is not True:
            return _invalid("provider_ack", "The provider disclosure must be acknowledged")
        latest = self._latest_by_module(instance_id)
        if not latest:
            return _refusal(404, "not_found", "No memory stored for this instance")
        wanted = body.get("modules")
        if wanted is not None and (not isinstance(wanted, list) or not all(isinstance(m, str) for m in wanted)):
            return _invalid("modules", "modules must be a list of names")
        modules = sorted(m for m in latest if wanted is None or m in wanted)
        if not modules:
            return _invalid("modules", "None of the modules has memory stored")
        token = f"consent-{uuid.uuid4()}"
        expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=CONSENT_TTL_SECONDS)
        envelope_ids = {m: latest[m]["id"] for m in modules}
        with self._lock:
            self._consents[token] = {
                "user_id": self._user_id(), "instance_id": instance_id, "mode": mode,
                "modules": modules, "envelope_ids": envelope_ids, "expires": expires,
            }
            hidden = self._hide_envelope_ids
        answer: dict[str, Any] = {
            "token": token, "expires_at": expires.isoformat(), "mode": mode, "modules": modules,
        }
        if not hidden:
            answer["envelope_ids"] = envelope_ids
        return 201, answer

    def dispatch(self, instance_id: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        consent = self._consent_for(instance_id, body)
        if isinstance(consent, tuple):
            return consent
        keys, passphrase = body.get("envelope_keys"), body.get("passphrase")
        if (keys is None) == (passphrase is None):
            return _invalid("envelope_keys", "Send exactly one of passphrase and envelope_keys")
        if keys is not None:
            outcome = self._data_keys(instance_id, consent, keys)
        else:
            outcome = self._passphrase_keys(consent, passphrase)
        if isinstance(outcome, tuple):
            return outcome
        previous = self._newest_success(instance_id)
        job = self._run_job(instance_id, consent, outcome, "envelope_keys" if keys is not None else "passphrase")
        return 202, {
            "status": "queued", "message": "Summary queued",
            "previous_summary_id": previous["result"]["id"] if previous else None,
            "queued_at": job["queued_at"], "poll_after_seconds": 1,
        }

    def latest(self, instance_id: str, after: Optional[str]) -> tuple[int, dict[str, Any]]:
        """``after`` is either a queued_at timestamp or an envelope id.

        Only the timestamp form reports a failed job (200 with the reason); the
        id form never returns a failed body. 202 means pending.
        """
        since = _parse_timestamp(after)
        with self._lock:
            mine = [j for j in self._jobs
                    if j["instance_id"] == instance_id and j["user_id"] == self._user_id()]
            if since is not None:
                # One-second precision, inclusive, like the service.
                mine = [j for j in mine if _parse_timestamp(j["queued_at"]).replace(microsecond=0) >= since.replace(microsecond=0)]
            if not mine:
                return (202, {"status": "pending", "poll_after_seconds": 1}) if since is not None \
                    else _refusal(404, "not_found", "No summary")
            job = mine[-1]
            if job["status"] == "failed":
                if since is None:
                    return 202, {"status": "pending", "previous_summary_id": job["previous_id"],
                                 "poll_after_seconds": 1}
                return 200, {"status": "failed", "reason": job["reason"], "failed_at": job["queued_at"]}
            if job["pending_polls"] > 0:
                job["pending_polls"] -= 1
                return 202, {"status": "pending", "previous_summary_id": job["previous_id"],
                             "poll_after_seconds": 1}
            result = copy.deepcopy(job["result"])
        if since is None and after is not None and result["id"] == after:
            return 202, {"status": "pending", "previous_summary_id": after, "poll_after_seconds": 1}
        return 200, result

    # -- helpers --------------------------------------------------------------

    def _latest_by_module(self, instance_id: str) -> dict[str, dict[str, Any]]:
        uid = self._user_id()
        latest: dict[str, dict[str, Any]] = {}
        for envelope in self._memory.find(instance_id=instance_id):
            if any(w.get("recipient_user_id") == uid for w in envelope.get("dek_wraps", [])):
                latest[envelope["module"]] = envelope
        return latest

    def _consent_for(self, instance_id: str, body: dict[str, Any]) -> "dict[str, Any] | tuple[int, dict[str, Any]]":
        with self._lock:
            consent = self._consents.get(str(body.get("consent_token")))
        now = dt.datetime.now(dt.timezone.utc)
        if (consent is None or consent["user_id"] != self._user_id()
                or consent["instance_id"] != instance_id or consent["expires"] < now):
            return _invalid("consent_token", "The consent token is not valid")
        if body.get("mode") != consent["mode"]:
            return _invalid("mode", "mode must match the consent")
        return consent

    def _newest_success(self, instance_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            done = [j for j in self._jobs if j["instance_id"] == instance_id
                    and j["user_id"] == self._user_id() and j["status"] == "success"]
            return copy.deepcopy(done[-1]) if done else None

    def _data_keys(
        self, instance_id: str, consent: dict[str, Any], keys: Any
    ) -> "dict[str, bytes] | tuple[int, dict[str, Any]]":
        """Checks of the ``envelope_keys`` form; returns the data key per envelope id."""
        uid = self._user_id()
        if not isinstance(keys, list) or not keys:
            return _invalid("envelope_keys", "envelope_keys must be a non-empty list")
        parsed: dict[str, bytes] = {}
        modules: set[str] = set()
        latest = self._latest_by_module(instance_id)
        stale = False
        for entry in keys:
            dek = _dek(entry.get("dek")) if isinstance(entry, dict) else None
            envelope_id = entry.get("envelope_id") if isinstance(entry, dict) else None
            found = self._memory.find(id=envelope_id) if isinstance(envelope_id, str) else []
            stored = found[0] if found else None
            if (dek is None or stored is None or stored["instance_id"] != instance_id
                    or stored["module"] not in consent["modules"] or stored["module"] in modules
                    or not any(w.get("recipient_user_id") == uid for w in stored.get("dek_wraps", []))):
                return _invalid("envelope_keys", "An envelope key does not match this instance and module")
            modules.add(stored["module"])
            parsed[envelope_id] = dek
            stale = stale or latest.get(stored["module"], {}).get("id") != envelope_id
        if not self._memory.vault_custody_enabled:
            return _refusal(503, "feature_disabled", "Vault custody for Memory Sync keys is not available yet.")
        with self._lock:
            forced = self._stale_once > 0
            if forced:
                self._stale_once -= 1
        if stale or forced:
            return _refusal(409, "stale_envelopes", "Memory changed since the consent was given.")
        if set(parsed) != set(consent["envelope_ids"].values()):
            return _invalid("envelope_keys", "Send keys for exactly the consented envelopes")
        return parsed

    def _passphrase_keys(
        self, consent: dict[str, Any], passphrase: Any
    ) -> "dict[str, bytes] | tuple[int, dict[str, Any]]":
        """The passphrase form: only for a passphrase-custody key the passphrase opens."""
        from servonaut.services.memory.crypto import CryptoError, WrappedPrivateKey, unwrap_private_key

        uid = self._user_id()
        key = self._memory.enrolled_key(uid)
        if (key is None or key.get("custody") == "vault" or not key.get("wrapped_private_key")
                or not self._memory.passphrase_custody_accepted):
            return _refusal(409, "memory_key_custody_vault", "Update Servonaut to set up Memory Sync.")
        if not isinstance(passphrase, str) or not passphrase:
            return _invalid("passphrase", "passphrase must be a non-empty string")
        try:
            private = unwrap_private_key(WrappedPrivateKey.from_json(key["wrapped_private_key"]), passphrase)
        except CryptoError:
            return _invalid("passphrase", "The passphrase does not open the key")
        keys: dict[str, bytes] = {}
        for envelope_id in consent["envelope_ids"].values():
            stored = (self._memory.find(id=envelope_id) or [None])[0]
            wrap = next((w for w in (stored or {}).get("dek_wraps", []) if w.get("recipient_user_id") == uid), None)
            try:
                keys[envelope_id] = nacl.public.SealedBox(nacl.public.PrivateKey(private)).decrypt(
                    base64.b64decode(wrap["wrapped_dek"])) if wrap else b""
            except (nacl.exceptions.CryptoError, ValueError):
                keys[envelope_id] = b""
        return keys

    def _run_job(
        self, instance_id: str, consent: dict[str, Any], keys: dict[str, bytes], form: str
    ) -> dict[str, Any]:
        """Open each consented envelope with its key; seal a result, or record the failure."""
        uid = self._user_id()
        job: dict[str, Any] = {
            "instance_id": instance_id, "user_id": uid, "queued_at": _now(), "status": "success",
            "modules": consent["modules"], "form": form,
            "reason": None, "result": None, "pending_polls": self._pending_polls,
            "previous_id": (self._newest_success(instance_id) or {}).get("result", {}).get("id"),
        }
        try:
            for envelope_id, dek in keys.items():
                stored = self._memory.find(id=envelope_id)[0]
                AESGCM(dek).decrypt(
                    base64.b64decode(stored["iv"]),
                    base64.b64decode(stored["ciphertext"]) + base64.b64decode(stored["tag"]), None)
            job["result"] = self._seal_result(instance_id, consent["modules"], uid)
        except (InvalidTag, ValueError, IndexError):
            job.update(status="failed", reason=FAILURE_REASON)
        with self._lock:
            self._jobs.append(job)
        return job

    def _seal_result(self, instance_id: str, modules: list[str], uid: int) -> dict[str, Any]:
        from servonaut.services.memory.crypto import encrypt_envelope

        public = base64.b64decode(self._memory.enrolled_key(uid)["public_key"])
        text = f"# Summary of {instance_id}\n\nCovers: {', '.join(modules)}.\n"
        envelope = encrypt_envelope(
            json.dumps({"summary": text}).encode(), self_public_key=public, self_user_id=uid)
        wire = envelope.to_dict()
        return {
            "id": str(uuid.uuid4()), "instance_id": instance_id, "module": "ai_summary",
            "probed_at": _now(), "created_at": _now(), "ttl_seconds": 3600, "snapshot_version": 1,
            "iv": wire["iv"], "tag": wire["tag"], "salt": None, "ciphertext": wire["ciphertext"],
            "encryption": wire["encryption"], "wrapped_dek": wire["dek_wraps"][0]["wrapped_dek"],
        }


def add_routes(app: web.Application, store: ScenarioStore, summaries: SummaryCloud) -> None:
    """Register the summary routes (before the memory routes: ``ai-provider-info`` is a fixed path)."""

    def guarded(handler: Any) -> Any:
        async def wrapper(request: web.Request) -> web.StreamResponse:
            if not bearer_ok(request, store):
                return unauthorized()
            return await handler(request)

        return wrapper

    def answer(result: tuple[int, dict[str, Any]]) -> web.Response:
        return web.json_response(result[1], status=result[0])

    async def provider_info(request: web.Request) -> web.Response:
        return web.json_response(PROVIDER_INFO)

    async def consent(request: web.Request) -> web.Response:
        return answer(summaries.consent(request.match_info["instance_id"], await json_body(request)))

    async def dispatch(request: web.Request) -> web.Response:
        return answer(summaries.dispatch(request.match_info["instance_id"], await json_body(request)))

    async def latest(request: web.Request) -> web.Response:
        return answer(summaries.latest(request.match_info["instance_id"], request.query.get("after")))

    async def control(request: web.Request) -> web.Response:
        body = await json_body(request)
        if "hide_envelope_ids" in body:
            summaries.hide_envelope_ids(bool(body["hide_envelope_ids"]))
        if "force_stale_once" in body:
            summaries.force_stale_once(int(body["force_stale_once"]))
        if "pending_polls" in body:
            summaries.set_pending_polls(int(body["pending_polls"]))
        return web.json_response({"ok": True})

    app.router.add_get(f"{MEMORY}/ai-provider-info", guarded(provider_info))
    app.router.add_post(f"{MEMORY}/summary/{{instance_id}}/consent", guarded(consent))
    app.router.add_post(f"{MEMORY}/summary/{{instance_id}}", guarded(dispatch))
    app.router.add_get(f"{MEMORY}/summary/{{instance_id}}/latest", guarded(latest))
    app.router.add_post(f"{CONTROL_PREFIX}memory/summary", control)
