"""Self-tests for the data-feature side of the harness.

The data journeys prove secrets stay secret by asserting what the fakes
did *not* receive, which only means something if the checks can fail:

* the unredacted wire capture finds a value however a client encoded it,
  where the redacted request log cannot;
* the fakes refuse plaintext dressed up as ciphertext, grants that share
  more than they name, and confirm tokens whose signature does not cover
  the request;
* the Bitwarden stand-ins never log a secret argument, and registered
  secrets never reach a failure artifact.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
from urllib.parse import quote

import httpx
import pytest

from e2e.harness.fake_cloud.wire import WireRequest, find_on_wire

pytestmark = [pytest.mark.e2e_pr]

SECRET = "fabricated-wire-secret-0f3e"


def _client(fake_cloud) -> httpx.Client:
    access, _ = fake_cloud.tokens()
    return httpx.Client(
        base_url=fake_cloud.url, headers={"Authorization": f"Bearer {access}"}, timeout=10
    )


# ---------------------------------------------------------------------------
# Wire capture
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("prefix", [b"", b"x", b"xy", b"xyz"])
def test_find_on_wire_sees_every_encoding(prefix):
    raw = SECRET.encode()
    embedded = prefix + raw + b" and more"
    bodies = {
        "as is": b'{"note": "' + raw + b'"}',
        "base64": base64.b64encode(embedded),
        "URL-safe base64": base64.urlsafe_b64encode(b"\xfb\xff" + embedded),
        "hex": embedded.hex().encode(),
        "URL-encoded": b"q=" + quote(SECRET + "/?&").encode(),
    }
    for name, body in bodies.items():
        request = WireRequest("POST", b"/api/x", (), body)
        assert find_on_wire([request], SECRET), name
    header = WireRequest("GET", b"/api/x", ((b"X-Note", raw),), b"")
    query = WireRequest("GET", b"/api/x?v=" + quote(SECRET).encode(), (), b"")
    assert find_on_wire([header], SECRET) and find_on_wire([query], SECRET)
    clean = WireRequest("POST", b"/api/x", (), base64.b64encode(os.urandom(4096)))
    assert find_on_wire([clean], SECRET) == []
    with pytest.raises(ValueError):
        find_on_wire([clean], "short")


def test_wire_capture_sees_what_the_request_log_redacts(fake_cloud):
    with _client(fake_cloud) as client:
        client.post("/api/v1/memory/instances", json={"instance_id": "i-1", "password": SECRET})
        client.get("/api/v1/findings", params={"token": SECRET})
    assert SECRET not in json.dumps(fake_cloud.requests())
    with pytest.raises(AssertionError) as caught:
        fake_cloud.assert_absent_on_wire(SECRET)
    report = str(caught.value)
    assert "body of POST /api/v1/memory/instances" in report
    assert "path or query of GET /api/v1/findings" in report
    assert SECRET not in report
    mark = fake_cloud.wire_mark()
    with _client(fake_cloud) as client:
        client.get("/api/v1/findings")
    fake_cloud.assert_absent_on_wire(SECRET, since=mark)


def test_unexpected_error_answers_are_reported(fake_cloud):
    with _client(fake_cloud) as client:
        client.get("/api/v1/me/secrets-config")
        client.get("/api/v1/no-such-route")
    from e2e.harness.fake_cloud.wire import expected

    with pytest.raises(AssertionError, match=r"GET /api/v1/no-such-route -> 404"):
        fake_cloud.assert_no_unexpected_errors(*expected("no secret store on file"))
    fake_cloud.assert_no_unexpected_errors(
        *expected("no secret store on file"), ("GET", r"/api/v1/no-such-route", 404)
    )


# ---------------------------------------------------------------------------
# Fakes refuse what the service refuses
# ---------------------------------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def test_fakes_refuse_plaintext_labelled_as_ciphertext(fake_cloud):
    user_id = fake_cloud.entitlements()["user_id"]
    plaintext = _b64(json.dumps({"observed": {"distro": "Debian"}}).encode())
    real_shape = {
        "instance_id": "i-1", "module": "os", "probed_at": "2030-01-01T00:00:00+00:00",
        "encryption": "aes-256-gcm", "iv": _b64(os.urandom(12)), "tag": _b64(os.urandom(16)),
        "salt": None, "ciphertext": _b64(os.urandom(64)),
        "dek_wraps": [{"recipient_user_id": user_id, "wrapped_dek": _b64(os.urandom(80))}],
    }
    wrong = [
        {"iv": "not base64!"},
        {"iv": _b64(b"too short")},
        {"tag": _b64(os.urandom(8))},
        {"dek_wraps": [{"recipient_user_id": user_id, "wrapped_dek": plaintext}]},
        {"encryption": "none"},
    ]
    with _client(fake_cloud) as client:
        client.post("/api/v1/memory/instances", json={"instance_id": "i-1"})
        envelopes = [real_shape] + [{**real_shape, **change} for change in wrong]
        answer = client.post("/api/v1/memory/sync", json={"envelopes": envelopes}).json()
        assert [a["index"] for a in answer["accepted"]] == [0]
        assert {r["reason"] for r in answer["rejected"]} == {"invalid_envelope"}

        snapshot = {
            "encryption": "aes-256-gcm", "data": plaintext, "salt": _b64(os.urandom(16)),
            "iv": _b64(os.urandom(12)), "tag": _b64(os.urandom(16)),
        }
        assert client.post("/api/v1/configs", json=snapshot).status_code == 201
        for change in ({"salt": _b64(b"x")}, {"tag": plaintext}, {"encryption": "plain"}):
            assert client.post("/api/v1/configs", json={**snapshot, **change}).status_code == 422
        # Snapshots are addressed by id, never by version number.
        assert client.get("/api/v1/configs/1").status_code == 404


def test_findings_tokens_cover_exactly_what_was_previewed(fake_cloud):
    from e2e.harness.fake_cloud.routes_findings import block_ip_remediation

    finding = fake_cloud.findings.add(
        instance_id="i-1", evidence={"source_ip": "9.9.9.9"},
        remediations=[block_ip_remediation()],
    )
    path = f"/api/v1/findings/{finding}/remediate"
    with _client(fake_cloud) as client:
        def preview() -> str:
            answer = client.get(f"{path}/preview", params={"action": "block_ip", "method": "waf"})
            return answer.json()["confirm_token"]

        token = preview()
        body = {"action": "block_ip", "dry_run": False, "method": "waf"}
        forged = token[:-4] + ("0000" if not token.endswith("0000") else "1111")
        for attempt in (
            {**body, "confirm_token": forged},
            {**body, "method": "nacl", "confirm_token": token},
            {**body, "dry_run": True, "confirm_token": token},
        ):
            assert client.post(path, json=attempt).json()["error"]["code"] == (
                "remediation_token_invalid"
            )
        assert fake_cloud.findings.consume_open_previews(finding) == 1
        spent = client.post(path, json={**body, "confirm_token": token})
        assert spent.status_code == 409
        assert client.post(path, json={**body, "confirm_token": preview()}).status_code == 202
    assert [e["method"] for e in fake_cloud.findings.executed()] == ["waf"]


# ---------------------------------------------------------------------------
# Secrets stay out of logs and artifacts
# ---------------------------------------------------------------------------


def test_bitwarden_stand_ins_log_digests_not_secrets(journey):
    from e2e.harness.bitwarden import FakeBitwarden
    from e2e.harness.bitwarden_shim import digest

    vault = FakeBitwarden(journey.shims)
    project = vault.add_project("servers")
    env = {**os.environ, "BWS_ACCESS_TOKEN": vault.access_token}
    bws = str(journey.shims.path_of("bws"))
    bw = str(journey.shims.path_of("bw"))
    for argv in (
        [bws, "--output", "json", "secret", "create", "db/web-1", SECRET, project],
        [bws, "--access-token", vault.access_token, "project", "list"],
        [bw, "--session", vault.session, "list", "items"],
        [bw, "unlock", "--raw", vault.master_password],
    ):
        subprocess.run(argv, env=env, capture_output=True, timeout=30, check=False)
    log = (journey.shims.directory / "argv.jsonl").read_text(encoding="utf-8")
    for secret in (SECRET, vault.access_token, vault.session, vault.master_password):
        assert secret not in log
    create = [c for c in vault.calls("bws") if "create" in c.argv][0]
    assert create.argv[-2:] == [digest(SECRET), project]
    assert vault.secrets(project) == {"db/web-1": SECRET}


def test_registered_secrets_never_reach_an_artifact(e2e_ctx):
    from e2e.harness.artifacts import _rewrite, register_secret
    from e2e.harness.bitwarden import fabricated_ssh_key

    private, _ = fabricated_ssh_key()
    register_secret(SECRET, private)
    text = json.dumps({"note": f"value {SECRET} here", "key": private}) + "\n" + private
    rewritten = _rewrite(text, e2e_ctx)
    assert SECRET not in rewritten
    for line in private.splitlines():
        assert line not in rewritten
