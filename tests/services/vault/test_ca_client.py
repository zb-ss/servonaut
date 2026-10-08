"""CA client tests include real OpenSSH certificate parsing and verification."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from servonaut.services.vault.ca_client import (
    CertificateAuthorityClient,
    CertificateValidationError,
    _fingerprint,
)
from servonaut.services.vault.ca_pins import CaPinMismatchError, CaPinStore
from servonaut.services.vault.crypto import build_ed25519_certificate, ssh_ed25519_public_blob


TEAM = "example-team"
DEVICE = "device-1234"
SERVER = "server-1234"


class _KeyStore:
    def __init__(self) -> None:
        self.key: bytes | None = None

    def get_device_ssh_private_key(self) -> bytes | None:
        return self.key

    def store_device_ssh_private_key(self, private_key: bytes) -> None:
        self.key = private_key


class _Api:
    def __init__(self, status: dict[str, Any], certificate: dict[str, Any]) -> None:
        self.status = status
        self.certificate = certificate
        self.signed: list[tuple[str, str, dict[str, Any] | None]] = []

    async def get(self, path: str) -> dict[str, Any]:
        assert path == f"/api/v1/teams/{TEAM}/ssh-ca"
        return self.status

    async def request_signed(
        self, method: str, path: str, body: dict[str, Any] | None, device: object
    ) -> dict[str, Any]:
        self.signed.append((method, path, body))
        if path.endswith("/certs"):
            return self.certificate
        return {"success": True}


def _public_line(seed: bytes, comment: str) -> str:
    from nacl.signing import SigningKey

    blob = ssh_ed25519_public_blob(bytes(SigningKey(seed).verify_key))
    return f"ssh-ed25519 {base64.b64encode(blob).decode('ascii')} {comment}"


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="OpenSSH ssh-keygen is unavailable")
def test_ca_fingerprint_matches_openssh_tooling(tmp_path: Path):
    public_line = Ed25519PrivateKey.generate().public_key().public_bytes(
        Encoding.OpenSSH, PublicFormat.OpenSSH
    ).decode("ascii") + " ca"
    public_file = tmp_path / "ca.pub"
    public_file.write_text(public_line + "\n", encoding="ascii")

    rendered = subprocess.run(
        ["ssh-keygen", "-lf", str(public_file), "-E", "sha256"],
        check=True, capture_output=True, text=True,
    ).stdout

    assert _fingerprint(public_line) in rendered


def _fixture_response() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    from nacl.signing import SigningKey

    ca_seed = b"c" * 32
    host_seed = b"h" * 32
    subject = Ed25519PrivateKey.generate()
    subject_public = subject.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    valid_after = int((now - timedelta(seconds=30)).timestamp())
    valid_before = int((now + timedelta(hours=1)).timestamp())
    user_line = _public_line(ca_seed, "user-ca")
    host_line = _public_line(host_seed, "host-ca")
    _, _, blob = build_ed25519_certificate(
        subject_public,
        7,
        1,
        "test-lease",
        [f"svn:{SERVER}:deploy"],
        valid_after,
        valid_before,
        {},
        ["permit-pty"],
        b"n" * 32,
        bytes(SigningKey(ca_seed).verify_key),
        ca_seed,
    )
    status = {
        "enabled": True,
        "user_ca": {"public_key": user_line, "fingerprint": _fingerprint(user_line)},
        "host_ca": {"public_key": host_line, "fingerprint": _fingerprint(host_line)},
        "policy": {},
        "my_logins_by_server": {SERVER: ["deploy"]},
        "krl_version": 1,
    }
    certificate = {
        "certificate": "ssh-ed25519-cert-v01@openssh.com " + base64.b64encode(blob).decode("ascii") + " test",
        "serial": 7,
        "principals": [f"svn:{SERVER}:deploy"],
        "logins_by_server": {SERVER: ["deploy"]},
        "valid_after": datetime.fromtimestamp(valid_after, timezone.utc).isoformat(),
        "valid_before": datetime.fromtimestamp(valid_before, timezone.utc).isoformat(),
        "renew_after": datetime.fromtimestamp(valid_after + 1800, timezone.utc).isoformat(),
        "ca_fingerprint": status["user_ca"]["fingerprint"],
    }
    return status, certificate, subject.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())


@pytest.mark.asyncio
async def test_issues_and_parses_real_openssh_certificate(tmp_path: Path):
    status, response, private_key = _fixture_response()
    api = _Api(status, response)
    client = CertificateAuthorityClient(
        api, TEAM, object(), DEVICE, _store(private_key),
        pins=CaPinStore(tmp_path / "pins.json"), certificate_dir=tmp_path / "certs",
    )

    certificate = await client.issue_certificate([SERVER], requested_ttl_seconds=3600)

    assert certificate.principals == (f"svn:{SERVER}:deploy",)
    assert certificate.certificate_path.read_text(encoding="ascii").startswith("ssh-ed25519-cert-v01@openssh.com ")
    assert certificate.certificate_path.stat().st_mode & 0o777 == 0o600
    assert api.signed[-1][1].endswith("/certs")


@pytest.mark.asyncio
async def test_reuses_cached_certificate_before_server_renew_after_then_renews(tmp_path: Path):
    status, response, private_key = _fixture_response()
    api = _Api(status, response)
    client = CertificateAuthorityClient(
        api, TEAM, object(), DEVICE, _store(private_key),
        pins=CaPinStore(tmp_path / "pins.json"), certificate_dir=tmp_path / "certs",
    )
    issued = await client.issue_certificate([SERVER], purpose="automation")
    cached = client.load_cached_certificate([SERVER], purpose="automation", status=await client.get_status())

    assert cached is not None
    assert await client.renew_if_due(cached, [SERVER], purpose="automation") is None
    assert len([call for call in api.signed if call[1].endswith("/certs")]) == 1

    metadata_path = cached.certificate_path.with_suffix(".json")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["renew_after"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    due = client.load_cached_certificate([SERVER], purpose="automation", status=await client.get_status())

    assert due is not None
    assert await client.renew_if_due(due, [SERVER], purpose="automation") is not None
    assert len([call for call in api.signed if call[1].endswith("/certs")]) == 2


@pytest.mark.asyncio
async def test_cached_certificate_is_not_reused_after_the_team_krl_changes(tmp_path: Path):
    # A revoked certificate would be refused by every host until it expires;
    # members only see the KRL version, so any change means a fresh certificate.
    status, response, private_key = _fixture_response()
    api = _Api(status, response)
    client = CertificateAuthorityClient(
        api, TEAM, object(), DEVICE, _store(private_key),
        pins=CaPinStore(tmp_path / "pins.json"), certificate_dir=tmp_path / "certs",
    )
    await client.issue_certificate([SERVER], purpose="interactive")
    assert client.load_cached_certificate([SERVER], purpose="interactive", status=await client.get_status()) is not None

    api.status = {**status, "krl_version": 2}

    assert client.load_cached_certificate([SERVER], purpose="interactive", status=await client.get_status()) is None


def test_certificate_artifacts_are_immutable_per_serial_and_contents(tmp_path: Path):
    status, response, private_key = _fixture_response()
    client = CertificateAuthorityClient(
        _Api(status, response), TEAM, object(), DEVICE, _store(private_key),
        pins=CaPinStore(tmp_path / "pins.json"), certificate_dir=tmp_path / "certs",
    )

    first = client._write_public_certificate("ssh-ed25519-cert-v01@openssh.com AAAA first", 7)
    second = client._write_public_certificate("ssh-ed25519-cert-v01@openssh.com BBBB second", 8)

    assert first != second
    assert first.read_text(encoding="ascii").endswith("AAAA first\n")
    assert second.read_text(encoding="ascii").endswith("BBBB second\n")


def test_client_discovers_only_its_immutable_certificate_artifacts(tmp_path: Path):
    status, response, private_key = _fixture_response()
    client = CertificateAuthorityClient(
        _Api(status, response), TEAM, object(), DEVICE, _store(private_key),
        pins=CaPinStore(tmp_path / "pins.json"), certificate_dir=tmp_path / "certs",
    )
    certificate = client._write_public_certificate("ssh-ed25519-cert-v01@openssh.com AAAA", 7)
    (certificate.parent / "unrelated.cert.pub").write_text("not a certificate", encoding="ascii")

    assert client._local_certificate_paths() == {7: certificate}


@pytest.mark.asyncio
async def test_rejects_certificate_claiming_a_different_ca(tmp_path: Path):
    status, response, private_key = _fixture_response()
    response["ca_fingerprint"] = "SHA256:not-the-pinned-ca"
    client = CertificateAuthorityClient(
        _Api(status, response), TEAM, object(), DEVICE, _store(private_key),
        pins=CaPinStore(tmp_path / "pins.json"), certificate_dir=tmp_path / "certs",
    )

    with pytest.raises(CertificateValidationError, match="different CA"):
        await client.issue_certificate([SERVER])


@pytest.mark.asyncio
async def test_refuses_ca_pin_change(tmp_path: Path):
    status, response, private_key = _fixture_response()
    pins = CaPinStore(tmp_path / "pins.json")
    first = CertificateAuthorityClient(_Api(status, response), TEAM, object(), DEVICE, _store(private_key), pins=pins)
    await first.get_status()
    status["host_ca"] = {"public_key": status["user_ca"]["public_key"], "fingerprint": status["user_ca"]["fingerprint"]}
    changed = CertificateAuthorityClient(_Api(status, response), TEAM, object(), DEVICE, _store(private_key), pins=pins)

    with pytest.raises(CaPinMismatchError):
        await changed.get_status()


@pytest.mark.asyncio
async def test_registers_a_per_device_ed25519_key(tmp_path: Path):
    status, response, _ = _fixture_response()
    store = _KeyStore()
    api = _Api(status, response)
    client = CertificateAuthorityClient(api, TEAM, object(), DEVICE, store, pins=CaPinStore(tmp_path / "pins.json"))

    key = await client.register_device_key()

    assert store.key is not None
    assert key.public_key.startswith("ssh-ed25519 ")
    assert api.signed[-1] == (
        "PUT", f"/api/v1/vault/devices/{DEVICE}/ssh-key", {"ssh_public_key": key.public_key}
    )


@pytest.mark.asyncio
async def test_invalid_ca_response_does_not_create_a_tofu_pin(tmp_path: Path):
    status, response, private_key = _fixture_response()
    status["user_ca"]["fingerprint"] = "SHA256:wrong"
    pin_path = tmp_path / "pins.json"
    client = CertificateAuthorityClient(_Api(status, response), TEAM, object(), DEVICE, _store(private_key), pins=CaPinStore(pin_path))

    with pytest.raises(CertificateValidationError, match="fingerprint"):
        await client.get_status()
    assert not pin_path.exists()


@pytest.mark.asyncio
async def test_rejects_newline_injected_ca_before_pinning(tmp_path: Path):
    status, response, private_key = _fixture_response()
    status["host_ca"]["public_key"] += "\nattacker.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGF0dGFja2Vy"
    pin_path = tmp_path / "pins.json"
    client = CertificateAuthorityClient(_Api(status, response), TEAM, object(), DEVICE, _store(private_key), pins=CaPinStore(pin_path))

    with pytest.raises(CertificateValidationError, match="printable line"):
        await client.get_status()
    assert not pin_path.exists()


@pytest.mark.asyncio
async def test_rejects_certificate_for_a_different_device_key(tmp_path: Path):
    status, response, _ = _fixture_response()
    client = CertificateAuthorityClient(
        _Api(status, response), TEAM, object(), DEVICE, _KeyStore(),
        pins=CaPinStore(tmp_path / "pins.json"), certificate_dir=tmp_path / "certs",
    )
    with pytest.raises(CertificateValidationError, match="subject"):
        await client.issue_certificate([SERVER])


@pytest.mark.asyncio
async def test_rejects_relaxed_source_address_constraint(tmp_path: Path):
    status, response, private_key = _fixture_response()
    status["policy"] = {"source_address_cidrs": ["192.0.2.0/24"]}
    client = CertificateAuthorityClient(
        _Api(status, response), TEAM, object(), DEVICE, _store(private_key),
        pins=CaPinStore(tmp_path / "pins.json"), certificate_dir=tmp_path / "certs",
    )
    with pytest.raises(CertificateValidationError, match="source-address"):
        await client.issue_certificate([SERVER])


def _store(private_key: bytes) -> _KeyStore:
    store = _KeyStore()
    store.key = private_key
    return store


@pytest.mark.asyncio
async def test_first_device_key_registration_keeps_later_requests_signed_validly(tmp_path: Path):
    # The CA client holds the device it was built with. Creating the device
    # SSH key on first use must not wipe that device's signing key.
    from nacl.signing import VerifyKey

    from servonaut.services.vault.identity_store import IdentityStore

    store = IdentityStore(tmp_path / "vault_keys.json", environment_key=base64.b64encode(b"\0" * 32).decode())
    identity = store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=1)
    store.save()
    device_public = identity.device.signing_public_key

    class SigningApi:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def request_signed(self, method, path, body, device):
            VerifyKey(device_public).verify(path.encode(), device.sign(path.encode()))  # raises if wiped
            self.calls.append(f"{method} {path}")
            return {}

    api = SigningApi()
    client = CertificateAuthorityClient(api, TEAM, identity.device, identity.device.device_id, store,
                                        pins=CaPinStore(tmp_path / "pins.json"), certificate_dir=tmp_path / "certs")

    await client.register_device_key()
    await client.register_device_key()

    assert len(api.calls) == 2


def _ecdsa_ca() -> tuple[Any, str]:
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    return key, key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")


def _generation(line: str, generation: int, status: str) -> dict[str, Any]:
    return {"generation": generation, "alg": line.split()[0], "public_key": line,
            "fingerprint": _fingerprint(line), "status": status}


@pytest.mark.asyncio
async def test_status_reports_and_pins_an_announced_ecdsa_next_ca(tmp_path: Path):
    status, response, private_key = _fixture_response()
    _, next_line = _ecdsa_ca()
    status["user_ca_next"] = _generation(next_line, 2, "next")
    pins = CaPinStore(tmp_path / "pins.json")
    client = CertificateAuthorityClient(_Api(status, response), TEAM, object(), DEVICE, _store(private_key), pins=pins)

    read = await client.get_status()

    assert read.user_ca_next_fingerprint == _fingerprint(next_line)
    assert read.trusted_user_ca_fingerprints == {status["user_ca"]["fingerprint"], _fingerprint(next_line)}
    assert read.to_dict()["user_ca_next_fingerprint"] == _fingerprint(next_line)


@pytest.mark.asyncio
async def test_a_next_ca_whose_fingerprint_does_not_match_its_key_is_refused(tmp_path: Path):
    status, response, private_key = _fixture_response()
    _, next_line = _ecdsa_ca()
    status["user_ca_next"] = {**_generation(next_line, 2, "next"), "fingerprint": status["user_ca"]["fingerprint"]}
    client = CertificateAuthorityClient(
        _Api(status, response), TEAM, object(), DEVICE, _store(private_key), pins=CaPinStore(tmp_path / "pins.json"),
    )

    with pytest.raises(CertificateValidationError, match="does not match its key"):
        await client.get_status()


@pytest.mark.asyncio
async def test_after_a_rollover_to_an_ecdsa_ca_certificates_it_signs_are_accepted(tmp_path: Path):
    from cryptography.hazmat.primitives.serialization import load_ssh_private_key
    from cryptography.hazmat.primitives.serialization.ssh import SSHCertificateBuilder, SSHCertificateType

    status, response, private_key = _fixture_response()
    pins = CaPinStore(tmp_path / "pins.json")
    await CertificateAuthorityClient(
        _Api(status, response), TEAM, object(), DEVICE, _store(private_key), pins=pins,
    ).get_status()  # pinned the Ed25519 generation 1

    ca_key, ca_line = _ecdsa_ca()
    old = status["user_ca"]
    status["user_ca"] = _generation(ca_line, 2, "active")
    status["user_ca_previous"] = [{**_generation(old["public_key"], 1, "previous")}]
    valid_after = int(datetime.fromisoformat(response["valid_after"]).timestamp())
    valid_before = int(datetime.fromisoformat(response["valid_before"]).timestamp())
    certificate = (
        SSHCertificateBuilder()
        .public_key(load_ssh_private_key(private_key, None).public_key())
        .serial(7).type(SSHCertificateType.USER).key_id(b"test-lease")
        .valid_principals([f"svn:{SERVER}:deploy".encode()])
        .valid_after(valid_after).valid_before(valid_before)
        .add_extension(b"permit-pty", b"")
        .sign(ca_key)
    )
    response["certificate"] = certificate.public_bytes().decode("ascii") + " test"
    response["ca_fingerprint"] = _fingerprint(ca_line)
    client = CertificateAuthorityClient(
        _Api(status, response), TEAM, object(), DEVICE, _store(private_key),
        pins=pins, certificate_dir=tmp_path / "certs",
    )

    issued = await client.issue_certificate([SERVER], requested_ttl_seconds=3600)

    assert issued.ca_fingerprint == _fingerprint(ca_line)
    assert issued.certificate_path.read_text(encoding="ascii").startswith("ssh-ed25519-cert-v01@openssh.com ")
    assert pins.pinned(TEAM).user_ca_fingerprint == _fingerprint(ca_line)


@pytest.mark.asyncio
async def test_showing_a_changed_ca_for_trust_does_not_touch_the_pins(tmp_path: Path):
    status, response, private_key = _fixture_response()
    pins = CaPinStore(tmp_path / "pins.json")
    await CertificateAuthorityClient(_Api(status, response), TEAM, object(), DEVICE, _store(private_key), pins=pins).get_status()
    _, other = _ecdsa_ca()
    status["user_ca"] = _generation(other, 2, "active")
    client = CertificateAuthorityClient(_Api(status, response), TEAM, object(), DEVICE, _store(private_key), pins=pins)

    shown = await client.get_status(enforce_pins=False)

    assert shown.user_ca_fingerprint == _fingerprint(other)
    with pytest.raises(CaPinMismatchError):
        await client.get_status()


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["next_not_newer", "previous_not_older", "previous_not_a_list"])
async def test_ca_generations_out_of_order_or_malformed_are_refused(tmp_path: Path, change: str):
    status, response, private_key = _fixture_response()
    status["user_ca"]["generation"] = 2
    _, other = _ecdsa_ca()
    if change == "next_not_newer":
        status["user_ca_next"] = _generation(other, 2, "next")
    elif change == "previous_not_older":
        status["user_ca_previous"] = [_generation(other, 3, "previous")]
    else:
        status["user_ca_previous"] = {"fingerprint": _fingerprint(other)}
    client = CertificateAuthorityClient(
        _Api(status, response), TEAM, object(), DEVICE, _store(private_key), pins=CaPinStore(tmp_path / "pins.json"),
    )

    with pytest.raises(CertificateValidationError):
        await client.get_status()
    assert not (tmp_path / "pins.json").exists()


@pytest.mark.asyncio
async def test_installable_user_cas_are_labelled_for_the_confirmation(tmp_path: Path):
    status, response, private_key = _fixture_response()
    status["user_ca"]["generation"] = 2
    _, upcoming = _ecdsa_ca()
    _, retired = _ecdsa_ca()
    status["user_ca_next"] = _generation(upcoming, 3, "next")
    status["user_ca_previous"] = [_generation(retired, 1, "previous")]
    client = CertificateAuthorityClient(
        _Api(status, response), TEAM, object(), DEVICE, _store(private_key), pins=CaPinStore(tmp_path / "pins.json"),
    )

    roles = (await client.get_status()).user_ca_roles

    assert roles == {status["user_ca"]["fingerprint"]: "active (pinned)",
                     _fingerprint(upcoming): "next (new)", _fingerprint(retired): "retired"}
