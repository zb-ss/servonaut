"""Every urllib request verifies HTTPS with the shared context that carries certifi roots."""

from __future__ import annotations

import ssl
import urllib.request

import certifi
import pytest

from servonaut.services import ip_enrichment_service, update_service, voice_models
from servonaut.updates import index
from servonaut.utils import tls


@pytest.fixture
def empty_system_trust(tmp_path, monkeypatch):
    """Point OpenSSL's defaults at nothing, as a bundle with a foreign OPENSSLDIR does."""
    nothing = tmp_path / "missing"
    monkeypatch.setenv("SSL_CERT_FILE", str(nothing))
    monkeypatch.setenv("SSL_CERT_DIR", str(nothing))
    tls.client_ssl_context.cache_clear()
    yield
    tls.client_ssl_context.cache_clear()


def test_context_has_roots_when_the_system_has_none(empty_system_trust):
    assert ssl.create_default_context().cert_store_stats()["x509_ca"] == 0

    context = tls.client_ssl_context()

    assert context.cert_store_stats()["x509_ca"] > 0
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname


def test_context_keeps_the_trust_named_by_ssl_cert_file(tmp_path, monkeypatch):
    # A corporate or test CA arrives through SSL_CERT_FILE and must keep working.
    bundle = tmp_path / "extra.pem"
    bundle.write_bytes(open(certifi.where(), "rb").read().split(b"\n\n")[0] + b"\n")
    monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path / "missing"))
    tls.client_ssl_context.cache_clear()
    try:
        assert tls.client_ssl_context().cert_store_stats()["x509_ca"] >= 1
    finally:
        tls.client_ssl_context.cache_clear()


def test_context_is_cached():
    assert tls.client_ssl_context() is tls.client_ssl_context()


def test_missing_certifi_falls_back_to_system_trust(monkeypatch):
    monkeypatch.setitem(__import__("sys").modules, "certifi", None)
    tls.client_ssl_context.cache_clear()
    try:
        assert tls.client_ssl_context().verify_mode is ssl.CERT_REQUIRED
    finally:
        tls.client_ssl_context.cache_clear()


def _https_context(opener: urllib.request.OpenerDirector) -> ssl.SSLContext:
    handlers = [h for h in opener.handlers if isinstance(h, urllib.request.HTTPSHandler)]
    assert len(handlers) == 1
    return handlers[0]._context


@pytest.mark.parametrize(
    "build",
    [
        update_service.build_https_opener,
        voice_models.build_https_only_opener,
        lambda: tls.build_opener(),
    ],
)
def test_opener_builders_carry_the_shared_context(build):
    assert _https_context(build()) is tls.client_ssl_context()


def test_index_opener_carries_the_shared_context(monkeypatch):
    seen = []

    def capture(self, request, timeout=None):
        seen.append(self)
        raise OSError("stop")

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", capture)
    with pytest.raises(OSError):
        index._open("https://example.invalid/x", 1)
    assert _https_context(seen[0]) is tls.client_ssl_context()
    assert any(isinstance(h, index._RestrictedRedirects) for h in seen[0].handlers)


@pytest.mark.asyncio
async def test_ip_enrichment_opener_carries_the_shared_context(monkeypatch):
    seen = []

    def capture(self, request, timeout=None):
        seen.append(self)
        raise OSError("stop")

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", capture)
    service = ip_enrichment_service.IPEnrichmentService()
    with pytest.raises(OSError):
        await service._urllib_request("https://example.invalid/x", method="GET")
    assert _https_context(seen[0]) is tls.client_ssl_context()
    assert any(isinstance(h, ip_enrichment_service._RefuseRedirects) for h in seen[0].handlers)


def test_selftest_ca_probe_checks_the_shared_context(monkeypatch):
    from servonaut import _artifact_selftest as selftest

    selftest._probe_ca_bundle()

    class Empty:
        def cert_store_stats(self):
            return {"x509_ca": 0}

    monkeypatch.setattr(tls, "client_ssl_context", lambda: Empty())
    with pytest.raises(selftest._SelftestFailure) as failure:
        selftest._probe_ca_bundle()
    assert failure.value.code == "diagnostic-ca"


def test_a_certificate_failure_is_logged_as_such_without_the_url(tmp_path, caplog):
    from servonaut.services.update_service import UpdateCheckResult, UpdateService
    from tests.services.test_update_service_frozen import _FakeOpener, _make_frozen_runtime
    import urllib.error

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from servonaut.distribution import TrustPolicy
    from servonaut.runtime import DistributionKind

    failure = ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer certificate")
    failure.verify_message = "unable to get local issuer certificate"
    runtime = _make_frozen_runtime(tmp_path, kind=DistributionKind.PACKAGED_DESKTOP)
    service = UpdateService(
        runtime, manifest_url="https://secret-host.example/manifest.json",
        trust_policy=TrustPolicy(
            trusted_public_keys={"k": Ed25519PrivateKey.generate().public_key()}, minimum_signatures=1,
        ),
        opener=_FakeOpener(urllib.error.URLError(failure)),
    )

    with caplog.at_level("WARNING", logger=update_service.__name__):
        assert service.check_for_update() is None

    assert service.last_check_result is UpdateCheckResult.OFFLINE
    assert "certificate verification failed (unable to get local issuer certificate)" in caplog.text
    assert "URLError" in caplog.text
    assert "secret-host" not in caplog.text
    assert service.update_status == "Could not reach the update server. Check your connection and try again."


def test_an_unreachable_server_is_logged_at_info_so_it_never_reaches_stderr(tmp_path, caplog):
    # Offline use is ordinary; where logging is not set up (the packaged
    # build's self-test), Python prints only WARNING and above to stderr.
    import logging
    import urllib.error

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from servonaut.distribution import TrustPolicy
    from servonaut.runtime import DistributionKind
    from servonaut.services.update_service import UpdateCheckResult, UpdateService
    from tests.services.test_update_service_frozen import _FakeOpener, _make_frozen_runtime

    runtime = _make_frozen_runtime(tmp_path, kind=DistributionKind.PACKAGED_DESKTOP)
    service = UpdateService(
        runtime, manifest_url="https://127.0.0.1:9/manifest.json",
        trust_policy=TrustPolicy(
            trusted_public_keys={"k": Ed25519PrivateKey.generate().public_key()}, minimum_signatures=1,
        ),
        opener=_FakeOpener(urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))),
    )
    with caplog.at_level("INFO", logger=update_service.__name__):
        assert service.check_for_update() is None
    assert service.last_check_result is UpdateCheckResult.OFFLINE
    records = [r for r in caplog.records if "Release manifest request failed" in r.getMessage()]
    assert records and all(r.levelno == logging.INFO for r in records)
