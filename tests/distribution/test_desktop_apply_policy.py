"""Signed policy and fresh staged apply decisions with fixture Ed25519 keys."""
from __future__ import annotations

import hashlib
import io
import stat
import urllib.error
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from servonaut.distribution import (
    ArtifactKind, ManifestError, ManifestSignatureError, ReleaseArtifact, ReleaseChannel, ReleaseManifest,
    TrustPolicy, canonicalize_json, sign_manifest,
)
from servonaut.distribution.apply_policy import (
    DesktopApplyPolicy, DesktopArtifactIdentity, sign_apply_policy, verify_apply_policy,
)
from servonaut.runtime import DistributionKind, RuntimeCapabilityError
from servonaut.services.update_service import UpdateCheckResult, UpdateService
from servonaut.updates.desktop_apply import DESKTOP_STAGING_DIR, DesktopApplyDecision, DesktopApplyEvidence, StagedDesktopUpdate

MANIFEST_URL = "https://releases.example.test/manifest/stable.json"
POLICY_URL = "https://releases.example.test/manifest/stable-apply.json"
KEY_ID = "fixture-release"
PAYLOAD = b"a verified disk image fixture"


class ApplyFixture:
    def __init__(self, root):
        self.calls = []
        self.documents = {}
        self.key = Ed25519PrivateKey.generate()
        self.trust = TrustPolicy(
            {KEY_ID: self.key.public_key()}, allowed_origin_prefixes=("https://releases.example.test/",),
            allowed_channels=(ReleaseChannel.STABLE, ReleaseChannel.PREVIEW),
        )
        self.now = datetime.now(timezone.utc)
        self.artifact = ReleaseArtifact(
            "macos-dmg-arm64", ArtifactKind.MACOS_DMG, DistributionKind.PACKAGED_DESKTOP,
            "darwin", "arm64", "desktop.dmg", "https://releases.example.test/desktop.dmg",
            len(PAYLOAD), hashlib.sha256(PAYLOAD).hexdigest(), min_os="13.0",
        )
        self.manifest = ReleaseManifest(
            1, ReleaseChannel.STABLE, "1.2.4", self.now.isoformat(), (self.artifact,), (),
            packaging_revision=2, expires_at=(self.now + timedelta(days=1)).isoformat(),
        )
        self.identity = DesktopArtifactIdentity.from_artifact(self.manifest, self.artifact)
        staging = root / DESKTOP_STAGING_DIR
        staging.mkdir(mode=0o700)
        self.staged = StagedDesktopUpdate(self.identity, staging / self.artifact.filename)
        self.staged.path.write_bytes(PAYLOAD)
        self.staged.path.chmod(0o600)
        self.root = root
        self.set_manifest(self.manifest)
        self.set_policy(self.policy())

    def service(self, channel="stable", *, current="1.2.3", revision=1, trust=None):
        runtime = SimpleNamespace(
            kind=DistributionKind.PACKAGED_DESKTOP, release_channel=channel,
            packaging_revision=revision, product_version=current, data_root=self.root,
        )
        return UpdateService(runtime, manifest_url=MANIFEST_URL, trust_policy=trust or self.trust, opener=self)

    def open(self, request, *, timeout):
        self.calls.append((request.full_url, request.get_header("Cache-control"), timeout))
        body = self.documents.get(request.full_url)
        if body is None:
            raise urllib.error.HTTPError(request.full_url, 404, "fixture missing", {}, None)
        if isinstance(body, Exception):
            raise body
        response = io.BytesIO(body)
        response.headers = {"Content-Length": str(len(body))}
        return response

    def policy(self, sequence=10, **changes):
        document = DesktopApplyPolicy(
            ReleaseChannel.STABLE, sequence, (self.now - timedelta(minutes=1)).isoformat(),
            (self.now + timedelta(minutes=59)).isoformat(), False, (self.identity,),
        )
        return replace(document, **changes)

    def set_policy(self, policy):
        signed = sign_apply_policy(policy, self.key, KEY_ID)
        self.documents[POLICY_URL] = canonicalize_json(signed.to_dict())
        return signed

    def set_manifest(self, manifest):
        signed = sign_manifest(manifest, self.key, KEY_ID)
        self.documents[MANIFEST_URL] = canonicalize_json(signed.to_dict())
        return signed

    def check(self):
        return self.service().authorize_staged_desktop_apply(self.staged)


@pytest.fixture
def apply(tmp_path):
    return ApplyFixture(tmp_path)


def test_exact_apply_fetches_both_fresh_documents_without_cache(apply):
    assert apply.check() is DesktopApplyDecision.AUTHORIZED
    assert apply.staged.path.read_bytes() == PAYLOAD
    assert [url for url, _, _ in apply.calls] == [POLICY_URL, MANIFEST_URL]
    assert all("no-cache" in cache and "no-store" in cache and timeout > 0 for _, cache, timeout in apply.calls)


def test_private_macos_stage_reuses_only_the_exact_verified_download(apply):
    service = apply.service()
    service._latest_manifest = apply.set_manifest(apply.manifest)
    service._target_artifact = apply.artifact
    apply.documents[apply.artifact.download_url] = PAYLOAD

    staged = service.stage_macos_desktop_update()
    assert staged.identity == apply.identity
    assert staged.path == apply.staged.path.parent / f"{apply.artifact.sha256}.dmg"
    assert stat.S_IMODE(staged.path.stat().st_mode) == 0o600
    assert service.downloaded_path is None
    assert service.stage_macos_desktop_update() == staged
    assert [url for url, _, _ in apply.calls] == [POLICY_URL, apply.artifact.download_url, POLICY_URL]

    staged.path.write_bytes(b"x" * len(PAYLOAD))
    assert service.stage_macos_desktop_update() == staged
    assert staged.path.read_bytes() == PAYLOAD
    assert [url for url, _, _ in apply.calls] == [
        POLICY_URL, apply.artifact.download_url, POLICY_URL, POLICY_URL, apply.artifact.download_url,
    ]
    assert apply.check() is DesktopApplyDecision.AUTHORIZED  # same signed publication is current


@pytest.mark.parametrize("outcome", ["allowed", "missing", "paused", "withdrawn", "unsupported-installation"])
def test_mac_offer_needs_preflight_and_a_signed_policy_before_download(apply, monkeypatch, outcome):
    from servonaut.updates.macos_install import Installation, MacUpdateError

    service = apply.service()
    service._latest_manifest = apply.set_manifest(apply.manifest)
    service._target_artifact = apply.artifact
    service._last_result = UpdateCheckResult.UPDATE_AVAILABLE
    validated = Mock(side_effect=MacUpdateError("fixture ownership") if outcome == "unsupported-installation" else None)
    monkeypatch.setattr(Installation, "from_runtime", lambda _: SimpleNamespace(validate_offer=validated))
    if outcome == "missing":
        apply.documents.pop(POLICY_URL)
    elif outcome == "paused":
        apply.set_policy(apply.policy(paused=True, permitted=()))
    elif outcome == "withdrawn":
        apply.set_policy(apply.policy(permitted=(), withdrawn=(apply.identity,)))

    service._check_macos_offer(apply.manifest, apply.artifact)
    assert service.macos_install_offered == (outcome == "allowed")
    validated.assert_called_once()
    if outcome == "unsupported-installation":
        assert apply.calls == []
    if outcome in ("missing", "paused", "withdrawn"):
        with pytest.raises(RuntimeCapabilityError, match="Download and install"):
            service.stage_macos_desktop_update()
        assert all(url == POLICY_URL for url, _, _ in apply.calls)


def test_prepared_policy_rechecks_expiry_and_replay_without_network(apply):
    import time_machine

    service = apply.service()
    evidence = service.prepare_staged_desktop_apply(apply.staged)
    assert isinstance(evidence, DesktopApplyEvidence)
    assert evidence.is_current()
    with time_machine.travel(apply.now + timedelta(hours=2), tick=False):
        assert not evidence.is_current()
    assert [url for url, _, _ in apply.calls] == [POLICY_URL, MANIFEST_URL]
    apply.set_policy(apply.policy(sequence=11))
    assert service._read_macos_policy().sequence == 11
    assert not evidence.is_current()
    assert [url for url, _, _ in apply.calls] == [POLICY_URL, MANIFEST_URL, POLICY_URL]


def test_prepared_policy_does_not_follow_replaced_replay_state(apply):
    evidence = apply.service().prepare_staged_desktop_apply(apply.staged)
    assert isinstance(evidence, DesktopApplyEvidence)
    state = evidence.state_dir / "stable.json"
    relocated = state.rename(state.with_suffix(".saved"))
    try:
        state.symlink_to(relocated)
    except OSError:
        pytest.skip("the platform does not allow test symlinks")
    assert not evidence.is_current()
    assert [url for url, _, _ in apply.calls] == [POLICY_URL, MANIFEST_URL]


@pytest.mark.parametrize(
    "bad_document",
    ["expired", "future", "tampered", "wrong-channel", "missing", "offline",
     "manifest-offline", "manifest-expired", "manifest-tampered"],
)
def test_unverified_or_unavailable_documents_defer_without_erasing_stage(apply, bad_document):
    if bad_document == "expired":
        apply.set_policy(apply.policy(issued_at=(apply.now - timedelta(hours=1)).isoformat(), expires_at=apply.now.isoformat()))
    elif bad_document == "future":
        apply.set_policy(apply.policy(issued_at=(apply.now + timedelta(minutes=6)).isoformat()))
    elif bad_document == "tampered":
        apply.documents[POLICY_URL] = apply.documents[POLICY_URL].replace(b'"sequence":10', b'"sequence":11')
    elif bad_document == "wrong-channel":
        apply.set_policy(apply.policy(channel=ReleaseChannel.PREVIEW))
    elif bad_document == "missing":
        del apply.documents[POLICY_URL]
    elif bad_document == "manifest-expired":
        apply.set_manifest(replace(apply.manifest, expires_at=(apply.now - timedelta(seconds=1)).isoformat()))
    elif bad_document == "manifest-tampered":
        apply.documents[MANIFEST_URL] = apply.documents[MANIFEST_URL].replace(b"1.2.4", b"1.2.5")
    else:
        url = POLICY_URL if bad_document == "offline" else MANIFEST_URL
        apply.documents[url] = urllib.error.URLError("offline fixture")

    assert apply.check() is DesktopApplyDecision.DEFERRED
    assert apply.staged.path.read_bytes() == PAYLOAD


@pytest.mark.parametrize("replayed_sequence", [10, 11])
def test_higher_sequence_refuses_a_replay_that_would_permit_the_staged_artifact(apply, replayed_sequence):
    apply.set_policy(apply.policy(sequence=11))
    del apply.documents[MANIFEST_URL]
    assert apply.check() is DesktopApplyDecision.DEFERRED
    apply.set_manifest(apply.manifest)
    # Both replayed documents permit the staged bytes. The equal-sequence
    # case changes the signed timestamps so the new signature conflicts.
    apply.set_policy(apply.policy(
        sequence=replayed_sequence, issued_at=(apply.now - timedelta(minutes=2)).isoformat(),
        expires_at=(apply.now + timedelta(minutes=58)).isoformat(),
    ))
    assert apply.check() is DesktopApplyDecision.DEFERRED
    assert apply.staged.path.exists()
    apply.set_policy(apply.policy(sequence=12))
    assert apply.check() is DesktopApplyDecision.AUTHORIZED


def test_symlinked_sequence_file_keeps_stage_and_does_not_read_or_replace_target(apply):
    sequence_dir = apply.root / "desktop-apply-policy"
    sequence_dir.mkdir(mode=0o700)
    external = apply.root / "external-policy-state.json"
    external.write_text("{")
    saved = sequence_dir / "stable.json"
    saved.symlink_to(external)
    assert apply.check() is DesktopApplyDecision.DEFERRED
    assert saved.is_symlink()
    assert external.read_text() == "{"
    assert apply.staged.path.exists()



def test_highest_sequence_is_independent_for_preview(apply):
    apply.set_policy(apply.policy(sequence=100))
    assert apply.check() is DesktopApplyDecision.AUTHORIZED
    apply.set_policy(apply.policy(sequence=1, channel=ReleaseChannel.PREVIEW))
    assert apply.service("preview").authorize_staged_desktop_apply(apply.staged) is DesktopApplyDecision.AUTHORIZED


@pytest.mark.parametrize("changed", ["version", "revision", "target", "digest", "file-digest"])
def test_manifest_must_match_policy_and_staged_bytes(apply, changed):
    manifest = apply.manifest
    if changed == "version":
        manifest = replace(manifest, product_version="1.2.5")
    elif changed == "revision":
        manifest = replace(manifest, packaging_revision=3)
    elif changed == "target":
        manifest = replace(manifest, artifacts=(replace(apply.artifact, arch="x86_64"),))
    elif changed == "digest":
        manifest = replace(manifest, artifacts=(replace(apply.artifact, sha256="a" * 64),))
    else:
        apply.staged.path.write_bytes(b"x" * len(PAYLOAD))
    apply.set_manifest(manifest)

    decision = DesktopApplyDecision.DENIED if changed == "file-digest" else DesktopApplyDecision.DEFERRED
    assert apply.check() is decision
    assert apply.staged.path.exists() == (changed != "file-digest")


def test_exact_withdrawal_disposes_even_when_manifest_was_unpublished(apply):
    apply.set_policy(apply.policy(permitted=(), withdrawn=(apply.identity,)))
    del apply.documents[MANIFEST_URL]
    assert apply.check() is DesktopApplyDecision.DENIED
    assert not apply.staged.path.exists()
    assert [url for url, _, _ in apply.calls] == [POLICY_URL]


def test_signed_denial_cannot_discard_an_artifact_outside_private_staging(apply):
    apply.set_policy(apply.policy(permitted=(), withdrawn=(apply.identity,)))
    download = apply.root / "download.dmg"
    download.write_bytes(PAYLOAD)
    staged = StagedDesktopUpdate(apply.identity, download)
    assert apply.service().authorize_staged_desktop_apply(staged) is DesktopApplyDecision.DEFERRED
    assert download.read_bytes() == PAYLOAD
    assert not apply.calls


def test_manifest_signature_cannot_authorize_a_policy_document(apply):
    manifest = apply.set_manifest(apply.manifest)
    policy = replace(apply.policy(), signatures=manifest.signatures)
    with pytest.raises(ManifestSignatureError):
        verify_apply_policy(policy, apply.trust, ReleaseChannel.STABLE, now=apply.now)


@pytest.mark.parametrize("paused", [False, True])
def test_unlisted_or_paused_policy_keeps_verified_download(apply, paused):
    apply.set_policy(apply.policy(paused=paused, permitted=()))
    assert apply.check() is DesktopApplyDecision.DEFERRED
    assert apply.staged.path.read_bytes() == PAYLOAD


def test_manifest_downgrade_discards_staged_file(apply):
    service = apply.service(current="1.2.4", revision=3)
    assert service.authorize_staged_desktop_apply(apply.staged) is DesktopApplyDecision.DENIED
    assert not apply.staged.path.exists()


def test_public_staging_defers_explicit_denial_without_unlinking(apply):
    apply.set_policy(apply.policy(permitted=(), withdrawn=(apply.identity,)))
    apply.staged.path.parent.chmod(0o755)
    assert apply.check() is DesktopApplyDecision.DEFERRED
    assert apply.staged.path.read_bytes() == PAYLOAD
    assert not apply.calls


def test_policy_issuance_uses_configured_skew_and_reports_an_excess(apply, caplog):
    apply.set_policy(apply.policy(issued_at=(apply.now + timedelta(minutes=2)).isoformat()))
    assert apply.check() is DesktopApplyDecision.AUTHORIZED
    strict = apply.service(trust=replace(apply.trust, clock_skew_tolerance_seconds=30))
    assert strict.authorize_staged_desktop_apply(apply.staged) is DesktopApplyDecision.DEFERRED
    assert "date and time" in strict.update_guidance
    assert "date and time" in caplog.text


def test_corrupt_state_recovers_only_from_verified_current_policy(apply, caplog):
    assert apply.check() is DesktopApplyDecision.AUTHORIZED
    state = apply.root / "desktop-apply-policy" / "stable.json"
    state.write_text("{")
    saved = apply.documents.pop(POLICY_URL)
    assert apply.check() is DesktopApplyDecision.DEFERRED
    assert state.read_text() == "{"
    apply.documents[POLICY_URL] = saved
    service = apply.service()
    assert service.authorize_staged_desktop_apply(apply.staged) is DesktopApplyDecision.AUTHORIZED
    assert '"sequence": 10' in state.read_text()
    assert "repaired its saved update policy" in service.update_guidance
    assert "repaired its saved update policy" in caplog.text


def test_policy_lifetime_limits_replay_after_state_recovery(apply):
    with pytest.raises(ManifestError, match="at most seven days"):
        apply.policy(expires_at=(apply.now + timedelta(days=7)).isoformat())


def test_a_three_day_policy_authorizes_the_staged_update(apply):
    # The publisher signs three-day policies; clients must accept them.
    apply.set_policy(apply.policy(expires_at=(apply.now + timedelta(days=3)).isoformat()))
    assert apply.check() is DesktopApplyDecision.AUTHORIZED


def test_stage_replacement_during_hash_is_deferred_without_unlinking(apply, monkeypatch):
    from servonaut.updates import desktop_apply

    def replace_stage(path, digest):
        swapped = path.with_name("replacement.dmg")
        swapped.write_bytes(PAYLOAD)
        swapped.chmod(0o600)
        swapped.replace(path)
        return True

    monkeypatch.setattr(desktop_apply, "verify_file_sha256", replace_stage)
    assert apply.check() is DesktopApplyDecision.DEFERRED
    assert apply.staged.path.read_bytes() == PAYLOAD


def test_non_desktop_runtime_does_not_open_apply_policy(apply):
    service = apply.service()
    service._runtime.kind = DistributionKind.FROZEN_CLI
    assert service.authorize_staged_desktop_apply(apply.staged) is DesktopApplyDecision.DEFERRED
    assert not apply.calls


@pytest.mark.parametrize("change", ["withdrawn", "paused", "sequence", "unknown", "purpose", "digest"])
def test_policy_rejects_invalid_signed_field_combinations(apply, change):
    data = apply.policy().to_dict()
    if change == "withdrawn":
        data["withdrawn"] = [data["permitted"][0]]
    elif change == "paused":
        data["paused"] = True
    elif change == "sequence":
        data["sequence"] = 1 << 53
    elif change == "unknown":
        data["unexpected"] = True
    elif change == "purpose":
        data["purpose"] = "unrelated-purpose"
    else:
        data["permitted"][0]["sha256"] = "b" * 63
    with pytest.raises(ManifestError):
        DesktopApplyPolicy.from_dict(data)


def test_withdrawal_rechecks_staging_privacy_before_unlink(apply):
    apply.set_policy(apply.policy(permitted=(), withdrawn=(apply.identity,)))
    original_open = apply.open

    def open_after_permissions_changed(request, **options):
        apply.staged.path.parent.chmod(0o755)
        return original_open(request, **options)

    apply.open = open_after_permissions_changed
    assert apply.check() is DesktopApplyDecision.DENIED
    assert apply.staged.path.read_bytes() == PAYLOAD


def test_inconsistent_signed_size_cannot_authorize_identical_digest(apply):
    artifact = replace(apply.artifact, byte_size=apply.artifact.byte_size + 1)
    apply.set_manifest(replace(apply.manifest, artifacts=(artifact,)))
    assert apply.check() is DesktopApplyDecision.DENIED
    assert not apply.staged.path.exists()
