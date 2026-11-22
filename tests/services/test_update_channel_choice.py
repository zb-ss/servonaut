"""A packaged desktop build follows the channel its user chose, checked at use time."""

from __future__ import annotations

import base64
import hashlib
import json
import stat
from unittest.mock import patch

import pytest

from servonaut.distribution import (
    ArtifactKind, ReleaseArtifact, ReleaseChannel, ReleaseManifest, TrustPolicy, sign_manifest, trust_root,
)
from servonaut.distribution.apply_policy import DesktopArtifactIdentity
from servonaut.runtime import DistributionKind
from servonaut.services import update_service as update_module
from servonaut.services.update_service import UpdateCheckResult, UpdateService, default_manifest_url
from servonaut.updates import channel_preference as pref
from servonaut.updates.desktop_apply import DESKTOP_STAGING_DIR, DesktopApplyDecision, StagedDesktopUpdate
from servonaut.updates.status import read_update_status, set_update_channel
from tests.services.test_update_service_frozen import (  # noqa: F401
    _FakeOpener, _MockResponse, _make_frozen_runtime, _raw, linux_x64, trust_setup,
)

_DOWNLOADS = "https://github.com/zb-ss/servonaut/releases/download"
_PAYLOAD = b"a desktop installer fixture"
_URLS = {"stable": "https://example.test/stable.json", "preview": "https://example.test/preview.json"}


@pytest.fixture(autouse=True)
def _pinned_urls(monkeypatch):
    monkeypatch.delenv(update_module.RELEASE_MANIFEST_URL_ENV, raising=False)
    monkeypatch.setattr(trust_root, "DEFAULT_MANIFEST_URLS", _URLS)


def _runtime(tmp_path, build_channel="stable", version="2.35.0", revision=1):
    return _make_frozen_runtime(
        tmp_path, kind=DistributionKind.PACKAGED_DESKTOP, version=version,
        channel=build_channel, packaging_revision=revision,
    )


def _deb(version):
    return ReleaseArtifact(
        "desktop-ubuntu-deb", ArtifactKind.UBUNTU_DEB, DistributionKind.PACKAGED_DESKTOP, "linux", "x86_64",
        "servonaut-desktop.deb", f"{_DOWNLOADS}/v{version}/servonaut-desktop.deb",
        len(_PAYLOAD), hashlib.sha256(_PAYLOAD).hexdigest(),
    )


def _manifest(key, key_id, channel, version, revision=1):
    manifest = ReleaseManifest(
        1, channel, version, "2026-09-23T12:00:00Z", (_deb(version),), (),
        packaging_revision=revision, expires_at="2099-01-01T00:00:00Z",
    )
    return sign_manifest(manifest, key, key_id)


@pytest.fixture
def pinned(trust_setup, monkeypatch):  # noqa: F811
    """Trust the fixture key, with the policy each build channel really gets."""
    key, key_id, _policy = trust_setup
    monkeypatch.setattr(trust_root, "PINNED_RELEASE_KEYS", {
        key_id: base64.b64encode(key.public_key().public_bytes_raw()).decode(),
    })

    def policy_for(channel):
        accepted = (
            (ReleaseChannel.PREVIEW, ReleaseChannel.STABLE) if channel == "preview"
            else (ReleaseChannel.STABLE,)
        )
        return TrustPolicy(
            trusted_public_keys={key_id: key.public_key()}, minimum_signatures=1,
            allowed_origin_prefixes=(f"{_DOWNLOADS}/",), allowed_channels=accepted,
        )

    monkeypatch.setattr(update_module, "_pinned_trust_policy", policy_for)
    return key, key_id


def _service(runtime, *responses):
    # No injected trust policy: the policy has to follow the effective channel.
    return UpdateService(runtime, opener=_FakeOpener(*responses))


# --- preference storage ------------------------------------------------------

def test_no_file_means_no_preference(tmp_path):
    assert pref.read_channel_preference(tmp_path) is None


@pytest.mark.parametrize("channel", ["stable", "rc"])
def test_a_valid_choice_round_trips_privately(tmp_path, channel):
    assert pref.write_channel_preference(tmp_path, channel) is True

    assert pref.read_channel_preference(tmp_path) == channel
    path = pref.preference_path(tmp_path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [p.name for p in path.parent.iterdir()] == [path.name]  # no temporary left behind


@pytest.mark.parametrize("channel", ["preview", "beta", "", "STABLE", None, 1])
def test_only_stable_and_rc_can_be_saved(tmp_path, channel):
    assert pref.write_channel_preference(tmp_path, channel) is False
    assert not pref.preference_path(tmp_path).exists()


@pytest.mark.parametrize("content", [
    b"", b"not json", b"[]", b'{"channel": "preview"}', b'{"channel": 3}',
    b'{"channel": "rc", "extra": 1}', b'{"channel": "' + b"x" * 500 + b'"}',
])
def test_an_invalid_file_is_ignored(tmp_path, content):
    path = pref.preference_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    path.chmod(0o600)

    assert pref.read_channel_preference(tmp_path) is None


def test_a_group_writable_or_linked_file_is_ignored(tmp_path):
    pref.write_channel_preference(tmp_path, "rc")
    path = pref.preference_path(tmp_path)
    path.chmod(0o666)
    assert pref.read_channel_preference(tmp_path) is None

    path.unlink()
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps({"channel": "rc"}))
    path.symlink_to(target)
    assert pref.read_channel_preference(tmp_path) is None


def test_a_failed_write_keeps_the_previous_choice(tmp_path):
    pref.write_channel_preference(tmp_path, "rc")
    with patch("servonaut.updates.channel_preference.write_json_atomic", side_effect=OSError("disk full")):
        assert pref.write_channel_preference(tmp_path, "stable") is False
    assert pref.read_channel_preference(tmp_path) == "rc"


# --- effective channel: URL and trust follow it ------------------------------

@pytest.mark.parametrize(("build", "choice", "effective"), [
    ("stable", None, "stable"), ("stable", "rc", "preview"),
    ("preview", None, "preview"), ("preview", "stable", "stable"),
    ("stable", "stable", "stable"), ("preview", "rc", "preview"),
])
def test_effective_channel_and_manifest_url(tmp_path, build, choice, effective):
    runtime = _runtime(tmp_path, build)
    if choice:
        pref.write_channel_preference(runtime.data_root, choice)
    service = UpdateService(runtime)

    assert service.effective_channel() == effective
    assert service._resolve_manifest_url() == _URLS[effective]
    assert default_manifest_url(runtime) == _URLS[build]  # the build's own default is unchanged


def test_a_switch_applies_without_rebuilding_the_service(tmp_path):
    runtime = _runtime(tmp_path, "stable")
    service = UpdateService(runtime)
    assert service.effective_channel() == "stable"

    pref.write_channel_preference(runtime.data_root, "rc")

    assert service.effective_channel() == "preview"
    assert service._resolve_manifest_url() == _URLS["preview"]


def test_explicit_manifest_url_and_override_still_win(tmp_path, monkeypatch):
    runtime = _runtime(tmp_path)
    pref.write_channel_preference(runtime.data_root, "rc")

    explicit = UpdateService(runtime, manifest_url="https://x.test/m.json")
    assert explicit._resolve_manifest_url() == "https://x.test/m.json"
    monkeypatch.setenv(update_module.RELEASE_MANIFEST_URL_ENV, "https://127.0.0.1:9/m.json")
    assert UpdateService(runtime)._resolve_manifest_url() == "https://127.0.0.1:9/m.json"


@pytest.mark.parametrize("kind", [DistributionKind.FROZEN_CLI, DistributionKind.PIP])
def test_other_install_kinds_ignore_a_stray_preference(tmp_path, kind):
    runtime = _make_frozen_runtime(tmp_path, kind=kind, channel="stable", packaging_revision=1)
    pref.write_channel_preference(runtime.data_root, "rc")

    assert UpdateService(runtime).effective_channel() == "stable"


def test_stable_build_that_opted_into_rc_accepts_a_preview_manifest(tmp_path, pinned, linux_x64):
    key, key_id = pinned
    runtime = _runtime(tmp_path, "stable")
    pref.write_channel_preference(runtime.data_root, "rc")
    preview = _manifest(key, key_id, ReleaseChannel.PREVIEW, "2.36.0-rc.1")

    service = _service(runtime, _MockResponse(_raw(preview)))

    assert service.check_for_update() == "2.36.0rc1"
    assert service.last_check_result is UpdateCheckResult.UPDATE_AVAILABLE


def test_stable_build_without_opt_in_rejects_a_preview_manifest(tmp_path, pinned, linux_x64):
    key, key_id = pinned
    runtime = _runtime(tmp_path, "stable")
    preview = _manifest(key, key_id, ReleaseChannel.PREVIEW, "2.36.0-rc.1")

    service = _service(runtime, _MockResponse(_raw(preview)))

    assert service.check_for_update() is None
    assert service.last_check_result is UpdateCheckResult.VERIFICATION_FAILED


def test_switching_back_to_stable_stops_accepting_previews(tmp_path, pinned, linux_x64):
    key, key_id = pinned
    runtime = _runtime(tmp_path, "stable")
    pref.write_channel_preference(runtime.data_root, "rc")
    preview = _manifest(key, key_id, ReleaseChannel.PREVIEW, "2.36.0-rc.1")
    service = _service(runtime, _MockResponse(_raw(preview)), _MockResponse(_raw(preview)))
    assert service.check_for_update() == "2.36.0rc1"

    pref.write_channel_preference(runtime.data_root, "stable")

    assert service.check_for_update() is None
    assert service.last_check_result is UpdateCheckResult.VERIFICATION_FAILED


def test_rc_app_switched_to_stable_is_never_offered_an_older_stable(tmp_path, pinned, linux_x64):
    key, key_id = pinned
    runtime = _runtime(tmp_path, "preview", version="2.36.0rc2")
    pref.write_channel_preference(runtime.data_root, "stable")
    older_stable = _manifest(key, key_id, ReleaseChannel.STABLE, "2.35.0")

    service = _service(runtime, _MockResponse(_raw(older_stable)))

    assert service.check_for_update() is None
    assert service.last_check_result is UpdateCheckResult.UP_TO_DATE


def test_rc_app_switched_to_stable_gets_the_next_stable_release(tmp_path, pinned, linux_x64):
    key, key_id = pinned
    runtime = _runtime(tmp_path, "preview", version="2.36.0rc2")
    pref.write_channel_preference(runtime.data_root, "stable")
    final = _manifest(key, key_id, ReleaseChannel.STABLE, "2.36.0")

    assert _service(runtime, _MockResponse(_raw(final))).check_for_update() == "2.36.0"


def test_checks_request_the_manifest_of_the_chosen_channel(tmp_path, pinned, linux_x64):
    key, key_id = pinned
    runtime = _runtime(tmp_path, "stable")
    pref.write_channel_preference(runtime.data_root, "rc")
    opener = _FakeOpener(_MockResponse(_raw(_manifest(key, key_id, ReleaseChannel.PREVIEW, "2.36.0-rc.1"))))

    UpdateService(runtime, opener=opener).check_for_update()

    assert [r.full_url for r in opener.requests] == [_URLS["preview"]]


# --- staged update of the other channel -------------------------------------

def _staged(runtime, version):
    staging = runtime.data_root / DESKTOP_STAGING_DIR
    staging.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = staging / "candidate.dmg"
    path.write_bytes(_PAYLOAD)
    path.chmod(0o600)
    sha = hashlib.sha256(_PAYLOAD).hexdigest()
    identity = DesktopArtifactIdentity(version, 3, ArtifactKind.MACOS_DMG, "darwin", "arm64", sha)
    return StagedDesktopUpdate(identity, path)


def test_a_staged_candidate_is_discarded_once_the_user_is_back_on_stable(tmp_path, pinned):
    runtime = _runtime(tmp_path, "stable")
    staged = _staged(runtime, "2.36.0-rc.1")
    pref.write_channel_preference(runtime.data_root, "stable")
    opener = _FakeOpener()

    decision = UpdateService(runtime, opener=opener).prepare_staged_desktop_apply(staged)

    assert decision is DesktopApplyDecision.DENIED
    assert not staged.path.exists()
    assert opener.requests == []  # refused locally, nothing fetched


def test_a_staged_candidate_is_kept_while_the_user_follows_rc(tmp_path, pinned):
    runtime = _runtime(tmp_path, "stable")
    staged = _staged(runtime, "2.36.0-rc.1")
    pref.write_channel_preference(runtime.data_root, "rc")

    decision = UpdateService(runtime, opener=_FakeOpener(OSError("offline"))).prepare_staged_desktop_apply(staged)

    assert decision is DesktopApplyDecision.DEFERRED
    assert staged.path.exists()


def test_apply_uses_the_chosen_channel_for_the_signed_documents(tmp_path, pinned):
    runtime = _runtime(tmp_path, "stable")
    staged = _staged(runtime, "2.36.0-rc.1")
    pref.write_channel_preference(runtime.data_root, "rc")
    seen = {}

    def capture(*_args, **kwargs):
        seen.update(channel=kwargs["channel"], url=kwargs["manifest_url"])
        return DesktopApplyDecision.DEFERRED

    with patch.object(update_module, "prepare_desktop_apply", capture):
        UpdateService(runtime, opener=_FakeOpener()).prepare_staged_desktop_apply(staged)

    assert seen == {"channel": ReleaseChannel.PREVIEW, "url": _URLS["preview"]}


# --- status snapshot and saving ----------------------------------------------

@pytest.mark.parametrize(("build", "choice", "shown"), [
    ("stable", None, "stable"), ("stable", "rc", "rc"), ("preview", None, "rc"), ("preview", "stable", "stable"),
])
def test_packaged_status_reports_the_effective_channel(tmp_path, monkeypatch, build, choice, shown):
    monkeypatch.setattr("servonaut.updates.status.locate_install", lambda _p=None: None)
    runtime = _runtime(tmp_path, build)
    if choice:
        pref.write_channel_preference(runtime.data_root, choice)

    status = read_update_status(runtime)

    assert (status.state, status.channel, status.channel_selectable) == ("managed_elsewhere", shown, True)


@pytest.mark.parametrize("kind", [DistributionKind.PIP, DistributionKind.SOURCE, DistributionKind.FROZEN_CLI])
def test_other_installs_have_no_channel_choice(tmp_path, monkeypatch, kind):
    monkeypatch.setattr("servonaut.updates.status.locate_install", lambda _p=None: None)
    runtime = _make_frozen_runtime(tmp_path, kind=kind)

    assert read_update_status(runtime).channel_selectable is False


def test_saving_for_a_packaged_app_writes_the_preference(tmp_path):
    runtime = _runtime(tmp_path)

    assert set_update_channel("rc", runtime) is True
    assert pref.read_channel_preference(runtime.data_root) == "rc"
    assert set_update_channel("preview", runtime) is False  # type: ignore[arg-type]
    assert pref.read_channel_preference(runtime.data_root) == "rc"
