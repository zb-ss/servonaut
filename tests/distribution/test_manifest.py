"""Tests for release manifest data models and deterministic canonicalization."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from servonaut.distribution import manifest as manifest_module
from servonaut.distribution.manifest import (
    ArtifactKind,
    ManifestSchemaError,
    ManifestSignature,
    ReleaseArtifact,
    ReleaseChannel,
    ReleaseManifest,
    canonicalize_json,
    parse_timestamp,
)
from servonaut.runtime import DistributionKind

VALID_SHA256 = "a" * 64
VALID_SBOM_SHA256 = "b" * 64


def make_valid_artifact(
    *,
    artifact_id: str = "cli-linux-x64",
    kind: ArtifactKind = ArtifactKind.STANDALONE_CLI,
    distribution: DistributionKind = DistributionKind.FROZEN_CLI,
    platform: str = "linux",
    arch: str = "x86_64",
    filename: str = "servonaut-2.26.3-linux-x64.tar.gz",
    download_url: str = "https://github.com/zb-ss/servonaut/releases/download/v2.26.3/servonaut-2.26.3-linux-x64.tar.gz",
    byte_size: int = 15_000_000,
    sha256: str = VALID_SHA256,
    min_os: str | None = None,
    sbom_sha256: str | None = None,
) -> ReleaseArtifact:
    return ReleaseArtifact(
        artifact_id=artifact_id,
        kind=kind,
        distribution=distribution,
        platform=platform,
        arch=arch,
        filename=filename,
        download_url=download_url,
        byte_size=byte_size,
        sha256=sha256,
        min_os=min_os,
        sbom_sha256=sbom_sha256,
    )


def make_valid_signature(
    *,
    key_id: str = "key-prod-1",
    algorithm: str = "ed25519",
    signature: str = "c2lnbmF0dXJlX2J5dGVz",
    signed_at: str = "2026-09-23T12:00:00Z",
) -> ManifestSignature:
    return ManifestSignature(
        key_id=key_id,
        algorithm=algorithm,
        signature=signature,
        signed_at=signed_at,
    )


def make_valid_manifest(
    *,
    schema_version: int = 1,
    channel: ReleaseChannel = ReleaseChannel.STABLE,
    product_version: str = "2.26.3",
    published_at: str = "2026-09-23T12:00:00Z",
    artifacts: tuple[ReleaseArtifact, ...] | None = None,
    signatures: tuple[ManifestSignature, ...] | None = None,
    packaging_revision: int | None = None,
    expires_at: str | None = None,
) -> ReleaseManifest:
    return ReleaseManifest(
        schema_version=schema_version,
        channel=channel,
        product_version=product_version,
        published_at=published_at,
        artifacts=artifacts if artifacts is not None else (make_valid_artifact(),),
        signatures=signatures if signatures is not None else (make_valid_signature(),),
        packaging_revision=packaging_revision,
        expires_at=expires_at,
    )


class TestReleaseArtifact:
    def test_valid_artifact_roundtrip(self) -> None:
        artifact = make_valid_artifact(min_os="ubuntu 22.04", sbom_sha256=VALID_SBOM_SHA256)
        data = artifact.to_dict()
        assert data["artifact_id"] == "cli-linux-x64"
        assert data["kind"] == "standalone_cli"
        assert data["distribution"] == "frozen-cli"
        assert data["min_os"] == "ubuntu 22.04"
        assert data["sbom_sha256"] == VALID_SBOM_SHA256

        restored = ReleaseArtifact.from_dict(data)
        assert restored == artifact

    @pytest.mark.parametrize(
        "kwargs,match",
        [
            ({"artifact_id": ""}, "Artifact ID"),
            ({"kind": "not_a_kind"}, "Invalid artifact kind"),
            ({"distribution": "not_a_dist"}, "Invalid distribution kind"),
            ({"platform": "freebsd"}, "Platform 'freebsd' is not supported"),
            ({"arch": "mips"}, "Architecture 'mips' is not supported"),
            ({"filename": ""}, "Filename"),
            ({"download_url": ""}, "Download URL"),
            ({"byte_size": 0}, "Byte size must be a positive integer"),
            ({"byte_size": -50}, "Byte size must be a positive integer"),
            ({"byte_size": True}, "Byte size must be a positive integer"),
            ({"sha256": "bad_hex"}, "SHA-256 digest must be a 64-character hex string"),
            ({"sha256": "a" * 63}, "SHA-256 digest must be a 64-character hex string"),
            ({"sbom_sha256": "bad_hex"}, "SBOM SHA-256 digest must be a 64-character hex string"),
        ],
    )
    def test_invalid_artifact_fields(self, kwargs: dict, match: str) -> None:
        base_args = {
            "artifact_id": "art-1",
            "kind": ArtifactKind.STANDALONE_CLI,
            "distribution": DistributionKind.FROZEN_CLI,
            "platform": "linux",
            "arch": "x86_64",
            "filename": "file.tar.gz",
            "download_url": "https://example.com/file.tar.gz",
            "byte_size": 1000,
            "sha256": VALID_SHA256,
        }
        base_args.update(kwargs)
        with pytest.raises(ManifestSchemaError, match=match):
            ReleaseArtifact(**base_args)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "filename",
        [
            "../../.bashrc",
            "/tmp/abs-target",
            "nested/file.tar.gz",
            "nested\\file.msi",
            "C:file.msi",
            "..",
            ".",
            "file\x00.tar.gz",
            "file\n.tar.gz",
        ],
    )
    def test_filename_must_be_a_bare_name(self, filename: str) -> None:
        with pytest.raises(ManifestSchemaError, match="bare file name"):
            make_valid_artifact(filename=filename)

    @pytest.mark.parametrize(
        "field,value",
        [("platform", ["linux"]), ("arch", {}), ("platform", None), ("arch", 64)],
    )
    def test_non_string_platform_or_arch_is_a_schema_error(self, field: str, value: object) -> None:
        data = make_valid_artifact().to_dict()
        data[field] = value
        with pytest.raises(ManifestSchemaError, match="is not supported"):
            ReleaseArtifact.from_dict(data)

    @pytest.mark.parametrize(
        "field,value,match",
        [
            ("signature", "not-hex", "128-character hex"),
            ("signature", {"sig": "x"}, "128-character hex"),
            ("attestation_url", ["x"], "Attestation URL"),
            ("min_os", 13, "min_os must be a non-empty string"),
        ],
    )
    def test_optional_fields_are_type_checked(self, field: str, value: object, match: str) -> None:
        data = make_valid_artifact().to_dict()
        data[field] = value
        with pytest.raises(ManifestSchemaError, match=match):
            ReleaseArtifact.from_dict(data)

    @pytest.mark.parametrize("platform", ["darwin", "windows"])
    def test_min_os_is_a_dotted_version_where_it_is_enforced(self, platform: str) -> None:
        with pytest.raises(ManifestSchemaError, match="dotted decimal version"):
            make_valid_artifact(platform=platform, min_os="Sonoma")
        assert make_valid_artifact(platform=platform, min_os="13.0").min_os == "13.0"

    def test_schema_errors_escape_and_bound_untrusted_values(self) -> None:
        data = make_valid_artifact().to_dict()
        data["platform"] = "\x1b]0;owned\x07" + "A" * 100_000
        with pytest.raises(ManifestSchemaError) as raised:
            ReleaseArtifact.from_dict(data)
        message = str(raised.value)
        assert "\x1b" not in message and "\x07" not in message
        assert len(message) < 300

    def test_artifact_missing_required_fields_in_dict(self) -> None:
        data = {"artifact_id": "art-1"}
        with pytest.raises(ManifestSchemaError, match="Artifact missing required fields"):
            ReleaseArtifact.from_dict(data)


class TestManifestSignature:
    def test_valid_signature_roundtrip(self) -> None:
        sig = make_valid_signature()
        data = sig.to_dict()
        assert data["key_id"] == "key-prod-1"
        assert data["algorithm"] == "ed25519"
        restored = ManifestSignature.from_dict(data)
        assert restored == sig

    @pytest.mark.parametrize(
        "kwargs,match",
        [
            ({"key_id": ""}, "key_id must be a non-empty string"),
            ({"algorithm": "rsa"}, "Unsupported signature algorithm"),
            ({"signature": ""}, "Signature bytes must be a non-empty string"),
            ({"signed_at": ""}, "signed_at must be a non-empty ISO 8601 string"),
        ],
    )
    def test_invalid_signature_fields(self, kwargs: dict, match: str) -> None:
        base_args = {
            "key_id": "k1",
            "algorithm": "ed25519",
            "signature": "sig",
            "signed_at": "2026-09-23T00:00:00Z",
        }
        base_args.update(kwargs)
        with pytest.raises(ManifestSchemaError, match=match):
            ManifestSignature(**base_args)


class TestReleaseManifest:
    def test_valid_manifest_roundtrip(self) -> None:
        manifest = make_valid_manifest(packaging_revision=2, expires_at="2027-09-23T00:00:00Z")
        data = manifest.to_dict()
        assert data["schema_version"] == 1
        assert data["channel"] == "stable"
        assert data["product_version"] == "2.26.3"
        assert data["packaging_revision"] == 2
        assert len(data["artifacts"]) == 1
        assert len(data["signatures"]) == 1

        restored = ReleaseManifest.from_dict(data)
        assert restored == manifest

    def test_manifest_from_json(self) -> None:
        manifest = make_valid_manifest()
        raw_json = json.dumps(manifest.to_dict())
        restored = ReleaseManifest.from_json(raw_json)
        assert restored == manifest

    def test_unknown_channel_error_is_bounded(self) -> None:
        data = make_valid_manifest().to_dict()
        data["channel"] = "on the latest version\x1b[2J" * 1000
        with pytest.raises(ManifestSchemaError, match="Unknown release channel") as raised:
            ReleaseManifest.from_dict(data)
        assert "\x1b" not in str(raised.value)
        assert len(str(raised.value)) < 200

    def test_manifest_from_invalid_json(self) -> None:
        with pytest.raises(ManifestSchemaError, match="Failed to decode manifest JSON"):
            ReleaseManifest.from_json("invalid json {")

    @pytest.mark.parametrize(
        "kwargs,match",
        [
            ({"schema_version": 2}, "Unsupported manifest schema_version"),
            ({"schema_version": True}, "Unsupported manifest schema_version"),
            ({"channel": "beta"}, "Invalid release channel"),
            ({"product_version": "2.26"}, "not a valid Semantic Version"),
            ({"product_version": "v2.26.3"}, "not a valid Semantic Version"),
            ({"product_version": "2.26.3\n"}, "not a valid Semantic Version"),
            ({"product_version": "2.26.3-01"}, "not a valid Semantic Version"),
            ({"product_version": ["2.26.3"]}, "not a valid Semantic Version"),
            ({"published_at": ""}, "published_at must be a non-empty ISO 8601 string"),
            ({"packaging_revision": 0}, "packaging_revision must be a positive integer"),
            ({"packaging_revision": -1}, "packaging_revision must be a positive integer"),
            ({"packaging_revision": True}, "packaging_revision must be a positive integer"),
            ({"packaging_revision": 65536}, "packaging_revision must be a positive integer"),
            ({"artifacts": ()}, "must declare at least one artifact"),
            ({"expires_at": ""}, "expires_at must be a non-empty string"),
        ],
    )
    def test_invalid_manifest_fields(self, kwargs: dict, match: str) -> None:
        base_args = {
            "schema_version": 1,
            "channel": ReleaseChannel.STABLE,
            "product_version": "2.26.3",
            "published_at": "2026-09-23T00:00:00Z",
            "artifacts": (make_valid_artifact(),),
            "signatures": (),
        }
        base_args.update(kwargs)
        with pytest.raises(ManifestSchemaError, match=match):
            ReleaseManifest(**base_args)  # type: ignore[arg-type]


class TestCanonicalization:
    def test_canonical_manifest_omits_signatures(self) -> None:
        manifest = make_valid_manifest(signatures=(make_valid_signature(),))
        canonical = manifest.canonical_bytes()
        decoded = json.loads(canonical.decode("utf-8"))
        assert "signatures" not in decoded
        assert "artifacts" in decoded
        assert decoded["product_version"] == "2.26.3"

    def test_canonical_json_sorting_and_compactness(self) -> None:
        obj1 = {"z": 1, "a": {"d": 4, "c": 3}, "b": 2}
        obj2 = {"a": {"c": 3, "d": 4}, "b": 2, "z": 1}
        c1 = canonicalize_json(obj1)
        c2 = canonicalize_json(obj2)
        assert c1 == c2
        assert b" " not in c1  # No whitespace
        assert c1 == b'{"a":{"c":3,"d":4},"b":2,"z":1}'

    def test_canonical_json_unicode_preservation(self) -> None:
        data = {"name": "Servonaut", "symbol": "🚀"}
        c = canonicalize_json(data)
        assert "🚀".encode("utf-8") in c

    def test_lone_surrogate_is_a_schema_error(self) -> None:
        raw = json.dumps(make_valid_manifest(signatures=()).to_dict()).replace(
            '"2026-09-23T12:00:00Z"', '"\\ud800"', 1
        )
        manifest = ReleaseManifest.from_json(raw)
        with pytest.raises(ManifestSchemaError, match="not valid Unicode"):
            manifest.canonical_bytes()


class TestTimestamps:
    def test_zulu_suffix_is_normalised_before_parsing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _StrictIsoDatetime(datetime):
            """Mimics Python 3.10, whose fromisoformat rejects a trailing Z."""

            @classmethod
            def fromisoformat(cls, value: str) -> datetime:  # type: ignore[override]
                if value.endswith("Z"):
                    raise ValueError(f"Invalid isoformat string: {value!r}")
                return datetime.fromisoformat(value)

        monkeypatch.setattr(manifest_module, "datetime", _StrictIsoDatetime)
        assert parse_timestamp("2026-09-23T12:00:00Z") == datetime(2026, 9, 23, 12, tzinfo=timezone.utc)

    def test_naive_timestamp_is_utc(self) -> None:
        assert parse_timestamp("2026-09-23T12:00:00").tzinfo is timezone.utc

    @pytest.mark.parametrize("value", ["", "next tuesday", None, 20260923])
    def test_invalid_timestamp_is_a_schema_error(self, value: object) -> None:
        with pytest.raises(ManifestSchemaError, match="Invalid ISO 8601 timestamp"):
            parse_timestamp(value)
