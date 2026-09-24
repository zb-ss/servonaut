"""Distribution packaging and release manifest assembly scripts."""

from scripts.distribution.notarize_macos import staple_ticket, submit_notarization, validate_staple
from scripts.distribution.package_cli import package_standalone_cli
from scripts.distribution.package_deb import package_deb
from scripts.distribution.package_macos import assemble_app_bundle, package_dmg
from scripts.distribution.package_windows import package_windows
from scripts.distribution.release_candidate import (
    ReleaseCandidate,
    channel_for_tag,
    ensure_publishable,
    load_evidence,
    plan_candidate,
    verify_candidate,
)
from scripts.distribution.sign_macos import sign_app_bundle, sign_dmg, verify_signature
from scripts.distribution.sign_windows import sign_msi, sign_payload_binaries
from scripts.distribution.webview2_detect import detect_openssh, detect_webview2

__all__ = [
    "package_standalone_cli",
    "package_deb",
    "assemble_app_bundle",
    "package_dmg",
    "package_windows",
    "sign_app_bundle",
    "sign_dmg",
    "sign_payload_binaries",
    "sign_msi",
    "verify_signature",
    "submit_notarization",
    "staple_ticket",
    "validate_staple",
    "detect_webview2",
    "detect_openssh",
    "ReleaseCandidate",
    "plan_candidate",
    "verify_candidate",
    "load_evidence",
    "ensure_publishable",
    "channel_for_tag",
]

