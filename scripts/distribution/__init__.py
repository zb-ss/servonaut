"""Distribution packaging and release manifest assembly scripts."""

from scripts.distribution.package_cli import package_standalone_cli
from scripts.distribution.package_deb import package_deb
from scripts.distribution.package_macos import assemble_app_bundle, package_dmg
from scripts.distribution.sign_macos import sign_app_bundle, sign_dmg, verify_signature
from scripts.distribution.notarize_macos import submit_notarization, staple_ticket, validate_staple

__all__ = [
    "package_standalone_cli",
    "package_deb",
    "assemble_app_bundle",
    "package_dmg",
    "sign_app_bundle",
    "sign_dmg",
    "verify_signature",
    "submit_notarization",
    "staple_ticket",
    "validate_staple",
]
