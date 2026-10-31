"""Contract tests for the workflow that attaches the signed macOS preview to releases.

Static checks pin its triggers, permissions, the signing environment, the
order of its signing steps and what each job may hand on; the steps that
decide, plan, archive, unpack, prepare and clean up the signing keychain,
verify and upload also run here for real, under bash, with the environment
the workflow gives them and stand-ins for the macOS-only tools.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from scripts.distribution.desktop_preview import (
    MACOS_TARGETS,
    DesktopPreviewError,
    declared_versions,
    preview_for_tag,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOWS = _REPO_ROOT / ".github" / "workflows"
_WORKFLOW_PATH = _WORKFLOWS / "desktop-preview-macos.yml"
_ATTEST_PIN = (
    "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2"
)
_SECRETS = (
    "MACOS_CERTIFICATE_P12_BASE64",
    "MACOS_CERTIFICATE_PASSWORD",
    "APPLE_NOTARY_KEY_P8_BASE64",
)
_SIGNING_VARIABLES = (
    "MACOS_SIGNING_IDENTITY",
    "APPLE_TEAM_ID",
    "APPLE_NOTARY_KEY_ID",
    "APPLE_NOTARY_ISSUER_ID",
)
_EXECUTABLES = ("servonaut-desktop", "servonaut-desktop-child", "servonaut")
# A stand-in signing identity; the real one is an environment variable.
_IDENTITY = "Developer ID Application: Example Publisher (ABCDE12345)"


@pytest.fixture(scope="module")
def workflow() -> str:
    return _WORKFLOW_PATH.read_text(encoding="utf-8")


def _job(workflow: str, name: str) -> str:
    jobs = workflow.split("\njobs:\n", 1)[1]
    blocks = re.split(r"\n  (?=[a-z][a-z-]*:\n)", "\n" + jobs)
    return next(block for block in blocks if block.startswith(f"{name}:\n"))


def _step(workflow: str, name: str) -> str:
    start = workflow.index(f"      - name: {name}\n")
    step = workflow[start:]
    following = re.search(r"\n      - ", step)
    return step[: following.start()] if following else step


def _script(workflow: str, name: str) -> str:
    block = _step(workflow, name).split("        run: |\n", 1)[1]
    lines = []
    for line in block.splitlines():
        if line.strip() and not line.startswith("          "):
            break
        lines.append(line)
    return textwrap.dedent("\n".join(lines))


def _outputs(path: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines())


def _run(
    workflow: str,
    name: str,
    tmp_path: Path,
    *,
    cwd: Path | None = None,
    prelude: str = "",
    **env: str,
) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    output = tmp_path / "github-output"
    output.write_text("", encoding="utf-8")
    result = subprocess.run(
        ["bash", "-c", prelude + _script(workflow, name)],
        cwd=cwd or tmp_path,
        text=True,
        capture_output=True,
        check=False,
        env={
            "PATH": os.environ["PATH"],
            "GITHUB_OUTPUT": str(output),
            "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
            "RUNNER_TEMP": str(tmp_path),
            **env,
        },
    )
    return result, _outputs(output)


def _positions(job: str, markers: list[str]) -> list[int]:
    return [job.index(marker) for marker in markers]


def _matrix(job: str) -> list[tuple[str, str, str]]:
    return re.findall(
        r"- target: (\S+)\n\s+runner: (\S+)\n\s+python-architecture: (\S+)\n", job
    )


# ---------------------------------------------------------------------------
# Triggers, permissions and isolation
# ---------------------------------------------------------------------------


def test_is_named_for_the_workflows_that_follow_it(workflow: str) -> None:
    assert workflow.startswith("name: Desktop preview macOS\n")


def test_runs_for_published_releases_and_on_request_only(workflow: str) -> None:
    triggers = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]

    assert "  release:\n    types: [published]\n" in triggers
    assert "  workflow_dispatch:\n" in triggers
    for trigger in ("push:", "pull_request", "schedule:", "workflow_run:", "workflow_call:"):
        assert trigger not in triggers
    for name in ("tag:", "dry_run:", "rehearsal_version:"):
        assert f"      {name}\n" in triggers
    assert "        type: boolean\n" in triggers.split("dry_run:", 1)[1]


def test_never_runs_for_forks(workflow: str) -> None:
    assert "    if: github.repository == 'zb-ss/servonaut'\n" in _job(workflow, "resolve")
    assert "    needs: resolve\n    if: needs.resolve.outputs.build == 'true'\n" in _job(
        workflow, "qualify"
    )
    assert "    needs: [resolve, qualify]\n" in _job(workflow, "sign")
    assert "    needs: [resolve, qualify, sign]\n" in _job(workflow, "publish")


def _granted(job: str) -> list[tuple[str, str]]:
    granted = job.split("    permissions:\n", 1)[1]
    granted = re.split(r"\n    (?! )", granted, maxsplit=1)[0]
    return re.findall(r"^      ([a-z-]+): (\w+)$", granted, re.MULTILINE)


def test_each_job_has_the_least_privilege_it_needs(workflow: str) -> None:
    assert "\npermissions:\n  contents: read\n" in workflow
    assert "    permissions: {}\n" in _job(workflow, "resolve")
    assert _granted(_job(workflow, "qualify")) == [("contents", "read")]
    assert _granted(_job(workflow, "sign")) == [("contents", "read")]
    assert _granted(_job(workflow, "publish")) == [
        ("contents", "write"),
        ("id-token", "write"),
        ("attestations", "write"),
    ]
    for job in ("resolve", "qualify", "sign"):
        header = _job(workflow, job).split("\n    steps:", 1)[0]
        assert not re.search(r"^ +[a-z-]+: write$", header, re.MULTILINE), job


def test_only_the_sign_job_is_in_the_signing_environment(workflow: str) -> None:
    assert re.findall(r"^ *environment:.*$", workflow, re.MULTILINE) == [
        "    environment: desktop-signing"
    ]
    assert "    environment: desktop-signing\n" in _job(workflow, "sign")


def test_the_signing_secrets_reach_one_step_only(workflow: str) -> None:
    sign = _job(workflow, "sign")
    keychain = _step(sign, "Prepare the signing keychain")

    assert sorted(re.findall(r"secrets\.(\w+)", workflow)) == sorted(_SECRETS)
    for secret in _SECRETS:
        assert f"          {secret}: ${{{{ secrets.{secret} }}}}\n" in keychain
    for variable in _SIGNING_VARIABLES:
        assert f"vars.{variable}" in sign
        for job in ("resolve", "qualify", "publish"):
            assert f"vars.{variable}" not in _job(workflow, job)
    # The scripts reach the notary key as a file, never as a secret value.
    for name in ("Notarize and staple the app", "Package, sign and notarize the disk image"):
        assert "secrets." not in _step(sign, name)
        assert "NOTARY_KEY: ${{ steps.keychain.outputs.notary-key }}" in _step(sign, name)


def test_only_the_built_in_token_reaches_the_publish_steps(workflow: str) -> None:
    for job in ("resolve", "qualify", "sign"):
        assert "github.token" not in _job(workflow, job)
    publish = _job(workflow, "publish")
    assert publish.count("GH_TOKEN: ${{ github.token }}") == 2
    assert "GH_TOKEN" not in publish.split("\n    steps:", 1)[0]


def test_the_publish_job_runs_no_repository_code(workflow: str) -> None:
    publish = _job(workflow, "publish")

    assert "actions/checkout" not in publish
    assert "python" not in publish
    assert "scripts." not in publish
    assert "uses: ./" not in publish
    assert "environment:" not in publish


def test_checkouts_keep_no_credentials(workflow: str) -> None:
    checkouts = re.findall(r"uses: actions/checkout@", workflow)

    assert len(checkouts) == 2
    assert workflow.count("persist-credentials: false") == len(checkouts)
    # Both build jobs check out the commit resolve chose.
    for job in ("qualify", "sign"):
        assert "ref: ${{ needs.resolve.outputs.checkout-ref }}" in _job(workflow, job)


def test_actions_are_pinned_like_the_other_desktop_workflows(workflow: str) -> None:
    uses = re.findall(r"uses:\s*(\S+)(.*)", workflow)
    assert uses
    for reference, comment in uses:
        if reference.startswith("./"):
            continue
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", reference), reference
        assert re.fullmatch(r"\s*# v\d+\.\d+\.\d+", comment), reference
    shared = {
        reference
        for path in ("desktop-shell.yml", "desktop-preview-deb.yml")
        for reference in re.findall(r"uses:\s*(\S+)", (_WORKFLOWS / path).read_text("utf-8"))
    }
    ours = {reference for reference, _ in uses}
    assert ours <= shared
    assert f"uses: {_ATTEST_PIN}\n" in workflow


def test_the_pypi_publish_and_the_linux_preview_do_not_wait_for_it(workflow: str) -> None:
    for other in ("publish.yml", "desktop-preview-deb.yml"):
        text = (_WORKFLOWS / other).read_text(encoding="utf-8")
        assert "desktop-preview-macos" not in text
        assert "Desktop preview macOS" not in text
    assert "workflow_run" not in workflow
    assert "publish.yml" not in workflow


def test_every_job_has_a_timeout(workflow: str) -> None:
    for job in ("resolve", "qualify", "sign", "publish"):
        assert re.search(r"\n    timeout-minutes: \d+\n", _job(workflow, job)), job


def test_runs_for_one_tag_queue_instead_of_cancelling(workflow: str) -> None:
    assert (
        "\nconcurrency:\n"
        "  group: desktop-preview-macos-${{ github.event.release.tag_name || inputs.tag"
        " || github.ref }}\n"
        "  cancel-in-progress: false\n"
    ) in workflow


def test_inputs_reach_scripts_only_through_the_environment(workflow: str) -> None:
    run_blocks = re.findall(r"\n        run: \|\n(.*?)(?=\n      - |\n  [a-z]|\Z)", workflow, re.S)
    one_liners = re.findall(r"\n        run: (?!\|)(.*)", workflow)

    assert run_blocks and one_liners
    for block in [*run_blocks, *one_liners]:
        assert "${{" not in block


# ---------------------------------------------------------------------------
# The targets, and what one job hands the next
# ---------------------------------------------------------------------------


def test_the_targets_and_runners_are_the_desktop_qualifications(workflow: str) -> None:
    shell = (_WORKFLOWS / "desktop-shell.yml").read_text(encoding="utf-8")
    qualified = [entry for entry in _matrix(shell) if entry[0].startswith("macos-")]

    for job in ("qualify", "sign"):
        legs = _matrix(_job(workflow, job))
        assert sorted(legs) == sorted(qualified)
        assert [target for target, _, _ in legs] == list(MACOS_TARGETS)
        assert "      fail-fast: false\n" in _job(workflow, job)


def test_matrix_legs_write_outputs_named_after_their_target(workflow: str) -> None:
    """Matrix legs share one set of job outputs; the last to finish would win."""
    qualify = _job(workflow, "qualify")
    sign = _job(workflow, "sign")

    for target in MACOS_TARGETS:
        assert (
            f"      app-sha256-{target}: ${{{{ steps.handoff.outputs.app-sha256-{target} }}}}\n"
            in qualify
        )
        assert (
            f"      dmg-sha256-{target}: ${{{{ steps.dmg.outputs.dmg-sha256-{target} }}}}\n"
            in sign
        )
    archive = _script(qualify, "Archive the unsigned app for the sign job")
    assert 'echo "app-sha256-${TARGET}=' in archive
    assert 'echo "dmg-sha256-${TARGET}=${digest}"' in _script(
        sign, "Package, sign and notarize the disk image"
    )
    assert (
        "      APP_SHA256: ${{ needs.qualify.outputs[format('app-sha256-{0}', matrix.target)] }}\n"
        in sign
    )
    # No output that differs between the legs is shared.
    for job in (qualify, sign):
        declared = job.split("    outputs:\n", 1)[1].split("\n    env:", 1)[0]
        for line in declared.splitlines():
            if "sha256" in line:
                assert re.search(r"-(macos-arm64|macos-x64): ", line), line


def test_asset_names_come_from_the_plan(workflow: str) -> None:
    qualify = _job(workflow, "qualify")
    planned = preview_for_tag("v2.28.0rc1").macos_outputs()

    assert "servonaut-desktop-preview_" not in workflow
    for key in planned:
        if key.startswith("dmg-asset-") or key == "sums-asset":
            assert f"      {key}: ${{{{ steps.plan.outputs.{key} }}}}\n" in qualify
    assert (
        "      DMG_ASSET: ${{ needs.qualify.outputs[format('dmg-asset-{0}', matrix.target)] }}\n"
        in _job(workflow, "sign")
    )
    assert '--filename "${DMG_ASSET}"' in _step(
        _job(workflow, "sign"), "Package, sign and notarize the disk image"
    )
    publish = _job(workflow, "publish")
    assert "      ARM64_DMG: ${{ needs.qualify.outputs.dmg-asset-macos-arm64 }}\n" in publish
    assert "      X64_DMG: ${{ needs.qualify.outputs.dmg-asset-macos-x64 }}\n" in publish
    assert "      SUMS_ASSET: ${{ needs.qualify.outputs.sums-asset }}\n" in publish
    # Every output the workflow reads from the plan, the plan gives.
    read = set(re.findall(r"steps\.plan\.outputs\.([a-z0-9-]+)", workflow))
    assert read <= set(planned)


def test_the_unsigned_app_travels_as_an_archive(workflow: str) -> None:
    """upload-artifact drops symbolic links and file modes; a tar keeps both."""
    qualify = _job(workflow, "qualify")
    archive = _script(qualify, "Archive the unsigned app for the sign job")
    handoff = _step(qualify, "Hand the unsigned app to the sign job")

    assert re.search(
        r"tar -c -f \"\$\{archive\}\" .*-C \"\$\{MACOS_DIR\}\" Servonaut.app", archive, re.S
    )
    for flag in ("--no-mac-metadata", "--no-xattrs", "--no-acls", "--no-fflags"):
        assert flag in archive
    assert "name: desktop-preview-macos-app-${{ matrix.target }}\n" in handoff
    assert "path: ${{ steps.handoff.outputs.archive-path }}\n" in handoff
    assert "overwrite: true\n" in handoff
    # The app handed on is the one assembled unsigned, not the ad-hoc copy.
    assert 'MACOS_DIR: ${{ steps.paths.outputs.macos-dir }}' in _step(
        qualify, "Archive the unsigned app for the sign job"
    )
    assert "name: desktop-preview-macos-app-${{ matrix.target }}\n" in _step(
        _job(workflow, "sign"), "Receive the unsigned app"
    )


def test_the_unsigned_app_outlasts_the_wait_for_the_signing_approval(workflow: str) -> None:
    """The sign job waits for a reviewer; the app it signs must still be there."""
    handoff = _step(_job(workflow, "qualify"), "Hand the unsigned app to the sign job")
    retention = int(re.search(r"\n          retention-days: (\d+)\n", handoff).group(1))
    # A week covers the release train: a Monday candidate approved by Thursday.
    assert retention >= 7
    # Nothing waits between signing and publishing, so the image goes at once.
    image = _step(_job(workflow, "sign"), "Hand the disk image to the publish job")
    assert "retention-days: 1\n" in image
    guide = (_REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert f"within {retention} days" in guide


def test_a_dry_run_hands_no_disk_image_on(workflow: str) -> None:
    sign = _job(workflow, "sign")
    handoff = _step(sign, "Hand the disk image to the publish job")

    assert "        if: env.DRY_RUN != 'true'\n" in handoff
    assert "name: desktop-preview-macos-dmg-${{ matrix.target }}\n" in handoff
    assert "path: ${{ steps.dmg.outputs.dmg-path }}\n" in handoff
    assert "retention-days: 1\n" in handoff
    # Every other upload holds reports and screenshots, or the unsigned app.
    uploads = re.findall(
        r"      - name: ([^\n]+)\n(?:        [^\n]*\n)*?        uses: actions/upload-artifact@",
        workflow,
    )
    assert sorted(uploads) == sorted(
        [
            "Hand the unsigned app to the sign job",
            "Upload qualification evidence",
            "Hand the disk image to the publish job",
            "Upload signing evidence",
        ]
    )
    for name in ("Upload qualification evidence", "Upload signing evidence"):
        evidence = _step(workflow, name).split("          path: |\n", 1)[1]
        evidence = evidence.split("\n          retention-days", 1)[0]
        paths = [line.strip() for line in evidence.splitlines()]
        assert [path.rsplit("/", 1)[1] for path in paths] == ["*.json", "*.png"]
    publish = _job(workflow, "publish")
    for name in (
        "Receive the signed disk images",
        "Verify the disk images and write their checksums",
        "Confirm the release and its tag",
        "Attest the disk images' build provenance",
        "Upload the macOS preview to the release",
    ):
        assert "        if: env.DRY_RUN != 'true'\n" in _step(publish, name), name
    assert "if:" not in _step(publish, "Summarize")
    assert "pattern: desktop-preview-macos-dmg-*\n" in _step(
        publish, "Receive the signed disk images"
    )


# ---------------------------------------------------------------------------
# Qualification before anyone is asked to approve the signing
# ---------------------------------------------------------------------------


def test_the_app_is_qualified_before_it_leaves_the_job(workflow: str) -> None:
    qualify = _job(workflow, "qualify")
    order = [
        "- name: Plan the preview from the release tag",
        "-m scripts.desktop_shell.build",
        "-m scripts.desktop_shell.inspect",
        "-m scripts.desktop_shell.smoke_artifact",
        "-m scripts.distribution.package_macos --app-only",
        "- name: Check the release identity of the app",
        "- name: Sign a copy of the app ad-hoc",
        "- name: Run policy-bound smoke checks on the ad-hoc signed app",
        "- name: Run ad-hoc signed app window smoke",
        "- name: Archive the unsigned app for the sign job",
        "- name: Hand the unsigned app to the sign job",
    ]
    positions = _positions(qualify, order)
    assert positions == sorted(positions)
    before_handoff = qualify.split("- name: Hand the unsigned app", 1)[0]
    assert "continue-on-error" not in workflow
    assert "if: always()" not in before_handoff


def test_the_build_is_a_release_build_of_the_tag(workflow: str) -> None:
    qualify = _job(workflow, "qualify")
    build = _step(qualify, "Build internal desktop onedir payload")

    assert "uses: ./.github/actions/setup-standalone-cli" in qualify
    assert '--commit "${COMMIT}"' in build
    assert '--release-tag "${TAG}"' in build
    assert '--channel "${CHANNEL}"' in build
    assert '--packaging-revision "${PACKAGING_REVISION}"' in build
    assert "CHANNEL: ${{ steps.plan.outputs.channel }}" in build
    assert "PACKAGING_REVISION: ${{ steps.plan.outputs.packaging-revision }}" in build
    assert "--platform macos" in _step(qualify, "Plan the preview from the release tag")
    installs = [line for line in workflow.splitlines() if "pip" in line and " install " in line]
    assert len(installs) == 2 and all("--require-hashes" in line for line in installs)
    assert "--upgrade" not in workflow
    # The bundle version is the product version; the marker carries the revision.
    commands = [line for line in workflow.splitlines() if not line.lstrip().startswith("#")]
    assert not any(re.search(r"--revision\b", line) for line in commands)


def test_the_app_marker_is_checked_where_the_app_reads_it(workflow: str) -> None:
    check = _step(_job(workflow, "qualify"), "Check the release identity of the app")

    assert "-m scripts.distribution.desktop_preview check-marker" in check
    assert '--marker "${APP_DIR}/Contents/MacOS/servonaut-runtime.json"' in check
    assert "APP_DIR: ${{ steps.app.outputs.app-dir }}" in check


def test_an_ad_hoc_copy_proves_the_hardened_runtime_first(workflow: str) -> None:
    qualify = _job(workflow, "qualify")
    adhoc = _script(qualify, "Sign a copy of the app ad-hoc")

    assert 'ditto "${APP_DIR}" "${APP}"' in adhoc
    assert 'APP="${ADHOC_DIR}/Servonaut.app"' in adhoc
    assert '-m scripts.distribution.sign_macos --target "${APP}" --identity - --verify' in adhoc
    assert "runtime" in adhoc
    for name in (
        "Run policy-bound smoke checks on the ad-hoc signed app",
        "Run ad-hoc signed app window smoke",
    ):
        step = _step(qualify, name)
        assert "APP_DIR: ${{ steps.adhoc.outputs.app-dir }}" in step
        assert '--payload-root "${APP_DIR}/Contents/MacOS"' in step
    assert "--selftest" in _step(qualify, "Run policy-bound smoke checks on the ad-hoc signed app")
    window = _step(qualify, "Run ad-hoc signed app window smoke")
    assert "-m scripts.desktop_shell.window_smoke" in window


def test_a_rehearsal_sets_the_version_as_the_release_workflow_does(workflow: str) -> None:
    qualify = _job(workflow, "qualify")
    step = _step(qualify, "Rehearse as a release commit")

    assert "if: needs.resolve.outputs.rehearsal-version != ''" in step
    assert (
        'run: python .github/scripts/release-policy.py set-version "${REHEARSAL_VERSION}"' in step
    )
    assert qualify.index("Rehearse as a release commit") < qualify.index(
        "Plan the preview from the release tag"
    )


# ---------------------------------------------------------------------------
# Signing, notarization and cleanup
# ---------------------------------------------------------------------------


def test_signing_steps_run_in_the_order_notarization_needs(workflow: str) -> None:
    sign = _job(workflow, "sign")
    order = [
        "- name: Confirm the commit to sign",
        "- name: Receive the unsigned app",
        "- name: Verify and unpack the unsigned app",
        "- name: Prepare the signing keychain",
        "- name: Sign the app with the Developer ID",
        "- name: Notarize and staple the app",
        "- name: Package, sign and notarize the disk image",
        "- name: Remove signing material",
        "- name: Run policy-bound smoke checks on the signed app",
        "- name: Run signed app window smoke",
        "- name: Hand the disk image to the publish job",
        "- name: Remove build material",
    ]
    positions = _positions(sign, order)
    assert positions == sorted(positions)


def test_the_app_is_not_assessed_before_it_is_notarized(workflow: str) -> None:
    sign = _job(workflow, "sign")
    app = _script(sign, "Sign the app with the Developer ID")

    assert '-m scripts.distribution.sign_macos --target "${APP}" \\\n' in app
    assert '--identity "${MACOS_SIGNING_IDENTITY}"\n' in app
    assert "--verify" not in app.replace("codesign --verify", "")
    assert "spctl" not in app
    assert "codesign --verify --strict --deep" in app
    for check in ("Authority=", "TeamIdentifier=", "^Timestamp=", "runtime"):
        assert check in app
    # Only the ad-hoc copy is signed with --verify.
    assert workflow.count("scripts.distribution.sign_macos --target") == 3
    assert workflow.count("--identity - --verify") == 1


def test_gatekeeper_must_accept_the_notarized_app_and_image(workflow: str) -> None:
    sign = _job(workflow, "sign")
    app = _script(sign, "Notarize and staple the app")
    image = _script(sign, "Package, sign and notarize the disk image")

    assert 'ditto -c -k --keepParent "${APP}" "${archive}"' in app
    for script in (app, image):
        assert "scripts.distribution.notarize_macos --artifact" in script
        assert '--api-key-file "${NOTARY_KEY}" --api-key-id "${APPLE_NOTARY_KEY_ID}"' in script
        assert '--api-issuer "${APPLE_NOTARY_ISSUER_ID}"' in script
        assert "grep -qx 'source=Notarized Developer ID'" in script
    stapled = _positions(
        app,
        [
            "scripts.distribution.notarize_macos",
            'xcrun stapler staple "${APP}"',
            'xcrun stapler validate "${APP}"',
            "spctl --assess --type execute -vv",
        ],
    )
    assert stapled == sorted(stapled)
    markers = [
        'scripts.distribution.package_macos --app-bundle "${APP}"',
        "--verify-image",
        'scripts.distribution.sign_macos --target "${dmg}"',
        'codesign --verify --strict --verbose=2 "${dmg}"',
        "--staple",
        'xcrun stapler validate "${dmg}"',
        "spctl --assess --type open --context context:primary-signature -vv",
        'shasum -a 256 "${dmg}"',
    ]
    positions = _positions(image, markers)
    assert positions == sorted(positions)


def test_the_signed_app_is_smoke_tested(workflow: str) -> None:
    sign = _job(workflow, "sign")
    smoke = _step(sign, "Run policy-bound smoke checks on the signed app")
    window = _step(sign, "Run signed app window smoke")

    for step in (smoke, window):
        assert "APP_DIR: ${{ steps.unpacked.outputs.app-dir }}" in step
        assert '--payload-root "${APP_DIR}/Contents/MacOS"' in step
        assert "secrets." not in step and "vars." not in step
    assert "--selftest" in smoke.split()
    assert '--product-version "${PRODUCT_VERSION}"' in smoke
    assert '--screenshot "${SCREENSHOT_DIR}/signed-desktop-window-${TARGET}.png"' in window
    assert "      PRODUCT_VERSION: ${{ needs.qualify.outputs.product-version }}\n" in sign


def test_signing_material_is_removed_whatever_happens(workflow: str) -> None:
    sign = _job(workflow, "sign")
    cleanup = _step(sign, "Remove signing material")
    script = _script(sign, "Remove signing material")

    assert "        if: always()\n" in cleanup
    assert "security delete-keychain" in script
    assert 'security list-keychains -d user -s "$@"' in script
    assert 'rm -f -- "${SIGNING_DIR}/certificate.p12" "${SIGNING_DIR}/notary-key.p8"' in script
    # Every part runs even when an earlier one fails.
    assert script.startswith("set -uo pipefail\n")
    assert "        if: always()\n" in _step(sign, "Remove build material")


def test_the_keychain_password_is_masked_before_it_is_used(workflow: str) -> None:
    script = _script(_job(workflow, "sign"), "Prepare the signing keychain")
    mask = script.index('echo "::add-mask::${password}"')

    assert 'password="$(openssl rand -hex 32)"' in script
    assert mask < script.index('security create-keychain -p "${password}"')
    assert script.count("${password}") == 4
    assert script.index("umask 077") < script.index("base64 --decode")
    assert script.index("security import") < script.index(
        'rm -f -- "${SIGNING_DIR}/certificate.p12"'
    ) < script.index("security set-key-partition-list")


def test_the_sign_job_checks_what_it_was_handed(workflow: str) -> None:
    sign = _job(workflow, "sign")
    unpack = _script(sign, "Verify and unpack the unsigned app")

    assert unpack.index("shasum -a 256 --check") < unpack.index("tar -x -p -f")
    assert "QUALIFIED_COMMIT: ${{ needs.qualify.outputs.commit }}" in _step(
        sign, "Confirm the commit to sign"
    )


# ---------------------------------------------------------------------------
# The resolve step, executed
# ---------------------------------------------------------------------------


def _resolve(workflow: str, tmp_path: Path, **env: str):
    return _run(
        workflow,
        "Decide what to build",
        tmp_path,
        **{
            "GITHUB_SHA": "c" * 40,
            "RELEASE_TAG": "",
            "INPUT_TAG": "",
            "INPUT_DRY_RUN": "",
            "INPUT_REHEARSAL_VERSION": "",
            "PREVIEW_PUBLISH": "",
            "MACOS_PUBLISH": "on",
            **env,
        },
    )


def test_it_accepts_the_same_tags_as_the_linux_preview(workflow: str) -> None:
    pattern = re.compile(r"^          version='(.+)'$", re.MULTILINE)
    deb = (_WORKFLOWS / "desktop-preview-deb.yml").read_text(encoding="utf-8")

    assert pattern.search(workflow).group(1) == pattern.search(deb).group(1)


@pytest.mark.parametrize("tag", ["v2.28.0rc1", "v2.28.0", "v3.0.0rc12"])
def test_a_published_release_builds_its_tag(workflow: str, tmp_path: Path, tag: str) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="release",
        GITHUB_REF=f"refs/tags/{tag}",
        RELEASE_TAG=tag,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert outputs == {
        "build": "true",
        "tag": tag,
        "dry-run": "false",
        "rehearsal-version": "",
        "checkout-ref": f"refs/tags/{tag}",
        "expected-commit": "c" * 40,
    }


@pytest.mark.parametrize("tag", ["v2.28.0-preview.1", "desktop-1", "v2.28.0a1"])
def test_other_releases_are_skipped_without_failing(
    workflow: str, tmp_path: Path, tag: str
) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="release",
        GITHUB_REF=f"refs/tags/{tag}",
        RELEASE_TAG=tag,
    )

    assert result.returncode == 0, result.stderr
    assert outputs == {"build": "false"}


def test_a_release_event_for_another_ref_fails(workflow: str, tmp_path: Path) -> None:
    result, _ = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="release",
        GITHUB_REF="refs/tags/v2.27.0",
        RELEASE_TAG="v2.28.0",
    )

    assert result.returncode == 1


@pytest.mark.parametrize("ref", ["refs/tags/v2.28.0rc1", "refs/heads/release/2.28.0"])
def test_a_manual_run_starts_where_the_signing_environment_deploys(
    workflow: str, tmp_path: Path, ref: str
) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF=ref,
        INPUT_TAG="v2.28.0rc1",
        INPUT_DRY_RUN="true",
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert outputs["build"] == "true"
    assert outputs["checkout-ref"] == "refs/tags/v2.28.0rc1"


@pytest.mark.parametrize(
    "ref",
    ["refs/heads/master", "refs/heads/feature/example", "refs/heads/release", "refs/pull/1/merge"],
)
def test_a_manual_run_elsewhere_is_refused_before_it_builds(
    workflow: str, tmp_path: Path, ref: str
) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF=ref,
        INPUT_TAG="v2.28.0rc1",
        INPUT_DRY_RUN="true",
    )

    assert result.returncode == 1
    assert f"Signing runs only from a release tag or a release/* branch, not {ref}." in (
        result.stdout
    )
    assert outputs == {}


def test_a_re_run_publishes_from_the_tag_itself(workflow: str, tmp_path: Path) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF="refs/tags/v2.28.0rc1",
        INPUT_TAG="v2.28.0rc1",
        INPUT_DRY_RUN="false",
    )

    assert result.returncode == 0, result.stderr
    assert outputs["dry-run"] == "false"
    assert outputs["checkout-ref"] == "refs/tags/v2.28.0rc1"
    assert outputs["expected-commit"] == "c" * 40


def test_publishing_from_a_branch_is_refused(workflow: str, tmp_path: Path) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF="refs/heads/release/2.28.0",
        INPUT_TAG="v2.28.0rc1",
        INPUT_DRY_RUN="false",
    )

    assert result.returncode == 1
    assert "gh workflow run desktop-preview-macos.yml --ref v2.28.0rc1 -f tag=v2.28.0rc1" in (
        result.stdout
    )
    assert outputs == {}


def test_a_rehearsal_from_a_release_branch_builds_its_own_commit(
    workflow: str, tmp_path: Path
) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF="refs/heads/release/macos-signing-rehearsal",
        INPUT_DRY_RUN="true",
        INPUT_REHEARSAL_VERSION="2.28.0",
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert outputs == {
        "build": "true",
        "tag": "v2.28.0",
        "dry-run": "true",
        "rehearsal-version": "2.28.0",
        "checkout-ref": "c" * 40,
        "expected-commit": "c" * 40,
    }
    summary = (tmp_path / "summary").read_text(encoding="utf-8")
    assert "nothing is handed on, attested or uploaded" in summary


@pytest.mark.parametrize(
    ("tag", "dry_run", "rehearsal"),
    [
        ("", "false", "2.28.0rc1"),
        ("v2.28.0rc1", "true", "2.28.0rc1"),
        ("", "true", "2.28.0-rc1"),
        ("", "true", "v2.28.0rc1"),
        ("", "true", ""),
        ("v2.28.0; true", "true", ""),
        ("v2.28.0-preview.1", "true", ""),
    ],
)
def test_invalid_requests_are_refused(
    workflow: str, tmp_path: Path, tag: str, dry_run: str, rehearsal: str
) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF="refs/heads/release/2.28.0",
        INPUT_TAG=tag,
        INPUT_DRY_RUN=dry_run,
        INPUT_REHEARSAL_VERSION=rehearsal,
    )

    assert result.returncode == 1
    assert outputs == {}


def test_other_events_are_refused(workflow: str, tmp_path: Path) -> None:
    result, _ = _resolve(
        workflow, tmp_path, GITHUB_EVENT_NAME="push", GITHUB_REF="refs/heads/master"
    )

    assert result.returncode == 1


# ---------------------------------------------------------------------------
# The DESKTOP_PREVIEW_PUBLISH and DESKTOP_MACOS_PUBLISH switches
# ---------------------------------------------------------------------------


def test_the_switches_are_repository_variables_only_resolve_reads(workflow: str) -> None:
    step = _step(_job(workflow, "resolve"), "Decide what to build")

    assert "          PREVIEW_PUBLISH: ${{ vars.DESKTOP_PREVIEW_PUBLISH }}\n" in step
    assert "          MACOS_PUBLISH: ${{ vars.DESKTOP_MACOS_PUBLISH }}\n" in step
    assert workflow.count("vars.DESKTOP_PREVIEW_PUBLISH") == 1
    assert workflow.count("vars.DESKTOP_MACOS_PUBLISH") == 1


def _release(workflow: str, tmp_path: Path, tag: str = "v2.28.0", **switches: str):
    return _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="release",
        GITHUB_REF=f"refs/tags/{tag}",
        RELEASE_TAG=tag,
        **switches,
    )


@pytest.mark.parametrize("value", ["", "off", "OFF", "Off"])
def test_a_release_gets_no_macos_preview_until_it_is_switched_on(
    workflow: str, tmp_path: Path, value: str
) -> None:
    result, outputs = _release(workflow, tmp_path, MACOS_PUBLISH=value)

    assert result.returncode == 0, result.stderr + result.stdout
    assert outputs == {"build": "false"}
    assert (
        "::notice::DESKTOP_MACOS_PUBLISH is not on, so v2.28.0 gets no macOS desktop preview."
        in result.stdout
    )
    assert "Set the repository variable to on" in result.stdout
    later = "gh workflow run desktop-preview-macos.yml --ref v2.28.0 -f tag=v2.28.0"
    assert later in result.stdout
    summary = (tmp_path / "summary").read_text(encoding="utf-8")
    assert "DESKTOP_MACOS_PUBLISH is not on" in summary and later in summary


@pytest.mark.parametrize("value", ["on", "ON", "On"])
def test_a_release_gets_its_macos_preview_once_switched_on(
    workflow: str, tmp_path: Path, value: str
) -> None:
    result, outputs = _release(workflow, tmp_path, MACOS_PUBLISH=value)

    assert result.returncode == 0, result.stderr + result.stdout
    assert outputs["build"] == "true"


@pytest.mark.parametrize("macos", ["", "on", "off"])
def test_the_desktop_preview_switch_holds_back_the_macos_preview_too(
    workflow: str, tmp_path: Path, macos: str
) -> None:
    result, outputs = _release(workflow, tmp_path, PREVIEW_PUBLISH="off", MACOS_PUBLISH=macos)

    assert result.returncode == 0, result.stderr + result.stdout
    assert outputs == {"build": "false"}
    assert "::notice::DESKTOP_PREVIEW_PUBLISH is off" in result.stdout


@pytest.mark.parametrize(
    ("switch", "value"),
    [("PREVIEW_PUBLISH", "false"), ("MACOS_PUBLISH", "0"), ("MACOS_PUBLISH", "skip")],
)
def test_an_unknown_switch_value_fails_instead_of_guessing(
    workflow: str, tmp_path: Path, switch: str, value: str
) -> None:
    result, outputs = _release(workflow, tmp_path, **{switch: value})

    assert result.returncode == 1
    assert f"must be on or off, not '{value}'" in result.stdout
    assert outputs == {}


@pytest.mark.parametrize("dry_run", ["false", "true"])
def test_a_manual_run_ignores_both_switches(
    workflow: str, tmp_path: Path, dry_run: str
) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF="refs/tags/v2.28.0",
        INPUT_TAG="v2.28.0",
        INPUT_DRY_RUN=dry_run,
        PREVIEW_PUBLISH="off",
        MACOS_PUBLISH="",
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert outputs["build"] == "true"
    assert outputs["dry-run"] == dry_run


@pytest.mark.parametrize(
    "tag",
    [
        "v0.0.0",
        "v2.28.0",
        "v2.28.0rc1",
        "v2.28.0rc0",
        "v02.28.0",
        "v2.28.0rc01",
        "v2.28",
        "V2.28.0",
    ],
)
def test_the_step_and_the_planner_accept_the_same_tags(
    workflow: str, tmp_path: Path, tag: str
) -> None:
    result, outputs = _release(workflow, tmp_path, tag)
    try:
        preview_for_tag(tag)
        planned = True
    except DesktopPreviewError:
        planned = False

    assert result.returncode == 0
    assert (outputs["build"] == "true") is planned


# ---------------------------------------------------------------------------
# Plan and release-identity steps, executed
# ---------------------------------------------------------------------------


def test_the_plan_step_plans_the_macos_preview_of_the_checkout(
    workflow: str, tmp_path: Path
) -> None:
    version = declared_versions(_REPO_ROOT)[0]
    result, outputs = _run(
        workflow,
        "Plan the preview from the release tag",
        tmp_path,
        cwd=_REPO_ROOT,
        TAG=f"v{version}",
        QUALIFIED_PYTHON=sys.executable,
        GITHUB_WORKSPACE=str(_REPO_ROOT),
    )

    assert result.returncode == 0, result.stderr
    assert outputs == preview_for_tag(f"v{version}").macos_outputs()


def test_the_plan_step_stops_a_tag_its_checkout_disagrees_with(
    workflow: str, tmp_path: Path
) -> None:
    result, outputs = _run(
        workflow,
        "Plan the preview from the release tag",
        tmp_path,
        cwd=_REPO_ROOT,
        TAG="v999.0.0rc1",
        QUALIFIED_PYTHON=sys.executable,
        GITHUB_WORKSPACE=str(_REPO_ROOT),
    )

    assert result.returncode == 1
    assert "::error::v999.0.0rc1 does not match the package version" in result.stderr
    assert outputs == {}


@pytest.mark.parametrize("planner", [None, "PACKAGE_NAME = 'servonaut'\n"])
def test_the_plan_step_names_a_tag_that_predates_the_macos_preview(
    workflow: str, tmp_path: Path, planner: str | None
) -> None:
    if planner is not None:
        (tmp_path / "scripts" / "distribution").mkdir(parents=True)
        (tmp_path / "scripts" / "distribution" / "desktop_preview.py").write_text(planner)

    result, _ = _run(
        workflow,
        "Plan the preview from the release tag",
        tmp_path,
        TAG="v2.27.0",
        QUALIFIED_PYTHON=sys.executable,
        GITHUB_WORKSPACE=str(tmp_path),
    )

    assert result.returncode == 1
    assert "v2.27.0 predates the macOS desktop preview packaging" in result.stdout


def _app(root: Path, tag: str = "v2.28.0rc1", **marker_fields: object) -> Path:
    """A stand-in Servonaut.app with the links and modes of the signable layout."""
    preview = preview_for_tag(tag)
    app = root / "Servonaut.app"
    macos = app / "Contents" / "MacOS"
    resources = app / "Contents" / "Resources"
    frameworks = app / "Contents" / "Frameworks"
    for directory in (macos, resources, frameworks / "voice"):
        directory.mkdir(parents=True)
    for name in _EXECUTABLES:
        (macos / name).write_bytes(b"\xcf\xfa\xed\xfe executable " + name.encode())
        (macos / name).chmod(0o755)
    (frameworks / "voice" / "uv").write_bytes(b"\xcf\xfa\xed\xfe uv")
    (frameworks / "voice" / "uv").chmod(0o755)
    marker = {
        "schema_version": 1,
        "distribution": "packaged-desktop",
        "product_version": preview.product_version,
        "build_revision": "1234",
        **preview.identity.marker_fields(),
        "console_helper": "servonaut",
        "desktop_child": "servonaut-desktop-child",
        **marker_fields,
    }
    (resources / "servonaut-runtime.json").write_text(json.dumps(marker), encoding="utf-8")
    (resources / "servonaut-runtime.json").chmod(0o644)
    (macos / "servonaut-runtime.json").symlink_to("../Resources/servonaut-runtime.json")
    (resources / "voice").symlink_to("../Frameworks/voice")
    (app / "Contents" / "Info.plist").write_text("<plist/>", encoding="utf-8")
    return app


def _tree(root: Path) -> dict[str, tuple[str, int | str]]:
    tree: dict[str, tuple[str, int | str]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            tree[relative] = ("link", os.readlink(path))
        elif path.is_dir():
            tree[relative] = ("dir", stat.S_IMODE(path.stat().st_mode))
        else:
            tree[relative] = ("file", stat.S_IMODE(path.stat().st_mode))
    return tree


@pytest.mark.parametrize("tag", ["v2.28.0rc1", "v2.28.0"])
def test_the_marker_check_accepts_the_tags_release_build(
    workflow: str, tmp_path: Path, tag: str
) -> None:
    app = _app(tmp_path / "macos", tag)

    result, _ = _run(
        workflow,
        "Check the release identity of the app",
        tmp_path,
        cwd=_REPO_ROOT,
        TAG=tag,
        QUALIFIED_PYTHON=sys.executable,
        GITHUB_WORKSPACE=str(_REPO_ROOT),
        APP_DIR=str(app),
    )

    assert result.returncode == 0, result.stderr + result.stdout
    channel = preview_for_tag(tag).identity.channel
    assert f"on the {channel} channel at packaging revision 1." in result.stdout


@pytest.mark.parametrize(
    ("fields", "reason"),
    [
        ({"channel": "stable"}, "follows the stable channel"),
        ({"packaging_revision": 3}, "at packaging revision 3"),
        ({"product_version": "2.28.0"}, "is version '2.28.0'"),
    ],
)
def test_the_marker_check_refuses_another_build(
    workflow: str, tmp_path: Path, fields: dict[str, object], reason: str
) -> None:
    app = _app(tmp_path / "macos", "v2.28.0rc1", **fields)

    result, _ = _run(
        workflow,
        "Check the release identity of the app",
        tmp_path,
        cwd=_REPO_ROOT,
        TAG="v2.28.0rc1",
        QUALIFIED_PYTHON=sys.executable,
        GITHUB_WORKSPACE=str(_REPO_ROOT),
        APP_DIR=str(app),
    )

    assert result.returncode == 1
    assert reason in result.stderr


# ---------------------------------------------------------------------------
# The unsigned app's trip from the qualify job to the sign job, executed
# ---------------------------------------------------------------------------

# GNU tar stands in for the macOS bsdtar; the flags only bsdtar knows keep
# Mac metadata out of the archive and have nothing to do on Linux.
_BSDTAR_STUB = r"""
tar() {
  local args=()
  for arg in "$@"; do
    case "${arg}" in
      --no-mac-metadata|--no-fflags) ;;
      *) args+=("${arg}") ;;
    esac
  done
  command tar "${args[@]}"
}
"""


def _archived(workflow: str, tmp_path: Path) -> tuple[Path, dict[str, str], dict]:
    macos = tmp_path / "qualify" / "macos"
    handoff = tmp_path / "qualify" / "handoff"
    handoff.mkdir(parents=True)
    app = _app(macos)
    result, outputs = _run(
        workflow,
        "Archive the unsigned app for the sign job",
        tmp_path,
        prelude=_BSDTAR_STUB,
        TARGET="macos-arm64",
        MACOS_DIR=str(macos),
        HANDOFF_DIR=str(handoff),
    )
    assert result.returncode == 0, result.stderr + result.stdout
    return handoff, outputs, _tree(app)


def _unpack(workflow: str, tmp_path: Path, handoff: Path, digest: str):
    parent = tmp_path / "sign" / "app"
    parent.mkdir(parents=True)
    result, outputs = _run(
        workflow,
        "Verify and unpack the unsigned app",
        tmp_path,
        prelude=_BSDTAR_STUB,
        TARGET="macos-arm64",
        APP_SHA256=digest,
        HANDOFF_DIR=str(handoff),
        APP_PARENT=str(parent),
    )
    return result, outputs, parent


def test_the_app_reaches_the_sign_job_with_its_links_and_modes(
    workflow: str, tmp_path: Path
) -> None:
    handoff, archived, tree = _archived(workflow, tmp_path)

    archive = Path(archived["archive-path"])
    assert archive == handoff / "Servonaut-macos-arm64.app.tar"
    assert archived["app-sha256-macos-arm64"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert set(archived) == {"archive-path", "app-sha256-macos-arm64"}

    digest = archived["app-sha256-macos-arm64"]
    result, outputs, parent = _unpack(workflow, tmp_path, handoff, digest)

    assert result.returncode == 0, result.stderr + result.stdout
    assert outputs == {"app-dir": str(parent / "Servonaut.app")}
    assert _tree(parent / "Servonaut.app") == tree
    assert tree["Contents/MacOS/servonaut-runtime.json"] == (
        "link",
        "../Resources/servonaut-runtime.json",
    )
    assert tree["Contents/MacOS/servonaut"] == ("file", 0o755)


@pytest.mark.parametrize("tamper", ["digest", "no-digest", "extra-file", "extra-entry"])
def test_the_sign_job_refuses_an_app_it_was_not_promised(
    workflow: str, tmp_path: Path, tamper: str
) -> None:
    handoff, archived, _ = _archived(workflow, tmp_path)
    digest = archived["app-sha256-macos-arm64"]
    archive = Path(archived["archive-path"])
    if tamper == "digest":
        digest = "0" * 64
    elif tamper == "no-digest":
        digest = ""
    elif tamper == "extra-file":
        (handoff / "other.tar").write_bytes(b"not qualified")
    else:
        (tmp_path / "stray").write_text("stray", encoding="utf-8")
        subprocess.run(
            ["tar", "-r", "-f", str(archive), "-C", str(tmp_path), "stray"], check=True
        )
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()

    result, outputs, parent = _unpack(workflow, tmp_path, handoff, digest)

    assert result.returncode != 0
    assert outputs == {}
    if tamper != "extra-entry":
        assert not any(parent.iterdir())


# ---------------------------------------------------------------------------
# The signing keychain, executed with a stand-in for security(1)
# ---------------------------------------------------------------------------

_SECURITY_STUB = r"""
security() {
  local p12=absent
  [ -e "${SIGNING_DIR}/certificate.p12" ] && p12=present
  printf '%s|p12=%s\n' "$*" "${p12}" >> "${TEST_SECURITY_LOG}"
  case "$1" in
    list-keychains)
      if [ "$*" = "list-keychains -d user" ]; then
        printf '    "/Users/runner/Library/Keychains/login.keychain-db"\n'
        printf '    "/Library/Keychains/System.keychain"\n'
      fi
      ;;
    create-keychain) : > "${@: -1}" ;;
    delete-keychain) rm -f -- "$2" ;;
    find-identity)
      printf '  1) %s "%s"\n' "${TEST_FINGERPRINT}" "${TEST_IDENTITY}"
      printf '     1 valid identities found\n'
      ;;
  esac
  [ -z "${TEST_SECURITY_FAIL:-}" ]
}
"""
_P12 = b"\x30\x82 certificate bundle"
_P8 = b"-----BEGIN PRIVATE KEY-----\nnotary key\n-----END PRIVATE KEY-----\n"


def _keychain_env(tmp_path: Path, **overrides: str) -> dict[str, str]:
    signing = tmp_path / "signing"
    signing.mkdir(mode=0o700, exist_ok=True)
    return {
        "SIGNING_DIR": str(signing),
        "MACOS_CERTIFICATE_P12_BASE64": base64.b64encode(_P12).decode(),
        "MACOS_CERTIFICATE_PASSWORD": "certificate-password",
        "APPLE_NOTARY_KEY_P8_BASE64": base64.b64encode(_P8).decode(),
        "MACOS_SIGNING_IDENTITY": _IDENTITY,
        "APPLE_TEAM_ID": "ABCDE12345",
        "APPLE_NOTARY_KEY_ID": "KEYID",
        "APPLE_NOTARY_ISSUER_ID": "issuer-id",
        "TEST_SECURITY_LOG": str(tmp_path / "security.log"),
        "TEST_IDENTITY": _IDENTITY,
        "TEST_FINGERPRINT": "A" * 40,
        **overrides,
    }


def _security_calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "security.log"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def test_the_keychain_holds_the_identity_and_the_key_files_stay_private(
    workflow: str, tmp_path: Path
) -> None:
    env = _keychain_env(tmp_path)
    signing = Path(env["SIGNING_DIR"])

    result, outputs = _run(
        workflow, "Prepare the signing keychain", tmp_path, prelude=_SECURITY_STUB, **env
    )

    assert result.returncode == 0, result.stderr + result.stdout
    keychain = signing / "signing.keychain-db"
    mask = re.fullmatch(r"::add-mask::([0-9a-f]{64})\n", result.stdout)
    assert mask, result.stdout
    password = mask.group(1)
    calls = [call.split("|")[0] for call in _security_calls(tmp_path)]
    assert calls == [
        "list-keychains -d user",
        f"create-keychain -p {password} {keychain}",
        f"set-keychain-settings -lut 21600 {keychain}",
        f"unlock-keychain -p {password} {keychain}",
        f"import {signing}/certificate.p12 -k {keychain} -f pkcs12 -P certificate-password"
        " -T /usr/bin/codesign",
        f"set-key-partition-list -S apple-tool:,apple:,codesign: -s -k {password} {keychain}",
        f"list-keychains -d user -s {keychain} /Users/runner/Library/Keychains/login.keychain-db"
        " /Library/Keychains/System.keychain",
        f"find-identity -v -p codesigning {keychain}",
    ]
    presence = dict(call.split("|") for call in _security_calls(tmp_path))
    # The certificate exists only until it is imported.
    assert presence[calls[4]] == "p12=present"
    assert presence[calls[5]] == "p12=absent"
    assert not (signing / "certificate.p12").exists()
    notary_key = signing / "notary-key.p8"
    assert outputs == {"notary-key": str(notary_key)}
    assert notary_key.read_bytes() == _P8
    assert stat.S_IMODE(notary_key.stat().st_mode) == 0o600
    assert (signing / "search-list").read_text(encoding="utf-8") == (
        "/Users/runner/Library/Keychains/login.keychain-db\n/Library/Keychains/System.keychain\n"
    )
    assert password not in result.stdout.replace(mask.group(0), "")
    assert password not in result.stderr


@pytest.mark.parametrize(
    "setting", ["MACOS_CERTIFICATE_PASSWORD", "MACOS_SIGNING_IDENTITY", "APPLE_TEAM_ID"]
)
def test_a_missing_signing_setting_stops_before_any_keychain_exists(
    workflow: str, tmp_path: Path, setting: str
) -> None:
    env = _keychain_env(tmp_path, **{setting: ""})

    result, outputs = _run(
        workflow, "Prepare the signing keychain", tmp_path, prelude=_SECURITY_STUB, **env
    )

    assert result.returncode == 1
    assert f"::error::The desktop-signing environment does not set {setting}." in result.stdout
    assert _security_calls(tmp_path) == []
    assert outputs == {}


def test_a_keychain_without_the_named_identity_fails(workflow: str, tmp_path: Path) -> None:
    other = "Developer ID Application: Another Publisher (ZZZZZ99999)"
    env = _keychain_env(tmp_path, TEST_IDENTITY=other)

    result, outputs = _run(
        workflow, "Prepare the signing keychain", tmp_path, prelude=_SECURITY_STUB, **env
    )

    assert result.returncode == 1
    assert "holds no valid code-signing identity named MACOS_SIGNING_IDENTITY" in result.stdout
    assert _IDENTITY not in result.stdout
    assert outputs == {}


def _signing_material(tmp_path: Path) -> Path:
    signing = tmp_path / "signing"
    signing.mkdir(mode=0o700)
    (signing / "search-list").write_text("/one.keychain-db\n/two keychain-db\n", encoding="utf-8")
    for name in ("signing.keychain-db", "certificate.p12", "notary-key.p8"):
        (signing / name).write_bytes(b"material")
    return signing


def test_the_cleanup_deletes_the_keychain_and_restores_the_search_list(
    workflow: str, tmp_path: Path
) -> None:
    signing = _signing_material(tmp_path)

    result, _ = _run(
        workflow,
        "Remove signing material",
        tmp_path,
        prelude=_SECURITY_STUB,
        SIGNING_DIR=str(signing),
        TEST_SECURITY_LOG=str(tmp_path / "security.log"),
    )

    assert result.returncode == 0, result.stderr + result.stdout
    calls = [call.split("|")[0] for call in _security_calls(tmp_path)]
    assert calls == [
        "list-keychains -d user -s /one.keychain-db /two keychain-db",
        f"delete-keychain {signing}/signing.keychain-db",
    ]
    assert sorted(path.name for path in signing.iterdir()) == ["search-list"]


def test_the_cleanup_removes_the_key_files_even_when_security_fails(
    workflow: str, tmp_path: Path
) -> None:
    signing = _signing_material(tmp_path)

    result, _ = _run(
        workflow,
        "Remove signing material",
        tmp_path,
        prelude=_SECURITY_STUB,
        SIGNING_DIR=str(signing),
        TEST_SECURITY_LOG=str(tmp_path / "security.log"),
        TEST_SECURITY_FAIL="1",
    )

    assert result.returncode == 1
    assert not (signing / "certificate.p12").exists()
    assert not (signing / "notary-key.p8").exists()
    assert len(_security_calls(tmp_path)) == 2


@pytest.mark.parametrize("prepared", [False, True])
def test_the_cleanup_has_nothing_to_do_before_the_keychain_exists(
    workflow: str, tmp_path: Path, prepared: bool
) -> None:
    signing = tmp_path / "signing"
    if prepared:
        signing.mkdir()

    result, _ = _run(
        workflow,
        "Remove signing material",
        tmp_path,
        prelude=_SECURITY_STUB,
        SIGNING_DIR=str(signing) if prepared else "",
        TEST_SECURITY_LOG=str(tmp_path / "security.log"),
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert _security_calls(tmp_path) == []


# ---------------------------------------------------------------------------
# Publishing, executed
# ---------------------------------------------------------------------------


def _signed_images(tmp_path: Path, tag: str = "v2.28.0rc1") -> tuple[Path, dict[str, str]]:
    preview = preview_for_tag(tag)
    received = tmp_path / "preview"
    received.mkdir()
    env = {"TAG": tag, "SUMS_ASSET": preview.macos_sums_asset}
    for target, prefix in zip(MACOS_TARGETS, ("ARM64", "X64"), strict=True):
        name = preview.macos_dmg_asset(target)
        (received / name).write_bytes(f"signed image {target}".encode())
        env[f"{prefix}_DMG"] = name
        env[f"{prefix}_SHA256"] = hashlib.sha256((received / name).read_bytes()).hexdigest()
    return received, env


def test_the_publish_job_writes_checksums_users_can_check(
    workflow: str, tmp_path: Path
) -> None:
    received, env = _signed_images(tmp_path)

    result, _ = _run(
        workflow, "Verify the disk images and write their checksums", tmp_path, cwd=received, **env
    )

    assert result.returncode == 0, result.stderr + result.stdout
    sums = received / "servonaut-desktop-preview_2.28.0rc1_macos_SHA256SUMS"
    assert sums.read_text(encoding="utf-8") == (
        f"{env['ARM64_SHA256']}  servonaut-desktop-preview_2.28.0rc1_macos-arm64.dmg\n"
        f"{env['X64_SHA256']}  servonaut-desktop-preview_2.28.0rc1_macos-x64.dmg\n"
    )
    subprocess.run(["sha256sum", "--check", "--strict", sums.name], cwd=received, check=True)


@pytest.mark.parametrize("tamper", ["digest", "no-digest", "extra-file", "missing-file"])
def test_the_publish_job_refuses_images_it_was_not_promised(
    workflow: str, tmp_path: Path, tamper: str
) -> None:
    received, env = _signed_images(tmp_path, "v2.28.0")
    if tamper == "digest":
        env["X64_SHA256"] = "0" * 64
    elif tamper == "no-digest":
        env["ARM64_SHA256"] = ""
    elif tamper == "extra-file":
        (received / "other.dmg").write_bytes(b"not signed here")
    else:
        (received / env["X64_DMG"]).unlink()

    result, _ = _run(
        workflow, "Verify the disk images and write their checksums", tmp_path, cwd=received, **env
    )

    assert result.returncode != 0
    assert not (received / env["SUMS_ASSET"]).exists()


# A stand-in for gh: the release is a directory of assets.
_GH_STUB = r"""
gh() {
  printf '%s\n' "$*" >> "${TEST_GH_LOG}"
  case "$1 $2" in
    "release upload")
      shift 3
      for file in "$@"; do
        [ "${file}" = "--clobber" ] && continue
        cp "${file}" "${TEST_RELEASE}/"
        if [ -n "${TEST_CORRUPT:-}" ]; then printf 'x' >> "${TEST_RELEASE}/$(basename "${file}")"; fi
      done
      if [ -n "${TEST_DROP:-}" ]; then rm "${TEST_RELEASE}/${TEST_DROP}"; fi
      ;;
    "api repos/"*)
      ls -1 "${TEST_RELEASE}"
      ;;
    "release download")
      local dir="" names=()
      shift 3
      while [ "$#" -gt 0 ]; do
        case "$1" in
          --dir) dir="$2"; shift 2 ;;
          --pattern) names+=("$2"); shift 2 ;;
          *) shift ;;
        esac
      done
      for name in "${names[@]}"; do cp "${TEST_RELEASE}/${name}" "${dir}/"; done
      ;;
    *) return 1 ;;
  esac
}
"""


def _upload(workflow: str, tmp_path: Path, **env: str) -> subprocess.CompletedProcess[str]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    received, images = _signed_images(workspace)
    lines = [
        f"{images[f'{prefix}_SHA256']}  {images[f'{prefix}_DMG']}\n" for prefix in ("ARM64", "X64")
    ]
    (received / images["SUMS_ASSET"]).write_text("".join(lines), encoding="utf-8")
    release = tmp_path / "release"
    release.mkdir()
    linux = preview_for_tag("v2.28.0rc1")
    for name in ("notes.txt", linux.deb_asset, linux.sums_asset, images["ARM64_DMG"]):
        (release / name).write_text("published earlier\n", encoding="utf-8")
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    (runner_temp / "assets-before").write_text(
        "".join(f"{path.name}\n" for path in sorted(release.iterdir())), encoding="utf-8"
    )
    return subprocess.run(
        ["bash", "-c", _GH_STUB + _script(workflow, "Upload the macOS preview to the release")],
        cwd=workspace,
        text=True,
        capture_output=True,
        check=False,
        env={
            "PATH": os.environ["PATH"],
            "RUNNER_TEMP": str(runner_temp),
            "GH_REPO": "example/project",
            "TEST_RELEASE": str(release),
            "TEST_GH_LOG": str(tmp_path / "gh.log"),
            **images,
            **env,
        },
    )


def test_the_upload_replaces_its_assets_and_checks_what_users_download(
    workflow: str, tmp_path: Path
) -> None:
    result = _upload(workflow, tmp_path)

    assert result.returncode == 0, result.stderr + result.stdout
    preview = preview_for_tag("v2.28.0rc1")
    release = tmp_path / "release"
    macos = [*map(preview.macos_dmg_asset, MACOS_TARGETS), preview.macos_sums_asset]
    assert sorted(path.name for path in release.iterdir()) == sorted(
        ["notes.txt", preview.deb_asset, preview.sums_asset, *macos]
    )
    # The Linux preview's assets are left alone.
    for name in ("notes.txt", preview.deb_asset, preview.sums_asset):
        assert (release / name).read_text(encoding="utf-8") == "published earlier\n"
    arm64 = release / preview.macos_dmg_asset("macos-arm64")
    assert arm64.read_bytes() == b"signed image macos-arm64"
    calls = (tmp_path / "gh.log").read_text(encoding="utf-8").splitlines()
    uploaded = " ".join(f"preview/{name}" for name in macos)
    assert calls[0] == f"release upload v2.28.0rc1 {uploaded} --clobber"
    assert not any("delete" in call for call in calls)
    assert "gh release delete" not in workflow
    assert "delete-asset" not in workflow
    assert "gh release create" not in workflow
    assert "gh release edit" not in workflow


def test_the_upload_fails_if_another_asset_disappeared(workflow: str, tmp_path: Path) -> None:
    result = _upload(workflow, tmp_path, TEST_DROP="notes.txt")

    assert result.returncode == 1
    assert "::error::The upload removed another asset of v2.28.0rc1." in result.stdout


def test_the_upload_fails_if_the_published_images_do_not_match(
    workflow: str, tmp_path: Path
) -> None:
    result = _upload(workflow, tmp_path, TEST_CORRUPT="1")

    assert result.returncode != 0
    assert "FAILED" in result.stdout + result.stderr


def test_both_images_are_attested_before_they_are_uploaded(workflow: str) -> None:
    publish = _job(workflow, "publish")
    attest = _step(publish, "Attest the disk images' build provenance")

    for target in MACOS_TARGETS:
        assert f"preview/${{{{ needs.qualify.outputs.dmg-asset-{target} }}}}\n" in attest
    positions = _positions(
        publish,
        [
            "- name: Receive the signed disk images",
            "- name: Verify the disk images and write their checksums",
            "- name: Confirm the release and its tag",
            "- name: Attest the disk images' build provenance",
            "- name: Upload the macOS preview to the release",
            "- name: Summarize",
        ],
    )
    assert positions == sorted(positions)
    confirm = _step(publish, "Confirm the release and its tag")
    assert 'gh api "repos/${GH_REPO}/commits/refs/tags/${TAG}"' in confirm
    assert '"${tagged}" != "${COMMIT}"' in confirm


def test_the_user_guide_matches_the_published_names() -> None:
    guide = (_REPO_ROOT / "docs" / "release-candidates.md").read_text(encoding="utf-8")
    section = guide.split("## macOS desktop preview\n", 1)[1].split("\n## ", 1)[0]
    preview = preview_for_tag("v2.28.0rc1")

    def spelled(asset: str, version: str) -> str:
        return asset.replace(preview.product_version, version)

    for target in MACOS_TARGETS:
        assert f"`{spelled(preview.macos_dmg_asset(target), '<version>')}`" in section
        assert f"`{target}`" in section
    assert f"`{spelled(preview.macos_sums_asset, '<version>')}`" in section
    # The commands build the same names from the version and the image.
    image = spelled(preview.macos_dmg_asset("macos-arm64"), "${version}").replace("macos-arm64", "${image}")
    assert "| shasum -a 256 -c -\n" in section
    assert f'"{spelled(preview.macos_sums_asset, "${version}")}"' in section
    assert f'gh attestation verify "{image}" --repo zb-ss/servonaut\n' in section
    assert "source=Notarized Developer ID" in section
    assert "macOS 13" in section


def test_the_switch_signing_and_rehearsal_are_documented(workflow: str) -> None:
    guide = (_REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    preview = preview_for_tag("v2.31.0rc1")

    assert "`DESKTOP_MACOS_PUBLISH`" in guide
    assert "`desktop-signing`" in guide
    for name in (*_SECRETS, *_SIGNING_VARIABLES):
        assert f"`{name}`" in guide
    for command in (
        "gh workflow run desktop-preview-macos.yml --ref vX.Y.Z -f tag=vX.Y.Z",
        "gh workflow run desktop-preview-macos.yml --ref release/macos-signing-rehearsal "
        "-f dry_run=true -f rehearsal_version=X.Y.Z",
    ):
        assert command in guide
    # The rehearsal is the one the workflow itself describes.
    assert "--ref release/<branch> -f dry_run=true -f rehearsal_version=X.Y.Z" in workflow
    assert (
        f"gh release delete-asset v2.31.0rc1 {preview.macos_dmg_asset('macos-arm64')} "
        "--yes --repo zb-ss/servonaut"
    ) in guide
