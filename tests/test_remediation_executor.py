"""Tests for proactive-remediation handling (Phase 3).

Pins the mutating half of the contract:

- remediation envelopes (``source: "proactive_remediation"``) route to
  the verb-allowlisted executor — never the probe bridge, never the AI
  chat path, and NEVER a server-supplied command string;
- the command line is built locally from validated payload fields
  (fixed argv, shell-quoted) and success is judged on the remote exit
  code recovered via the exit marker;
- EVERY dispatch is answered, including validation rejections and
  "no executors wired" (silence burns the relay TTL server-side);
- failure messages LEAD with a snake_case slug (failure-evidence
  contract, mirroring probe skip reasons).

Fixtures are generic — no real hosts, IPs, or customer identifiers.
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

httpx = pytest.importorskip("httpx")
pytest.importorskip("httpx_sse")

from servonaut.models.relay_messages import CommandResponse, CommandType
from servonaut.services.relay_listener import RelayListener
from servonaut.services.remediation_executor import (
    EXIT_MARKER,
    REMEDIATION_SOURCE,
    REMEDIATION_VERBS,
    RemediationValidationError,
    build_remediation_command,
    build_remediation_result,
    classify_failure,
    parse_exit_marker,
    wrap_with_exit_marker,
)


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Command builder
# ---------------------------------------------------------------------------


class TestBuildRemediationCommand:
    def test_certbot_renew_fixed_argv(self):
        cmd = build_remediation_command(
            "certbot_renew", {"cert_name": "example.com"},
        )
        assert cmd == (
            "sudo -n certbot renew --cert-name example.com --non-interactive"
        )

    def test_dry_run_appends_flag(self):
        cmd = build_remediation_command(
            "certbot_renew", {"cert_name": "example.com", "dry_run": True},
        )
        assert cmd.endswith("--dry-run")

    @pytest.mark.parametrize("falsy_dry_run", ["false", "False", "0", "", "no"])
    def test_string_falsy_dry_run_does_not_append_flag(self, falsy_dry_run):
        # bool("false") is True in Python — a payload that arrives with a
        # string instead of a JSON boolean must not silently build a
        # DIFFERENT command than the one the confirm_token was signed over.
        cmd = build_remediation_command(
            "certbot_renew",
            {"cert_name": "example.com", "dry_run": falsy_dry_run},
        )
        assert "--dry-run" not in cmd

    @pytest.mark.parametrize("truthy_dry_run", ["true", "True", "1", "yes"])
    def test_string_truthy_dry_run_appends_flag(self, truthy_dry_run):
        cmd = build_remediation_command(
            "certbot_renew",
            {"cert_name": "example.com", "dry_run": truthy_dry_run},
        )
        assert cmd.endswith("--dry-run")

    def test_wildcard_and_lineage_suffix_names_accepted(self):
        for name in ("*.example.com", "example.com-0001"):
            assert name in build_remediation_command(
                "certbot_renew", {"cert_name": name},
            )

    @pytest.mark.parametrize("bad", [
        "example.com; rm -rf /",
        "$(reboot)",
        "example..com",
        "-r example.com",
        "",
        None,
        42,
    ])
    def test_hostile_or_malformed_cert_name_rejected(self, bad):
        with pytest.raises(RemediationValidationError) as exc:
            build_remediation_command("certbot_renew", {"cert_name": bad})
        assert str(exc.value).startswith("invalid_cert_name:")

    def test_unknown_verb_rejected_with_slug(self):
        with pytest.raises(RemediationValidationError) as exc:
            build_remediation_command("rm_rf_slash", {"cert_name": "a.com"})
        assert str(exc.value).startswith("unknown_remediation_verb:")

    def test_run_command_is_not_a_verb(self):
        # The generic shell verb must never sneak into the allowlist.
        assert "run_command" not in REMEDIATION_VERBS
        with pytest.raises(RemediationValidationError):
            build_remediation_command("run_command", {"command": "id"})


class TestSetConfigValueBuilder:
    def _payload(self, **over):
        p = {"file": "/etc/ssh/sshd_config", "key": "PermitRootLogin",
             "value": "no"}
        p.update(over)
        return p

    def test_live_has_backup_validate_reload_restore(self):
        cmd = build_remediation_command("set_config_value", self._payload())
        # backup before any mutation
        assert ".servonaut.bak." in cmd
        # validate BEFORE reload, restore-on-fail is the safety core
        assert "sshd -t" in cmd
        assert "VALIDATE_FAILED_RESTORED" in cmd
        assert "RELOAD_FAILED_RESTORED" in cmd
        # reload tries both service names
        assert "systemctl reload ssh" in cmd and "systemctl reload sshd" in cmd
        # sshd -t must come before the reload in the command string
        assert cmd.index("sshd -t") < cmd.index("systemctl reload")
        # key/value are shlex-quoted into shell vars
        assert "KEY=PermitRootLogin" in cmd and "VAL=no" in cmd

    def test_dry_run_is_pure_preview(self):
        cmd = build_remediation_command(
            "set_config_value", self._payload(dry_run=True),
        )
        assert "DRY RUN" in cmd
        # no live mutation in dry-run
        assert "systemctl reload" not in cmd
        assert 'cp "$OUT" "$FILE"' not in cmd
        assert "sshd -T" in cmd  # reads effective value only

    def test_drop_in_conf_file_accepted(self):
        cmd = build_remediation_command("set_config_value", self._payload(
            file="/etc/ssh/sshd_config.d/50-cloud.conf"))
        assert "/etc/ssh/sshd_config.d/50-cloud.conf" in cmd

    @pytest.mark.parametrize("bad_file", [
        "/etc/passwd", "/etc/ssh/sshd_config.d/../evil", "/tmp/x",
        "/etc/ssh/sshd_config.d/no-conf-suffix", "", None, 42,
    ])
    def test_file_not_allowed_rejected(self, bad_file):
        with pytest.raises(RemediationValidationError) as exc:
            build_remediation_command(
                "set_config_value", self._payload(file=bad_file))
        assert str(exc.value).startswith("set_config_file_not_allowed:")

    @pytest.mark.parametrize("bad_key", ["Permit Root", "Key;rm", "1Key", ""])
    def test_bad_key_rejected(self, bad_key):
        with pytest.raises(RemediationValidationError) as exc:
            build_remediation_command(
                "set_config_value", self._payload(key=bad_key))
        assert str(exc.value).startswith("invalid_config_key:")

    @pytest.mark.parametrize("bad_value", [
        "no; rm -rf /", "$(reboot)", "yes no", "a`b`", "",
    ])
    def test_hostile_value_rejected(self, bad_value):
        with pytest.raises(RemediationValidationError) as exc:
            build_remediation_command(
                "set_config_value", self._payload(value=bad_value))
        assert str(exc.value).startswith("invalid_config_value:")


class TestFixPermissionsBuilder:
    def _payload(self, **over):
        p = {"path": "/etc/crontab", "mode": "644", "owner": "root:root"}
        p.update(over)
        return p

    def test_live_captures_prior_then_chmod_chown(self):
        cmd = build_remediation_command("fix_permissions", self._payload())
        # prior mode+owner captured (revert handle) BEFORE any change
        assert 'PRIOR=$(stat -c "%a|%U:%G"' in cmd
        assert cmd.index("PRIOR=") < cmd.index("chmod")
        assert "sudo -n chmod" in cmd and "sudo -n chown" in cmd
        assert "STAT_FAIL" in cmd and "CHMOD_FAIL" in cmd and "CHOWN_FAIL" in cmd
        assert "M=644" in cmd and "O=root:root" in cmd

    def test_dry_run_no_mutation(self):
        cmd = build_remediation_command(
            "fix_permissions", self._payload(dry_run=True))
        assert "DRY RUN" in cmd
        # the echo MENTIONS chmod/chown in its preview text — assert no
        # actual mutating command runs.
        assert "sudo -n chmod" not in cmd and "sudo -n chown" not in cmd

    @pytest.mark.parametrize("path", [
        "/etc/ssh/sshd_config", "/etc/ssh/ssh_host_ed25519_key",
        "/etc/sudoers", "/etc/sudoers.d/90-cloud", "/etc/cron.d/anacron",
        "/etc/passwd", "/root/.ssh/authorized_keys",
    ])
    def test_curated_paths_accepted(self, path):
        cmd = build_remediation_command(
            "fix_permissions", self._payload(path=path))
        assert path in cmd

    @pytest.mark.parametrize("bad_path", [
        "/etc/hosts", "/tmp/x", "/etc/ssh/../passwd", "/root/.ssh/../shadow",
        "/etc/cron.d/x;rm", "", None,
    ])
    def test_path_not_allowed_rejected(self, bad_path):
        with pytest.raises(RemediationValidationError) as exc:
            build_remediation_command(
                "fix_permissions", self._payload(path=bad_path))
        assert str(exc.value).startswith("fix_permissions_path_not_allowed:")

    @pytest.mark.parametrize("bad_mode", ["88", "64", "abc", "755x", "12345", ""])
    def test_bad_mode_rejected(self, bad_mode):
        with pytest.raises(RemediationValidationError) as exc:
            build_remediation_command(
                "fix_permissions", self._payload(mode=bad_mode))
        assert str(exc.value).startswith("invalid_fix_perms_mode:")

    @pytest.mark.parametrize("bad_owner", [
        "root:root:extra", "root; rm", "1root", "root ", "",
    ])
    def test_bad_owner_rejected(self, bad_owner):
        with pytest.raises(RemediationValidationError) as exc:
            build_remediation_command(
                "fix_permissions", self._payload(owner=bad_owner))
        assert str(exc.value).startswith("invalid_fix_perms_owner:")


class TestHardeningClassifyFailure:
    @pytest.mark.parametrize("output,slug", [
        ("VALIDATE_FAILED_RESTORED", "set_config_validate_failed_restored"),
        ("RELOAD_FAILED_RESTORED", "set_config_reload_failed_restored"),
        ("BACKUP_FAIL", "set_config_backup_failed"),
        ("READ_FAIL", "set_config_backup_failed"),
        ("EDIT_FAIL", "set_config_edit_failed"),
        ("TMP_FAIL", "set_config_edit_failed"),
        ("sudo: a password is required", "set_config_value_permission_denied"),
    ])
    def test_set_config_slugs(self, output, slug):
        assert classify_failure("set_config_value", 1, output) == slug

    @pytest.mark.parametrize("output,slug", [
        ("STAT_FAIL", "fix_permissions_stat_failed"),
        ("CHMOD_FAIL", "fix_permissions_chmod_failed"),
        ("CHOWN_FAIL", "fix_permissions_chown_failed"),
        ("sudo: a password is required",
         "fix_permissions_permission_denied"),
    ])
    def test_fix_permissions_slugs(self, output, slug):
        assert classify_failure("fix_permissions", 1, output) == slug


# ---------------------------------------------------------------------------
# Exit marker + failure classification
# ---------------------------------------------------------------------------


class TestExitMarker:
    def test_round_trip_success(self):
        wrapped = wrap_with_exit_marker("true")
        assert EXIT_MARKER in wrapped
        code, cleaned = parse_exit_marker(f"renewed ok\n{EXIT_MARKER}0\n")
        assert code == 0
        assert cleaned == "renewed ok"

    def test_nonzero_exit(self):
        code, _ = parse_exit_marker(f"boom\n{EXIT_MARKER}1")
        assert code == 1

    def test_missing_marker_is_transport_failure(self):
        code, cleaned = parse_exit_marker("connection reset")
        assert code is None
        assert cleaned == "connection reset"
        assert classify_failure("certbot_renew", None, cleaned) == (
            "remediation_transport_failed"
        )

    def test_nonce_qualified_marker_round_trips(self):
        nonce = "deadbeefcafe0001"
        wrapped = wrap_with_exit_marker("certbot renew", nonce)
        assert f"{EXIT_MARKER}{nonce}:" in wrapped
        code, cleaned = parse_exit_marker(
            f"renewed\n{EXIT_MARKER}{nonce}:0\n", nonce,
        )
        assert code == 0
        assert cleaned == "renewed"

    def test_static_forged_marker_ignored_when_nonce_expected(self):
        # An attacker echoing a STATIC marker (no nonce) cannot forge a
        # success once a per-dispatch nonce is in play — the parser only
        # matches the nonce-qualified prefix, so the forged line is left
        # in the output and the exit code reads as absent (fail-closed).
        nonce = "0123456789abcdef"
        forged = f"attacker output\n{EXIT_MARKER}0\n"
        code, cleaned = parse_exit_marker(forged, nonce)
        assert code is None
        assert EXIT_MARKER in cleaned  # forged line was NOT consumed

    def test_wrong_nonce_marker_not_matched(self):
        code, _ = parse_exit_marker(
            f"{EXIT_MARKER}aaaa:0", "bbbb",
        )
        assert code is None

    def test_marker_echoed_to_stderr(self):
        # The epilogue writes to stderr so the marker survives the relay
        # executor's stdout truncation (ISSUE-1).
        assert wrap_with_exit_marker("certbot renew", "n1").endswith(
            '>&2'
        )

    def test_marker_found_in_appended_stderr_block(self):
        # relay_executors appends the untruncated stderr block AFTER
        # stdout ("\nSTDERR:\n..."). A stderr-echoed marker lands there
        # and must still parse, even when stdout is long/chatty.
        nonce = "abc123"
        stdout = "\n".join(f"line {i}" for i in range(800))
        combined = f"{stdout}\nSTDERR:\ncertbot noise\n{EXIT_MARKER}{nonce}:0"
        code, _ = parse_exit_marker(combined, nonce)
        assert code == 0

    def test_internal_exit_does_not_preempt_marker(self):
        # A command that calls ``exit N`` internally (raise_container_memory /
        # set_config_value / fix_permissions signal outcomes with ``exit``)
        # must STILL emit the marker: the subshell wrap keeps the ``exit``
        # from killing the outer shell before the epilogue runs. Executed in a
        # real bash so the fix is proven at the shell level, not just asserted.
        # (Regression: the raise_container_memory live E2E reported a clean run
        # as remediation_transport_failed because ``exit 0`` pre-empted the
        # epilogue and the marker never echoed.)
        import subprocess
        nonce = "e2e0badc0de00001"
        wrapped = wrap_with_exit_marker('echo "OK did the thing"; exit 7', nonce)
        proc = subprocess.run(
            ["bash", "-c", wrapped], capture_output=True, text=True,
        )
        combined = proc.stdout + "\nSTDERR:\n" + proc.stderr
        code, cleaned = parse_exit_marker(combined, nonce)
        assert code == 7, f"marker lost after internal exit; got {combined!r}"
        assert "OK did the thing" in cleaned


class TestPreviewCommandLines:
    """The confirm modal renders command.human verbatim, with a
    structural fallback for older/other command shapes (ISSUE-6)."""

    def test_human_string_rendered_verbatim(self):
        from servonaut.screens.remediation_confirm import (
            preview_command_lines,
        )
        preview = {"command": {
            "verb": "certbot_renew",
            "human": "sudo -n certbot renew --cert-name example.com",
        }}
        assert preview_command_lines(preview) == [
            "sudo -n certbot renew --cert-name example.com",
        ]

    def test_structural_fallback_sorts_args(self):
        from servonaut.screens.remediation_confirm import (
            preview_command_lines,
        )
        preview = {"command": {
            "verb": "certbot_renew",
            "args": {"dry_run": True, "cert_name": "example.com"},
        }}
        lines = preview_command_lines(preview)
        assert lines[0] == "type: certbot_renew"
        # Args rendered in sorted key order, deterministic.
        assert lines[1].startswith("  cert_name: ")
        assert lines[2].startswith("  dry_run: ")

    def test_missing_command_is_safe(self):
        from servonaut.screens.remediation_confirm import (
            preview_command_lines,
        )
        assert preview_command_lines({}) == [
            "(no command payload in preview)",
        ]


class TestClassifyFailure:
    @pytest.mark.parametrize("output,slug", [
        ("sudo: a password is required",
         "certbot_renew_permission_denied"),
        ("No certificate found with name shop.example.com",
         "cert_name_not_found"),
        ("bash: certbot: command not found",
         "certbot_renew_not_installed"),
        ("Some challenges have failed.", "certbot_renew_failed"),
    ])
    def test_slugs(self, output, slug):
        assert classify_failure("certbot_renew", 1, output) == slug


class TestBuildResult:
    def test_shape_and_bounds(self):
        payload = {"cert_name": "example.com", "dry_run": True}
        raw = build_remediation_result(
            verb="certbot_renew", ok=False, exit_code=1,
            output="stdout-part\nSTDERR:\n" + "x" * 5000, payload=payload,
            slug="certbot_renew_failed",
        )
        result = json.loads(raw)
        assert result["verb"] == "certbot_renew"
        assert result["ok"] is False
        assert result["exit_code"] == 1
        assert result["dry_run"] is True
        assert result["cert_name"] == "example.com"
        # Contract §F.3: the server lifts these field names verbatim.
        assert result["slug"] == "certbot_renew_failed"
        assert result["stdout_tail"] == "stdout-part"
        assert len(result["stderr_tail"]) == 2000

    def test_no_slug_field_when_ok(self):
        raw = build_remediation_result(
            verb="certbot_renew", ok=True, exit_code=0,
            output="renewed", payload={"cert_name": "example.com"},
        )
        result = json.loads(raw)
        assert result["ok"] is True
        assert "slug" not in result
        assert result["stdout_tail"] == "renewed"
        assert result["stderr_tail"] == ""


# ---------------------------------------------------------------------------
# Listener routing + always-answer
# ---------------------------------------------------------------------------


def make_listener(*, executors="default"):
    if executors == "default":
        executors = MagicMock()
        executors.execute = AsyncMock()
    listener = RelayListener(
        executors=executors,
        base_url="https://app.example.com",
        mercure_url="https://hub.example.com/.well-known/mercure",
        auth_token="tok-abc",
        user_id="user-123",
        heartbeat_interval=30,
    )
    listener._post_result = AsyncMock()
    return listener


def remediation_event(
    *, req_id="rmd-1", verb="certbot_renew", target="web-1", payload=None,
):
    return json.dumps({
        "id": req_id,
        "user_id": "user-123",
        "type": verb,
        "target_server_id": target,
        "payload": payload if payload is not None else {
            "finding_id": "fnd-1", "action": "renew_certificate",
            "cert_name": "example.com",
        },
        "ttl_seconds": 300,
        "source": REMEDIATION_SOURCE,
    })


def posted_response(listener) -> CommandResponse:
    listener._post_result.assert_awaited_once()
    return listener._post_result.await_args.args[0]


class TestRemediationRouting:
    def test_success_path_posts_result_json(self):
        listener = make_listener()

        # The listener chooses a fresh nonce per dispatch and echoes it
        # in the wrapped command — reflect it back so the success line
        # matches what the parser expects.
        def _echo_marker(request):
            command = request.payload["command"]
            # Extract the nonce-qualified prefix the epilogue will print.
            marker = command.split('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(
                request_id=request.id, status="success",
                output=f"Congratulations, renewed\n{marker}0\n",
            )

        listener._executors.execute = AsyncMock(side_effect=_echo_marker)
        run(listener._handle_event(remediation_event()))

        # The executor received a locally-built command, not server text.
        request = listener._executors.execute.await_args.args[0]
        assert request.type == CommandType.RUN_COMMAND
        # Subshell-wrapped so an internal ``exit`` can't pre-empt the epilogue.
        assert request.payload["command"].startswith(
            "(sudo -n certbot renew --cert-name example.com",
        )
        assert EXIT_MARKER in request.payload["command"]

        response = posted_response(listener)
        assert response.request_id == "rmd-1"
        assert response.status == "success"
        result = json.loads(response.output)
        assert result["ok"] is True
        assert result["exit_code"] == 0
        assert result["cert_name"] == "example.com"

    def test_static_forged_success_line_does_not_settle_resolved(self):
        # Target-side output echoing a STATIC marker (no nonce) must NOT
        # be read as success — the listener expects its per-dispatch
        # nonce, so the forged line is ignored and the run fails closed.
        listener = make_listener()
        listener._executors.execute = AsyncMock(return_value=CommandResponse(
            request_id="rmd-1", status="success",
            output=f"malicious hook says\n{EXIT_MARKER}0\n",
        ))
        run(listener._handle_event(remediation_event()))
        response = posted_response(listener)
        # SSH round-trip completed, so status="success"; the forged
        # static marker isn't nonce-qualified, so the exit code is
        # unreadable → ok:false, fail-closed. The server reads ok:false
        # from the payload and does NOT settle the finding resolved.
        assert response.status == "success"
        result = json.loads(response.output)
        assert result["ok"] is False
        assert result["slug"] == "remediation_transport_failed"

    def test_nonzero_exit_answers_with_slug(self):
        listener = make_listener()

        def _echo_marker(request):
            command = request.payload["command"]
            marker = command.split('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(
                request_id=request.id, status="success",
                output=f"Some challenges have failed.\n{marker}1\n",
            )

        listener._executors.execute = AsyncMock(side_effect=_echo_marker)
        run(listener._handle_event(remediation_event()))
        response = posted_response(listener)
        # Contract §F.3: a command that RAN and exited non-zero is a
        # SUCCESSFUL relay round-trip — status="success" with the command
        # outcome (ok:false, slug, exit_code) in the JSON payload, which
        # the server lifts out to return 200 {ok:false, slug}.
        assert response.status == "success"
        result = json.loads(response.output)
        assert result["ok"] is False
        assert result["exit_code"] == 1
        assert result["slug"] == "certbot_renew_failed"

    def test_unknown_verb_rejected_without_execution(self):
        listener = make_listener()
        run(listener._handle_event(remediation_event(verb="wipe_disk")))
        listener._executors.execute.assert_not_awaited()
        response = posted_response(listener)
        assert response.status == "error"
        assert response.error_message.startswith("unknown_remediation_verb:")

    def test_invalid_cert_name_rejected_without_execution(self):
        listener = make_listener()
        run(listener._handle_event(remediation_event(
            payload={"cert_name": "a.com; reboot"},
        )))
        listener._executors.execute.assert_not_awaited()
        response = posted_response(listener)
        assert response.error_message.startswith("invalid_cert_name:")

    def test_no_executors_still_answers(self):
        listener = make_listener(executors=None)
        run(listener._handle_event(remediation_event()))
        response = posted_response(listener)
        assert response.status == "error"
        assert response.error_message.startswith(
            "remediation_executor_unavailable:",
        )

    def test_executor_timeout_answers_with_slug(self):
        listener = make_listener()
        listener._executors.execute = AsyncMock(return_value=CommandResponse(
            request_id="rmd-1", status="timeout",
            error_message="Command timed out after 300s",
        ))
        run(listener._handle_event(remediation_event()))
        response = posted_response(listener)
        # A timeout is a command outcome, not a transport failure — the
        # command ran, it just exceeded budget. Report it as a success
        # round-trip carrying ok:false + a clean timeout slug so the
        # finding gets meaningful evidence, not an opaque relay error.
        assert response.status == "success"
        result = json.loads(response.output)
        assert result["ok"] is False
        assert result["slug"] == "remediation_timeout"

    def test_mismatched_user_id_rejected(self):
        listener = make_listener()
        event = json.loads(remediation_event())
        event["user_id"] = "someone-else"
        run(listener._handle_event(json.dumps(event)))
        listener._executors.execute.assert_not_awaited()
        listener._post_result.assert_not_awaited()

    def test_probe_source_does_not_reach_remediation_path(self):
        # A probe envelope must keep routing to the probe path (which,
        # with no bridge wired, answers probe_executor_unavailable —
        # NOT a remediation slug).
        listener = make_listener()
        event = json.loads(remediation_event())
        event["source"] = "proactive"
        run(listener._handle_event(json.dumps(event)))
        response = posted_response(listener)
        assert response.error_message.startswith(
            "probe_executor_unavailable:",
        )


# ---------------------------------------------------------------------------
# block_ip — payload validation (client-side mirror of the server rails)
# ---------------------------------------------------------------------------


from servonaut.services.remediation_executor import (  # noqa: E402
    BLOCK_IP_METHODS,
    LOCAL_DISPATCH_VERBS,
    SSH_COMMAND_VERBS,
    validate_block_ip_payload,
)


class TestVerbSets:
    def test_block_ip_is_an_allowlisted_local_dispatch_verb(self):
        assert "block_ip" in REMEDIATION_VERBS
        assert "block_ip" in LOCAL_DISPATCH_VERBS
        assert "block_ip" not in SSH_COMMAND_VERBS

    def test_dispatch_sets_partition_the_allowlist(self):
        from servonaut.services.remediation_executor import WAF_DISPATCH_VERBS
        assert (
            SSH_COMMAND_VERBS | LOCAL_DISPATCH_VERBS | WAF_DISPATCH_VERBS
            == REMEDIATION_VERBS
        )
        assert not SSH_COMMAND_VERBS & LOCAL_DISPATCH_VERBS
        assert not SSH_COMMAND_VERBS & WAF_DISPATCH_VERBS
        assert not LOCAL_DISPATCH_VERBS & WAF_DISPATCH_VERBS

    def test_block_ip_never_becomes_a_command_line(self):
        with pytest.raises(RemediationValidationError) as exc:
            build_remediation_command("block_ip", {"ip": "9.9.9.9"})
        assert str(exc.value).startswith("local_dispatch_verb:")


class TestValidateBlockIpPayload:
    def test_valid_public_ipv4(self):
        ip, method = validate_block_ip_payload(
            {"ip": "9.9.9.9", "method": "waf"},
        )
        assert ip == "9.9.9.9"
        assert method == "waf"

    def test_valid_public_ipv6(self):
        ip, method = validate_block_ip_payload(
            {"ip": "2606:4700:4700::1111", "method": "nacl"},
        )
        assert ip == "2606:4700:4700::1111"
        assert method == "nacl"

    @pytest.mark.parametrize("payload", [
        {},
        {"ip": None},
        {"ip": 42},
        {"ip": "   "},
    ])
    def test_missing_or_nonstring_ip_rejected(self, payload):
        payload.setdefault("method", "waf")
        with pytest.raises(RemediationValidationError) as exc:
            validate_block_ip_payload(payload)
        assert str(exc.value).startswith("invalid_block_ip_address:")

    def test_cidr_rejected(self):
        with pytest.raises(RemediationValidationError) as exc:
            validate_block_ip_payload({"ip": "9.9.9.0/24", "method": "waf"})
        assert str(exc.value).startswith("invalid_block_ip_address:")

    @pytest.mark.parametrize("garbage", ["not-an-ip", "999.999.1.1", "9.9.9.9 extra"])
    def test_garbage_rejected(self, garbage):
        with pytest.raises(RemediationValidationError) as exc:
            validate_block_ip_payload({"ip": garbage, "method": "waf"})
        assert str(exc.value).startswith("invalid_block_ip_address:")

    @pytest.mark.parametrize("bad_ip", [
        "10.0.0.5",          # private
        "192.168.1.1",       # private
        "172.16.0.1",        # private
        "127.0.0.1",         # loopback
        "169.254.1.1",       # link-local
        "224.0.0.1",         # multicast
        "240.0.0.1",         # reserved
        "0.0.0.0",           # unspecified
        "100.64.0.1",        # shared address space (CGN)
        "::1",               # v6 loopback
        "fe80::1",           # v6 link-local
        "fd00::1",           # v6 ULA
    ])
    def test_non_global_addresses_refused(self, bad_ip):
        with pytest.raises(RemediationValidationError) as exc:
            validate_block_ip_payload({"ip": bad_ip, "method": "waf"})
        assert str(exc.value).startswith("block_ip_address_not_public:")

    def test_instance_own_ip_refused(self):
        with pytest.raises(RemediationValidationError) as exc:
            validate_block_ip_payload(
                {"ip": "9.9.9.9", "method": "waf"},
                refused_ips=frozenset({"9.9.9.9"}),
            )
        assert str(exc.value).startswith("block_ip_self_ban_refused:")

    @pytest.mark.parametrize("bad_method", [
        None, "", "iptables", "WAF", 42, "pf",
    ])
    def test_unknown_method_rejected(self, bad_method):
        with pytest.raises(RemediationValidationError) as exc:
            validate_block_ip_payload(
                {"ip": "9.9.9.9", "method": bad_method},
            )
        assert str(exc.value).startswith("invalid_block_ip_method:")

    def test_aws_method_enum_matches_ip_ban_strategies(self):
        from servonaut.services.ip_ban_service import IPBanService
        from servonaut.services.remediation_executor import AWS_BLOCK_METHODS
        assert AWS_BLOCK_METHODS == frozenset(IPBanService.STRATEGIES)


class TestBuildResultExtras:
    def test_extras_are_additive(self):
        raw = build_remediation_result(
            verb="block_ip", ok=True, exit_code=0, output="banned",
            payload={"dry_run": False},
            extra={"strategy": "waf", "rule_id": "9.9.9.9/32",
                   "ip": "9.9.9.9"},
        )
        result = json.loads(raw)
        assert result["strategy"] == "waf"
        assert result["rule_id"] == "9.9.9.9/32"
        assert result["ip"] == "9.9.9.9"
        assert result["ok"] is True

    def test_extras_cannot_override_core_contract_keys(self):
        raw = build_remediation_result(
            verb="block_ip", ok=False, exit_code=1, output="",
            payload={}, slug="block_ip_failed",
            extra={"ok": True, "exit_code": 0, "slug": "spoofed"},
        )
        result = json.loads(raw)
        assert result["ok"] is False
        assert result["exit_code"] == 1
        assert result["slug"] == "block_ip_failed"


# ---------------------------------------------------------------------------
# block_ip — listener routing (local dispatch, never SSH)
# ---------------------------------------------------------------------------


def _ip_ban_config(name="ban-waf", method="waf", region=""):
    from servonaut.config.schema import IPBanConfig
    return IPBanConfig(name=name, method=method, region=region)


def make_block_ip_listener(
    *,
    configs=None,
    ban_result=None,
    instance=None,
):
    listener = make_listener()
    executors = listener._executors
    executors.find_instance = AsyncMock(return_value=instance)
    ip_ban = MagicMock()
    ip_ban.get_configs = MagicMock(
        return_value=configs if configs is not None else [_ip_ban_config()],
    )
    ip_ban.ban_ip = AsyncMock(
        return_value=ban_result if ban_result is not None else {
            "success": True,
            "message": "Banned 9.9.9.9 via WAF IP set",
            "rule_id": "9.9.9.9/32",
        },
    )
    # The lazy property on the real RelayExecutors is replaced wholesale
    # here because the executors object is a MagicMock.
    executors.ip_ban_service = ip_ban
    return listener, ip_ban


def block_ip_event(*, payload=None, target="web-1"):
    return remediation_event(
        req_id="rmd-ban-1", verb="block_ip", target=target,
        payload=payload if payload is not None else {
            "finding_id": "fnd-2", "action": "block_ip",
            "ip": "9.9.9.9", "method": "waf", "dry_run": False,
        },
    )


class TestBlockIpRouting:
    def test_success_path_dispatches_locally_never_ssh(self):
        listener, ip_ban = make_block_ip_listener()
        run(listener._handle_event(block_ip_event()))

        # Local dispatch only — the SSH command executor is never used.
        listener._executors.execute.assert_not_awaited()
        ip_ban.ban_ip.assert_awaited_once_with("9.9.9.9", "ban-waf")

        response = posted_response(listener)
        assert response.status == "success"
        result = json.loads(response.output)
        assert result["ok"] is True
        assert result["exit_code"] == 0
        assert result["strategy"] == "waf"
        assert result["rule_id"] == "9.9.9.9/32"
        assert result["ip"] == "9.9.9.9"

    def test_dry_run_makes_no_mutation(self):
        listener, ip_ban = make_block_ip_listener()
        run(listener._handle_event(block_ip_event(payload={
            "finding_id": "fnd-2", "action": "block_ip",
            "ip": "9.9.9.9", "method": "waf", "dry_run": True,
        })))
        ip_ban.ban_ip.assert_not_awaited()
        response = posted_response(listener)
        assert response.status == "success"
        result = json.loads(response.output)
        assert result["ok"] is True
        assert result["dry_run"] is True
        assert result["would_ban"] is True
        assert result["rule_id"] is None

    def test_instance_own_ip_is_refused(self):
        listener, ip_ban = make_block_ip_listener(
            instance={"id": "i-1", "name": "web-1",
                      "public_ip": "9.9.9.9", "private_ip": "10.0.0.5",
                      "region": "eu-west-1"},
        )
        run(listener._handle_event(block_ip_event()))
        ip_ban.ban_ip.assert_not_awaited()
        response = posted_response(listener)
        assert response.status == "error"
        assert response.error_message.startswith(
            "block_ip_self_ban_refused:",
        )

    def test_private_ip_is_refused(self):
        listener, ip_ban = make_block_ip_listener()
        run(listener._handle_event(block_ip_event(payload={
            "finding_id": "fnd-2", "action": "block_ip",
            "ip": "192.168.1.50", "method": "waf",
        })))
        ip_ban.ban_ip.assert_not_awaited()
        response = posted_response(listener)
        assert response.status == "error"
        assert response.error_message.startswith(
            "block_ip_address_not_public:",
        )

    def test_missing_config_for_method_is_cant_process(self):
        listener, ip_ban = make_block_ip_listener(configs=[])
        run(listener._handle_event(block_ip_event()))
        ip_ban.ban_ip.assert_not_awaited()
        response = posted_response(listener)
        assert response.status == "error"
        assert response.error_message.startswith("block_ip_config_missing:")

    def test_region_match_preferred_over_first_config(self):
        listener, ip_ban = make_block_ip_listener(configs=[
            _ip_ban_config(name="ban-us", method="waf", region="us-east-1"),
            _ip_ban_config(name="ban-eu", method="waf", region="eu-west-1"),
        ])
        run(listener._handle_event(block_ip_event(payload={
            "finding_id": "fnd-2", "action": "block_ip",
            "ip": "9.9.9.9", "method": "waf", "region": "eu-west-1",
        })))
        ip_ban.ban_ip.assert_awaited_once_with("9.9.9.9", "ban-eu")

    def test_ran_but_failed_ban_reports_slug_in_payload(self):
        listener, ip_ban = make_block_ip_listener(ban_result={
            "success": False, "message": "AccessDenied: not authorized",
        })
        run(listener._handle_event(block_ip_event()))
        response = posted_response(listener)
        # Transport fine, outcome in the payload (contract F.3).
        assert response.status == "success"
        result = json.loads(response.output)
        assert result["ok"] is False
        assert result["exit_code"] == 1
        assert result["slug"] == "block_ip_failed"
        assert "AccessDenied" in result["stdout_tail"]

    def test_already_banned_is_idempotent_success(self):
        listener, ip_ban = make_block_ip_listener(ban_result={
            "success": False,
            "message": "9.9.9.9 already banned in WAF",
        })
        run(listener._handle_event(block_ip_event()))
        response = posted_response(listener)
        assert response.status == "success"
        result = json.loads(response.output)
        assert result["ok"] is True
        assert result["already_banned"] is True

    def test_ban_exception_still_answers(self):
        listener, ip_ban = make_block_ip_listener()
        ip_ban.ban_ip = AsyncMock(side_effect=RuntimeError("boom"))
        run(listener._handle_event(block_ip_event()))
        response = posted_response(listener)
        assert response.status == "success"
        result = json.loads(response.output)
        assert result["ok"] is False
        assert result["slug"] == "block_ip_failed"

    def test_failed_instance_lookup_does_not_block_execution(self):
        # The self-ban mirror is best-effort; the server enforces the
        # same rail authoritatively.
        listener, ip_ban = make_block_ip_listener()
        listener._executors.find_instance = AsyncMock(
            side_effect=RuntimeError("cache unavailable"),
        )
        run(listener._handle_event(block_ip_event()))
        ip_ban.ban_ip.assert_awaited_once()
        response = posted_response(listener)
        assert response.status == "success"


# ---------------------------------------------------------------------------
# On-box block_ip methods (nftables / ufw / firewalld)
# ---------------------------------------------------------------------------


from servonaut.services.remediation_executor import (  # noqa: E402
    AWS_BLOCK_METHODS,
    ONBOX_BLOCK_METHODS,
    build_onbox_block_command,
)


class TestOnboxBlockCommand:
    def test_method_sets_partition(self):
        assert AWS_BLOCK_METHODS | ONBOX_BLOCK_METHODS == BLOCK_IP_METHODS
        assert not AWS_BLOCK_METHODS & ONBOX_BLOCK_METHODS
        assert ONBOX_BLOCK_METHODS == {"nftables", "ufw", "firewalld"}

    def test_onbox_methods_pass_validation(self):
        for m in ONBOX_BLOCK_METHODS:
            ip, method = validate_block_ip_payload({"ip": "9.9.9.9", "method": m})
            assert (ip, method) == ("9.9.9.9", m)

    def test_aws_method_rejected_by_onbox_builder(self):
        with pytest.raises(RemediationValidationError) as exc:
            build_onbox_block_command("waf", "9.9.9.9")
        assert str(exc.value).startswith("invalid_block_ip_method:")

    @pytest.mark.parametrize("method", ["nftables", "ufw", "firewalld"])
    def test_command_bans_and_verifies_the_ip(self, method):
        cmd = build_onbox_block_command(method, "9.9.9.9")
        # Every method runs under non-interactive sudo and ends by
        # VERIFYING the ip is in the active ruleset (idempotent success).
        assert "sudo -n" in cmd
        assert cmd.rstrip().endswith("grep -qF '9.9.9.9'")
        assert "9.9.9.9" in cmd

    def test_nftables_bootstrap_is_guarded_against_duplicate_rule(self):
        cmd = build_onbox_block_command("nftables", "9.9.9.9")
        # The table/set/chain/rule bootstrap only runs when the table is
        # absent — a repeat ban never appends a duplicate drop rule.
        assert "if ! sudo -n nft list table inet servonaut_ban" in cmd
        assert "add element inet servonaut_ban banned4 '{ 9.9.9.9 }'" in cmd

    def test_ipv6_uses_v6_set_and_family(self):
        cmd = build_onbox_block_command("nftables", "2606:4700:4700::1111")
        assert "banned6" in cmd
        assert "ip6 saddr" in cmd
        assert "ipv6_addr" in cmd

    def test_firewalld_writes_runtime_and_permanent(self):
        cmd = build_onbox_block_command("firewalld", "9.9.9.9")
        assert cmd.count("--add-rich-rule") == 2
        assert "--permanent" in cmd
        assert 'family="ipv4"' in cmd

    def test_validated_ip_has_no_shell_metacharacters(self):
        # Defense-in-depth: validate_block_ip_payload only ever yields a
        # canonical inet address, so nothing a shell could interpret can
        # reach the builder. A hostile method payload is refused upstream.
        for bad in ["9.9.9.9; rm x", "9.9.9.9$(id)", "9.9.9.9 && x"]:
            with pytest.raises(RemediationValidationError):
                validate_block_ip_payload({"ip": bad, "method": "ufw"})


def onbox_block_event(*, method="nftables", payload=None, target="custom-web-1"):
    return remediation_event(
        req_id="rmd-onbox-1", verb="block_ip", target=target,
        payload=payload if payload is not None else {
            "finding_id": "fnd-3", "action": "block_ip",
            "ip": "9.9.9.9", "method": method, "dry_run": False,
        },
    )


def _onbox_listener(*, instance=None):
    listener = make_listener()
    listener._executors.find_instance = AsyncMock(return_value=instance)
    # An on-box ban must NOT touch IPBanService.
    ip_ban = MagicMock()
    ip_ban.ban_ip = AsyncMock()
    ip_ban.get_configs = MagicMock(return_value=[])
    listener._executors.ip_ban_service = ip_ban
    return listener, ip_ban


class TestOnboxBlockRouting:
    def test_success_runs_firewall_cmd_over_ssh_not_ipbanservice(self):
        listener, ip_ban = _onbox_listener()

        def _echo_marker(request):
            command = request.payload["command"]
            marker = command.split('echo "', 1)[1].split("$rc", 1)[0]
            # VERIFY grep succeeds → exit 0 (ip is banned).
            return CommandResponse(
                request_id=request.id, status="success",
                output=f"{marker}0\n",
            )

        listener._executors.execute = AsyncMock(side_effect=_echo_marker)
        run(listener._handle_event(onbox_block_event(method="nftables")))

        ip_ban.ban_ip.assert_not_awaited()
        request = listener._executors.execute.await_args.args[0]
        assert request.type == CommandType.RUN_COMMAND
        assert "nft add element" in request.payload["command"]

        response = posted_response(listener)
        assert response.status == "success"
        result = json.loads(response.output)
        assert result["ok"] is True
        assert result["strategy"] == "nftables"
        # The ip is its own stable unban handle.
        assert result["rule_id"] == "9.9.9.9"
        assert result["ip"] == "9.9.9.9"

    def test_dry_run_makes_no_ssh_call(self):
        listener, _ip_ban = _onbox_listener()
        listener._executors.execute = AsyncMock()
        run(listener._handle_event(onbox_block_event(payload={
            "finding_id": "fnd-3", "action": "block_ip",
            "ip": "9.9.9.9", "method": "ufw", "dry_run": True,
        })))
        listener._executors.execute.assert_not_awaited()
        result = json.loads(posted_response(listener).output)
        assert result["ok"] is True
        assert result["dry_run"] is True
        assert result["would_ban"] is True
        assert result["rule_id"] is None

    def test_verify_failure_reports_slug(self):
        listener, _ip_ban = _onbox_listener()

        def _echo_fail(request):
            command = request.payload["command"]
            marker = command.split('echo "', 1)[1].split("$rc", 1)[0]
            # VERIFY grep fails → exit 1 (ban did not take).
            return CommandResponse(
                request_id=request.id, status="success",
                output=f"{marker}1\n",
            )

        listener._executors.execute = AsyncMock(side_effect=_echo_fail)
        run(listener._handle_event(onbox_block_event(method="ufw")))
        result = json.loads(posted_response(listener).output)
        assert result["ok"] is False
        assert result["slug"] == "block_ip_failed"

    def test_sudo_denied_classified_as_permission(self):
        listener, _ip_ban = _onbox_listener()

        def _echo_denied(request):
            command = request.payload["command"]
            marker = command.split('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(
                request_id=request.id, status="success",
                output=f"sudo: a password is required\n{marker}1\n",
            )

        listener._executors.execute = AsyncMock(side_effect=_echo_denied)
        run(listener._handle_event(onbox_block_event()))
        result = json.loads(posted_response(listener).output)
        assert result["ok"] is False
        assert result["slug"] == "block_ip_permission_denied"

    def test_timeout_is_a_command_outcome(self):
        listener, _ip_ban = _onbox_listener()
        listener._executors.execute = AsyncMock(return_value=CommandResponse(
            request_id="rmd-onbox-1", status="timeout", output="",
        ))
        run(listener._handle_event(onbox_block_event()))
        response = posted_response(listener)
        assert response.status == "success"
        result = json.loads(response.output)
        assert result["slug"] == "remediation_timeout"

    def test_transport_failure_is_error_status(self):
        listener, _ip_ban = _onbox_listener()
        listener._executors.execute = AsyncMock(return_value=CommandResponse(
            request_id="rmd-onbox-1", status="error", output="",
            error_message="ssh channel closed",
        ))
        run(listener._handle_event(onbox_block_event()))
        response = posted_response(listener)
        assert response.status == "error"
        assert response.error_message.startswith("remediation_execution_failed:")

    def test_missing_target_refuses(self):
        listener, _ip_ban = _onbox_listener()
        listener._executors.execute = AsyncMock()
        run(listener._handle_event(onbox_block_event(target="")))
        listener._executors.execute.assert_not_awaited()
        response = posted_response(listener)
        assert response.status == "error"
        assert response.error_message.startswith("block_ip_target_missing:")


# ---------------------------------------------------------------------------
# unblock_ip — the inverse verb (Phase 2 one-click Undo executor)
# ---------------------------------------------------------------------------

from servonaut.services.remediation_executor import (  # noqa: E402
    AWS_BLOCK_METHODS,
    BLOCK_IP_METHODS,
    ONBOX_BLOCK_METHODS,
    build_onbox_unblock_command,
    validate_unblock_ip_payload,
)


class TestUnblockIpVerbSet:
    def test_unblock_ip_is_a_local_dispatch_verb(self):
        from servonaut.services.remediation_executor import (
            LOCAL_DISPATCH_VERBS, SSH_COMMAND_VERBS,
        )
        assert "unblock_ip" in REMEDIATION_VERBS
        assert "unblock_ip" in LOCAL_DISPATCH_VERBS
        assert "unblock_ip" not in SSH_COMMAND_VERBS

    def test_unblock_ip_never_becomes_a_command_line(self):
        with pytest.raises(RemediationValidationError) as exc:
            build_remediation_command("unblock_ip", {"ip": "9.9.9.9"})
        assert str(exc.value).startswith("local_dispatch_verb:")


class TestValidateUnblockIpPayload:
    def test_valid_payload_returns_canonical_ip_and_method(self):
        for method in BLOCK_IP_METHODS:
            ip, m = validate_unblock_ip_payload({"ip": "9.9.9.9", "method": method})
            assert (ip, m) == ("9.9.9.9", method)

    def test_ip_is_canonicalised(self):
        ip, _ = validate_unblock_ip_payload(
            {"ip": "2606:4700:4700::0001", "method": "waf"},
        )
        assert ip == "2606:4700:4700::1"

    def test_missing_ip_rejected(self):
        with pytest.raises(RemediationValidationError) as exc:
            validate_unblock_ip_payload({"method": "waf"})
        assert str(exc.value).startswith("invalid_unblock_ip_address:")

    def test_cidr_rejected(self):
        # Any '/' is rejected before the address is parsed (no CIDR in v1),
        # so a neutral host literal with a prefix exercises the same guard.
        with pytest.raises(RemediationValidationError) as exc:
            validate_unblock_ip_payload({"ip": "9.9.9.9/24", "method": "waf"})
        assert str(exc.value).startswith("invalid_unblock_ip_address:")

    @pytest.mark.parametrize("ip", ["192.168.1.5", "127.0.0.1", "10.0.0.1"])
    def test_private_ip_rejected(self, ip):
        with pytest.raises(RemediationValidationError) as exc:
            validate_unblock_ip_payload({"ip": ip, "method": "waf"})
        assert str(exc.value).startswith("unblock_ip_address_not_public:")

    @pytest.mark.parametrize("bad_method", ["", "iptables", "block", None])
    def test_unknown_method_rejected(self, bad_method):
        with pytest.raises(RemediationValidationError) as exc:
            validate_unblock_ip_payload({"ip": "9.9.9.9", "method": bad_method})
        assert str(exc.value).startswith("invalid_unblock_ip_method:")

    def test_no_self_ban_refusal_on_unban(self):
        # Unlike the ban validator, unban takes no refused_ips set — the
        # signature has exactly one argument. Unbanning is never a lock-out.
        import inspect
        params = inspect.signature(validate_unblock_ip_payload).parameters
        assert list(params) == ["payload"]


class TestOnboxUnblockCommand:
    def test_method_partition_matches_block(self):
        assert AWS_BLOCK_METHODS | ONBOX_BLOCK_METHODS == BLOCK_IP_METHODS
        assert ONBOX_BLOCK_METHODS == {"nftables", "ufw", "firewalld"}

    def test_aws_method_rejected_by_onbox_builder(self):
        with pytest.raises(RemediationValidationError) as exc:
            build_onbox_unblock_command("waf", "9.9.9.9")
        assert str(exc.value).startswith("invalid_unblock_ip_method:")

    @pytest.mark.parametrize("method", ["nftables", "ufw", "firewalld"])
    def test_command_removes_then_verifies_absence(self, method):
        cmd = build_onbox_unblock_command(method, "9.9.9.9")
        assert "sudo -n" in cmd
        # Ends with a NEGATED verify: exit 0 iff the ip is no longer present.
        assert cmd.rstrip().endswith("grep -qF '9.9.9.9'")
        assert "! sudo -n" in cmd
        assert "9.9.9.9" in cmd

    @pytest.mark.parametrize("method", ["nftables", "ufw", "firewalld"])
    def test_rule_removal_is_error_tolerant(self, method):
        # Removing a rule that was never there must not fail the command —
        # only the VERIFY step judges success — so removals swallow errors.
        cmd = build_onbox_unblock_command(method, "9.9.9.9")
        assert "2>/dev/null" in cmd

    def test_ipv6_uses_v6_set(self):
        cmd = build_onbox_unblock_command("nftables", "2606:4700:4700::1111")
        assert "banned6" in cmd

    def test_firewalld_removes_runtime_and_permanent(self):
        cmd = build_onbox_unblock_command("firewalld", "9.9.9.9")
        assert cmd.count("--remove-rich-rule") == 2
        assert "--permanent" in cmd

    def test_validated_ip_has_no_shell_metacharacters(self):
        for bad in ["9.9.9.9; rm x", "9.9.9.9$(id)", "9.9.9.9 && x"]:
            with pytest.raises(RemediationValidationError):
                validate_unblock_ip_payload({"ip": bad, "method": "ufw"})


# --- AWS unblock routing (IPBanService, never SSH) -------------------------


def make_unblock_ip_listener(*, configs=None, unban_result=None, instance=None):
    listener = make_listener()
    executors = listener._executors
    executors.find_instance = AsyncMock(return_value=instance)
    ip_ban = MagicMock()
    ip_ban.get_configs = MagicMock(
        return_value=configs if configs is not None else [_ip_ban_config()],
    )
    ip_ban.unban_ip = AsyncMock(
        return_value=unban_result if unban_result is not None else {
            "success": True,
            "message": "Unbanned 9.9.9.9 from WAF IP set",
        },
    )
    executors.ip_ban_service = ip_ban
    return listener, ip_ban


def unblock_ip_event(*, payload=None, target="web-1"):
    return remediation_event(
        req_id="rmd-unban-1", verb="unblock_ip", target=target,
        payload=payload if payload is not None else {
            "finding_id": "fnd-2", "action": "unblock_ip",
            "ip": "9.9.9.9", "method": "waf", "applied_strategy": "waf",
            "rule_id": "9.9.9.9/32", "dry_run": False,
        },
    )


class TestUnblockIpRouting:
    def test_success_dispatches_to_ipbanservice_never_ssh(self):
        listener, ip_ban = make_unblock_ip_listener()
        run(listener._handle_event(unblock_ip_event()))
        listener._executors.execute.assert_not_awaited()
        ip_ban.unban_ip.assert_awaited_once_with("9.9.9.9", "ban-waf")
        response = posted_response(listener)
        assert response.status == "success"
        result = json.loads(response.output)
        assert result["verb"] == "unblock_ip"
        assert result["ok"] is True
        assert result["strategy"] == "waf"
        assert result["ip"] == "9.9.9.9"

    def test_ipbanservice_reresolves_from_ip_not_wire_rule_id(self):
        # The wire rule_id is informational — unban_ip receives (ip, config),
        # never the payload rule_id, so an out-of-band-mutated id can't make
        # us delete the wrong rule.
        listener, ip_ban = make_unblock_ip_listener()
        run(listener._handle_event(unblock_ip_event(payload={
            "finding_id": "fnd-2", "action": "unblock_ip",
            "ip": "9.9.9.9", "method": "waf",
            "rule_id": "stale-rule-id-from-a-mutated-sg",
        })))
        # Only (ip, config_name) — the stale rule_id is never passed through.
        ip_ban.unban_ip.assert_awaited_once_with("9.9.9.9", "ban-waf")

    def test_dry_run_makes_no_mutation(self):
        listener, ip_ban = make_unblock_ip_listener()
        run(listener._handle_event(unblock_ip_event(payload={
            "finding_id": "fnd-2", "action": "unblock_ip",
            "ip": "9.9.9.9", "method": "waf", "dry_run": True,
        })))
        ip_ban.unban_ip.assert_not_awaited()
        result = json.loads(posted_response(listener).output)
        assert result["ok"] is True
        assert result["dry_run"] is True
        assert result["would_unban"] is True

    @pytest.mark.parametrize("message", [
        "9.9.9.9 not found in WAF ban list",
        "9.9.9.9 not found in NACL ban list",
        "Failed to unban 9.9.9.9: The specified rule does not exist in this security group",
    ])
    def test_already_unbanned_is_idempotent_success(self, message):
        listener, ip_ban = make_unblock_ip_listener(
            unban_result={"success": False, "message": message},
        )
        run(listener._handle_event(unblock_ip_event()))
        response = posted_response(listener)
        # Goal state (ip not banned) already holds → success, not error.
        assert response.status == "success"
        result = json.loads(response.output)
        assert result["ok"] is True
        assert result["already_unbanned"] is True

    def test_missing_config_for_method_is_cant_process(self):
        listener, ip_ban = make_unblock_ip_listener(configs=[])
        run(listener._handle_event(unblock_ip_event()))
        ip_ban.unban_ip.assert_not_awaited()
        response = posted_response(listener)
        assert response.status == "error"
        assert response.error_message.startswith("unblock_ip_config_missing:")

    def test_region_match_preferred_over_first_config(self):
        listener, ip_ban = make_unblock_ip_listener(configs=[
            _ip_ban_config(name="ban-us", method="waf", region="us-east-1"),
            _ip_ban_config(name="ban-eu", method="waf", region="eu-west-1"),
        ])
        run(listener._handle_event(unblock_ip_event(payload={
            "finding_id": "fnd-2", "action": "unblock_ip",
            "ip": "9.9.9.9", "method": "waf", "region": "eu-west-1",
        })))
        ip_ban.unban_ip.assert_awaited_once_with("9.9.9.9", "ban-eu")

    def test_ran_but_failed_unban_reports_slug_in_payload(self):
        listener, ip_ban = make_unblock_ip_listener(
            unban_result={"success": False, "message": "AccessDenied: not authorized"},
        )
        run(listener._handle_event(unblock_ip_event()))
        response = posted_response(listener)
        assert response.status == "success"  # transport fine
        result = json.loads(response.output)
        assert result["ok"] is False
        assert result["slug"] == "unblock_ip_failed"

    def test_validation_refusal_is_cant_process(self):
        listener, ip_ban = make_unblock_ip_listener()
        run(listener._handle_event(unblock_ip_event(payload={
            "finding_id": "fnd-2", "action": "unblock_ip",
            "ip": "192.168.1.9", "method": "waf",
        })))
        ip_ban.unban_ip.assert_not_awaited()
        response = posted_response(listener)
        assert response.status == "error"
        assert response.error_message.startswith("unblock_ip_address_not_public:")


# --- on-box unblock routing (SSH firewall command) -------------------------


def _onbox_unblock_listener(*, instance=None):
    listener = make_listener()
    listener._executors.find_instance = AsyncMock(return_value=instance)
    ip_ban = MagicMock()
    ip_ban.unban_ip = AsyncMock()
    ip_ban.get_configs = MagicMock(return_value=[])
    listener._executors.ip_ban_service = ip_ban
    return listener, ip_ban


def onbox_unblock_event(*, method="nftables", payload=None, target="custom-web-1"):
    return remediation_event(
        req_id="rmd-onbox-unban-1", verb="unblock_ip", target=target,
        payload=payload if payload is not None else {
            "finding_id": "fnd-3", "action": "unblock_ip",
            "ip": "9.9.9.9", "method": method, "dry_run": False,
        },
    )


class TestOnboxUnblockRouting:
    def test_success_runs_firewall_over_ssh_not_ipbanservice(self):
        listener, ip_ban = _onbox_unblock_listener()

        def _echo_marker(request):
            command = request.payload["command"]
            marker = command.split('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(
                request_id=request.id, status="success", output=f"{marker}0\n",
            )

        listener._executors.execute = AsyncMock(side_effect=_echo_marker)
        run(listener._handle_event(onbox_unblock_event(method="nftables")))

        ip_ban.unban_ip.assert_not_awaited()
        request = listener._executors.execute.await_args.args[0]
        assert "nft delete element" in request.payload["command"]
        result = json.loads(posted_response(listener).output)
        assert result["verb"] == "unblock_ip"
        assert result["ok"] is True
        assert result["strategy"] == "nftables"

    def test_dry_run_makes_no_ssh_call(self):
        listener, _ip_ban = _onbox_unblock_listener()
        listener._executors.execute = AsyncMock()
        run(listener._handle_event(onbox_unblock_event(payload={
            "finding_id": "fnd-3", "action": "unblock_ip",
            "ip": "9.9.9.9", "method": "ufw", "dry_run": True,
        })))
        listener._executors.execute.assert_not_awaited()
        result = json.loads(posted_response(listener).output)
        assert result["ok"] is True
        assert result["would_unban"] is True

    def test_verify_absence_failure_reports_slug(self):
        listener, _ip_ban = _onbox_unblock_listener()

        def _echo_fail(request):
            command = request.payload["command"]
            marker = command.split('echo "', 1)[1].split("$rc", 1)[0]
            # VERIFY still finds the ip → exit 1 (unban did not take).
            return CommandResponse(
                request_id=request.id, status="success", output=f"{marker}1\n",
            )

        listener._executors.execute = AsyncMock(side_effect=_echo_fail)
        run(listener._handle_event(onbox_unblock_event(method="ufw")))
        result = json.loads(posted_response(listener).output)
        assert result["ok"] is False
        assert result["slug"] == "unblock_ip_failed"

    def test_sudo_denied_classified_as_permission(self):
        listener, _ip_ban = _onbox_unblock_listener()

        def _echo_denied(request):
            command = request.payload["command"]
            marker = command.split('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(
                request_id=request.id, status="success",
                output=f"sudo: a password is required\n{marker}1\n",
            )

        listener._executors.execute = AsyncMock(side_effect=_echo_denied)
        run(listener._handle_event(onbox_unblock_event()))
        result = json.loads(posted_response(listener).output)
        assert result["ok"] is False
        assert result["slug"] == "unblock_ip_permission_denied"

    def test_timeout_is_a_command_outcome(self):
        listener, _ip_ban = _onbox_unblock_listener()
        listener._executors.execute = AsyncMock(return_value=CommandResponse(
            request_id="rmd-onbox-unban-1", status="timeout", output="",
        ))
        run(listener._handle_event(onbox_unblock_event()))
        response = posted_response(listener)
        assert response.status == "success"
        result = json.loads(response.output)
        assert result["slug"] == "remediation_timeout"

    def test_transport_failure_is_error_status(self):
        listener, _ip_ban = _onbox_unblock_listener()
        listener._executors.execute = AsyncMock(return_value=CommandResponse(
            request_id="rmd-onbox-unban-1", status="error", output="",
            error_message="ssh channel closed",
        ))
        run(listener._handle_event(onbox_unblock_event()))
        response = posted_response(listener)
        assert response.status == "error"
        assert response.error_message.startswith("remediation_execution_failed:")

    def test_missing_target_refuses(self):
        listener, _ip_ban = _onbox_unblock_listener()
        listener._executors.execute = AsyncMock()
        run(listener._handle_event(onbox_unblock_event(target="")))
        listener._executors.execute.assert_not_awaited()
        response = posted_response(listener)
        assert response.status == "error"
        assert response.error_message.startswith("unblock_ip_target_missing:")


# ---------------------------------------------------------------------------
# restart_service — SSH-command verb (mirror of certbot_renew)
# ---------------------------------------------------------------------------

from servonaut.services.remediation_executor import (  # noqa: E402
    SSH_COMMAND_VERBS,
    LOCAL_DISPATCH_VERBS,
)


class TestRestartServiceVerbSet:
    def test_restart_service_is_an_ssh_command_verb(self):
        assert "restart_service" in REMEDIATION_VERBS
        assert "restart_service" in SSH_COMMAND_VERBS
        assert "restart_service" not in LOCAL_DISPATCH_VERBS

    def test_builders_and_ssh_verbs_stay_in_sync(self):
        from servonaut.services.remediation_executor import _VERB_BUILDERS
        assert set(_VERB_BUILDERS) == SSH_COMMAND_VERBS


class TestBuildRestartServiceCommand:
    def test_live_restart_fixed_argv(self):
        cmd = build_remediation_command("restart_service", {"unit": "nginx.service"})
        assert cmd == "sudo -n systemctl restart nginx.service"

    def test_bare_unit_name_accepted(self):
        # systemctl accepts a bare name (implies .service).
        cmd = build_remediation_command("restart_service", {"unit": "nginx"})
        assert cmd == "sudo -n systemctl restart nginx"

    @pytest.mark.parametrize("unit", [
        "getty@tty1.service",              # leak-guard:allow  systemd template unit, not an email
        "user@1000.service",               # leak-guard:allow  systemd template unit, not an email
        "systemd-fsck@dev-sda1.service",   # leak-guard:allow  systemd template unit, not an email
    ])
    def test_template_instance_units_accepted(self, unit):
        # The '@' in template/instance units must not be rejected — the
        # server allows them, so the client floor must too (never a shell
        # risk: the argv is shlex-quoted).
        cmd = build_remediation_command("restart_service", {"unit": unit})
        assert unit in cmd

    @pytest.mark.parametrize("suffix_unit", [
        "foo.socket", "bar.timer", "baz.target", "m.mount", "p.path",
        "s.slice", "sc.scope",
    ])
    def test_known_unit_type_suffixes_accepted(self, suffix_unit):
        cmd = build_remediation_command("restart_service", {"unit": suffix_unit})
        assert suffix_unit in cmd

    def test_dry_run_reports_state_and_forces_zero_exit(self):
        cmd = build_remediation_command(
            "restart_service", {"unit": "nginx", "dry_run": True},
        )
        assert "systemctl is-active nginx" in cmd
        assert "systemctl status nginx --no-pager" in cmd
        assert cmd.rstrip().endswith("; true")
        # A dry run must never mutate.
        assert "systemctl restart" not in cmd

    @pytest.mark.parametrize("falsy", ["false", "False", "0", "", "no"])
    def test_string_falsy_dry_run_builds_live_command(self, falsy):
        cmd = build_remediation_command(
            "restart_service", {"unit": "nginx", "dry_run": falsy},
        )
        assert cmd == "sudo -n systemctl restart nginx"

    @pytest.mark.parametrize("bad", [
        "a/b.service",        # path separator
        "..up.service",       # traversal
        "nginx;id",           # command separator
        "$(id)",              # command substitution
        "a b.service",        # whitespace
        "n`id`",              # backtick
        "unit\nname",         # newline
        "",                   # empty
        None,                 # missing
        42,                   # wrong type
    ])
    def test_hostile_or_malformed_unit_rejected(self, bad):
        with pytest.raises(RemediationValidationError) as exc:
            build_remediation_command("restart_service", {"unit": bad})
        assert str(exc.value).startswith("invalid_unit_name:")


class TestClassifyRestartFailure:
    @pytest.mark.parametrize("output,slug", [
        ("Unit foo.service not found.", "unit_not_found"),
        ("Failed to restart x: Unit x.service not loaded.", "unit_not_found"),
        ("sudo: a password is required", "restart_permission_denied"),
        ("Job for nginx.service failed", "restart_failed"),
        ("some other error", "restart_failed"),
    ])
    def test_restart_slugs(self, output, slug):
        assert classify_failure("restart_service", 1, output) == slug

    def test_transport_failure_still_generic(self):
        assert classify_failure("restart_service", None, "") == (
            "remediation_transport_failed"
        )

    def test_certbot_classification_unaffected(self):
        assert classify_failure("certbot_renew", 1, "no certificate found") == (
            "cert_name_not_found"
        )


def restart_service_event(*, unit="nginx.service", dry_run=False, target="web-1"):
    return remediation_event(
        req_id="rmd-restart-1", verb="restart_service", target=target,
        payload={
            "finding_id": "fnd-5", "action": "restart_service",
            "unit": unit, "dry_run": dry_run,
        },
    )


class TestRestartServiceRouting:
    def test_success_builds_systemctl_over_ssh(self):
        listener = make_listener()

        def _echo_marker(request):
            command = request.payload["command"]
            marker = command.split('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(
                request_id=request.id, status="success",
                output=f"Restarted nginx.service\n{marker}0\n",
            )

        listener._executors.execute = AsyncMock(side_effect=_echo_marker)
        run(listener._handle_event(restart_service_event()))

        request = listener._executors.execute.await_args.args[0]
        assert request.type == CommandType.RUN_COMMAND
        assert request.payload["command"].startswith(
            "(sudo -n systemctl restart nginx.service",
        )
        assert EXIT_MARKER in request.payload["command"]

        result = json.loads(posted_response(listener).output)
        assert result["verb"] == "restart_service"
        assert result["ok"] is True
        assert result["exit_code"] == 0

    def test_unit_not_found_answers_with_slug(self):
        listener = make_listener()

        def _echo_fail(request):
            command = request.payload["command"]
            marker = command.split('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(
                request_id=request.id, status="success",
                output=f"Unit bogus.service not found.\n{marker}5\n",
            )

        listener._executors.execute = AsyncMock(side_effect=_echo_fail)
        run(listener._handle_event(restart_service_event(unit="bogus.service")))
        result = json.loads(posted_response(listener).output)
        assert result["ok"] is False
        assert result["slug"] == "unit_not_found"

    def test_sudo_denied_classified_as_permission(self):
        listener = make_listener()

        def _echo_denied(request):
            command = request.payload["command"]
            marker = command.split('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(
                request_id=request.id, status="success",
                output=f"sudo: a password is required\n{marker}1\n",
            )

        listener._executors.execute = AsyncMock(side_effect=_echo_denied)
        run(listener._handle_event(restart_service_event()))
        result = json.loads(posted_response(listener).output)
        assert result["ok"] is False
        assert result["slug"] == "restart_permission_denied"

    def test_dry_run_reports_state_and_makes_no_restart(self):
        listener = make_listener()
        captured = {}

        def _echo_marker(request):
            captured["command"] = request.payload["command"]
            marker = request.payload["command"].split('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(
                request_id=request.id, status="success",
                output=f"active\n{marker}0\n",
            )

        listener._executors.execute = AsyncMock(side_effect=_echo_marker)
        run(listener._handle_event(restart_service_event(dry_run=True)))
        # The dispatched command inspects state, never restarts.
        assert "systemctl restart" not in captured["command"]
        assert "is-active" in captured["command"]
        result = json.loads(posted_response(listener).output)
        assert result["ok"] is True
        assert result["dry_run"] is True

    def test_timeout_is_a_command_outcome(self):
        listener = make_listener()
        listener._executors.execute = AsyncMock(return_value=CommandResponse(
            request_id="rmd-restart-1", status="timeout", output="",
        ))
        run(listener._handle_event(restart_service_event()))
        response = posted_response(listener)
        assert response.status == "success"
        result = json.loads(response.output)
        assert result["slug"] == "remediation_timeout"


# ---------------------------------------------------------------------------
# restart_container / start_container — SSH-command verbs (docker <verb> <name>)
# ---------------------------------------------------------------------------


class TestContainerVerbSet:
    @pytest.mark.parametrize("verb", ["restart_container", "start_container"])
    def test_container_verbs_are_ssh_command_verbs(self, verb):
        assert verb in REMEDIATION_VERBS
        assert verb in SSH_COMMAND_VERBS
        assert verb not in LOCAL_DISPATCH_VERBS

    def test_builders_and_ssh_verbs_stay_in_sync(self):
        from servonaut.services.remediation_executor import _VERB_BUILDERS
        assert set(_VERB_BUILDERS) == SSH_COMMAND_VERBS


class TestBuildContainerCommand:
    def test_live_restart_fixed_argv(self):
        cmd = build_remediation_command(
            "restart_container", {"container": "web-1"},
        )
        # No sudo: the relay user reaches the docker socket directly, the same
        # access path as the read-side docker probe.
        assert cmd == "docker restart web-1"

    def test_live_start_fixed_argv(self):
        cmd = build_remediation_command(
            "start_container", {"container": "web-1"},
        )
        assert cmd == "docker start web-1"

    @pytest.mark.parametrize("name", [
        "web-1", "myapp_web_1", "db.cache-2", "svc.worker_3-a", "R2",
    ])
    def test_valid_docker_names_accepted(self, name):
        cmd = build_remediation_command(
            "restart_container", {"container": name},
        )
        assert cmd == f"docker restart {name}"

    @pytest.mark.parametrize("verb", ["restart_container", "start_container"])
    def test_dry_run_inspects_and_forces_zero_exit(self, verb):
        cmd = build_remediation_command(
            verb, {"container": "web-1", "dry_run": True},
        )
        assert "docker inspect -f" in cmd
        assert "{{.State.Status}}" in cmd
        assert "{{.RestartCount}}" in cmd
        assert "web-1" in cmd
        assert cmd.rstrip().endswith("; true")
        # A dry run must never mutate.
        assert "docker restart" not in cmd
        assert "docker start" not in cmd

    def test_name_at_128_chars_accepted_129_rejected(self):
        # Server bound is 128 chars total (leading char + up to 127 more).
        ok = "a" + "b" * 127
        assert len(ok) == 128
        cmd = build_remediation_command(
            "restart_container", {"container": ok},
        )
        assert ok in cmd
        too_long = "a" + "b" * 128  # 129 chars
        with pytest.raises(RemediationValidationError):
            build_remediation_command("restart_container", {"container": too_long})

    @pytest.mark.parametrize("falsy", ["false", "False", "0", "", "no"])
    def test_string_falsy_dry_run_builds_live_command(self, falsy):
        cmd = build_remediation_command(
            "restart_container", {"container": "web-1", "dry_run": falsy},
        )
        assert cmd == "docker restart web-1"

    @pytest.mark.parametrize("bad", [
        "a/b",             # path separator
        "..up",            # traversal
        "web;id",          # command separator
        "$(id)",           # command substitution
        "a b",             # whitespace
        "n`id`",           # backtick
        "name\nx",         # newline
        "a:b",             # colon — not a valid docker name char
        "x@y",             # at-sign
        "-leading",        # must start alphanumeric
        ".dotfirst",       # must start alphanumeric
        "_underfirst",     # must start alphanumeric
        "",                # empty
        None,              # missing
        42,                # wrong type
    ])
    @pytest.mark.parametrize("verb", ["restart_container", "start_container"])
    def test_hostile_or_malformed_container_rejected(self, verb, bad):
        with pytest.raises(RemediationValidationError) as exc:
            build_remediation_command(verb, {"container": bad})
        assert str(exc.value).startswith("invalid_container_name:")


class TestClassifyContainerFailure:
    @pytest.mark.parametrize("output,slug", [
        ("Error: No such container: web-1", "container_not_found"),
        ("Error response from daemon: No such container: x", "container_not_found"),
        ("permission denied while trying to connect to the Docker daemon socket",
         "docker_permission_denied"),
        ("Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
         "docker_permission_denied"),
        ("some other docker error", "restart_container_failed"),
    ])
    def test_restart_slugs(self, output, slug):
        assert classify_failure("restart_container", 1, output) == slug

    def test_start_generic_slug_uses_verb(self):
        assert classify_failure("start_container", 1, "boom") == (
            "start_container_failed"
        )

    def test_transport_failure_still_generic(self):
        assert classify_failure("restart_container", None, "") == (
            "remediation_transport_failed"
        )

    def test_restart_service_classification_unaffected(self):
        assert classify_failure("restart_service", 1, "Unit x.service not found.") == (
            "unit_not_found"
        )


def container_event(
    *, verb="restart_container", container="web-1", dry_run=False, target="web-1",
):
    return remediation_event(
        req_id="rmd-container-1", verb=verb, target=target,
        payload={
            "finding_id": "fnd-6", "action": verb,
            "container": container, "dry_run": dry_run,
        },
    )


class TestContainerRouting:
    @pytest.mark.parametrize("verb,docker_verb", [
        ("restart_container", "docker restart"),
        ("start_container", "docker start"),
    ])
    def test_success_builds_docker_over_ssh(self, verb, docker_verb):
        listener = make_listener()

        def _echo_marker(request):
            command = request.payload["command"]
            marker = command.split('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(
                request_id=request.id, status="success",
                output=f"web-1\n{marker}0\n",
            )

        listener._executors.execute = AsyncMock(side_effect=_echo_marker)
        run(listener._handle_event(container_event(verb=verb)))

        request = listener._executors.execute.await_args.args[0]
        assert request.type == CommandType.RUN_COMMAND
        assert request.payload["command"].startswith(f"({docker_verb} web-1")
        assert EXIT_MARKER in request.payload["command"]

        result = json.loads(posted_response(listener).output)
        assert result["verb"] == verb
        assert result["ok"] is True
        assert result["exit_code"] == 0

    def test_no_such_container_answers_with_slug(self):
        listener = make_listener()

        def _echo_fail(request):
            command = request.payload["command"]
            marker = command.split('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(
                request_id=request.id, status="success",
                output=f"Error: No such container: web-1\n{marker}1\n",
            )

        listener._executors.execute = AsyncMock(side_effect=_echo_fail)
        run(listener._handle_event(container_event(container="web-1")))
        result = json.loads(posted_response(listener).output)
        assert result["ok"] is False
        assert result["slug"] == "container_not_found"

    def test_dry_run_inspects_and_makes_no_mutation(self):
        listener = make_listener()
        captured = {}

        def _echo_marker(request):
            captured["command"] = request.payload["command"]
            marker = request.payload["command"].split('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(
                request_id=request.id, status="success",
                output=f"running\n{marker}0\n",
            )

        listener._executors.execute = AsyncMock(side_effect=_echo_marker)
        run(listener._handle_event(container_event(dry_run=True)))
        # The dispatched command inspects state, never restarts/starts.
        assert "docker inspect" in captured["command"]
        assert "docker restart" not in captured["command"]
        result = json.loads(posted_response(listener).output)
        assert result["ok"] is True
        assert result["dry_run"] is True


# ---------------------------------------------------------------------------
# rate_limit / rate_limit_path — WAF control-plane verbs (validation rail).
# Dispatch (_execute_rate_limit) lands once the WebACL-resolution contract is
# settled; these pin the pure, frozen validation half.
# ---------------------------------------------------------------------------

from servonaut.services.remediation_executor import (  # noqa: E402
    WAF_DISPATCH_VERBS,
    RATE_LIMIT_RATES,
    validate_rate_limit_payload,
)


class TestWafVerbSet:
    @pytest.mark.parametrize("verb", ["rate_limit", "rate_limit_path"])
    def test_waf_verbs_are_recognised_but_not_ssh_or_local(self, verb):
        assert verb in REMEDIATION_VERBS
        assert verb in WAF_DISPATCH_VERBS
        assert verb not in SSH_COMMAND_VERBS
        assert verb not in LOCAL_DISPATCH_VERBS

    def test_dispatch_categories_are_pairwise_disjoint(self):
        assert not (SSH_COMMAND_VERBS & WAF_DISPATCH_VERBS)
        assert not (LOCAL_DISPATCH_VERBS & WAF_DISPATCH_VERBS)

    def test_rates_respect_the_aws_floor_of_100(self):
        # AWS WAF per-IP aggregation refuses a Limit below 100.
        assert all(int(r) >= 100 for r in RATE_LIMIT_RATES)
        assert RATE_LIMIT_RATES == {"500", "2000", "10000"}


class TestValidateRateLimitPayload:
    def test_valid_rate_limit_returns_ip_rate_and_no_path(self):
        ip, rate, path = validate_rate_limit_payload(
            {"ip": "9.9.9.9", "method": "waf", "rate": "2000"},
        )
        assert (ip, rate, path) == ("9.9.9.9", "2000", None)

    def test_valid_rate_limit_path_returns_path_and_no_ip(self):
        # A path rule spans all clients — no ip is carried.
        ip, rate, path = validate_rate_limit_payload(
            {"method": "waf", "rate": "500", "path": "/api/login"},
            require_path=True,
        )
        assert (ip, rate, path) == (None, "500", "/api/login")

    @pytest.mark.parametrize("rate", ["50", "100", "999", "2001", "", "abc"])
    def test_off_enum_rate_rejected(self, rate):
        with pytest.raises(RemediationValidationError) as exc:
            validate_rate_limit_payload(
                {"ip": "9.9.9.9", "method": "waf", "rate": rate},
            )
        assert str(exc.value).startswith("invalid_rate_limit_rate:")

    @pytest.mark.parametrize("rate", [2000, 2000.0, True, None])
    def test_non_string_rate_rejected(self, rate):
        # The rate is folded into the confirm-token preimage as a string; a
        # non-string must never reach the wire.
        with pytest.raises(RemediationValidationError):
            validate_rate_limit_payload(
                {"ip": "9.9.9.9", "method": "waf", "rate": rate},
            )

    @pytest.mark.parametrize("method", ["nacl", "security_group", "nftables", "ufw"])
    def test_non_waf_method_rejected(self, method):
        with pytest.raises(RemediationValidationError) as exc:
            validate_rate_limit_payload(
                {"ip": "9.9.9.9", "method": method, "rate": "2000"},
            )
        assert str(exc.value).startswith("invalid_rate_limit_method:")

    @pytest.mark.parametrize("ip", ["10.0.0.1", "127.0.0.1", "169.254.1.1", "1.2.3.4/24"])
    def test_non_public_or_cidr_ip_rejected(self, ip):
        with pytest.raises(RemediationValidationError):
            validate_rate_limit_payload(
                {"ip": ip, "method": "waf", "rate": "2000"},
            )

    def test_self_ip_refused(self):
        with pytest.raises(RemediationValidationError):
            validate_rate_limit_payload(
                {"ip": "9.9.9.9", "method": "waf", "rate": "2000"},
                frozenset({"9.9.9.9"}),
            )

    def test_bare_root_path_rejected(self):
        # A whole-site "/" scope-down defeats the point of the path verb —
        # the {1,255} floor rejects it (matches the server's floor).
        with pytest.raises(RemediationValidationError) as exc:
            validate_rate_limit_payload(
                {"ip": "9.9.9.9", "method": "waf", "rate": "2000", "path": "/"},
                require_path=True,
            )
        assert str(exc.value).startswith("invalid_rate_limit_path:")

    @pytest.mark.parametrize("path", ["a b", "../etc", "no-leading-slash", "/x;y", "/a`b`"])
    def test_hostile_path_rejected(self, path):
        with pytest.raises(RemediationValidationError) as exc:
            validate_rate_limit_payload(
                {"ip": "9.9.9.9", "method": "waf", "rate": "2000", "path": path},
                require_path=True,
            )
        assert str(exc.value).startswith("invalid_rate_limit_path:")

    def test_require_path_but_missing_rejected(self):
        with pytest.raises(RemediationValidationError):
            validate_rate_limit_payload(
                {"ip": "9.9.9.9", "method": "waf", "rate": "2000"},
                require_path=True,
            )

    def test_plain_rate_limit_ignores_absent_path(self):
        # rate_limit (require_path=False) with no path is valid.
        _, _, path = validate_rate_limit_payload(
            {"ip": "9.9.9.9", "method": "waf", "rate": "10000"},
        )
        assert path is None


# ---------------------------------------------------------------------------
# Shared WebACL resolver (extracted from the MCP tool for the rate_limit
# executor). ARN paths need no AWS/instance lookup and are unit-testable.
# ---------------------------------------------------------------------------

from servonaut.services.waf_management_service import (  # noqa: E402
    resolve_webacl,
)


class TestResolveWebacl:
    def test_webacl_arn_parsed_without_aws(self):
        arn = ("arn:aws:wafv2:eu-west-2:EXAMPLE-ACCT:regional/webacl/"
               "myacl/abc-123")
        out = run(resolve_webacl(arn))
        assert out == {"name": "myacl", "id": "abc-123", "scope": "REGIONAL",
                       "region": "eu-west-2", "arn": arn}

    def test_non_webacl_arn_rejected(self):
        ipset = ("arn:aws:wafv2:eu-west-2:EXAMPLE-ACCT:regional/ipset/"
                 "s/i-1")
        assert "error" in run(resolve_webacl(ipset))

    def test_empty_target_errors(self):
        assert "error" in run(resolve_webacl(""))

    def test_instance_target_without_resolver_errors(self):
        # An instance id/name needs a find_instance callable; absent one,
        # resolution fails closed rather than raising.
        out = run(resolve_webacl("web-1", find_instance=None))
        assert "error" in out

    def test_instance_resolver_reaches_ingress_walk(self):
        # A non-AWS instance is refused before any ingress walk.
        async def _fake_find(_):
            return {"id": "web-1", "is_ovh": True}
        out = run(resolve_webacl("web-1", find_instance=_fake_find))
        assert "not an AWS instance" in out["error"]


# ---------------------------------------------------------------------------
# rate_limit / rate_limit_path — WAF dispatch (_execute_rate_limit).
# Mocks the WebACL resolver + WAFManagementService.set_rate_rule.
# ---------------------------------------------------------------------------

from unittest.mock import patch  # noqa: E402


def _webacl(**over):
    base = {"name": "acl", "id": "acl-1", "scope": "REGIONAL",
            "region": "eu-west-2",
            "arn": "arn:aws:wafv2:eu-west-2:EXAMPLE-ACCT:regional/webacl/acl/acl-1"}
    base.update(over)
    return base


def make_rate_limit_listener(*, acl=None, set_result=None, instance=None):
    listener = make_listener()
    ex = listener._executors
    ex.find_instance = AsyncMock(return_value=instance)
    ex.resolve_webacl = AsyncMock(
        return_value=acl if acl is not None else _webacl(),
    )
    svc = MagicMock()
    svc.set_rate_rule = AsyncMock(
        return_value=set_result if set_result is not None else {
            "applied": True, "error": "", "rule_name": "servonaut-rate-9-9-9-9",
            "created_or_updated": "created", "previous": None,
            "ip_set_arn": "arn:aws:wafv2:eu-west-2:EXAMPLE-ACCT:regional/"
                          "ipset/servonaut-rate-9-9-9-9-scope/is-1",
            "ip_set_name": "servonaut-rate-9-9-9-9-scope",
        },
    )
    return listener, ex, svc


def rate_limit_event(*, verb="rate_limit", ip="9.9.9.9", rate="2000",
                     path=None, dry_run=False, target="web-1"):
    payload = {"finding_id": "fnd-9", "action": verb, "method": "waf",
               "rate": rate, "dry_run": dry_run, "timeout_seconds": 60}
    if verb == "rate_limit_path":
        payload["path"] = path or "/api/login"
    else:
        payload["ip"] = ip
    return remediation_event(req_id="rmd-rate-1", verb=verb, target=target,
                             payload=payload)


class TestRateLimitRouting:
    def test_ip_scoped_success_never_ssh(self):
        listener, ex, svc = make_rate_limit_listener()
        with patch("servonaut.services.waf_management_service."
                   "WAFManagementService", return_value=svc):
            run(listener._handle_event(rate_limit_event()))

        listener._executors.execute.assert_not_awaited()  # WAF, never SSH
        ex.resolve_webacl.assert_awaited_once()
        # set_rate_rule called with ip_scope (not uri_scope) for rate_limit.
        _, kwargs = svc.set_rate_rule.await_args
        assert kwargs["ip_scope"] == "9.9.9.9"
        assert kwargs["uri_scope"] == ""
        assert kwargs["limit"] == 2000

        result = json.loads(posted_response(listener).output)
        assert result["verb"] == "rate_limit"
        assert result["ok"] is True
        assert result["ip"] == "9.9.9.9"
        assert result["ip_set_arn"].endswith("is-1")
        assert result["rule_name"] == "servonaut-rate-9-9-9-9"
        assert result["limit_applied"] == 2000

    def test_dry_run_makes_no_mutation(self):
        listener, ex, svc = make_rate_limit_listener()
        with patch("servonaut.services.waf_management_service."
                   "WAFManagementService", return_value=svc):
            run(listener._handle_event(rate_limit_event(dry_run=True)))
        svc.set_rate_rule.assert_not_awaited()  # pure preview
        result = json.loads(posted_response(listener).output)
        assert result["ok"] is True
        assert result["dry_run"] is True
        assert result["would_apply"] is True

    def test_path_scoped_uses_uri_scope_no_ipset(self):
        listener, ex, svc = make_rate_limit_listener(set_result={
            "applied": True, "error": "", "rule_name": "servonaut-ratep-api",
            "created_or_updated": "created", "previous": None,
            "ip_set_arn": "", "ip_set_name": "",
        })
        with patch("servonaut.services.waf_management_service."
                   "WAFManagementService", return_value=svc):
            run(listener._handle_event(
                rate_limit_event(verb="rate_limit_path", path="/api/login")))
        _, kwargs = svc.set_rate_rule.await_args
        assert kwargs["uri_scope"] == "/api/login"
        assert kwargs["ip_scope"] == ""
        result = json.loads(posted_response(listener).output)
        assert result["verb"] == "rate_limit_path"
        assert result["ok"] is True
        assert result["path"] == "/api/login"
        assert "ip" not in result

    def test_unresolved_webacl_is_command_outcome_not_relay_error(self):
        # An unresolved WebACL is a command-OUTCOME ("nothing to rate-limit"),
        # not a relay/transport failure: status stays "success" so the server
        # reads ok:false + the specific slug and keeps the finding detected,
        # rather than mislabelling it remediation_relay_error.
        listener, ex, svc = make_rate_limit_listener(
            acl={"error": "no WebACL found fronting web-1"},
        )
        with patch("servonaut.services.waf_management_service."
                   "WAFManagementService", return_value=svc):
            run(listener._handle_event(rate_limit_event()))
        svc.set_rate_rule.assert_not_awaited()
        response = posted_response(listener)
        assert response.status == "success"
        assert response.error_message == ""
        result = json.loads(response.output)
        assert result["ok"] is False
        assert result["slug"] == "rate_limit_webacl_unresolved"

    def test_off_enum_rate_refused_before_resolve(self):
        listener, ex, svc = make_rate_limit_listener()
        with patch("servonaut.services.waf_management_service."
                   "WAFManagementService", return_value=svc):
            run(listener._handle_event(rate_limit_event(rate="50")))
        ex.resolve_webacl.assert_not_awaited()
        svc.set_rate_rule.assert_not_awaited()
        response = posted_response(listener)
        assert response.status == "error"
        assert response.error_message.startswith("invalid_rate_limit_rate:")

    def test_set_rate_rule_failure_reports_slug(self):
        listener, ex, svc = make_rate_limit_listener(set_result={
            "applied": False, "error": "update_web_acl: boom",
        })
        with patch("servonaut.services.waf_management_service."
                   "WAFManagementService", return_value=svc):
            run(listener._handle_event(rate_limit_event()))
        result = json.loads(posted_response(listener).output)
        assert result["ok"] is False
        assert result["slug"] == "rate_limit_failed"


# ---------------------------------------------------------------------------
# enable_service / reload_service — SSH-command verbs (systemctl variants of
# restart_service, same unit binding + envelope).
# ---------------------------------------------------------------------------


class TestServiceStateVerbSet:
    @pytest.mark.parametrize("verb", ["enable_service", "reload_service", "disable_service"])
    def test_is_an_ssh_command_verb(self, verb):
        assert verb in REMEDIATION_VERBS
        assert verb in SSH_COMMAND_VERBS
        assert verb not in LOCAL_DISPATCH_VERBS

    def test_builders_and_ssh_verbs_stay_in_sync(self):
        from servonaut.services.remediation_executor import _VERB_BUILDERS
        assert set(_VERB_BUILDERS) == SSH_COMMAND_VERBS


class TestBuildServiceStateCommand:
    def test_enable_live_uses_enable_now(self):
        cmd = build_remediation_command("enable_service", {"unit": "nginx.service"})
        assert cmd == "sudo -n systemctl enable --now nginx.service"

    def test_reload_live_uses_reload(self):
        cmd = build_remediation_command("reload_service", {"unit": "nginx.service"})
        assert cmd == "sudo -n systemctl reload nginx.service"

    def test_disable_live_uses_disable_now(self):
        cmd = build_remediation_command("disable_service", {"unit": "telnet.socket"})
        assert cmd == "sudo -n systemctl disable --now telnet.socket"

    def test_disable_dry_run_reports_state_no_change(self):
        cmd = build_remediation_command(
            "disable_service", {"unit": "telnet.socket", "dry_run": True})
        assert "systemctl is-enabled telnet.socket" in cmd
        assert cmd.rstrip().endswith("; true")
        assert "disable --now" not in cmd

    def test_enable_dry_run_reports_state_no_change(self):
        cmd = build_remediation_command(
            "enable_service", {"unit": "nginx", "dry_run": True})
        assert "systemctl is-enabled nginx" in cmd
        assert "systemctl is-active nginx" in cmd
        assert cmd.rstrip().endswith("; true")
        assert "enable --now" not in cmd

    def test_reload_dry_run_reports_state_no_change(self):
        cmd = build_remediation_command(
            "reload_service", {"unit": "nginx", "dry_run": True})
        assert "systemctl is-active nginx" in cmd
        assert cmd.rstrip().endswith("; true")
        assert "systemctl reload" not in cmd

    @pytest.mark.parametrize("verb", ["enable_service", "reload_service", "disable_service"])
    @pytest.mark.parametrize("bad", ["a/b.service", "..x", "n;id", "$(id)", "a b", "", None, 42])
    def test_hostile_unit_rejected(self, verb, bad):
        with pytest.raises(RemediationValidationError) as exc:
            build_remediation_command(verb, {"unit": bad})
        assert str(exc.value).startswith("invalid_unit_name:")

    @pytest.mark.parametrize("unit", [
        "getty@tty1.service",  # leak-guard:allow  systemd template unit, not an email
    ])
    def test_template_units_accepted(self, unit):
        assert unit in build_remediation_command("enable_service", {"unit": unit})


class TestClassifyServiceStateFailure:
    @pytest.mark.parametrize("verb,output,slug", [
        ("enable_service", "sudo: a password is required", "enable_permission_denied"),
        ("reload_service", "sudo: a password is required", "reload_permission_denied"),
        ("enable_service", "Unit x.service not found.", "unit_not_found"),
        ("reload_service", "Failed to reload x: Job type reload is not applicable for unit x.",
         "reload_unsupported"),
        ("enable_service", "some other error", "enable_failed"),
        ("reload_service", "some other error", "reload_failed"),
        ("disable_service", "sudo: a password is required", "disable_permission_denied"),
        ("disable_service", "Unit x.service not found.", "unit_not_found"),
        ("disable_service", "boom", "disable_failed"),
    ])
    def test_slugs(self, verb, output, slug):
        assert classify_failure(verb, 1, output) == slug

    def test_restart_service_slugs_unchanged(self):
        # The shared branch must not regress restart_service's slugs.
        assert classify_failure("restart_service", 1, "sudo: a password is required") == (
            "restart_permission_denied")
        assert classify_failure("restart_service", 1, "Unit x.service not found.") == (
            "unit_not_found")
        assert classify_failure("restart_service", 1, "boom") == "restart_failed"


def service_state_event(*, verb="enable_service", unit="nginx.service", dry_run=False):
    return remediation_event(
        req_id="rmd-svc-1", verb=verb, target="web-1",
        payload={"finding_id": "fnd-8", "action": verb, "unit": unit,
                 "dry_run": dry_run, "timeout_seconds": 60},
    )


class TestServiceStateRouting:
    @pytest.mark.parametrize("verb,frag", [
        ("enable_service", "sudo -n systemctl enable --now nginx.service"),
        ("reload_service", "sudo -n systemctl reload nginx.service"),
        ("disable_service", "sudo -n systemctl disable --now nginx.service"),
    ])
    def test_success_builds_systemctl_over_ssh(self, verb, frag):
        listener = make_listener()

        def _echo(request):
            command = request.payload["command"]
            marker = command.split('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(request_id=request.id, status="success",
                                   output=f"ok\n{marker}0\n")

        listener._executors.execute = AsyncMock(side_effect=_echo)
        run(listener._handle_event(service_state_event(verb=verb)))
        request = listener._executors.execute.await_args.args[0]
        # Subshell-wrapped so an internal ``exit`` can't pre-empt the epilogue.
        assert request.payload["command"].startswith(f"({frag}")
        result = json.loads(posted_response(listener).output)
        assert result["verb"] == verb
        assert result["ok"] is True

    def test_reload_unsupported_slug(self):
        listener = make_listener()

        def _echo_fail(request):
            command = request.payload["command"]
            marker = command.split('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(
                request_id=request.id, status="success",
                output=("Failed to reload nginx.service: Job type reload is "
                        f"not applicable for unit nginx.service.\n{marker}1\n"))

        listener._executors.execute = AsyncMock(side_effect=_echo_fail)
        run(listener._handle_event(service_state_event(verb="reload_service")))
        result = json.loads(posted_response(listener).output)
        assert result["ok"] is False
        assert result["slug"] == "reload_unsupported"


# ---------------------------------------------------------------------------
# raise_container_memory — Tier-2 compose-edit executor (guarded on-box script)
# ---------------------------------------------------------------------------

from servonaut.services.remediation_executor import (  # noqa: E402
    RAISE_MEM_MULTIPLIERS,
)


class TestRaiseContainerMemoryVerbSet:
    def test_is_an_ssh_command_verb(self):
        assert "raise_container_memory" in REMEDIATION_VERBS
        assert "raise_container_memory" in SSH_COMMAND_VERBS
        assert "raise_container_memory" not in LOCAL_DISPATCH_VERBS

    def test_builders_in_sync(self):
        from servonaut.services.remediation_executor import _VERB_BUILDERS
        assert set(_VERB_BUILDERS) == SSH_COMMAND_VERBS

    def test_multipliers_are_ge_2(self):
        assert RAISE_MEM_MULTIPLIERS == {"2", "3", "4"}


class TestBuildRaiseContainerMemory:
    def test_live_has_full_guardrail_chain(self):
        cmd = build_remediation_command(
            "raise_container_memory", {"container": "web-1", "multiplier": "3"})
        # read current -> compute -> locate compose -> yq edit -> validate
        # BEFORE recreate -> recreate -> restore-on-fail.
        assert "docker inspect -f '{{.HostConfig.Memory}}' web-1" in cmd
        assert "CUR * 3" in cmd
        assert 'com.docker.compose.project.config_files' in cmd
        assert "command -v yq" in cmd                    # safe editor, never sed
        assert "sed -i" not in cmd
        assert 'cp "$FILE" "$BAK"' in cmd                # backup first
        assert "docker compose -f" in cmd and "config" in cmd  # validate
        # validate must precede recreate in the script text
        assert cmd.index('config >/dev/null') < cmd.index("up -d --no-deps")
        assert 'cp "$BAK" "$FILE"' in cmd                # restore-on-fail
        assert "up -d --no-deps" in cmd

    def test_dry_run_makes_no_mutation(self):
        cmd = build_remediation_command(
            "raise_container_memory",
            {"container": "web-1", "multiplier": "2", "dry_run": True})
        assert "DRY RUN" in cmd
        assert "yq -i" not in cmd
        assert "up -d" not in cmd
        assert "cp " not in cmd  # no backup/edit in a dry run

    @pytest.mark.parametrize("mult", ["1", "5", "0", "", "2x", 2, 2.0, None])
    def test_bad_multiplier_rejected(self, mult):
        with pytest.raises(RemediationValidationError) as exc:
            build_remediation_command(
                "raise_container_memory", {"container": "web-1", "multiplier": mult})
        assert str(exc.value).startswith("invalid_raise_mem_multiplier:")

    @pytest.mark.parametrize("bad", ["a b", "../x", "a/b", "x@y", ""])
    def test_bad_container_rejected(self, bad):
        with pytest.raises(RemediationValidationError) as exc:
            build_remediation_command(
                "raise_container_memory", {"container": bad, "multiplier": "2"})
        assert str(exc.value).startswith("invalid_container_name:")


class TestClassifyRaiseMemFailure:
    @pytest.mark.parametrize("out,slug", [
        ("INSPECT_FAIL", "container_not_found"),
        ("NO_LIMIT", "raise_mem_no_limit"),
        ("NOT_COMPOSE", "raise_mem_not_compose"),
        ("NO_YAML_EDITOR", "raise_mem_no_yaml_editor"),
        ("VALIDATE_FAIL_RESTORED", "raise_mem_validate_failed"),
        ("RECREATE_FAIL_RESTORED", "raise_mem_recreate_failed"),
        ("EDIT_FAIL", "raise_mem_edit_failed"),
        ("something else", "raise_container_memory_failed"),
    ])
    def test_slugs(self, out, slug):
        assert classify_failure("raise_container_memory", 1, out) == slug


def raise_mem_event(*, container="web-1", multiplier="3", dry_run=False):
    return remediation_event(
        req_id="rmd-mem-1", verb="raise_container_memory", target="web-1",
        payload={"finding_id": "fnd-m", "action": "raise_container_memory",
                 "container": container, "multiplier": multiplier,
                 "dry_run": dry_run, "timeout_seconds": 60})


class TestRaiseContainerMemoryRouting:
    def test_success_builds_script_over_ssh(self):
        listener = make_listener()

        def _echo(request):
            command = request.payload["command"]
            marker = command.rsplit('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(request_id=request.id, status="success",
                                   output=f"OK raised web-1\n{marker}0\n")

        listener._executors.execute = AsyncMock(side_effect=_echo)
        run(listener._handle_event(raise_mem_event()))
        request = listener._executors.execute.await_args.args[0]
        assert request.type == CommandType.RUN_COMMAND
        assert "com.docker.compose.service" in request.payload["command"]
        result = json.loads(posted_response(listener).output)
        assert result["verb"] == "raise_container_memory"
        assert result["ok"] is True

    def test_no_limit_answers_with_slug(self):
        listener = make_listener()

        def _echo_fail(request):
            command = request.payload["command"]
            marker = command.rsplit('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(request_id=request.id, status="success",
                                   output=f"NO_LIMIT\n{marker}4\n")

        listener._executors.execute = AsyncMock(side_effect=_echo_fail)
        run(listener._handle_event(raise_mem_event()))
        result = json.loads(posted_response(listener).output)
        assert result["ok"] is False
        assert result["slug"] == "raise_mem_no_limit"


# rotate_logs — SSH-command verb, TARGET-LESS (no per-finding payload field)
# ---------------------------------------------------------------------------


class TestRotateLogsVerbSet:
    def test_rotate_logs_is_an_ssh_command_verb(self):
        assert "rotate_logs" in REMEDIATION_VERBS
        assert "rotate_logs" in SSH_COMMAND_VERBS
        assert "rotate_logs" not in LOCAL_DISPATCH_VERBS

    def test_builders_and_ssh_verbs_stay_in_sync(self):
        from servonaut.services.remediation_executor import _VERB_BUILDERS
        assert set(_VERB_BUILDERS) == SSH_COMMAND_VERBS


class TestBuildRotateLogsCommand:
    def test_live_is_forced_logrotate(self):
        cmd = build_remediation_command(
            "rotate_logs", {"finding_id": "f1", "action": "rotate_logs"},
        )
        assert cmd == "sudo -n logrotate --force /etc/logrotate.conf"

    def test_dry_run_uses_debug_and_never_forces(self):
        cmd = build_remediation_command(
            "rotate_logs", {"action": "rotate_logs", "dry_run": True},
        )
        assert cmd == "sudo -n logrotate -d /etc/logrotate.conf"
        # A dry run must never rotate.
        assert "--force" not in cmd

    def test_target_less_builds_with_empty_payload(self):
        # No unit/container/ip/cert field — the verb takes no per-finding
        # argument, so an empty payload still builds the live command.
        assert build_remediation_command("rotate_logs", {}) == (
            "sudo -n logrotate --force /etc/logrotate.conf"
        )

    def test_extra_payload_fields_are_ignored(self):
        # Nothing from the payload reaches the command line except dry_run,
        # so a stray field can't alter the built command.
        cmd = build_remediation_command(
            "rotate_logs", {"unit": "nginx", "container": "x", "ip": "1.1.1.1"},
        )
        assert cmd == "sudo -n logrotate --force /etc/logrotate.conf"

    @pytest.mark.parametrize("falsy", ["false", "False", "0", "", "no"])
    def test_string_falsy_dry_run_builds_live_command(self, falsy):
        cmd = build_remediation_command(
            "rotate_logs", {"action": "rotate_logs", "dry_run": falsy},
        )
        assert cmd == "sudo -n logrotate --force /etc/logrotate.conf"


class TestClassifyRotateLogsFailure:
    @pytest.mark.parametrize("output,slug", [
        ("sudo: a password is required", "rotate_logs_permission_denied"),
        ("logrotate: command not found", "rotate_logs_not_installed"),
        ("error: bad config in /etc/logrotate.conf", "rotate_logs_failed"),
    ])
    def test_rotate_logs_slugs(self, output, slug):
        assert classify_failure("rotate_logs", 1, output) == slug

    def test_transport_failure_still_generic(self):
        assert classify_failure("rotate_logs", None, "") == (
            "remediation_transport_failed"
        )


def rotate_logs_event(*, dry_run=False, target="web-1"):
    return remediation_event(
        req_id="rmd-rotate-1", verb="rotate_logs", target=target,
        payload={
            "finding_id": "fnd-7", "action": "rotate_logs",
            "dry_run": dry_run, "timeout_seconds": 120,
        },
    )


class TestRotateLogsRouting:
    def test_success_builds_logrotate_over_ssh(self):
        listener = make_listener()

        def _echo_marker(request):
            command = request.payload["command"]
            marker = command.split('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(
                request_id=request.id, status="success",
                output=f"rotating pattern\n{marker}0\n",
            )

        listener._executors.execute = AsyncMock(side_effect=_echo_marker)
        run(listener._handle_event(rotate_logs_event()))

        request = listener._executors.execute.await_args.args[0]
        assert request.type == CommandType.RUN_COMMAND
        # Subshell-wrapped so an internal ``exit`` can't pre-empt the epilogue.
        assert request.payload["command"].startswith(
            "(sudo -n logrotate --force /etc/logrotate.conf",
        )
        assert EXIT_MARKER in request.payload["command"]

        result = json.loads(posted_response(listener).output)
        assert result["verb"] == "rotate_logs"
        assert result["ok"] is True
        assert result["exit_code"] == 0

    def test_sudo_denied_classified_as_permission(self):
        listener = make_listener()

        def _echo_denied(request):
            command = request.payload["command"]
            marker = command.split('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(
                request_id=request.id, status="success",
                output=f"sudo: a password is required\n{marker}1\n",
            )

        listener._executors.execute = AsyncMock(side_effect=_echo_denied)
        run(listener._handle_event(rotate_logs_event()))
        result = json.loads(posted_response(listener).output)
        assert result["ok"] is False
        assert result["slug"] == "rotate_logs_permission_denied"

    def test_dry_run_uses_debug_and_makes_no_rotation(self):
        listener = make_listener()
        captured = {}

        def _echo_marker(request):
            captured["command"] = request.payload["command"]
            marker = request.payload["command"].split('echo "', 1)[1].split("$rc", 1)[0]
            return CommandResponse(
                request_id=request.id, status="success",
                output=f"considering log /var/log/x\n{marker}0\n",
            )

        listener._executors.execute = AsyncMock(side_effect=_echo_marker)
        run(listener._handle_event(rotate_logs_event(dry_run=True)))
        # The dispatched command debugs, never forces a rotation.
        assert "logrotate -d" in captured["command"]
        assert "--force" not in captured["command"]
        result = json.loads(posted_response(listener).output)
        assert result["ok"] is True
        assert result["dry_run"] is True
