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
            output="x" * 5000, payload=payload,
        )
        result = json.loads(raw)
        assert result["verb"] == "certbot_renew"
        assert result["ok"] is False
        assert result["exit_code"] == 1
        assert result["dry_run"] is True
        assert result["cert_name"] == "example.com"
        assert len(result["output_tail"]) == 2000


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
        assert request.payload["command"].startswith(
            "sudo -n certbot renew --cert-name example.com",
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
        assert response.status == "error"
        # No valid marker → transport-failure classification.
        assert response.error_message.startswith(
            "remediation_transport_failed:",
        )

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
        assert response.status == "error"
        assert response.error_message.startswith("certbot_renew_failed:")
        assert "exit 1" in response.error_message
        # Structured evidence still attached for the server.
        assert json.loads(response.output)["ok"] is False

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
        assert response.status == "error"
        assert response.error_message.startswith("remediation_timeout:")

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
