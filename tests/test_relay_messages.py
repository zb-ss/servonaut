"""Tests for relay message DTOs (CommandType, CommandRequest, CommandResponse)."""
from __future__ import annotations

import dataclasses

import pytest

from servonaut.models.relay_messages import CommandRequest, CommandResponse, CommandType


class TestCommandTypeEnum:
    def test_has_run_command(self):
        assert CommandType.RUN_COMMAND == "run_command"

    def test_has_get_logs(self):
        assert CommandType.GET_LOGS == "get_logs"

    def test_has_transfer_file(self):
        assert CommandType.TRANSFER_FILE == "transfer_file"

    def test_has_deploy(self):
        assert CommandType.DEPLOY == "deploy"

    def test_has_provision_plan(self):
        assert CommandType.PROVISION_PLAN == "provision_plan"

    def test_has_provision_apply(self):
        assert CommandType.PROVISION_APPLY == "provision_apply"

    def test_has_cost_report(self):
        assert CommandType.COST_REPORT == "cost_report"

    def test_has_security_scan(self):
        assert CommandType.SECURITY_SCAN == "security_scan"

    def test_all_expected_values_present(self):
        expected = {
            "run_command",
            "get_logs",
            "transfer_file",
            "deploy",
            "provision_plan",
            "provision_apply",
            "cost_report",
            "security_scan",
        }
        actual = {member.value for member in CommandType}
        assert actual == expected

    def test_is_str_subclass(self):
        # CommandType must be a str enum so values are JSON-serializable
        assert issubclass(CommandType, str)

    def test_str_value_usable_in_json(self):
        import json
        # Direct use of enum value as string — no special encoding needed
        serialized = json.dumps({"type": CommandType.RUN_COMMAND})
        assert '"run_command"' in serialized

    def test_constructible_from_string(self):
        assert CommandType("run_command") is CommandType.RUN_COMMAND
        assert CommandType("get_logs") is CommandType.GET_LOGS

    def test_equality_with_string(self):
        assert CommandType.RUN_COMMAND == "run_command"
        assert CommandType.GET_LOGS == "get_logs"


class TestCommandRequest:
    def _make_request(self, **kwargs):
        defaults = dict(
            id="req-001",
            user_id="user-123",
            type=CommandType.RUN_COMMAND,
            target_server_id="i-abc123",
        )
        defaults.update(kwargs)
        return CommandRequest(**defaults)

    def test_required_fields_construction(self):
        req = self._make_request()
        assert req.id == "req-001"
        assert req.user_id == "user-123"
        assert req.type == CommandType.RUN_COMMAND
        assert req.target_server_id == "i-abc123"

    def test_payload_defaults_to_empty_dict(self):
        req = self._make_request()
        assert req.payload == {}

    def test_ttl_defaults_to_60(self):
        req = self._make_request()
        assert req.ttl_seconds == 60

    def test_explicit_payload(self):
        req = self._make_request(payload={"command": "ls -la"})
        assert req.payload == {"command": "ls -la"}

    def test_explicit_ttl(self):
        req = self._make_request(ttl_seconds=120)
        assert req.ttl_seconds == 120

    def test_type_can_be_any_command_type(self):
        for cmd_type in CommandType:
            req = self._make_request(type=cmd_type)
            assert req.type == cmd_type

    def test_payload_is_independent_per_instance(self):
        # Mutable default_factory: each instance gets its own dict
        req1 = self._make_request()
        req2 = self._make_request()
        req1.payload["key"] = "value"
        assert req2.payload == {}

    def test_asdict_produces_expected_structure(self):
        req = self._make_request(
            id="req-42",
            user_id="usr-7",
            type=CommandType.GET_LOGS,
            target_server_id="i-server",
            payload={"log_path": "/var/log/syslog"},
            ttl_seconds=90,
        )
        result = dataclasses.asdict(req)
        assert result == {
            "id": "req-42",
            "user_id": "usr-7",
            "type": "get_logs",
            "target_server_id": "i-server",
            "payload": {"log_path": "/var/log/syslog"},
            "ttl_seconds": 90,
        }

    def test_asdict_type_value_is_string(self):
        req = self._make_request(type=CommandType.DEPLOY)
        result = dataclasses.asdict(req)
        assert result["type"] == "deploy"
        assert isinstance(result["type"], str)


class TestCommandResponse:
    def test_required_fields_construction(self):
        resp = CommandResponse(request_id="req-001", status="success")
        assert resp.request_id == "req-001"
        assert resp.status == "success"

    def test_output_defaults_to_empty_string(self):
        resp = CommandResponse(request_id="req-001", status="success")
        assert resp.output == ""

    def test_error_message_defaults_to_empty_string(self):
        resp = CommandResponse(request_id="req-001", status="success")
        assert resp.error_message == ""

    def test_execution_time_ms_defaults_to_zero(self):
        resp = CommandResponse(request_id="req-001", status="success")
        assert resp.execution_time_ms == 0

    def test_all_status_values_accepted(self):
        for status in ("success", "error", "timeout", "rejected"):
            resp = CommandResponse(request_id="r", status=status)
            assert resp.status == status

    def test_explicit_fields(self):
        resp = CommandResponse(
            request_id="req-99",
            status="error",
            output="some output",
            error_message="connection refused",
            execution_time_ms=250,
        )
        assert resp.output == "some output"
        assert resp.error_message == "connection refused"
        assert resp.execution_time_ms == 250

    def test_asdict_produces_expected_structure(self):
        resp = CommandResponse(
            request_id="req-99",
            status="success",
            output="hello world",
            error_message="",
            execution_time_ms=42,
        )
        result = dataclasses.asdict(resp)
        assert result == {
            "request_id": "req-99",
            "status": "success",
            "output": "hello world",
            "error_message": "",
            "execution_time_ms": 42,
        }

    def test_asdict_with_defaults(self):
        resp = CommandResponse(request_id="r", status="timeout")
        result = dataclasses.asdict(resp)
        assert result["output"] == ""
        assert result["error_message"] == ""
        assert result["execution_time_ms"] == 0
