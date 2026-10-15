"""Data models for Mercure relay messaging."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class CommandType(str, Enum):
    RUN_COMMAND = "run_command"
    GET_LOGS = "get_logs"
    TRANSFER_FILE = "transfer_file"
    DEPLOY = "deploy"
    PROVISION_PLAN = "provision_plan"
    PROVISION_APPLY = "provision_apply"
    COST_REPORT = "cost_report"
    SECURITY_SCAN = "security_scan"


@dataclass
class CommandRequest:
    """Inbound command request received from the Mercure hub."""
    id: str
    user_id: str
    type: CommandType
    target_server_id: str
    payload: dict = field(default_factory=dict)
    ttl_seconds: int = 60
    # Set only by a local caller that composes the command itself (a log
    # read, a remediation): what was asked for, in plain words, so a
    # refusal names that rather than the internal command. Never read
    # from a hub event.
    requested_as: str = ""


@dataclass
class CommandResponse:
    """Outbound result posted back to the backend after execution."""
    request_id: str
    status: str          # success | error | timeout | rejected
    output: str = ""
    error_message: str = ""
    execution_time_ms: int = 0
