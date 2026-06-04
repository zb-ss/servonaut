"""Run shell commands on an EC2 instance via AWS Systems Manager (SSM).

Backs the ``transport=ssm`` path of ``run_command``. The single biggest
blocker in the incident was sshd refusing connections at load 700+ — there was
no way to apply the fix. SSM rides the instance's *outbound* agent channel, so
it works even when sshd can't accept inbound connections.

Prerequisites (documented for the operator, enforced by AWS at call time):
- The target instance runs the SSM agent and has an instance profile granting
  ``AmazonSSMManagedInstanceCore``.
- The CLI's AWS identity has ``ssm:SendCommand`` + ``ssm:GetCommandInvocation``.

Like the other AWS services here, boto3 runs in a thread (``run_in_executor``)
and the service never raises out of :meth:`run_command` — failures come back as
a structured dict so the caller can decide whether to surface or fall through.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict

import boto3

logger = logging.getLogger(__name__)

# Statuses that mean the invocation is finished (success or otherwise).
_TERMINAL = {"Success", "Cancelled", "TimedOut", "Failed"}

# How long stdout/stderr we surface (SSM inline output caps at 24000 chars; we
# stay well under and let the caller's own max-lines clamp apply on top).
_MAX_OUTPUT = 24000


class SSMService:
    """Execute commands on EC2 instances over the SSM agent channel."""

    async def run_command(
        self, instance_id: str, command: str,
        region: str = "", timeout: int = 60,
    ) -> Dict[str, Any]:
        """Send *command* via SSM and poll for the result.

        Returns a dict: ``{ok: bool, status: str, stdout: str, stderr: str,
        error: str}``. ``ok`` is True only when the invocation reached
        ``Success``. ``error`` is set for setup failures (instance not
        SSM-managed, access denied, timeout waiting for the result).
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._run_sync, instance_id, command, region, timeout,
        )

    def _run_sync(
        self, instance_id: str, command: str, region: str, timeout: int,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "ok": False, "status": "", "stdout": "", "stderr": "", "error": "",
        }
        kwargs = {"region_name": region} if region else {}
        try:
            ssm = boto3.client("ssm", **kwargs)
        except Exception as exc:  # noqa: BLE001
            result["error"] = f"ssm client: {exc}"
            return result

        try:
            send = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [command]},
                TimeoutSeconds=max(30, min(int(timeout), 2592000)),
            )
        except Exception as exc:  # noqa: BLE001
            # InvalidInstanceId = not SSM-managed (no agent / no instance role);
            # AccessDenied = missing ssm:SendCommand. Both surface verbatim.
            result["error"] = f"send_command: {exc}"
            return result

        command_id = send.get("Command", {}).get("CommandId", "")
        if not command_id:
            result["error"] = "send_command returned no CommandId"
            return result

        deadline = time.monotonic() + max(10, int(timeout))
        poll_interval = 1.0
        while True:
            try:
                inv = ssm.get_command_invocation(
                    CommandId=command_id, InstanceId=instance_id,
                )
            except Exception as exc:  # noqa: BLE001
                # InvocationDoesNotExist is expected briefly after send_command
                # (eventual consistency) — keep polling until the deadline.
                if "InvocationDoesNotExist" in str(exc) and time.monotonic() < deadline:
                    time.sleep(poll_interval)
                    continue
                result["error"] = f"get_command_invocation: {exc}"
                return result

            status = inv.get("Status", "")
            result["status"] = status
            if status in _TERMINAL:
                result["stdout"] = (inv.get("StandardOutputContent", "") or "")[:_MAX_OUTPUT]
                result["stderr"] = (inv.get("StandardErrorContent", "") or "")[:_MAX_OUTPUT]
                result["ok"] = status == "Success"
                if not result["ok"] and not result["error"]:
                    result["error"] = f"command status: {status}"
                return result

            if time.monotonic() >= deadline:
                result["error"] = f"timed out waiting for SSM result (last status: {status or 'pending'})"
                return result
            time.sleep(poll_interval)
