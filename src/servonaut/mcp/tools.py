"""MCP tool implementations for Servonaut."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import secrets
import shlex
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional

from servonaut.utils.ssh_utils import run_ssh_subprocess

logger = logging.getLogger(__name__)


# Headers agents may override on api_request. Everything else is dropped
# silently so the bearer / cookies / custom X-* cannot be smuggled through.
_ALLOWED_REQUEST_HEADERS = frozenset({
    "accept", "content-type", "accept-language", "if-none-match",
})

# Response bodies > 1 MiB are refused — agents should not be hoovering large
# payloads through the CLI.
_MAX_RESPONSE_BYTES = 1024 * 1024

# CLI-side sliding-window rate limit for api_request.
_API_REQUEST_WINDOW_SECONDS = 60.0
_API_REQUEST_MAX_PER_WINDOW = 30

# Supported object-storage providers — single source of truth for validation.
_S3_PROVIDERS: frozenset = frozenset({"aws", "hetzner", "ovh"})

# Short-lived per-(provider, instance_id) memo of Bitwarden ssh-ref lookups
# (positive AND negative results). Fleet-wide tools resolve connections once
# per instance per call; without the memo every SSH-backed tool call pays an
# uncached backend GET — and, when the API is degraded, its full HTTP timeout.
# Internal coalescing window, not an ops-tunable: key material is still
# resolved and wiped per call, only the opaque ref pointer is memoized.
_BW_REF_MEMO_TTL_SECONDS = 60.0

# --- aws_call passthrough -------------------------------------------------
# boto3 operation names are snake_case (describe_security_group_rules, get_ip_set,
# filter_log_events, …). These prefixes mark a call as a read; reads run at the
# readonly guard tier (IAM is the real backstop). Anything else is "mutating".
_AWS_READ_PREFIXES = (
    "describe_", "get_", "list_", "filter_", "lookup_",
    "head_", "batch_get_", "search_",
)
# Destructive verbs. Refused by default; allowed via aws_call ONLY when
# MCPConfig.allow_destructive_aws_call is on, and then only behind the dangerous
# tier + mutate=true + a mandatory two-phase confirmation token.
_AWS_DESTRUCTIVE_PREFIXES = ("delete_", "terminate_", "destroy_", "purge_")
# Never-allow floor: the most unrecoverable ops stay refused via aws_call even
# when allow_destructive_aws_call is on. These cause irreversible data/fleet
# loss with no generic undo — route them through a curated tool or the console
# where the snapshot/retention semantics are explicit.
_AWS_NEVER_DESTRUCTIVE = frozenset({
    "delete_bucket",            # S3 bucket
    "delete_object", "delete_objects",  # S3 data
    "delete_db_instance", "delete_db_cluster",  # RDS (snapshot nuance unenforceable here)
    "delete_db_snapshot", "delete_cluster_snapshot", "delete_snapshot",  # backups
    "delete_volume",            # EBS
    "delete_file_system",       # EFS
    "delete_table",             # DynamoDB
})
# A destructive confirmation token is single-use and expires after this long.
_AWS_CONFIRM_TTL_SECONDS = 300
_AWS_SERVICE_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_AWS_OPERATION_RE = re.compile(r"^[a-z][a-z0-9_]{1,127}$")
# Cap a single aws_call result so an over-broad Describe can't flood the model
# context. Reads auto-paginate up to this many items when no max_items is given.
_AWS_CALL_MAX_RESULT_CHARS = 200_000
_AWS_CALL_DEFAULT_MAX_ITEMS = 1000


def _error(code: str, message: str) -> Dict[str, Any]:
    """Uniform error envelope for api_request failures."""
    return {"error": {"code": code, "message": message}}


def _sanitize_response_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Drop any header that could leak auth material back to the agent."""
    sensitive = {
        "authorization", "proxy-authorization", "set-cookie", "cookie",
        "www-authenticate",
    }
    return {k: v for k, v in headers.items() if k.lower() not in sensitive}


class ServonautTools:
    """Implements all MCP tools using Servonaut services."""

    def __init__(self, config_manager, aws_service, custom_server_service,
                 cache_service, ssh_service, connection_service, scp_service,
                 guard, audit, ovh_service=None,
                 ovh_monitoring_service=None, ovh_ip_service=None,
                 ovh_snapshot_service=None, ovh_dns_service=None,
                 ovh_billing_service=None, ovh_cloud_service=None,
                 hetzner_service=None,
                 cloudtrail_service=None, cloudwatch_service=None,
                 ip_ban_service=None,
                 aws_client_factory=None,
                 auth_service=None, memory_service=None,
                 aws_object_storage_service=None,
                 hetzner_object_storage_service=None,
                 ovh_object_storage_service=None,
                 secret_provider=None,
                 ip_enrichment_service=None,
                 bw_ssh_config_service=None) -> None:
        self._config_manager = config_manager
        self._aws_service = aws_service
        self._custom_server_service = custom_server_service
        self._cache_service = cache_service
        self._ssh_service = ssh_service
        self._connection_service = connection_service
        self._scp_service = scp_service
        self._guard = guard
        self._audit = audit
        self._ovh_service = ovh_service
        self._ovh_monitoring_service = ovh_monitoring_service
        self._ovh_ip_service = ovh_ip_service
        self._ovh_snapshot_service = ovh_snapshot_service
        self._ovh_dns_service = ovh_dns_service
        self._ovh_billing_service = ovh_billing_service
        self._ovh_cloud_service = ovh_cloud_service
        self._hetzner_service = hetzner_service
        self._cloudtrail_service = cloudtrail_service
        self._cloudwatch_service = cloudwatch_service
        self._ip_ban_service = ip_ban_service
        # Shared boto3 client factory (STS control-plane role / region pinning).
        # Lazily built from config on first aws_call use when not injected, so
        # the 4 minimal construction sites don't all need updating.
        self._aws_client_factory = aws_client_factory
        self._auth_service = auth_service
        self._memory_service = memory_service
        self._aws_object_storage_service = aws_object_storage_service
        self._hetzner_object_storage_service = hetzner_object_storage_service
        self._ovh_object_storage_service = ovh_object_storage_service
        # Active secret store (LocalProvider / BitwardenProvider / None) used
        # to resolve DB passwords for db_processlist / db_top_queries. None
        # when unauthenticated or not entitled — those tools then error clearly.
        self._secret_provider = secret_provider
        # IP enrichment (rDNS / ASN / abuse) for enrich_ips. Lazily built if
        # not injected so the tool works even in minimal construction sites.
        self._ip_enrichment_service = ip_enrichment_service
        # Bitwarden SSH-ref client (personal tier). None → SSH tools resolve
        # keys from local sources only, byte-for-byte the historical behavior.
        self._bw_ssh_config_service = bw_ssh_config_service
        # (provider, instance_id) -> (monotonic_expiry, ref-or-None). See
        # _BW_REF_MEMO_TTL_SECONDS — holds opaque ref pointers, never keys.
        self._bw_ref_memo: Dict[tuple, tuple] = {}
        self._max_lines = config_manager.get().mcp.max_output_lines
        self._api_request_window: Deque[float] = deque()
        # Server-side staging for db_setup_scan → db_setup_save. Holds plaintext
        # DBCandidate objects keyed by an opaque token so the secret is committed
        # to the secret store WITHOUT ever entering a tool result / model context.
        self._db_staging: Dict[str, Any] = {}
        # Server-side staging for the aws_call destructive two-phase confirm.
        # token -> {signature, expires_at}. The op cannot execute until a second
        # call echoes a token whose signature matches the exact call.
        self._aws_confirm_staging: Dict[str, Dict[str, Any]] = {}

    @property
    def config_manager(self):
        """Expose the config manager so external adapters (e.g. chat) can
        reuse our MCP config without reaching into private attributes."""
        return self._config_manager

    # Capability flags — public so construction sites (MCP server, relay
    # AI-tool executor) can gate tool listings without reaching into
    # private attributes.

    @property
    def has_ovh(self) -> bool:
        return self._ovh_service is not None

    @property
    def has_hetzner(self) -> bool:
        return self._hetzner_service is not None

    @property
    def has_ip_ban(self) -> bool:
        return self._ip_ban_service is not None

    @property
    def has_memory(self) -> bool:
        return self._memory_service is not None

    def set_secret_provider(self, provider) -> None:
        """Bind/rebind the active secret store used by the DB tools.

        Mirrors :meth:`SSHService.set_secret_provider` — the app resolves the
        provider after the tools are constructed (and again on login / plan
        change), so it's pushed in rather than passed at construction time.
        ``None`` is valid (unauthenticated / Free tier); the DB tools then
        return a clear "log in" error when a profile references a secret.
        """
        self._secret_provider = provider

    def set_bw_ssh_config_service(self, service) -> None:
        """Bind/rebind the Bitwarden SSH-ref client after construction.

        Mirrors :meth:`set_secret_provider` — the TUI builds the shared
        ``ServonautTools`` instance BEFORE the authenticated ``APIClient``
        exists, so the app pushes the service in once sign-in wiring
        completes. This keeps vault-backed SSH resolution identical across
        all tool surfaces (in-TUI chat, standalone MCP server, relay
        listener). ``None`` is valid (signed out / not entitled) — SSH tools
        then resolve keys from local sources only.

        Rebinding clears the ssh-ref memo so entries resolved (or negatively
        memoized) under the previous binding cannot bleed into the new one.
        """
        self._bw_ssh_config_service = service
        self._bw_ref_memo.clear()

    async def list_instances(self, region: str = "", state: str = "") -> str:
        """List all managed instances (AWS EC2 + custom servers), optionally filtered."""
        allowed, reason = self._guard.check_tool('list_instances')
        if not allowed:
            self._audit.log('list_instances', {'region': region, 'state': state}, '', False, reason)
            return f"Blocked: {reason}"

        aws_instances = await self._aws_service.fetch_instances_cached()
        custom_instances = self._custom_server_service.list_as_instances()
        ovh_instances = (
            await self._ovh_service.fetch_instances_cached()
            if self._ovh_service is not None
            else []
        )
        hetzner_instances = (
            await self._hetzner_service.fetch_instances_cached()
            if self._hetzner_service is not None
            else []
        )
        instances = (
            aws_instances + custom_instances + ovh_instances + hetzner_instances
        )
        if region:
            instances = [i for i in instances if i.get('region') == region]
        if state:
            instances = [i for i in instances if i.get('state') == state]

        result = self._format_instances(instances)
        self._audit.log('list_instances', {'region': region, 'state': state}, result, True)
        return result

    async def run_command(
        self, instance_id: str, command: str, transport: str = "auto",
    ) -> str:
        """Run a command on a managed instance.

        ``transport`` (additive, default ``auto``):
          - ``ssh``  — SSH only (the classic path).
          - ``ssm``  — AWS Systems Manager only (rides the agent's OUTBOUND
            channel; works when sshd refuses inbound, e.g. under heavy load).
          - ``auto`` — try SSH; if the SSH *connection* fails (refused /
            timed out / unreachable) and the instance is AWS + SSM-managed,
            fall back to SSM. The result is annotated with which channel won.
        """
        args = {
            'instance_id': instance_id, 'command': command, 'transport': transport,
        }
        allowed, reason = self._guard.check_tool('run_command')
        if not allowed:
            self._audit.log('run_command', args, '', False, reason)
            return f"Blocked: {reason}"

        cmd_allowed, cmd_reason = self._guard.check_command(command)
        if not cmd_allowed:
            self._audit.log('run_command', args, '', False, cmd_reason)
            return f"Blocked: {cmd_reason}"

        instance = await self._find_instance(instance_id)
        if not instance:
            self._audit.log('run_command', args, '', False, 'instance_not_found')
            return f"Instance not found: {instance_id}"

        transport = (transport or "auto").strip().lower()
        if transport not in ("auto", "ssh", "ssm"):
            self._audit.log('run_command', args, '', False, 'bad_transport')
            return f"Error: transport must be 'auto', 'ssh', or 'ssm'; got {transport!r}."

        is_aws = not (
            instance.get('is_custom') or instance.get('is_ovh')
            or instance.get('is_hetzner')
        )

        # --- SSM-only transport ----------------------------------------
        if transport == "ssm":
            if not is_aws:
                self._audit.log('run_command', args, '', False, 'ssm_non_aws')
                return "Error: transport='ssm' is AWS-only (Systems Manager)."
            return await self._run_command_via_ssm(instance, command, args)

        # --- SSH (ssh / auto) ------------------------------------------
        output, conn_failed, timed_out, key_source = await self._run_command_via_ssh(
            instance, command,
        )
        # Audit extra only when the vault key was used — local-key rows keep
        # their existing shape (no churn for the common case).
        key_extras = {'key_source': key_source} if key_source else {}

        # A command timeout means the host WAS reachable — the command simply
        # ran past the budget. Surface the message and stop; no SSM fallback.
        if timed_out:
            self._audit.log(
                'run_command', args, '', False, 'command_timeout', **key_extras,
            )
            return output  # already contains the human-readable timeout message

        if not conn_failed:
            result = f"{output}\n[transport_used: ssh]"
            self._audit.log('run_command', args, result, True, **key_extras)
            return result

        # SSH connection failed (host not reachable / sshd refused).
        if transport == "ssh":
            msg = (
                "Error: SSH connection failed (host not reachable / sshd "
                "refused). If the instance is AWS + SSM-managed, retry with "
                "transport='ssm'."
            )
            self._audit.log(
                'run_command', args, '', False, 'ssh_conn_failed', **key_extras,
            )
            return msg

        # transport == auto → fall back to SSM when possible.
        if not is_aws:
            self._audit.log(
                'run_command', args, '', False, 'ssh_conn_failed_non_aws',
                **key_extras,
            )
            return (
                "Error: SSH connection failed and SSM fallback is AWS-only "
                "(non-AWS instance)."
            )
        return await self._run_command_via_ssm(
            instance, command, args, ssh_fell_back=True,
        )

    def _is_ssh_connection_failure(self, stderr_text: str) -> bool:
        """True if stderr looks like a CONNECTION-level SSH failure.

        Distinguishes "sshd unreachable" (worth an SSM fallback) from a
        command that ran but exited non-zero, or an auth/config error (which
        SSM can't fix and shouldn't mask).
        """
        low = stderr_text.lower()
        signatures = (
            "connection refused", "connection timed out", "operation timed out",
            "connection reset", "connection closed", "no route to host",
            "network is unreachable", "could not resolve hostname",
            "connect to host", "timed out waiting",
        )
        return any(sig in low for sig in signatures)

    async def _run_command_via_ssh(self, instance: Dict, command: str):
        """Run via SSH. Returns (output_or_msg, connection_failed, timed_out,
        key_source).

        Three distinct outcomes (``key_source`` is ``'bw_personal'`` when the
        key came from a Bitwarden ref, else ``None`` — carried so the caller
        can tag its audit row):
          - Success:          (output_str, False, False, key_source)
          - Command timeout:  (timeout_msg, False, True, key_source)  — host
                              IS reachable; the caller must NOT trigger SSM
                              fallback.
          - Connection error: (None, True, False, key_source) — sshd
                              unreachable; caller may fall back to SSM when
                              available.
        """
        conn, cleanup = await self._resolve_connection_with_vault(instance)
        key_source = conn.get('key_source')
        # Everything after the vault key hits disk runs INSIDE the try so the
        # finally deletes the temp key even when the command builder or a
        # config read raises (matches transfer_file's pattern).
        timeout = 0
        try:
            ssh_cmd = self._ssh_service.build_ssh_command(
                host=conn['host'], username=conn['username'], key_path=conn['key_path'],
                proxy_args=conn['proxy_args'], remote_command=command,
                port=conn.get('port'),
                extra_options=conn.get('extra_options') or [],
            )
            timeout = self._config_manager.get().mcp.command_timeout_seconds
            stdout, stderr = await run_ssh_subprocess(ssh_cmd, timeout=timeout)
        except asyncio.TimeoutError:
            # The SSH connection itself was alive (keepalives kept it open);
            # the *command* simply ran longer than the allowed budget.
            # Surface a clear message and do NOT signal a connection failure —
            # the caller must not trigger SSM fallback for a timeout.
            msg = (
                f"command timed out after {timeout}s "
                f"(host reachable; raise mcp.command_timeout_seconds for long ops)"
            )
            return (msg, False, True, key_source)
        except Exception as e:  # noqa: BLE001
            return (f"Error: {e}", False, False, key_source)
        finally:
            # Per-call vault-key lifecycle: the MCP server is long-running,
            # so the temp key must not outlive this subprocess.
            if cleanup is not None:
                await cleanup()

        stderr_text = stderr.decode('utf-8', errors='replace') if stderr else ""
        # Empty stdout + a connection signature in stderr → sshd unreachable.
        if not stdout and self._is_ssh_connection_failure(stderr_text):
            return (None, True, False, key_source)

        output = stdout.decode('utf-8', errors='replace')
        lines = output.split('\n')
        if len(lines) > self._max_lines:
            output = '\n'.join(lines[:self._max_lines]) + f'\n... (truncated, {len(lines)} total lines)'
        if stderr_text:
            output += f"\nSTDERR:\n{stderr_text}"
        return (output, False, False, key_source)

    async def _run_command_via_ssm(
        self, instance: Dict, command: str, args: Dict, ssh_fell_back: bool = False,
    ) -> str:
        """Run via AWS SSM. Returns formatted output (already audited)."""
        from servonaut.services.ssm_service import SSMService
        prefix = "[SSH unreachable — fell back to SSM]\n" if ssh_fell_back else ""
        region = instance.get('region') or ''
        aws_id = instance.get('id', '')
        try:
            res = await SSMService().run_command(
                aws_id, command, region=region, timeout=60,
            )
        except Exception as e:  # noqa: BLE001
            self._audit.log('run_command', args, '', False, f"ssm_error: {e}")
            return f"{prefix}Error (SSM): {e}"

        if not res.get("ok"):
            err = res.get("error") or f"status {res.get('status', '?')}"
            out = f"{prefix}Error (SSM): {err}"
            if res.get("stderr"):
                out += f"\nSTDERR:\n{res['stderr']}"
            self._audit.log('run_command', args, '', False, f"ssm: {err}")
            return out

        output = res.get("stdout", "")
        lines = output.split('\n')
        if len(lines) > self._max_lines:
            output = '\n'.join(lines[:self._max_lines]) + f'\n... (truncated, {len(lines)} total lines)'
        if res.get("stderr"):
            output += f"\nSTDERR:\n{res['stderr']}"
        result = f"{prefix}{output}\n[transport_used: ssm]"
        self._audit.log('run_command', args, result, True)
        return result

    async def get_logs(self, instance_id: str, log_path: str = "/var/log/syslog", lines: int = 100) -> str:
        """Get log content from remote instance."""
        return await self.run_command(instance_id, f"tail -n {lines} {log_path}")

    async def check_status(self, instance_id: str) -> str:
        """Get instance status (state, IPs, type, region)."""
        allowed, reason = self._guard.check_tool('check_status')
        if not allowed:
            self._audit.log('check_status', {'instance_id': instance_id}, '', False, reason)
            return f"Blocked: {reason}"

        instance = await self._find_instance(instance_id)
        if not instance:
            return f"Instance not found: {instance_id}"

        lines = [
            f"Instance:   {instance.get('id', '')}",
            f"Name:       {instance.get('name', '')}",
            f"State:      {instance.get('state', '')}",
            f"Type:       {instance.get('type', '')}",
            f"Region:     {instance.get('region', '')}",
            f"Public IP:  {instance.get('public_ip') or '-'}",
            f"Private IP: {instance.get('private_ip') or '-'}",
            f"Key Name:   {instance.get('key_name') or '-'}",
        ]
        result = '\n'.join(lines)
        self._audit.log('check_status', {'instance_id': instance_id}, result, True)
        return result

    async def get_server_info(self, instance_id: str) -> str:
        """Get detailed server info (hostname, uptime, disk, memory)."""
        allowed, reason = self._guard.check_tool('get_server_info')
        if not allowed:
            self._audit.log('get_server_info', {'instance_id': instance_id}, '', False, reason)
            return f"Blocked: {reason}"

        command = "hostname && uptime && df -h && free -m"
        # Bypass guard check since these are safe info commands, but must bypass
        # the standard-mode allowlist. We call run_command directly but need to
        # temporarily allow compound commands in dangerous-equivalent mode.
        # Instead, execute via SSH directly to avoid double guard checking.
        instance = await self._find_instance(instance_id)
        if not instance:
            return f"Instance not found: {instance_id}"

        conn, cleanup = await self._resolve_connection_with_vault(instance)
        key_extras = (
            {'key_source': conn['key_source']} if conn.get('key_source') else {}
        )

        # Command build + config read stay INSIDE the try — an exception there
        # must still trigger the temp-key cleanup in the finally.
        timeout = 0
        try:
            ssh_cmd = self._ssh_service.build_ssh_command(
                host=conn['host'], username=conn['username'], key_path=conn['key_path'],
                proxy_args=conn['proxy_args'], remote_command=command,
                port=conn.get('port'),
                extra_options=conn.get('extra_options') or [],
            )
            timeout = self._config_manager.get().mcp.command_timeout_seconds
            stdout, stderr = await run_ssh_subprocess(ssh_cmd, timeout=timeout)
        except asyncio.TimeoutError:
            # Every early return writes an audit row with a distinct reason
            # code; key_extras carries key_source so vault-key-backed failures
            # stay traceable in mcp_audit.jsonl (mirrors run_command).
            self._audit.log(
                'get_server_info', {'instance_id': instance_id}, '', False,
                'command_timeout', **key_extras,
            )
            return (
                f"command timed out after {timeout}s "
                f"(host reachable; raise mcp.command_timeout_seconds for long ops)"
            )
        except Exception as e:
            self._audit.log(
                'get_server_info', {'instance_id': instance_id}, '', False,
                f"ssh_error: {e}", **key_extras,
            )
            return f"Error: {e}"
        finally:
            if cleanup is not None:
                await cleanup()

        output = stdout.decode('utf-8', errors='replace')
        if stderr:
            output += f"\nSTDERR:\n{stderr.decode('utf-8', errors='replace')}"

        self._audit.log(
            'get_server_info', {'instance_id': instance_id}, output, True,
            **key_extras,
        )
        return output

    async def transfer_file(self, instance_id: str, local_path: str, remote_path: str, direction: str = "download") -> str:
        """Transfer file via SCP."""
        allowed, reason = self._guard.check_tool('transfer_file')
        if not allowed:
            self._audit.log('transfer_file', {
                'instance_id': instance_id, 'local_path': local_path,
                'remote_path': remote_path, 'direction': direction,
            }, '', False, reason)
            return f"Blocked: {reason}"

        instance = await self._find_instance(instance_id)
        if not instance:
            return f"Instance not found: {instance_id}"

        conn, cleanup = await self._resolve_connection_with_vault(instance)
        # Everything after the vault key hits disk runs INSIDE the try so the
        # finally deletes the temp key even when a conn read, the proxy-jump
        # lookup, or the command builder raises (matches
        # _run_command_via_ssh / get_server_info / _exec_ssh).
        try:
            host = conn['host']
            username = conn['username']
            key_path = conn['key_path']
            proxy_args = conn['proxy_args']
            profile = conn['profile']
            port = conn.get('port')
            extra_options = conn.get('extra_options') or []
            key_extras = (
                {'key_source': conn['key_source']} if conn.get('key_source') else {}
            )

            proxy_jump = self._connection_service.get_proxy_jump_string(profile) if profile else None

            if direction == "upload":
                scp_cmd = self._scp_service.build_upload_command(
                    local_path=local_path, remote_path=remote_path,
                    host=host, username=username, key_path=key_path,
                    proxy_jump=proxy_jump, proxy_args=proxy_args or None,
                    port=port,
                    extra_options=extra_options,
                )
            else:
                scp_cmd = self._scp_service.build_download_command(
                    remote_path=remote_path, local_path=local_path,
                    host=host, username=username, key_path=key_path,
                    proxy_jump=proxy_jump, proxy_args=proxy_args or None,
                    port=port,
                    extra_options=extra_options,
                )

            returncode, stdout, stderr = await self._scp_service.execute_transfer(scp_cmd)
        finally:
            if cleanup is not None:
                await cleanup()

        if returncode == 0:
            result = f"Transfer successful: {direction} complete"
            if stdout:
                result += f"\n{stdout}"
        else:
            result = f"Transfer failed (exit {returncode})"
            if stderr:
                result += f"\n{stderr}"

        self._audit.log('transfer_file', {
            'instance_id': instance_id, 'local_path': local_path,
            'remote_path': remote_path, 'direction': direction,
        }, result, returncode == 0, **key_extras)
        return result

    async def ovh_monitoring(self, instance_id: str, period: str = "lastday") -> str:
        """Get CPU/RAM/network monitoring data for an OVH instance."""
        if self._ovh_monitoring_service is None:
            return "Error: OVH monitoring service is not available. Ensure OVH is configured and enabled."

        instance = await self._find_instance(instance_id)
        if not instance:
            return f"Instance not found: {instance_id}"

        provider_type = instance.get('provider_type', '')
        if not provider_type and self._ovh_service is not None:
            # Custom-server entries (e.g. an OVH VPS registered manually)
            # carry no provider_type, so route via the discovered OVH
            # inventory instead — matched by public IP, then name.
            correlated = await self._correlate_ovh_instance(instance)
            if correlated is not None:
                instance = correlated
                provider_type = instance.get('provider_type', '')

        name = instance.get('id', '') or instance.get('name', '')

        try:
            if provider_type == 'vps':
                data = await self._ovh_monitoring_service.get_vps_monitoring(name, period)
                lines = [f"VPS Monitoring: {name} (period={period})"]
                for metric, series in data.items():
                    if series:
                        last = series[-1]
                        lines.append(f"  {metric}: latest={last.get('value')} (at {last.get('timestamp')})")
                    else:
                        lines.append(f"  {metric}: no data")
            elif provider_type == 'dedicated':
                data = await self._ovh_monitoring_service.get_dedicated_monitoring(name, period)
                lines = [f"Dedicated Server Monitoring: {name} (period={period})"]
                for metric, series in data.items():
                    if series:
                        last = series[-1]
                        lines.append(f"  {metric}: latest={last.get('value')} (at {last.get('timestamp')})")
                    else:
                        lines.append(f"  {metric}: no data")
            else:
                # Public Cloud instance: needs project_id
                project_id = instance.get('project_id', '')
                if not project_id:
                    if not provider_type:
                        # Uncorrelated custom entry — explain what the
                        # tool supports instead of a bare project_id error.
                        return (
                            f"Error: Cannot determine the OVH product type "
                            f"for {instance_id}. ovh_monitoring supports "
                            f"OVH VPS, dedicated, and Public Cloud "
                            f"instances discovered via the OVH API. If "
                            f"this server is a custom entry, enable the "
                            f"matching OVH discovery (include_vps / "
                            f"include_dedicated / include_cloud) and make "
                            f"sure its public IP or name matches the OVH "
                            f"service so it can be correlated. Note: a "
                            f"custom entry whose host is a DNS name rather "
                            f"than an IPv4 address never matches by IP — "
                            f"set host to the server's primary IPv4 or "
                            f"align the entry name with the discovered "
                            f"service name."
                        )
                    return f"Error: Cannot determine project_id for instance {instance_id}. Provider type: {provider_type!r}"
                data = await self._ovh_monitoring_service.get_cloud_monitoring(project_id, name, period)
                lines = [f"Cloud Instance Monitoring: {name} (project={project_id}, period={period})"]
                for metric, series in data.items():
                    if series:
                        last = series[-1]
                        lines.append(f"  {metric}: latest={last.get('value')} (at {last.get('timestamp')})")
                    else:
                        lines.append(f"  {metric}: no data")
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Error fetching monitoring data: {e}"

        return '\n'.join(lines)

    async def ovh_list_ips(self) -> str:
        """List all IPs on the OVH account with type and routing info."""
        if self._ovh_ip_service is None:
            return "Error: OVH IP service is not available. Ensure OVH is configured and enabled."

        try:
            ips = await self._ovh_ip_service.list_ips()
        except Exception as e:
            return f"Error fetching OVH IPs: {e}"

        if not ips:
            return "No IPs found on the OVH account."

        lines = [f"{'IP':<22} {'Type':<14} {'Routed To':<30} {'Country':<8}"]
        lines.append('-' * 76)
        for ip_info in ips:
            # OVH API can return JSON nulls for any of these fields.
            # ``dict.get(k, '')`` does NOT default when the key is present with
            # value None — it returns None, which then crashes the column
            # formatter below with "unsupported format string passed to
            # NoneType.__format__". Coerce every column to a string explicitly.
            ip = str(ip_info.get('ip') or '')
            ip_type = str(ip_info.get('type') or '')
            routed_to = ip_info.get('routedTo') or {}
            if isinstance(routed_to, dict):
                routed_service = str(routed_to.get('serviceName') or '')
            else:
                routed_service = str(routed_to)
            country = str(ip_info.get('country') or '')
            lines.append(f"{ip:<22} {ip_type:<14} {routed_service:<30} {country:<8}")

        return '\n'.join(lines)

    async def ovh_firewall_rules(self, ip: str) -> str:
        """List firewall rules for an OVH IP address."""
        if self._ovh_ip_service is None:
            return "Error: OVH IP service is not available. Ensure OVH is configured and enabled."

        try:
            rules = await self._ovh_ip_service.list_firewall_rules(ip)
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Error fetching firewall rules for {ip}: {e}"

        if not rules:
            return f"No firewall rules found for IP: {ip}"

        lines = [f"Firewall rules for {ip}:"]
        lines.append(f"  {'Seq':<5} {'Action':<8} {'Protocol':<10} {'Source':<20} {'Port'}")
        lines.append('  ' + '-' * 60)
        for rule in rules:
            seq = rule.get('sequence', '')
            action = rule.get('action', '')
            protocol = rule.get('protocol', '')
            source = rule.get('source', rule.get('sourcePort', ''))
            port = rule.get('destinationPort', rule.get('port', ''))
            lines.append(f"  {str(seq):<5} {action:<8} {protocol:<10} {str(source):<20} {str(port)}")

        return '\n'.join(lines)

    async def ovh_ssh_keys(self) -> str:
        """List SSH keys on the OVH account."""
        if self._ovh_service is None:
            return "Error: OVH service is not available. Ensure OVH is configured and enabled."

        import asyncio as _asyncio
        client = self._ovh_service.client
        try:
            key_names = await _asyncio.to_thread(client.get, "/me/sshKey")
        except Exception as e:
            return f"Error fetching OVH SSH keys: {e}"

        if not key_names:
            return "No SSH keys found on the OVH account."

        lines = [f"OVH SSH Keys ({len(key_names)} total):"]
        for key_name in key_names:
            try:
                key = await _asyncio.to_thread(client.get, f"/me/sshKey/{key_name}")
                default = " [default]" if key.get('default') else ""
                lines.append(f"  {key_name}{default}")
                if key.get('key'):
                    # Show fingerprint-like truncation of the key
                    key_val = key['key']
                    key_parts = key_val.split()
                    if len(key_parts) >= 2:
                        lines.append(f"    type={key_parts[0]}, length={len(key_parts[1])}")
            except Exception:
                lines.append(f"  {key_name} (details unavailable)")

        return '\n'.join(lines)

    async def ovh_snapshots(self, instance_id: str) -> str:
        """List snapshots for an OVH VPS or Cloud instance."""
        if self._ovh_snapshot_service is None:
            return "Error: OVH snapshot service is not available. Ensure OVH is configured and enabled."

        instance = await self._find_instance(instance_id)
        if not instance:
            return f"Instance not found: {instance_id}"

        provider_type = instance.get('provider_type', '')
        name = instance.get('id', '') or instance.get('name', '')

        try:
            if provider_type == 'vps':
                snapshots = await self._ovh_snapshot_service.list_vps_snapshots(name)
                label = f"VPS snapshots for {name}"
            else:
                # Public Cloud: use project_id
                project_id = instance.get('project_id', '')
                if not project_id:
                    return f"Error: Cannot determine project_id for instance {instance_id}. Provider type: {provider_type!r}"
                snapshots = await self._ovh_snapshot_service.list_cloud_snapshots(project_id)
                label = f"Cloud snapshots for project {project_id}"
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Error fetching snapshots: {e}"

        if not snapshots:
            return f"No snapshots found. ({label})"

        lines = [f"{label} ({len(snapshots)} found):"]
        for snap in snapshots:
            if not isinstance(snap, dict):
                # Defensive: older normalisation could slip a non-dict through.
                lines.append(f"  {snap}")
                continue
            snap_id = snap.get('id') or snap.get('name') or '(no id)'
            snap_name = snap.get('name') or snap.get('description') or ''
            created = snap.get('creationDate') or snap.get('createdAt') or ''
            size = snap.get('size')
            size_str = f", size={size}" if size else ""
            lines.append(f"  {snap_id} - {snap_name} (created={created}{size_str})")

        return '\n'.join(lines)

    async def ovh_dns_records(self, zone: str, record_type: str = "") -> str:
        """List DNS records for an OVH zone."""
        if self._ovh_dns_service is None:
            return "Error: OVH DNS service is not available. Ensure OVH is configured and enabled."

        try:
            records = await self._ovh_dns_service.list_records(zone, field_type=record_type)
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Error fetching DNS records for zone {zone!r}: {e}"

        if not records:
            filter_note = f" (type={record_type})" if record_type else ""
            return f"No DNS records found for zone: {zone}{filter_note}"

        type_note = f" [{record_type}]" if record_type else ""
        lines = [f"DNS records for {zone}{type_note} ({len(records)} found):"]
        lines.append(f"  {'Type':<8} {'Subdomain':<30} {'TTL':<8} Target")
        lines.append('  ' + '-' * 70)
        for rec in records:
            rec_type = rec.get('fieldType', '')
            subdomain = rec.get('subDomain', '@') or '@'
            ttl = rec.get('ttl', '')
            target = rec.get('target', '')
            lines.append(f"  {rec_type:<8} {subdomain:<30} {str(ttl):<8} {target}")

        return '\n'.join(lines)

    async def ovh_billing(self) -> str:
        """Get current OVH billing summary (spend, forecast)."""
        if self._ovh_billing_service is None:
            return "Error: OVH billing service is not available. Ensure OVH is configured and enabled."

        try:
            usage = await self._ovh_billing_service.get_current_usage()
        except Exception as e:
            return f"Error fetching OVH billing data: {e}"

        lines = ["OVH Billing Summary:"]

        current = usage.get('current_spend', {})
        if isinstance(current, dict) and current:
            lines.append("  Current Spend:")
            for key, val in current.items():
                if key not in ('provider',):
                    lines.append(f"    {key}: {val}")
        elif not current:
            lines.append("  Current Spend: no data available")

        forecast = usage.get('forecast', {})
        if isinstance(forecast, dict) and forecast:
            lines.append("  Forecast:")
            for key, val in forecast.items():
                lines.append(f"    {key}: {val}")
        elif not forecast:
            lines.append("  Forecast: no data available")

        return '\n'.join(lines)

    async def ovh_invoices(self, limit: int = 5) -> str:
        """List recent OVH invoices."""
        if self._ovh_billing_service is None:
            return "Error: OVH billing service is not available. Ensure OVH is configured and enabled."

        try:
            invoices = await self._ovh_billing_service.get_invoices(limit=limit)
        except Exception as e:
            return f"Error fetching OVH invoices: {e}"

        if not invoices:
            return "No invoices found on the OVH account."

        lines = [f"Recent OVH Invoices (up to {limit}):"]
        lines.append(f"  {'ID':<20} {'Date':<14} {'Amount':<16} Status")
        lines.append('  ' + '-' * 64)
        for inv in invoices:
            bill_id = inv.get('billId', inv.get('id', ''))
            date = inv.get('date', inv.get('billDate', ''))
            if date and len(date) > 10:
                date = date[:10]
            amount_raw = inv.get('priceWithTax', inv.get('amount', {}))
            if isinstance(amount_raw, dict):
                value = amount_raw.get('value', '')
                currency = amount_raw.get('currencyCode', '')
                amount_str = f"{value} {currency}".strip()
            else:
                amount_str = str(amount_raw)
            status = inv.get('pdfUrl', inv.get('status', ''))
            if status and status.startswith('http'):
                status = 'PDF available'
            lines.append(f"  {bill_id:<20} {date:<14} {amount_str:<16} {status}")

        return '\n'.join(lines)

    async def whoami(self) -> str:
        """Introspect the CLI's logged-in session without exposing the bearer.

        Returns logged_in flag plus email/plan/base_url/expiry when authenticated.
        The access token itself is never included in the response.
        """
        args: Dict[str, Any] = {}
        auth = self._auth_service
        if auth is None or not getattr(auth, "is_authenticated", False):
            payload: Dict[str, Any] = {"logged_in": False}
            self._audit.log("whoami", args, json.dumps(payload), True)
            return json.dumps(payload)

        token = getattr(auth, "_token", None)
        expires_at = getattr(token, "expires_at", 0.0) if token else 0.0
        email = getattr(token, "email", "") if token else ""
        plan = getattr(auth, "plan", "free")

        from datetime import datetime, timezone
        try:
            expires_iso = datetime.fromtimestamp(
                float(expires_at), tz=timezone.utc
            ).isoformat()
        except (TypeError, ValueError, OSError):
            expires_iso = None
        expires_in = int(float(expires_at) - time.time()) if expires_at else None

        payload = {
            "logged_in": True,
            "email": email,
            "plan": plan,
            "base_url": self._api_base_url(),
            "token_expires_at": expires_iso,
            "token_expires_in_seconds": expires_in,
        }
        self._audit.log("whoami", args, json.dumps(payload), True)
        return json.dumps(payload)

    async def api_request(self, method: str, path: str,
                          query: Optional[Dict[str, Any]] = None,
                          body: Any = None,
                          headers: Optional[Dict[str, str]] = None) -> str:
        """Make an authenticated request against the Servonaut REST API.

        Agents invoke backend endpoints through this tool so the OAuth bearer
        never leaves the CLI. Failures are returned as structured errors
        (``{"error": {"code": ..., "message": ...}}``) rather than raised —
        MCP agents handle structured results far better than exceptions.
        """
        started = time.monotonic()
        method_upper = (method or "").upper()
        result = await self._api_request_impl(method_upper, path, query, body, headers)
        duration_ms = int((time.monotonic() - started) * 1000)

        status = result.get("status") if isinstance(result, dict) else None
        audit_args = {"method": method_upper, "path": path}
        audit_meta = {"status": status, "duration_ms": duration_ms}
        if "error" in result:
            audit_meta["error_code"] = result["error"].get("code")
        self._audit.log(
            "api_request",
            {**audit_args, **audit_meta},
            "",
            "error" not in result,
        )
        # Only the method+path hits the INFO log — bodies stay out of the
        # default log stream per the token-handling policy.
        logger.info(
            "api_request %s %s -> status=%s (%dms)",
            method_upper, path, status, duration_ms,
        )
        return json.dumps(result)

    async def _api_request_impl(
        self, method: str, path: str,
        query: Optional[Dict[str, Any]],
        body: Any,
        headers: Optional[Dict[str, str]],
    ) -> Dict[str, Any]:
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            return _error("invalid_method", f"Unsupported HTTP method: {method!r}")

        if not isinstance(path, str) or not path.startswith("/"):
            return _error(
                "invalid_path",
                "path must be a relative path starting with '/' (no scheme/host).",
            )

        auth = self._auth_service
        if auth is None or not getattr(auth, "is_authenticated", False):
            return _error("not_logged_in", "Run `servonaut login` first.")

        access_token = getattr(auth, "access_token", None)
        if not access_token:
            return _error("not_logged_in", "Run `servonaut login` first.")

        if not self._record_api_request_or_reject():
            return _error(
                "cli_rate_limited",
                f"api_request is capped at {_API_REQUEST_MAX_PER_WINDOW} calls "
                f"per {int(_API_REQUEST_WINDOW_SECONDS)}s on the CLI side.",
            )

        try:
            import httpx
        except ImportError:
            return _error(
                "httpx_missing",
                "httpx is not installed. Install with `pip install 'servonaut[ai]'`.",
            )

        base = self._api_base_url().rstrip("/")
        url = f"{base}{path}"

        safe_headers: Dict[str, str] = {"Accept": "application/json"}
        if isinstance(headers, dict):
            for key, value in headers.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    continue
                if key.lower() in _ALLOWED_REQUEST_HEADERS:
                    safe_headers[key] = value
        safe_headers["Authorization"] = f"Bearer {access_token}"

        request_kwargs: Dict[str, Any] = {
            "params": query or None,
            "headers": safe_headers,
            "timeout": 10.0,
        }
        if body is not None:
            request_kwargs["json"] = body

        try:
            async with httpx.AsyncClient() as client:
                response = await client.request(method, url, **request_kwargs)
                # One-shot 401 refresh + retry. Skip if the caller is already
                # targeting the OAuth endpoints — avoids pointless loops.
                if (response.status_code == 401
                        and not path.startswith("/api/oauth/")
                        and hasattr(auth, "refresh_token")):
                    if await auth.refresh_token():
                        new_token = getattr(auth, "access_token", None)
                        if new_token:
                            safe_headers["Authorization"] = f"Bearer {new_token}"
                            response = await client.request(method, url, **request_kwargs)
        except httpx.TimeoutException:
            return _error("timeout", "Request exceeded 10 second timeout.")
        except httpx.HTTPError as e:
            return _error("network_error", str(e))

        content = response.content or b""
        if len(content) > _MAX_RESPONSE_BYTES:
            return _error(
                "response_too_large",
                f"Response body is {len(content)} bytes (max {_MAX_RESPONSE_BYTES}).",
            )

        response_headers = _sanitize_response_headers(dict(response.headers))
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type.lower() and content:
            try:
                parsed_body: Any = response.json()
            except (ValueError, json.JSONDecodeError):
                parsed_body = content.decode("utf-8", errors="replace")
        else:
            parsed_body = content.decode("utf-8", errors="replace") if content else ""

        return {
            "status": response.status_code,
            "headers": response_headers,
            "body": parsed_body,
        }

    def _record_api_request_or_reject(self) -> bool:
        """Track a request in the sliding window. Returns False when over cap."""
        now = time.monotonic()
        cutoff = now - _API_REQUEST_WINDOW_SECONDS
        window = self._api_request_window
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= _API_REQUEST_MAX_PER_WINDOW:
            return False
        window.append(now)
        return True

    def _api_base_url(self) -> str:
        """Resolve the API base URL from the same source AuthService uses."""
        from servonaut.services.auth_service import _api_base
        return _api_base()

    async def relay_status(self) -> str:
        """Report what the backend knows about the current relay connection.

        Thin wrapper over ``GET /api/cli/status`` — unwraps the ``api_request``
        envelope so agents get the backend payload directly (connected flag,
        last heartbeat, client_ids). Errors propagate as the normal
        ``{"error": ...}`` shape.
        """
        raw = await self.api_request("GET", "/api/cli/status")
        try:
            wrapped = json.loads(raw)
        except ValueError:
            # api_request always returns JSON; preserve the raw string as a fallback
            return raw
        if not isinstance(wrapped, dict):
            return json.dumps(_error("unexpected_response", "Non-object payload."))
        if "error" in wrapped:
            return json.dumps(wrapped)
        body = wrapped.get("body")
        if not isinstance(body, dict):
            return json.dumps(_error(
                "unexpected_response",
                f"Expected JSON object body, got {type(body).__name__}.",
            ))
        return json.dumps(body)

    async def mcp_tool_call(self, name: str,
                            arguments: Optional[Dict[str, Any]] = None) -> str:
        """Invoke a tool on the hosted MCP server at mcp.servonaut.dev.

        Wraps ``(name, arguments)`` into a JSON-RPC 2.0 ``tools/call`` envelope
        and POSTs to ``$SERVONAUT_MCP_URL/mcp/message`` with the CLI's OAuth
        bearer. Returns the raw JSON-RPC response so agents can inspect
        ``result`` or ``error`` without constructing the envelope themselves.
        One-shot 401 refresh + retry mirrors ``api_request``.
        """
        import uuid
        request_id = str(uuid.uuid4())
        envelope: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
            "id": request_id,
        }

        started = time.monotonic()
        audit_args = {"name": name, "has_arguments": bool(arguments)}

        auth = self._auth_service
        if auth is None or not getattr(auth, "is_authenticated", False):
            payload = _error("not_logged_in", "Run `servonaut login` first.")
            self._audit.log("mcp_tool_call", audit_args, "", False, payload["error"]["code"])
            return json.dumps(payload)
        access_token = getattr(auth, "access_token", None)
        if not access_token:
            payload = _error("not_logged_in", "Run `servonaut login` first.")
            self._audit.log("mcp_tool_call", audit_args, "", False, payload["error"]["code"])
            return json.dumps(payload)

        try:
            import httpx
        except ImportError:
            payload = _error(
                "httpx_missing",
                "httpx is not installed. Install with `pip install 'servonaut[ai]'`.",
            )
            self._audit.log("mcp_tool_call", audit_args, "", False, payload["error"]["code"])
            return json.dumps(payload)

        from servonaut.mcp.remote_client import _mcp_base
        url = f"{_mcp_base().rstrip('/')}/mcp/message"
        request_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url, json=envelope, headers=request_headers, timeout=30.0,
                )
                if response.status_code == 401 and hasattr(auth, "refresh_token"):
                    if await auth.refresh_token():
                        new_token = getattr(auth, "access_token", None)
                        if new_token:
                            request_headers["Authorization"] = f"Bearer {new_token}"
                            response = await client.post(
                                url, json=envelope,
                                headers=request_headers, timeout=30.0,
                            )
        except httpx.TimeoutException:
            payload = _error("timeout", "Request exceeded 30 second timeout.")
            self._audit.log("mcp_tool_call", audit_args, "", False, payload["error"]["code"])
            return json.dumps(payload)
        except httpx.HTTPError as e:
            payload = _error("network_error", str(e))
            self._audit.log("mcp_tool_call", audit_args, "", False, payload["error"]["code"])
            return json.dumps(payload)

        duration_ms = int((time.monotonic() - started) * 1000)
        content = response.content or b""
        if len(content) > _MAX_RESPONSE_BYTES:
            payload = _error(
                "response_too_large",
                f"MCP response is {len(content)} bytes (max {_MAX_RESPONSE_BYTES}).",
            )
            self._audit.log("mcp_tool_call", audit_args, "", False, payload["error"]["code"])
            return json.dumps(payload)

        try:
            parsed: Any = response.json() if content else {}
        except ValueError:
            parsed = {"raw": content.decode("utf-8", errors="replace")}

        # Forward the JSON-RPC response verbatim so the agent sees either
        # `result` or `error` per the JSON-RPC spec.
        result_envelope = {
            "status": response.status_code,
            "response": parsed,
        }
        self._audit.log(
            "mcp_tool_call",
            {**audit_args, "status": response.status_code, "duration_ms": duration_ms},
            "",
            200 <= response.status_code < 300,
        )
        logger.info(
            "mcp_tool_call %s -> status=%s (%dms)",
            name, response.status_code, duration_ms,
        )
        return json.dumps(result_envelope)

    async def relay_reconnect(self, force: bool = False) -> str:
        """Heal a stale relay connection.

        Flow:
        * ask the backend via ``GET /api/cli/status`` whether it still sees the
          listener. If it does, no-op (``action="none"``) — agents should not
          churn a healthy connection;
        * otherwise send SIGTERM to the recorded listener PID (if any), wait
          up to 3 s for it to exit, then start a fresh background process.

        Set ``force=True`` to skip the backend health-check and always restart.
        The OAuth bearer still stays on the CLI: the backend status is fetched
        through the existing ``api_request`` tool envelope.
        """
        args = {"force": force}
        now_connected = None
        if not force:
            status_raw = await self.api_request("GET", "/api/cli/status")
            try:
                status = json.loads(status_raw)
            except ValueError:
                status = {}
            body = status.get("body") if isinstance(status, dict) else None
            if isinstance(body, dict) and "connected" in body:
                now_connected = bool(body.get("connected"))
            if now_connected is True:
                payload = {
                    "action": "none",
                    "reason": "Backend already reports the listener as connected.",
                    "backend": status.get("body"),
                }
                self._audit.log("relay_reconnect", args, json.dumps(payload), True)
                return json.dumps(payload)

        try:
            from servonaut.main import _relay_reconnect as _do_reconnect
        except ImportError as e:
            return json.dumps(_error(
                "reconnect_unavailable",
                f"Cannot import relay reconnect helper: {e}",
            ))

        try:
            await asyncio.to_thread(_do_reconnect)
        except Exception as e:
            payload = _error("reconnect_failed", str(e))
            self._audit.log("relay_reconnect", args, json.dumps(payload), False)
            return json.dumps(payload)

        payload = {
            "action": "restarted",
            "backend_connected_before": now_connected,
        }
        self._audit.log("relay_reconnect", args, json.dumps(payload), True)
        return json.dumps(payload)

    async def get_server_memory(
        self, instance_id: str, format: str = "summary"
    ) -> str:
        """Return cached server memory for an instance.

        Formats:
          summary       — token-efficient Markdown (max ~1 500 tokens, default)
          markdown      — full untruncated Markdown
          full          — raw JSON for all stored modules
          context_block — same <CONTEXT name="server_memory:..."> envelope
                          the Servonaut chat client injects, so agents
                          consuming this output see the same shape as
                          first-party chat sessions
        """
        allowed, reason = self._guard.check_tool('get_server_memory')
        if not allowed:
            self._audit.log(
                'get_server_memory', {'instance_id': instance_id, 'format': format},
                '', False, reason,
            )
            return f"Blocked: {reason}"

        if self._memory_service is None:
            self._audit.log(
                'get_server_memory', {'instance_id': instance_id, 'format': format},
                'memory_service_missing', False, 'memory_service_missing',
            )
            return "Error: memory subsystem not wired."

        instance = await self._find_instance(instance_id)
        if not instance:
            self._audit.log(
                'get_server_memory', {'instance_id': instance_id, 'format': format},
                'instance_not_found', False, 'instance_not_found',
            )
            return f"Instance not found: {instance_id}"

        iid = instance.get('id') or instance.get('name', instance_id)
        iname = instance.get('name', '')
        provider = instance.get('provider', 'custom')
        config = self._config_manager.get()

        # Per-server opt-out check (checks both id and name).
        if (not config.memory.enabled) or config.memory.is_instance_disabled(iid, iname):
            payload = json.dumps({
                "error": {
                    "code": "opt_out",
                    "message": f"Memory disabled for {iid}.",
                }
            })
            self._audit.log(
                'get_server_memory', {'instance_id': instance_id, 'format': format},
                payload, False, 'opt_out',
            )
            return payload

        meta = {
            "id": iid,
            "name": instance.get("name", iid),
            "provider": provider,
        }

        # Short-circuit when there is no memory on disk at all — give the
        # agent a machine-readable `missing` code and a clear hint so it can
        # self-heal by calling build_server_memory.
        stored_modules = self._memory_service.get_all_modules(iid, provider)
        if not stored_modules:
            payload = json.dumps({
                "error": {
                    "code": "missing",
                    "message": f"No memory stored for {iid}.",
                    "hint": (
                        f"Call build_server_memory(instance_id='{iid}') to "
                        "probe the host and populate memory, then retry."
                    ),
                }
            })
            self._audit.log(
                'get_server_memory', {'instance_id': instance_id, 'format': format},
                payload, False, 'missing',
            )
            return payload

        # Every format below is handed straight into a calling agent's model
        # context, so each carries the untrusted-data trust notice. Text
        # formats get a prepended prose notice; the JSON `full` format embeds
        # it as a field so the output stays valid JSON. `context_block` is
        # framed inside build_memory_context already.
        from servonaut.services.ai_memory_injector import (
            MEMORY_TRUST_NOTICE, frame_as_untrusted,
        )
        try:
            if format == "full":
                # Strip raw_output from the full-format response — agents use
                # structured observed/declared/probed_at fields.  Raw probe
                # output is diagnostic and will be gated behind T9 redaction.
                sanitized = {
                    name: {k: v for k, v in mod.items() if k != "raw_output"}
                    for name, mod in stored_modules.items()
                }
                result = json.dumps(
                    {
                        "_trust_notice": MEMORY_TRUST_NOTICE,
                        "instance_id": iid,
                        "modules": sanitized,
                    },
                    indent=2,
                )
            elif format == "markdown":
                result = frame_as_untrusted(
                    await self._memory_service.get_summary(meta, max_tokens=1_000_000)
                )
            elif format == "context_block":
                from servonaut.services.ai_memory_injector import (
                    InstanceScope, build_memory_context,
                )
                scope = InstanceScope(id=iid, name=iname or iid, provider=provider)
                body, _telemetry = build_memory_context(
                    instances=[scope],
                    prompt="",
                    memory_service=self._memory_service,
                    config_memory=config.memory,
                    redaction_enabled=getattr(
                        config.memory, "redaction_enabled", True,
                    ),
                )
                result = body or "<!-- empty memory context -->"
            else:  # "summary" or anything else — default to summary
                result = frame_as_untrusted(
                    await self._memory_service.get_summary(meta, max_tokens=1500)
                )
        except Exception as exc:
            result = f"Error retrieving memory: {exc}"
            self._audit.log(
                'get_server_memory', {'instance_id': instance_id, 'format': format},
                result, False, str(exc),
            )
            return result

        self._audit.log(
            'get_server_memory', {'instance_id': instance_id, 'format': format},
            result, True,
        )
        return result

    async def _run_memory_build(
        self,
        tool_name: str,
        instance_id: str,
        modules: Optional[List[str]],
    ) -> str:
        """Shared implementation for build_server_memory + refresh_server_memory.

        The two MCP tools are semantically paired (build = first time,
        refresh = update) but the underlying probe flow is identical.  This
        helper centralises the guard / lookup / opt-out / structured-response
        path so both tools stay in lockstep.
        """
        audit_args = {'instance_id': instance_id, 'modules': modules}

        allowed, reason = self._guard.check_tool(tool_name)
        if not allowed:
            self._audit.log(tool_name, audit_args, '', False, reason)
            return f"Blocked: {reason}"

        if self._memory_service is None:
            self._audit.log(
                tool_name, audit_args,
                'memory_service_missing', False, 'memory_service_missing',
            )
            return "Error: memory subsystem not wired."

        instance = await self._find_instance(instance_id)
        if not instance:
            self._audit.log(
                tool_name, audit_args, 'instance_not_found', False, 'instance_not_found',
            )
            return f"Instance not found: {instance_id}"

        iid = instance.get('id') or instance.get('name', instance_id)
        iname = instance.get('name', '')
        config = self._config_manager.get()

        # Per-server opt-out check (checks both id and name).  Shape mirrors
        # get_server_memory so agents can detect all "refused" outcomes with
        # a single `error.code` lookup.
        if (not config.memory.enabled) or config.memory.is_instance_disabled(iid, iname):
            payload = json.dumps({
                "error": {
                    "code": "opt_out",
                    "message": f"Memory disabled for {iid}.",
                }
            })
            self._audit.log(tool_name, audit_args, payload, False, 'opt_out')
            return payload

        # Prefer build_report (per-module failure reasons) when available;
        # fall back to the legacy dict-returning refresh() for older/mocked
        # service implementations that don't expose the richer API.
        try:
            if hasattr(self._memory_service, "build_report"):
                report = await self._memory_service.build_report(instance, modules)
                successes = list(report.successes.keys())
                failures = [
                    {"module": f.module, "reason": f.reason, "message": f.message}
                    for f in report.failures
                ]
                overall_reason = report.overall_reason
            else:
                results = await self._memory_service.refresh(instance, modules)
                successes = list(results.keys())
                failures = []
                overall_reason = None if successes else "all_probers_failed"
        except Exception as exc:
            result = f"Error building memory: {exc}"
            self._audit.log(tool_name, audit_args, result, False, str(exc))
            return result

        response: Dict[str, Any] = {
            "instance_id": iid,
            "count": len(successes),
            "successes": successes,
            "failures": failures,
        }
        if overall_reason:
            response["reason"] = overall_reason
            if overall_reason == "all_probers_failed":
                response["message"] = (
                    "Every prober failed — typically an SSH reachability or "
                    "authentication problem. See 'failures' for per-module "
                    "details and fix the connection before retrying."
                )
            elif overall_reason == "no_modules_matched":
                response["message"] = (
                    "No probers matched the requested modules. Omit 'modules' "
                    "to probe all enabled modules."
                )
            elif overall_reason == "disabled":
                response["message"] = (
                    "Memory subsystem is disabled in config (memory.enabled=false)."
                )
            elif overall_reason == "opt_out":
                response["message"] = f"Memory disabled for {iid}."

        payload = json.dumps(response)
        self._audit.log(
            tool_name, audit_args, payload,
            len(successes) > 0,
            overall_reason or "",
        )
        return payload

    async def build_server_memory(
        self, instance_id: str, modules: Optional[List[str]] = None
    ) -> str:
        """Probe and store memory for an instance from scratch.

        Use this when ``get_server_memory`` returns ``code='missing'`` or to
        force a fresh full scan.  Returns structured JSON with per-module
        successes and failures.
        """
        return await self._run_memory_build(
            'build_server_memory', instance_id, modules
        )

    async def refresh_server_memory(
        self, instance_id: str, modules: Optional[List[str]] = None
    ) -> str:
        """Re-probe one or more memory modules for an instance and update cache.

        Semantically equivalent to ``build_server_memory`` (the probe flow is
        identical); prefer this name when updating existing memory.
        """
        return await self._run_memory_build(
            'refresh_server_memory', instance_id, modules
        )

    async def list_server_memories(self, stale_only: bool = False) -> str:
        """List all instances with cached server memory.

        When stale_only=True, returns only instances that have at least one
        module with data exceeding its TTL.
        """
        allowed, reason = self._guard.check_tool('list_server_memories')
        if not allowed:
            self._audit.log(
                'list_server_memories', {'stale_only': stale_only},
                '', False, reason,
            )
            return f"Blocked: {reason}"

        if self._memory_service is None:
            self._audit.log(
                'list_server_memories', {'stale_only': stale_only},
                'memory_service_missing', False, 'memory_service_missing',
            )
            return "Error: memory subsystem not wired."

        config = self._config_manager.get()
        all_entries = self._memory_service.list_all()

        # Filter instances that are opted out — agents should not see memory
        # for servers that have opted out of the memory subsystem.
        non_opted_out = []
        for entry in all_entries:
            iid = entry.get('instance_id', '')
            iname = entry.get('name', '')
            if not config.memory.is_instance_disabled(iid, iname):
                non_opted_out.append(entry)

        if stale_only:
            filtered = []
            for entry in non_opted_out:
                iid = entry.get('instance_id', '')
                provider = entry.get('provider', 'custom')
                stale = self._memory_service.stale_modules(iid, provider)
                if stale:
                    filtered.append(entry)
            result_entries = filtered
        else:
            result_entries = non_opted_out

        result = json.dumps(result_entries, indent=2)
        self._audit.log(
            'list_server_memories', {'stale_only': stale_only},
            result, True,
        )
        return result

    async def remember_server_finding(
        self,
        instance_id: str,
        title: str,
        body: str,
        tags: Optional[List[str]] = None,
        confidence: float = 0.6,
        supersede_id: Optional[str] = None,
    ) -> str:
        """Persist a hard-won agent finding for an instance.

        The full body is NOT included in the audit row (can be large/sensitive);
        only body_len is recorded, mirroring the presigned-URL masking precedent.
        """
        args = {
            'instance_id': instance_id,
            'title': title,
            'body_len': len(body or ""),
            'tags': tags,
            'confidence': confidence,
            'supersede_id': supersede_id,
        }

        allowed, reason = self._guard.check_tool('remember_server_finding')
        if not allowed:
            self._audit.log('remember_server_finding', args, '', False, 'guard_denied')
            return f"Blocked: {reason}"

        if self._memory_service is None:
            self._audit.log(
                'remember_server_finding', args, '', False, 'memory_unavailable',
            )
            return "Error: memory subsystem not wired."

        instance = await self._find_instance(instance_id)
        if not instance:
            self._audit.log(
                'remember_server_finding', args, '', False, 'instance_not_found',
            )
            return f"Instance not found: {instance_id}"

        try:
            result = self._memory_service.remember_finding(
                instance,
                title=title,
                body=body,
                tags=tags,
                confidence=confidence,
                source="agent",
                supersede_id=supersede_id,
            )
        except ValueError as exc:
            self._audit.log('remember_server_finding', args, str(exc), False, 'validation')
            return f"validation: {exc}"
        except Exception as exc:
            self._audit.log('remember_server_finding', args, str(exc), False, 'api_error')
            return f"api_error: {exc}"

        if result.get("refused"):
            msg = f"Memory is disabled for instance {instance_id}; finding not saved."
            self._audit.log('remember_server_finding', args, msg, False, 'memory_disabled')
            return msg

        finding_id = result.get("finding_id", "")
        auto_inject = result.get("auto_inject", False)
        superseded = result.get("superseded")
        secret_warning = result.get("secret_warning", "")

        lines = [
            f"finding_id: {finding_id}",
            f"auto_inject: {auto_inject}",
        ]
        if superseded:
            lines.append(f"superseded: {superseded}")
        if secret_warning:
            categories = (
                ", ".join(secret_warning)
                if isinstance(secret_warning, (list, tuple))
                else str(secret_warning)
            )
            lines.append(f"WARNING possible secret in body: {categories}")

        result_str = "\n".join(lines)
        self._audit.log('remember_server_finding', args, result_str, True)
        return result_str

    async def recall_server_findings(
        self,
        instance_id: str,
        query: str = "",
        tags: Optional[List[str]] = None,
        limit: int = 10,
        include_superseded: bool = False,
    ) -> str:
        """Retrieve previously-saved findings for an instance.

        Results include full titles and bodies. Treat findings as agent-authored
        reference material — verify before acting on destructive suggestions.
        """
        args = {
            'instance_id': instance_id,
            'query': query,
            'tags': tags,
            'limit': limit,
            'include_superseded': include_superseded,
        }

        allowed, reason = self._guard.check_tool('recall_server_findings')
        if not allowed:
            self._audit.log('recall_server_findings', args, '', False, 'guard_denied')
            return f"Blocked: {reason}"

        if self._memory_service is None:
            self._audit.log(
                'recall_server_findings', args, '', False, 'memory_unavailable',
            )
            return "Error: memory subsystem not wired."

        instance = await self._find_instance(instance_id)
        if not instance:
            self._audit.log(
                'recall_server_findings', args, '', False, 'instance_not_found',
            )
            return f"Instance not found: {instance_id}"

        resolved_id = instance.get('id') or instance.get('name', instance_id)
        provider = instance.get('provider', 'custom')

        try:
            findings = self._memory_service.recall_findings(
                resolved_id,
                instance_name=instance.get('name', ''),
                query=query,
                tags=tags,
                limit=limit,
                include_superseded=include_superseded,
                provider=provider,
            )
        except Exception as exc:
            self._audit.log('recall_server_findings', args, str(exc), False, 'api_error')
            return f"api_error: {exc}"

        output_fields = ['id', 'title', 'body', 'tags', 'confidence', 'source', 'created_at']
        # Findings are agent-authored + unverified. The result carries the
        # provenance/trust notice as a field (keeps the output valid JSON) so the
        # framing sits next to the untrusted bodies — mirrors get_server_memory.
        from servonaut.services.memory.trust_notices import FINDINGS_PROVENANCE_NOTICE
        payload = json.dumps(
            {
                "_notice": FINDINGS_PROVENANCE_NOTICE,
                "instance_id": resolved_id,
                "count": len(findings),
                "findings": [
                    {k: f.get(k) for k in output_fields}
                    for f in findings
                ],
            },
            indent=2,
        )
        self._audit.log('recall_server_findings', args, payload, True)
        return payload

    # ------------------------------------------------------------------
    # Hetzner Cloud tools (read + lifecycle)
    # ------------------------------------------------------------------

    def _hetzner_unavailable(self, tool_name: str, payload: Dict[str, Any]) -> str:
        """Common early-return when the Hetzner service isn't wired up."""
        msg = (
            "Error: Hetzner service is not available. Set "
            "config.hetzner.enabled=true and provide a token via "
            "config.hetzner.api_token, $HCLOUD_TOKEN, or ~/.config/hcloud/token."
        )
        self._audit.log(tool_name, payload, '', False, 'hetzner_unavailable')
        return msg

    async def hetzner_list_servers(self) -> str:
        """List Hetzner Cloud servers in the configured project."""
        if self._hetzner_service is None:
            return self._hetzner_unavailable('hetzner_list_servers', {})

        allowed, reason = self._guard.check_tool('hetzner_list_servers')
        if not allowed:
            self._audit.log('hetzner_list_servers', {}, '', False, reason)
            return f"Blocked: {reason}"

        try:
            instances = await self._hetzner_service.fetch_instances_cached(
                force_refresh=True,
            )
        except Exception as exc:
            self._audit.log(
                'hetzner_list_servers', {}, '', False, f"api_error: {exc}",
            )
            return f"Error listing Hetzner servers: {exc}"

        if not instances:
            self._audit.log('hetzner_list_servers', {}, '0 servers', True)
            return "No Hetzner Cloud servers in project."

        lines = [
            f"Hetzner Cloud servers ({len(instances)} total):",
            f"  {'Name':<24} {'ID':<10} {'Type':<10} {'State':<10} "
            f"{'Public IP':<16} {'Location':<8}",
            '  ' + '-' * 80,
        ]
        for inst in instances:
            lines.append(
                f"  {(inst.get('name') or '')[:24]:<24} "
                f"{inst.get('id', ''):<10} "
                f"{(inst.get('type') or ''):<10} "
                f"{(inst.get('state') or ''):<10} "
                f"{(inst.get('public_ip') or '-'):<16} "
                f"{(inst.get('region') or ''):<8}"
            )

        result = '\n'.join(lines)
        self._audit.log('hetzner_list_servers', {}, result, True)
        return result

    async def hetzner_list_server_types(self) -> str:
        """List Hetzner Cloud server types with their EUR prices."""
        if self._hetzner_service is None:
            return self._hetzner_unavailable('hetzner_list_server_types', {})

        allowed, reason = self._guard.check_tool('hetzner_list_server_types')
        if not allowed:
            self._audit.log('hetzner_list_server_types', {}, '', False, reason)
            return f"Blocked: {reason}"

        try:
            types = await self._hetzner_service.list_server_types()
        except Exception as exc:
            self._audit.log(
                'hetzner_list_server_types', {}, '', False, f"api_error: {exc}",
            )
            return f"Error listing server types: {exc}"

        lines = [
            f"Hetzner Cloud server types ({len(types)} total):",
            f"  {'Name':<10} {'Cores':<6} {'RAM(GB)':<8} {'Disk(GB)':<9} "
            f"{'Arch':<6} {'Hourly':<10} {'Monthly':<10} {'CCY':<4} Description",
            '  ' + '-' * 100,
        ]
        for t in types:
            lines.append(
                f"  {t.get('name', ''):<10} "
                f"{str(t.get('cores', 0)):<6} "
                f"{str(t.get('memory_gb', 0)):<8} "
                f"{str(t.get('disk_gb', 0)):<9} "
                f"{(t.get('architecture') or ''):<6} "
                f"{(t.get('hourly_price_gross') or '-'):<10} "
                f"{(t.get('monthly_price_gross') or '-'):<10} "
                f"{(t.get('currency') or '-'):<4} "
                f"{(t.get('description') or '')}"
            )

        result = '\n'.join(lines)
        self._audit.log('hetzner_list_server_types', {}, result, True)
        return result

    async def hetzner_list_ssh_keys(self) -> str:
        """List SSH keys registered on the Hetzner Cloud project."""
        if self._hetzner_service is None:
            return self._hetzner_unavailable('hetzner_list_ssh_keys', {})

        allowed, reason = self._guard.check_tool('hetzner_list_ssh_keys')
        if not allowed:
            self._audit.log('hetzner_list_ssh_keys', {}, '', False, reason)
            return f"Blocked: {reason}"

        try:
            keys = await self._hetzner_service.list_ssh_keys()
        except Exception as exc:
            self._audit.log(
                'hetzner_list_ssh_keys', {}, '', False, f"api_error: {exc}",
            )
            return f"Error listing SSH keys: {exc}"

        if not keys:
            self._audit.log('hetzner_list_ssh_keys', {}, '0 keys', True)
            return "No SSH keys registered on the Hetzner project."

        lines = [f"Hetzner Cloud SSH keys ({len(keys)} total):"]
        for k in keys:
            lines.append(
                f"  {k.get('name', ''):<30} "
                f"id={k.get('id', '')}  "
                f"fingerprint={k.get('fingerprint', '')}"
            )

        result = '\n'.join(lines)
        self._audit.log('hetzner_list_ssh_keys', {}, result, True)
        return result

    async def hetzner_create_ssh_key(self, name: str, public_key: str) -> str:
        """Register a new SSH public key with Hetzner Cloud."""
        payload = {'name': name}  # public_key intentionally not logged
        if self._hetzner_service is None:
            return self._hetzner_unavailable('hetzner_create_ssh_key', payload)

        allowed, reason = self._guard.check_tool('hetzner_create_ssh_key')
        if not allowed:
            self._audit.log('hetzner_create_ssh_key', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            key = await self._hetzner_service.create_ssh_key(name, public_key)
        except ValueError as exc:
            self._audit.log(
                'hetzner_create_ssh_key', payload, '', False, f"validation: {exc}",
            )
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log(
                'hetzner_create_ssh_key', payload, '', False, f"api_error: {exc}",
            )
            return f"Error registering SSH key {name!r}: {exc}"

        result = (
            f"Registered SSH key {key.get('name')!r} "
            f"(id={key.get('id')}, fingerprint={key.get('fingerprint')})."
        )
        self._audit.log('hetzner_create_ssh_key', payload, result, True)
        return result

    async def hetzner_delete_ssh_key(self, identifier: str) -> str:
        """Delete a Hetzner Cloud SSH key by name or numeric ID."""
        payload = {'identifier': identifier}
        if self._hetzner_service is None:
            return self._hetzner_unavailable(
                'hetzner_delete_ssh_key', payload,
            )

        allowed, reason = self._guard.check_tool('hetzner_delete_ssh_key')
        if not allowed:
            self._audit.log(
                'hetzner_delete_ssh_key', payload, '', False, reason,
            )
            return f"Blocked: {reason}"

        try:
            await self._hetzner_service.delete_ssh_key(identifier)
        except ValueError as exc:
            self._audit.log(
                'hetzner_delete_ssh_key', payload, '', False,
                f"validation: {exc}",
            )
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log(
                'hetzner_delete_ssh_key', payload, '', False,
                f"api_error: {exc}",
            )
            return f"Error deleting Hetzner SSH key {identifier!r}: {exc}"

        result = f"Deleted Hetzner SSH key {identifier!r}."
        self._audit.log('hetzner_delete_ssh_key', payload, result, True)
        return result

    async def hetzner_create_server(
        self,
        name: str,
        server_type: Optional[str] = None,
        image: Optional[str] = None,
        location: Optional[str] = None,
        ssh_keys: Optional[List[str]] = None,
        wait_until_running: bool = True,
    ) -> str:
        """Create a Hetzner Cloud server (auto-registers in the fleet)."""
        payload = {
            'name': name, 'server_type': server_type, 'image': image,
            'location': location, 'ssh_keys': ssh_keys,
            'wait_until_running': wait_until_running,
        }
        if self._hetzner_service is None:
            return self._hetzner_unavailable('hetzner_create_server', payload)

        allowed, reason = self._guard.check_tool('hetzner_create_server')
        if not allowed:
            self._audit.log('hetzner_create_server', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            instance = await self._hetzner_service.create_server(
                name=name,
                server_type=server_type,
                image=image,
                location=location,
                ssh_keys=ssh_keys,
                wait_until_running=wait_until_running,
            )
        except ValueError as exc:
            self._audit.log(
                'hetzner_create_server', payload, '', False, f"validation: {exc}",
            )
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log(
                'hetzner_create_server', payload, '', False, f"api_error: {exc}",
            )
            return f"Error creating Hetzner server {name!r}: {exc}"

        result = (
            f"Created Hetzner server {instance.get('name')!r} "
            f"(id={instance.get('id')}, type={instance.get('type')}, "
            f"location={instance.get('region')}, "
            f"public_ip={instance.get('public_ip') or '-'}, "
            f"state={instance.get('state')}). "
            f"Auto-registered in the fleet — try 'check_status {instance.get('name')}'."
        )
        # Truncate audit row for the success path: instance dict can contain
        # noisy ``raw`` payloads on other providers; here we keep a focused
        # human-readable line.
        self._audit.log('hetzner_create_server', payload, result, True)
        return result

    async def hetzner_delete_server(self, identifier: str) -> str:
        """Delete a Hetzner Cloud server by ID or name."""
        payload = {'identifier': identifier}
        if self._hetzner_service is None:
            return self._hetzner_unavailable('hetzner_delete_server', payload)

        allowed, reason = self._guard.check_tool('hetzner_delete_server')
        if not allowed:
            self._audit.log('hetzner_delete_server', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            await self._hetzner_service.delete_server(identifier)
        except ValueError as exc:
            self._audit.log(
                'hetzner_delete_server', payload, '', False, f"validation: {exc}",
            )
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log(
                'hetzner_delete_server', payload, '', False, f"api_error: {exc}",
            )
            return f"Error deleting Hetzner server {identifier!r}: {exc}"

        result = f"Deleted Hetzner server {identifier!r}."
        self._audit.log('hetzner_delete_server', payload, result, True)
        return result

    # ------------------------------------------------------------------
    # Hetzner power management — boot / halt / reboot
    # ------------------------------------------------------------------

    async def _hetzner_lifecycle(
        self, tool_name: str, method: str, identifier: str, verb: str,
    ) -> str:
        """Shared handler for the four Hetzner power tools.

        Mirrors the create/delete handlers' structure:
        unavailable check → guard check → service dispatch → audit. Each
        public tool method is a one-liner that picks the underlying
        ``HetznerService`` method and the human-readable verb.
        """
        payload = {'identifier': identifier}
        if self._hetzner_service is None:
            return self._hetzner_unavailable(tool_name, payload)

        allowed, reason = self._guard.check_tool(tool_name)
        if not allowed:
            self._audit.log(tool_name, payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            await getattr(self._hetzner_service, method)(identifier)
        except ValueError as exc:
            self._audit.log(
                tool_name, payload, '', False, f"validation: {exc}",
            )
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log(
                tool_name, payload, '', False, f"api_error: {exc}",
            )
            return f"Error: {verb} failed on {identifier!r}: {exc}"

        result = f"Hetzner server {identifier!r}: {verb}."
        self._audit.log(tool_name, payload, result, True)
        return result

    async def hetzner_power_on(self, identifier: str) -> str:
        return await self._hetzner_lifecycle(
            'hetzner_power_on', 'power_on', identifier, 'started',
        )

    async def hetzner_power_off(self, identifier: str) -> str:
        return await self._hetzner_lifecycle(
            'hetzner_power_off', 'power_off', identifier, 'powered off',
        )

    async def hetzner_shutdown(self, identifier: str) -> str:
        return await self._hetzner_lifecycle(
            'hetzner_shutdown', 'shutdown', identifier, 'shutdown sent',
        )

    async def hetzner_reboot(self, identifier: str) -> str:
        return await self._hetzner_lifecycle(
            'hetzner_reboot', 'reboot', identifier, 'reboot sent',
        )

    # ------------------------------------------------------------------
    # OVH instance lifecycle — create / delete / start / stop / reboot
    # ------------------------------------------------------------------

    def _ovh_unavailable(self, tool_name: str, payload: dict) -> str:
        """Return a uniform "not configured" message + audit row.

        Mirrors :meth:`_hetzner_unavailable` so the agent gets the same
        actionable hint regardless of which provider it's reaching for.
        """
        msg = (
            "OVHcloud is not configured. Set ovh.enabled=true and "
            "credentials in ~/.servonaut/config.json (or visit Settings → "
            "OVHcloud in the TUI)."
        )
        self._audit.log(tool_name, payload, msg, False, "not_configured")
        return msg

    async def ovh_create_instance(
        self,
        project_id: str,
        name: str,
        flavor_id: str,
        image_id: str,
        region: str,
        ssh_key_id: Optional[str] = None,
    ) -> str:
        """Create an OVH Public Cloud instance."""
        payload = {
            'project_id': project_id, 'name': name,
            'flavor_id': flavor_id, 'image_id': image_id,
            'region': region, 'ssh_key_id': ssh_key_id,
        }
        cloud_svc = getattr(self, '_ovh_cloud_service', None)
        if cloud_svc is None:
            return self._ovh_unavailable('ovh_create_instance', payload)

        allowed, reason = self._guard.check_tool('ovh_create_instance')
        if not allowed:
            self._audit.log('ovh_create_instance', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            result = await cloud_svc.create_instance(
                project_id=project_id,
                name=name,
                flavor_id=flavor_id,
                image_id=image_id,
                region=region,
                ssh_key_id=ssh_key_id or "",
            )
        except ValueError as exc:
            self._audit.log(
                'ovh_create_instance', payload, '', False, f"validation: {exc}",
            )
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log(
                'ovh_create_instance', payload, '', False, f"api_error: {exc}",
            )
            return f"Error creating OVH instance {name!r}: {exc}"

        text = (
            f"Created OVH Cloud instance {result.get('name', name)!r} "
            f"(id={result.get('id', '?')}, status={result.get('status', '?')}, "
            f"flavor={flavor_id}, region={region})."
        )
        self._audit.log('ovh_create_instance', payload, text, True)
        return text

    async def ovh_delete_instance(
        self, project_id: str, instance_id: str,
    ) -> str:
        """Delete an OVH Public Cloud instance."""
        payload = {'project_id': project_id, 'instance_id': instance_id}
        cloud_svc = getattr(self, '_ovh_cloud_service', None)
        if cloud_svc is None:
            return self._ovh_unavailable('ovh_delete_instance', payload)

        allowed, reason = self._guard.check_tool('ovh_delete_instance')
        if not allowed:
            self._audit.log('ovh_delete_instance', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            await cloud_svc.delete_instance(project_id, instance_id)
        except ValueError as exc:
            self._audit.log(
                'ovh_delete_instance', payload, '', False, f"validation: {exc}",
            )
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log(
                'ovh_delete_instance', payload, '', False, f"api_error: {exc}",
            )
            return f"Error deleting OVH instance {project_id}/{instance_id}: {exc}"

        text = f"Deleted OVH instance {project_id}/{instance_id}."
        self._audit.log('ovh_delete_instance', payload, text, True)
        return text

    async def _ovh_lifecycle(
        self, tool_name: str, method: str,
        instance_id: str, provider_type: str, verb: str,
    ) -> str:
        """Shared handler for OVH start/stop/reboot.

        Routes through the existing :class:`OVHService` lifecycle methods
        which already encode the per-resource-type endpoints (cloud, vps,
        dedicated). The audit row records both the id and the
        provider_type so post-mortem queries can see which resource path
        was taken.
        """
        payload = {'instance_id': instance_id, 'provider_type': provider_type}
        if self._ovh_service is None:
            return self._ovh_unavailable(tool_name, payload)

        allowed, reason = self._guard.check_tool(tool_name)
        if not allowed:
            self._audit.log(tool_name, payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            await getattr(self._ovh_service, method)(instance_id, provider_type)
        except ValueError as exc:
            self._audit.log(
                tool_name, payload, '', False, f"validation: {exc}",
            )
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log(
                tool_name, payload, '', False, f"api_error: {exc}",
            )
            return f"Error: {verb} failed on OVH {provider_type} {instance_id}: {exc}"

        text = f"OVH {provider_type} {instance_id}: {verb}."
        self._audit.log(tool_name, payload, text, True)
        return text

    async def ovh_start_instance(
        self, instance_id: str, provider_type: str,
    ) -> str:
        return await self._ovh_lifecycle(
            'ovh_start_instance', 'start_instance',
            instance_id, provider_type, 'started',
        )

    async def ovh_stop_instance(
        self, instance_id: str, provider_type: str,
    ) -> str:
        return await self._ovh_lifecycle(
            'ovh_stop_instance', 'stop_instance',
            instance_id, provider_type, 'stop sent',
        )

    async def ovh_reboot_instance(
        self, instance_id: str, provider_type: str,
    ) -> str:
        return await self._ovh_lifecycle(
            'ovh_reboot_instance', 'reboot_instance',
            instance_id, provider_type, 'reboot sent',
        )

    # ------------------------------------------------------------------
    # AWS CloudWatch Logs tools (read-only)
    # ------------------------------------------------------------------

    async def cloudwatch_list_log_groups(
        self, prefix: str = "", region: str = ""
    ) -> str:
        """List CloudWatch log groups, optionally filtered by name prefix."""
        args = {'prefix': prefix, 'region': region}
        allowed, reason = self._guard.check_tool('cloudwatch_list_log_groups')
        if not allowed:
            self._audit.log('cloudwatch_list_log_groups', args, '', False, reason)
            return f"Blocked: {reason}"
        if self._cloudwatch_service is None:
            self._audit.log(
                'cloudwatch_list_log_groups', args, '', False, 'service_unavailable',
            )
            return "Error: CloudWatch service is not available."

        try:
            groups = await self._cloudwatch_service.list_log_groups(prefix, region)
        except Exception as e:
            self._audit.log(
                'cloudwatch_list_log_groups', args, '', False, f"api_error: {e}",
            )
            return f"Error listing CloudWatch log groups: {e}"

        if not groups:
            self._audit.log('cloudwatch_list_log_groups', args, '0 groups', True)
            return "No CloudWatch log groups found."

        lines = [
            f"CloudWatch log groups ({len(groups)} total):",
            f"  {'Name':<56} {'Stored bytes':<14} Retention",
            '  ' + '-' * 86,
        ]
        for g in groups:
            retention = g.get('retention_days')
            retention_str = f"{retention}d" if retention else "never expire"
            lines.append(
                f"  {str(g.get('name', ''))[:56]:<56} "
                f"{str(g.get('stored_bytes', 0)):<14} {retention_str}"
            )

        result = '\n'.join(lines)
        self._audit.log('cloudwatch_list_log_groups', args, result, True)
        return result

    async def cloudwatch_get_log_events(
        self, log_group: str, hours_back: int = 1,
        filter_pattern: str = "", region: str = "", max_events: int = 100,
        group_by: str = "", top_n: int = 0, summary_only: bool = False,
        client_ip: str = "",
    ) -> str:
        """Get recent log events from a CloudWatch log group.

        Additive aggregation (avoids dumping 1.5MB of raw events): set
        ``group_by`` to ``clientIp``, ``status`` or ``uri`` to get back a
        server-side ranked summary (top ``top_n``, default 20) instead of raw
        lines. ``summary_only`` returns just the event count.

        Filter handling: a bare ``filter_pattern`` literal (an IP, a path) is
        auto-quoted before it reaches CloudWatch — a raw dotted string is
        tokenised and silently fails to match otherwise. Pass ``client_ip`` to
        build the structured WAF/ALB selector ``{ $.httpRequest.clientIp = "x" }``
        server-side. An empty result is reported as "0 matched filter X",
        never conflated with "the group is empty".
        """
        args = {
            'log_group': log_group, 'hours_back': hours_back,
            'filter_pattern': filter_pattern, 'region': region,
            'max_events': max_events, 'group_by': group_by,
            'top_n': top_n, 'summary_only': summary_only,
            'client_ip': client_ip,
        }
        allowed, reason = self._guard.check_tool('cloudwatch_get_log_events')
        if not allowed:
            self._audit.log('cloudwatch_get_log_events', args, '', False, reason)
            return f"Blocked: {reason}"
        if self._cloudwatch_service is None:
            self._audit.log(
                'cloudwatch_get_log_events', args, '', False, 'service_unavailable',
            )
            return "Error: CloudWatch service is not available."

        group = (group_by or "").strip()
        if group and group not in ("clientIp", "status", "uri"):
            self._audit.log(
                'cloudwatch_get_log_events', args, '', False, 'bad_group_by',
            )
            return (f"Error: group_by must be 'clientIp', 'status', or 'uri'; "
                    f"got {group_by!r}.")

        # Resolve the effective CloudWatch filter pattern. client_ip builds a
        # structured selector; otherwise a bare literal term is auto-quoted.
        raw_filter = (filter_pattern or "").strip()
        if client_ip:
            ip_arg = client_ip.strip()
            try:
                from ipaddress import ip_address
                ip_address(ip_arg)
            except ValueError:
                self._audit.log(
                    'cloudwatch_get_log_events', args, '', False, 'bad_client_ip',
                )
                return f"Error: client_ip {client_ip!r} is not a valid IP address."
            effective_filter = '{ $.httpRequest.clientIp = "%s" }' % ip_arg
        else:
            effective_filter = self._cloudwatch_service.normalize_filter_pattern(
                raw_filter
            )
        filter_rewritten = bool(effective_filter) and effective_filter != raw_filter

        from datetime import datetime, timedelta
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=max(int(hours_back), 1))

        try:
            events = await self._cloudwatch_service.get_log_events(
                log_group, start_time, end_time,
                effective_filter, region, max_events,
            )
        except Exception as e:
            self._audit.log(
                'cloudwatch_get_log_events', args, '', False, f"api_error: {e}",
            )
            return f"Error fetching CloudWatch log events: {e}"

        if not events:
            self._audit.log('cloudwatch_get_log_events', args, '0 events', True)
            if effective_filter:
                # Critical: a filtered empty result means "nothing matched",
                # NOT "the group is empty" — conflating the two sent a live
                # investigation toward a false WAF-bypass conclusion.
                return (
                    f"0 events matched filter {effective_filter!r} in {log_group} "
                    f"over the last {hours_back}h. The group may still be "
                    f"receiving traffic that doesn't match — re-run without a "
                    f"filter (or with cloudwatch_top_ips) to confirm it's live."
                )
            return f"No log events in {log_group} for the last {hours_back}h."

        # --- aggregation mode --------------------------------------------
        if group:
            limit = top_n if top_n and top_n > 0 else 20
            agg = self._cloudwatch_service.aggregate_events(events, group, limit)
            sampled = len(events) >= max_events
            out = [
                f"CloudWatch {log_group} (last {hours_back}h) — top {group} "
                f"by count [{agg['total_matched']}/{agg['total_events']} events"
                + (", SAMPLED (hit max_events — widen max_events for full counts)"
                   if sampled else "") + "]:",
                f"  {'key':<46} {'count':<8} pct",
                "  " + "-" * 62,
            ]
            for row in agg["ranking"]:
                out.append(f"  {str(row['key'])[:46]:<46} "
                           f"{row['count']:<8} {row['pct']}%")
            if not agg["ranking"]:
                out.append(f"  (no events carried a {group} field — not "
                           "structured WAF/ALB JSON?)")
            result = "\n".join(out)
            self._audit.log('cloudwatch_get_log_events', args, result, True)
            return result

        # --- summary-only mode -------------------------------------------
        if summary_only:
            result = (f"{len(events)} events in {log_group} over the last "
                      f"{hours_back}h"
                      + (" (sampled — hit max_events)"
                         if len(events) >= max_events else "") + ".")
            self._audit.log('cloudwatch_get_log_events', args, result, True)
            return result

        matched_note = " matched" if effective_filter else ""
        lines = [
            f"CloudWatch events: {log_group} "
            f"(last {hours_back}h, {len(events)}{matched_note} events)"
        ]
        if filter_rewritten:
            lines.append(f"  (filter normalized to {effective_filter!r} so it "
                         "matches reliably)")
        display = events
        if len(display) > self._max_lines:
            display = display[-self._max_lines:]
            lines.append(
                f"... (showing the most recent {self._max_lines} "
                f"of {len(events)} events)"
            )
        for e in display:
            ts = e.get('timestamp')
            ts_str = (
                ts.isoformat(sep=' ', timespec='seconds')
                if hasattr(ts, 'isoformat') else str(ts)
            )
            msg = str(e.get('message', '')).rstrip()
            lines.append(f"  [{ts_str}] {msg}")

        result = '\n'.join(lines)
        self._audit.log('cloudwatch_get_log_events', args, result, True)
        return result

    async def cloudwatch_top_ips(
        self, log_group: str, hours_back: int = 24,
        action_filter: str = "", region: str = "",
        limit: int = 20, max_events: int = 0,
    ) -> str:
        """Rank the top client IPs seen in a CloudWatch log group.

        Parses WAF/ALB structured JSON logs to extract ``clientIp`` and the
        WAF ``action``, returning per-IP allowed/blocked counts. Use this to
        spot abusive IPs before banning them with ``ip_ban_set``.
        """
        args = {
            'log_group': log_group, 'hours_back': hours_back,
            'action_filter': action_filter, 'region': region,
            'limit': limit, 'max_events': max_events,
        }
        allowed, reason = self._guard.check_tool('cloudwatch_top_ips')
        if not allowed:
            self._audit.log('cloudwatch_top_ips', args, '', False, reason)
            return f"Blocked: {reason}"
        if self._cloudwatch_service is None:
            self._audit.log(
                'cloudwatch_top_ips', args, '', False, 'service_unavailable',
            )
            return "Error: CloudWatch service is not available."

        action = (action_filter or "").strip().upper()
        if action and action not in ('ALLOW', 'BLOCK'):
            self._audit.log(
                'cloudwatch_top_ips', args, '', False, 'invalid_action_filter',
            )
            return (
                f"Error: action_filter must be 'ALLOW', 'BLOCK', or empty; "
                f"got {action_filter!r}."
            )

        from datetime import datetime, timedelta
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=max(int(hours_back), 1))

        try:
            events = await self._cloudwatch_service.get_log_events(
                log_group, start_time, end_time, "", region, max_events,
            )
        except Exception as e:
            self._audit.log(
                'cloudwatch_top_ips', args, '', False, f"api_error: {e}",
            )
            return f"Error fetching CloudWatch log events: {e}"

        top = self._cloudwatch_service.extract_top_ips(
            events, limit, action or None,
        )
        if not top:
            self._audit.log('cloudwatch_top_ips', args, '0 ips', True)
            return (
                f"No client IPs found in {log_group} over the last "
                f"{hours_back}h ({len(events)} events scanned)."
            )

        filt_note = f", action={action}" if action else ""
        lines = [
            f"Top {len(top)} client IPs in {log_group} "
            f"(last {hours_back}h, {len(events)} events{filt_note}):",
            f"  {'IP':<22} {'Total':<10} {'Allowed':<10} {'Blocked':<10}",
            '  ' + '-' * 54,
        ]
        for row in top:
            lines.append(
                f"  {str(row.get('ip', '')):<22} "
                f"{str(row.get('count', 0)):<10} "
                f"{str(row.get('allowed', 0)):<10} "
                f"{str(row.get('blocked', 0)):<10}"
            )

        result = '\n'.join(lines)
        self._audit.log('cloudwatch_top_ips', args, result, True)
        return result

    async def cloudwatch_insights(
        self, query: str, log_groups: Optional[List[str]] = None,
        log_group: str = "", hours_back: int = 1, region: str = "",
        limit: int = 1000, timeout_seconds: int = 60,
    ) -> str:
        """Run a CloudWatch Logs Insights query over one or more log groups.

        Insights is the general aggregation primitive — top IPs, status mix,
        URI ranking, time-bucketing — so you don't need a bespoke parser per
        question. Pass either ``log_group`` (single) or ``log_groups`` (list)
        plus a ``query`` string, e.g.::

            stats count(*) as hits by httpRequest.clientIp
            | sort hits desc | limit 20
        """
        groups = list(log_groups or [])
        if log_group:
            groups.append(log_group)
        groups = [g for g in (g.strip() for g in groups) if g]
        args = {
            'query': query, 'log_groups': groups, 'hours_back': hours_back,
            'region': region, 'limit': limit, 'timeout_seconds': timeout_seconds,
        }
        allowed, reason = self._guard.check_tool('cloudwatch_insights')
        if not allowed:
            self._audit.log('cloudwatch_insights', args, '', False, reason)
            return f"Blocked: {reason}"
        if self._cloudwatch_service is None:
            self._audit.log(
                'cloudwatch_insights', args, '', False, 'service_unavailable',
            )
            return "Error: CloudWatch service is not available."
        if not groups:
            self._audit.log('cloudwatch_insights', args, '', False, 'no_log_group')
            return "Error: provide a log_group or a non-empty log_groups list."
        if not (query or "").strip():
            self._audit.log('cloudwatch_insights', args, '', False, 'empty_query')
            return "Error: query must not be empty."

        from datetime import datetime, timedelta
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=max(int(hours_back), 1))

        try:
            res = await self._cloudwatch_service.run_insights_query(
                groups, query, start_time, end_time, region,
                max(1, int(limit)), max(5, int(timeout_seconds)),
            )
        except Exception as e:
            self._audit.log(
                'cloudwatch_insights', args, '', False, f"api_error: {e}",
            )
            return f"Error running CloudWatch Logs Insights query: {e}"

        status = res.get("status", "Unknown")
        rows = res.get("rows", [])
        columns = res.get("columns", [])
        if status != "Complete":
            note = {
                "Timeout": (f"query did not finish within {timeout_seconds}s — "
                            "narrow the window or raise timeout_seconds"),
                "Failed": "query failed — check the query syntax",
                "Cancelled": "query was cancelled",
            }.get(status, f"query ended with status {status}")
            result = f"CloudWatch Insights ({status}): {note}."
            self._audit.log('cloudwatch_insights', args, result, True)
            return result
        if not rows:
            result = (f"CloudWatch Insights: 0 rows over the last {hours_back}h "
                      f"across {len(groups)} group(s).")
            self._audit.log('cloudwatch_insights', args, result, True)
            return result

        # Drop the synthetic @ptr column Insights appends to non-stats queries.
        cols = [c for c in columns if c != "@ptr"] or columns
        widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
        out = [
            f"CloudWatch Insights — {len(rows)} row(s), last {hours_back}h "
            f"({len(groups)} group(s)):",
            "  " + "  ".join(c.ljust(min(widths[c], 48)) for c in cols),
            "  " + "-" * min(sum(min(widths[c], 48) + 2 for c in cols), 110),
        ]
        for r in rows[:self._max_lines]:
            out.append("  " + "  ".join(
                str(r.get(c, "")).ljust(min(widths[c], 48)) for c in cols
            ))
        if len(rows) > self._max_lines:
            out.append(f"  ... ({len(rows) - self._max_lines} more rows; "
                       "tighten the query's limit)")
        result = "\n".join(out)
        self._audit.log('cloudwatch_insights', args, result, True)
        return result

    # ------------------------------------------------------------------
    # Generic AWS API passthrough (aws_call)
    # ------------------------------------------------------------------

    def _get_aws_factory(self):
        """Return the shared AWS client factory, building it lazily from config."""
        if self._aws_client_factory is None:
            from servonaut.services.aws_client_factory import (
                build_aws_client_factory,
            )
            self._aws_client_factory = build_aws_client_factory(
                self._config_manager.get()
            )
        return self._aws_client_factory

    async def aws_call(
        self, service: str, operation: str,
        params: Optional[Dict[str, Any]] = None,
        region: str = "", account: str = "",
        mutate: bool = False, max_items: int = 0,
        confirm: str = "",
    ) -> str:
        """Generic boto3 passthrough — call any AWS describe/get/list/filter op.

        This ends the "not pre-wrapped" dead-ends: any read in the account's
        IAM scope is reachable without a bespoke tool (DescribeSecurityGroupRules,
        GetIPSet, GetWebACL, FilterLogEvents, DescribeTargetHealth, …).

        ``operation`` is the boto3 snake_case method name (``get_ip_set``,
        ``describe_security_group_rules``). Reads (Describe/Get/List/Filter/
        Lookup/Head/BatchGet/Search prefixes) run read-only and auto-paginate.
        Mutating ops require ``mutate=true`` AND dangerous guard mode.

        Destructive verbs (delete/terminate/destroy/purge) are refused unless
        ``allow_destructive_aws_call`` is enabled in config; even then they run
        only behind a MANDATORY two-phase confirmation: the first call returns a
        summary + single-use token and does NOT touch AWS; you must re-call with
        ``confirm`` set to that token. The most unrecoverable ops stay refused
        regardless. ``region``/``account`` pin the call; the configured control-
        plane STS role (if any) is assumed automatically.
        """
        params = params or {}
        args = {
            'service': service, 'operation': operation, 'params': params,
            'region': region, 'account': account, 'mutate': mutate,
            'max_items': max_items, 'confirm': bool(confirm),
        }
        allowed, reason = self._guard.check_tool('aws_call')
        if not allowed:
            self._audit.log('aws_call', args, '', False, reason)
            return f"Blocked: {reason}"

        svc = (service or "").strip()
        op = (operation or "").strip()
        if not _AWS_SERVICE_RE.match(svc):
            self._audit.log('aws_call', args, '', False, 'validation: bad_service')
            return f"Error: invalid service name {service!r}."
        if not _AWS_OPERATION_RE.match(op):
            self._audit.log('aws_call', args, '', False, 'validation: bad_operation')
            return (f"Error: invalid operation {operation!r} — expected a boto3 "
                    "snake_case method name like 'describe_security_group_rules'.")
        if not isinstance(params, dict):
            self._audit.log('aws_call', args, '', False, 'validation: bad_params')
            return "Error: params must be an object (mapping of boto3 arguments)."

        is_read = op.startswith(_AWS_READ_PREFIXES)
        is_destructive = op.startswith(_AWS_DESTRUCTIVE_PREFIXES)
        if is_destructive:
            # 1. Never-allow floor: the most unrecoverable ops, regardless of config.
            if op in _AWS_NEVER_DESTRUCTIVE:
                self._audit.log('aws_call', args, '', False, 'blocked_destructive_floor')
                return (f"Error: '{op}' causes unrecoverable data/fleet loss and "
                        "is never available via aws_call. Use a curated tool or "
                        "the AWS console where the snapshot/retention semantics "
                        "are explicit.")
            # 2. Opt-in: destructive verbs are off unless enabled in config.
            if not self._config_manager.get().mcp.allow_destructive_aws_call:
                self._audit.log('aws_call', args, '', False, 'blocked_destructive_disabled')
                return (f"Error: '{op}' is a destructive operation. It is disabled "
                        "by default. Set mcp.allow_destructive_aws_call=true in "
                        "config to enable it (still gated by dangerous guard mode "
                        "+ mutate=true + a mandatory confirmation), or use a "
                        "curated tool (aws_terminate_instance, …).")
            # 3. Destructive is a mutation: require mutate=true + dangerous tier.
            if not mutate:
                self._audit.log('aws_call', args, '', False, 'mutate_required')
                return (f"Error: '{op}' is destructive — re-run with mutate=true "
                        "(requires dangerous guard mode).")
            m_allowed, m_reason = self._guard.check_tool('aws_call_mutate')
            if not m_allowed:
                self._audit.log('aws_call', args, '', False, m_reason)
                return f"Blocked: {m_reason}"
            # 4. MANDATORY two-phase confirmation token.
            gate = self._aws_confirm_gate(svc, op, params, region, account,
                                          confirm, args)
            if gate is not None:
                return gate  # confirmation-required summary, or token error
        elif not is_read:
            if not mutate:
                self._audit.log('aws_call', args, '', False, 'mutate_required')
                return (f"Error: '{op}' is not a read operation. Re-run with "
                        "mutate=true (requires dangerous guard mode) if you "
                        "intend to change state, or use a curated tool.")
            m_allowed, m_reason = self._guard.check_tool('aws_call_mutate')
            if not m_allowed:
                self._audit.log('aws_call', args, '', False, m_reason)
                return f"Blocked: {m_reason}"

        try:
            result = await asyncio.to_thread(
                self._aws_call_sync, svc, op, params, region, account,
                is_read, max_items,
            )
        except ValueError as e:
            self._audit.log('aws_call', args, '', False, f"validation: {e}")
            return f"Error: {e}"
        except Exception as e:  # noqa: BLE001 - surface boto3/botocore errors
            self._audit.log('aws_call', args, '', False, f"api_error: {e}")
            return f"Error calling {svc}.{op}: {e}"

        text = self._format_aws_call_result(svc, op, result)
        self._audit.log('aws_call', args, text, True)
        return text

    @staticmethod
    def _aws_call_signature(
        service: str, op: str, params: Dict[str, Any], region: str, account: str,
    ) -> str:
        """Stable hash of the exact call — binds a confirm token to one action."""
        payload = json.dumps(
            {"s": service, "o": op, "p": params, "r": region, "a": account},
            sort_keys=True, default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _aws_confirm_gate(
        self, service: str, op: str, params: Dict[str, Any],
        region: str, account: str, confirm: str, args: Dict[str, Any],
    ) -> Optional[str]:
        """Two-phase confirmation for a destructive aws_call.

        Returns a string to short-circuit aws_call (the CONFIRMATION REQUIRED
        summary, or a token error) — or ``None`` to let the op execute. The op
        physically cannot run on the first call: a single-use token bound to the
        exact (service, op, params, region, account) must be echoed back.
        """
        now = time.time()
        sig = self._aws_call_signature(service, op, params, region, account)
        confirm = (confirm or "").strip()

        if not confirm:
            # Issue a fresh token; prune any stale ones while we're here.
            self._aws_confirm_staging = {
                t: v for t, v in self._aws_confirm_staging.items()
                if v["expires_at"] > now
            }
            token = secrets.token_urlsafe(18)
            self._aws_confirm_staging[token] = {
                "signature": sig, "expires_at": now + _AWS_CONFIRM_TTL_SECONDS,
            }
            summary = (
                "CONFIRMATION REQUIRED — destructive AWS operation (NOT executed)\n"
                f"  service.operation: {service}.{op}\n"
                f"  region / account:  {region or '(default)'} / "
                f"{account or '(default)'}\n"
                f"  params:            {json.dumps(params, default=str, sort_keys=True)}\n"
                "This runs a destructive operation against live AWS and cannot be "
                "undone here. Confirm with the user first, then re-call aws_call "
                "with the SAME service/operation/params/region/account and "
                f'confirm="{token}" within {_AWS_CONFIRM_TTL_SECONDS // 60} '
                "minutes to execute."
            )
            self._audit.log('aws_call', args, summary, False, 'confirmation_required')
            return summary

        # Confirm provided — consume the token (single-use) and validate it.
        staged = self._aws_confirm_staging.pop(confirm, None)
        if staged is None:
            self._audit.log('aws_call', args, '', False, 'bad_confirm_token')
            return ("Error: confirmation token is unknown or already used. "
                    "Re-run without confirm to get a fresh token.")
        if staged["expires_at"] <= now:
            self._audit.log('aws_call', args, '', False, 'expired_confirm_token')
            return ("Error: confirmation token expired. Re-run without confirm "
                    "to get a fresh token.")
        if staged["signature"] != sig:
            self._audit.log('aws_call', args, '', False, 'mismatched_confirm_token')
            return ("Error: confirmation token does not match this call — the "
                    "service/operation/params/region/account differ from what "
                    "was confirmed. Re-run without confirm to get a fresh token.")
        return None  # valid → proceed to execute

    def _aws_call_sync(
        self, service: str, operation: str, params: Dict[str, Any],
        region: str, account: str, is_read: bool, max_items: int,
    ) -> Any:
        """Build the client (via factory) and invoke the boto3 operation."""
        factory = self._get_aws_factory()
        # Write calls use the separate mutate role (or ambient creds) — never
        # the read-only control-plane role, which would only AccessDenied.
        client = factory.client(
            service, region=region, account=account, mutate=not is_read,
        )
        method = getattr(client, operation, None)
        if method is None or not callable(method):
            raise ValueError(
                f"operation '{operation}' is not valid for service '{service}'"
            )
        # Auto-paginate reads so a windowed query returns the full result set
        # (capped) rather than just the first page.
        if is_read and client.can_paginate(operation):
            cap = max_items if max_items and max_items > 0 \
                else _AWS_CALL_DEFAULT_MAX_ITEMS
            paginator = client.get_paginator(operation)
            paginate_kwargs = dict(params)
            paginate_kwargs["PaginationConfig"] = {"MaxItems": cap}
            return paginator.paginate(**paginate_kwargs).build_full_result()
        return method(**params)

    @staticmethod
    def _format_aws_call_result(service: str, operation: str, result: Any) -> str:
        """Serialise a boto3 response to JSON, dropping noise and capping size."""
        if isinstance(result, dict):
            result = {k: v for k, v in result.items() if k != "ResponseMetadata"}
        body = json.dumps(result, indent=2, default=str, sort_keys=True)
        truncated = len(body) > _AWS_CALL_MAX_RESULT_CHARS
        if truncated:
            body = body[:_AWS_CALL_MAX_RESULT_CHARS]
        header = f"aws_call {service}.{operation} →"
        if truncated:
            body += (f"\n... [truncated at {_AWS_CALL_MAX_RESULT_CHARS} chars — "
                     "narrow params or lower max_items]")
        return f"{header}\n{body}"

    # ------------------------------------------------------------------
    # AWS CloudTrail tools (read-only)
    # ------------------------------------------------------------------

    async def cloudtrail_lookup_events(
        self, region: str = "", hours_back: int = 0,
        event_name: str = "", username: str = "",
        resource_type: str = "", max_results: int = 50,
    ) -> str:
        """Look up AWS CloudTrail management events with optional filters."""
        args = {
            'region': region, 'hours_back': hours_back,
            'event_name': event_name, 'username': username,
            'resource_type': resource_type, 'max_results': max_results,
        }
        allowed, reason = self._guard.check_tool('cloudtrail_lookup_events')
        if not allowed:
            self._audit.log('cloudtrail_lookup_events', args, '', False, reason)
            return f"Blocked: {reason}"
        if self._cloudtrail_service is None:
            self._audit.log(
                'cloudtrail_lookup_events', args, '', False, 'service_unavailable',
            )
            return "Error: CloudTrail service is not available."

        start_time = None
        if hours_back and int(hours_back) > 0:
            from datetime import datetime, timedelta
            start_time = datetime.utcnow() - timedelta(hours=int(hours_back))

        try:
            events = await self._cloudtrail_service.lookup_events(
                region=region, start_time=start_time,
                event_name=event_name, username=username,
                resource_type=resource_type, max_results=max_results,
            )
        except Exception as e:
            self._audit.log(
                'cloudtrail_lookup_events', args, '', False, f"api_error: {e}",
            )
            return f"Error looking up CloudTrail events: {e}"

        if not events:
            self._audit.log('cloudtrail_lookup_events', args, '0 events', True)
            return "No CloudTrail events matched the given filters."

        lines = [
            f"CloudTrail events ({len(events)} found):",
            f"  {'Time':<20} {'Event':<26} {'User':<20} "
            f"{'Source IP':<16} {'Region':<14} Error",
            '  ' + '-' * 110,
        ]
        for e in events:
            ev_time = e.get('event_time', '')
            ev_time_str = (
                ev_time.isoformat(sep=' ', timespec='seconds')
                if hasattr(ev_time, 'isoformat') else str(ev_time)
            )
            lines.append(
                f"  {ev_time_str[:20]:<20} "
                f"{str(e.get('event_name', ''))[:26]:<26} "
                f"{str(e.get('username', ''))[:20]:<20} "
                f"{str(e.get('source_ip', ''))[:16]:<16} "
                f"{str(e.get('region', ''))[:14]:<14} "
                f"{e.get('error_code', '')}"
            )

        result = '\n'.join(lines)
        self._audit.log('cloudtrail_lookup_events', args, result, True)
        return result

    # ------------------------------------------------------------------
    # IP ban tools (WAF / Security Group / NACL)
    # ------------------------------------------------------------------

    async def ip_ban_list_configs(self) -> str:
        """List the configured IP-ban targets (WAF IP sets, SGs, NACLs)."""
        allowed, reason = self._guard.check_tool('ip_ban_list_configs')
        if not allowed:
            self._audit.log('ip_ban_list_configs', {}, '', False, reason)
            return f"Blocked: {reason}"
        if self._ip_ban_service is None:
            self._audit.log(
                'ip_ban_list_configs', {}, '', False, 'service_unavailable',
            )
            return "Error: IP ban service is not available."

        configs = self._ip_ban_service.get_configs()
        if not configs:
            self._audit.log('ip_ban_list_configs', {}, '0 configs', True)
            return (
                "No IP ban configurations defined. Add one in Settings "
                "(WAF IP set, Security Group, or NACL) before banning."
            )

        lines = [
            f"IP ban configurations ({len(configs)} total):",
            f"  {'Name':<24} {'Method':<16} {'Region':<14} Target",
            '  ' + '-' * 80,
        ]
        for c in configs:
            method = getattr(c, 'method', '')
            if method == 'waf':
                target = getattr(c, 'ip_set_name', '') or getattr(c, 'ip_set_id', '')
            elif method == 'security_group':
                target = getattr(c, 'security_group_id', '')
            elif method == 'nacl':
                target = getattr(c, 'nacl_id', '')
            else:
                target = ''
            lines.append(
                f"  {str(getattr(c, 'name', ''))[:24]:<24} "
                f"{str(method)[:16]:<16} "
                f"{str(getattr(c, 'region', '') or '-')[:14]:<14} "
                f"{target}"
            )

        result = '\n'.join(lines)
        self._audit.log('ip_ban_list_configs', {}, result, True)
        return result

    async def ip_ban_list_banned(self, config_name: str) -> str:
        """List the IP addresses currently banned under a named config."""
        args = {'config_name': config_name}
        allowed, reason = self._guard.check_tool('ip_ban_list_banned')
        if not allowed:
            self._audit.log('ip_ban_list_banned', args, '', False, reason)
            return f"Blocked: {reason}"
        if self._ip_ban_service is None:
            self._audit.log(
                'ip_ban_list_banned', args, '', False, 'service_unavailable',
            )
            return "Error: IP ban service is not available."

        try:
            banned = await self._ip_ban_service.list_banned(config_name)
        except ValueError as e:
            self._audit.log('ip_ban_list_banned', args, '', False, f"config: {e}")
            return f"Error: {e}"
        except Exception as e:
            self._audit.log('ip_ban_list_banned', args, '', False, f"api_error: {e}")
            return f"Error listing banned IPs for {config_name!r}: {e}"

        if not banned:
            self._audit.log('ip_ban_list_banned', args, '0 banned', True)
            return f"No IPs currently banned under config {config_name!r}."

        lines = [f"Banned IPs under {config_name!r} ({len(banned)} total):"]
        for cidr in banned:
            lines.append(f"  {cidr}")

        result = '\n'.join(lines)
        self._audit.log('ip_ban_list_banned', args, result, True)
        return result

    async def ip_ban_set(
        self, ip_address: str, config_name: str, action: str = "ban",
    ) -> str:
        """Ban or unban an IP address via a named WAF/SG/NACL config.

        ``action`` must be ``"ban"`` or ``"unban"``. The underlying
        IPBanService validates the IP and records every action to its own
        audit trail in addition to the MCP audit log.
        """
        args = {
            'ip_address': ip_address, 'config_name': config_name,
            'action': action,
        }
        allowed, reason = self._guard.check_tool('ip_ban_set')
        if not allowed:
            self._audit.log('ip_ban_set', args, '', False, reason)
            return f"Blocked: {reason}"
        if self._ip_ban_service is None:
            self._audit.log('ip_ban_set', args, '', False, 'service_unavailable')
            return "Error: IP ban service is not available."

        action_norm = (action or "").strip().lower()
        if action_norm not in ('ban', 'unban'):
            self._audit.log('ip_ban_set', args, '', False, 'invalid_action')
            return f"Error: action must be 'ban' or 'unban', got {action!r}."

        try:
            if action_norm == 'ban':
                result = await self._ip_ban_service.ban_ip(ip_address, config_name)
            else:
                result = await self._ip_ban_service.unban_ip(ip_address, config_name)
        except Exception as e:
            self._audit.log('ip_ban_set', args, '', False, f"error: {e}")
            return f"Error during {action_norm} of {ip_address}: {e}"

        success = bool(result.get('success'))
        message = result.get('message', '')
        self._audit.log('ip_ban_set', args, message, success)
        return f"{'OK' if success else 'Failed'}: {message}"

    def _resolve_connection(self, instance: Dict) -> Dict:
        """Resolve SSH connection parameters for an instance."""
        profile = self._connection_service.resolve_profile(instance)
        host = self._connection_service.get_target_host(instance, profile)
        proxy_args = self._connection_service.get_proxy_args(profile) if profile else []
        extra_options = self._connection_service.get_extra_options(instance, profile)

        if instance.get('is_ovh'):
            from servonaut.services.ovh_service import OVHService
            provider_type = instance.get('provider_type', '')
            username = OVHService.default_username(provider_type)
            key_path = self._config_manager.get().default_key or None
            port = None
        elif instance.get('is_hetzner'):
            # Hetzner cloud-init does not seed a non-root user on the
            # standard images; fall back to the per-provider default
            # configured by the operator (typically ``root``).
            username = (
                instance.get('username')
                or self._config_manager.get().default_username
                or 'root'
            )
            # The instance dict carries the operator-configured default
            # SSH key (resolved via $ENV_VAR/file: at probe time) so the
            # local SSH command can authenticate without re-querying
            # config here.
            key_path = instance.get('ssh_key') or None
            port = None
        elif instance.get('is_custom'):
            username = (
                instance.get('username')
                or self._config_manager.get().default_username
                or 'root'
            )
            key_path = instance.get('ssh_key') or instance.get('key_name') or None
            port = instance.get('port') or None
        else:
            username = (
                (profile.username if profile else None)
                or self._config_manager.get().default_username
            )
            instance_id = instance.get('id', '')
            key_path = self._ssh_service.get_key_path(instance_id)
            if not key_path and instance.get('key_name'):
                key_path = self._ssh_service.discover_key(instance['key_name'])
            port = None

        return {
            'host': host, 'username': username, 'key_path': key_path,
            'proxy_args': proxy_args, 'profile': profile, 'port': port,
            'extra_options': extra_options,
        }

    async def _resolve_connection_with_vault(self, instance: Dict):
        """Resolve connection params, preferring a stored Bitwarden ref.

        Wraps :meth:`_resolve_connection` (unchanged) with the same
        personal-tier Bitwarden resolution the TUI connect flow uses: if the
        user stored a vault ref for this instance, resolve the key body via
        the ``bw`` CLI (ambient ``BW_SESSION`` is the headless session
        source) and point ``key_path`` at a 0600 temp file.

        Returns ``(conn, cleanup)``:

        - ``conn`` — the connection dict. When the vault key was used it is a
          copy with ``key_path`` set to the temp file and
          ``key_source='bw_personal'``; otherwise the untouched local result.
        - ``cleanup`` — ``None``, or a zero-arg ASYNC callable that
          best-effort removes the temp key file (the zero-overwrite +
          ``fsync`` runs in a thread so it never stalls the event loop).
          Callers MUST ``await`` it in a ``finally`` after the ssh/scp
          subprocess completes: the MCP server is long-running, so key
          lifetime is strictly per-call.

        The ssh-ref lookup (positive and negative results alike) is memoized
        per ``(provider, instance_id)`` for :data:`_BW_REF_MEMO_TTL_SECONDS`
        so fleet-wide tools don't pay one backend GET per instance per call.
        Key material is never memoized — the ``bw`` CLI resolve and the temp
        file lifecycle stay strictly per-call.

        Failure policy: ANY error in the Bitwarden tier (API errors, locked
        vault, missing CLI, unexpected) is logged WITHOUT key material or
        session tokens and falls back to the unmodified local resolution —
        the vault tier must never break a working local-key setup.

        Team-tier refs are not resolved on this surface yet (personal refs
        only).
        """
        conn = self._resolve_connection(instance)

        if self._bw_ssh_config_service is None:
            return conn, None
        instance_id = instance.get('id', '')
        if not instance_id:
            return conn, None
        provider = str(instance.get('provider', 'aws') or 'aws').lower()

        memo_key = (provider, instance_id)
        now = time.monotonic()
        memo_hit = self._bw_ref_memo.get(memo_key)
        if memo_hit is not None and memo_hit[0] > now:
            ref = memo_hit[1]
        else:
            try:
                ref = await self._bw_ssh_config_service.get_personal_instance_ref(
                    provider, instance_id,
                )
            except Exception as exc:  # noqa: BLE001 — vault tier is best-effort
                logger.debug(
                    "BW ref lookup skipped for %s/%s (%s); using local key",
                    provider, instance_id, type(exc).__name__,
                )
                # Memoize the failure as a negative result so a degraded API
                # costs one HTTP timeout per TTL window, not one per tool call.
                self._bw_ref_memo[memo_key] = (
                    now + _BW_REF_MEMO_TTL_SECONDS, None,
                )
                return conn, None
            self._bw_ref_memo[memo_key] = (now + _BW_REF_MEMO_TTL_SECONDS, ref)

        if not ref:
            return conn, None
        cred_ref = ref.get('ssh_credential_ref') or {}
        item_id = cred_ref.get('item_id')
        if not item_id:
            # Partial roll-up row (ref exists but item_id unknown on this
            # device) — nothing resolvable, keep the local key.
            return conn, None

        try:
            from servonaut.services.bw_resolver import BwResolver
            from servonaut.utils.ephemeral_key import (
                persistent_bw_ssh_key, remove_bw_ssh_key,
            )
            # session_getter=None → BwResolver falls back to the ambient
            # BW_SESSION env var, the only session source in headless mode.
            key_body = await asyncio.to_thread(
                BwResolver(session_getter=None).resolve_ssh_key, str(item_id),
            )
            # File IO (makedirs + 0600 open + write) off the event loop.
            key_path = await asyncio.to_thread(persistent_bw_ssh_key, key_body)
        except Exception as exc:  # noqa: BLE001 — vault tier is best-effort
            # Exception TYPE only: resolver/API error messages are crafted to
            # be secret-free, but the type alone is enough to debug and can
            # never carry key material or a session token.
            logger.info(
                "BW key resolution unavailable for %s/%s (%s); using local key",
                provider, instance_id, type(exc).__name__,
            )
            return conn, None

        conn = dict(conn)
        conn['key_path'] = key_path
        conn['key_source'] = 'bw_personal'

        async def _cleanup() -> None:
            # zero-overwrite + fsync + unlink can stall on slow/contended
            # disks — run it in a thread so concurrent tool handling (and the
            # TUI event loop) never freezes inside a finally block.
            await asyncio.to_thread(remove_bw_ssh_key, key_path)

        return conn, _cleanup

    async def _find_instance(self, instance_id: str) -> Optional[Dict]:
        """Find instance by ID or name across all providers (AWS + custom + OVH + Hetzner)."""
        aws_instances = await self._aws_service.fetch_instances_cached()
        custom_instances = self._custom_server_service.list_as_instances()
        ovh_instances = (
            await self._ovh_service.fetch_instances_cached()
            if self._ovh_service is not None
            else []
        )
        hetzner_instances = (
            await self._hetzner_service.fetch_instances_cached()
            if self._hetzner_service is not None
            else []
        )
        all_instances = (
            aws_instances + custom_instances + ovh_instances + hetzner_instances
        )
        instance_id_lower = instance_id.lower()
        for inst in all_instances:
            if (inst.get('id') == instance_id
                    or inst.get('id', '').lower() == instance_id_lower
                    or inst.get('name') == instance_id
                    or inst.get('name', '').lower() == instance_id_lower):
                return inst
        return None

    async def _correlate_ovh_instance(self, instance: Dict) -> Optional[Dict]:
        """Match an instance without provider_type to a discovered OVH one.

        Custom-server entries are matched in :meth:`_find_instance` before
        the OVH inventory, so a manually registered OVH box resolves to a
        dict without ``provider_type`` and OVH-specific tools cannot route
        it. Correlate by public IP first (strongest signal), then by
        case-insensitive name.
        """
        try:
            ovh_instances = await self._ovh_service.fetch_instances_cached()
        except Exception:
            return None
        public_ip = instance.get('public_ip') or ''
        name = (instance.get('name') or '').lower()
        if public_ip:
            for inst in ovh_instances:
                if inst.get('public_ip') == public_ip:
                    return inst
        if name:
            for inst in ovh_instances:
                if (inst.get('name') or '').lower() == name:
                    return inst
        return None

    def _format_instances(self, instances: List[Dict]) -> str:
        lines = [f"{'Name':<30} {'ID':<20} {'State':<10} {'Public IP':<16} {'Region':<14}"]
        lines.append('-' * 90)
        for i in instances:
            lines.append(
                f"{(i.get('name') or ''):<30} "
                f"{i.get('id', ''):<20} "
                f"{i.get('state', ''):<10} "
                f"{(i.get('public_ip') or '-'):<16} "
                f"{i.get('region', ''):<14}"
            )
        return '\n'.join(lines)

    # ------------------------------------------------------------------
    # AWS EC2 lifecycle — start / stop / reboot / terminate / run
    # ------------------------------------------------------------------

    def _aws_unavailable(self, tool_name: str, payload: Dict[str, Any]) -> str:
        """Common early-return when the AWS EC2 service isn't wired up."""
        msg = (
            "Error: AWS service is not available. Ensure boto3 is installed "
            "and AWS credentials are configured (config.aws, environment "
            "variables, or instance-profile IAM role)."
        )
        self._audit.log(tool_name, payload, '', False, 'aws_unavailable')
        return msg

    async def _aws_ec2_lifecycle(
        self, tool_name: str, method: str,
        instance_id: str, region: str, verb: str,
    ) -> str:
        """Shared handler for AWS EC2 start/stop/reboot/terminate.

        Mirrors :meth:`_ovh_lifecycle` — routes through the existing
        :class:`AWSService` lifecycle methods. The audit row records both
        instance_id and region so post-mortem queries know which endpoint
        was targeted.
        """
        payload = {'instance_id': instance_id, 'region': region}
        if self._aws_service is None:
            return self._aws_unavailable(tool_name, payload)

        allowed, reason = self._guard.check_tool(tool_name)
        if not allowed:
            self._audit.log(tool_name, payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            await getattr(self._aws_service, method)(instance_id, region)
        except ValueError as exc:
            self._audit.log(tool_name, payload, '', False, f"validation: {exc}")
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log(tool_name, payload, '', False, f"api_error: {exc}")
            return f"Error: {verb} failed on EC2 {instance_id} ({region}): {exc}"

        text = f"EC2 instance {instance_id} ({region}): {verb}."
        self._audit.log(tool_name, payload, text, True)
        return text

    async def aws_start_instance(self, instance_id: str, region: str) -> str:
        """Start a stopped AWS EC2 instance."""
        return await self._aws_ec2_lifecycle(
            'aws_start_instance', 'start_instance', instance_id, region, 'start sent',
        )

    async def aws_stop_instance(self, instance_id: str, region: str) -> str:
        """Stop a running AWS EC2 instance."""
        return await self._aws_ec2_lifecycle(
            'aws_stop_instance', 'stop_instance', instance_id, region, 'stop sent',
        )

    async def aws_reboot_instance(self, instance_id: str, region: str) -> str:
        """Reboot a running AWS EC2 instance."""
        return await self._aws_ec2_lifecycle(
            'aws_reboot_instance', 'reboot_instance', instance_id, region, 'reboot sent',
        )

    async def aws_terminate_instance(self, instance_id: str, region: str) -> str:
        """Permanently terminate an AWS EC2 instance."""
        return await self._aws_ec2_lifecycle(
            'aws_terminate_instance', 'terminate_instance',
            instance_id, region, 'terminate sent — irreversible',
        )

    async def aws_run_instances(
        self,
        region: str,
        ami_id: str,
        instance_type: str,
        key_name: str,
        subnet_id: str,
        security_group_ids: List[str],
        name_tag: str,
        count: int = 1,
    ) -> str:
        """Launch one or more new AWS EC2 instances."""
        payload = {
            'region': region, 'ami_id': ami_id, 'instance_type': instance_type,
            'key_name': key_name, 'subnet_id': subnet_id,
            'security_group_ids': security_group_ids, 'name_tag': name_tag,
            'count': count,
        }
        if self._aws_service is None:
            return self._aws_unavailable('aws_run_instances', payload)

        allowed, reason = self._guard.check_tool('aws_run_instances')
        if not allowed:
            self._audit.log('aws_run_instances', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            instances = await self._aws_service.run_instances(
                region=region,
                ami_id=ami_id,
                instance_type=instance_type,
                key_name=key_name,
                subnet_id=subnet_id,
                security_group_ids=security_group_ids,
                name_tag=name_tag,
                count=count,
            )
        except ValueError as exc:
            self._audit.log('aws_run_instances', payload, '', False, f"validation: {exc}")
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log('aws_run_instances', payload, '', False, f"api_error: {exc}")
            return f"Error launching EC2 instances in {region}: {exc}"

        result_data = {
            'count': len(instances),
            'region': region,
            'instances': [
                {
                    'id': inst.get('id', ''),
                    'state': inst.get('state', ''),
                    'type': inst.get('type', ''),
                    'region': inst.get('region', region),
                }
                for inst in instances
            ],
        }
        result = json.dumps(result_data)
        self._audit.log('aws_run_instances', payload, result, True)
        return result

    # ------------------------------------------------------------------
    # AWS EC2 describe helpers — read-only catalogue queries
    # ------------------------------------------------------------------

    async def aws_list_regions(self, bootstrap_region: str = 'us-east-1') -> str:
        """List all AWS regions enabled on the account."""
        payload: Dict[str, Any] = {'bootstrap_region': bootstrap_region}
        if self._aws_service is None:
            return self._aws_unavailable('aws_list_regions', payload)

        allowed, reason = self._guard.check_tool('aws_list_regions')
        if not allowed:
            self._audit.log('aws_list_regions', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            regions = await self._aws_service.list_regions(
                bootstrap_region or 'us-east-1',
            )
        except Exception as exc:
            self._audit.log('aws_list_regions', payload, '', False, f"api_error: {exc}")
            return f"Error listing AWS regions: {exc}"

        lines = [
            f"AWS regions ({len(regions)} total):",
            f"  {'region':<20}",
            '  ' + '-' * 20,
        ]
        for r in regions:
            lines.append(f"  {r:<20}")
        result = '\n'.join(lines)
        self._audit.log('aws_list_regions', payload, result, True)
        return result

    async def aws_list_amis(
        self,
        region: str,
        name_filter: str = '',
        owners: Optional[List[str]] = None,
        max_results: int = 50,
    ) -> str:
        """List AMIs in the given region, sorted newest-first."""
        payload: Dict[str, Any] = {
            'region': region, 'name_filter': name_filter,
            'owners': owners or ['amazon'], 'max_results': max_results,
        }
        if self._aws_service is None:
            return self._aws_unavailable('aws_list_amis', payload)

        allowed, reason = self._guard.check_tool('aws_list_amis')
        if not allowed:
            self._audit.log('aws_list_amis', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            amis = await self._aws_service.list_amis(
                region,
                name_filter,
                tuple(owners) if owners else ('amazon',),
                max_results,
            )
        except ValueError as exc:
            self._audit.log('aws_list_amis', payload, '', False, f"validation: {exc}")
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log('aws_list_amis', payload, '', False, f"api_error: {exc}")
            return f"Error listing AMIs in {region}: {exc}"

        lines = [
            f"AMIs in {region} ({len(amis)} results):",
            f"  {'Image ID':<25} {'Name':<42} {'Arch':<8} {'Creation Date':<14}",
            '  ' + '-' * 90,
        ]
        for ami in amis:
            name = (ami.get('name') or '')[:40]
            lines.append(
                f"  {ami.get('image_id', ''):<25} "
                f"{name:<42} "
                f"{(ami.get('architecture') or ''):<8} "
                f"{(ami.get('creation_date') or ''):<14}"
            )
        result = '\n'.join(lines)
        self._audit.log('aws_list_amis', payload, result, True)
        return result

    async def aws_list_instance_types(
        self, region: str, max_results: int = 100,
    ) -> str:
        """List EC2 instance types available in the given region."""
        payload: Dict[str, Any] = {'region': region, 'max_results': max_results}
        if self._aws_service is None:
            return self._aws_unavailable('aws_list_instance_types', payload)

        allowed, reason = self._guard.check_tool('aws_list_instance_types')
        if not allowed:
            self._audit.log('aws_list_instance_types', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            types = await self._aws_service.list_instance_types(region, max_results)
        except ValueError as exc:
            self._audit.log('aws_list_instance_types', payload, '', False, f"validation: {exc}")
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log('aws_list_instance_types', payload, '', False, f"api_error: {exc}")
            return f"Error listing instance types in {region}: {exc}"

        lines = [
            f"EC2 instance types in {region} ({len(types)} results):",
            f"  {'Instance Type':<20} {'vCPUs':<8} {'RAM (MiB)':<12}",
            '  ' + '-' * 42,
        ]
        for t in types:
            lines.append(
                f"  {t.get('instance_type', ''):<20} "
                f"{str(t.get('vcpus', 0)):<8} "
                f"{str(t.get('memory_mib', 0)):<12}"
            )
        result = '\n'.join(lines)
        self._audit.log('aws_list_instance_types', payload, result, True)
        return result

    async def aws_list_key_pairs(self, region: str) -> str:
        """List EC2 key pairs registered in the given region."""
        payload: Dict[str, Any] = {'region': region}
        if self._aws_service is None:
            return self._aws_unavailable('aws_list_key_pairs', payload)

        allowed, reason = self._guard.check_tool('aws_list_key_pairs')
        if not allowed:
            self._audit.log('aws_list_key_pairs', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            keys = await self._aws_service.list_key_pairs(region)
        except ValueError as exc:
            self._audit.log('aws_list_key_pairs', payload, '', False, f"validation: {exc}")
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log('aws_list_key_pairs', payload, '', False, f"api_error: {exc}")
            return f"Error listing key pairs in {region}: {exc}"

        lines = [
            f"EC2 key pairs in {region} ({len(keys)} total):",
            f"  {'Name':<32} {'ID':<22} {'Fingerprint':<50}",
            '  ' + '-' * 106,
        ]
        for k in keys:
            lines.append(
                f"  {(k.get('key_name') or ''):<32} "
                f"{(k.get('key_pair_id') or ''):<22} "
                f"{(k.get('fingerprint') or ''):<50}"
            )
        result = '\n'.join(lines)
        self._audit.log('aws_list_key_pairs', payload, result, True)
        return result

    async def aws_list_subnets(self, region: str) -> str:
        """List VPC subnets in the given region."""
        payload: Dict[str, Any] = {'region': region}
        if self._aws_service is None:
            return self._aws_unavailable('aws_list_subnets', payload)

        allowed, reason = self._guard.check_tool('aws_list_subnets')
        if not allowed:
            self._audit.log('aws_list_subnets', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            subnets = await self._aws_service.list_subnets(region)
        except ValueError as exc:
            self._audit.log('aws_list_subnets', payload, '', False, f"validation: {exc}")
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log('aws_list_subnets', payload, '', False, f"api_error: {exc}")
            return f"Error listing subnets in {region}: {exc}"

        lines = [
            f"VPC subnets in {region} ({len(subnets)} total):",
            f"  {'Subnet ID':<24} {'VPC':<24} {'AZ':<18} {'CIDR':<20} {'Avail IPs':<10}",
            '  ' + '-' * 96,
        ]
        for s in subnets:
            lines.append(
                f"  {(s.get('subnet_id') or ''):<24} "
                f"{(s.get('vpc_id') or ''):<24} "
                f"{(s.get('availability_zone') or ''):<18} "
                f"{(s.get('cidr_block') or ''):<20} "
                f"{str(s.get('available_ip_count', 0)):<10}"
            )
        result = '\n'.join(lines)
        self._audit.log('aws_list_subnets', payload, result, True)
        return result

    async def aws_list_security_groups(self, region: str) -> str:
        """List EC2 security groups in the given region."""
        payload: Dict[str, Any] = {'region': region}
        if self._aws_service is None:
            return self._aws_unavailable('aws_list_security_groups', payload)

        allowed, reason = self._guard.check_tool('aws_list_security_groups')
        if not allowed:
            self._audit.log('aws_list_security_groups', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            groups = await self._aws_service.list_security_groups(region)
        except ValueError as exc:
            self._audit.log('aws_list_security_groups', payload, '', False, f"validation: {exc}")
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log('aws_list_security_groups', payload, '', False, f"api_error: {exc}")
            return f"Error listing security groups in {region}: {exc}"

        lines = [
            f"EC2 security groups in {region} ({len(groups)} total):",
            f"  {'Group ID':<24} {'Name':<32} {'VPC':<24} {'Description':<52}",
            '  ' + '-' * 134,
        ]
        for g in groups:
            desc = (g.get('description') or '')[:50]
            lines.append(
                f"  {(g.get('group_id') or ''):<24} "
                f"{(g.get('group_name') or ''):<32} "
                f"{(g.get('vpc_id') or ''):<24} "
                f"{desc:<52}"
            )
        result = '\n'.join(lines)
        self._audit.log('aws_list_security_groups', payload, result, True)
        return result

    # ------------------------------------------------------------------
    # S3 / object storage — provider-parameterised (aws | hetzner | ovh)
    # ------------------------------------------------------------------

    def _get_object_storage(self, provider: str) -> Optional[Any]:
        """Return the ObjectStorageService for the given provider, or None."""
        if provider not in _S3_PROVIDERS:
            return None  # caller converts to validation: invalid_provider error
        return getattr(self, f'_{provider}_object_storage_service', None)

    def _s3_unavailable(
        self, tool_name: str, provider: str, payload: Dict[str, Any],
    ) -> str:
        """Return a structured 'not configured' error + audit row for S3."""
        msg = (
            f"S3 ({provider}) is not configured. Set "
            f"config.{provider}.object_storage.access_key and "
            f"(region or endpoint_url) in ~/.servonaut/config.json."
        )
        self._audit.log(
            tool_name, payload, '', False,
            f"s3_provider_unavailable_{provider}",
        )
        return msg

    def _validate_s3_provider(
        self, provider: str, tool_name: str, payload: Dict[str, Any],
    ):
        """Validate the provider string and check service availability.

        Returns:
            (svc, None) on success, or (None, error_string) on failure.
            The audit row is already logged on failure.
        """
        if provider not in _S3_PROVIDERS:
            providers_list = ', '.join(f"'{p}'" for p in sorted(_S3_PROVIDERS))
            msg = f"Error: provider must be one of {providers_list}; got {provider!r}."
            self._audit.log(tool_name, payload, '', False, 'validation: invalid_provider')
            return None, msg
        svc = self._get_object_storage(provider)
        if svc is None:
            return None, self._s3_unavailable(tool_name, provider, payload)
        return svc, None

    async def s3_list_buckets(self, provider: str) -> str:
        """List S3 buckets for the given provider."""
        payload: Dict[str, Any] = {'provider': provider}
        svc, err = self._validate_s3_provider(provider, 's3_list_buckets', payload)
        if err is not None:
            return err

        allowed, reason = self._guard.check_tool('s3_list_buckets')
        if not allowed:
            self._audit.log('s3_list_buckets', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            buckets = await svc.list_buckets()
        except Exception as exc:
            self._audit.log('s3_list_buckets', payload, '', False, f"api_error: {exc}")
            return f"Error listing {provider} S3 buckets: {exc}"

        lines = [
            f"{provider} buckets ({len(buckets)} total):",
            f"  {'Name':<48}  {'Creation Date':<20}",
            '  ' + '-' * 70,
        ]
        for b in buckets:
            lines.append(
                f"  {(b.get('name') or ''):<48}  "
                f"{(b.get('creation_date') or ''):<20}"
            )
        result = '\n'.join(lines)
        self._audit.log('s3_list_buckets', payload, result, True)
        return result

    async def s3_list_objects(
        self,
        provider: str,
        bucket: str,
        prefix: str = '',
        delimiter: str = '/',
    ) -> str:
        """List objects and virtual-folder prefixes in an S3 bucket."""
        payload: Dict[str, Any] = {
            'provider': provider, 'bucket': bucket,
            'prefix': prefix, 'delimiter': delimiter,
        }
        svc, err = self._validate_s3_provider(provider, 's3_list_objects', payload)
        if err is not None:
            return err

        allowed, reason = self._guard.check_tool('s3_list_objects')
        if not allowed:
            self._audit.log('s3_list_objects', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            data = await svc.list_objects(bucket, prefix, delimiter)
        except ValueError as exc:
            self._audit.log('s3_list_objects', payload, '', False, f"validation: {exc}")
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log('s3_list_objects', payload, '', False, f"api_error: {exc}")
            return f"Error listing objects in s3://{bucket}: {exc}"

        result = json.dumps({
            "bucket": bucket,
            "prefix": prefix,
            "folders": data.get("folders", []),
            "objects": data.get("objects", []),
            "is_truncated": data.get("is_truncated", False),
        })
        self._audit.log('s3_list_objects', payload, result, True)
        return result

    async def s3_download_object(
        self, provider: str, bucket: str, key: str, local_path: str,
    ) -> str:
        """Download an S3 object to a local file."""
        payload: Dict[str, Any] = {
            'provider': provider, 'bucket': bucket,
            'key': key, 'local_path': local_path,
        }
        svc, err = self._validate_s3_provider(provider, 's3_download_object', payload)
        if err is not None:
            return err

        allowed, reason = self._guard.check_tool('s3_download_object')
        if not allowed:
            self._audit.log('s3_download_object', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            await svc.download_object(bucket, key, local_path)
        except ValueError as exc:
            self._audit.log('s3_download_object', payload, '', False, f"validation: {exc}")
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log('s3_download_object', payload, '', False, f"api_error: {exc}")
            return f"Error downloading s3://{bucket}/{key}: {exc}"

        from pathlib import Path as _Path
        resolved = str(_Path(local_path).expanduser().resolve())
        result = f"Downloaded s3://{bucket}/{key} to {resolved}."
        self._audit.log('s3_download_object', payload, result, True)
        return result

    async def s3_create_bucket(self, provider: str, bucket: str) -> str:
        """Create a new S3 bucket on the given provider."""
        payload: Dict[str, Any] = {'provider': provider, 'bucket': bucket}
        svc, err = self._validate_s3_provider(provider, 's3_create_bucket', payload)
        if err is not None:
            return err

        allowed, reason = self._guard.check_tool('s3_create_bucket')
        if not allowed:
            self._audit.log('s3_create_bucket', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            await svc.create_bucket(bucket)
        except ValueError as exc:
            self._audit.log('s3_create_bucket', payload, '', False, f"validation: {exc}")
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log('s3_create_bucket', payload, '', False, f"api_error: {exc}")
            return f"Error creating {provider} S3 bucket {bucket!r}: {exc}"

        result = f"Created {provider} S3 bucket {bucket!r}."
        self._audit.log('s3_create_bucket', payload, result, True)
        return result

    async def s3_delete_bucket(self, provider: str, bucket: str) -> str:
        """Delete an empty S3 bucket."""
        payload: Dict[str, Any] = {'provider': provider, 'bucket': bucket}
        svc, err = self._validate_s3_provider(provider, 's3_delete_bucket', payload)
        if err is not None:
            return err

        allowed, reason = self._guard.check_tool('s3_delete_bucket')
        if not allowed:
            self._audit.log('s3_delete_bucket', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            await svc.delete_bucket(bucket)
        except ValueError as exc:
            self._audit.log('s3_delete_bucket', payload, '', False, f"validation: {exc}")
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log('s3_delete_bucket', payload, '', False, f"api_error: {exc}")
            return f"Error deleting {provider} S3 bucket {bucket!r}: {exc}"

        result = f"Deleted {provider} S3 bucket {bucket!r}."
        self._audit.log('s3_delete_bucket', payload, result, True)
        return result

    async def s3_upload_object(
        self, provider: str, bucket: str, key: str, local_path: str,
    ) -> str:
        """Upload a local file to an S3 bucket."""
        payload: Dict[str, Any] = {
            'provider': provider, 'bucket': bucket,
            'key': key, 'local_path': local_path,
        }
        svc, err = self._validate_s3_provider(provider, 's3_upload_object', payload)
        if err is not None:
            return err

        allowed, reason = self._guard.check_tool('s3_upload_object')
        if not allowed:
            self._audit.log('s3_upload_object', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            await svc.upload_object(bucket, key, local_path)
        except ValueError as exc:
            self._audit.log('s3_upload_object', payload, '', False, f"validation: {exc}")
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log('s3_upload_object', payload, '', False, f"api_error: {exc}")
            return f"Error uploading to s3://{bucket}/{key}: {exc}"

        from pathlib import Path as _Path
        import os as _os
        resolved = str(_Path(local_path).expanduser().resolve())
        try:
            size_bytes = _os.path.getsize(resolved)
        except OSError:
            size_bytes = 0
        result = f"Uploaded {resolved} to s3://{bucket}/{key} ({size_bytes} bytes)."
        self._audit.log('s3_upload_object', payload, result, True)
        return result

    async def s3_delete_object(
        self, provider: str, bucket: str, key: str,
    ) -> str:
        """Delete a single object from S3."""
        payload: Dict[str, Any] = {'provider': provider, 'bucket': bucket, 'key': key}
        svc, err = self._validate_s3_provider(provider, 's3_delete_object', payload)
        if err is not None:
            return err

        allowed, reason = self._guard.check_tool('s3_delete_object')
        if not allowed:
            self._audit.log('s3_delete_object', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            await svc.delete_object(bucket, key)
        except ValueError as exc:
            self._audit.log('s3_delete_object', payload, '', False, f"validation: {exc}")
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log('s3_delete_object', payload, '', False, f"api_error: {exc}")
            return f"Error deleting s3://{bucket}/{key} ({provider}): {exc}"

        result = f"Deleted s3://{bucket}/{key} ({provider})."
        self._audit.log('s3_delete_object', payload, result, True)
        return result

    async def s3_copy_object(
        self,
        provider: str,
        src_bucket: str,
        src_key: str,
        dst_bucket: str,
        dst_key: str,
    ) -> str:
        """Server-side copy of an S3 object within the same provider."""
        payload: Dict[str, Any] = {
            'provider': provider, 'src_bucket': src_bucket, 'src_key': src_key,
            'dst_bucket': dst_bucket, 'dst_key': dst_key,
        }
        svc, err = self._validate_s3_provider(provider, 's3_copy_object', payload)
        if err is not None:
            return err

        allowed, reason = self._guard.check_tool('s3_copy_object')
        if not allowed:
            self._audit.log('s3_copy_object', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            await svc.copy_object(src_bucket, src_key, dst_bucket, dst_key)
        except ValueError as exc:
            self._audit.log('s3_copy_object', payload, '', False, f"validation: {exc}")
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log('s3_copy_object', payload, '', False, f"api_error: {exc}")
            return (
                f"Error copying s3://{src_bucket}/{src_key} to "
                f"s3://{dst_bucket}/{dst_key} ({provider}): {exc}"
            )

        result = (
            f"Copied s3://{src_bucket}/{src_key} to "
            f"s3://{dst_bucket}/{dst_key} ({provider})."
        )
        self._audit.log('s3_copy_object', payload, result, True)
        return result

    async def s3_move_object(
        self,
        provider: str,
        src_bucket: str,
        src_key: str,
        dst_bucket: str,
        dst_key: str,
    ) -> str:
        """Move an S3 object (server-side copy then delete source)."""
        payload: Dict[str, Any] = {
            'provider': provider, 'src_bucket': src_bucket, 'src_key': src_key,
            'dst_bucket': dst_bucket, 'dst_key': dst_key,
        }
        svc, err = self._validate_s3_provider(provider, 's3_move_object', payload)
        if err is not None:
            return err

        allowed, reason = self._guard.check_tool('s3_move_object')
        if not allowed:
            self._audit.log('s3_move_object', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            await svc.move_object(src_bucket, src_key, dst_bucket, dst_key)
        except ValueError as exc:
            self._audit.log('s3_move_object', payload, '', False, f"validation: {exc}")
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log('s3_move_object', payload, '', False, f"api_error: {exc}")
            return (
                f"Error moving s3://{src_bucket}/{src_key} to "
                f"s3://{dst_bucket}/{dst_key} ({provider}): {exc}"
            )

        result = (
            f"Moved s3://{src_bucket}/{src_key} to "
            f"s3://{dst_bucket}/{dst_key} ({provider})."
        )
        self._audit.log('s3_move_object', payload, result, True)
        return result

    async def s3_generate_presigned_url(
        self,
        provider: str,
        bucket: str,
        key: str,
        expires_in: int = 3600,
    ) -> str:
        """Generate a time-limited pre-signed URL granting read access to an S3 object.

        SECURITY NOTE: The URL is a bearer secret — it goes ONLY in the JSON
        response, never in the audit log. The audit result field contains only
        a placeholder with the URL length.
        """
        # payload intentionally excludes the URL (not yet generated).
        # expires_in included because it determines how dangerous the URL is.
        payload: Dict[str, Any] = {
            'provider': provider, 'bucket': bucket,
            'key': key, 'expires_in': expires_in,
        }
        svc, err = self._validate_s3_provider(provider, 's3_generate_presigned_url', payload)
        if err is not None:
            return err

        allowed, reason = self._guard.check_tool('s3_generate_presigned_url')
        if not allowed:
            self._audit.log('s3_generate_presigned_url', payload, '', False, reason)
            return f"Blocked: {reason}"

        try:
            url = await svc.generate_presigned_url(bucket, key, expires_in)
        except ValueError as exc:
            self._audit.log(
                's3_generate_presigned_url', payload, '', False, f"validation: {exc}",
            )
            return f"Error: {exc}"
        except Exception as exc:
            self._audit.log(
                's3_generate_presigned_url', payload, '', False, f"api_error: {exc}",
            )
            return f"Error generating presigned URL for s3://{bucket}/{key}: {exc}"

        # CRITICAL: audit result MUST NOT contain the URL — it's a bearer secret.
        # Only log a placeholder with the length so auditors can see the call
        # happened and how long the URL was, without being able to replay it.
        audit_result = f"presigned url issued ({len(url)} chars)"
        self._audit.log('s3_generate_presigned_url', payload, audit_result, True)

        return json.dumps({
            'url': url,
            'bucket': bucket,
            'key': key,
            'expires_in': expires_in,
            'provider': provider,
        })

    # ------------------------------------------------------------------
    # Incident-response tools (Group A): SSH/network only, read-only
    # ------------------------------------------------------------------

    async def _exec_ssh(
        self, instance: Dict, command: str, timeout: int = 60,
        audit_extras: Optional[Dict[str, Any]] = None,
    ) -> tuple:
        """Run a read-only command on an instance over SSH.

        Shared helper for the incident-response probes. ``command`` is passed
        as a single SSH argument, so the *remote* shell parses it — nested
        single-quoted awk/grep is safe (there is no intermediate local shell;
        see ``run_ssh_subprocess`` which uses ``create_subprocess_exec``).
        Returns ``(stdout_str, stderr_str)``.

        ``audit_extras``: optional dict the helper populates with
        ``key_source`` when the key came from a Bitwarden ref, so callers can
        tag their audit rows the same way run_command / transfer_file do.
        """
        conn, cleanup = await self._resolve_connection_with_vault(instance)
        if audit_extras is not None and conn.get('key_source'):
            audit_extras['key_source'] = conn['key_source']
        # Command build stays INSIDE the try — an exception there must still
        # trigger the temp-key cleanup in the finally.
        try:
            ssh_cmd = self._ssh_service.build_ssh_command(
                host=conn['host'], username=conn['username'],
                key_path=conn['key_path'], proxy_args=conn['proxy_args'],
                remote_command=command, port=conn.get('port'),
                extra_options=conn.get('extra_options') or [],
            )
            stdout, stderr = await run_ssh_subprocess(ssh_cmd, timeout=timeout)
        finally:
            if cleanup is not None:
                await cleanup()
        return (
            stdout.decode('utf-8', errors='replace'),
            stderr.decode('utf-8', errors='replace'),
        )

    async def _gather_all_instances(self) -> List[Dict]:
        """Merge instances across every wired provider (AWS + custom + OVH + Hetzner)."""
        aws_instances = await self._aws_service.fetch_instances_cached()
        custom_instances = self._custom_server_service.list_as_instances()
        ovh_instances = (
            await self._ovh_service.fetch_instances_cached()
            if self._ovh_service is not None else []
        )
        hetzner_instances = (
            await self._hetzner_service.fetch_instances_cached()
            if self._hetzner_service is not None else []
        )
        return aws_instances + custom_instances + ovh_instances + hetzner_instances

    async def web_traffic_summary(
        self, instance_id: str, log_path: str = "",
        lines: int = 10000, top_n: int = 15,
    ) -> str:
        """Summarize a box's OWN web access logs (XFF / mod_remoteip aware).

        Parses the instance's access logs to report, per vhost: request
        volume, approx req/s, status-code mix, top client IPs and top URLs.
        Unlike ``cloudwatch_top_ips`` (which only sees WAF logs), this reads
        the decisive data that lives on the box. When ``log_path`` is empty
        it auto-discovers nginx/apache/httpd access logs.
        """
        args = {
            'instance_id': instance_id, 'log_path': log_path,
            'lines': lines, 'top_n': top_n,
        }
        allowed, reason = self._guard.check_tool('web_traffic_summary')
        if not allowed:
            self._audit.log('web_traffic_summary', args, '', False, reason)
            return f"Blocked: {reason}"

        instance = await self._find_instance(instance_id)
        if not instance:
            self._audit.log('web_traffic_summary', args, '', False, 'instance_not_found')
            return f"Instance not found: {instance_id}"

        n = max(100, min(int(lines or 10000), 200000))
        top = max(1, min(int(top_n or 15), 100))

        if log_path:
            quoted = shlex.quote(log_path)
            remote = f'echo "===VHOST:{log_path}==="; tail -n {n} -- {quoted}'
            hint = log_path
        else:
            remote = (
                'for f in $(ls -1t /var/log/nginx/*access*.log '
                '/var/log/apache2/*access*.log /var/log/httpd/*access*.log '
                '2>/dev/null | head -20); do '
                f'echo "===VHOST:$f==="; tail -n {n} "$f"; done'
            )
            hint = "auto-discovered nginx/apache/httpd access logs"

        key_extras: Dict[str, Any] = {}
        try:
            stdout, stderr = await self._exec_ssh(
                instance, remote, timeout=90, audit_extras=key_extras,
            )
        except asyncio.TimeoutError:
            self._audit.log(
                'web_traffic_summary', args, '', False, 'timeout', **key_extras,
            )
            return "Error: web_traffic_summary timed out after 90 seconds"
        except Exception as e:
            self._audit.log(
                'web_traffic_summary', args, '', False, f"ssh_error: {e}",
                **key_extras,
            )
            return f"Error: {e}"

        from servonaut.utils.log_analysis import (
            summarize_web_traffic, format_web_traffic,
        )
        summary = summarize_web_traffic(stdout, top)
        result = format_web_traffic(summary, log_hint=hint)
        if not summary.get("vhosts") and stderr.strip():
            result += f"\n\n(stderr: {stderr.strip()[:300]})"
        self._audit.log('web_traffic_summary', args, result, True, **key_extras)
        return result

    # Single read-only probe per host: load, cpu, mem, php-fpm saturation,
    # web stack, listening ports. Emits KEY=VALUE lines parsed in Python.
    _FLEET_PROBE_CMD = (
        'echo "LOAD=$(awk \'{print $1, $2, $3}\' /proc/loadavg 2>/dev/null)"; '
        'echo "CPU=$(nproc 2>/dev/null)"; '
        'echo "MEM=$(free -m 2>/dev/null | awk \'/^Mem:/{print $2, $3, $4}\')"; '
        # php-fpm saturation. Detect presence via the MASTER process title
        # ("php-fpm: master process …") — this matches whether or not any
        # worker is currently spawned (an idle pm=ondemand/dynamic pool has 0
        # workers at the probe instant) and, unlike a bare "php-fpm" match,
        # cannot self-match the probe shell's own command line. Whenever php-fpm
        # is present we ALWAYS emit a column (active/max, max="?" if the pool
        # config isn't readable) so the key triage signal never goes blank.
        'if pgrep -f \'php-fpm: master\' >/dev/null 2>&1; then '
        'FPM_A=$(pgrep -c -f \'php-fpm: pool\' 2>/dev/null || echo 0); '
        'FPM_RE=\'^[[:space:]]*pm.max_children[[:space:]]*=[[:space:]]*[0-9]+\'; '
        'FPM_P="/etc/php*/fpm/pool.d /etc/php-fpm.d /usr/local/etc/php-fpm.d /etc/php/*/fpm/pool.d"; '
        # Total worker capacity = SUM of pm.max_children across every pool
        # (so it's comparable to the active count, which spans all pools). Try
        # an unprivileged read first; only fall back to sudo -n (never prompts)
        # when nothing was readable, so world-readable pool.d files are never
        # double-counted.
        'FPM_M=$(grep -rhoE "$FPM_RE" $FPM_P 2>/dev/null '
        '| grep -oE \'[0-9]+\' | awk \'{s+=$1} END{if(s>0)print s}\'); '
        '[ -z "$FPM_M" ] && FPM_M=$(sudo -n grep -rhoE "$FPM_RE" $FPM_P 2>/dev/null '
        '| grep -oE \'[0-9]+\' | awk \'{s+=$1} END{if(s>0)print s}\'); '
        'echo "FPM=${FPM_A:-0}/${FPM_M:-?}"; '
        'else echo "FPM="; fi; '
        'S=""; pgrep -x nginx >/dev/null 2>&1 && S="$S nginx"; '
        'pgrep -x apache2 >/dev/null 2>&1 && S="$S apache"; '
        'pgrep -x httpd >/dev/null 2>&1 && S="$S httpd"; '
        'pgrep -f \'php-fpm: master\' >/dev/null 2>&1 && S="$S php-fpm"; '
        'pgrep -x node >/dev/null 2>&1 && S="$S node"; '
        'echo "STACK=$(echo $S)"; '
        'echo "LISTEN=$(ss -ltn 2>/dev/null | awk \'NR>1{n=split($4,a,":"); '
        'print a[n]}\' | sort -un | tr \'\\n\' \',\')"'
    )

    async def fleet_health_snapshot(
        self, region: str = "", running_only: bool = True, timeout: int = 15,
    ) -> str:
        """Triage the whole fleet in one table: load, CPU, mem, FPM, web stack.

        SSH fan-out across every managed instance. Surfaces the sick box (high
        load / saturated php-fpm pool) without SSH'ing into each one by hand.
        Unreachable hosts are listed separately rather than failing the call.
        """
        args = {'region': region, 'running_only': running_only, 'timeout': timeout}
        allowed, reason = self._guard.check_tool('fleet_health_snapshot')
        if not allowed:
            self._audit.log('fleet_health_snapshot', args, '', False, reason)
            return f"Blocked: {reason}"

        instances = await self._gather_all_instances()
        if region:
            instances = [i for i in instances if i.get('region') == region]
        if running_only:
            instances = [
                i for i in instances
                if (i.get('state') or 'running').lower() in ('running', '')
            ]
        if not instances:
            self._audit.log('fleet_health_snapshot', args, '0 targets', True)
            return "No instances to probe (after region/state filtering)."

        per_host_timeout = max(5, min(int(timeout or 15), 60))

        from servonaut.utils.log_analysis import (
            fleet_row_from_probe, format_fleet_table,
        )

        # Distinct key sources used across the fan-out (e.g. 'bw_personal')
        # so the aggregate audit row can tell vault-key probes from local-key
        # probes — mirrors the per-call key_source tagging on run_command.
        fleet_key_sources: set = set()

        async def _probe(inst: Dict) -> Dict:
            name = inst.get('name') or inst.get('id') or '?'
            extras: Dict[str, Any] = {}
            try:
                stdout, _ = await self._exec_ssh(
                    inst, self._FLEET_PROBE_CMD, timeout=per_host_timeout,
                    audit_extras=extras,
                )
                return fleet_row_from_probe(name, stdout)
            except asyncio.TimeoutError:
                return {'name': name, 'error': 'timeout'}
            except Exception as e:  # noqa: BLE001 — one bad host must not fail all
                return {'name': name, 'error': str(e)[:80]}
            finally:
                if extras.get('key_source'):
                    fleet_key_sources.add(extras['key_source'])

        rows = await asyncio.gather(*(_probe(i) for i in instances))
        result = format_fleet_table(list(rows))
        agg_extras = (
            {'key_sources': sorted(fleet_key_sources)}
            if fleet_key_sources else {}
        )
        self._audit.log('fleet_health_snapshot', args, result, True, **agg_extras)
        return result

    async def enrich_ips(self, ips: str) -> str:
        """Enrich IPs with rDNS, ASN/org, country and AbuseIPDB score.

        Accepts a comma/space/newline-separated list. Helps decide *how* to
        block: a single /32 rotates, but an ASN/org (bulletproof host) can be
        blocked wholesale. ASN/geo via ip-api.com (free); abuse score via
        AbuseIPDB when an API key is set in Settings.
        """
        args = {'ips': ips}
        allowed, reason = self._guard.check_tool('enrich_ips')
        if not allowed:
            self._audit.log('enrich_ips', args, '', False, reason)
            return f"Blocked: {reason}"

        import re as _re
        ip_list = [t for t in _re.split(r'[\s,]+', ips or '') if t]
        if not ip_list:
            self._audit.log('enrich_ips', args, '', False, 'no_ips')
            return "Error: provide one or more IP addresses (comma or space separated)."

        service = self._ip_enrichment_service
        if service is None:
            from servonaut.services.ip_enrichment_service import IPEnrichmentService
            service = IPEnrichmentService(self._config_manager)
            self._ip_enrichment_service = service

        if len(ip_list) > service.max_ips:
            ip_list = ip_list[:service.max_ips]

        try:
            rows = await service.enrich(ip_list)
        except Exception as e:  # noqa: BLE001
            self._audit.log('enrich_ips', args, '', False, f"lookup_error: {e}")
            return f"Error enriching IPs: {e}"

        from servonaut.services.ip_enrichment_service import format_enrichment
        result = format_enrichment(rows)
        self._audit.log('enrich_ips', args, result, True)
        return result

    # ------------------------------------------------------------------
    # Database introspection tools (Group A): read-only, secret-store creds
    # ------------------------------------------------------------------

    async def _resolve_db(
        self, instance_id: str, tool_name: str, args: Dict, app: str = "",
    ):
        """Resolve (instance, profile, password) for the DB tools.

        Returns ``(instance, profile, password, error_str)``. ``error_str`` is
        non-empty (and the rest None) when resolution fails — the caller
        returns it directly. The password is fetched from the user's active
        secret store and is NEVER placed in the audit trail.

        ``app`` selects one DB when the instance hosts several (each website
        stored under its own label). Omitted + a single DB → that one; omitted
        + several → an error listing the sites to name.
        """
        instance = await self._find_instance(instance_id)
        if not instance:
            self._audit.log(tool_name, args, '', False, 'instance_not_found')
            return None, None, None, f"Instance not found: {instance_id}"

        config = self._config_manager.get()
        inst_id, inst_name = instance.get('id', ''), instance.get('name', '')
        profiles = config.db_profiles_for(inst_id, inst_name)
        if not profiles:
            self._audit.log(tool_name, args, '', False, 'no_db_profile')
            return None, None, None, (
                f"No db_profile configured for {instance_id}. To set one up "
                f"automatically, call db_setup_scan(instance_id='{instance_id}') "
                "— it reads the app's DB credentials from the box (read-only) "
                "and stages them; then ask the user to confirm and call "
                "db_setup_save. (Or the user can run `servonaut db setup "
                f"{instance_id}`.)"
            )

        if app.strip():
            profile = config.db_profile_by_label(inst_id, app, inst_name)
            if profile is None:
                sites = ", ".join(sorted(
                    (p.label or "(unlabelled)") for p in profiles
                ))
                self._audit.log(tool_name, args, '', False, 'db_label_no_match')
                return None, None, None, (
                    f"No DB on {instance_id} matches app {app!r} (or the match "
                    f"is ambiguous). Stored sites: {sites}."
                )
        elif len(profiles) == 1:
            profile = profiles[0]
        else:
            sites = ", ".join(sorted(
                (p.label or "(unlabelled)") for p in profiles
            ))
            self._audit.log(tool_name, args, '', False, 'db_label_required')
            return None, None, None, (
                f"{instance_id} has {len(profiles)} databases — name one with "
                f"app='<site>'. Stored sites: {sites}."
            )

        engine = (profile.engine or 'mysql').strip().lower()
        if engine not in ('mysql', 'mariadb', 'postgres', 'postgresql'):
            self._audit.log(tool_name, args, '', False, f"bad_engine:{engine}")
            return None, None, None, (
                f"Unsupported db engine {engine!r}; use 'mysql' or 'postgres'."
            )

        password = ""
        if profile.password_secret:
            if self._secret_provider is None:
                self._audit.log(tool_name, args, '', False, 'no_secret_provider')
                return None, None, None, (
                    "DB profile references a secret but no secret store is "
                    "active. Run `servonaut login` (the secret store is a "
                    "Solo/Teams feature) so the password can be resolved."
                )
            try:
                password = await self._secret_provider.get_secret(
                    profile.password_secret,
                )
            except Exception as e:  # noqa: BLE001
                self._audit.log(tool_name, args, '', False, f"secret_error: {e}")
                return None, None, None, f"Error reading secret: {e}"
            if password is None:
                self._audit.log(tool_name, args, '', False, 'secret_not_found')
                return None, None, None, (
                    f"Secret {profile.password_secret!r} not found in the "
                    "active secret store."
                )

        return instance, profile, (password or ""), ""

    # PHP fallbacks used when the box has no mysql/psql CLI (common on Joomla /
    # PHP web boxes — PHP + mysqli/PDO are always present). Read connection +
    # SQL from exported env vars so no credential lands in php's own argv.
    # Single-quoted at the call site; these use ONLY double quotes internally.
    _PHP_MYSQLI_FALLBACK = (
        '$m=@new mysqli(getenv("DBH"),getenv("DBU"),getenv("DBP"),'
        'getenv("DBN")?:NULL,(int)getenv("DBPORT"));'
        'if($m->connect_errno){fwrite(STDERR,"connect: ".$m->connect_error);exit(1);}'
        '$q=getenv("DBSQL");'
        'if($m->multi_query($q)){do{if($r=$m->store_result()){'
        '$h=array();foreach($r->fetch_fields() as $c)$h[]=$c->name;'
        'echo implode("\\t",$h)."\\n";'
        'while($w=$r->fetch_row())echo implode("\\t",array_map('
        'function($x){return $x===null?"NULL":$x;},$w))."\\n";'
        'echo "\\n";$r->free();}}while($m->more_results()&&$m->next_result());}'
        'if($m->errno)fwrite(STDERR,"query: ".$m->error);'
    )
    _PHP_PDO_PGSQL_FALLBACK = (
        'try{$p=new PDO("pgsql:host=".getenv("DBH").";port=".getenv("DBPORT").'
        '";dbname=".(getenv("DBN")?:"postgres"),getenv("DBU"),getenv("DBP"));}'
        'catch(Exception $e){fwrite(STDERR,$e->getMessage());exit(1);}'
        '$first=true;foreach($p->query(getenv("DBSQL")) as $row){'
        '$row=array_filter($row,"is_string",ARRAY_FILTER_USE_KEY);'
        'if($first){echo implode("\\t",array_keys($row))."\\n";$first=false;}'
        'echo implode("\\t",array_map(function($x){return $x===null?"NULL":$x;},'
        '$row))."\\n";}'
    )

    def _build_db_command(self, profile, sql: str, password: str) -> str:
        """Build the on-box DB command for *sql*, with a no-client fallback.

        Prefers the native CLI (mysql/psql); if it's absent — common on Joomla
        web boxes — falls back to ``php -r`` (mysqli / PDO_pgsql), which is
        guaranteed on a PHP box. Credentials + SQL are passed via exported env
        vars (not argv on the DB client), so the password never appears in the
        client's own process list. The whole string is one SSH argument, parsed
        by the remote shell.
        """
        engine = (profile.engine or 'mysql').strip().lower()
        host = profile.host or '127.0.0.1'
        port = int(profile.port or (5432 if engine.startswith('postgres') else 3306))
        user = profile.user or 'root'
        is_pg = engine.startswith('postgres')
        database = profile.database or ('postgres' if is_pg else '')

        q = shlex.quote
        env = (
            f"DBH={q(host)}; DBU={q(user)}; DBP={q(password)}; "
            f"DBN={q(database)}; DBPORT={q(str(port))}; DBSQL={q(sql)}; "
            "export DBH DBU DBP DBN DBPORT DBSQL; "
        )
        if is_pg:
            native = (
                'PGPASSWORD="$DBP" psql -h "$DBH" -p "$DBPORT" -U "$DBU" '
                '-d "${DBN:-postgres}" --no-psqlrc -P pager=off -c "$DBSQL"'
            )
            php = f"php -r {q(self._PHP_PDO_PGSQL_FALLBACK)}"
            client = "psql"
        else:
            native = (
                'MYSQL_PWD="$DBP" mysql -h "$DBH" -P "$DBPORT" -u "$DBU" '
                '${DBN:+"$DBN"} --batch --table -e "$DBSQL"'
            )
            php = f"php -r {q(self._PHP_MYSQLI_FALLBACK)}"
            client = "mysql"
        return (
            f"{env}"
            f"if command -v {client} >/dev/null 2>&1; then {native}; "
            f"elif command -v php >/dev/null 2>&1; then {php}; "
            f"else echo 'ERROR: no {client} client and no php on this host' >&2; "
            f"exit 127; fi"
        )

    async def db_processlist(
        self, instance_id: str, full: bool = False, app: str = "",
    ) -> str:
        """Show DB connection saturation + a session summary for an instance.

        By default this SUMMARISES server-side instead of dumping every row (a
        busy box can have hundreds of sessions): connection saturation, a
        breakdown of sessions by command/state with counts + oldest age, and the
        10 longest-running non-idle queries. Pass ``full=true`` for the raw
        ``SHOW FULL PROCESSLIST`` / full ``pg_stat_activity`` dump.

        ``app`` names one website/app when the instance hosts several DBs (e.g.
        ``app='shop.example.com'``) — matched loosely against the stored site
        labels. Omit it when the instance has a single DB.

        MySQL/MariaDB uses ``information_schema.PROCESSLIST``; Postgres uses
        ``pg_stat_activity``. Credentials come from the instance's db_profile +
        your secret store.
        """
        args = {'instance_id': instance_id, 'full': full, 'app': app}
        allowed, reason = self._guard.check_tool('db_processlist')
        if not allowed:
            self._audit.log('db_processlist', args, '', False, reason)
            return f"Blocked: {reason}"

        instance, profile, password, err = await self._resolve_db(
            instance_id, 'db_processlist', args, app=app,
        )
        if err:
            return f"Error: {err}"

        engine = (profile.engine or 'mysql').strip().lower()
        is_postgres = engine.startswith('postgres')
        if is_postgres:
            if full:
                sql = (
                    "SELECT pid, usename, state, wait_event_type, "
                    "now()-query_start AS duration, left(query,80) AS query "
                    "FROM pg_stat_activity WHERE state IS DISTINCT FROM 'idle' "
                    "ORDER BY query_start NULLS LAST;"
                )
            else:
                # Saturation, by-state breakdown, and the 10 oldest non-idle.
                sql = (
                    "SELECT count(*) AS total, "
                    "count(*) FILTER (WHERE state IS DISTINCT FROM 'idle') "
                    "AS active, "
                    "(SELECT setting FROM pg_settings "
                    "WHERE name='max_connections') AS max_connections "
                    "FROM pg_stat_activity; "
                    "SELECT state, wait_event_type, count(*) AS sessions, "
                    "max(now()-query_start) AS max_age FROM pg_stat_activity "
                    "GROUP BY state, wait_event_type ORDER BY sessions DESC; "
                    "SELECT pid, usename, state, now()-query_start AS age, "
                    "left(regexp_replace(query,'\\s+',' ','g'),80) AS query "
                    "FROM pg_stat_activity WHERE state IS DISTINCT FROM 'idle' "
                    "AND query_start IS NOT NULL "
                    "ORDER BY query_start LIMIT 10;"
                )
        else:
            if full:
                sql = (
                    "SHOW STATUS LIKE 'Threads_connected'; "
                    "SHOW VARIABLES LIKE 'max_connections'; "
                    "SHOW FULL PROCESSLIST;"
                )
            else:
                # Saturation, by command/state breakdown, and the 10 oldest
                # active queries — all aggregated in-DB so the result is a
                # handful of rows even when hundreds of sessions are open.
                sql = (
                    "SHOW STATUS LIKE 'Threads_connected'; "
                    "SHOW STATUS LIKE 'Threads_running'; "
                    "SHOW VARIABLES LIKE 'max_connections'; "
                    "SELECT COMMAND, COALESCE(STATE,'') AS STATE, "
                    "COUNT(*) AS sessions, MAX(TIME) AS max_age_s "
                    "FROM information_schema.PROCESSLIST "
                    "GROUP BY COMMAND, STATE ORDER BY sessions DESC; "
                    "SELECT ID, USER, DB, TIME AS age_s, STATE, "
                    "LEFT(REPLACE(REPLACE(INFO,'\\n',' '),'\\t',' '),80) AS info "
                    "FROM information_schema.PROCESSLIST "
                    "WHERE INFO IS NOT NULL AND COMMAND <> 'Sleep' "
                    "ORDER BY TIME DESC LIMIT 10;"
                )

        command = self._build_db_command(profile, sql, password)
        key_extras: Dict[str, Any] = {}
        try:
            stdout, stderr = await self._exec_ssh(
                instance, command, timeout=30, audit_extras=key_extras,
            )
        except asyncio.TimeoutError:
            self._audit.log(
                'db_processlist', args, '', False, 'timeout', **key_extras,
            )
            return "Error: db_processlist timed out after 30 seconds"
        except Exception as e:  # noqa: BLE001
            self._audit.log(
                'db_processlist', args, '', False, f"ssh_error: {e}", **key_extras,
            )
            return f"Error: {e}"

        output = stdout or ""
        if stderr.strip():
            output += f"\nSTDERR:\n{stderr.strip()[:500]}"
        # Audit WITHOUT the command (it carries the password via env).
        self._audit.log('db_processlist', args, output, True, **key_extras)
        return output or "(no rows)"

    async def db_top_queries(
        self, instance_id: str, limit: int = 15, app: str = "",
    ) -> str:
        """Show the slowest / heaviest queries for an instance's DB.

        MySQL: ``performance_schema.events_statements_summary_by_digest``.
        Postgres: ``pg_stat_statements`` (extension must be enabled). Useful
        for the shared-RDS noisy-neighbour case. Creds via db_profile + secret
        store. ``app`` names one website/app when the instance hosts several
        DBs (matched loosely against the stored site labels).
        """
        args = {'instance_id': instance_id, 'limit': limit, 'app': app}
        allowed, reason = self._guard.check_tool('db_top_queries')
        if not allowed:
            self._audit.log('db_top_queries', args, '', False, reason)
            return f"Blocked: {reason}"

        instance, profile, password, err = await self._resolve_db(
            instance_id, 'db_top_queries', args, app=app,
        )
        if err:
            return f"Error: {err}"

        n = max(1, min(int(limit or 15), 100))
        engine = (profile.engine or 'mysql').strip().lower()
        if engine.startswith('postgres'):
            sql = (
                "SELECT left(query,80) AS query, calls, "
                "round(total_exec_time::numeric,2) AS total_ms, "
                "round(mean_exec_time::numeric,2) AS mean_ms "
                "FROM pg_stat_statements ORDER BY total_exec_time DESC "
                f"LIMIT {n};"
            )
        else:
            sql = (
                "SELECT DIGEST_TEXT, COUNT_STAR AS calls, "
                "ROUND(SUM_TIMER_WAIT/1e12,2) AS total_s, "
                "ROUND(AVG_TIMER_WAIT/1e9,2) AS avg_ms "
                "FROM performance_schema.events_statements_summary_by_digest "
                f"ORDER BY SUM_TIMER_WAIT DESC LIMIT {n};"
            )

        command = self._build_db_command(profile, sql, password)
        key_extras: Dict[str, Any] = {}
        try:
            stdout, stderr = await self._exec_ssh(
                instance, command, timeout=30, audit_extras=key_extras,
            )
        except asyncio.TimeoutError:
            self._audit.log(
                'db_top_queries', args, '', False, 'timeout', **key_extras,
            )
            return "Error: db_top_queries timed out after 30 seconds"
        except Exception as e:  # noqa: BLE001
            self._audit.log(
                'db_top_queries', args, '', False, f"ssh_error: {e}", **key_extras,
            )
            return f"Error: {e}"

        output = stdout or ""
        if stderr.strip():
            output += f"\nSTDERR:\n{stderr.strip()[:500]}"
        self._audit.log('db_top_queries', args, output, True, **key_extras)
        return output or "(no rows)"

    # ------------------------------------------------------------------
    # Incident-response tools (Group B): boto3 AWS topology (read-only)
    # ------------------------------------------------------------------

    # Best-effort on-box check for whether the web server trusts a proxy's
    # forwarded client IP (Apache mod_remoteip / nginx real_ip). Read-only.
    _REMOTEIP_PROBE_CMD = (
        "grep -rliE "
        "'remoteipheader|mod_remoteip|set_real_ip_from|real_ip_header' "
        "/etc/apache2 /etc/httpd /etc/nginx 2>/dev/null | head -1"
    )

    async def _detect_mod_remoteip(self, instance: Dict):
        """Return True/False/None for whether the box trusts forwarded client IPs."""
        try:
            stdout, _ = await self._exec_ssh(
                instance, self._REMOTEIP_PROBE_CMD, timeout=15,
            )
        except Exception:  # noqa: BLE001 — best-effort; unknown on failure
            return None
        return bool(stdout.strip())

    async def describe_ingress_path(
        self, instance_id: str, region: str = "", check_remoteip: bool = True,
        verbose: bool = False,
    ) -> str:
        """Map an instance's ALB/WAF ingress path in one call.

        instance → target group(s) → load balancer(s) → listeners/rules →
        associated WebACL → IP sets + rate-based rules, plus a flag for whether
        the box trusts forwarded client IPs (mod_remoteip / real_ip). Answers
        "behind ALB or direct?", "which WebACL fronts it?", and "is the WAF even
        attached?" — the questions that cost the most time in the incident.
        Partial results are returned when IAM scope is incomplete.
        """
        args = {'instance_id': instance_id, 'region': region,
                'check_remoteip': check_remoteip, 'verbose': verbose}
        allowed, reason = self._guard.check_tool('describe_ingress_path')
        if not allowed:
            self._audit.log('describe_ingress_path', args, '', False, reason)
            return f"Blocked: {reason}"

        instance = await self._find_instance(instance_id)
        if not instance:
            self._audit.log('describe_ingress_path', args, '', False, 'instance_not_found')
            return f"Instance not found: {instance_id}"

        if instance.get('is_custom') or instance.get('is_ovh') or instance.get('is_hetzner'):
            self._audit.log('describe_ingress_path', args, '', False, 'not_aws')
            return (
                "describe_ingress_path is AWS-only (ALB/WAF topology). "
                f"{instance_id} is a non-AWS instance."
            )

        aws_id = instance.get('id', '')
        private_ip = instance.get('private_ip') or ''
        eff_region = region or instance.get('region') or ''

        from servonaut.services.ingress_path_service import (
            IngressPathService, format_ingress_path,
        )
        try:
            topo = await IngressPathService().describe(
                aws_id, private_ip, eff_region,
            )
        except Exception as e:  # noqa: BLE001
            self._audit.log('describe_ingress_path', args, '', False, f"aws_error: {e}")
            return f"Error walking ingress path: {e}"

        remoteip = None
        if check_remoteip:
            remoteip = await self._detect_mod_remoteip(instance)

        result = format_ingress_path(topo, remoteip, verbose=verbose)
        self._audit.log('describe_ingress_path', args, result, True)
        return result

    # ------------------------------------------------------------------
    # Incident-response tools (Group C): WAF mitigation (dangerous tier)
    # ------------------------------------------------------------------

    async def _resolve_webacl(self, target: str, region: str = "") -> Dict[str, Any]:
        """Resolve a WebACL from a WebACL ARN, an ALB ARN, or an instance.

        Returns {name, id, scope, region, arn} or {error}. For an instance it
        walks the ingress path (Group B) to find the WebACL fronting its ALB.
        """
        from servonaut.services.waf_management_service import (
            WAFManagementService, parse_wafv2_arn,
        )
        target = (target or "").strip()
        if not target:
            return {"error": "no target (need a WebACL/ALB ARN or instance)."}

        if target.startswith("arn:aws:wafv2:"):
            parsed = parse_wafv2_arn(target)
            if not parsed or parsed["kind"] != "webacl":
                return {"error": f"not a WebACL ARN: {target}"}
            return {"name": parsed["name"], "id": parsed["id"],
                    "scope": parsed["scope"], "region": parsed["region"] or region,
                    "arn": target}

        if target.startswith("arn:aws:elasticloadbalancing:"):
            alb_region = (target.split(":")[3] if ":" in target else "") or region
            summ = await WAFManagementService().get_web_acl_for_resource(
                target, alb_region,
            )
            if not summ:
                return {"error": f"no WebACL attached to {target}"}
            parsed = parse_wafv2_arn(summ["arn"])
            return {"name": summ["name"], "id": summ["id"],
                    "scope": parsed["scope"] if parsed else "REGIONAL",
                    "region": (parsed["region"] if parsed else alb_region) or region,
                    "arn": summ["arn"]}

        # Otherwise treat target as an instance id/name → walk its ingress path.
        instance = await self._find_instance(target)
        if not instance:
            return {"error": f"instance not found: {target}"}
        if instance.get("is_custom") or instance.get("is_ovh") or instance.get("is_hetzner"):
            return {"error": f"{target} is not an AWS instance"}
        from servonaut.services.ingress_path_service import IngressPathService
        eff_region = region or instance.get("region") or ""
        topo = await IngressPathService().describe(
            instance.get("id", ""), instance.get("private_ip") or "", eff_region,
        )
        for lb in topo.get("load_balancers", []):
            acl = lb.get("web_acl")
            if acl and acl.get("arn"):
                parsed = parse_wafv2_arn(acl["arn"])
                if parsed:
                    return {"name": parsed["name"], "id": parsed["id"],
                            "scope": parsed["scope"],
                            "region": parsed["region"] or eff_region, "arn": acl["arn"]}
        return {"error": f"no WebACL found fronting {target}"}

    def _collect_ban_targets(self, ip_address, cidr, ip_addresses) -> List[str]:
        """Union ip_address + cidr + ip_addresses[], deduped, order-preserving."""
        out: List[str] = []
        for src in (ip_address, cidr):
            if src and src.strip() and src.strip() not in out:
                out.append(src.strip())
        for ip in (ip_addresses or []):
            if ip and str(ip).strip() and str(ip).strip() not in out:
                out.append(str(ip).strip())
        return out

    async def ip_ban_set(
        self, ip_address: str = "", config_name: str = "", action: str = "ban",
        ip_addresses: Optional[List[str]] = None, cidr: str = "",
        site: str = "", region: str = "",
    ) -> str:
        """Ban/unban IP(s) or CIDR(s) via a named config OR a site's WebACL.

        Additive (old ``ip_address`` + ``config_name`` calls unchanged): accepts
        CIDR in ``ip_address``/``cidr``, a bulk ``ip_addresses[]`` list, and a
        ``site`` (WebACL ARN, ALB ARN, or instance id/name) that resolves the
        WebACL fronting it — so you can ban into the WebACL that actually fronts
        the box without a pre-defined config. Returns an applied/failed split.
        """
        args = {
            'ip_address': ip_address, 'config_name': config_name, 'action': action,
            'ip_addresses': ip_addresses, 'cidr': cidr, 'site': site, 'region': region,
        }
        allowed, reason = self._guard.check_tool('ip_ban_set')
        if not allowed:
            self._audit.log('ip_ban_set', args, '', False, reason)
            return f"Blocked: {reason}"

        action_norm = (action or "").strip().lower()
        if action_norm not in ('ban', 'unban'):
            self._audit.log('ip_ban_set', args, '', False, 'invalid_action')
            return f"Error: action must be 'ban' or 'unban', got {action!r}."

        targets = self._collect_ban_targets(ip_address, cidr, ip_addresses)
        if not targets:
            self._audit.log('ip_ban_set', args, '', False, 'no_targets')
            return "Error: provide at least one ip_address, cidr, or ip_addresses[]."

        # --- site path: resolve the WebACL fronting the site/instance ---
        if site and not config_name:
            return await self._ip_ban_via_site(site, targets, action_norm, region, args)

        # --- named-config path (existing behaviour, now CIDR + bulk aware) ---
        if not config_name:
            self._audit.log('ip_ban_set', args, '', False, 'no_target_selector')
            return "Error: provide config_name or site."
        if self._ip_ban_service is None:
            self._audit.log('ip_ban_set', args, '', False, 'service_unavailable')
            return "Error: IP ban service is not available."

        applied: List[str] = []
        failed: List[Dict[str, str]] = []
        for target in targets:
            try:
                if action_norm == 'ban':
                    res = await self._ip_ban_service.ban_ip(target, config_name)
                else:
                    res = await self._ip_ban_service.unban_ip(target, config_name)
            except Exception as e:  # noqa: BLE001
                failed.append({"ip": target, "reason": str(e)})
                continue
            if res.get('success'):
                applied.append(target)
            else:
                failed.append({"ip": target, "reason": res.get('message', 'failed')})

        result = self._format_ban_result(
            target_label=config_name, web_acl="", action=action_norm,
            applied=applied, failed=failed,
        )
        self._audit.log('ip_ban_set', args, result, bool(applied) and not failed)
        return result

    async def _ip_ban_via_site(
        self, site: str, targets: List[str], action_norm: str,
        region: str, args: Dict,
    ) -> str:
        acl = await self._resolve_webacl(site, region)
        if acl.get("error"):
            self._audit.log('ip_ban_set', args, '', False, f"webacl: {acl['error']}")
            return f"Error: {acl['error']}"
        from servonaut.services.waf_management_service import WAFManagementService
        res = await WAFManagementService().add_ip_to_block_ipset(
            acl["name"], acl["id"], acl["scope"], acl["region"],
            cidrs=targets, remove=(action_norm == 'unban'),
        )
        if res.get("error") and not res.get("applied"):
            self._audit.log('ip_ban_set', args, '', False, f"waf: {res['error']}")
            return (f"Error banning via WebACL {acl['name']}: {res['error']}")
        result = self._format_ban_result(
            target_label=site, web_acl=f"{acl['name']} (IP set {res.get('ip_set','?')})",
            action=action_norm, applied=res.get("applied", []),
            failed=res.get("failed", []),
        )
        self._audit.log('ip_ban_set', args, result, bool(res.get("applied")))
        return result

    def _format_ban_result(
        self, target_label, web_acl, action, applied, failed,
    ) -> str:
        verb = "Banned" if action == "ban" else "Unbanned"
        undo = "unban" if action == "ban" else "ban"
        lines = [f"ip_ban_set {action} via {target_label}:"]
        if web_acl:
            lines.append(f"  WebACL: {web_acl}")
        lines.append(f"  {verb} ({len(applied)}): {', '.join(applied) or '-'}")
        if failed:
            lines.append(f"  Failed ({len(failed)}):")
            for f in failed:
                lines.append(f"    {f.get('ip','')}: {f.get('reason','')}")
        if applied:
            lines.append(f"  reverse_hint: ip_ban_set action={undo} "
                         + (f"site={target_label}" if web_acl else f"config_name={target_label}")
                         + f" ip_addresses={applied}")
        return "\n".join(lines)

    async def waf_rate_rule_set(
        self, site: str, rule_name: str = "servonaut-rate", limit: int = 2000,
        uri_scope: str = "", action: str = "block", remove: bool = False,
        region: str = "",
    ) -> str:
        """Create/attach (or remove) a WAF rate-based rule on a site's WebACL.

        ``site`` is a WebACL ARN, ALB ARN, or instance id/name. ``limit`` is the
        request count per 5-minute window per client IP; ``uri_scope`` optionally
        restricts the rule to a URI path prefix (e.g. ``/``). This is the durable
        fix for a flood — applied reversibly (``remove=true`` undoes it).
        """
        args = {
            'site': site, 'rule_name': rule_name, 'limit': limit,
            'uri_scope': uri_scope, 'action': action, 'remove': remove,
            'region': region,
        }
        allowed, reason = self._guard.check_tool('waf_rate_rule_set')
        if not allowed:
            self._audit.log('waf_rate_rule_set', args, '', False, reason)
            return f"Blocked: {reason}"
        act = (action or "block").strip().lower()
        if act not in ('block', 'count'):
            self._audit.log('waf_rate_rule_set', args, '', False, 'bad_action')
            return f"Error: action must be 'block' or 'count', got {action!r}."

        acl = await self._resolve_webacl(site, region)
        if acl.get("error"):
            self._audit.log('waf_rate_rule_set', args, '', False, f"webacl: {acl['error']}")
            return f"Error: {acl['error']}"

        from servonaut.services.waf_management_service import WAFManagementService
        res = await WAFManagementService().set_rate_rule(
            acl["name"], acl["id"], acl["scope"], acl["region"],
            rule_name=rule_name, limit=int(limit), uri_scope=uri_scope,
            action=act, remove=remove,
        )
        if not res.get("applied"):
            err = res.get("error", "unknown error")
            self._audit.log('waf_rate_rule_set', args, '', False, f"waf: {err}")
            return f"Error setting rate rule on WebACL {acl['name']}: {err}"

        prev = res.get("previous")
        if remove:
            lines = [f"Removed rate rule '{rule_name}' from WebACL {acl['name']}."]
            if prev:
                lines.append(
                    f"  previous: {prev.get('limit')} req/5min, action="
                    f"{prev.get('action')}{', uri-scoped' if prev.get('uri_scoped') else ''}")
                lines.append(
                    f"  reverse_hint: waf_rate_rule_set site={site} "
                    f"rule_name={rule_name} limit={prev.get('limit')} "
                    f"action={prev.get('action')}  (re-creates the removed rule)")
            else:
                lines.append(
                    f"  reverse_hint: re-add with waf_rate_rule_set site={site} "
                    f"rule_name={rule_name} limit={limit}"
                    + (f" uri_scope={uri_scope}" if uri_scope else ""))
            body = "\n".join(lines)
        else:
            scope_note = f" scoped to URI {uri_scope!r}" if uri_scope else ""
            verb = res.get("created_or_updated", "applied")
            lines = [
                f"{verb.capitalize()} rate rule '{rule_name}' on WebACL "
                f"{acl['name']}: {limit} req/5min per IP{scope_note}, action={act}.",
            ]
            if verb == "updated" and prev:
                # Reversible to the PRIOR state, not just deletable.
                lines.append(
                    f"  previous: {prev.get('limit')} req/5min, action="
                    f"{prev.get('action')}{', uri-scoped' if prev.get('uri_scoped') else ''}")
                lines.append(
                    f"  reverse_hint: restore prior with waf_rate_rule_set "
                    f"site={site} rule_name={rule_name} limit={prev.get('limit')} "
                    f"action={prev.get('action')}")
            else:
                lines.append(
                    f"  reverse_hint: waf_rate_rule_set site={site} "
                    f"rule_name={rule_name} remove=true")
            body = "\n".join(lines)
        self._audit.log('waf_rate_rule_set', args, body, True)
        return body

    async def block_ip(
        self, ip: str, site: str = "", action: str = "block", region: str = "",
    ) -> str:
        """Block (or unblock) an IP/CIDR at the layer that actually works.

        Resolves the best layer for ``site`` (a WebACL/ALB ARN or instance):
        prefers the WebACL (it sees the real client IP behind an ALB); falls
        back to a configured SG/NACL ip_ban config; and if neither exists,
        recommends the host layer rather than silently editing the firewall.
        Always reversible. ``action`` is ``block`` or ``unblock``.
        """
        args = {'ip': ip, 'site': site, 'action': action, 'region': region}
        allowed, reason = self._guard.check_tool('block_ip')
        if not allowed:
            self._audit.log('block_ip', args, '', False, reason)
            return f"Blocked: {reason}"
        act = (action or "block").strip().lower()
        if act not in ('block', 'unblock'):
            self._audit.log('block_ip', args, '', False, 'bad_action')
            return f"Error: action must be 'block' or 'unblock', got {action!r}."
        if not ip.strip():
            self._audit.log('block_ip', args, '', False, 'no_ip')
            return "Error: provide an ip or CIDR to block."
        if not site.strip():
            self._audit.log('block_ip', args, '', False, 'no_site')
            return "Error: provide a site (WebACL/ALB ARN or instance id/name)."

        ban_action = 'ban' if act == 'block' else 'unban'

        # --- layer 1: WebACL (sees the real client IP behind an ALB) ---
        acl = await self._resolve_webacl(site, region)
        if not acl.get("error"):
            from servonaut.services.waf_management_service import WAFManagementService
            res = await WAFManagementService().add_ip_to_block_ipset(
                acl["name"], acl["id"], acl["scope"], acl["region"],
                cidrs=[ip], remove=(ban_action == 'unban'),
            )
            if not res.get("error") or res.get("applied"):
                applied = bool(res.get("applied"))
                out = self._format_block_ip(
                    site, ip, act, layer="waf", applied=applied,
                    detail=f"WebACL {acl['name']} IP set {res.get('ip_set','?')}",
                    failed=res.get("failed", []),
                    rationale=(
                        "a WebACL fronts this site — a ban here matches the "
                        "real client IP; host/SG bans would see only the ALB hop."
                    ),
                )
                self._audit.log('block_ip', args, out, applied)
                return out
            webacl_note = res.get("error", "")
        else:
            webacl_note = acl["error"]

        # --- layer 2: a configured SG/NACL/WAF ip_ban config ---
        if self._ip_ban_service is not None:
            configs = self._ip_ban_service.get_configs()
            if configs:
                cfg = configs[0]
                try:
                    if ban_action == 'ban':
                        res = await self._ip_ban_service.ban_ip(ip, cfg.name)
                    else:
                        res = await self._ip_ban_service.unban_ip(ip, cfg.name)
                except Exception as e:  # noqa: BLE001
                    res = {'success': False, 'message': str(e)}
                layer = getattr(cfg, 'method', 'sg')
                layer = {'security_group': 'sg', 'nacl': 'nacl', 'waf': 'waf'}.get(layer, layer)
                out = self._format_block_ip(
                    site, ip, act, layer=layer, applied=bool(res.get('success')),
                    detail=f"config '{cfg.name}' ({getattr(cfg,'method','')}): {res.get('message','')}",
                    failed=[] if res.get('success') else [{"ip": ip, "reason": res.get('message','')}],
                    rationale=(
                        f"no WebACL resolved ({webacl_note}); used the configured "
                        f"{getattr(cfg,'method','')} '{cfg.name}'. Note: SG/NACL match by "
                        "source IP — best for direct-to-instance traffic; for "
                        "ALB-fronted traffic prefer a WebACL (source IP is the ALB)."
                    ),
                )
                self._audit.log('block_ip', args, out, bool(res.get('success')))
                return out

        # --- layer 3: no AWS layer available → recommend host-level ---
        out = self._format_block_ip(
            site, ip, act, layer="host", applied=False,
            detail=(
                f"No WebACL ({webacl_note}) and no SG/NACL ip_ban config. "
                "Block at the host instead — but only if the box trusts "
                "forwarded IPs (check describe_ingress_path). Apache: "
                f"'Require not ip {ip}'; nginx: 'deny {ip};'. Not applied "
                "automatically (host firewall edits aren't auto-reversible here)."
            ),
            failed=[],
            rationale=(
                "no AWS edge layer (WebACL/SG/NACL) is available for this site, "
                "so the only place left to block is the host itself — and only "
                "if it trusts forwarded IPs."
            ),
        )
        self._audit.log('block_ip', args, out, False, 'no_aws_layer')
        return out

    def _format_block_ip(self, site, ip, action, layer, applied, detail,
                         failed, rationale=""):
        undo = 'unblock' if action == 'block' else 'block'
        lines = [
            f"block_ip {action} {ip} on {site}:",
            f"  layer_used: {layer}",
        ]
        if rationale:
            lines.append(f"  why: {rationale}")
        lines.append(f"  applied: {applied}")
        lines.append(f"  detail: {detail}")
        if failed:
            for f in failed:
                lines.append(f"  failed: {f.get('ip','')}: {f.get('reason','')}")
        if applied:
            lines.append(f"  reverse_hint: block_ip ip={ip} site={site} action={undo}")
        return "\n".join(lines)

    async def rds_metrics(
        self, db_instance: str, region: str = "", window_hours: int = 3,
    ) -> str:
        """Snapshot an RDS instance's health: CPU, connections, credit, latency.

        Reads CloudWatch AWS/RDS metrics (CPUUtilization, DatabaseConnections,
        CPUCreditBalance, Read/WriteLatency, FreeableMemory) for the named DB
        instance. The first thing to check for the shared-RDS noisy-neighbour
        case. ``db_instance`` is the RDS DB instance identifier. Read-only.
        """
        args = {'db_instance': db_instance, 'region': region,
                'window_hours': window_hours}
        allowed, reason = self._guard.check_tool('rds_metrics')
        if not allowed:
            self._audit.log('rds_metrics', args, '', False, reason)
            return f"Blocked: {reason}"
        if not db_instance.strip():
            self._audit.log('rds_metrics', args, '', False, 'no_db_instance')
            return "Error: provide a db_instance (the RDS DB instance identifier)."

        from servonaut.services.rds_metrics_service import (
            RDSMetricsService, format_rds_metrics,
        )
        try:
            data = await RDSMetricsService().fetch(
                db_instance, region=region, window_hours=max(1, int(window_hours or 3)),
            )
        except Exception as e:  # noqa: BLE001
            self._audit.log('rds_metrics', args, '', False, f"aws_error: {e}")
            return f"Error fetching RDS metrics: {e}"

        result = format_rds_metrics(data)
        self._audit.log('rds_metrics', args, result, True)
        return result

    # ------------------------------------------------------------------
    # DB credential setup (staging-token pattern — secrets never in context)
    # ------------------------------------------------------------------

    async def _scan_db_and_stage(
        self, instance, search_path: str, source: str,
        audit_extras: Optional[Dict[str, Any]] = None,
    ):
        """Run the credential scanner + stage candidates server-side.

        Shared core of :meth:`db_setup_scan` (string/agent surface) and
        :meth:`db_scan_stage` (structured/human surface) so both reuse ONE
        scan+stage path — the parsing lives in
        :class:`DBCredentialScanner`, never reimplemented per surface.

        Returns ``(staged, err)`` where ``staged`` is a list of
        ``(token, DBCandidate)`` (plaintext held only in
        ``self._db_staging`` keyed by token) and ``err`` is ``None`` or a
        ``(kind, message)`` tuple (``kind`` ∈ ``{"ssh_error",
        "local_read"}``). Only surfaces an error for an EXPLICIT source
        failure — an ``auto`` ssh miss falls through to the local branch,
        matching the original behaviour.
        """
        from servonaut.services.db_credential_scanner import DBCredentialScanner
        scanner = DBCredentialScanner()
        src = (source or "auto").strip().lower()

        candidates = []
        if src in ("auto", "ssh"):
            command = scanner.build_scan_command(search_path)
            try:
                stdout, _ = await self._exec_ssh(
                    instance, command, timeout=30, audit_extras=audit_extras,
                )
                candidates = scanner.parse(stdout)
            except Exception as e:  # noqa: BLE001
                if src == "ssh":
                    return [], ("ssh_error", str(e))
        if not candidates and src in ("auto", "local") and search_path:
            import os
            if os.path.isfile(os.path.expanduser(search_path)):
                try:
                    with open(os.path.expanduser(search_path), "r",
                              encoding="utf-8", errors="replace") as fh:
                        candidates = scanner.parse_text(fh.read(), search_path)
                except OSError as e:
                    return [], ("local_read", str(e))

        import secrets as _secrets
        staged = []
        for cand in candidates:
            token = "dbstg_" + _secrets.token_urlsafe(6)
            self._db_staging[token] = cand
            staged.append((token, cand))
        return staged, None

    async def db_setup_scan(
        self, instance_id: str, search_path: str = "", source: str = "auto",
    ) -> str:
        """Discover DB credentials for an instance and stage them for setup.

        Reads the app's config (``.env`` / ``DATABASE_URL`` / ``wp-config.php``
        / docker env) — for a managed instance, READ-ONLY over SSH on the box.
        Returns a REDACTED preview plus a staging token per candidate; the
        plaintext password is held server-side and is NEVER returned (so it
        can't leak into your model context). Then call ``db_setup_save`` with
        the chosen token to commit it to the secret store. Read-only.
        """
        args = {'instance_id': instance_id, 'search_path': search_path,
                'source': source}
        allowed, reason = self._guard.check_tool('db_setup_scan')
        if not allowed:
            self._audit.log('db_setup_scan', args, '', False, reason)
            return f"Blocked: {reason}"

        instance = await self._find_instance(instance_id)
        if not instance:
            self._audit.log('db_setup_scan', args, '', False, 'instance_not_found')
            return f"Instance not found: {instance_id}"

        from servonaut.services.db_credential_scanner import redact
        # key_extras carries key_source (e.g. "bw_personal") when the on-box
        # scan resolved its SSH key from the Bitwarden vault, so the audit row
        # records which credential the scan authenticated with.
        key_extras: Dict[str, Any] = {}
        staged, err = await self._scan_db_and_stage(
            instance, search_path, source, audit_extras=key_extras,
        )
        if err is not None:
            kind, msg = err
            self._audit.log('db_setup_scan', args, '', False, f"{kind}: {msg}", **key_extras)
            if kind == "ssh_error":
                return f"Error scanning on box: {msg}"
            return f"Error reading {search_path}: {msg}"

        if not staged:
            self._audit.log('db_setup_scan', args, '0 candidates', True, **key_extras)
            return (
                f"No DB credentials found for {instance_id}"
                + (f" under {search_path}" if search_path else "")
                + ". Try db_setup_scan with an explicit search_path (a dir on "
                "the box, or a local .env file), or ask the user for the DSN."
            )

        lines = [
            f"Found {len(staged)} DB credential candidate(s) for "
            f"{instance_id} (passwords hidden — held server-side):",
        ]
        previews = []
        multi = len(staged) > 1
        for token, cand in staged:
            r = redact(cand)
            previews.append(r)
            site = f"[{r['label']}] " if r.get('label') else ""
            lines.append(
                f"  token={token}  {site}{r['engine']} {r['user']}@{r['host']}:"
                f"{r['port']}/{r['database'] or '?'}  pw={r['password_preview']}  "
                f"(from {r['source']})"
            )
        commit_hint = (
            "\nReview with the user, then commit EACH site you want with: "
            "db_setup_save(token=<token>, instance_id='" + instance_id + "'"
            "). Each candidate is stored under its own site label, so several "
            "DBs on this instance coexist — name the site later with app='...'."
            if multi else
            "\nReview with the user, then commit with: db_setup_save("
            "token=<token>, instance_id='" + instance_id + "')."
        )
        lines.append(
            commit_hint + " The password is NOT shown here and will go straight "
            "to the secret store."
        )
        # Audit stores only redacted previews — never the plaintext.
        self._audit.log(
            'db_setup_scan', args, f"{len(previews)} candidates staged", True,
            **key_extras,
        )
        return "\n".join(lines)

    async def db_scan_stage(
        self, instance_id: str, search_path: str = "", source: str = "auto",
    ) -> Dict[str, Any]:
        """Structured sibling of :meth:`db_setup_scan` for human surfaces.

        Same scan + server-side staging as the agent tool, but returns
        structured REDACTED previews (with the staging token) so the TUI
        can render a review table. Commit a chosen row with
        :meth:`db_setup_save` ``(token=...)`` — identical to the agent path.

        Returns ``{"error": str | None, "instance": id, "candidates":
        [{token, engine, user, host, port, database, password_preview,
        source}]}``. Plaintext passwords stay in ``self._db_staging``;
        only ``redact()`` previews cross this boundary.
        """
        args = {'instance_id': instance_id, 'search_path': search_path,
                'source': source}
        allowed, reason = self._guard.check_tool('db_setup_scan')
        if not allowed:
            self._audit.log('db_setup_scan', args, '', False, reason)
            return {"error": f"Blocked: {reason}", "instance": instance_id,
                    "candidates": []}

        instance = await self._find_instance(instance_id)
        if not instance:
            self._audit.log('db_setup_scan', args, '', False, 'instance_not_found')
            return {"error": f"Instance not found: {instance_id}",
                    "instance": instance_id, "candidates": []}

        from servonaut.services.db_credential_scanner import redact
        staged, err = await self._scan_db_and_stage(instance, search_path, source)
        if err is not None:
            kind, msg = err
            self._audit.log('db_setup_scan', args, '', False, f"{kind}: {msg}")
            return {"error": f"{kind}: {msg}", "instance": instance_id,
                    "candidates": []}

        candidates = []
        for token, cand in staged:
            preview = redact(cand)
            preview["token"] = token
            candidates.append(preview)
        self._audit.log(
            'db_setup_scan', args,
            f"{len(candidates)} candidates staged (structured)", True,
        )
        return {"error": None, "instance": instance_id, "candidates": candidates}

    async def db_setup_save(
        self, token: str, instance_id: str = "", engine: str = "",
        host: str = "", port: int = 0, user: str = "", database: str = "",
        password_secret: str = "", label: str = "",
    ) -> str:
        """Commit a staged DB credential (from db_setup_scan) to the secret store.

        Looks up the staged candidate by ``token``, applies any non-empty
        overrides, writes the password into your active secret store, and saves
        a db_profile so db_processlist / db_top_queries work. The password is
        read from server-side staging — never from your context. Mutating:
        confirm with the user first.
        """
        args = {'token': token, 'instance_id': instance_id, 'engine': engine,
                'host': host, 'port': port, 'user': user, 'database': database,
                'password_secret': password_secret}
        allowed, reason = self._guard.check_tool('db_setup_save')
        if not allowed:
            self._audit.log('db_setup_save', args, '', False, reason)
            return f"Blocked: {reason}"

        cand = self._db_staging.get(token)
        if cand is None:
            self._audit.log('db_setup_save', args, '', False, 'unknown_token')
            return (f"Error: unknown or expired staging token {token!r}. Run "
                    "db_setup_scan again to re-stage.")

        if self._secret_provider is None:
            self._audit.log('db_setup_save', args, '', False, 'no_secret_provider')
            return (
                "Error: no secret store is active. Run `servonaut login` (the "
                "secret store is a Solo/Teams feature) so the password can be "
                "stored, then retry."
            )

        from servonaut.services.db_credential_scanner import (
            derive_app_label, sanitize_label,
        )
        target_instance = instance_id.strip() or cand.host
        eff_engine = (engine.strip() or cand.engine).lower()
        eff_host = host.strip() or cand.host
        eff_port = int(port) if port else cand.port
        eff_user = user.strip() or cand.user
        eff_db = database.strip() or cand.database
        # App/site label: explicit override, else derived from the config path
        # the candidate was found in (the website/app on a multi-site box).
        eff_label = (label.strip() or derive_app_label(cand.source)).strip()
        # Secret name includes the label so multiple DBs on one instance don't
        # collide on db/<instance>. Unlabelled → the legacy single-DB name.
        if password_secret.strip():
            secret_name = password_secret.strip()
        elif eff_label:
            secret_name = f"db/{target_instance}/{sanitize_label(eff_label)}".replace(" ", "_")
        else:
            secret_name = f"db/{target_instance}".replace(" ", "_")

        try:
            await self._secret_provider.set_secret(secret_name, cand.password)
        except Exception as e:  # noqa: BLE001
            self._audit.log('db_setup_save', args, '', False, f"secret_error: {e}")
            return f"Error storing secret: {e}"

        # Persist the db_profile, replacing any existing one for the SAME
        # (instance, label) pair — so multiple labelled DBs on one instance
        # coexist, while re-saving the same site updates in place.
        from servonaut.config.schema import DBProfile
        config = self._config_manager.get()
        _inst_key = target_instance.strip().lower()
        _label_key = eff_label.strip().lower()
        profiles = [
            p for p in config.db_profiles
            if not (
                (p.instance or "").strip().lower() == _inst_key
                and (p.label or "").strip().lower() == _label_key
            )
        ]
        profiles.append(DBProfile(
            instance=target_instance, engine=eff_engine, host=eff_host,
            port=eff_port, user=eff_user, password_secret=secret_name,
            database=eff_db, label=eff_label,
        ))
        try:
            self._config_manager.update(db_profiles=profiles)
        except Exception as e:  # noqa: BLE001
            self._audit.log('db_setup_save', args, '', False, f"config_error: {e}")
            return f"Error saving db_profile: {e}"

        # Consume the token so the staged plaintext doesn't linger.
        self._db_staging.pop(token, None)

        _label_note = f" [{eff_label}]" if eff_label else ""
        _select_hint = (
            f" Name the site to target it: "
            f"db_processlist(instance_id='{target_instance}', app='{eff_label}')."
            if eff_label else ""
        )
        result = (
            f"Saved db_profile for {target_instance}{_label_note}: {eff_engine} "
            f"{eff_user}@{eff_host}:{eff_port}/{eff_db or '?'} "
            f"(password in secret store as {secret_name!r})."
            + _select_hint + "\n"
            f"  tip: {eff_user!r} looks like the app user — for routine "
            "diagnostics prefer a dedicated read-only DB user (SELECT + "
            "PROCESS) over storing app/admin creds.\n"
            f"  undo: db_setup_remove(instance_id='{target_instance}'"
            + (f", label='{eff_label}'" if eff_label else "") + ")"
        )
        self._audit.log('db_setup_save', args, result, True)
        return result

    async def db_setup_remove(
        self, instance_id: str, delete_secret: bool = True, app: str = "",
    ) -> str:
        """Remove an instance's db_profile (and its stored secret) — the undo
        for db_setup_save. ``app`` names one site when the instance has
        several DBs; omit it only when there is exactly one. Deletes the
        db_profile from config; when
        ``delete_secret`` is true (default) also deletes the password from the
        secret store. Mutating: confirm with the user first.
        """
        args = {'instance_id': instance_id, 'delete_secret': delete_secret,
                'app': app}
        allowed, reason = self._guard.check_tool('db_setup_remove')
        if not allowed:
            self._audit.log('db_setup_remove', args, '', False, reason)
            return f"Blocked: {reason}"

        config = self._config_manager.get()
        target = instance_id.strip().lower()
        instance_profiles = [
            p for p in config.db_profiles
            if (p.instance or "").strip().lower() == target
        ]
        if not instance_profiles:
            self._audit.log('db_setup_remove', args, '', False, 'no_db_profile')
            return f"No db_profile found for {instance_id}."

        if app.strip():
            match = config.db_profile_by_label(target, app)
            if match is None:
                sites = ", ".join(sorted(
                    (p.label or "(unlabelled)") for p in instance_profiles
                ))
                self._audit.log('db_setup_remove', args, '', False, 'db_label_no_match')
                return (f"No DB on {instance_id} matches app {app!r}. "
                        f"Stored sites: {sites}.")
        elif len(instance_profiles) == 1:
            match = instance_profiles[0]
        else:
            # app omitted on a multi-DB instance: fall back to the unlabelled
            # "default" DB when there is exactly one — it's an unambiguous
            # target (db_setup_save upserts by (instance, label), so at most one
            # profile per instance is unlabelled). Otherwise the choice is
            # genuinely ambiguous and the caller must name a site.
            unlabelled = [
                p for p in instance_profiles if not (p.label or "").strip()
            ]
            if len(unlabelled) == 1:
                match = unlabelled[0]
            else:
                sites = ", ".join(sorted(
                    (p.label or "(unlabelled)") for p in instance_profiles
                ))
                self._audit.log(
                    'db_setup_remove', args, '', False, 'db_label_required')
                return (
                    f"{instance_id} has {len(instance_profiles)} databases — name "
                    f"one with app='<site>'. Stored sites: {sites}.")

        # Remove only the matched profile (by identity), keep the rest.
        remaining = [p for p in config.db_profiles if p is not match]
        try:
            self._config_manager.update(db_profiles=remaining)
        except Exception as e:  # noqa: BLE001
            self._audit.log('db_setup_remove', args, '', False, f"config_error: {e}")
            return f"Error removing db_profile: {e}"

        secret_note = ""
        if delete_secret and match.password_secret and self._secret_provider is not None:
            try:
                deleted = await self._secret_provider.delete_secret(match.password_secret)
                secret_note = (f" Secret {match.password_secret!r} "
                               + ("deleted." if deleted else "was not present."))
            except Exception as e:  # noqa: BLE001
                secret_note = (f" (could not delete secret "
                               f"{match.password_secret!r}: {e})")
        elif match.password_secret:
            secret_note = (f" Secret {match.password_secret!r} left in the "
                           "store (delete_secret=false or no provider).")

        _lbl = f" [{match.label}]" if match.label else ""
        result = f"Removed db_profile for {instance_id}{_lbl}.{secret_note}"
        self._audit.log('db_setup_remove', args, result, True)
        return result

    # ------------------------------------------------------------------
    # Docker read-only probes (container-aware monitoring)
    # ------------------------------------------------------------------
    #
    # Contract (proactive-monitoring tool catalog): all four are
    # tier=readonly, instance-targeted, and return a JSON object encoded
    # as a string. When docker is absent the result is a structured
    # error with message "docker_not_available" (the server maps that to
    # a "no containerized workload detected" skip-reason); a docker
    # binary the SSH user may not talk to yields
    # "docker_permission_denied" (additive).

    # Resolve the docker invocation once per probe: plain `docker` when
    # the SSH user is in the docker group, `sudo -n docker` (never
    # prompts) otherwise. Sentinel lines short-circuit the probe.
    _DOCKER_PRELUDE = (
        'if ! command -v docker >/dev/null 2>&1; then '
        'echo DOCKER_NOT_AVAILABLE; exit 0; fi; '
        'if docker version >/dev/null 2>&1; then D="docker"; '
        'elif sudo -n docker version >/dev/null 2>&1; then D="sudo -n docker"; '
        'else echo DOCKER_PERMISSION_DENIED; exit 0; fi; '
    )

    # Go template projecting exactly the inspect fields docker_ps needs.
    # Single-quoted in the remote command — it must never contain "'".
    _DOCKER_PS_TEMPLATE = (
        '{"name":{{json .Name}},"image":{{json .Config.Image}},'
        '"status":{{json .State.Status}},'
        '"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}},'
        '"restart_count":{{json .RestartCount}},'
        '"started_at":{{json .State.StartedAt}},'
        '"ports":{{json .NetworkSettings.Ports}},'
        '"labels":{{json .Config.Labels}}}'
    )

    _SAFE_CONTAINER_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')

    async def _docker_probe(
        self, tool: str, args: Dict, instance_id: str,
        docker_command: str, timeout: int = 60,
    ):
        """Shared guard/instance/SSH plumbing for the docker_* tools.

        Returns ``(payload_error_str, stdout)`` — exactly one is None.
        The error string is already audited.
        """
        allowed, reason = self._guard.check_tool(tool)
        if not allowed:
            self._audit.log(tool, args, '', False, reason)
            return f"Blocked: {reason}", None

        instance = await self._find_instance(instance_id)
        if not instance:
            self._audit.log(tool, args, '', False, 'instance_not_found')
            return f"Instance not found: {instance_id}", None

        remote = self._DOCKER_PRELUDE + docker_command
        try:
            stdout, stderr = await self._exec_ssh(instance, remote, timeout=timeout)
        except asyncio.TimeoutError:
            self._audit.log(tool, args, '', False, 'timeout')
            return f"Error: {tool} timed out after {timeout} seconds", None
        except Exception as e:
            self._audit.log(tool, args, '', False, f"ssh_error: {e}")
            return f"Error: {e}", None

        head = stdout.strip().splitlines()[0].strip() if stdout.strip() else ""
        if head == "DOCKER_NOT_AVAILABLE":
            self._audit.log(tool, args, '', False, 'docker_not_available')
            return "Error: docker_not_available", None
        if head == "DOCKER_PERMISSION_DENIED":
            self._audit.log(tool, args, '', False, 'docker_permission_denied')
            return "Error: docker_permission_denied", None
        return None, stdout

    async def docker_ps(self, instance_id: str) -> str:
        """List containers (state, health, restarts, ports, compose labels).

        Read-only container inventory for one instance; JSON output per
        the proactive-monitoring tool contract.
        """
        from servonaut.utils.docker_probe import parse_docker_ps_lines

        args = {'instance_id': instance_id}
        remote = (
            'IDS=$($D ps -aq 2>/dev/null | head -100); '
            '[ -n "$IDS" ] && $D inspect --format '
            f"'{self._DOCKER_PS_TEMPLATE}' $IDS 2>/dev/null; true"
        )
        error, stdout = await self._docker_probe(
            'docker_ps', args, instance_id, remote,
        )
        if error is not None:
            return error
        result = json.dumps({"containers": parse_docker_ps_lines(stdout)})
        self._audit.log('docker_ps', args, f"{len(result)} chars", True)
        return result

    async def docker_stats(self, instance_id: str) -> str:
        """Single-sample container resource usage (CPU, memory, PIDs)."""
        from servonaut.utils.docker_probe import parse_docker_stats_lines

        args = {'instance_id': instance_id}
        remote = "$D stats --no-stream --format '{{json .}}' 2>/dev/null; true"
        error, stdout = await self._docker_probe(
            'docker_stats', args, instance_id, remote, timeout=90,
        )
        if error is not None:
            return error
        result = json.dumps({"containers": parse_docker_stats_lines(stdout)})
        self._audit.log('docker_stats', args, f"{len(result)} chars", True)
        return result

    async def docker_logs(
        self, instance_id: str, container: str, lines: int = 200,
    ) -> str:
        """Tail one container's logs (bounded)."""
        args = {'instance_id': instance_id, 'container': container,
                'lines': lines}
        if not self._SAFE_CONTAINER_RE.match(container or ""):
            self._audit.log('docker_logs', args, '', False,
                            'validation: invalid_container_name')
            return f"validation: invalid container name: {container!r}"
        n = max(1, min(int(lines or 200), 1000))
        quoted = shlex.quote(container)
        # 2>&1 — container stderr is half the story for crash loops.
        # Byte-cap defensively; a chatty container can emit MBs in 1000
        # lines and evidence strings are bounded server-side anyway.
        remote = f'$D logs --tail {n} {quoted} 2>&1 | tail -c 200000'
        error, stdout = await self._docker_probe(
            'docker_logs', args, instance_id, remote, timeout=60,
        )
        if error is not None:
            return error
        result = json.dumps({
            "container": container,
            "lines": stdout.splitlines()[-n:],
        })
        self._audit.log('docker_logs', args, f"{len(result)} chars", True)
        return result

    async def docker_events_summary(
        self, instance_id: str, since_minutes: int = 1440,
    ) -> str:
        """Aggregate container lifecycle events (die/oom/restart/kill/start)."""
        from servonaut.utils.docker_probe import summarize_docker_events

        args = {'instance_id': instance_id, 'since_minutes': since_minutes}
        minutes = max(1, min(int(since_minutes or 1440), 10080))
        # Filter daemon-side: healthcheck exec_* chatter dominates the raw
        # stream (verified on a live compose host — thousands of lines per
        # day), so only the lifecycle events we aggregate cross the wire.
        remote = (
            f"$D events --since {minutes}m --until \"$(date +%s)\" "
            "--filter type=container "
            "--filter event=die --filter event=oom --filter event=restart "
            "--filter event=kill --filter event=start "
            "--format '{{json .}}' 2>/dev/null; true"
        )
        error, stdout = await self._docker_probe(
            'docker_events_summary', args, instance_id, remote, timeout=90,
        )
        if error is not None:
            return error
        result = json.dumps({"events": summarize_docker_events(stdout)})
        self._audit.log('docker_events_summary', args,
                        f"{len(result)} chars", True)
        return result
