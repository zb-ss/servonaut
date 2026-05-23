"""MCP tool implementations for Servonaut."""
from __future__ import annotations

import asyncio
import json
import logging
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
                 auth_service=None, memory_service=None,
                 aws_object_storage_service=None,
                 hetzner_object_storage_service=None,
                 ovh_object_storage_service=None) -> None:
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
        self._auth_service = auth_service
        self._memory_service = memory_service
        self._aws_object_storage_service = aws_object_storage_service
        self._hetzner_object_storage_service = hetzner_object_storage_service
        self._ovh_object_storage_service = ovh_object_storage_service
        self._max_lines = config_manager.get().mcp.max_output_lines
        self._api_request_window: Deque[float] = deque()

    @property
    def config_manager(self):
        """Expose the config manager so external adapters (e.g. chat) can
        reuse our MCP config without reaching into private attributes."""
        return self._config_manager

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

    async def run_command(self, instance_id: str, command: str) -> str:
        """Run a command on a remote instance via SSH."""
        allowed, reason = self._guard.check_tool('run_command')
        if not allowed:
            self._audit.log('run_command', {'instance_id': instance_id, 'command': command}, '', False, reason)
            return f"Blocked: {reason}"

        cmd_allowed, cmd_reason = self._guard.check_command(command)
        if not cmd_allowed:
            self._audit.log('run_command', {'instance_id': instance_id, 'command': command}, '', False, cmd_reason)
            return f"Blocked: {cmd_reason}"

        instance = await self._find_instance(instance_id)
        if not instance:
            return f"Instance not found: {instance_id}"

        conn = self._resolve_connection(instance)

        ssh_cmd = self._ssh_service.build_ssh_command(
            host=conn['host'], username=conn['username'], key_path=conn['key_path'],
            proxy_args=conn['proxy_args'], remote_command=command,
            port=conn.get('port'),
            extra_options=conn.get('extra_options') or [],
        )

        try:
            stdout, stderr = await run_ssh_subprocess(ssh_cmd, timeout=60)
        except asyncio.TimeoutError:
            return "Error: Command timed out after 60 seconds"
        except Exception as e:
            return f"Error: {e}"

        output = stdout.decode('utf-8', errors='replace')
        lines = output.split('\n')
        if len(lines) > self._max_lines:
            output = '\n'.join(lines[:self._max_lines]) + f'\n... (truncated, {len(lines)} total lines)'

        if stderr:
            output += f"\nSTDERR:\n{stderr.decode('utf-8', errors='replace')}"

        self._audit.log('run_command', {'instance_id': instance_id, 'command': command}, output, True)
        return output

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

        conn = self._resolve_connection(instance)

        ssh_cmd = self._ssh_service.build_ssh_command(
            host=conn['host'], username=conn['username'], key_path=conn['key_path'],
            proxy_args=conn['proxy_args'], remote_command=command,
            port=conn.get('port'),
            extra_options=conn.get('extra_options') or [],
        )

        try:
            stdout, stderr = await run_ssh_subprocess(ssh_cmd, timeout=60)
        except asyncio.TimeoutError:
            return "Error: Command timed out after 60 seconds"
        except Exception as e:
            return f"Error: {e}"

        output = stdout.decode('utf-8', errors='replace')
        if stderr:
            output += f"\nSTDERR:\n{stderr.decode('utf-8', errors='replace')}"

        self._audit.log('get_server_info', {'instance_id': instance_id}, output, True)
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

        conn = self._resolve_connection(instance)
        host = conn['host']
        username = conn['username']
        key_path = conn['key_path']
        proxy_args = conn['proxy_args']
        profile = conn['profile']
        port = conn.get('port')
        extra_options = conn.get('extra_options') or []

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
        }, result, returncode == 0)
        return result

    async def ovh_monitoring(self, instance_id: str, period: str = "lastday") -> str:
        """Get CPU/RAM/network monitoring data for an OVH instance."""
        if self._ovh_monitoring_service is None:
            return "Error: OVH monitoring service is not available. Ensure OVH is configured and enabled."

        instance = await self._find_instance(instance_id)
        if not instance:
            return f"Instance not found: {instance_id}"

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
                    {"instance_id": iid, "modules": sanitized}, indent=2
                )
            elif format == "markdown":
                result = await self._memory_service.get_summary(meta, max_tokens=1_000_000)
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
                result = await self._memory_service.get_summary(meta, max_tokens=1500)
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
