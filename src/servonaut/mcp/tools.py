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
                 ovh_billing_service=None, auth_service=None) -> None:
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
        self._auth_service = auth_service
        self._max_lines = config_manager.get().mcp.max_output_lines
        self._api_request_window: Deque[float] = deque()

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
        instances = aws_instances + custom_instances + ovh_instances
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
            ip = ip_info.get('ip', '')
            ip_type = ip_info.get('type', '')
            routed_to = ip_info.get('routedTo', {})
            routed_service = routed_to.get('serviceName', '') if isinstance(routed_to, dict) else str(routed_to)
            country = ip_info.get('country', '')
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
            snap_id = snap.get('id', snap.get('name', ''))
            snap_name = snap.get('name', snap.get('description', ''))
            created = snap.get('creationDate', snap.get('createdAt', ''))
            size = snap.get('size', '')
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
        """Find instance by ID or name across all providers (AWS + custom + OVH)."""
        aws_instances = await self._aws_service.fetch_instances_cached()
        custom_instances = self._custom_server_service.list_as_instances()
        ovh_instances = (
            await self._ovh_service.fetch_instances_cached()
            if self._ovh_service is not None
            else []
        )
        all_instances = aws_instances + custom_instances + ovh_instances
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
