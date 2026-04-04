"""IP management, reverse DNS, and firewall via OVHcloud API."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import List, TYPE_CHECKING
from urllib.parse import quote

if TYPE_CHECKING:
    from servonaut.services.ovh_service import OVHService

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Input validation patterns
# ---------------------------------------------------------------------------

# Accepts IPv4, IPv6, and CIDR notations used in OVH API paths.
# Examples: "1.2.3.4", "1.2.3.4/32", "2001:db8::1", "2001:db8::/48"
_IP_RE = re.compile(r'^[a-fA-F0-9:./%]+$')

# Reverse DNS hostname: RFC-1123 hostnames (labels separated by dots, optional trailing dot)
_RDNS_RE = re.compile(r'^[a-zA-Z0-9._-]+$')

# OVH service name: alphanumeric with hyphens and dots (VPS names, dedicated server names, etc.)
_SERVICE_NAME_RE = re.compile(r'^[\w\-.]+$')


def _validate_ip(ip: str, param_name: str = "ip") -> None:
    """Raise ValueError if *ip* contains characters illegal in an API path segment."""
    if not ip or not _IP_RE.match(ip):
        raise ValueError(f"Invalid {param_name} format: {ip!r}")


def _enc(ip: str) -> str:
    """URL-encode an IP/CIDR block for use in OVH API paths.

    OVH returns IP blocks like '51.195.150.236/32' from GET /ip.
    The '/' must be percent-encoded when used in path segments.
    """
    return quote(ip, safe='')


def _validate_service(name: str, param_name: str = "target_service") -> None:
    """Raise ValueError if *name* contains characters illegal in an API path segment."""
    if not name or not _SERVICE_NAME_RE.match(name):
        raise ValueError(f"Invalid {param_name} format: {name!r}")


def _validate_rdns(reverse: str) -> None:
    """Raise ValueError if *reverse* is not a valid hostname string."""
    if not reverse or not _RDNS_RE.match(reverse):
        raise ValueError(f"Invalid reverse DNS hostname: {reverse!r}")


class OVHIPService:
    """IP management, reverse DNS, and firewall operations via OVHcloud API."""

    def __init__(self, ovh_service: "OVHService") -> None:
        """Initialize the IP service.

        Args:
            ovh_service: Shared OVHService instance providing the API client.
        """
        self._ovh_service = ovh_service

    # ------------------------------------------------------------------
    # IP Management
    # ------------------------------------------------------------------

    async def list_ips(self) -> List[dict]:
        """List all IPs on the account with their details.

        Calls GET /ip to obtain IP blocks, then GET /ip/{ip} for each.

        Returns:
            List of IP detail dicts.  Empty list on error.
        """
        client = self._ovh_service.client
        try:
            ip_blocks: List[str] = await asyncio.to_thread(client.get, "/ip")
        except Exception as exc:
            logger.error("Error listing OVH IPs: %s", exc)
            return []

        if not ip_blocks:
            return []

        results: List[dict] = []
        for block in ip_blocks:
            try:
                encoded = quote(block, safe='')
                detail = await asyncio.to_thread(client.get, f"/ip/{encoded}")
                if isinstance(detail, dict):
                    results.append(detail)
                else:
                    # Fallback: wrap the raw value so callers always get dicts.
                    results.append({"ip": block, "raw": detail})
            except Exception as exc:
                logger.error("Error fetching OVH IP details for %s: %s", block, exc)

        return results

    async def list_failover_ips(self) -> List[dict]:
        """Return only failover IPs from the full IP list.

        Returns:
            Filtered list of IP detail dicts whose ``type`` is ``"failover"``.
        """
        all_ips = await self.list_ips()
        return [ip for ip in all_ips if ip.get("type") == "failover"]

    async def move_failover_ip(self, ip: str, target_service: str) -> bool:
        """Move a failover IP to another service.

        POST /ip/{ip}/move with body ``{to: target_service}``.

        Args:
            ip: IP block to move (e.g. ``"1.2.3.4/32"``).
            target_service: Destination service name.

        Returns:
            True on success.

        Raises:
            ValueError: If *ip* or *target_service* contain invalid characters.
        """
        _validate_ip(ip)
        _validate_service(target_service)

        client = self._ovh_service.client
        await asyncio.to_thread(client.post, f"/ip/{_enc(ip)}/move", to=target_service)
        return True

    async def get_ip_details(self, ip: str) -> dict:
        """Fetch details for a single IP block.

        GET /ip/{ip}

        Args:
            ip: IP block identifier (e.g. ``"1.2.3.4/32"``).

        Returns:
            IP detail dict, or empty dict on error.

        Raises:
            ValueError: If *ip* contains invalid characters.
        """
        _validate_ip(ip)

        client = self._ovh_service.client
        try:
            result = await asyncio.to_thread(client.get, f"/ip/{_enc(ip)}")
            return result if isinstance(result, dict) else {}
        except Exception as exc:
            logger.error("Error fetching OVH IP details for %s: %s", ip, exc)
            return {}

    # ------------------------------------------------------------------
    # Reverse DNS
    # ------------------------------------------------------------------

    async def get_reverse_dns(self, ip_block: str, ip: str) -> dict:
        """Fetch the reverse DNS record for an IP within a block.

        GET /ip/{ip_block}/reverse/{ip}

        Args:
            ip_block: IP block (e.g. ``"1.2.3.0/24"``).
            ip: Specific IP address (e.g. ``"1.2.3.4"``).

        Returns:
            Reverse DNS record dict, or empty dict on error.

        Raises:
            ValueError: If either argument contains invalid characters.
        """
        _validate_ip(ip_block, "ip_block")
        _validate_ip(ip)

        client = self._ovh_service.client
        try:
            result = await asyncio.to_thread(
                client.get, f"/ip/{_enc(ip_block)}/reverse/{_enc(ip)}"
            )
            return result if isinstance(result, dict) else {}
        except Exception as exc:
            logger.error(
                "Error fetching reverse DNS for %s in %s: %s", ip, ip_block, exc
            )
            return {}

    async def set_reverse_dns(self, ip_block: str, ip: str, reverse: str) -> bool:
        """Create or update the reverse DNS entry for an IP.

        POST /ip/{ip_block}/reverse with body ``{ipReverse: ip, reverse: reverse}``.

        Args:
            ip_block: IP block that owns the IP.
            ip: Specific IP address to configure.
            reverse: Target hostname (e.g. ``"server.example.com"``).

        Returns:
            True on success.

        Raises:
            ValueError: If any argument contains invalid characters.
        """
        _validate_ip(ip_block, "ip_block")
        _validate_ip(ip)
        _validate_rdns(reverse)

        client = self._ovh_service.client
        await asyncio.to_thread(
            client.post,
            f"/ip/{_enc(ip_block)}/reverse",
            ipReverse=ip,
            reverse=reverse,
        )
        return True

    async def delete_reverse_dns(self, ip_block: str, ip: str) -> bool:
        """Remove the reverse DNS entry for an IP.

        DELETE /ip/{ip_block}/reverse/{ip}

        Args:
            ip_block: IP block that owns the IP.
            ip: Specific IP address.

        Returns:
            True on success.

        Raises:
            ValueError: If either argument contains invalid characters.
        """
        _validate_ip(ip_block, "ip_block")
        _validate_ip(ip)

        client = self._ovh_service.client
        await asyncio.to_thread(client.delete, f"/ip/{_enc(ip_block)}/reverse/{_enc(ip)}")
        return True

    # ------------------------------------------------------------------
    # Firewall
    # ------------------------------------------------------------------

    async def get_firewall(self, ip: str) -> dict:
        """Fetch the firewall state for an IP.

        GET /ip/{ip}/firewall/{ip}

        Args:
            ip: IP address (e.g. ``"1.2.3.4"``).

        Returns:
            Firewall state dict (``{enabled, ipOnFirewall, state}``),
            or empty dict on error.

        Raises:
            ValueError: If *ip* contains invalid characters.
        """
        _validate_ip(ip)

        client = self._ovh_service.client
        try:
            result = await asyncio.to_thread(
                client.get, f"/ip/{_enc(ip)}/firewall/{_enc(ip)}"
            )
            return result if isinstance(result, dict) else {}
        except Exception as exc:
            logger.error("Error fetching OVH firewall state for %s: %s", ip, exc)
            return {}

    async def toggle_firewall(self, ip: str, enabled: bool) -> bool:
        """Enable or disable the firewall for an IP.

        PUT /ip/{ip}/firewall/{ip} with body ``{enabled: <bool>}``.

        Args:
            ip: IP address.
            enabled: Target state.

        Returns:
            True on success.

        Raises:
            ValueError: If *ip* contains invalid characters.
        """
        _validate_ip(ip)

        client = self._ovh_service.client
        await asyncio.to_thread(
            client.put, f"/ip/{_enc(ip)}/firewall/{_enc(ip)}", enabled=enabled
        )
        return True

    async def list_firewall_rules(self, ip: str) -> List[dict]:
        """List all firewall rules for an IP.

        GET /ip/{ip}/firewall/{ip}/rule returns sequence numbers, then
        GET /ip/{ip}/firewall/{ip}/rule/{sequence} for each.

        Args:
            ip: IP address.

        Returns:
            List of rule dicts ordered by sequence.  Empty list on error.

        Raises:
            ValueError: If *ip* contains invalid characters.
        """
        _validate_ip(ip)

        client = self._ovh_service.client
        try:
            sequences: List[int] = await asyncio.to_thread(
                client.get, f"/ip/{_enc(ip)}/firewall/{_enc(ip)}/rule"
            )
        except Exception as exc:
            logger.error("Error listing OVH firewall rules for %s: %s", ip, exc)
            return []

        if not sequences:
            return []

        rules: List[dict] = []
        for seq in sequences:
            try:
                rule = await asyncio.to_thread(
                    client.get, f"/ip/{_enc(ip)}/firewall/{_enc(ip)}/rule/{seq}"
                )
                if isinstance(rule, dict):
                    rules.append(rule)
            except Exception as exc:
                logger.error(
                    "Error fetching OVH firewall rule %s for %s: %s", seq, ip, exc
                )

        return rules

    async def add_firewall_rule(self, ip: str, rule: dict) -> dict:
        """Add a firewall rule for an IP.

        POST /ip/{ip}/firewall/{ip}/rule

        Expected keys in *rule*: ``action``, ``protocol``, ``port``,
        ``source``, ``sequence``.

        Args:
            ip: IP address.
            rule: Rule parameters dict.

        Returns:
            Created rule dict returned by the API.

        Raises:
            ValueError: If *ip* contains invalid characters, or if *rule* is
                missing required keys.
        """
        _validate_ip(ip)
        if not isinstance(rule, dict):
            raise ValueError("rule must be a dict")

        required = {"action", "protocol", "sequence"}
        missing = required - rule.keys()
        if missing:
            raise ValueError(f"rule is missing required keys: {missing!r}")

        client = self._ovh_service.client
        result = await asyncio.to_thread(
            client.post,
            f"/ip/{_enc(ip)}/firewall/{_enc(ip)}/rule",
            **rule,
        )
        return result if isinstance(result, dict) else {}

    async def delete_firewall_rule(self, ip: str, sequence: int) -> bool:
        """Delete a firewall rule by sequence number.

        DELETE /ip/{ip}/firewall/{ip}/rule/{sequence}

        Args:
            ip: IP address.
            sequence: Rule sequence number (0–19).

        Returns:
            True on success.

        Raises:
            ValueError: If *ip* contains invalid characters or *sequence* is
                out of range.
        """
        _validate_ip(ip)
        if not isinstance(sequence, int) or sequence < 0:
            raise ValueError(f"Invalid sequence number: {sequence!r}")

        client = self._ovh_service.client
        await asyncio.to_thread(
            client.delete, f"/ip/{_enc(ip)}/firewall/{_enc(ip)}/rule/{sequence}"
        )
        return True
