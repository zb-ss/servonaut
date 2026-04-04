"""DNS zone and record management via OVHcloud API."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.services.ovh_service import OVHService

logger = logging.getLogger(__name__)

# Validation regexes — zone/domain names: labels of letters, digits, hyphens
# separated by dots; at minimum one dot required for real domains, but we allow
# single-label names too (e.g. "localhost") for flexibility.
_ZONE_NAME_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
_DOMAIN_RE = _ZONE_NAME_RE


class OVHDNSService:
    """DNS zone and record management via OVHcloud API."""

    def __init__(self, ovh_service: 'OVHService') -> None:
        """Initialize DNS service.

        Args:
            ovh_service: Shared OVHService instance providing the API client.
        """
        self._ovh_service = ovh_service

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_zone_name(zone_name: str) -> None:
        if not zone_name or not _ZONE_NAME_RE.match(zone_name):
            raise ValueError(f"Invalid zone_name: {zone_name!r}")

    @staticmethod
    def _validate_domain(domain: str) -> None:
        if not domain or not _DOMAIN_RE.match(domain):
            raise ValueError(f"Invalid domain: {domain!r}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def list_domains(self) -> List[str]:
        """Return the list of DNS zone names managed by the account.

        GET /domain/zone
        """
        client = self._ovh_service.client
        try:
            result = await asyncio.to_thread(client.get, "/domain/zone")
            return list(result) if result else []
        except Exception as exc:
            logger.error("list_domains failed: %s", exc)
            return []

    async def get_zone_info(self, zone_name: str) -> dict:
        """Return metadata for a DNS zone.

        GET /domain/zone/{zoneName}

        Args:
            zone_name: The zone to inspect (e.g. ``"example.com"``).

        Returns:
            Zone info dict or empty dict on error.
        """
        self._validate_zone_name(zone_name)
        client = self._ovh_service.client
        try:
            return await asyncio.to_thread(client.get, f"/domain/zone/{zone_name}")
        except Exception as exc:
            logger.error("get_zone_info(%r) failed: %s", zone_name, exc)
            return {}

    async def list_records(
        self,
        zone_name: str,
        field_type: str = "",
        sub_domain: str = "",
    ) -> List[dict]:
        """Return all DNS records for a zone, optionally filtered.

        Performs:
            GET /domain/zone/{zoneName}/record  (with optional fieldType / subDomain params)
        Then for each returned ID:
            GET /domain/zone/{zoneName}/record/{id}

        Args:
            zone_name:   The zone name.
            field_type:  Optional record type filter (``"A"``, ``"MX"``, …).
            sub_domain:  Optional sub-domain filter (``"www"``, ``"@"``, …).

        Returns:
            List of ``{id, fieldType, subDomain, target, ttl}`` dicts.
        """
        self._validate_zone_name(zone_name)
        client = self._ovh_service.client

        # Build query params
        params: dict = {}
        if field_type:
            params["fieldType"] = field_type
        if sub_domain:
            params["subDomain"] = sub_domain

        try:
            if params:
                record_ids = await asyncio.to_thread(
                    client.get, f"/domain/zone/{zone_name}/record", **params
                )
            else:
                record_ids = await asyncio.to_thread(
                    client.get, f"/domain/zone/{zone_name}/record"
                )
        except Exception as exc:
            logger.error("list_records(%r) failed: %s", zone_name, exc)
            return []

        if not record_ids:
            return []

        records: List[dict] = []
        for record_id in record_ids:
            try:
                detail = await asyncio.to_thread(
                    client.get, f"/domain/zone/{zone_name}/record/{record_id}"
                )
                records.append({
                    "id": detail.get("id", record_id),
                    "fieldType": detail.get("fieldType", ""),
                    "subDomain": detail.get("subDomain", ""),
                    "target": detail.get("target", ""),
                    "ttl": detail.get("ttl", 3600),
                })
            except Exception as exc:
                logger.error(
                    "list_records: failed to fetch record %s in zone %r: %s",
                    record_id, zone_name, exc,
                )

        return records

    async def create_record(
        self,
        zone_name: str,
        field_type: str,
        sub_domain: str,
        target: str,
        ttl: int = 3600,
    ) -> dict:
        """Create a new DNS record.

        POST /domain/zone/{zoneName}/record

        Args:
            zone_name:  Target zone.
            field_type: Record type (``"A"``, ``"AAAA"``, ``"CNAME"``, …).
            sub_domain: Subdomain label (``"www"``, ``"@"``, ``""``).
            target:     Record value (IP, hostname, …).
            ttl:        Time-to-live in seconds (default 3600).

        Returns:
            The created record dict from the API.
        """
        self._validate_zone_name(zone_name)
        if not field_type:
            raise ValueError("field_type must not be empty")
        if not target:
            raise ValueError("target must not be empty")

        client = self._ovh_service.client
        return await asyncio.to_thread(
            client.post,
            f"/domain/zone/{zone_name}/record",
            fieldType=field_type,
            subDomain=sub_domain,
            target=target,
            ttl=ttl,
        )

    async def update_record(
        self,
        zone_name: str,
        record_id: int,
        sub_domain: Optional[str] = None,
        target: Optional[str] = None,
        ttl: Optional[int] = None,
    ) -> bool:
        """Update an existing DNS record (only changed fields sent).

        PUT /domain/zone/{zoneName}/record/{recordId}

        Args:
            zone_name:  Zone containing the record.
            record_id:  Numeric record identifier.
            sub_domain: New subdomain value, or ``None`` to leave unchanged.
            target:     New record value, or ``None`` to leave unchanged.
            ttl:        New TTL, or ``None`` to leave unchanged.

        Returns:
            ``True`` on success.
        """
        self._validate_zone_name(zone_name)

        payload: dict = {}
        if sub_domain is not None:
            payload["subDomain"] = sub_domain
        if target is not None:
            payload["target"] = target
        if ttl is not None:
            payload["ttl"] = ttl

        client = self._ovh_service.client
        await asyncio.to_thread(
            client.put,
            f"/domain/zone/{zone_name}/record/{record_id}",
            **payload,
        )
        return True

    async def delete_record(self, zone_name: str, record_id: int) -> bool:
        """Delete a DNS record.

        DELETE /domain/zone/{zoneName}/record/{recordId}

        Args:
            zone_name: Zone containing the record.
            record_id: Numeric record identifier.

        Returns:
            ``True`` on success.
        """
        self._validate_zone_name(zone_name)
        client = self._ovh_service.client
        await asyncio.to_thread(
            client.delete, f"/domain/zone/{zone_name}/record/{record_id}"
        )
        return True

    async def refresh_zone(self, zone_name: str) -> bool:
        """Apply pending changes to a DNS zone.

        POST /domain/zone/{zoneName}/refresh

        Args:
            zone_name: Zone to refresh.

        Returns:
            ``True`` on success.
        """
        self._validate_zone_name(zone_name)
        client = self._ovh_service.client
        await asyncio.to_thread(client.post, f"/domain/zone/{zone_name}/refresh")
        return True

    async def get_domain_info(self, domain: str) -> dict:
        """Return domain-level metadata.

        GET /domain/{domain}

        Args:
            domain: Registered domain name.

        Returns:
            Domain info dict or empty dict on error.
        """
        self._validate_domain(domain)
        client = self._ovh_service.client
        try:
            return await asyncio.to_thread(client.get, f"/domain/{domain}")
        except Exception as exc:
            logger.error("get_domain_info(%r) failed: %s", domain, exc)
            return {}

    async def list_domain_tasks(self, domain: str) -> List[dict]:
        """Return pending tasks for a domain.

        GET /domain/{domain}/task

        Args:
            domain: Registered domain name.

        Returns:
            List of task dicts.
        """
        self._validate_domain(domain)
        client = self._ovh_service.client
        try:
            result = await asyncio.to_thread(client.get, f"/domain/{domain}/task")
            return list(result) if result else []
        except Exception as exc:
            logger.error("list_domain_tasks(%r) failed: %s", domain, exc)
            return []
