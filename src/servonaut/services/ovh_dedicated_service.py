"""Dedicated server lifecycle operations via OVHcloud API."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.services.ovh_service import OVHService

logger = logging.getLogger(__name__)

_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9._:/-]+$')


class OVHDedicatedService:
    """Dedicated server reinstall and installation status operations via OVHcloud API."""

    def __init__(self, ovh_service: 'OVHService') -> None:
        self._ovh_service = ovh_service

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def list_templates(self, server_name: str) -> List[dict]:
        """Return compatible OS templates for a dedicated server.

        Calls GET /dedicated/server/{sn}/install/compatibleTemplates and
        flattens the family-grouped response into a list of dicts with
        ``name`` and ``family`` keys.

        Args:
            server_name: Dedicated server hostname/identifier.

        Returns:
            List of dicts: ``[{"name": str, "family": str}, ...]``

        Raises:
            ValueError: If server_name contains invalid characters.
        """
        self._validate_name(server_name, "server_name")
        client = self._ovh_service.client
        raw = await asyncio.to_thread(
            client.get,
            f"/dedicated/server/{server_name}/install/compatibleTemplates",
        )
        templates: List[dict] = []
        if isinstance(raw, dict):
            for family, names in raw.items():
                if isinstance(names, list):
                    for name in names:
                        templates.append({"name": name, "family": family})
        logger.debug(
            "list_templates: server=%s returned %d templates",
            server_name, len(templates),
        )
        return templates

    async def get_template_details(self, template_name: str) -> dict:
        """Fetch details for an OS installation template.

        Calls GET /dedicated/installationTemplate/{templateName}.

        Args:
            template_name: OVH template identifier.

        Returns:
            Template detail dict as returned by the OVH API.

        Raises:
            ValueError: If template_name contains invalid characters.
        """
        self._validate_name(template_name, "template_name")
        client = self._ovh_service.client
        result = await asyncio.to_thread(
            client.get,
            f"/dedicated/installationTemplate/{template_name}",
        )
        logger.debug("get_template_details: template=%s", template_name)
        return result

    async def reinstall(
        self,
        server_name: str,
        template_name: str,
        customization: Optional[dict] = None,
    ) -> dict:
        """Start a dedicated server OS reinstallation.

        Calls POST /dedicated/server/{sn}/install/start with a body
        containing at minimum ``templateName``.  Optional ``customization``
        keys accepted by OVH: ``sshKeyName``, ``hostname``,
        ``partitionSchemeName``.

        Args:
            server_name: Dedicated server hostname/identifier.
            template_name: OVH template identifier to install.
            customization: Optional extra fields merged into the POST body.

        Returns:
            Task dict returned by the OVH API.

        Raises:
            ValueError: If server_name or template_name contain invalid
                characters.
        """
        self._validate_name(server_name, "server_name")
        self._validate_name(template_name, "template_name")
        client = self._ovh_service.client
        body: dict = {"templateName": template_name}
        if customization:
            body.update(customization)
        result = await asyncio.to_thread(
            client.post,
            f"/dedicated/server/{server_name}/install/start",
            **body,
        )
        logger.info(
            "reinstall: server=%s template=%s task=%s",
            server_name, template_name, result,
        )
        return result

    async def get_install_status(self, server_name: str) -> dict:
        """Return the current installation progress for a dedicated server.

        Calls GET /dedicated/server/{sn}/install/status.

        Args:
            server_name: Dedicated server hostname/identifier.

        Returns:
            Installation status dict as returned by the OVH API.

        Raises:
            ValueError: If server_name contains invalid characters.
        """
        self._validate_name(server_name, "server_name")
        client = self._ovh_service.client
        result = await asyncio.to_thread(
            client.get,
            f"/dedicated/server/{server_name}/install/status",
        )
        logger.debug("get_install_status: server=%s status=%s", server_name, result)
        return result

    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_name(value: str, param: str) -> None:
        """Raise ValueError if value contains disallowed characters.

        Args:
            value: Input string to validate.
            param: Parameter name used in the error message.

        Raises:
            ValueError: If value does not match ``^[a-zA-Z0-9._:/-]+$``.
        """
        if not _NAME_PATTERN.match(value):
            raise ValueError(
                f"Invalid {param} format: {value!r}. "
                "Only alphanumerics and ._:/- are allowed."
            )
