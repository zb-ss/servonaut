"""Custom server service for managing non-AWS servers."""

from __future__ import annotations

import logging
from typing import List, Optional

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import CustomServer
from servonaut.services.interfaces import CustomServerServiceInterface

logger = logging.getLogger(__name__)


class CustomServerService(CustomServerServiceInterface):
    """CRUD service for custom (non-AWS) server entries stored in config."""

    def __init__(self, config_manager: ConfigManager) -> None:
        """Initialize the custom server service.

        Args:
            config_manager: Configuration manager instance.
        """
        self._config_manager = config_manager

    def add_server(self, server: CustomServer) -> None:
        """Add a custom server to config and persist.

        Args:
            server: CustomServer instance to add.

        Raises:
            ValueError: If a server with the same name already exists.
        """
        config = self._config_manager.get()
        if any(s.name == server.name for s in config.custom_servers):
            raise ValueError(f"Custom server '{server.name}' already exists")
        config.custom_servers.append(server)
        self._config_manager.save(config)
        logger.info("Added custom server: %s (%s)", server.name, server.host)

    def remove_server(self, name: str) -> bool:
        """Remove a custom server by name and persist.

        Args:
            name: Server name to remove.

        Returns:
            True if found and removed, False otherwise.
        """
        config = self._config_manager.get()
        original_count = len(config.custom_servers)
        config.custom_servers = [s for s in config.custom_servers if s.name != name]
        if len(config.custom_servers) == original_count:
            return False
        self._config_manager.save(config)
        logger.info("Removed custom server: %s", name)
        return True

    def update_server(self, name: str, server: CustomServer) -> bool:
        """Replace a custom server entry by name and persist.

        Args:
            name: Existing server name to replace.
            server: New CustomServer data.

        Returns:
            True if found and updated, False otherwise.
        """
        config = self._config_manager.get()
        for idx, existing in enumerate(config.custom_servers):
            if existing.name == name:
                config.custom_servers[idx] = server
                self._config_manager.save(config)
                logger.info("Updated custom server: %s", name)
                return True
        return False

    def list_servers(self) -> List[CustomServer]:
        """Return all custom servers from config.

        Returns:
            List of CustomServer instances.
        """
        return self._config_manager.get().custom_servers

    def get_server(self, name: str) -> Optional[CustomServer]:
        """Get a custom server by name.

        Args:
            name: Server name to look up.

        Returns:
            CustomServer if found, None otherwise.
        """
        for server in self._config_manager.get().custom_servers:
            if server.name == name:
                return server
        return None

    def to_instance_dict(self, server: CustomServer) -> dict:
        """Convert a CustomServer to instance dict format.

        Args:
            server: CustomServer to convert.

        Returns:
            Instance dictionary compatible with app.instances format.
        """
        return {
            'id': f'custom-{server.name}',
            'name': server.name,
            'type': 'custom',
            'state': 'unknown',
            'public_ip': server.host,
            'private_ip': server.host,
            'region': server.provider or 'custom',
            'key_name': server.ssh_key,
            'ssh_key': server.ssh_key,
            'provider': server.provider or 'custom',
            'group': server.group,
            'tags': server.tags,
            'port': server.port,
            'username': server.username,
            'is_custom': True,
        }

    def list_as_instances(self) -> List[dict]:
        """Return all custom servers as instance dicts.

        Returns:
            List of instance dictionaries.
        """
        return [self.to_instance_dict(s) for s in self.list_servers()]
