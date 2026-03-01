"""Connection service for profile resolution and proxy configuration."""

from __future__ import annotations
import logging
import os
import shlex
from typing import Optional, Dict, List

from servonaut.services.interfaces import ConnectionServiceInterface
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import ConnectionProfile
from servonaut.utils.match_utils import matches_conditions

logger = logging.getLogger(__name__)


class ConnectionService(ConnectionServiceInterface):
    """Connection service for resolving connection profiles and bastion configuration.

    Implements match condition evaluation with AND logic for all conditions.
    """

    def __init__(self, config_manager: ConfigManager) -> None:
        """Initialize connection service.

        Args:
            config_manager: Configuration manager instance.
        """
        self._config_manager = config_manager

    def resolve_profile(self, instance: dict) -> Optional[ConnectionProfile]:
        """Find the first matching connection profile for an instance.

        Evaluates connection rules in order. Returns the first profile
        whose match conditions are satisfied.

        Args:
            instance: Instance dictionary.

        Returns:
            Matching ConnectionProfile, or None if no rules match (direct connection).
        """
        config = self._config_manager.get()
        for rule in config.connection_rules:
            if matches_conditions(instance, rule.match_conditions):
                # Find the profile by name
                for profile in config.connection_profiles:
                    if profile.name == rule.profile_name:
                        logger.info(
                            "Instance %s matched rule '%s', using profile '%s'",
                            instance.get('id'),
                            rule.name,
                            profile.name
                        )
                        return profile
                logger.warning(
                    "Connection rule '%s' references missing profile '%s'",
                    rule.name,
                    rule.profile_name
                )
        logger.debug(
            "No connection rules matched for instance %s, using direct connection",
            instance.get('id')
        )
        return None

    def get_proxy_jump_string(
        self,
        profile: ConnectionProfile,
        key_path: Optional[str] = None
    ) -> Optional[str]:
        """Build ProxyJump string from profile. Returns None if no bastion configured.

        Format: [user@]host[:port]
        If profile has proxy_command instead, return None (handled separately).

        Args:
            profile: Connection profile with bastion config.
            key_path: SSH key path for bastion (optional, not used in ProxyJump string).

        Returns:
            ProxyJump string (user@host or user@host:port), or None if no bastion.
        """
        if not profile.bastion_host:
            return None

        parts = []
        if profile.bastion_user:
            parts.append(f"{profile.bastion_user}@")
        parts.append(profile.bastion_host)
        if profile.ssh_port != 22:
            parts.append(f":{profile.ssh_port}")

        proxy_jump = ''.join(parts)
        logger.debug("Built ProxyJump string: %s", proxy_jump)
        return proxy_jump

    def get_proxy_args(self, profile: ConnectionProfile) -> List[str]:
        """Build SSH proxy arguments for bastion connection.

        Uses ProxyCommand when bastion_key is specified (ProxyJump doesn't
        support separate keys for the jump host). Falls back to ProxyJump
        when no bastion key is needed. Uses raw proxy_command if set.

        Args:
            profile: Connection profile with bastion config.

        Returns:
            List of SSH arguments for proxy, or empty list if no bastion.
        """
        if not profile:
            return []

        # Use explicit proxy_command if set
        if profile.proxy_command:
            logger.debug("Using explicit ProxyCommand: %s", profile.proxy_command)
            return ['-o', f'ProxyCommand={profile.proxy_command}']

        if not profile.bastion_host:
            return []

        # When bastion_key is specified, use ProxyCommand so we can pass -i
        if profile.bastion_key:
            bastion_user = profile.bastion_user or 'ec2-user'
            key_expanded = os.path.expanduser(profile.bastion_key)
            parts = [
                'ssh',
                '-i', shlex.quote(key_expanded),
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'IdentitiesOnly=yes',
            ]
            if profile.ssh_port != 22:
                parts.extend(['-p', str(profile.ssh_port)])
            parts.extend(['-W', '%h:%p', f'{bastion_user}@{profile.bastion_host}'])
            proxy_cmd = ' '.join(parts)
            logger.debug("Using ProxyCommand with bastion key: %s", proxy_cmd)
            return ['-o', f'ProxyCommand={proxy_cmd}']

        # No bastion key — use simpler ProxyJump
        jump = self.get_proxy_jump_string(profile)
        if jump:
            logger.debug("Using ProxyJump: %s", jump)
            return ['-J', jump]

        return []

    def get_target_host(
        self,
        instance: dict,
        profile: Optional[ConnectionProfile] = None
    ) -> str:
        """Get the target host for connection.

        If through bastion, use private IP. Direct connection uses public IP.

        Args:
            instance: Instance dictionary.
            profile: Connection profile (uses bastion_host to determine routing).

        Returns:
            IP address or hostname to connect to.
        """
        if profile and profile.bastion_host:
            # Connection through bastion — prefer private IP
            private_ip = instance.get('private_ip')
            public_ip = instance.get('public_ip')
            host = private_ip if private_ip else (public_ip or '')
            logger.debug(
                "Bastion connection: target=%s (private=%s, public=%s)",
                host, private_ip, public_ip
            )
        else:
            # Direct connection — prefer public IP, fall back to private
            public_ip = instance.get('public_ip')
            private_ip = instance.get('private_ip')
            host = public_ip if public_ip else (private_ip or '')
            logger.debug(
                "Direct connection: target=%s (public=%s, private=%s)",
                host, public_ip, private_ip
            )
        return host
