"""Connection service for profile resolution and proxy configuration."""

from __future__ import annotations
import logging
import os
import shlex
from typing import Optional, List

from servonaut.services.interfaces import ConnectionServiceInterface, SSHConnectionOptions
from servonaut.services.ssh_host_keys import (
    OFF_OPTIONS_KEEP_KNOWN_HOSTS,
    HostKeyPolicy,
    host_key_alias_options,
    identity_file_args,
    proxy_command_word,
)
from servonaut.utils.ssh_utils import SSH_LOG_ENV
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import ConnectionProfile, SSHConfig
from servonaut.utils.match_utils import matches_conditions
from servonaut.utils.platform_utils import get_os

logger = logging.getLogger(__name__)


def _int_setting(value: object, default: int) -> int:
    """Return *value* as an int, or *default* when it is not a number."""
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


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

    def resolve_ovh_connection(
        self, instance: dict, fallback_key: Optional[str] = None,
    ) -> SSHConnectionOptions:
        """Use the same OVH defaults for interactive SSH and background reads."""
        from servonaut.services.ovh_service import OVHService

        config = self._config_manager.get()
        return {
            "host": instance.get("public_ip") or instance.get("private_ip") or "",
            "username": config.ovh.default_username or OVHService.default_username(
                instance.get("provider_type", "vps"),
            ),
            "key_path": (
                config.instance_keys.get(instance.get("id", ""))
                or config.ovh.default_ssh_key or config.default_key or fallback_key
            ),
            "proxy_args": [],
            "port": None,
            "extra_options": self.get_extra_options(instance, None),
        }

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

        The bastion hop is a second ssh process. OpenSSH applies
        command-line ``-o`` options only to the final host, never to a
        ``-J`` jump host, so while host keys are verified the hop is spelled
        out as a ProxyCommand carrying the same host-key options as the
        target. ``-J`` remains for ``ssh.host_key_checking = "off"`` (the
        previous argv) and on Windows, where OpenSSH does not run a
        ProxyCommand through a POSIX shell; there the jump host follows the
        user's own ssh configuration. A ``bastion_key`` always uses the
        ProxyCommand form, the only way to give the hop its own ``-i``. A
        raw ``proxy_command`` is used verbatim.

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

        ssh_cfg = self._ssh_config()
        policy = HostKeyPolicy.from_ssh_config(ssh_cfg)
        if profile.bastion_key or self._hop_uses_proxy_command(policy):
            proxy_cmd = self._bastion_proxy_command(profile, ssh_cfg, policy)
            logger.debug("Using ProxyCommand for the bastion hop: %s", proxy_cmd)
            return ['-o', f'ProxyCommand={proxy_cmd}']

        jump = self.get_proxy_jump_string(profile)
        if jump:
            logger.debug("Using ProxyJump: %s", jump)
            return ['-J', jump]

        return []

    def _ssh_config(self) -> SSHConfig:
        """Return ``config.ssh``, or the defaults when config is unavailable."""
        try:
            return self._config_manager.get().ssh
        except Exception:
            return SSHConfig()

    def host_key_policy(self) -> HostKeyPolicy:
        """The host-key policy every command for this configuration uses."""
        return HostKeyPolicy.from_ssh_config(self._ssh_config())

    @staticmethod
    def _hop_uses_proxy_command(policy: HostKeyPolicy) -> bool:
        """True when a key-less bastion hop must carry the host-key options."""
        return policy.verifies_host_keys and get_os() != 'windows'

    @staticmethod
    def _bastion_proxy_command(
        profile: ConnectionProfile,
        ssh_cfg: SSHConfig,
        policy: HostKeyPolicy,
    ) -> str:
        """Return the ProxyCommand that reaches the target via the bastion.

        The outer ssh percent-expands the string and runs it through
        ``sh -c``, so every inserted value is escaped for both; numbers are
        coerced to integers so a config value cannot add shell text. In
        ``off`` mode the hop keeps its previous host-key options:
        ``StrictHostKeyChecking=no`` without ``/dev/null``.
        """
        defaults = SSHConfig()
        # When the calling process names a private log (see
        # ssh_utils.SshLog), the hop writes its own messages there too;
        # unset (interactive sessions), the hop reports on stderr as before.
        parts = ['ssh', f'${{{SSH_LOG_ENV}:+-E "${SSH_LOG_ENV}"}}']
        if profile.bastion_key:
            key_expanded = os.path.expanduser(profile.bastion_key)
            # Escaped for both expansions (this ProxyCommand, then the hop).
            parts.extend(
                shlex.quote(arg)
                for arg in identity_file_args(key_expanded, expansions=2)
            )
        parts.extend(
            shlex.quote(arg)
            for arg in policy.ssh_options(
                off_options=OFF_OPTIONS_KEEP_KNOWN_HOSTS, expansions=2,
            )
        )
        if profile.bastion_key:
            parts.extend(['-o', 'IdentitiesOnly=yes'])
        # Add keepalive options on the bastion hop so long operations
        # don't get reaped by the gateway firewall before the inner
        # connection completes.
        _tcp_ka = 'yes' if ssh_cfg.tcp_keepalive else 'no'
        interval = _int_setting(ssh_cfg.server_alive_interval, defaults.server_alive_interval)
        count_max = _int_setting(ssh_cfg.server_alive_count_max, defaults.server_alive_count_max)
        timeout = _int_setting(ssh_cfg.connect_timeout, defaults.connect_timeout)
        parts.extend([
            '-o', f'ServerAliveInterval={interval}',
            '-o', f'ServerAliveCountMax={count_max}',
            '-o', f'TCPKeepAlive={_tcp_ka}',
            '-o', f'ConnectTimeout={timeout}',
        ])
        port = _int_setting(profile.ssh_port, 22)
        if port != 22:
            parts.extend(['-p', str(port)])
        # A keyed hop has always defaulted to ec2-user; a key-less hop keeps
        # what -J did and lets ssh choose the user when none is configured.
        bastion_user = profile.bastion_user or ('ec2-user' if profile.bastion_key else '')
        destination = (
            f'{bastion_user}@{profile.bastion_host}' if bastion_user
            else profile.bastion_host
        )
        # "[%h]:%p", quoted for the shell as OpenSSH's own -J does, so an
        # IPv6 target is forwarded correctly. "--" ends option parsing, so
        # the destination cannot be read as an ssh option.
        parts.extend(['-W', "'[%h]:%p'", '--', proxy_command_word(destination)])
        return ' '.join(parts)

    def get_extra_options(
        self,
        instance: dict,
        profile: Optional[ConnectionProfile] = None,
    ) -> List[str]:
        """Merge extra SSH ``-o KEY=VALUE`` entries from profile and custom server.

        A cloud instance's ``HostKeyAlias`` comes first (see
        ``ssh_host_keys.host_key_alias``), then profile options, so
        custom-server overrides can refine them (OpenSSH uses the first
        matching value).

        Args:
            instance: Instance dictionary (may include ``extra_ssh_options``
                for custom servers).
            profile: Resolved connection profile, or None for direct connections.

        Returns:
            Flat list of ``KEY=VALUE`` strings (without the leading ``-o``).
        """
        # The host-key alias comes first so no per-host entry can replace it.
        extras: List[str] = host_key_alias_options(instance, self.host_key_policy())
        if profile and profile.extra_ssh_options:
            extras.extend(profile.extra_ssh_options)
        instance_extras = instance.get('extra_ssh_options') or []
        if instance_extras:
            extras.extend(instance_extras)
        return extras

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

    def get_target_port(self, instance: dict) -> Optional[int]:
        """Get the SSH port for the target host.

        Custom servers carry their own ``port``; every other provider listens
        on the SSH default. A bastion's port is not returned here: it lives on
        the connection profile and :meth:`get_proxy_args` emits it.

        Args:
            instance: Instance dictionary.

        Returns:
            The custom server's port, or None for the SSH default. Callers pass
            it straight to ``build_ssh_command`` / ``build_*_command``, which
            omit the flag for None and 22.
        """
        if not instance.get('is_custom'):
            return None
        return instance.get('port') or None
