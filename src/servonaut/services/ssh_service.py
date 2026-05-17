"""SSH service for key management and SSH command building."""

from __future__ import annotations
import os
import re
import subprocess
import logging
from pathlib import Path
from typing import List, Optional

from servonaut.services.interfaces import SSHServiceInterface, SecretProviderInterface
from servonaut.config.manager import ConfigManager

logger = logging.getLogger(__name__)


# Provider-supplied private keys land here. Kept under ``~/.servonaut/``
# so the dotfile-permissions story is uniform (everything secret lives
# in one tree the user already protects). Mode 0700 on the directory +
# 0600 on every key file inside — matches the convention OpenSSH itself
# enforces for ``~/.ssh``.
PROVIDER_KEYS_DIR = Path.home() / '.servonaut' / 'keys'

# Cheap structural check for a private-key blob. Reject anything that
# doesn't look like a PEM- or OpenSSH-encoded PRIVATE key — public keys
# (``ssh-rsa AAAA...``) are useless for outbound connections and a
# provider returning one would just confuse the discovery cascade.
# Lower-cased compare to be lenient about case variants nobody really
# uses but theoretically exist.
_PRIVATE_KEY_PEM_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE,
)

# Filename sanitiser for provider-supplied key names. We only allow
# alphanumerics, dash, and underscore — same shape as the team-slug
# regex used for URL paths elsewhere. Anything else gets folded to
# underscore so a key name like ``aws/prod-server`` doesn't escape
# :data:`PROVIDER_KEYS_DIR`.
_KEY_FILENAME_SAFE_RE = re.compile(r"[^a-zA-Z0-9._-]+")


class SSHService(SSHServiceInterface):
    """SSH service implementing key management and command building.

    Migrated from legacy KeyManager class with enhanced functionality.
    Always uses IdentitiesOnly=yes with -i flag to prevent
    'Too many authentication failures' errors.
    """

    def __init__(
        self,
        config_manager: ConfigManager,
        secret_provider: Optional[SecretProviderInterface] = None,
    ) -> None:
        """Initialize SSH service.

        Args:
            config_manager: Configuration manager instance.
            secret_provider: Optional :class:`SecretProviderInterface`
                consulted FIRST by :meth:`discover_key_async` for
                named-key lookups. When ``None`` (the default and the
                state on a fresh install) the service behaves exactly
                as before — pure ``~/.ssh`` discovery — so existing
                consumers don't have to thread anything through.

                The provider is set in :class:`ServonautApp._init_services`
                (Step 6) once the team's effective :class:`SecretsConfig`
                has been resolved from cache or the API.

                Backward-compatibility contract: a ``None`` provider here
                must produce IDENTICAL output to the original
                ``SSHService(config_manager)`` call. Pinned by the
                existing test_ssh_service tests that pass no provider
                AND by the new test_ssh_service_secret_provider tests
                that pin "without provider, behaviour is unchanged".
        """
        self._config_manager = config_manager
        self._ssh_dir = Path.home() / '.ssh'
        self._secret_provider = secret_provider

    @property
    def secret_provider(self) -> Optional[SecretProviderInterface]:
        """Read-only view of the currently-bound :class:`SecretProvider`.

        Exposed so the status surface (settings screen, ``servonaut
        secrets status`` command) can report which backend is active
        without reaching for a private attribute.
        """
        return self._secret_provider

    def set_secret_provider(
        self, provider: Optional[SecretProviderInterface],
    ) -> None:
        """Rebind the active :class:`SecretProvider`.

        Called from :meth:`ServonautApp.init_paid_services` after
        auth + entitlements are wired (Step 6) and again whenever
        the team's :class:`SecretsConfig` cache changes (refresh
        worker, settings save). ``None`` disables provider lookup —
        :meth:`discover_key_async` falls back to legacy ``~/.ssh``
        discovery, identical to a fresh-install / Free-tier session.

        The setter is intentionally synchronous and idempotent: it
        only swaps the reference. No tear-down on the previous
        provider is needed because providers are stateless across
        operations (Bitwarden's bws subprocess is per-call, the
        local file-store reopens the file per-call).
        """
        self._secret_provider = provider

    def get_key_path(self, instance_id: str) -> Optional[str]:
        """Get SSH key path for an instance. Falls back to default key.

        Args:
            instance_id: EC2 instance ID.

        Returns:
            Path to SSH key file, or None if not configured.
        """
        config = self._config_manager.get()
        return config.instance_keys.get(instance_id, config.default_key or None)

    def set_key_path(self, instance_id: str, key_path: str) -> None:
        """Set SSH key path for a specific instance and save.

        Args:
            instance_id: EC2 instance ID.
            key_path: Path to SSH key file.
        """
        config = self._config_manager.get()
        config.instance_keys[instance_id] = key_path
        self._config_manager.save(config)

    def set_default_key(self, key_path: str) -> None:
        """Set default SSH key and save.

        Args:
            key_path: Path to SSH key file.
        """
        self._config_manager.update(default_key=key_path)

    def discover_key(self, key_name: str) -> Optional[str]:
        """Auto-discover SSH key in ~/.ssh/ based on AWS key name.

        Searches in order:
        1. Exact match patterns (key_name, key_name.pem, id_rsa_*, etc.)
        2. Fuzzy match (case-insensitive substring in filename)

        Args:
            key_name: AWS key pair name.

        Returns:
            Path to discovered key, or None if not found.
        """
        if not key_name:
            return None

        # Ensure .ssh directory exists
        if not self._ssh_dir.exists():
            logger.debug("SSH directory does not exist: %s", self._ssh_dir)
            return None

        # Common key file patterns to search for
        patterns = [
            f"{key_name}",
            f"{key_name}.pem",
            f"id_rsa_{key_name}",
            f"{key_name}_id_rsa",
            f"aws_{key_name}",
            f"{key_name}_aws",
        ]

        # Search for matching keys
        for pattern in patterns:
            # Check for exact match
            key_path = self._ssh_dir / pattern
            if key_path.exists():
                logger.info("Discovered SSH key: %s", key_path)
                return str(key_path)

            # Check for .pem extension
            key_path_pem = self._ssh_dir / f"{pattern}.pem"
            if key_path_pem.exists():
                logger.info("Discovered SSH key: %s", key_path_pem)
                return str(key_path_pem)

        # If no exact match, try fuzzy search
        all_keys = self.list_available_keys()
        for key_path in all_keys:
            key_filename = Path(key_path).stem.lower()
            if key_name.lower() in key_filename:
                logger.info("Fuzzy match discovered SSH key: %s", key_path)
                return key_path

        logger.debug("No matching SSH key found for: %s", key_name)
        return None

    async def discover_key_async(self, key_name: str) -> Optional[str]:
        """Async-aware variant of :meth:`discover_key` that checks the
        active :class:`SecretProviderInterface` first.

        Resolution cascade:

        1. **SecretProvider lookup**: if a provider is injected AND
           :meth:`SecretProviderInterface.get_secret` returns a value
           that PARSES as a PEM/OpenSSH private key, write it to
           ``~/.servonaut/keys/<sanitised-name>`` at mode 0600 and
           return the absolute path.
        2. **Fallback**: delegate to the existing :meth:`discover_key`
           — pattern-match then fuzzy-match against ``~/.ssh``.

        Failure modes (silently degrade to step 2, log at WARNING):

        - No provider injected.
        - Provider returns ``None`` (key not present in backend).
        - Provider returns a value that doesn't look like a private
          key (public key, random string, empty after strip).
        - Provider raises any exception (network glitch, BWS hiccup,
          missing token). We swallow the exception so a transient
          provider failure doesn't break SSH for keys the user
          already has locally.

        Sync callers stay with :meth:`discover_key`. New async-aware
        flows (chat panel, MCP tool dispatch, future provider-first
        SCP transfers) call this method.
        """
        if not key_name:
            return None
        provider = self._secret_provider
        if provider is not None:
            try:
                material = await provider.get_secret(key_name)
            except Exception as exc:  # noqa: BLE001 — graceful degrade
                logger.warning(
                    "SecretProvider %s lookup failed for %r (%s); "
                    "falling back to ~/.ssh discovery",
                    getattr(provider, "provider_name", "?"),
                    key_name, exc,
                )
                material = None
            if isinstance(material, str) and material:
                if self._looks_like_private_key(material):
                    try:
                        return self._write_provider_key(key_name, material)
                    except (OSError, ValueError) as exc:
                        logger.warning(
                            "Could not persist provider-supplied key for "
                            "%r (%s); falling back to ~/.ssh discovery",
                            key_name, exc,
                        )
                else:
                    logger.warning(
                        "SecretProvider %s returned a value for %r that "
                        "does not look like a private key (no "
                        "'BEGIN ... PRIVATE KEY' marker); falling back "
                        "to ~/.ssh discovery",
                        getattr(provider, "provider_name", "?"), key_name,
                    )
        # Fallback path.
        return self.discover_key(key_name)

    @staticmethod
    def _looks_like_private_key(material: str) -> bool:
        """Cheap structural check for a private-key blob.

        Accepts PEM- and OpenSSH-encoded PRIVATE keys (any of RSA, EC,
        DSA, PKCS#8, OpenSSH). Rejects public keys (``ssh-rsa ...``),
        empty strings, random text, and anything missing the
        ``BEGIN ... PRIVATE KEY`` marker.

        Not a cryptographic validity check — that would require
        parsing the body. We trust the OpenSSH client to fail loud
        on a malformed key, and our role is just to filter out
        obviously-wrong inputs before they hit disk.
        """
        if not material:
            return False
        return bool(_PRIVATE_KEY_PEM_RE.search(material))

    @staticmethod
    def _sanitise_key_filename(key_name: str) -> str:
        """Reduce ``key_name`` to a safe filename.

        Replaces every character outside ``[a-zA-Z0-9._-]`` with an
        underscore so a malicious key name like ``../id_rsa`` can't
        escape :data:`PROVIDER_KEYS_DIR`. Truncates at 255 chars to
        stay within typical filesystem limits.

        Raises:
            ValueError: if the input is empty or sanitisation leaves
                an empty string (e.g. all-slashes input).
        """
        if not key_name:
            raise ValueError("key_name must be non-empty")
        sanitised = _KEY_FILENAME_SAFE_RE.sub("_", key_name)
        # Reject leading dots and dashes — both are nuisance values
        # (hidden file, can confuse argv parsing) and a sanitised
        # ``.``-only or ``-``-only input is meaningless.
        sanitised = sanitised.lstrip(".-")
        if not sanitised:
            raise ValueError(
                f"key_name {key_name!r} produced no safe filename chars"
            )
        if len(sanitised) > 255:
            sanitised = sanitised[:255]
        return sanitised

    def _write_provider_key(self, key_name: str, material: str) -> str:
        """Persist provider-supplied key material to
        :data:`PROVIDER_KEYS_DIR` and return the absolute path.

        Same atomic-write pattern as :meth:`AuthService._save_token`
        and :meth:`LocalProvider._save`: open the tmp file with
        explicit 0600 mode + O_CREAT|O_TRUNC, write + fsync + chmod
        + ``os.replace``. No window where a world-readable copy of
        the private key exists on disk.

        Directory perms are tightened on every call (mode 0700) so a
        user who created the dir manually with looser perms gets it
        fixed silently — matches :meth:`AuthService._ensure_secure_mode`.
        """
        safe_name = self._sanitise_key_filename(key_name)
        # ``mkdir(parents=True, exist_ok=True)`` may inherit umask
        # bits; tighten explicitly afterward.
        PROVIDER_KEYS_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(PROVIDER_KEYS_DIR, 0o700)
        except OSError as exc:
            logger.warning(
                "Could not chmod %s to 0700: %s", PROVIDER_KEYS_DIR, exc,
            )
        target = PROVIDER_KEYS_DIR / safe_name
        tmp = target.with_suffix(target.suffix + ".tmp")
        fd = os.open(
            tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600,
        )
        try:
            with os.fdopen(fd, "w") as f:
                f.write(material)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise
        # Belt-and-braces against umask masking bits off the open mode.
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
        logger.info(
            "Wrote provider-supplied SSH key to %s (mode 0600)", target,
        )
        return str(target)

    def list_available_keys(self) -> List[str]:
        """List SSH keys in ~/.ssh/ directory.

        Returns:
            List of absolute paths to SSH key files.
        """
        if not self._ssh_dir.exists():
            logger.debug("SSH directory does not exist: %s", self._ssh_dir)
            return []

        key_files = []
        # Look for common SSH key files
        patterns = ['*.pem', 'id_*', '*_id_rsa', '*_rsa', 'aws_*']

        for pattern in patterns:
            for key_file in self._ssh_dir.glob(pattern):
                if key_file.is_file():
                    key_files.append(str(key_file))

        return sorted(list(set(key_files)))  # Remove duplicates and sort

    def check_ssh_agent(self) -> bool:
        """Check if SSH agent is running and accessible.

        Uses ssh-add -l as the authoritative check, since many systems
        run the agent via socket activation (systemd, GNOME Keyring,
        macOS Keychain) without setting SSH_AGENT_PID.

        Returns:
            True if SSH agent is running and reachable.
        """
        # Quick check: if SSH_AUTH_SOCK is set and socket exists, try it
        auth_sock = os.environ.get('SSH_AUTH_SOCK')
        if auth_sock and os.path.exists(auth_sock):
            try:
                result = subprocess.run(
                    ['ssh-add', '-l'],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                # 0 = keys listed, 1 = agent running but no keys
                return result.returncode in (0, 1)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return False

        # Fallback: check env var
        return os.environ.get('SSH_AGENT_PID') is not None

    def start_ssh_agent(self) -> bool:
        """Start SSH agent and set environment variables.

        Returns:
            True if agent was started successfully.
        """
        try:
            result = subprocess.run(
                ['ssh-agent', '-s'],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.error("Failed to start ssh-agent: %s", result.stderr)
                return False

            # Parse the output to set environment variables
            # ssh-agent -s outputs: SSH_AUTH_SOCK=/tmp/...; export SSH_AUTH_SOCK;
            #                       SSH_AGENT_PID=12345; export SSH_AGENT_PID;
            for line in result.stdout.splitlines():
                if line.startswith('SSH_AUTH_SOCK='):
                    sock = line.split(';')[0].split('=', 1)[1]
                    os.environ['SSH_AUTH_SOCK'] = sock
                elif line.startswith('SSH_AGENT_PID='):
                    pid = line.split(';')[0].split('=', 1)[1]
                    os.environ['SSH_AGENT_PID'] = pid

            logger.info("Started SSH agent (PID: %s)", os.environ.get('SSH_AGENT_PID'))
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error("Failed to start ssh-agent: %s", e)
            return False

    def add_key_to_agent(self, key_path: str) -> bool:
        """Add key to SSH agent. Check permissions first.

        Args:
            key_path: Path to SSH key file.

        Returns:
            True if key was successfully added.
        """
        try:
            # Expand ~ in paths
            key_path = os.path.expanduser(key_path)

            # Check if key file exists
            if not os.path.exists(key_path):
                logger.error("Key file does not exist: %s", key_path)
                return False

            # Check key file permissions
            if not self.check_key_permissions(key_path):
                logger.warning(
                    "Key file %s has incorrect permissions. Should be 600 or 400.",
                    key_path
                )
                return False

            # Try to add the key
            result = subprocess.run(
                ['ssh-add', key_path],
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )

            # Verify the key was added
            verify = subprocess.run(
                ['ssh-add', '-l'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if verify.returncode == 0:
                logger.info("Successfully added key %s to SSH agent", key_path)
                return True
            else:
                logger.error("Failed to verify key addition: %s", verify.stderr)
                return False

        except subprocess.CalledProcessError as e:
            if "Could not open a connection to your authentication agent" in str(e.stderr):
                logger.error("SSH agent is not running")
            else:
                logger.error("Error adding key to SSH agent: %s", e.stderr)
            return False
        except Exception as e:
            logger.error("Unexpected error adding key to agent: %s", e)
            return False

    def check_key_permissions(self, key_path: str) -> bool:
        """Check if key file has correct permissions (600 or 400).

        Args:
            key_path: Path to SSH key file.

        Returns:
            True if permissions are correct.
        """
        key_path = os.path.expanduser(key_path)
        if not os.path.exists(key_path):
            return False
        perms = oct(os.stat(key_path).st_mode)[-3:]
        return perms in ('600', '400')

    def fix_key_permissions(self, key_path: str) -> None:
        """Fix key file permissions to 600.

        Args:
            key_path: Path to SSH key file.
        """
        key_path = os.path.expanduser(key_path)
        os.chmod(key_path, 0o600)
        logger.info("Fixed permissions for key: %s", key_path)

    def build_ssh_command(
        self,
        host: str,
        username: str,
        key_path: Optional[str] = None,
        proxy_jump: Optional[str] = None,
        remote_command: Optional[str] = None,
        proxy_args: Optional[List[str]] = None,
        port: Optional[int] = None,
        extra_options: Optional[List[str]] = None,
    ) -> List[str]:
        """Build SSH command as List[str]. NEVER use shell=True.

        Always uses -o IdentitiesOnly=yes with -i to prevent
        'Too many authentication failures' errors.

        Args:
            host: Target hostname or IP.
            username: SSH username.
            key_path: Path to SSH key (optional if using agent).
            proxy_jump: ProxyJump string (user@host or user@host:port).
            remote_command: Command to execute remotely.
            proxy_args: List of SSH proxy arguments (takes precedence over proxy_jump).
            port: SSH port to connect on (omitted if None or 22).
            extra_options: Extra ``-o KEY=VALUE`` entries (KEY=VALUE strings
                only — the ``-o`` is added automatically). Applied before proxy
                and identity flags so later ``-o`` values can refine them.

        Returns:
            List of command arguments for subprocess.
        """
        cmd = [
            'ssh',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
        ]

        # Add non-default port
        if port is not None and port != 22:
            cmd.extend(['-p', str(port)])

        # Apply per-host extras (e.g. legacy algorithm negotiation)
        if extra_options:
            for opt in extra_options:
                if opt:
                    cmd.extend(['-o', opt])

        # Add proxy arguments (proxy_args takes precedence over proxy_jump)
        if proxy_args:
            cmd.extend(proxy_args)
        elif proxy_jump:
            cmd.extend(['-J', proxy_jump])

        # Add identity file with IdentitiesOnly to prevent "Too many auth failures"
        if key_path:
            expanded = os.path.expanduser(key_path)
            cmd.extend(['-o', 'IdentitiesOnly=yes', '-i', expanded])

        # Add target host
        cmd.append(f'{username}@{host}')

        # Add remote command if specified
        if remote_command:
            cmd.append(remote_command)

        logger.debug("Built SSH command: %s", ' '.join(cmd))
        return cmd
