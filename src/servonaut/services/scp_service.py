"""SCP service for file transfer operations."""

from __future__ import annotations
import asyncio
import logging
import os
import subprocess
from typing import List, Optional, Tuple

from servonaut.services.interfaces import SCPServiceInterface

logger = logging.getLogger(__name__)


class SCPService(SCPServiceInterface):
    """SCP service implementing file transfer operations.

    Uses same ProxyJump pattern as SSH for bastion support.
    Uses IdentitiesOnly=yes when a key is specified to prevent auth failures.
    """

    def build_upload_command(
        self,
        local_path: str,
        remote_path: str,
        host: str,
        username: str,
        key_path: Optional[str] = None,
        proxy_jump: Optional[str] = None,
        proxy_args: Optional[List[str]] = None
    ) -> List[str]:
        """Build SCP upload command.

        Format: scp [options] local user@host:remote

        Args:
            local_path: Local file/directory path.
            remote_path: Remote destination path.
            host: Target hostname or IP.
            username: SSH username.
            key_path: Path to SSH key (optional if using agent).
            proxy_jump: ProxyJump string (user@host).
            proxy_args: List of SSH proxy arguments (takes precedence over proxy_jump).

        Returns:
            List of command arguments for subprocess.
        """
        cmd = self._build_base_args(key_path, proxy_jump, proxy_args)
        cmd.append(os.path.expanduser(local_path))
        cmd.append(f'{username}@{host}:{remote_path}')
        logger.debug("Built SCP upload command: %s", ' '.join(cmd))
        return cmd

    def build_download_command(
        self,
        remote_path: str,
        local_path: str,
        host: str,
        username: str,
        key_path: Optional[str] = None,
        proxy_jump: Optional[str] = None,
        proxy_args: Optional[List[str]] = None
    ) -> List[str]:
        """Build SCP download command.

        Format: scp [options] user@host:remote local

        Args:
            remote_path: Remote file/directory path.
            local_path: Local destination path.
            host: Target hostname or IP.
            username: SSH username.
            key_path: Path to SSH key (optional if using agent).
            proxy_jump: ProxyJump string (user@host).
            proxy_args: List of SSH proxy arguments (takes precedence over proxy_jump).

        Returns:
            List of command arguments for subprocess.
        """
        cmd = self._build_base_args(key_path, proxy_jump, proxy_args)
        cmd.append(f'{username}@{host}:{remote_path}')
        cmd.append(os.path.expanduser(local_path))
        logger.debug("Built SCP download command: %s", ' '.join(cmd))
        return cmd

    async def execute_transfer(self, command: List[str]) -> Tuple[int, str, str]:
        """Execute SCP transfer command.

        Runs in executor to avoid blocking the event loop.

        Args:
            command: Command list from build_upload_command or build_download_command.

        Returns:
            Tuple of (returncode, stdout, stderr).
        """
        logger.info("Executing SCP transfer: %s", ' '.join(command))
        loop = asyncio.get_event_loop()

        try:
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    stdin=subprocess.DEVNULL
                )
            )

            if result.returncode == 0:
                logger.info("SCP transfer completed successfully")
            else:
                logger.error("SCP transfer failed with code %d: %s", result.returncode, result.stderr)

            return result.returncode, result.stdout, result.stderr

        except subprocess.TimeoutExpired:
            logger.error("SCP transfer timed out after 300 seconds")
            return 1, '', 'Transfer timed out after 300 seconds'
        except Exception as e:
            logger.error("SCP transfer error: %s", e)
            return 1, '', str(e)

    def _build_base_args(
        self,
        key_path: Optional[str],
        proxy_jump: Optional[str],
        proxy_args: Optional[List[str]] = None
    ) -> List[str]:
        """Build base SCP command arguments.

        Args:
            key_path: SSH key path.
            proxy_jump: ProxyJump string.
            proxy_args: List of SSH proxy arguments (takes precedence over proxy_jump).

        Returns:
            List of base command arguments.
        """
        cmd = [
            'scp',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
        ]

        # Add proxy arguments (proxy_args takes precedence over proxy_jump)
        if proxy_args:
            cmd.extend(proxy_args)
        elif proxy_jump:
            cmd.extend(['-J', proxy_jump])

        # Add identity file with IdentitiesOnly to prevent "Too many auth failures"
        if key_path:
            expanded = os.path.expanduser(key_path)
            cmd.extend(['-o', 'IdentitiesOnly=yes', '-i', expanded])

        return cmd
