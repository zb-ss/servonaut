"""Command history service for persisting command history and saved commands."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Dict

logger = logging.getLogger(__name__)

MAX_GLOBAL_HISTORY = 200
MAX_INSTANCE_HISTORY = 50


class CommandHistoryService:
    """Persistent command history and saved commands.

    Storage format:
    {
        "saved_commands": [
            {"name": "PM2 Status", "command": "pm2 list"},
            {"name": "Disk Usage", "command": "df -h"}
        ],
        "history": {
            "_global": ["pm2 list", "df -h"],
            "i-abc123": ["pm2 list", "tail /var/log/syslog"]
        }
    }
    """

    def __init__(self, store_path: str = "~/.servonaut/command_history.json") -> None:
        """Initialize command history service.

        Args:
            store_path: Path to the JSON store file (supports ~ expansion).
        """
        self._store_path = Path(store_path).expanduser()

    def add_to_history(self, instance_id: str, command: str) -> None:
        """Add a command to per-instance and global history.

        Deduplicates consecutive entries and trims to max limits.

        Args:
            instance_id: EC2 instance ID.
            command: Command string to record.
        """
        data = self._load()
        history = data.setdefault('history', {})

        # Per-instance history
        inst_hist = history.setdefault(instance_id, [])
        if not inst_hist or inst_hist[-1] != command:
            inst_hist.append(command)
        if len(inst_hist) > MAX_INSTANCE_HISTORY:
            history[instance_id] = inst_hist[-MAX_INSTANCE_HISTORY:]

        # Global history
        global_hist = history.setdefault('_global', [])
        if not global_hist or global_hist[-1] != command:
            global_hist.append(command)
        if len(global_hist) > MAX_GLOBAL_HISTORY:
            history['_global'] = global_hist[-MAX_GLOBAL_HISTORY:]

        self._save(data)

    def get_instance_history(self, instance_id: str) -> List[str]:
        """Get command history for a specific instance.

        Args:
            instance_id: EC2 instance ID.

        Returns:
            List of commands (oldest first).
        """
        data = self._load()
        return data.get('history', {}).get(instance_id, [])

    def get_global_history(self) -> List[str]:
        """Get global command history across all instances.

        Returns:
            List of commands (oldest first).
        """
        data = self._load()
        return data.get('history', {}).get('_global', [])

    def save_command(self, name: str, command: str) -> None:
        """Save a named command to favorites.

        Args:
            name: Display name for the saved command.
            command: The command string.
        """
        data = self._load()
        saved = data.setdefault('saved_commands', [])

        # Overwrite if same name exists
        saved = [s for s in saved if s['name'] != name]
        saved.append({'name': name, 'command': command})
        data['saved_commands'] = saved
        self._save(data)
        logger.info("Saved command '%s': %s", name, command)

    def get_saved_commands(self) -> List[Dict[str, str]]:
        """Get all saved commands.

        Returns:
            List of dicts with 'name' and 'command' keys.
        """
        data = self._load()
        return data.get('saved_commands', [])

    def delete_saved_command(self, name: str) -> bool:
        """Delete a saved command by name.

        Args:
            name: Name of the saved command to delete.

        Returns:
            True if the command was found and deleted.
        """
        data = self._load()
        saved = data.get('saved_commands', [])
        new_saved = [s for s in saved if s['name'] != name]

        if len(new_saved) == len(saved):
            return False

        data['saved_commands'] = new_saved
        self._save(data)
        logger.info("Deleted saved command '%s'", name)
        return True

    def _load(self) -> dict:
        """Load store from disk.

        Returns:
            Dictionary with 'saved_commands' and 'history' keys.
        """
        if not self._store_path.exists():
            return {'saved_commands': [], 'history': {}}

        try:
            with open(self._store_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error("Error loading command history: %s", e)
            return {'saved_commands': [], 'history': {}}

    def _save(self, data: dict) -> None:
        """Save store to disk.

        Args:
            data: Dictionary with 'saved_commands' and 'history' keys.
        """
        try:
            self._store_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._store_path, 'w') as f:
                json.dump(data, f, indent=2)
        except IOError as e:
            logger.error("Error saving command history: %s", e)
