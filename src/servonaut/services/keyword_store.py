"""Keyword store service for Servonaut v2.0."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Dict

from servonaut.services.interfaces import KeywordStoreInterface

logger = logging.getLogger(__name__)


class KeywordStore(KeywordStoreInterface):
    """JSON-file backed keyword store for scan results.

    Storage format:
    {
        "i-abc123": [
            {"source": "path:~/shared/", "content": "file1.txt\nfile2.txt", "timestamp": "..."},
            {"source": "command:pm2 list", "content": "...", "timestamp": "..."}
        ],
        "i-def456": [...]
    }
    """

    def __init__(self, store_path: str = "~/.servonaut/keywords.json") -> None:
        """Initialize the keyword store.

        Args:
            store_path: Path to the JSON store file (supports ~ expansion)
        """
        self._store_path = Path(store_path).expanduser()

    def save_results(self, server_id: str, results: List[dict]) -> None:
        """Save or update scan results for a server.

        Overwrites previous results for that server.

        Args:
            server_id: Instance ID or unique identifier
            results: List of scan result dictionaries
        """
        data = self._load()
        data[server_id] = results
        self._save(data)
        logger.info("Saved %d scan results for %s", len(results), server_id)

    def get_results(self, server_id: str) -> List[dict]:
        """Get scan results for a specific server.

        Args:
            server_id: Instance ID or unique identifier

        Returns:
            List of scan results, or empty list if none found
        """
        data = self._load()
        return data.get(server_id, [])

    def search(self, query: str) -> List[dict]:
        """Search keyword store for matching content.

        Performs case-insensitive substring search across all stored content.

        Args:
            query: Search query string

        Returns:
            List of matches:
            [{"server_id": "i-abc123", "source": "path:~/shared/",
              "content": "matching line...", "match_type": "keyword", "timestamp": "..."}]
        """
        data = self._load()
        query_lower = query.lower()
        matches = []

        for server_id, results in data.items():
            for result in results:
                content = result.get('content', '')
                if query_lower in content.lower():
                    # Extract matching lines for context
                    matching_lines = [
                        line for line in content.splitlines()
                        if query_lower in line.lower()
                    ]
                    matches.append({
                        'server_id': server_id,
                        'source': result.get('source', ''),
                        'content': '\n'.join(matching_lines[:5]),  # limit to 5 lines
                        'match_type': 'keyword',
                        'timestamp': result.get('timestamp', '')
                    })

        return matches

    def prune_stale(self, active_instance_ids: List[str]) -> int:
        """Remove entries for instances that no longer exist.

        Args:
            active_instance_ids: List of currently active instance IDs

        Returns:
            Count of pruned entries
        """
        data = self._load()
        active_set = set(active_instance_ids)
        stale_keys = [k for k in data if k not in active_set]

        for key in stale_keys:
            del data[key]

        if stale_keys:
            self._save(data)
            logger.info("Pruned %d stale keyword entries", len(stale_keys))

        return len(stale_keys)

    def get_all_server_ids(self) -> List[str]:
        """Get all server IDs with stored results.

        Returns:
            List of server IDs
        """
        return list(self._load().keys())

    def clear(self) -> None:
        """Clear all stored results."""
        self._save({})
        logger.info("Cleared all keyword store results")

    def _load(self) -> Dict[str, List[dict]]:
        """Load store from disk.

        Returns:
            Dictionary of server_id -> results, or empty dict on error
        """
        if not self._store_path.exists():
            return {}

        try:
            with open(self._store_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error("Error loading keyword store: %s", e)
            return {}

    def _save(self, data: Dict[str, List[dict]]) -> None:
        """Save store to disk.

        Args:
            data: Dictionary of server_id -> results
        """
        try:
            with open(self._store_path, 'w') as f:
                json.dump(data, f, indent=2)
        except IOError as e:
            logger.error("Error saving keyword store: %s", e)
