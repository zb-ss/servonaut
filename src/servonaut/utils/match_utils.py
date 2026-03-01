"""Instance matching utilities for Servonaut v2.0."""

from __future__ import annotations

import logging
import re
from typing import Dict

logger = logging.getLogger(__name__)


def matches_conditions(instance: dict, conditions: Dict[str, str]) -> bool:
    """Check if instance matches ALL conditions (AND logic).

    Supported condition keys:
    - name_contains: case-insensitive substring match on instance name
    - name_regex: regex match on instance name
    - id: exact instance ID match
    - region: exact region match
    - type_contains: substring match on instance type
    - has_public_ip: "true" or "false"

    Args:
        instance: Instance dictionary.
        conditions: Dictionary of conditions to match.

    Returns:
        True if ALL conditions match (AND logic), False otherwise.
    """
    for key, value in conditions.items():
        if key == 'name_contains':
            if value.lower() not in instance.get('name', '').lower():
                return False
        elif key == 'name_regex':
            if not re.search(value, instance.get('name', ''), re.IGNORECASE):
                return False
        elif key == 'id':
            if instance.get('id') != value:
                return False
        elif key == 'region':
            if instance.get('region') != value:
                return False
        elif key == 'type_contains':
            if value.lower() not in instance.get('type', '').lower():
                return False
        elif key == 'has_public_ip':
            has_ip = instance.get('public_ip') is not None
            expected = value.lower() == 'true'
            if has_ip != expected:
                return False
        else:
            logger.debug("Unknown match condition: %s", key)
    return True
