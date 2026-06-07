"""Defense-in-depth: tool-name patterns that MUST be dangerous.

This module is the CLI's last line of defense against a buggy
server-emitted catalog that under-classifies a destructive tool.
When CLI consumes the dynamic catalog (PR5'), the resolved guard
level for any tool whose name matches one of these patterns is
escalated to ``dangerous`` regardless of what the server claims,
and the escalation is audit-logged.

Patterns are compiled once at module import. Order matches the
dangerous-tool classification spec.
"""
from __future__ import annotations

import re

# Tuple of compiled regexes. Tested in tests/test_dangerous_tool_floor.py.
DANGEROUS_FLOOR_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p)
    for p in (
        # AWS EC2 lifecycle — irreversible / billing-starting
        r"^aws_run_instances$",
        r"^aws_terminate_instance$",
        # S3 mutations + presigned URL (bearer credential)
        r"^s3_create_bucket$",
        r"^s3_delete_",
        r"^s3_upload_object$",
        r"^s3_copy_object$",
        r"^s3_move_object$",
        r"^s3_generate_presigned_url$",
        # Provider-prefix patterns — auto-catch future tools
        r"^hetzner_create_",
        r"^hetzner_delete_",
        r"^ovh_create_",
        r"^ovh_delete_",
        # Cross-provider destructive
        r"^deploy$",
        r"^provision$",
        r"^security_scan$",
        r"^run_command$",
        r"^transfer_file$",
        r"^ip_ban_set$",
    )
)


def is_dangerous_floor(tool_name: str) -> bool:
    """Return True if ``tool_name`` matches any dangerous-floor pattern.

    Used by the catalog-consumer (PR5') to escalate any tool the server
    classified as ``readonly``/``standard`` to ``dangerous`` when its
    name matches a known-destructive pattern.
    """
    return any(p.match(tool_name) for p in DANGEROUS_FLOOR_PATTERNS)
