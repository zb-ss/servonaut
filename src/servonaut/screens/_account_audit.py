"""Audit details that name the provider account an action ran in.

The account is recorded only when the provider has several accounts, so
the audit log of a single-account user reads exactly as before.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from servonaut.screens._demo_resolve import connection_instance
from servonaut.screens._provider_accounts import provider_accounts
from servonaut.services.accounts import row_provider


def with_account(
    app: Any, provider: str, account: Optional[str], details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """A copy of *details* naming *account* (a real label) when it matters."""
    recorded = dict(details or {})
    if account and len(provider_accounts(app, provider)) > 1:
        recorded["account"] = account
    return recorded


def row_account(app: Any, row: Optional[Dict[str, Any]]) -> str:
    """The real account label of a drawn server row ("" when it has none).

    Demo mode draws a stand-in label; the audit log keeps the real one.
    """
    if not isinstance(row, dict):
        return ""
    real = connection_instance(app, row)
    return str((real or {}).get("account") or "")


class ServerAuditMixin:
    """Per-server screens: audit details naming the server's account.

    The host screen keeps the server's row, as drawn, in ``_instance``.
    """

    _instance: Dict[str, Any]

    def _audit_details(self, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """A copy of *details*, naming the server's account when it matters."""
        app = self.app  # type: ignore[attr-defined]
        return with_account(
            app, row_provider(self._instance), row_account(app, self._instance), details,
        )
