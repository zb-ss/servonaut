"""Feature gating based on subscription entitlements."""
from __future__ import annotations

import logging
from functools import wraps
from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.services.auth_service import AuthService

logger = logging.getLogger(__name__)

# Feature → minimum plan mapping
FEATURE_PLANS = {
    "config_sync": "solo",
    "premium_ai": "solo",
    "gcp_support": "solo",
    "azure_support": "solo",
    "hosted_mcp": "solo",
    "mcp_deploy": "solo",
    "mcp_provision": "solo",
    "mcp_cost_report": "solo",
    "mcp_security_scan": "solo",
    "team_workspace": "teams",
    "shared_inventory": "teams",
    "shared_config": "teams",
    "rbac": "teams",
    "team_audit": "teams",
    "sso": "teams",
}

PLAN_HIERARCHY = {"free": 0, "solo": 1, "teams": 2}


class EntitlementGuard:
    """Check feature access before executing premium operations."""

    def __init__(self, auth_service: 'AuthService') -> None:
        self._auth = auth_service

    def check(self, feature: str) -> tuple[bool, str]:
        """Check if feature is available. Returns (allowed, reason)."""
        # First check server-side entitlements if available
        if self._auth.has_feature(feature):
            return True, "OK"

        # Fall back to plan-based check
        plan = self._auth.plan
        required_plan = FEATURE_PLANS.get(feature)
        if required_plan is None:
            # Unknown feature — allow (free features don't need gating)
            return True, "OK"

        plan_level = PLAN_HIERARCHY.get(plan, 0)
        required_level = PLAN_HIERARCHY.get(required_plan, 0)

        if plan_level >= required_level:
            return True, "OK"

        if plan == "free":
            return False, (
                f"'{feature}' requires a paid subscription. "
                f"Run 'servonaut --subscribe' to upgrade."
            )
        return False, f"'{feature}' requires the {required_plan} plan (you have {plan})."

    def require(self, feature: str) -> Callable:
        """Decorator for async methods that require a feature."""
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(*args, **kwargs):
                allowed, reason = self.check(feature)
                if not allowed:
                    screen = args[0] if args else None
                    if hasattr(screen, 'notify'):
                        screen.notify(reason, severity="warning")
                    return None
                return await func(*args, **kwargs)
            return wrapper
        return decorator
