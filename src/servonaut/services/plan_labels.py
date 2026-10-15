"""How features and plans are named to people.

The backend and the entitlement checks use slugs (``secrets_management``,
``solo``); every screen and message names them the way the product does
(``Secrets management``, ``Solo``).
"""
from __future__ import annotations

# Where people compare the plans and upgrade.
PRICING_URL = "https://servonaut.dev/pricing"

# A feature without a label here shows its raw slug on the Account screen;
# a test checks every feature the plan map names has one.
FEATURE_LABELS = {
    "config_sync": "Config sync across machines",
    "premium_ai": "Premium AI providers",
    "gcp_provider": "GCP provider support",
    "azure_provider": "Azure provider support",
    "team_workspaces": "Team workspaces",
    "memory_sync": "Memory Sync (encrypted memory backup)",
    "memory_drift": "Drift detection across re-probes",
    "memory_digest": "Periodic email digests of memory changes",
    "memory_team_share": "Share encrypted memory with team-mates",
    "memory_ai_summary": "AI-generated memory summaries",
    "memory_compliance_export": "Signed compliance export tarball",
    "secrets_management": "Secrets management",
    "secrets_team_shared": "Team-shared secrets",
    "personal_vault": "Personal vault for SSH keys and secrets",
    "team_vault": "Team vault shared with your team",
    "ssh_ca": "SSH certificates for team servers",
    "proactive_monitoring": "Proactive monitoring and findings",
}

# Plan names as the product writes them.
PLAN_LABELS = {"free": "Free", "solo": "Solo", "teams": "Teams"}


def feature_label(feature: str, default: str = "") -> str:
    """*feature*'s name for people; *default* (else the slug) when it has none."""
    return FEATURE_LABELS.get(feature, default or feature)


def plan_label(plan: object) -> str:
    """*plan*'s name for people; an unknown plan shows as sent."""
    text = str(plan or "")
    return PLAN_LABELS.get(text.lower(), text)
