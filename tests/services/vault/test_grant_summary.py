"""grant_summary: what a grant-processing run did, in words."""
from __future__ import annotations

from servonaut.services.vault.display import grant_summary


def _run(accepted=0, skipped=0, pending=()):
    return {
        "accepted": [{"recipient_user_id": n} for n in range(accepted)],
        "skipped": [{"recipient_user_id": n} for n in range(skipped)],
        "pending_confirmation": [{"user_id": n, "identity_changed": changed} for n, changed in enumerate(pending)],
    }


def test_nothing_to_do():
    assert grant_summary([]) == "No one is waiting for access."
    assert grant_summary([_run()]) == "No one is waiting for access."
    assert grant_summary(None) == "No one is waiting for access."


def test_counts_add_up_across_vaults():
    assert grant_summary([_run(accepted=1), _run(accepted=2)]) == "Granted access to 3 members."


def test_pending_members_and_changed_identities():
    assert grant_summary([_run(pending=(False,))]) == "1 member still needs approval before getting access."
    assert grant_summary([_run(accepted=1, pending=(True, False))]) == (
        "Granted access to 1 member. "
        "2 members still need approval before getting access (1 with a changed vault identity)."
    )


def test_skipped_grants():
    assert grant_summary([_run(skipped=1)]) == "1 grant was not applied."
    assert grant_summary([_run(accepted=2, skipped=2)]) == "Granted access to 2 members. 2 grants were not applied."
