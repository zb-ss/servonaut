"""Demo-mode stand-in ids are unique, so an action never reaches the wrong server."""
from __future__ import annotations

import pytest

from servonaut.services.redaction_service import RedactionService

# Two OVH VPS service names whose hostname stand-ins coincide on first derivation.
COLLIDING = ("vps-0000000e.vps.ovh.net", "vps-00000024.vps.ovh.net")


def test_colliding_hostnames_get_distinct_stand_ins() -> None:
    first_derivation = {RedactionService().redact_hostname(value) for value in COLLIDING}
    assert len(first_derivation) == 1, "fixture must exercise a real collision"

    redaction = RedactionService()
    fakes = [redaction.redact_instance_id(value) for value in COLLIDING]
    assert fakes[0] != fakes[1]
    assert [redaction.real_instance_id(fake) for fake in fakes] == list(COLLIDING)
    # The host columns show the same stand-in as the id column.
    assert [redaction.redact_hostname(value) for value in COLLIDING] == fakes


@pytest.mark.parametrize(
    "make_id",
    [
        lambda n: f"vps-{n:08x}.vps.ovh.net",
        lambda n: str(10_000_000 + n),
        lambda n: f"i-{n:017x}",
        lambda n: f"0acme000000000000000000000000001/{900_000 + n}",
    ],
    ids=["ovh-vps", "numeric", "aws", "ovh-cloud"],
)
def test_many_ids_never_share_a_stand_in(make_id) -> None:
    redaction = RedactionService()
    real_ids = [make_id(n) for n in range(400)]
    fakes = [redaction.redact_instance_id(real) for real in real_ids]
    assert len(set(fakes)) == len(fakes)
    assert not set(fakes) & set(real_ids)
    assert [redaction.real_instance_id(fake) for fake in fakes] == real_ids
    # Idempotent: stand-ins fed back in stay put.
    assert [redaction.redact_instance_id(fake) for fake in fakes] == fakes


def test_the_same_order_gives_the_same_stand_ins() -> None:
    first, second = RedactionService(), RedactionService()
    assert [first.redact_instance_id(v) for v in COLLIDING] == [
        second.redact_instance_id(v) for v in COLLIDING
    ]


def test_a_stand_in_already_owned_is_refused_rather_than_reassigned() -> None:
    redaction = RedactionService()
    fake = redaction.redact_instance_id(COLLIDING[0])
    with pytest.raises(ValueError):
        redaction._register_id(COLLIDING[1], fake)
    assert redaction.real_instance_id(fake) == COLLIDING[0]
