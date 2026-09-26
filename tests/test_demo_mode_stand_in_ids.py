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


def test_short_numeric_ids_never_stand_in_for_each_other() -> None:
    redaction = RedactionService()
    real_ids = [str(n) for n in range(1, 13)]
    redaction.register_real_ids(real_ids)
    fakes = [redaction.redact_instance_id(real) for real in real_ids]
    assert len(set(fakes)) == len(fakes)
    assert not set(fakes) & set(real_ids), "a stand-in must never equal a real id"
    assert [redaction.real_instance_id(fake) for fake in fakes] == real_ids


def test_a_real_id_equal_to_another_servers_stand_in_keeps_its_own_identity() -> None:
    redaction = RedactionService()
    first = "48151623"
    taken = redaction.redact_instance_id(first)
    # A second server whose real id happens to be the first one's stand-in.
    displaced = redaction.register_real_ids([taken])
    assert displaced == {taken: first}
    assert redaction.real_instance_id(taken) == taken
    assert redaction.redact_instance_id(taken) != taken
    renamed = redaction.redact_instance_id(first)
    assert renamed != taken and redaction.real_instance_id(renamed) == first


def test_a_late_colliding_server_redraws_the_row_it_displaced() -> None:
    from types import SimpleNamespace

    from servonaut.app import ServonautApp
    from servonaut.screens._demo_resolve import replace_instances

    redaction = RedactionService()
    app = SimpleNamespace(
        demo_mode=True, redaction_service=redaction, instances=[], _instances_pristine=[],
    )
    app.real_instance_id = lambda v: ServonautApp.real_instance_id(app, v)
    app.connection_instance = lambda r: ServonautApp.connection_instance(app, r)
    first = {"id": "48151623", "name": "acme-a", "is_hetzner": True}
    replace_instances(app, "hetzner", [first])
    row_a = app.instances[0]
    stand_in = row_a["id"]

    second = {"id": stand_in, "name": "acme-b", "provider": "aws"}
    replace_instances(app, "aws", [second])
    row_b = next(r for r in app.instances if r is not row_a)
    assert row_a["id"] != stand_in, "the displaced row shows its new stand-in"
    assert app.connection_instance(row_a)["name"] == "acme-a"
    assert app.connection_instance(row_b)["name"] == "acme-b"
