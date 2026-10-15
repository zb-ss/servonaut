"""replace_instances keeps a provider's servers where they were in the server list."""
from __future__ import annotations

from types import SimpleNamespace

from servonaut.screens._demo_resolve import replace_instances


def _app(rows):
    return SimpleNamespace(instances=rows, demo_mode=False, redaction_service=None)


def _names(app):
    return [row["name"] for row in app.instances]


FLEET = [
    {"id": "i-0a", "name": "app-1"},
    {"id": "i-0b", "name": "db-1"},
    {"id": "custom-web-1", "name": "web-1", "is_custom": True},
    {"id": "51", "name": "vps-1", "is_ovh": True},
    {"id": "4200001", "name": "cache-1", "is_hetzner": True},
]


def test_a_refreshed_slice_stays_in_place():
    app = _app([dict(row) for row in FLEET])
    replace_instances(app, "aws", [{"id": "i-0b", "name": "db-1"}, {"id": "i-0c", "name": "jobs-1"}])
    assert _names(app) == ["db-1", "jobs-1", "web-1", "vps-1", "cache-1"]

    replace_instances(app, "ovh", [{"id": "52", "name": "vps-2", "is_ovh": True}])
    assert _names(app) == ["db-1", "jobs-1", "web-1", "vps-2", "cache-1"]


def test_a_slice_emptied_by_a_delete_leaves_the_others_in_order():
    app = _app([dict(row) for row in FLEET])
    replace_instances(app, "ovh", [])
    assert _names(app) == ["app-1", "db-1", "web-1", "cache-1"]


def test_a_provider_listed_for_the_first_time_goes_last():
    app = _app([dict(row) for row in FLEET if not row.get("is_hetzner")])
    replace_instances(app, "hetzner", [{"id": "4200002", "name": "build-1", "is_hetzner": True}])
    assert _names(app) == ["app-1", "db-1", "web-1", "vps-1", "build-1"]


def test_the_whole_fleet_is_replaced_without_a_source():
    app = _app([dict(row) for row in FLEET])
    replace_instances(app, None, [{"id": "i-0z", "name": "solo-1"}])
    assert _names(app) == ["solo-1"]
