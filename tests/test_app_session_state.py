"""Each ServonautApp owns its session state.

A mutable default declared on the class body is one object shared by every
instance, so a second app in the same process (an in-process test, a host that
serves several sessions) would inherit the first app's instance list and its
"already prompted" sets.
"""
from __future__ import annotations

from textual.app import App

from servonaut.app import ServonautApp


def test_two_apps_do_not_share_session_state():
    first, second = ServonautApp(), ServonautApp()

    first.instances.append({"id": "i-web1", "name": "web-1"})
    first.memory_first_connect_seen.add("i-web1")
    first.memory_annotations_pulled_seen.add("i-web1")

    assert second.instances == []
    assert second.memory_first_connect_seen == set()
    assert second.memory_annotations_pulled_seen == set()


def test_app_class_holds_no_shared_mutable_defaults():
    """Guard against re-introducing a list/dict/set default on the class."""
    textual_registries = set(vars(App))  # per-class tables Textual maintains
    shared = sorted(
        name
        for name, value in vars(ServonautApp).items()
        if isinstance(value, (list, dict, set))
        and not name.startswith("__")
        and not name.isupper()  # BINDINGS / CSS_PATH are read-only config
        and name not in textual_registries
    )
    assert shared == []
