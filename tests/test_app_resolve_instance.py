"""Cross-seam tests for instance resolution (B.5).

Tests the shared ``_resolve_instance`` logic used by both
``cli/memory.py::_resolve_instance`` and ``ServonautApp.resolve_instance``.

The two implementations share the same contract:
- A name shared by several servers is refused, listing qualified references.
- ``custom/<name>`` and ``<account>/<name>`` pick one server.
- Matching is case-insensitive on both ``id`` and ``name`` fields.
- Returns None when no match is found.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from servonaut.utils.instance_resolver import AmbiguousInstanceError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _aws(iid: str, name: str) -> Dict[str, Any]:
    return {"id": iid, "name": name, "provider": "aws", "account": "aws"}


def _custom(iid: str, name: str) -> Dict[str, Any]:
    return {"id": iid, "name": name, "provider": "custom", "is_custom": True}


# ---------------------------------------------------------------------------
# CLI _resolve_instance (direct unit test — no Textual process required)
# ---------------------------------------------------------------------------

class TestCLIResolveInstance:
    """Tests for cli/memory.py::_resolve_instance."""

    def _resolve(
        self,
        needle: str,
        aws: List[Dict] = (),
        custom: List[Dict] = (),
        ovh: List[Dict] = (),
    ) -> Optional[Dict]:
        from servonaut.cli.memory import _resolve_instance
        return _resolve_instance(needle, list(aws), list(custom), list(ovh))

    def test_finds_aws_by_id(self) -> None:
        result = self._resolve("i-abc", aws=[_aws("i-abc", "prod")])
        assert result is not None
        assert result["id"] == "i-abc"

    def test_finds_aws_by_name(self) -> None:
        result = self._resolve("prod", aws=[_aws("i-abc", "prod")])
        assert result is not None
        assert result["name"] == "prod"

    def test_finds_custom_by_id(self) -> None:
        result = self._resolve("custom-prod", custom=[_custom("custom-prod", "prod")])
        assert result is not None
        assert result["id"] == "custom-prod"

    def test_shared_name_is_refused_with_qualified_candidates(self) -> None:
        """A name two servers share never silently picks one of them."""
        aws_inst = _aws("i-aws", "prod")
        custom_inst = _custom("custom-prod", "prod")
        with pytest.raises(AmbiguousInstanceError) as caught:
            self._resolve("prod", aws=[aws_inst], custom=[custom_inst])
        message = str(caught.value)
        assert "aws/prod" in message and "custom/prod" in message

    def test_qualified_references_pick_one_of_a_shared_name(self) -> None:
        aws_inst = _aws("i-aws", "prod")
        custom_inst = _custom("custom-prod", "prod")
        assert self._resolve("aws/prod", aws=[aws_inst], custom=[custom_inst]) is aws_inst
        assert self._resolve("Custom/PROD", aws=[aws_inst], custom=[custom_inst]) is custom_inst

    def test_case_insensitive_id(self) -> None:
        result = self._resolve("I-ABC", aws=[_aws("i-abc", "prod")])
        assert result is not None
        assert result["id"] == "i-abc"

    def test_case_insensitive_name(self) -> None:
        result = self._resolve("PROD", aws=[_aws("i-abc", "prod")])
        assert result is not None
        assert result["name"] == "prod"

    def test_returns_none_when_not_found(self) -> None:
        result = self._resolve("unknown", aws=[_aws("i-abc", "prod")])
        assert result is None

    def test_returns_none_on_empty_lists(self) -> None:
        result = self._resolve("i-abc")
        assert result is None

    def test_ovh_searched_last(self) -> None:
        """OVH instances are found but only when no AWS/custom match exists."""
        ovh_inst = {"id": "ovh-1", "name": "ovh-server", "provider": "ovh"}
        result = self._resolve("ovh-1", ovh=[ovh_inst])
        assert result is not None
        assert result["id"] == "ovh-1"

    def test_id_shared_across_providers_is_refused(self) -> None:
        """Ids are unique per provider only, so a cross-provider clash is refused."""
        custom_inst = _custom("box-1", "shared-name")
        ovh_inst = {"id": "box-1", "name": "shared-name", "is_ovh": True, "account": "ovh"}
        with pytest.raises(AmbiguousInstanceError):
            self._resolve("box-1", custom=[custom_inst], ovh=[ovh_inst])
        assert self._resolve("ovh/box-1", custom=[custom_inst], ovh=[ovh_inst]) is ovh_inst


# ---------------------------------------------------------------------------
# App.resolve_instance (logic test via the shared resolver function)
# ---------------------------------------------------------------------------

class TestAppResolveInstanceLogic:
    """Validate ServonautApp.resolve_instance contract using the real shared function.

    Tests call ``resolve_instance_from_lists`` directly — the same function
    that ``ServonautApp.resolve_instance`` and ``cli/memory._resolve_instance``
    delegate to — so changes to the implementation are always caught here.
    """

    def _resolve(
        self,
        id_or_name: str,
        instances: List[Dict],
    ) -> Optional[Dict]:
        """Simulate app.resolve_instance: AWS-first split, then delegate."""
        from servonaut.utils.instance_resolver import resolve_instance_from_lists
        aws = [i for i in instances if not i.get("is_custom")]
        other = [i for i in instances if i.get("is_custom")]
        return resolve_instance_from_lists(id_or_name, aws, other)

    def test_shared_name_is_refused(self) -> None:
        aws_inst = _aws("i-abc", "prod")
        custom_inst = _custom("custom-prod", "prod")
        with pytest.raises(AmbiguousInstanceError):
            self._resolve("prod", [aws_inst, custom_inst])
        assert self._resolve("i-abc", [aws_inst, custom_inst]) is aws_inst

    def test_custom_found_when_no_aws_match(self) -> None:
        custom_inst = _custom("custom-prod", "prod")
        result = self._resolve("custom-prod", [custom_inst])
        assert result is not None
        assert result["id"] == "custom-prod"

    def test_case_insensitive(self) -> None:
        aws_inst = _aws("i-abc", "Prod")
        result = self._resolve("PROD", [aws_inst])
        assert result is not None

    def test_returns_none_unknown(self) -> None:
        result = self._resolve("unknown", [_aws("i-abc", "prod")])
        assert result is None
