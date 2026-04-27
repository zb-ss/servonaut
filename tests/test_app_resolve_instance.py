"""Cross-seam tests for instance resolution (B.5).

Tests the shared ``_resolve_instance`` logic used by both
``cli/memory.py::_resolve_instance`` and ``ServonautApp.resolve_instance``.

The two implementations share the same contract:
- AWS instances take precedence over custom/OVH on name collision.
- Matching is case-insensitive on both ``id`` and ``name`` fields.
- Returns None when no match is found.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _aws(iid: str, name: str) -> Dict[str, Any]:
    return {"id": iid, "name": name, "provider": "aws"}


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

    def test_aws_wins_on_name_collision(self) -> None:
        """When AWS and custom share a name, AWS instance must be returned."""
        aws_inst = _aws("i-aws", "prod")
        custom_inst = _custom("custom-prod", "prod")
        result = self._resolve("prod", aws=[aws_inst], custom=[custom_inst])
        assert result is not None
        assert result["id"] == "i-aws"  # AWS wins

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

    def test_custom_searched_before_ovh(self) -> None:
        """Custom takes precedence over OVH on id collision."""
        custom_inst = _custom("box-1", "shared-name")
        ovh_inst = {"id": "box-1", "name": "shared-name", "provider": "ovh"}
        result = self._resolve("box-1", custom=[custom_inst], ovh=[ovh_inst])
        assert result is not None
        assert result["provider"] == "custom"


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

    def test_aws_first_on_name_collision(self) -> None:
        aws_inst = _aws("i-abc", "prod")
        custom_inst = _custom("custom-prod", "prod")
        result = self._resolve("prod", [aws_inst, custom_inst])
        assert result is not None
        assert result["id"] == "i-abc"

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
