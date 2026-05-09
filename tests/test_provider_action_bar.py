"""Tests for the provider action-bar widget and its provider-inference helper."""
from __future__ import annotations

import pytest

from servonaut.widgets.provider_action_bar import infer_provider, _CREATE_SUPPORTED


class TestInferProvider:
    def test_empty_list_returns_none(self) -> None:
        assert infer_provider([]) is None

    def test_single_provider_hetzner(self) -> None:
        rows = [{"provider": "hetzner"}, {"provider": "hetzner"}]
        assert infer_provider(rows) == "hetzner"

    def test_single_provider_ovh(self) -> None:
        rows = [{"provider": "ovh"}]
        assert infer_provider(rows) == "ovh"

    def test_aws_default_when_provider_missing(self) -> None:
        # AWS instance dicts predate the multi-provider field — entries
        # without ``provider`` must collapse to the AWS bucket.
        rows = [{"id": "i-1"}, {"id": "i-2"}]
        assert infer_provider(rows) == "aws"

    def test_case_insensitive(self) -> None:
        rows = [{"provider": "OVH"}, {"provider": "ovh"}]
        assert infer_provider(rows) == "ovh"

    def test_mixed_providers_returns_none(self) -> None:
        rows = [{"provider": "hetzner"}, {"provider": "ovh"}]
        assert infer_provider(rows) is None

    def test_aws_plus_hetzner_returns_none(self) -> None:
        rows = [{"id": "i-1"}, {"provider": "hetzner"}]
        assert infer_provider(rows) is None


class TestCreateSupportedSet:
    def test_known_providers_are_creatable(self) -> None:
        assert "ovh" in _CREATE_SUPPORTED
        assert "hetzner" in _CREATE_SUPPORTED

    def test_aws_is_not_creatable(self) -> None:
        # AWS uses the EC2 console / Terraform — no Servonaut wizard.
        assert "aws" not in _CREATE_SUPPORTED


@pytest.mark.asyncio
async def test_action_bar_disables_button_when_no_provider() -> None:
    """The bar must render the ``+ New`` button as disabled when no
    provider is active, and re-enable it when ``active_provider`` is
    set to a creatable provider. Exercised through Textual's
    ``Pilot.run_test`` so the watcher fires under the real Widget
    lifecycle."""
    from textual.app import App, ComposeResult
    from textual.widgets import Button

    from servonaut.widgets.provider_action_bar import ProviderActionBar

    class _Harness(App):
        def compose(self) -> ComposeResult:
            yield ProviderActionBar(id="bar")

    app = _Harness()
    async with app.run_test() as pilot:
        bar = app.query_one(ProviderActionBar)
        btn = bar.query_one("#action_new", Button)

        # Initial: no provider → disabled.
        assert btn.disabled is True

        bar.active_provider = "hetzner"
        await pilot.pause()
        assert btn.disabled is False

        bar.active_provider = "aws"  # not creatable
        await pilot.pause()
        assert btn.disabled is True

        bar.active_provider = "ovh"
        await pilot.pause()
        assert btn.disabled is False

        bar.active_provider = ""
        await pilot.pause()
        assert btn.disabled is True
