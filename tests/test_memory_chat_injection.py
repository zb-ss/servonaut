"""Tests for T6 — chat memory injection and stale-memory banner.

Covers:
  - ``AIAnalysisService.build_server_memory_block``: injects memory block,
    respects opt-out, handles ``get_summary`` raising.
  - ``ChatService.send_message``: ``<server_memory>`` tag present in captured
    ``system_prompt`` when ``instance_id`` is passed; absent on opt-out.
  - ``ChatPanel._parse_at_prefix``: @prefix resolution and no-prefix pass-through.
  - ``ChatPanel._update_memory_banner``: stale / clean / no-service / opt-out paths.
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest

from servonaut.config.schema import MemoryConfig
from servonaut.services.ai_analysis_service import AIAnalysisService
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.store import MemoryStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_inst(
    iid: str = "i-abc",
    name: str = "prod",
    provider: str = "custom",
) -> Dict[str, Any]:
    return {"id": iid, "name": name, "provider": provider}


def _make_memory_config(
    enabled: bool = True,
    disabled_instance: Optional[str] = None,
) -> MemoryConfig:
    overrides: Dict[str, Dict[str, Any]] = {}
    if disabled_instance:
        overrides[disabled_instance] = {"memory_disabled": True}
    return MemoryConfig(enabled=enabled, per_server_overrides=overrides)


def _make_ai_service(config_manager: Any = None) -> AIAnalysisService:
    """Return an AIAnalysisService backed by a mock config_manager."""
    if config_manager is None:
        cfg = MagicMock()
        cfg.ai_provider.provider = "anthropic"
        cfg.ai_provider.api_key = "sk-test"
        cfg.ai_provider.model = "claude-haiku"
        cfg.ai_provider.max_tokens = 2048
        cfg.ai_provider.temperature = 0.0
        cfg.ai_chunk_size = 100_000
        cfg.ai_system_prompt = "You are helpful."
        config_manager = MagicMock()
        config_manager.get.return_value = cfg
    return AIAnalysisService(config_manager)


def _make_memory_service(tmp_path: Path, enabled: bool = True) -> MemoryService:
    store = MemoryStore(root=tmp_path)
    config = _make_memory_config(enabled=enabled)
    return MemoryService(store=store, config=config, probers=[])


# ---------------------------------------------------------------------------
# AIAnalysisService.build_server_memory_block
# ---------------------------------------------------------------------------

class TestBuildServerMemoryBlock:
    """Unit tests for the new helper on AIAnalysisService."""

    def setup_method(self) -> None:
        self.ai_service = _make_ai_service()

    def _run(self, coro):
        return asyncio.run(coro)

    def test_returns_none_when_memory_service_is_none(self) -> None:
        result = self._run(
            self.ai_service.build_server_memory_block(
                "i-abc",
                memory_service=None,
                config_memory=_make_memory_config(),
            )
        )
        assert result is None

    def test_returns_none_when_config_memory_is_none(self) -> None:
        mock_memory = MagicMock()
        result = self._run(
            self.ai_service.build_server_memory_block(
                "i-abc",
                memory_service=mock_memory,
                config_memory=None,
            )
        )
        assert result is None

    def test_returns_none_when_memory_disabled_globally(self) -> None:
        mock_memory = MagicMock()
        result = self._run(
            self.ai_service.build_server_memory_block(
                "i-abc",
                memory_service=mock_memory,
                config_memory=_make_memory_config(enabled=False),
            )
        )
        assert result is None

    def test_returns_none_when_instance_opted_out(self) -> None:
        mock_memory = MagicMock()
        result = self._run(
            self.ai_service.build_server_memory_block(
                "i-abc",
                memory_service=mock_memory,
                config_memory=_make_memory_config(disabled_instance="i-abc"),
            )
        )
        assert result is None

    def test_wraps_summary_in_xml_tags(self, tmp_path: Path) -> None:
        memory_service = MagicMock()
        memory_service.get_summary = AsyncMock(return_value="OS: Ubuntu 22.04\nKernel: 5.15")
        config_memory = _make_memory_config()

        result = self._run(
            self.ai_service.build_server_memory_block(
                "i-abc",
                instance_name="prod",
                provider="aws",
                memory_service=memory_service,
                config_memory=config_memory,
            )
        )

        assert result is not None
        assert result.startswith('<server_memory id="i-abc">')
        assert "OS: Ubuntu 22.04" in result
        assert result.endswith("</server_memory>")

    def test_returns_none_when_get_summary_raises(self) -> None:
        memory_service = MagicMock()
        memory_service.get_summary = AsyncMock(side_effect=RuntimeError("connection failed"))
        config_memory = _make_memory_config()

        result = self._run(
            self.ai_service.build_server_memory_block(
                "i-abc",
                memory_service=memory_service,
                config_memory=config_memory,
            )
        )
        assert result is None

    def test_returns_none_when_summary_is_empty(self) -> None:
        memory_service = MagicMock()
        memory_service.get_summary = AsyncMock(return_value="")
        config_memory = _make_memory_config()

        result = self._run(
            self.ai_service.build_server_memory_block(
                "i-abc",
                memory_service=memory_service,
                config_memory=config_memory,
            )
        )
        assert result is None


# ---------------------------------------------------------------------------
# ChatService.send_message — system_prompt injection
# ---------------------------------------------------------------------------

class TestChatServiceMemoryInjection:
    """Verify that the memory block reaches ai_service.chat(system_prompt=...)."""

    @pytest.fixture(autouse=True)
    def _isolate_chat_history(self, tmp_path_factory):
        self._tmp_chat_history = tmp_path_factory.mktemp("chat_history")

    def _run(self, coro):
        return asyncio.run(coro)

    def _make_chat_service(
        self,
        memory_service: Any = None,
        config_memory: Optional[MemoryConfig] = None,
    ):
        """Build a ChatService with a mocked AI service that records system_prompt."""
        from servonaut.services.chat_service import ChatService, ChatSession

        captured: Dict[str, Any] = {}

        async def fake_chat(messages, system_prompt="", tools=None):
            captured["system_prompt"] = system_prompt
            return {
                "content": "OK",
                "tool_calls": [],
                "tokens_used": 10,
                "input_tokens": 5,
                "output_tokens": 5,
                "model": "claude-haiku",
                "estimated_cost": 0.0,
                "raw_message": None,
                "stop_reason": "end_turn",
            }

        ai_service = MagicMock()
        ai_service.chat = fake_chat

        # Wire build_server_memory_block through to actual implementation
        real_ai = _make_ai_service()
        ai_service.build_server_memory_block = real_ai.build_server_memory_block

        cfg = MagicMock()
        cfg.ai_provider.provider = "anthropic"
        cfg.chat_max_tool_iterations = 3
        cfg.chat_history_path = str(self._tmp_chat_history)
        mem_config = config_memory or _make_memory_config()
        cfg.memory = mem_config

        config_manager = MagicMock()
        config_manager.get.return_value = cfg

        tool_executor = MagicMock()
        tool_executor.get_tool_definitions.return_value = []

        chat_service = ChatService(
            config_manager=config_manager,
            ai_analysis_service=ai_service,
            tool_executor=tool_executor,
            memory_service=memory_service,
        )
        return chat_service, captured

    def test_memory_block_injected_when_instance_id_provided(self, tmp_path: Path) -> None:
        memory_service = MagicMock()
        memory_service.get_summary = AsyncMock(return_value="OS: Ubuntu\nKernel: 5.15")

        chat_service, captured = self._make_chat_service(memory_service=memory_service)

        from servonaut.services.chat_service import ChatSession
        session = ChatSession()
        self._run(
            chat_service.send_message(
                session,
                "What OS is running?",
                instance_id="i-abc",
                instance_name="prod",
                instance_provider="aws",
            )
        )

        assert "system_prompt" in captured
        assert '<server_memory id="i-abc">' in captured["system_prompt"]
        assert "OS: Ubuntu" in captured["system_prompt"]

    def test_no_memory_block_when_memory_disabled(self, tmp_path: Path) -> None:
        memory_service = MagicMock()
        memory_service.get_summary = AsyncMock(return_value="some data")

        chat_service, captured = self._make_chat_service(
            memory_service=memory_service,
            config_memory=_make_memory_config(enabled=False),
        )

        from servonaut.services.chat_service import ChatSession
        session = ChatSession()
        self._run(
            chat_service.send_message(
                session,
                "ping",
                instance_id="i-abc",
            )
        )

        assert '<server_memory' not in captured.get("system_prompt", "")

    def test_no_memory_block_when_instance_opted_out(self) -> None:
        memory_service = MagicMock()
        memory_service.get_summary = AsyncMock(return_value="data")

        chat_service, captured = self._make_chat_service(
            memory_service=memory_service,
            config_memory=_make_memory_config(disabled_instance="i-abc"),
        )

        from servonaut.services.chat_service import ChatSession
        session = ChatSession()
        self._run(
            chat_service.send_message(
                session,
                "ping",
                instance_id="i-abc",
            )
        )

        assert '<server_memory' not in captured.get("system_prompt", "")

    def test_call_succeeds_when_get_summary_raises(self) -> None:
        memory_service = MagicMock()
        memory_service.get_summary = AsyncMock(side_effect=RuntimeError("ssh error"))

        chat_service, captured = self._make_chat_service(memory_service=memory_service)

        from servonaut.services.chat_service import ChatSession
        session = ChatSession()
        # Must not raise
        result = self._run(
            chat_service.send_message(
                session,
                "ping",
                instance_id="i-abc",
            )
        )
        assert result["content"] == "OK"
        assert '<server_memory' not in captured.get("system_prompt", "")

    def test_no_memory_block_when_no_instance_id(self) -> None:
        memory_service = MagicMock()
        memory_service.get_summary = AsyncMock(return_value="data")

        chat_service, captured = self._make_chat_service(memory_service=memory_service)

        from servonaut.services.chat_service import ChatSession
        session = ChatSession()
        self._run(chat_service.send_message(session, "hello"))

        assert '<server_memory' not in captured.get("system_prompt", "")


# ---------------------------------------------------------------------------
# ChatPanel._parse_at_prefix
# ---------------------------------------------------------------------------

def _make_stub_app(instances=None) -> MagicMock:
    """Build a stub App-like MagicMock with a working resolve_instance."""
    app = MagicMock()
    app.instances = list(instances or [])

    def resolve_instance(token):
        needle = token.lower()
        for inst in app.instances:
            if (
                inst.get("id", "").lower() == needle
                or inst.get("name", "").lower() == needle
            ):
                return inst
        return None

    app.resolve_instance = resolve_instance
    return app


@contextmanager
def _panel_with_app(app: MagicMock):
    """Context manager: yields a ChatPanel instance whose .app property returns *app*."""
    from servonaut.widgets.chat_panel import ChatPanel

    panel = ChatPanel.__new__(ChatPanel)
    panel._session = None
    panel._thinking = False
    panel._total_tokens = 0
    panel._total_cost = 0.0
    panel._model = ""

    with patch.object(type(panel), "app", new_callable=PropertyMock, return_value=app):
        yield panel


class TestParseAtPrefix:
    """Unit tests for the @-prefix parser — no Textual app required."""

    def test_at_prefix_matched_by_id(self) -> None:
        instances = [_make_inst(iid="i-abc", name="prod")]
        app = _make_stub_app(instances)
        with _panel_with_app(app) as panel:
            inst, text = panel._parse_at_prefix("@i-abc ssh -i key.pem")
        assert inst is not None
        assert inst["id"] == "i-abc"
        assert text == "ssh -i key.pem"

    def test_at_prefix_matched_by_name(self) -> None:
        instances = [_make_inst(iid="i-abc", name="prod")]
        app = _make_stub_app(instances)
        with _panel_with_app(app) as panel:
            inst, text = panel._parse_at_prefix("@prod ssh foo")
        assert inst is not None
        assert inst["name"] == "prod"
        assert text == "ssh foo"

    def test_at_prefix_case_insensitive(self) -> None:
        instances = [_make_inst(iid="i-ABC", name="Prod")]
        app = _make_stub_app(instances)
        with _panel_with_app(app) as panel:
            inst, text = panel._parse_at_prefix("@PROD check logs")
        assert inst is not None

    def test_at_prefix_unknown_token_returns_original(self) -> None:
        app = _make_stub_app([])
        with _panel_with_app(app) as panel:
            inst, text = panel._parse_at_prefix("@unknown hello")
        assert inst is None
        assert text == "@unknown hello"

    def test_no_prefix_returns_original(self) -> None:
        app = _make_stub_app([])
        with _panel_with_app(app) as panel:
            inst, text = panel._parse_at_prefix("no prefix here")
        assert inst is None
        assert text == "no prefix here"

    def test_at_prefix_only_token_no_rest(self) -> None:
        instances = [_make_inst(iid="i-abc", name="prod")]
        app = _make_stub_app(instances)
        with _panel_with_app(app) as panel:
            inst, text = panel._parse_at_prefix("@prod")
        assert inst is not None
        assert text == ""


# ---------------------------------------------------------------------------
# ChatPanel._update_memory_banner
# ---------------------------------------------------------------------------

class TestUpdateMemoryBanner:
    """Unit tests for the stale-memory banner logic using MagicMock."""

    @contextmanager
    def _make_panel_with_banner(
        self,
        memory_service: Any = None,
        stale_modules_return=None,
        config_memory: Optional[MemoryConfig] = None,
        active_instance: Optional[Dict[str, Any]] = None,
    ):
        """Context manager yielding (panel, banner_mock) with a fully stubbed app."""
        from servonaut.widgets.chat_panel import ChatPanel

        panel = ChatPanel.__new__(ChatPanel)
        panel._session = None
        panel._thinking = False
        panel._total_tokens = 0
        panel._total_cost = 0.0
        panel._model = ""
        panel._stale_cache = {}  # required by _update_memory_banner debounce

        # Stub the banner Static widget
        banner = MagicMock()
        banner.has_class.return_value = False

        def query_one_stub(selector, _type=None):
            if "chat-memory-banner" in selector:
                return banner
            raise Exception(f"query_one: unknown selector {selector}")

        panel.query_one = query_one_stub

        # Build a stub app
        app = MagicMock()
        app.memory_service = memory_service
        app.instances = [active_instance] if active_instance else []

        mem_cfg = config_memory or _make_memory_config()
        cfg = MagicMock()
        cfg.memory = mem_cfg
        app.config_manager.get.return_value = cfg

        # _resolve_active_instance stubbed directly on the panel instance
        def _resolve_active_instance(text):
            return active_instance, text

        panel._resolve_active_instance = _resolve_active_instance

        if memory_service is not None and stale_modules_return is not None:
            # Use the public stale_modules API (not _store) — matches _update_memory_banner
            memory_service.stale_modules.return_value = stale_modules_return

        with patch.object(type(panel), "app", new_callable=PropertyMock, return_value=app):
            yield panel, banner

    def test_banner_hidden_when_no_memory_service(self) -> None:
        with self._make_panel_with_banner(memory_service=None) as (panel, banner):
            panel._update_memory_banner()
        banner.add_class.assert_called_with("hidden")

    def test_banner_hidden_when_no_active_instance(self) -> None:
        memory_service = MagicMock()
        with self._make_panel_with_banner(
            memory_service=memory_service,
            active_instance=None,
        ) as (panel, banner):
            panel._update_memory_banner()
        banner.add_class.assert_called_with("hidden")

    def test_banner_hidden_when_memory_globally_disabled(self) -> None:
        memory_service = MagicMock()
        with self._make_panel_with_banner(
            memory_service=memory_service,
            config_memory=_make_memory_config(enabled=False),
            active_instance=_make_inst(),
        ) as (panel, banner):
            panel._update_memory_banner()
        banner.add_class.assert_called_with("hidden")

    def test_banner_hidden_when_instance_opted_out(self) -> None:
        memory_service = MagicMock()
        inst = _make_inst(iid="i-abc")
        with self._make_panel_with_banner(
            memory_service=memory_service,
            config_memory=_make_memory_config(disabled_instance="i-abc"),
            active_instance=inst,
        ) as (panel, banner):
            panel._update_memory_banner()
        banner.add_class.assert_called_with("hidden")

    def test_banner_hidden_when_no_stale_modules(self) -> None:
        memory_service = MagicMock()
        memory_service.stale_modules.return_value = []
        inst = _make_inst()
        with self._make_panel_with_banner(
            memory_service=memory_service,
            stale_modules_return=[],
            active_instance=inst,
        ) as (panel, banner):
            panel._update_memory_banner()
        banner.add_class.assert_called_with("hidden")

    def test_banner_visible_when_stale_modules_present(self) -> None:
        memory_service = MagicMock()
        memory_service.stale_modules.return_value = ["os", "services"]
        inst = _make_inst(iid="i-abc")
        with self._make_panel_with_banner(
            memory_service=memory_service,
            stale_modules_return=["os", "services"],
            active_instance=inst,
        ) as (panel, banner):
            panel._update_memory_banner()
        # Banner should be updated with content and the hidden class removed
        banner.update.assert_called_once()
        call_args = banner.update.call_args[0][0]
        assert "i-abc" in call_args
        assert "os" in call_args
        banner.remove_class.assert_called_with("hidden")

    def test_banner_escapes_rich_markup_in_instance_id(self) -> None:
        """Defence: adversarial instance_id cannot inject Rich markup into the banner.

        If _rich_escape is NOT applied, an id like '[link=http://evil]click[/link]'
        would render as a clickable Rich hyperlink in the TUI.  After escaping it
        must appear as literal text (no unescaped opening '[link=').
        """
        memory_service = MagicMock()
        # Instance id that contains Rich markup injection payload
        evil_id = "[link=http://evil]click[/link]"
        inst = _make_inst(iid=evil_id, name="prod")
        memory_service.stale_modules.return_value = ["os"]

        with self._make_panel_with_banner(
            memory_service=memory_service,
            stale_modules_return=["os"],
            active_instance=inst,
        ) as (panel, banner):
            panel._update_memory_banner()

        # banner.update must have been called (stale modules present)
        banner.update.assert_called_once()
        rendered: str = banner.update.call_args[0][0]

        # rich.markup.escape converts '[' to '\[', so the injection payload
        # must appear with its brackets escaped.  A verbatim '[link=' opener
        # (without a preceding backslash) would be an active Rich tag.
        # We verify two things:
        #   1. The escaped form is present (proving _rich_escape ran).
        #   2. The raw unescaped form '[link=http://evil]' is NOT present
        #      except as part of the escaped form '\[link=http://evil]'.
        assert r"\[link=http://evil]" in rendered, (
            "Expected escaped markup '\\[link=...' in banner; "
            "_rich_escape may not have been applied to the instance_id."
        )
        # Verify no standalone (unescaped) '[link=' tag opener exists.
        # After escaping, every '[link=' in the string is preceded by '\'.
        import re
        unescaped_tag = re.search(r'(?<!\\)\[link=', rendered)
        assert unescaped_tag is None, (
            "Rich markup injection '[link=...' survived unescaped into banner text; "
            "instance_id must be escaped via _rich_escape before embedding."
        )
