"""Rich-markup-injection regression tests for the chat panel (A1 + A2).

The chat panel renders server-controlled strings into Rich markup contexts
on three surfaces:

1. ``app.notify(...)`` toasts — the Wave-3 streaming consumer surfaces
   ``info`` and ``error`` events whose ``message`` field is server-supplied.
2. The streamed assistant bubble — the model can theoretically inject
   ``[link=evil]`` into its own output.
3. ``load_remote_conversation`` — server-stored conversations may contain
   user-role rows that came from the model itself (not the user).

Every site MUST either pass ``markup=False`` to ``notify`` or escape the
server fragment before interpolating. These tests pin both behaviours.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from servonaut.services.api_client import APIError
from servonaut.services.chat_service import ChatMessage, ChatSession


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_panel():
    """Construct a :class:`ChatPanel` with ``app`` mocked.

    Avoids :func:`Widget.__init__`'s requirement of an active App context
    by going through ``ChatPanel.__new__`` and only setting the attributes
    each test needs. The properties / methods we exercise don't reach
    Textual internals.
    """
    from servonaut.widgets.chat_panel import ChatPanel

    panel = ChatPanel.__new__(ChatPanel)
    panel._stale_cache = {}
    panel._upstream_failures = []
    panel._session_provider_override = None
    panel._last_fallback_used = False
    panel._last_soft_capped = False
    panel._last_hard_capped = False
    panel._remote_conversation_id = None
    panel._pinned_error_active = False
    panel._first_run_modal_shown = False
    panel._empty_state_modal_shown = False
    panel._thinking = False
    panel._total_tokens = 0
    panel._total_cost = 0.0
    panel._model = ""
    panel._session = None
    panel._turn_tool_calls = 0
    return panel


def _attach_app(panel) -> MagicMock:
    """Wire a :class:`MagicMock` ``app`` onto *panel* and return it."""
    app = MagicMock()
    # Explicitly disable demo_mode so the redaction guard (which is now truthy-
    # checked, not `is True`) does not fire on this mock and return a MagicMock
    # from scrub_stream instead of the actual content string.
    app.demo_mode = False
    app.redaction_service = None
    type(panel).app = property(lambda self, _a=app: _a)  # type: ignore[assignment]
    return app


# ---------------------------------------------------------------------------
# A1 — notify markup injection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc_message",
    [
        "[link=https://evil/]click[/link]",
        "Error [bold red]rate_limited[/bold red]",
        "Quota exhausted; topup at [link=phish.example]here[/link]",
    ],
)
def test_notify_carrying_apierror_message_passes_markup_false(
    monkeypatch, exc_message,
):
    """A1 — ``_handle_stream_error`` must scrub server-controlled markup.

    Drives :meth:`_handle_stream_error` with a synthetic
    :class:`APIError` whose ``message`` carries Rich markup; asserts
    every ``app.notify`` call receives ``markup=False`` so the bracketed
    payload renders literally.
    """
    panel = _build_panel()
    app = _attach_app(panel)

    exc = APIError(
        code="upstream_unavailable",
        message=exc_message,
        status=503,
        details={},
    )

    panel._record_upstream_failure = MagicMock()
    panel._maybe_offer_fallback = MagicMock()
    panel._set_banner = MagicMock()

    panel._handle_stream_error(exc, accumulated="")

    # At least one notify call happened — and every call must carry
    # markup=False because the message field is server-supplied.
    assert app.notify.called or panel._set_banner.called

    for call in app.notify.call_args_list:
        kwargs = call.kwargs
        assert kwargs.get("markup") is False, (
            f"notify called WITHOUT markup=False — server markup leaked: "
            f"{call!r}"
        )


def test_notify_for_unhandled_exception_uses_markup_false():
    """A1 — the catch-all branch in ``_handle_stream_error`` must also scrub."""
    panel = _build_panel()
    app = _attach_app(panel)

    panel._handle_stream_error(
        RuntimeError("[link=evil]boom[/link]"), accumulated="",
    )
    assert app.notify.called
    kwargs = app.notify.call_args.kwargs
    assert kwargs.get("markup") is False


def test_handle_streamed_tool_call_bridge_failure_passes_markup_false(
    monkeypatch,
):
    """A1 — exception path inside ``_handle_streamed_tool_call`` keeps markup off.

    The notify message interpolates ``str(exc)`` which may contain
    server-controlled text. Confirm the failure-path notify uses
    ``markup=False``.
    """
    import asyncio

    panel = _build_panel()
    app = _attach_app(panel)

    bridge = MagicMock()

    async def _raise(_call):
        raise RuntimeError("[link=evil]bridge boom[/link]")

    async def _post(_result):
        return None

    bridge.handle_tool_call = _raise
    bridge.post_tool_result = _post
    app.ai_tool_bridge = bridge

    asyncio.run(
        panel._handle_streamed_tool_call(
            {"tool_call_id": "tc_1", "tool": "run_command", "args": {}}
        )
    )
    assert app.notify.called
    kwargs = app.notify.call_args.kwargs
    assert kwargs.get("markup") is False


# ---------------------------------------------------------------------------
# A2 — streamed assistant content escape
# ---------------------------------------------------------------------------


def _collect_rendered_static_widgets(panel) -> list:
    """Run ``_refresh_messages`` against a stub container and return
    every mounted widget's rendered Rich Content.
    """
    captured: list = []

    class _StubContainer:
        def remove_children(self) -> None:
            pass

        def mount(self, widget) -> None:
            try:
                captured.append(widget.render())
            except Exception:
                captured.append(None)

    panel.query_one = MagicMock(return_value=_StubContainer())  # type: ignore[assignment]
    panel.call_after_refresh = MagicMock()  # type: ignore[assignment]
    panel._update_stats = MagicMock()  # type: ignore[assignment]
    panel._refresh_messages()
    return captured


def _has_link_span(content) -> bool:
    """Return True iff *content* contains an active ``link=`` span.

    The unescaped path renders ``[link=evil]X[/link]`` as a Rich Content
    with a ``Span(0, 1, style='link=evil')`` — that is the security
    failure mode we're asserting against.
    """
    if content is None:
        return False
    spans = getattr(content, "_spans", None) or []
    for span in spans:
        style = getattr(span, "style", "")
        if isinstance(style, str) and style.startswith("link="):
            return True
    return False


def test_refresh_messages_escapes_assistant_content(monkeypatch):
    """A2 — the assistant bubble renders ``[link=evil]X[/link]`` as plain text.

    Drives ``_refresh_messages`` against a session containing the
    malicious markup and asserts NO ``link=`` span ends up in the
    rendered Rich Content. If escaping is dropped the test fails with
    a real Link span on the assistant widget.
    """
    panel = _build_panel()
    _attach_app(panel)

    payload = "[link=evil]X[/link]"
    panel._session = ChatSession(
        id="s1",
        title="t",
        messages=[ChatMessage(role="assistant", content=payload)],
    )

    captured = _collect_rendered_static_widgets(panel)

    assert captured, "Expected at least one mounted Static"
    leaks = [c for c in captured if _has_link_span(c)]
    assert not leaks, (
        f"Assistant content leaked an active Link span — Rich markup "
        f"injection is possible: {leaks!r}"
    )
    # Also assert the literal payload appears in the plain text — proves
    # the escape path (rather than a strip path) ran.
    assert any(
        c is not None and "[link=evil]X[/link]" in c.plain
        for c in captured
    ), f"Expected literal markup in plain text: {captured!r}"


def test_refresh_messages_escapes_user_content():
    """A2 — user-role rows are escaped too (server-imported user rows untrusted)."""
    panel = _build_panel()
    _attach_app(panel)

    payload = "[bold red]injected[/bold red]"
    panel._session = ChatSession(
        id="s1",
        title="t",
        messages=[ChatMessage(role="user", content=payload)],
    )

    captured = _collect_rendered_static_widgets(panel)

    # The unsafe payload uses ``[bold red]`` — Rich would set ``style``
    # to ``"bold red"``. Assert no such span survived.
    leaks = []
    for content in captured:
        if content is None:
            continue
        for span in getattr(content, "_spans", None) or []:
            style = getattr(span, "style", "")
            if "bold red" in str(style):
                leaks.append(span)
    assert not leaks, (
        f"User content leaked styled spans: {leaks!r}"
    )
    assert any(
        c is not None and "[bold red]injected[/bold red]" in c.plain
        for c in captured
    )


def test_update_thinking_status_escapes_streamed_text():
    """A2 — token-stream accumulator escapes its content.

    This is the most security-critical site: every token delta passes
    through here, so an injected ``[link=evil]`` mid-stream would mount
    a real Link widget if escaping were missing.
    """
    panel = _build_panel()
    _attach_app(panel)

    captured: list = []

    class _StubWidget:
        def update(self, content: str) -> None:
            captured.append(content)

    panel.query_one = MagicMock(return_value=_StubWidget())  # type: ignore[assignment]

    panel._update_thinking_status("Hello [link=evil]click me[/link] world")

    assert captured, "No thinking-status update happened"
    assert (
        r"\[link=evil]click me\[/link]" in captured[0]
    ), f"Thinking status leaked unescaped markup: {captured!r}"
