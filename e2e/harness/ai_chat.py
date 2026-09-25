"""Seed AI set-ups and drive the chat panel the way a user does.

The seeders build every config through :class:`~e2e.harness.seed.HomeSeeder`
(the real schema). :func:`seed_byo` points one bring-your-own provider at
:class:`~e2e.harness.fake_ai.FakeAi` through the product's own
``ai_provider.base_url`` setting; :func:`seed_hosted` signs the home in to
FakeCloud with the hosted-AI entitlement. The chat helpers open the panel
with F2, type into its input, and read what the panel shows: the message
bubbles, the stats bar and the banner.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from e2e.harness import fleet
from e2e.harness.session_seed import seed_session
from e2e.harness.fake_ai import KEYS

# The relay is covered by its own journeys; these keep it switched off.
_NO_RELAY = {"mcp_connections": 0}
# The user has already answered the server-memory question (declined), so no
# consent prompt covers the chat.
_MEMORY_ANSWERED = {"chat_inject_server_memory_decision": "denied"}


def web_1_server() -> Any:
    """``web-1`` as a configured custom server (see ``fleet.WEB_1``)."""
    from servonaut.config.schema import CustomServer

    host = fleet.WEB_1
    return CustomServer(
        name=host.name,
        host=host.host,
        username=host.username,
        port=host.port,
        ssh_key=host.ssh_key,
        provider=host.provider,
        group=host.group,
    )


def byo_provider_config(provider: str, base_url: str, *, with_key: bool = True) -> Any:
    """An ``AIProviderConfig`` for *provider* served from *base_url*.

    The provider's own fabricated key goes in its own field. Ollama gets one
    only when *with_key* (Ollama Cloud); a local Ollama has none.
    """
    from servonaut.config.schema import AIProviderConfig

    config = AIProviderConfig(provider=provider, base_url=base_url, model="")
    if provider != "ollama" or with_key:
        setattr(config, f"{provider}_api_key", KEYS[provider])
    return config


def seed_byo(
    seed: Any,
    fake_cloud: Any,
    provider: str,
    base_url: str,
    *,
    signed_in: bool,
    with_key: bool = True,
    **config: Any,
) -> None:
    """A home with *provider* configured, optionally signed in to the service."""
    fake_cloud.configure(**_NO_RELAY)
    ai_provider = byo_provider_config(provider, base_url, with_key=with_key)
    seed.config(ai_provider=ai_provider, **{**_MEMORY_ANSWERED, **config})
    seed.cache(fleet.cache_rows(), fresh=True)
    if signed_in:
        seed_session(seed.home, fake_cloud)


def seed_hosted(
    seed: Any, fake_cloud: Any, *, dangerous_tools: bool = False, **config: Any
) -> Path:
    """A home signed in with the hosted-AI entitlement and no other provider.

    *dangerous_tools* adds the team-admin entitlement that unlocks the
    dangerous AI tools to the saved session, in ``custom_limits`` where the
    service reports it. FakeCloud's entitlements leave the flag out, and a
    refresh keeps a flag the answer does not mention.
    """
    fake_cloud.configure(**_NO_RELAY)
    seed.config(**{**_MEMORY_ANSWERED, **config})
    seed.cache(fleet.cache_rows(), fresh=True)
    path = seed_session(seed.home, fake_cloud)
    if dangerous_tools:
        token = json.loads(path.read_text(encoding="utf-8"))
        token["entitlements"]["custom_limits"] = {"allow_dangerous_ai_tools": True}
        token["allow_dangerous_ai_tools"] = True
        path.write_text(json.dumps(token, indent=2), encoding="utf-8")
    return path


def audit_rows(home: Path, *, source: Optional[str] = None) -> list[dict[str, Any]]:
    """Rows of the MCP audit trail in *home*, optionally from one source."""
    path = home / ".servonaut" / "mcp_audit.jsonl"
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    return [row for row in rows if source is None or row.get("source") == source]


# ---------------------------------------------------------------------------
# Toasts
# ---------------------------------------------------------------------------


def shown(toast: Any) -> str:
    """The text a toast puts on screen: its markup rendered, if it is markup.

    Malformed markup raises ``MarkupError`` here, as it would in the app.
    """
    from textual.content import Content

    return Content.from_markup(toast.message).plain if toast.markup else toast.message


async def wait_for_literal_toast(t: Any, text: str, *, severity: Optional[str] = None) -> Any:
    """Wait for a toast that is exactly *text*, raised with markup off.

    For toasts that carry text from the service, a file or the user: with
    markup on, brackets in that text would be interpreted.
    """
    toast = await t.wait_for_toast_record(f"^{re.escape(text)}$", severity=severity)
    assert toast.markup is False, f"a toast carrying outside text has markup on: {toast}"
    return toast


async def wait_for_shown_toast(t: Any, text: str, *, severity: Optional[str] = None) -> Any:
    """Wait for a toast that shows exactly *text* on screen, markup or not."""

    def match() -> Any:
        for toast in t.toast_records():
            if severity in (None, toast.severity) and shown(toast) == text:
                return toast
        return None

    return await t.wait_until(match, desc=f"a toast showing {text!r}")


# ---------------------------------------------------------------------------
# The chat panel
# ---------------------------------------------------------------------------


def plain(widget: Any) -> str:
    """The text a Static shows, without its styling."""
    rendered = widget.render()
    return getattr(rendered, "plain", None) or str(rendered)


def panel(t: Any) -> Any:
    from servonaut.widgets.chat_panel import ChatPanel

    return t.find_one("#chat-panel", ChatPanel)


def bubbles(t: Any) -> list[tuple[str, str]]:
    """The rows the panel shows, as (kind, text).

    Kinds: welcome, user, assistant, tool, thinking. Rows on their way out
    (the panel rebuilds its list after every turn) are not shown, so they
    are left out.
    """
    container = panel(t).query_one("#chat-messages")
    rows = []
    for child in container.children:
        if not child.display:
            continue
        classes = child.classes
        if "chat-welcome" in classes:
            kind = "welcome"
        elif "chat-thinking" in classes:
            kind = "thinking"
        elif "chat-message-user" in classes:
            kind = "user"
        elif "chat-message-tool" in classes:
            kind = "tool"
        elif "chat-message-assistant" in classes:
            kind = "assistant"
        else:
            continue
        rows.append((kind, plain(child)))
    return rows


def replies(t: Any) -> list[str]:
    """Text of the assistant bubbles, without the "Servonaut" header line."""
    return [text.split("\n", 1)[-1] for kind, text in bubbles(t) if kind == "assistant"]


def stats(t: Any) -> str:
    return plain(panel(t).query_one("#chat-stats"))


def banner(t: Any) -> str:
    widget = panel(t).query_one("#chat-banner")
    return "" if widget.has_class("hidden") else plain(widget)


def busy(t: Any) -> bool:
    """True while a turn is in flight (the input refuses new sends)."""
    return bool(panel(t)._thinking)


async def open_chat(t: Any, *, prompt: Optional[str] = None) -> Any:
    """Press F2 and wait for the chat input to take the focus.

    When the panel opens with a prompt on top (*prompt*, a screen name),
    wait for that prompt instead.
    """
    await t.press("f2")
    if prompt is not None:
        await t.wait_for_screen(prompt)
    else:
        await t.wait_until(lambda: t.focused_id() == "chat-input", desc="chat input focused")
    return panel(t)


async def focus_input(t: Any) -> None:
    """Put the cursor in the chat input, clicking it when it is not focused.

    Toasts stack over the bottom-right corner, where the input ends, so the
    click goes to the input's first column rather than its middle.
    """
    field = panel(t).query_one("#chat-input")
    if field.has_focus:
        return
    if not await t.pilot.click(field, offset=(1, 0)):
        raise AssertionError("the click meant for the chat input landed elsewhere")
    await t.wait_until(lambda: field.has_focus, desc="chat input focused")


async def send(t: Any, text: str) -> None:
    """Type *text* into the chat input and press Enter."""
    await focus_input(t)
    await t.type(text)
    await t.press("enter")
    await t.wait_until(
        lambda: any(kind == "user" and text in body for kind, body in bubbles(t)) or busy(t),
        desc="message sent",
    )


async def wait_for_reply(t: Any, *, timeout: float = 10.0) -> list[str]:
    """Wait until the turn is over and return the assistant replies."""
    await t.wait_until(lambda: not busy(t), timeout=timeout, desc="the turn to finish")
    return replies(t)
