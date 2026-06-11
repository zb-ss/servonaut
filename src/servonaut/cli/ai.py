"""CLI subcommand handlers for ``servonaut ai`` (Wave 3 / Agent H — T9).

Mirrors the shape of :mod:`servonaut.cli.memory`:

- :func:`add_ai_parser` registers the ``ai`` parser on the top-level
  ``subparsers`` action and returns the parser so :mod:`servonaut.main`
  can dispatch on ``args.subcommand == 'ai'``.
- :func:`handle_ai_command` is the synchronous entry point invoked by
  ``main.py``; it dispatches on ``args.ai_command`` and returns an
  integer exit code.

Subcommand tree (per plan T9 + architect plan §T9):

    servonaut ai chat <prompt>           [--stream] [--no-tools] [--tools]
                                          [--ai-provider X] [--task TASK]
    servonaut ai quota                    [--json]
    servonaut ai conversations list       [--limit N] [--before ISO]
                                          [--status STATUS] [--json]
    servonaut ai conversations show UUID  [--json]
    servonaut ai conversations export UUID PATH
                                          [--format md|json] [--force]
    servonaut ai conversations archive UUID
    servonaut ai conversations delete UUID
    servonaut ai topup [PACK]             # small | medium | large
    servonaut ai provider reset

All Servonaut-AI-only commands gate on:

- ``auth.is_authenticated`` → exit 2 (with stderr "log in first") if False.
- ``auth.has_feature("premium_ai")`` → exit 3 (with /pricing link) if False.

``--ai-provider`` and ``SERVONAUT_AI_PROVIDER`` env var both bypass
:class:`ProviderPreferenceResolver` for one process; they do NOT persist.
The flag wins over the env var (argparse already enforces that ordering
since the CLI flag is checked first in
:func:`_resolve_per_session_provider`).

This module deliberately does NOT touch the chat panel, ``app.py`` or any
screen — those are owned by the sibling Wave 3 chat-panel agent.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import webbrowser
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exit codes (consistent with cli/memory.py)
# ---------------------------------------------------------------------------
_EXIT_SUCCESS = 0
_EXIT_GENERIC_ERROR = 1
_EXIT_UNAUTHENTICATED = 2
_EXIT_NOT_ENTITLED = 3
_EXIT_USAGE_ERROR = 4

# Hard-coded top-up packs as documented in the plan §"Top-up checkout".
# The server is authoritative; this is a UX fallback when no live pack
# table is available (mirrors plan T9 spec).
_TOPUP_PACKS = ("small", "medium", "large")

# Valid task enum (mirrors backend AiChatController + servonaut_provider).
_VALID_TASKS = ("chat", "analyze_logs", "security_audit",
                "cost_report", "incident_triage")

# Valid conversation statuses (mirrors AIConversationsClient).
_VALID_STATUSES = ("active", "archived", "deleted")

_LOGIN_HINT = "Log in first: run `servonaut login`"
_UPGRADE_HINT = (
    "Servonaut AI requires the Solo or Teams plan: "
    "https://servonaut.dev/pricing"
)


# ---------------------------------------------------------------------------
# Async wrapper
# ---------------------------------------------------------------------------

def _run_async(coro: Coroutine[Any, Any, Any]) -> Any:
    """Run *coro* synchronously via :func:`asyncio.run`.

    Mirrors :func:`servonaut.cli.memory._run_async` for consistency.

    D6 — type hint widened from ``Awaitable`` to ``Coroutine`` so static
    analysers see the precise shape :func:`asyncio.run` consumes.
    """
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Headless service initialisation
# ---------------------------------------------------------------------------


def _init_headless_services() -> Tuple[Any, Any, Any, Any, Any, Any]:
    """Construct the minimum service set the ``ai`` subcommands need.

    Returns ``(config_manager, auth, api_client, provider, conversations_client,
    pref_resolver)``.  Mirrors the wiring documented in the agent brief so
    headless callers behave identically to the TUI's ``app.py``.
    """
    from servonaut.config.manager import ConfigManager
    from servonaut.services.api_client import APIClient
    from servonaut.services.auth_service import AuthService
    from servonaut.services.ai_conversations import AIConversationsClient
    from servonaut.services.ai_provider_preference import (
        ProviderPreferenceResolver,
    )
    from servonaut.services.ai_providers.servonaut_provider import (
        ServonautProvider,
    )

    config_manager = ConfigManager()
    auth = AuthService()
    api_client = APIClient(auth)
    provider = ServonautProvider(api_client, auth)
    conversations_client = AIConversationsClient(api_client)
    pref_resolver = ProviderPreferenceResolver(auth, config_manager)
    return (
        config_manager,
        auth,
        api_client,
        provider,
        conversations_client,
        pref_resolver,
    )


# ---------------------------------------------------------------------------
# Auth / entitlement gates
# ---------------------------------------------------------------------------


def _gate_authenticated(auth: Any) -> Optional[int]:
    """Return an exit code when caller is not authenticated; ``None`` otherwise."""
    if not getattr(auth, "is_authenticated", False):
        print(_LOGIN_HINT, file=sys.stderr)
        return _EXIT_UNAUTHENTICATED
    return None


def _gate_premium_ai(auth: Any) -> Optional[int]:
    """Return an exit code when caller lacks ``premium_ai`` entitlement.

    Runs after :func:`_gate_authenticated`; callers should chain both.
    """
    has_feature = getattr(auth, "has_feature", None)
    if has_feature is None or not has_feature("premium_ai"):
        print(_UPGRADE_HINT, file=sys.stderr)
        return _EXIT_NOT_ENTITLED
    return None


def _resolve_per_session_provider(args: argparse.Namespace) -> Optional[str]:
    """Pick a per-session provider override.

    Order:
        1. ``--ai-provider`` flag on the parsed args (top-level flag from
           ``main.py`` OR the ``ai chat`` subcommand flag, whichever is set).
        2. ``SERVONAUT_AI_PROVIDER`` environment variable.
        3. ``None`` — caller falls back to the resolver's preference.

    The flag wins over the env var by being checked first.
    """
    flag = getattr(args, "ai_provider", None)
    if flag:
        return flag
    env_value = os.environ.get("SERVONAUT_AI_PROVIDER")
    if env_value:
        return env_value
    return None


# ---------------------------------------------------------------------------
# Subcommand: ai chat
# ---------------------------------------------------------------------------


def _handle_chat(args: argparse.Namespace) -> int:
    """Implement ``servonaut ai chat <prompt>``.

    Buffered mode by default (single ``provider.chat`` call → final content
    on stdout). ``--stream`` switches to ``provider.stream_chat`` and writes
    tokens to stdout line-buffered as they arrive.

    The ``--no-tools`` flag flips ``allow_tools=False`` on the request body
    so the server emits no ``tool_call`` events. Useful for one-shot
    scripted use where the caller doesn't want any side effects.
    """
    (
        _config_manager,
        auth,
        _api,
        provider,
        _convs,
        _pref,
    ) = _init_headless_services()

    code = _gate_authenticated(auth)
    if code is not None:
        return code
    code = _gate_premium_ai(auth)
    if code is not None:
        return code

    prompt: str = args.prompt
    if not prompt or not prompt.strip():
        print("Error: prompt cannot be empty.", file=sys.stderr)
        return _EXIT_USAGE_ERROR

    task: str = getattr(args, "task", None) or "chat"
    if task not in _VALID_TASKS:
        print(
            f"Error: --task must be one of {list(_VALID_TASKS)!r}.",
            file=sys.stderr,
        )
        return _EXIT_USAGE_ERROR

    # --no-tools (CLI flag OR env var inherited from main.py top-level).
    no_tools = bool(getattr(args, "no_tools", False)) or bool(
        os.environ.get("SERVONAUT_AI_NO_TOOLS")
    )
    allow_tools = not no_tools

    # Buffered mode defaults tools OFF: tool calls are executed by the TUI
    # chat panel or a running `servonaut connect` listener — without one,
    # a tool-requiring prompt blocks for the server's full wall-clock cap
    # and comes back degraded. --tools opts back in; --no-tools always wins.
    use_stream = bool(getattr(args, "stream", False))
    if not use_stream and allow_tools and not bool(getattr(args, "tools", False)):
        allow_tools = False
        print(
            "Note: tool execution is disabled in buffered headless chat by "
            "default. Start `servonaut connect` (the relay listener "
            "executes dispatched tools) and pass --tools to opt in, or use "
            "the TUI chat panel.",
            file=sys.stderr,
        )

    # Per-session provider override is resolved + threaded into env var so
    # the chat-panel TUI (sister Agent G) honours it without a side-channel.
    # For the headless CLI we currently only call the Servonaut provider —
    # if the override is non-servonaut we honour the user's expectation that
    # we exit with a clear message rather than silently ignore it.
    override = _resolve_per_session_provider(args)
    if override and override != "servonaut":
        print(
            f"Error: 'servonaut ai chat' uses the Servonaut provider; "
            f"--ai-provider={override!r} is only honoured inside the TUI.",
            file=sys.stderr,
        )
        return _EXIT_USAGE_ERROR

    from servonaut.config.schema import AIProviderConfig

    config = AIProviderConfig(provider="servonaut")
    messages: List[dict] = []

    instance_ids: List[str] = list(getattr(args, "instance", []) or [])
    if instance_ids:
        memory_block = _build_cli_memory_block(prompt, instance_ids)
        if memory_block:
            messages.append({"role": "user", "content": memory_block})

    messages.append({"role": "user", "content": prompt})

    if use_stream:
        return _run_async(
            _do_chat_stream(provider, messages, config, task, allow_tools)
        )
    return _run_async(
        _do_chat_buffered(provider, messages, config, task, allow_tools)
    )


def _build_cli_memory_block(prompt: str, instance_ids: List[str]) -> str:
    """Assemble a <CONTEXT> body for ``servonaut ai chat --instance …``.

    Best-effort: any failure to load memory falls through to today's
    stateless prompt — the user still gets a chat reply, just without
    pre-injected context.

    Args:
        prompt: Raw user prompt — drives conditional module curation
            (``logs``/``disk``/``databases``/``git``).
        instance_ids: One or more --instance values from argparse.

    Returns:
        Concatenated ``<CONTEXT>…</CONTEXT>`` blocks, or ``""``.
    """
    try:
        from servonaut.cli.memory import _init_headless_services
    except Exception:
        return ""
    try:
        config, memory_service, *_ = _init_headless_services()
    except Exception as exc:  # noqa: BLE001 — best-effort
        logger.debug("memory injector skipped (init failed): %s", exc)
        return ""

    # Tri-state consent gate — the CLI cannot show a modal, so an
    # "unset" decision prints a one-line hint to stderr and skips
    # injection.  The user's chat reply is still produced (no
    # --instance memory, today's stateless behaviour).  An "unset"
    # decision will flip to "allowed"/"denied" the moment the user
    # opens the TUI and triggers a chat with an in-scope server.
    decision = getattr(config, "chat_inject_server_memory_decision", "unset")
    if decision == "unset":
        print(
            "Note: --instance memory injection is gated by a one-time "
            "consent prompt that runs on the first TUI chat with a "
            "server in scope. Open Servonaut, send one prompt about a "
            "server, accept the modal — then this flag will work. "
            "(Skipping injection for this turn.)",
            file=sys.stderr,
        )
        return ""
    if decision == "denied":
        return ""
    if not getattr(config, "chat_inject_server_memory", False):
        return ""

    config_memory = getattr(config, "memory", None)
    if config_memory is None:
        return ""

    from servonaut.services.ai_memory_injector import (
        InstanceScope, build_memory_context,
    )

    # Look up provider per instance from the local memory index so opt-out
    # checks (which are keyed by both id+name) match what the TUI does.
    try:
        index = {row.get("instance_id"): row
                 for row in memory_service.list_all() or []}
    except Exception:
        index = {}

    scopes: List[InstanceScope] = []
    seen: set = set()
    for raw in instance_ids:
        if not raw or raw in seen:
            continue
        seen.add(raw)
        idx_row = index.get(raw, {}) or {}
        scopes.append(InstanceScope(
            id=raw,
            name=idx_row.get("name") or "",
            provider=idx_row.get("provider") or "custom",
        ))
    if not scopes:
        return ""

    try:
        body, telemetry = build_memory_context(
            instances=scopes,
            prompt=prompt,
            memory_service=memory_service,
            config_memory=config_memory,
            redaction_enabled=getattr(config_memory, "redaction_enabled", True),
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("memory injector skipped (build failed): %s", exc)
        return ""

    if body:
        logger.info("memory_injector chat=cli %s", telemetry.as_log_kv())
    return body


async def _do_chat_buffered(
    provider: Any,
    messages: List[dict],
    config: Any,
    task: str,
    allow_tools: bool,
) -> int:
    """Buffered one-shot chat — prints ``content`` to stdout.

    C2 fix — calls the public :meth:`ServonautProvider.chat` (now wider)
    instead of the private ``_chat_internal`` hop. The previous code
    leaked an internal API into a tested public surface.
    """
    from servonaut.services.api_client import APIError

    try:
        result = await provider.chat(
            messages=messages,
            system_prompt="",
            config=config,
            tools=None,
            task=task,
            allow_tools=allow_tools,
        )
    except APIError as exc:
        # T5 owns the rich UX mapping; here we degrade to a single-line
        # error so the CLI is scriptable. The error code is the most
        # actionable detail (rate_limited / quota_exhausted / ...).
        print(f"Error [{exc.code}]: {exc.message}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR
    except Exception as exc:  # noqa: BLE001 — last-resort defence
        logger.exception("Buffered chat failed")
        # str() of some httpx exceptions (e.g. ReadTimeout) is empty —
        # fall back to the class name so the user never sees "Error: ".
        print(f"Error: {exc or type(exc).__name__}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR

    result = result or {}
    warning = result.get("warning", "") or ""
    if warning:
        print(f"Warning: {warning}", file=sys.stderr)

    content = result.get("content", "") or ""
    if content:
        print(content)
        return _EXIT_SUCCESS

    # Empty content is never a success for a one-shot CLI. The common cause:
    # the model answered with a tool call, which only the TUI chat panel can
    # confirm and execute — buffered headless chat has no tool bridge.
    tool_calls_count = int(result.get("tool_calls_count") or 0)
    if tool_calls_count > 0 or result.get("stop_reason") == "tool_use":
        print(
            "Error: the model requested a tool call to answer this prompt, "
            "but headless chat cannot execute tools. Ask in the TUI chat "
            "panel (F2) where tools run with confirmation, or re-run with "
            "--no-tools for a text-only answer.",
            file=sys.stderr,
        )
    else:
        print("Error: the server returned an empty response.", file=sys.stderr)
    return _EXIT_GENERIC_ERROR


async def _do_chat_stream(
    provider: Any,
    messages: List[dict],
    config: Any,
    task: str,
    allow_tools: bool,
) -> int:
    """Streaming chat — writes tokens to stdout line-buffered, no ANSI.

    Final ``done`` event triggers a newline + summary line of the form
    ``-- model=<m> tokens=<sum>`` so scripted callers can tee the body
    apart from the metadata trailer.
    """
    from servonaut.services.api_client import APIError

    last_usage: dict = {}
    saw_any_token = False

    try:
        async for event in provider.stream_chat(
            messages,
            "",
            config,
            allow_tools=allow_tools,
            task=task,
        ):
            etype = (event or {}).get("event")
            data = (event or {}).get("data") or {}
            if etype == "token":
                text = data.get("text") or ""
                if text:
                    sys.stdout.write(text)
                    sys.stdout.flush()
                    saw_any_token = True
            elif etype == "usage":
                last_usage = data
            elif etype == "info":
                # Server-emitted informational events ("tool_round_limit",
                # "wall_clock_cap_exceeded") — surface to stderr so they
                # don't pollute stdout but the user still sees them.
                code = data.get("code", "")
                msg = data.get("message", "")
                print(f"\n[{code}] {msg}", file=sys.stderr)
            elif etype == "done":
                break
            # tool_call / tool_result events are not actionable in the
            # headless CLI — the chat-panel agent owns the bridge. We
            # surface their existence to stderr so the user knows a tool
            # ran and they should switch to the TUI for full execution.
            elif etype == "tool_call":
                tool = data.get("tool", "<unknown>")
                print(
                    f"\n[tool_call] {tool} (TUI required to confirm/execute)",
                    file=sys.stderr,
                )
    except APIError as exc:
        print(f"\nError [{exc.code}]: {exc.message}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR
    except Exception as exc:  # noqa: BLE001
        logger.exception("Stream chat failed")
        print(f"\nError: {exc}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR

    # Final newline so the prompt sits on its own row in interactive shells.
    if saw_any_token:
        sys.stdout.write("\n")
        sys.stdout.flush()

    if last_usage:
        model = last_usage.get("model", "")
        in_tokens = int(last_usage.get("input_tokens") or 0)
        out_tokens = int(last_usage.get("output_tokens") or 0)
        total = in_tokens + out_tokens
        print(
            f"-- model={model} tokens={total} "
            f"(in={in_tokens} out={out_tokens})",
            file=sys.stderr,
        )
    return _EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Subcommand: ai quota
# ---------------------------------------------------------------------------


def _handle_quota(args: argparse.Namespace) -> int:
    """Implement ``servonaut ai quota`` — print the current AIQuota.

    JSON mode (``--json``) emits the result of :py:meth:`AIQuota.to_dict`
    so it can be piped through ``jq``. Human mode prints a 5-line summary
    using :mod:`servonaut.utils.formatting` helpers (consistent with the
    chat-panel footer rendering).
    """
    (
        _config_manager,
        auth,
        _api,
        _provider,
        _convs,
        _pref,
    ) = _init_headless_services()

    code = _gate_authenticated(auth)
    if code is not None:
        return code
    code = _gate_premium_ai(auth)
    if code is not None:
        return code

    use_json = bool(getattr(args, "json", False))

    # Refresh entitlements first so the quota numbers reflect the latest
    # /api/entitlements snapshot. Any error here is non-fatal — we fall
    # back to the cached AuthToken state.
    async def _refresh() -> None:
        try:
            await auth.fetch_entitlements()
        except Exception:  # noqa: BLE001
            logger.debug("Entitlements refresh failed; using cached state")

    try:
        _run_async(_refresh())
    except Exception:  # noqa: BLE001
        pass

    from servonaut.services.ai_quota import AIQuota

    token = getattr(auth, "_token", None)
    raw_quota = None
    if token is not None and isinstance(getattr(token, "entitlements", None), dict):
        raw_quota = token.entitlements.get("quota")

    quota = AIQuota.from_dict(raw_quota)

    if use_json:
        if quota is None:
            print(json.dumps({"quota": None}))
        else:
            print(json.dumps(quota.to_dict(), indent=2))
        return _EXIT_SUCCESS

    if quota is None:
        print("Quota: unavailable (free plan or entitlements not yet fetched).")
        return _EXIT_SUCCESS

    from servonaut.utils.formatting import (
        format_resets_at,
        format_soft_cap_badge,
        format_tokens_remaining,
    )

    remaining = format_tokens_remaining(
        quota.tokens_used, quota.tokens_limit, quota.tokens_topup_remaining
    )
    resets = format_resets_at(quota.resets_at) or "unknown"
    badge = format_soft_cap_badge(quota.soft_capped, quota.hard_capped) or "OK"
    queries = quota.estimated_queries_remaining()

    print(f"Tokens remaining: {remaining}")
    print(f"≈ {queries} queries (5k tokens/query rolling avg)")
    print(f"Resets: {resets}")
    print(f"Status: {badge}")
    print(f"Rate limits: {quota.rpm_limit} req/min, "
          f"{quota.tokens_per_minute_limit} tokens/min")
    return _EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Subcommand: ai conversations …
# ---------------------------------------------------------------------------


def _handle_conversations_list(
    args: argparse.Namespace,
    convs: Any,
) -> int:
    limit = int(getattr(args, "limit", 25) or 25)
    before = getattr(args, "before", None)
    status = getattr(args, "status", "active") or "active"
    use_json = bool(getattr(args, "json", False))

    if status not in _VALID_STATUSES:
        print(
            f"Error: --status must be one of {list(_VALID_STATUSES)!r}",
            file=sys.stderr,
        )
        return _EXIT_USAGE_ERROR

    async def _do() -> List[Any]:
        return await convs.list(limit=limit, before=before, status=status)

    try:
        items = _run_async(_do())
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR

    if use_json:
        out = [
            {
                "id": s.id,
                "title": s.title,
                "status": s.status,
                "created_at": s.created_at,
                "updated_at": s.updated_at,
                "message_count": s.message_count,
                "last_model": s.last_model,
            }
            for s in items
        ]
        print(json.dumps(out, indent=2))
        return _EXIT_SUCCESS

    if not items:
        print("(no conversations)")
        return _EXIT_SUCCESS

    try:
        from tabulate import tabulate

        rows = [
            [s.id, s.title[:40], s.status, s.updated_at, s.message_count]
            for s in items
        ]
        print(tabulate(
            rows,
            headers=["ID", "Title", "Status", "Updated", "#msgs"],
            tablefmt="simple",
        ))
    except ImportError:
        # Fallback: tabulate is a hard dep but defensively degrade.
        for s in items:
            print(
                f"{s.id}  {s.status}  {s.updated_at}  "
                f"({s.message_count} msgs)  {s.title}"
            )
    return _EXIT_SUCCESS


def _handle_conversations_show(
    args: argparse.Namespace,
    convs: Any,
) -> int:
    uuid = args.uuid
    use_json = bool(getattr(args, "json", False))

    async def _do() -> dict:
        return await convs.get(uuid)

    try:
        thread = _run_async(_do())
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR

    if use_json:
        print(json.dumps(thread, indent=2))
        return _EXIT_SUCCESS

    title = thread.get("title", "(untitled)")
    print(f"# {title}\n")
    for msg in thread.get("messages", []) or []:
        role = msg.get("role", "?")
        content = msg.get("content", "")
        print(f"## {role}\n\n{content}\n")
    return _EXIT_SUCCESS


def _handle_conversations_export(
    args: argparse.Namespace,
    convs: Any,
) -> int:
    uuid: str = args.uuid
    raw_path: str = args.path
    fmt: str = (getattr(args, "format", None) or "md").lower()
    force: bool = bool(getattr(args, "force", False))

    if fmt not in ("md", "json"):
        print("Error: --format must be 'md' or 'json'.", file=sys.stderr)
        return _EXIT_USAGE_ERROR

    dest = Path(raw_path)
    # A6 — pass ``force`` to the client's validator instead of unlinking
    # eagerly. The previous code unlinked BEFORE path-traversal validation,
    # so ``--force /etc/sudoers`` could attempt to delete a file outside
    # CWD/~Downloads even though the export itself would have been
    # rejected. Validation now runs first; unlink-on-overwrite happens
    # only after the path is proven safe.

    async def _do() -> Path:
        if fmt == "md":
            return await convs.export_md(uuid, dest, force=force)
        return await convs.export_json(uuid, dest, force=force)

    try:
        written = _run_async(_do())
    except FileExistsError as exc:
        print(f"Error: {exc} (use --force to overwrite)", file=sys.stderr)
        return _EXIT_USAGE_ERROR
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return _EXIT_USAGE_ERROR
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR

    print(f"Exported to {written}")
    return _EXIT_SUCCESS


def _handle_conversations_archive(
    args: argparse.Namespace,
    convs: Any,
) -> int:
    async def _do() -> dict:
        return await convs.patch(args.uuid, status="archived")

    try:
        _run_async(_do())
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR
    print(f"Archived {args.uuid}")
    return _EXIT_SUCCESS


def _handle_conversations_delete(
    args: argparse.Namespace,
    convs: Any,
) -> int:
    async def _do() -> None:
        await convs.delete(args.uuid)

    try:
        _run_async(_do())
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR
    print(f"Deleted {args.uuid}")
    return _EXIT_SUCCESS


def _handle_conversations(args: argparse.Namespace) -> int:
    """Dispatch ``servonaut ai conversations <subcmd>``."""
    sub = getattr(args, "conversations_command", None)
    if sub is None:
        print(
            "Error: specify 'list', 'show', 'export', 'archive', or 'delete'.",
            file=sys.stderr,
        )
        return _EXIT_USAGE_ERROR

    (
        _config_manager,
        auth,
        _api,
        _provider,
        convs,
        _pref,
    ) = _init_headless_services()

    code = _gate_authenticated(auth)
    if code is not None:
        return code
    code = _gate_premium_ai(auth)
    if code is not None:
        return code

    # D6 — explicit Dict[str, Callable[..., int]] so a regression that
    # adds a non-int-returning handler shows up in type-check output.
    dispatch: Dict[str, Callable[[argparse.Namespace, Any], int]] = {
        "list": _handle_conversations_list,
        "show": _handle_conversations_show,
        "export": _handle_conversations_export,
        "archive": _handle_conversations_archive,
        "delete": _handle_conversations_delete,
    }
    handler = dispatch.get(sub)
    if handler is None:
        print(f"Error: unknown conversations subcommand {sub!r}",
              file=sys.stderr)
        return _EXIT_USAGE_ERROR
    return handler(args, convs)


# ---------------------------------------------------------------------------
# Subcommand: ai topup
# ---------------------------------------------------------------------------


def _handle_topup(args: argparse.Namespace) -> int:
    """Implement ``servonaut ai topup [pack]``.

    With a pack argument: directly drive the checkout — calls
    ``provider.topup_checkout(pack)`` (defined by sister Agent G as part
    of T8) and opens the returned URL in the user's default browser.
    Without a pack: prints the static pack table from the plan and asks
    the caller to re-run with a pack arg.

    Post-launch, schedules a delayed entitlements refresh via
    ``auth.schedule_post_topup_refresh()`` so the new
    ``tokens_topup_remaining`` shows up within ~60s of the Stripe
    webhook completing.
    """
    (
        _config_manager,
        auth,
        _api,
        provider,
        _convs,
        _pref,
    ) = _init_headless_services()

    code = _gate_authenticated(auth)
    if code is not None:
        return code
    code = _gate_premium_ai(auth)
    if code is not None:
        return code

    pack: Optional[str] = getattr(args, "pack", None)
    if not pack:
        # No pack arg → print the static table and exit cleanly.
        print("Available top-up packs:")
        for name in _TOPUP_PACKS:
            print(f"  - {name}")
        print(
            "\nRun `servonaut ai topup <pack>` to launch a Stripe Checkout "
            "for that pack."
        )
        return _EXIT_SUCCESS

    if pack not in _TOPUP_PACKS:
        print(
            f"Error: unknown pack {pack!r}; expected one of "
            f"{list(_TOPUP_PACKS)!r}.",
            file=sys.stderr,
        )
        return _EXIT_USAGE_ERROR

    async def _do() -> str:
        # ``topup_checkout`` lands with sister Wave 3 Agent G (T8).
        # Until that merges, the AttributeError surface below documents
        # the dependency clearly to the user.
        return await provider.topup_checkout(pack)

    try:
        url = _run_async(_do())
    except AttributeError:
        print(
            "Error: top-up checkout helper not yet wired in this build "
            "(Agent G / T8 dependency).",
            file=sys.stderr,
        )
        return _EXIT_GENERIC_ERROR
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR

    if not url:
        print("Error: server returned no checkout URL.", file=sys.stderr)
        return _EXIT_GENERIC_ERROR

    # A4 — only auto-launch the browser when the URL is a Stripe-hosted
    # checkout origin. A buggy / compromised gateway returning a different
    # host must not silently redirect the user.
    from servonaut.services.ai_providers.servonaut_provider import (
        is_valid_stripe_checkout_url,
    )

    if not is_valid_stripe_checkout_url(url):
        logger.warning(
            "Top-up checkout returned non-Stripe URL %r — refusing auto-open",
            url,
        )
        print(
            f"Refusing to auto-open non-Stripe URL. Open this URL manually: {url}",
            file=sys.stderr,
        )
    else:
        opened = False
        try:
            opened = bool(webbrowser.open(url))
        except Exception:  # noqa: BLE001
            opened = False

        print(f"Opening checkout for {pack!r} pack: {url}", flush=True)
        if not opened:
            print("(could not auto-launch browser; copy the URL above)",
                  flush=True)

    # B3 — block inline for the post-checkout entitlements refresh. The
    # TUI variant (:meth:`schedule_post_topup_refresh`) uses
    # :func:`asyncio.create_task`, which works against a long-running
    # event loop; in a one-shot CLI invocation those tasks die when
    # ``asyncio.run`` returns, leaving ``tokens_topup_remaining`` stale
    # forever. ``await_post_topup_refresh`` sleeps inline ~45s then
    # refreshes once — the user's CLI process waits, but the spec'd
    # T8 acceptance bullet ("balance reflected within 60s") is honoured.
    await_refresh = getattr(auth, "await_post_topup_refresh", None)
    if callable(await_refresh):
        try:
            _run_async(await_refresh(lambda msg: print(msg)))
        except KeyboardInterrupt:
            # The purchase is already done — interrupting the courtesy
            # wait is not a failure.
            print(
                "\nSkipping the entitlement refresh (your top-up is "
                "unaffected). Run `servonaut ai quota` in ~60s to see "
                "the new balance.",
                file=sys.stderr,
            )
        except Exception:  # noqa: BLE001
            logger.debug(
                "await_post_topup_refresh raised; continuing.",
            )
    else:
        # Backward-compat with older AuthService that only ships the TUI
        # variant: best-effort schedule, document the gap to the user.
        schedule = getattr(auth, "schedule_post_topup_refresh", None)
        if callable(schedule):
            try:
                # Old TUI variant — coroutine is created but never awaited
                # in a way that survives. Surface the limitation.
                result = schedule()
                if asyncio.iscoroutine(result):
                    _run_async(result)
            except Exception:  # noqa: BLE001
                logger.debug(
                    "schedule_post_topup_refresh raised; continuing.",
                )
        print(
            "Run `servonaut ai quota` in ~60s to confirm the new balance.",
            file=sys.stderr,
        )
    return _EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Subcommand: ai provider reset
# ---------------------------------------------------------------------------


def _handle_provider(args: argparse.Namespace) -> int:
    """Dispatch ``servonaut ai provider <subcmd>``.

    Currently only ``reset`` is supported (clears
    ``ai.provider_preference`` and dismissed-banner flags).
    """
    sub = getattr(args, "provider_command", None)
    if sub != "reset":
        print(
            "Error: only 'servonaut ai provider reset' is supported today.",
            file=sys.stderr,
        )
        return _EXIT_USAGE_ERROR

    # 'provider reset' does not require auth/entitlement — it's a local
    # config nuke. This matches the user's expectation that they can clear
    # a stuck preference even when offline / logged out.
    (
        _config_manager,
        _auth,
        _api,
        _provider,
        _convs,
        pref,
    ) = _init_headless_services()
    try:
        pref.reset()
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return _EXIT_GENERIC_ERROR
    print("OK")
    return _EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Argparse registration
# ---------------------------------------------------------------------------


def add_ai_parser(subparsers: Any) -> argparse.ArgumentParser:
    """Register the ``ai`` parser on the top-level subparsers action.

    Mirrors the shape used by ``memory_parser`` in :mod:`servonaut.main`
    so the two subcommand trees stay visually consistent.
    """
    ai_parser = subparsers.add_parser(
        "ai",
        help="Manage Servonaut AI conversations, quota, top-ups, and provider preference.",
    )
    ai_sub = ai_parser.add_subparsers(dest="ai_command")
    ai_sub.required = True

    # ---- ai chat ---------------------------------------------------------
    chat_parser = ai_sub.add_parser(
        "chat",
        help="Send a one-shot prompt to Servonaut AI and print the reply.",
    )
    chat_parser.add_argument("prompt", help="Prompt text to send.")
    chat_parser.add_argument(
        "--stream",
        action="store_true",
        help="Stream tokens to stdout as they arrive (line-buffered, no ANSI).",
    )
    chat_parser.add_argument(
        "--no-tools",
        action="store_true",
        help="Disable tool execution (sets allow_tools:false on the request).",
    )
    chat_parser.add_argument(
        "--tools",
        action="store_true",
        help=(
            "Enable tool execution in buffered mode (off by default there: "
            "no headless executor exists yet, so a tool-requiring prompt "
            "would block until the server's wall-clock cap). --no-tools "
            "wins if both are given."
        ),
    )
    chat_parser.add_argument(
        "--ai-provider",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Per-process provider override (servonaut/openai/anthropic/"
            "ollama/gemini). Bypasses ai.provider_preference; not persisted."
        ),
    )
    chat_parser.add_argument(
        "--task",
        type=str,
        default="chat",
        choices=list(_VALID_TASKS),
        help="Task profile (default: chat).",
    )
    chat_parser.add_argument(
        "--instance", "-i",
        action="append",
        default=[],
        metavar="ID_OR_NAME",
        help=(
            "Inject locally-stored server memory for this instance into "
            "the chat as a <CONTEXT> block. Repeatable. Without this flag "
            "the prompt is sent stateless (today's behaviour)."
        ),
    )

    # ---- ai quota --------------------------------------------------------
    quota_parser = ai_sub.add_parser(
        "quota",
        help="Show current Servonaut AI quota.",
    )
    quota_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit AIQuota.to_dict() as JSON for scriptable use.",
    )

    # ---- ai conversations -----------------------------------------------
    conv_parser = ai_sub.add_parser(
        "conversations",
        help="List, show, export, archive, or delete saved chat threads.",
    )
    conv_sub = conv_parser.add_subparsers(dest="conversations_command")
    conv_sub.required = True

    conv_list = conv_sub.add_parser("list", help="List recent conversations.")
    conv_list.add_argument("--limit", type=int, default=25,
                           help="Max rows to return (default: 25, capped at 100).")
    conv_list.add_argument("--before", type=str, default=None,
                           metavar="ISO",
                           help="Pagination cursor (ISO 8601 timestamp).")
    conv_list.add_argument(
        "--status",
        type=str,
        default="active",
        choices=list(_VALID_STATUSES),
        help="Filter by status (default: active).",
    )
    conv_list.add_argument("--json", action="store_true",
                           help="Emit JSON instead of a table.")

    conv_show = conv_sub.add_parser("show", help="Print a full thread.")
    conv_show.add_argument("uuid", help="Conversation UUID.")
    conv_show.add_argument("--json", action="store_true",
                           help="Emit raw thread JSON instead of Markdown.")

    conv_export = conv_sub.add_parser(
        "export",
        help="Download a thread to disk (Markdown or JSON).",
    )
    conv_export.add_argument("uuid", help="Conversation UUID.")
    conv_export.add_argument("path", help="Destination path "
                                          "(must resolve under CWD or ~/Downloads).")
    conv_export.add_argument(
        "--format",
        type=str,
        default="md",
        choices=("md", "json"),
        help="Export format (default: md).",
    )
    conv_export.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the destination file if it exists.",
    )

    conv_archive = conv_sub.add_parser(
        "archive", help="Archive a conversation.")
    conv_archive.add_argument("uuid", help="Conversation UUID.")

    conv_delete = conv_sub.add_parser(
        "delete", help="Soft-delete a conversation.")
    conv_delete.add_argument("uuid", help="Conversation UUID.")

    # ---- ai topup --------------------------------------------------------
    topup_parser = ai_sub.add_parser(
        "topup",
        help="Open a Stripe Checkout for a token top-up pack.",
    )
    topup_parser.add_argument(
        "pack",
        nargs="?",
        default=None,
        choices=list(_TOPUP_PACKS),
        help="Top-up pack name. Omit to print the available packs.",
    )

    # ---- ai provider reset ----------------------------------------------
    provider_parser = ai_sub.add_parser(
        "provider",
        help="Manage AI provider preference.",
    )
    provider_sub = provider_parser.add_subparsers(dest="provider_command")
    provider_sub.required = True
    provider_sub.add_parser(
        "reset",
        help="Clear ai.provider_preference and dismissed-banner flags.",
    )

    return ai_parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def handle_ai_command(args: argparse.Namespace) -> int:
    """Synchronous entry point — dispatches based on ``args.ai_command``.

    Returns an integer exit code suitable for :func:`sys.exit`.
    """
    sub = getattr(args, "ai_command", None)
    if sub is None:
        print("Error: specify an `ai` subcommand. Use --help.",
              file=sys.stderr)
        return _EXIT_USAGE_ERROR

    dispatch: Dict[str, Callable[[argparse.Namespace], int]] = {
        "chat": _handle_chat,
        "quota": _handle_quota,
        "conversations": _handle_conversations,
        "topup": _handle_topup,
        "provider": _handle_provider,
    }
    handler: Optional[Callable[[argparse.Namespace], int]] = dispatch.get(sub)
    if handler is None:
        print(f"Error: unknown ai subcommand {sub!r}.", file=sys.stderr)
        return _EXIT_USAGE_ERROR
    return handler(args)


__all__ = [
    "add_ai_parser",
    "handle_ai_command",
]
