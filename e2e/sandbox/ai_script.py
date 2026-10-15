"""A scripted hosted AI for the QA sandbox (``up --ai-script FILE``).

The fake service answers ``servonaut ai chat`` only with turns queued in
advance. This loads them from one JSON file, with the account's AI quota and
the stored conversations ``servonaut ai conversations`` lists::

    {
      "quota": {"tokens_used": 41200, "resets_in_days": 18},
      "turns": [{"reply": "Two servers are stopped: db-1 and build-1."}],
      "conversations": [
        {"id": "conv-1", "title": "Stopped servers", "minutes_ago": 45,
         "messages": [{"role": "user", "content": "Which servers are stopped?"},
                      {"role": "assistant", "content": "db-1 and build-1."}]}
      ]
    }

Every chat request consumes the next turn; a turn's reply is streamed in
short pieces. Times are relative to the start, so nothing shows a far-off
date. Everything in the file is for walks and recordings: keep it synthetic.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

_QUOTA_KEYS = {
    "tokens_used", "tokens_limit", "tokens_topup_remaining", "soft_capped", "hard_capped",
    "rpm_limit", "tokens_per_minute_limit",
}


class ScriptError(ValueError):
    """The file is not a usable AI script; the message says why."""


def load(path: Path) -> dict[str, Any]:
    """The script at *path*, checked; raises :class:`ScriptError`."""
    try:
        spec = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ScriptError(f"cannot read the AI script {path}: {exc}") from exc
    if not isinstance(spec, dict):
        raise ScriptError("the AI script must be a JSON object")
    quota = spec.get("quota", {})
    if not isinstance(quota, dict) or set(quota) - _QUOTA_KEYS - {"resets_in_days"}:
        raise ScriptError(f"quota takes only: {', '.join(sorted(_QUOTA_KEYS | {'resets_in_days'}))}")
    turns = spec.get("turns", [])
    if not isinstance(turns, list) or not all(
        isinstance(t, dict) and isinstance(t.get("reply"), str) for t in turns
    ):
        raise ScriptError('turns must be a list of {"reply": "..."} objects')
    conversations = spec.get("conversations", [])
    if not isinstance(conversations, list) or not all(
        isinstance(c, dict) and isinstance(c.get("id"), str) and isinstance(c.get("title"), str)
        for c in conversations
    ):
        raise ScriptError('conversations must be a list of objects with an "id" and a "title"')
    return spec


def _pieces(reply: str) -> list[str]:
    """The reply in word-sized pieces, so it streams like a real answer."""
    return [piece for piece in re.findall(r"\S+\s*|\s+", reply) if piece]


def _quota(spec: dict[str, Any], scenario_quota: Optional[dict[str, Any]], now: datetime) -> dict[str, Any]:
    quota = dict(scenario_quota or {})
    wanted = dict(spec.get("quota", {}))
    days = wanted.pop("resets_in_days", None)
    quota.update(wanted)
    if days is not None:
        quota["resets_at"] = (now + timedelta(days=float(days))).replace(microsecond=0).isoformat()
    return quota


def _conversation(entry: dict[str, Any], now: datetime) -> tuple[dict[str, Any], str]:
    from e2e.harness.fake_cloud.chat_script import conversation_row

    messages = [
        {"role": str(m.get("role", "user")), "content": str(m.get("content", ""))}
        for m in entry.get("messages", []) if isinstance(m, dict)
    ]
    row = conversation_row(entry["id"], entry["title"], messages=messages)
    updated = now - timedelta(minutes=float(entry.get("minutes_ago", 5)))
    row["updated_at"] = updated.replace(microsecond=0).isoformat()
    row["created_at"] = (updated - timedelta(minutes=len(messages) or 1)).replace(microsecond=0).isoformat()
    export = entry.get("export") or "\n\n".join(
        [f"# {entry['title']}"] + [f"**{m['role']}**: {m['content']}" for m in messages]
    ) + "\n"
    return row, export


def apply(fake_cloud: Any, spec: dict[str, Any], *, now: Optional[datetime] = None) -> None:
    """Queue the turns, set the quota and store the conversations on *fake_cloud*."""
    from e2e.harness.fake_cloud.chat_script import ChatTurn, token, usage

    now = now or datetime.now(timezone.utc)
    quota = _quota(spec, fake_cloud.entitlements().get("quota"), now)
    fake_cloud.configure(quota=quota)
    usage_quota = {k: v for k, v in quota.items() if k in _QUOTA_KEYS | {"resets_at"}}
    fake_cloud.ai.script(*(
        ChatTurn.of(*[token(piece) for piece in _pieces(turn["reply"])], usage(**usage_quota), gap=0.03)
        for turn in spec.get("turns", [])
    ))
    rows, exports = [], {}
    for entry in spec.get("conversations", []):
        row, export = _conversation(entry, now)
        rows.append(row)
        exports[row["id"]] = export
    if rows:
        fake_cloud.ai.configure(conversations=rows, exports=exports)
