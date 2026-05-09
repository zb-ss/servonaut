"""Bug report data-collection and submission service.

Gathers diagnostics (version, OS, log tail, config), runs the redactor so
secrets are scrubbed, and submits either via a prefilled GitHub issue URL or
via POST to the Servonaut backend.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import platform
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional

from importlib.metadata import version as pkg_version

logger = logging.getLogger(__name__)

from servonaut.services.memory.redaction import default_redactor, scan_for_secrets
from servonaut.services.api_client import APIError

# ---------------------------------------------------------------------------
# Public dataclasses (frozen — callers cannot mutate after collection)
# ---------------------------------------------------------------------------

# Last underscore-segment of a key name → treated as secret-bearing.
# Match is on ``key.lower().rsplit("_", 1)[-1]`` so ``application_secret``,
# ``openai_api_key``, ``consumer_key``, ``client_secret``, ``db_password``,
# ``self_privkey`` all hit; while ``max_tokens`` (plural), ``credentials_path``,
# ``keyword_store_path``, ``client_id``, ``token_endpoint`` do not.
_SECRET_KEY_SUFFIXES = frozenset({
    "key",
    "secret",
    "token",
    "password",
    "passphrase",
    "credentials",
    "privkey",
    "pat",
})


def _is_secret_key_name(key: str) -> bool:
    if not isinstance(key, str) or not key:
        return False
    return key.lower().rsplit("_", 1)[-1] in _SECRET_KEY_SUFFIXES


@dataclass(frozen=True)
class BugReportConsent:
    include_logs: bool
    include_config: bool
    include_anonymous_telemetry: bool   # provider counts only, no instance ids/names
    channel: Literal["github", "backend"]


@dataclass(frozen=True)
class BugReportPayload:
    servonaut_version: str
    python_version: str
    os_release: str                     # "Linux 6.17.0-23-generic" etc.
    textual_version: str
    install_method: str                 # "pipx" | "pip" | "unknown"
    auth_state: Literal["anonymous", "signed-in"]
    instance_count_by_provider: Dict[str, int]
    last_traceback: Optional[str]
    log_excerpt: Optional[str]          # None when consent.include_logs is False
    config_snapshot: Optional[Dict]     # None when consent.include_config is False
    redacted_categories_found: List[str]


@dataclass(frozen=True)
class BugReportReceipt:
    channel: Literal["github", "backend"]
    url: str
    submitted_at_iso: str
    report_id: Optional[str]            # backend-assigned id; None for github channel


# ---------------------------------------------------------------------------
# Domain exception
# ---------------------------------------------------------------------------

class BugReportSubmissionError(Exception):
    """Raised when the backend submission fails.

    Wraps an :class:`~servonaut.services.api_client.APIError` so the screen
    has one exception type to catch.
    """

    def __init__(self, message: str, *, cause: Optional[Exception] = None) -> None:
        super().__init__(message)
        self.cause = cause


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_GITHUB_URL_LIMIT = 8000


def _scrub_config_dict(obj: Any, redactor: Callable[[str], str]) -> Any:
    """Recursively scrub *obj*:

    1. Replace values whose key name's last underscore-segment is in
       ``_SECRET_KEY_SUFFIXES`` with ``"<removed:secret-key>"`` — but only
       when the value is a non-empty string (boolean flags and integers
       named e.g. ``max_tokens`` are left alone).
    2. Run *redactor* on all remaining string values.

    Returns a new dict/list; the original is never mutated.
    """
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if _is_secret_key_name(k) and isinstance(v, str) and v:
                out[k] = "<removed:secret-key>"
            else:
                out[k] = _scrub_config_dict(v, redactor)
        return out
    if isinstance(obj, list):
        return [_scrub_config_dict(item, redactor) for item in obj]
    if isinstance(obj, str):
        return redactor(obj)
    return obj


def _collect_secret_categories(obj: Any) -> List[str]:
    """Walk *obj* and return all secret categories found by ``scan_for_secrets``.

    Deduplicates while preserving first-seen order.
    """
    seen: list = []
    seen_set: set = set()

    def _walk(node: Any) -> None:
        if isinstance(node, str):
            for cat in scan_for_secrets(node):
                if cat not in seen_set:
                    seen_set.add(cat)
                    seen.append(cat)
        elif isinstance(node, dict):
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(obj)
    return seen


def _read_last_traceback(log_path: Path, tail_lines: int) -> Optional[str]:
    """Return the last traceback block in the last *tail_lines* of *log_path*.

    Returns ``None`` when the file does not exist or no traceback is found.
    """
    try:
        text = log_path.read_text(errors="replace")
    except OSError:
        return None

    lines = text.splitlines()
    tail = lines[-tail_lines:] if len(lines) > tail_lines else lines

    last_tb_idx: Optional[int] = None
    for i, line in enumerate(tail):
        if line.startswith("Traceback (most recent call last):"):
            last_tb_idx = i

    if last_tb_idx is None:
        return None

    return "\n".join(tail[last_tb_idx:])


def _read_log_tail(log_path: Path, tail_lines: int) -> Optional[str]:
    """Return the last *tail_lines* lines of *log_path*, or ``None`` on error."""
    try:
        text = log_path.read_text(errors="replace")
    except OSError:
        return None

    lines = text.splitlines()
    return "\n".join(lines[-tail_lines:] if len(lines) > tail_lines else lines)


def _utcnow_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class BugReportService:
    """Collect diagnostics, redact secrets, and submit bug reports."""

    def __init__(
        self,
        config_manager,
        api_client,
        auth_service,
        update_service,
        *,
        redactor: Callable[[str], str] = default_redactor,
        log_path: Optional[Path] = None,
        github_repo: str = "zb-ss/servonaut",
    ) -> None:
        self._config_manager = config_manager
        self._api_client = api_client
        self._auth_service = auth_service
        self._update_service = update_service
        self._redactor = redactor
        self._log_path: Path = log_path or Path.home() / ".servonaut" / "logs" / "servonaut.log"
        self._github_repo = github_repo

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def collect_diagnostics(
        self,
        *,
        consent: BugReportConsent,
        instances: List[Dict],
        log_tail_lines: int = 200,
    ) -> BugReportPayload:
        """Collect all diagnostics and return an immutable :class:`BugReportPayload`.

        Redaction is applied as the LAST step so no secret ever escapes into
        the frozen dataclass.
        """
        # --- Environment info ---
        servonaut_version = self._update_service.current_version
        python_version = platform.python_version()
        os_release = f"{platform.system()} {platform.release()}"
        textual_version = _safe_pkg_version("textual")
        install_method = self._update_service.detect_install_method()

        # --- Auth state ---
        auth_state: Literal["anonymous", "signed-in"] = (
            "signed-in" if self._auth_service.access_token else "anonymous"
        )

        # --- Provider telemetry ---
        if consent.include_anonymous_telemetry:
            provider_counts: Dict[str, int] = {}
            for inst in instances:
                provider = inst.get("provider", "aws")
                provider_counts[provider] = provider_counts.get(provider, 0) + 1
        else:
            provider_counts = {}

        # --- Log data (pre-redaction raw values) ---
        raw_log_tail = _read_log_tail(self._log_path, log_tail_lines)
        raw_traceback = _read_last_traceback(self._log_path, log_tail_lines)

        # --- Config snapshot (pre-redaction) ---
        raw_config: Optional[Dict] = None
        if consent.include_config:
            try:
                cfg = self._config_manager.get()
                raw_config = dataclasses.asdict(cfg)
                # Layer 1: remove secret-named keys
                raw_config = _scrub_config_dict(raw_config, lambda s: s)  # keys only
            except Exception as exc:
                logger.warning("Bug report: failed to serialise config: %s", exc)
                raw_config = {
                    "error": "could not serialise config",
                    "reason": f"{type(exc).__name__}: {exc}",
                }

        # --- Collect secret categories from RAW text BEFORE redaction ---
        # scan_for_secrets looks for patterns that the redactor will then scrub.
        # We must scan the raw values — after redaction the patterns are gone.
        raw_texts_to_scan: List[Any] = []
        if consent.include_logs and raw_log_tail is not None:
            raw_texts_to_scan.append(raw_log_tail)
        if raw_traceback is not None:
            raw_texts_to_scan.append(raw_traceback)
        if raw_config is not None:
            raw_texts_to_scan.append(raw_config)

        redacted_categories: List[str] = _collect_secret_categories(raw_texts_to_scan)

        # --- Redact all text fields (layer 2 for config, only layer for logs) ---
        redacted_log: Optional[str] = None
        if consent.include_logs and raw_log_tail is not None:
            redacted_log = self._redactor(raw_log_tail)

        redacted_traceback: Optional[str] = None
        if raw_traceback is not None:
            redacted_traceback = self._redactor(raw_traceback)

        redacted_config: Optional[Dict] = None
        if raw_config is not None:
            # Layer 2: run redactor on all remaining string values
            redacted_config = _scrub_config_dict(raw_config, self._redactor)

        return BugReportPayload(
            servonaut_version=servonaut_version,
            python_version=python_version,
            os_release=os_release,
            textual_version=textual_version,
            install_method=install_method,
            auth_state=auth_state,
            instance_count_by_provider=provider_counts,
            last_traceback=redacted_traceback,
            log_excerpt=redacted_log,
            config_snapshot=redacted_config,
            redacted_categories_found=redacted_categories,
        )

    def render_preview(
        self,
        *,
        payload: BugReportPayload,
        title: str,
        description: str,
    ) -> str:
        """Return the Markdown the user reviews verbatim before submission.

        Layout::

            <title>

            <description>

            ---

            ## Environment
            | key | value |
            ...

            ## Last traceback
            (if any)

            ## Log excerpt
            (if included)

            ## Config snapshot
            (if included, fenced JSON)

            ## Redacted categories detected
            (if list non-empty)
        """
        parts: List[str] = []

        parts.append(f"# {title}")
        parts.append("")
        parts.append(description)
        parts.append("")
        parts.append("---")
        parts.append("")

        # Environment table
        parts.append("## Environment")
        parts.append("")
        parts.append("| Key | Value |")
        parts.append("| --- | --- |")
        parts.append(f"| servonaut_version | {payload.servonaut_version} |")
        parts.append(f"| python_version | {payload.python_version} |")
        parts.append(f"| os_release | {payload.os_release} |")
        parts.append(f"| textual_version | {payload.textual_version} |")
        parts.append(f"| install_method | {payload.install_method} |")
        parts.append(f"| auth_state | {payload.auth_state} |")
        if payload.instance_count_by_provider:
            counts_str = ", ".join(
                f"{k}: {v}" for k, v in payload.instance_count_by_provider.items()
            )
            parts.append(f"| instance_count_by_provider | {counts_str} |")
        parts.append("")

        if payload.last_traceback is not None:
            parts.append("## Last traceback")
            parts.append("")
            parts.append("```")
            parts.append(payload.last_traceback)
            parts.append("```")
            parts.append("")

        if payload.log_excerpt is not None:
            parts.append("## Log excerpt")
            parts.append("")
            parts.append("```")
            parts.append(payload.log_excerpt)
            parts.append("```")
            parts.append("")

        if payload.config_snapshot is not None:
            parts.append("## Config snapshot")
            parts.append("")
            parts.append("```json")
            parts.append(json.dumps(payload.config_snapshot, indent=2, default=str))
            parts.append("```")
            parts.append("")

        if payload.redacted_categories_found:
            parts.append("## Redacted categories detected")
            parts.append("")
            for cat in payload.redacted_categories_found:
                parts.append(f"- {cat}")
            parts.append("")

        return "\n".join(parts)

    async def submit(
        self,
        *,
        payload: BugReportPayload,
        consent: BugReportConsent,
        title: str,
        description: str,
    ) -> BugReportReceipt:
        """Build and submit the bug report via the chosen *channel*.

        The browser is NOT opened here — that is the screen's responsibility.
        """
        submitted_at = _utcnow_iso()
        markdown_body = self.render_preview(
            payload=payload, title=title, description=description
        )

        if consent.channel == "github":
            return self._submit_github(
                title=title,
                body=markdown_body,
                payload=payload,
                submitted_at=submitted_at,
            )
        else:
            return await self._submit_backend(
                title=title,
                description=description,
                payload=payload,
                submitted_at=submitted_at,
            )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _submit_github(
        self,
        *,
        title: str,
        body: str,
        payload: BugReportPayload,
        submitted_at: str,
    ) -> BugReportReceipt:
        url = self._build_github_url(title=title, body=body, payload=payload)
        return BugReportReceipt(
            channel="github",
            url=url,
            submitted_at_iso=submitted_at,
            report_id=None,
        )

    def _build_github_url(
        self,
        *,
        title: str,
        body: str,
        payload: BugReportPayload,
    ) -> str:
        base = f"https://github.com/{self._github_repo}/issues/new"
        encoded_title = urllib.parse.quote(title)
        encoded_body = urllib.parse.quote(body)
        url = f"{base}?title={encoded_title}&body={encoded_body}"

        if len(url) > _GITHUB_URL_LIMIT:
            # Truncate log_excerpt and rebuild the preview with shortened payload
            truncation_note = (
                "\n... (truncated, full log too large for GitHub URL"
                " — use backend channel instead)"
            )
            # Binary search would be overkill; iteratively chop the excerpt
            truncated_payload = dataclasses.replace(
                payload,
                log_excerpt=(payload.log_excerpt or "") + truncation_note
                if payload.log_excerpt
                else truncation_note,
            )
            # We need to re-render with the truncated excerpt in the body.
            # Re-derive the body from the original title/description embedded in body,
            # but since we only have the rendered body here we rebuild by trimming.
            # Strategy: trim log_excerpt characters from the encoded body until URL fits.
            if payload.log_excerpt:
                excerpt = payload.log_excerpt
                while True:
                    # Chop 100 chars at a time from the middle of the excerpt
                    if len(excerpt) <= 100:
                        excerpt = ""
                    else:
                        excerpt = excerpt[: len(excerpt) - 100]
                    test_payload = dataclasses.replace(
                        payload,
                        log_excerpt=excerpt + truncation_note if excerpt else truncation_note,
                    )
                    test_body = self._rebuild_body_with_payload(
                        original_body=body, original_payload=payload, new_payload=test_payload
                    )
                    test_url = (
                        f"{base}?title={encoded_title}&body={urllib.parse.quote(test_body)}"
                    )
                    if len(test_url) <= _GITHUB_URL_LIMIT:
                        url = test_url
                        break
                    if not excerpt:
                        # Nothing left to trim; just use the truncation note alone
                        final_payload = dataclasses.replace(
                            payload, log_excerpt=truncation_note
                        )
                        final_body = self._rebuild_body_with_payload(
                            original_body=body,
                            original_payload=payload,
                            new_payload=final_payload,
                        )
                        url = f"{base}?title={encoded_title}&body={urllib.parse.quote(final_body)}"
                        break
            else:
                # No log excerpt to trim; URL is long for some other reason.
                # Return the URL as-is — it may exceed 8000 chars but there is
                # nothing safe to truncate.
                pass

        return url

    def _rebuild_body_with_payload(
        self,
        *,
        original_body: str,
        original_payload: BugReportPayload,
        new_payload: BugReportPayload,
    ) -> str:
        """Re-render the markdown body using *new_payload*.

        We extract title and description from the rendered *original_body*
        (first line stripped of ``# ``, and second non-empty block before ``---``).
        """
        lines = original_body.split("\n")
        title = lines[0].lstrip("# ").strip() if lines else ""
        # Description: content between first blank line after title and "---"
        desc_lines: List[str] = []
        in_desc = False
        for line in lines[2:]:
            if line.strip() == "---":
                break
            desc_lines.append(line)
        description = "\n".join(desc_lines).strip()
        return self.render_preview(
            payload=new_payload, title=title, description=description
        )

    async def _submit_backend(
        self,
        *,
        title: str,
        description: str,
        payload: BugReportPayload,
        submitted_at: str,
    ) -> BugReportReceipt:
        try:
            response = await self._api_client.post(
                "/api/v1/bug-reports",
                json={
                    "title": title,
                    "description": description,
                    "payload": dataclasses.asdict(payload),
                },
            )
        except APIError as exc:
            raise BugReportSubmissionError(
                _format_api_error(exc), cause=exc
            ) from exc

        return BugReportReceipt(
            channel="backend",
            url=response["url"],
            submitted_at_iso=submitted_at,
            report_id=response["id"],
        )


# ---------------------------------------------------------------------------
# Internal utility
# ---------------------------------------------------------------------------

def _format_api_error(exc: APIError) -> str:
    """Build a user-facing message that surfaces the server's reason.

    Backend bug-report errors put the actionable cause in
    ``error.details.reason`` (e.g. "title must be at least 5 characters").
    Without unpacking it, the user only sees the generic ``code`` label
    and has to read server logs to know what went wrong.
    """
    parts: list[str] = []
    if exc.message:
        parts.append(exc.message)
    if isinstance(exc.details, dict):
        reason = exc.details.get("reason")
        if isinstance(reason, str) and reason:
            parts.append(reason)
        else:
            extras = [
                f"{k}: {v}"
                for k, v in exc.details.items()
                if k != "reason" and isinstance(v, (str, int, float, bool))
            ]
            if extras:
                parts.append("; ".join(extras))
    base = " — ".join(parts) if parts else f"HTTP {exc.status}"
    return f"Failed to submit bug report ({exc.status} {exc.code}): {base}"


def _safe_pkg_version(package: str) -> str:
    try:
        return pkg_version(package)
    except Exception:
        return "unknown"
