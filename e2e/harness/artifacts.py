"""Failure artifacts: what a failed journey leaves behind for diagnosis.

For every failed test the suite writes ``e2e-artifacts/<test-id>/`` with the
driver's SVG screenshot and ``state.json`` (TUI journeys), the fake tools'
argv log, the FakeCloud request log, guard logs, child output and the tail of
each Servonaut log. CI uploads that folder, which is public, so every text
file is scrubbed: absolute paths become ``$E2E_ROOT`` / ``$REPO`` / ``$HOME``
style placeholders and anything shaped like a credential is replaced. The
fixtures themselves are neutral by construction.

The folder is only ever deleted when it carries the suite's marker file, so
pointing ``SERVONAUT_E2E_ARTIFACTS`` at an existing directory cannot remove it.
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path
from typing import Iterable, Optional

from e2e.harness.bootstrap import ARTIFACTS_MARKER, REPO_ROOT, E2EContext

_TEXT_SUFFIXES = {".json", ".jsonl", ".log", ".svg", ".txt", ".md"}
_TAIL_BYTES = 64 * 1024
_REDACTED = "<redacted>"

_SECRET_KEYS = (
    r"authorization|access_token|refresh_token|id_token|token|device_code|api_key|apikey"
    r"|x-api-key|password|passphrase|secret|client_secret|session_token"
    r"|aws_secret_access_key|aws_session_token"
)
# Authorization: Bearer <token>
_BEARER = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]+")
# "key": "value", key: value and key=value for credential-named keys.
_KEY_VALUE = re.compile(
    rf"(?i)(\"?\b(?:{_SECRET_KEYS})\b\"?\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,&}}\]]+)"
)
# Query-string secrets, including signed URLs and OAuth codes.
_QUERY = re.compile(
    r"(?i)([?&](?:access_token|refresh_token|token|code|device_code|api_key|apikey|key"
    r"|signature|x-amz-signature|x-amz-credential|x-amz-security-token|awsaccesskeyid"
    r"|password|secret|client_secret)=)[^&\s\"'<>]+"
)
# A long "code" value: an OAuth or device code, not a short error code.
_LONG_CODE = re.compile(r'(?i)("code"\s*:\s*)"[^"]{20,}"')
# Generic tokens: JWTs, long mixed-case alphanumerics (API keys) and long hex.
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?")
_MIXED_CASE_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_+=-])(?=[A-Za-z0-9_+=-]*[0-9])(?=[A-Za-z0-9_+=-]*[a-z])"
    r"(?=[A-Za-z0-9_+=-]*[A-Z])[A-Za-z0-9_+=-]{32,}"
)
_HEX_TOKEN = re.compile(r"(?i)(?<![0-9a-z])[0-9a-f]{40,}(?![0-9a-z])")


def sanitize(nodeid: str) -> str:
    """A filesystem-safe, bounded folder name for a pytest node id."""
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", nodeid).strip("_")
    return name[-150:]


def _redact_value(match: re.Match[str]) -> str:
    key, value = match.group(1), match.group(2)
    if _REDACTED in value:
        return match.group(0)
    quote = value[0] if value[:1] in ("'", '"') else ""
    return f"{key}{quote}{_REDACTED}{quote}"


def scrub(text: str) -> str:
    """Replace anything shaped like a credential."""
    text = _BEARER.sub(rf"\1 {_REDACTED}", text)
    text = _KEY_VALUE.sub(_redact_value, text)
    text = _QUERY.sub(rf"\1{_REDACTED}", text)
    text = _LONG_CODE.sub(rf'\1"{_REDACTED}"', text)
    for pattern in (_JWT, _MIXED_CASE_TOKEN, _HEX_TOKEN):
        text = pattern.sub(_REDACTED, text)
    return text


def _rewrite(text: str, ctx: E2EContext) -> str:
    replacements = [
        (str(ctx.root), "$E2E_ROOT"),
        (str(REPO_ROOT), "$REPO"),
        (sys.executable, "$PYTHON"),
        (sys.prefix, "$PYTHON_PREFIX"),
        (sys.base_prefix, "$PYTHON_BASE_PREFIX"),
    ]
    replacements += [(home, "$HOME") for home in ctx.protected_dirs]
    for old, new in sorted(replacements, key=lambda item: -len(item[0])):
        text = text.replace(old, new)
    return scrub(text)


def prepare_artifacts_dir(ctx: E2EContext) -> None:
    """Empty the artifacts folder at the start of a run, if the suite owns it.

    A folder without the marker is never deleted: an empty one is adopted,
    anything else stops the run.
    """
    folder = ctx.artifacts_dir
    if not folder.exists():
        return
    if (folder / ARTIFACTS_MARKER).is_file():
        shutil.rmtree(folder)
        return
    if any(folder.iterdir()):
        raise RuntimeError(
            f"{folder} holds files the e2e suite did not create; choose an empty "
            "directory for SERVONAUT_E2E_ARTIFACTS or remove it yourself."
        )
    (folder / ARTIFACTS_MARKER).write_text("created by the servonaut e2e suite\n")


def _artifacts_root(ctx: E2EContext) -> Path:
    folder = ctx.artifacts_dir
    folder.mkdir(parents=True, exist_ok=True)
    marker = folder / ARTIFACTS_MARKER
    if not marker.exists():
        marker.write_text("created by the servonaut e2e suite\n")
    return folder


def _copy(source: Path, destination: Path, ctx: E2EContext, *, tail: bool = False) -> None:
    if not source.is_file():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.suffix not in _TEXT_SUFFIXES and not source.name.endswith(".jsonl"):
        shutil.copyfile(source, destination)
        return
    data = source.read_bytes()
    if tail and len(data) > _TAIL_BYTES:
        data = data[-_TAIL_BYTES:]
    destination.write_text(_rewrite(data.decode("utf-8", "replace"), ctx), encoding="utf-8")


def collect(
    ctx: E2EContext,
    nodeid: str,
    *,
    staging: Path,
    shim_dir: Optional[Path],
    guard_logs: Iterable[Path],
    homes: Iterable[Path],
    fake_cloud: Optional[object] = None,
) -> Path:
    """Copy one failed journey's diagnostics into the artifacts folder."""
    destination = _artifacts_root(ctx) / sanitize(nodeid)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)

    if staging.is_dir():
        for item in staging.rglob("*"):
            if item.is_file():
                _copy(item, destination / item.relative_to(staging), ctx)
    if shim_dir is not None:
        _copy(shim_dir / "argv.jsonl", destination / "argv.jsonl", ctx)
        _copy(shim_dir / "scenario.json", destination / "shim-scenario.json", ctx)
        for transcript in sorted(shim_dir.glob("terminal-*.log")):
            _copy(transcript, destination / "terminals" / transcript.name, ctx)
    for index, log in enumerate(guard_logs):
        _copy(log, destination / f"guard-{index}.jsonl", ctx)
    for index, home in enumerate(homes):
        data_dir = home / ".servonaut"
        label = f"home-{index}"
        for log in sorted((data_dir / "logs").glob("*.log")):
            _copy(log, destination / label / "logs" / log.name, ctx, tail=True)
        for name in ("mcp_audit.jsonl", "command_history.json", "config.json"):
            _copy(data_dir / name, destination / label / name, ctx, tail=True)
    if fake_cloud is not None:
        fake_cloud.write_log(destination / "fake_cloud_requests.jsonl")  # type: ignore[attr-defined]
        log = destination / "fake_cloud_requests.jsonl"
        if log.exists():
            log.write_text(_rewrite(log.read_text(encoding="utf-8"), ctx), encoding="utf-8")
    return destination
