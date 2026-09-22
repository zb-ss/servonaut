"""Policy-bound smoke runner for packaged desktop onedir payloads."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from scripts.desktop_shell.model import (
    DesktopTargetSpec,
    load_desktop_target_spec,
)
from scripts.standalone_cli.smoke_artifact import isolated_child_environment
from scripts.standalone_cli.smoke_mcp import (
    MCPCheck,
    MCPSmokeError,
    MCPTimeouts,
    run_mcp_smoke,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_POLICY_PATH = _REPO_ROOT / "packaging" / "desktop_shell" / "smoke-policy.json"

_POLICY_KEYS = frozenset(
    {
        "schema_version",
        "process_argv_max_count",
        "selftest_stdin_max_bytes",
        "stdout_stderr_max_bytes",
        "transcript_max_bytes",
        "public_command_timeout_seconds",
        "selftest_timeout_seconds",
        "child_rejection_timeout_seconds",
        "mcp_initialize_timeout_seconds",
        "mcp_request_timeout_seconds",
        "mcp_shutdown_timeout_seconds",
        "mcp_frame_max_bytes",
    }
)


class DesktopSmokeError(RuntimeError):
    """Raised when a packaged desktop payload fails a smoke check."""


@dataclass(frozen=True)
class DesktopSmokePolicy:
    """Strict execution bounds for desktop artifact smoke validation."""

    schema_version: int
    process_argv_max_count: int
    selftest_stdin_max_bytes: int
    stdout_stderr_max_bytes: int
    transcript_max_bytes: int
    public_command_timeout_seconds: int
    selftest_timeout_seconds: int
    child_rejection_timeout_seconds: int
    mcp_initialize_timeout_seconds: int
    mcp_request_timeout_seconds: int
    mcp_shutdown_timeout_seconds: int
    mcp_frame_max_bytes: int


@dataclass(frozen=True)
class CheckResult:
    """Public, content-free result of a single smoke step."""

    ok: bool
    exit_code: int
    elapsed_ms: int
    stdout_bytes: int
    stdout_sha256: str
    stderr_bytes: int
    stderr_sha256: str
    details: str = ""


@dataclass(frozen=True)
class DesktopSmokeReport:
    """Audit report across all desktop smoke qualifications."""

    payload_root: str
    target: str
    product_version: str
    overall_ok: bool
    duration_seconds: float
    checks: dict[str, CheckResult]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2) + "\n"


@dataclass(frozen=True)
class _ProcessResult:
    exit_code: int
    elapsed_ms: int
    stdout: bytes
    stderr: bytes

    def to_check_result(self, *, ok: bool, details: str = "") -> CheckResult:
        return CheckResult(
            ok=ok,
            exit_code=self.exit_code,
            elapsed_ms=self.elapsed_ms,
            stdout_bytes=len(self.stdout),
            stdout_sha256=hashlib.sha256(self.stdout).hexdigest(),
            stderr_bytes=len(self.stderr),
            stderr_sha256=hashlib.sha256(self.stderr).hexdigest(),
            details=details,
        )


def load_desktop_smoke_policy(path: Path | None = None) -> DesktopSmokePolicy:
    """Load and validate the desktop smoke policy."""
    policy_file = (path or _DEFAULT_POLICY_PATH).resolve(strict=True)
    try:
        raw = json.loads(policy_file.read_text(encoding="utf-8"))
    except Exception as err:
        raise DesktopSmokeError(
            f"Failed to read smoke policy at {policy_file}"
        ) from err

    if not isinstance(raw, dict):
        raise DesktopSmokeError("Smoke policy must be a JSON object")

    missing = _POLICY_KEYS - set(raw)
    if missing:
        raise DesktopSmokeError(
            f"Smoke policy missing required keys: {sorted(missing)}"
        )

    if raw.get("schema_version") != 1:
        raise DesktopSmokeError(
            f"Unsupported smoke policy schema_version: {raw.get('schema_version')}"
        )

    return DesktopSmokePolicy(
        schema_version=raw["schema_version"],
        process_argv_max_count=raw["process_argv_max_count"],
        selftest_stdin_max_bytes=raw["selftest_stdin_max_bytes"],
        stdout_stderr_max_bytes=raw["stdout_stderr_max_bytes"],
        transcript_max_bytes=raw["transcript_max_bytes"],
        public_command_timeout_seconds=raw["public_command_timeout_seconds"],
        selftest_timeout_seconds=raw["selftest_timeout_seconds"],
        child_rejection_timeout_seconds=raw["child_rejection_timeout_seconds"],
        mcp_initialize_timeout_seconds=raw["mcp_initialize_timeout_seconds"],
        mcp_request_timeout_seconds=raw["mcp_request_timeout_seconds"],
        mcp_shutdown_timeout_seconds=raw["mcp_shutdown_timeout_seconds"],
        mcp_frame_max_bytes=raw["mcp_frame_max_bytes"],
    )


def _run_process(
    cmd: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    stdin_data: bytes | None = None,
    timeout: float,
    max_output_bytes: int = 65536,
) -> _ProcessResult:
    """Run a child process with bounded output, strict environment, and timeout."""
    start_time = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            cwd=str(cwd),
            env=env,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as err:
        elapsed_ms = int((time.monotonic() - start_time) * 1000)
        raise DesktopSmokeError(
            f"Process timed out after {timeout}s: {cmd[0]}"
        ) from err
    except OSError as err:
        raise DesktopSmokeError(f"Failed to spawn process {cmd[0]}: {err}") from err

    elapsed_ms = int((time.monotonic() - start_time) * 1000)

    if len(proc.stdout) > max_output_bytes or len(proc.stderr) > max_output_bytes:
        raise DesktopSmokeError(
            f"Process output exceeded limit of {max_output_bytes} bytes: {cmd[0]}"
        )

    return _ProcessResult(
        exit_code=proc.returncode,
        elapsed_ms=elapsed_ms,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def smoke_desktop_payload(
    payload_root: Path,
    target: DesktopTargetSpec,
    product_version: str,
    *,
    policy: DesktopSmokePolicy | None = None,
    evidence_dir: Path | None = None,
    skip_selftest: bool = False,
    skip_mcp: bool = False,
) -> DesktopSmokeReport:
    """Run all end-to-end smoke checks on a packaged desktop payload."""
    payload_root = payload_root.resolve(strict=True)
    if not payload_root.is_dir():
        raise DesktopSmokeError(f"Payload root not found: {payload_root}")

    active_policy = policy or load_desktop_smoke_policy()
    total_start = time.monotonic()

    ext = ".exe" if target.platform == "win32" else ""
    cli_path = payload_root / f"servonaut{ext}"
    child_path = payload_root / f"servonaut-desktop-child{ext}"
    gui_path = payload_root / f"servonaut-desktop{ext}"

    for path, label in (
        (cli_path, "CLI console helper"),
        (child_path, "Child process"),
        (gui_path, "Desktop GUI launcher"),
    ):
        if not path.is_file():
            raise DesktopSmokeError(f"Missing {label} executable: {path}")
        if target.platform != "win32" and not (path.stat().st_mode & stat.S_IXUSR):
            raise DesktopSmokeError(f"{label} is not executable: {path}")

    checks: dict[str, CheckResult] = {}

    with tempfile.TemporaryDirectory(prefix="servonaut-desktop-smoke-") as scratch_str:
        scratch_dir = Path(scratch_str)
        scratch_home = scratch_dir / "home"
        scratch_home.mkdir(parents=True, exist_ok=True)
        env = isolated_child_environment(scratch_home)

        # 1. CLI --version check
        cmd_version = [str(cli_path), "--version"]
        res_version = _run_process(
            cmd_version,
            cwd=scratch_home,
            env=env,
            timeout=active_policy.public_command_timeout_seconds,
            max_output_bytes=active_policy.stdout_stderr_max_bytes,
        )
        version_text = res_version.stdout.decode("utf-8", errors="replace")
        if res_version.exit_code != 0:
            raise DesktopSmokeError(
                f"CLI --version failed with exit code {res_version.exit_code}"
            )
        if product_version not in version_text:
            raise DesktopSmokeError(
                f"CLI --version output did not include version {product_version!r}: {version_text.strip()}"
            )
        checks["cli_version"] = res_version.to_check_result(
            ok=True, details="Version verified"
        )

        # 2. CLI --help check
        cmd_help = [str(cli_path), "--help"]
        res_help = _run_process(
            cmd_help,
            cwd=scratch_home,
            env=env,
            timeout=active_policy.public_command_timeout_seconds,
            max_output_bytes=active_policy.stdout_stderr_max_bytes,
        )
        help_text = res_help.stdout.decode("utf-8", errors="replace").lower()
        if res_help.exit_code != 0:
            raise DesktopSmokeError(
                f"CLI --help failed with exit code {res_help.exit_code}"
            )
        if "usage:" not in help_text and "servonaut" not in help_text:
            raise DesktopSmokeError(
                f"CLI --help output did not contain expected help text: {help_text[:100]}"
            )
        checks["cli_help"] = res_help.to_check_result(
            ok=True, details="Help output verified"
        )

        # 3. CLI bad argument rejection
        cmd_bad = [str(cli_path), "--_definitely_invalid_smoke_flag_xyz"]
        res_bad = _run_process(
            cmd_bad,
            cwd=scratch_home,
            env=env,
            timeout=active_policy.public_command_timeout_seconds,
            max_output_bytes=active_policy.stdout_stderr_max_bytes,
        )
        if res_bad.exit_code == 0:
            raise DesktopSmokeError("CLI unexpectedly accepted nonexistent option")
        checks["cli_bad_args"] = res_bad.to_check_result(
            ok=True, details=f"Rejected bad option with code {res_bad.exit_code}"
        )

        # 4. Child direct execution rejection
        # Direct execution without parent control frame must immediately exit with code 1
        cmd_child = [str(child_path)]
        res_child = _run_process(
            cmd_child,
            cwd=scratch_home,
            env=env,
            stdin_data=b"",
            timeout=active_policy.child_rejection_timeout_seconds,
            max_output_bytes=active_policy.stdout_stderr_max_bytes,
        )
        if res_child.exit_code != 1:
            raise DesktopSmokeError(
                f"Child executable did not exit with code 1 when invoked without parent frame (got {res_child.exit_code})"
            )
        checks["child_unauthorized_rejection"] = res_child.to_check_result(
            ok=True, details="Unauthorized execution rejected with exit code 1"
        )

        # 5. MCP stdio smoke
        if not skip_mcp:
            mcp_timeouts = MCPTimeouts(
                initialize_seconds=float(active_policy.mcp_initialize_timeout_seconds),
                request_seconds=float(active_policy.mcp_request_timeout_seconds),
                shutdown_seconds=float(active_policy.mcp_shutdown_timeout_seconds),
                frame_max_bytes=active_policy.mcp_frame_max_bytes,
                stderr_max_bytes=active_policy.stdout_stderr_max_bytes,
            )
            mcp_start = time.monotonic()
            try:
                mcp_check: MCPCheck = run_mcp_smoke(
                    command=cli_path,
                    args=["--mcp"],
                    environment=env,
                    working_directory=scratch_home,
                    timeouts=mcp_timeouts,
                )
                mcp_elapsed_ms = int((time.monotonic() - mcp_start) * 1000)
                checks["mcp_smoke"] = CheckResult(
                    ok=True,
                    exit_code=0,
                    elapsed_ms=mcp_elapsed_ms,
                    stdout_bytes=0,
                    stdout_sha256="",
                    stderr_bytes=mcp_check.stderr_bytes,
                    stderr_sha256=mcp_check.stderr_sha256,
                    details=f"MCP tools: {mcp_check.tool_count}, logged_out={mcp_check.whoami_logged_out}",
                )
            except MCPSmokeError as err:
                detail = str(err)
                if err.__cause__:
                    detail = f"{detail} (cause: {err.__cause__})"
                raise DesktopSmokeError(f"MCP stdio smoke failed: {detail}") from err

        # 6. Desktop GUI --_artifact-selftest (if not skipped)
        if not skip_selftest:
            # First, check authentication rejection on bad token
            selftest_env_bad = dict(env)
            bad_token = secrets.token_hex(16)
            selftest_env_bad["SERVONAUT_ARTIFACT_SELFTEST_TOKEN"] = bad_token
            bad_stdin = json.dumps(
                {"schema_version": 1, "token": "mismatched-token", "check": "tui"}
            ).encode("utf-8")
            res_st_bad = _run_process(
                [str(gui_path), "--_artifact-selftest"],
                cwd=scratch_home,
                env=selftest_env_bad,
                stdin_data=bad_stdin,
                timeout=active_policy.public_command_timeout_seconds,
                max_output_bytes=active_policy.stdout_stderr_max_bytes,
            )
            if res_st_bad.exit_code != 1:
                raise DesktopSmokeError(
                    f"GUI selftest accepted invalid token (exit code {res_st_bad.exit_code})"
                )
            checks["gui_selftest_auth_rejection"] = res_st_bad.to_check_result(
                ok=True, details="Unauthenticated selftest rejected"
            )

            # Second, run authenticated selftest
            valid_token = secrets.token_hex(32)
            selftest_env_good = dict(env)
            selftest_env_good["SERVONAUT_ARTIFACT_SELFTEST_TOKEN"] = valid_token
            good_stdin = json.dumps(
                {"schema_version": 1, "token": valid_token, "check": "tui"}
            ).encode("utf-8")
            res_st_good = _run_process(
                [str(gui_path), "--_artifact-selftest"],
                cwd=scratch_home,
                env=selftest_env_good,
                stdin_data=good_stdin,
                timeout=active_policy.selftest_timeout_seconds,
                max_output_bytes=active_policy.stdout_stderr_max_bytes,
            )
            if res_st_good.exit_code != 0:
                raise DesktopSmokeError(
                    f"GUI selftest failed with exit code {res_st_good.exit_code}: {res_st_good.stderr.decode('utf-8', errors='replace')}"
                )
            try:
                st_payload = json.loads(res_st_good.stdout.decode("utf-8"))
            except Exception as err:
                raise DesktopSmokeError(
                    f"GUI selftest returned non-JSON stdout: {err}"
                ) from err

            if not st_payload.get("ok"):
                raise DesktopSmokeError(
                    f"GUI selftest reported failure: {st_payload.get('error')}"
                )
            checks["gui_selftest"] = res_st_good.to_check_result(
                ok=True, details="Authenticated selftest passed"
            )

    total_duration = time.monotonic() - total_start
    report = DesktopSmokeReport(
        payload_root=str(payload_root),
        target=target.name,
        product_version=product_version,
        overall_ok=all(c.ok for c in checks.values()),
        duration_seconds=round(total_duration, 3),
        checks=checks,
    )

    if evidence_dir is not None:
        evidence_dir = evidence_dir.resolve()
        evidence_dir.mkdir(parents=True, exist_ok=True)
        report_file = evidence_dir / f"smoke-report-{target.name}.json"
        report_file.write_text(report.to_json(), encoding="utf-8")

    return report


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for desktop smoke verification."""
    parser = argparse.ArgumentParser(
        prog="smoke_artifact",
        description="Run policy-bound smoke checks on a packaged desktop onedir payload.",
    )
    parser.add_argument(
        "--payload",
        "--payload-root",
        dest="payload_root",
        type=Path,
        required=True,
        help="Path to the extracted or built desktop onedir directory",
    )
    parser.add_argument(
        "--target",
        type=str,
        required=True,
        help="Target platform identifier (e.g. linux-x64-ubuntu-22.04)",
    )
    parser.add_argument(
        "--product-version",
        type=str,
        required=True,
        help="Expected product version",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=None,
        help="Optional path to custom smoke-policy.json",
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=None,
        help="Optional directory to save public smoke evidence report",
    )
    parser.add_argument(
        "--skip-selftest",
        action="store_true",
        help="Skip GUI --_artifact-selftest execution",
    )
    parser.add_argument(
        "--skip-mcp",
        action="store_true",
        help="Skip MCP stdio smoke check",
    )

    args = parser.parse_args(argv)

    try:
        target_spec = load_desktop_target_spec(args.target)
        policy = load_desktop_smoke_policy(args.policy)
        report = smoke_desktop_payload(
            payload_root=args.payload_root,
            target=target_spec,
            product_version=args.product_version,
            policy=policy,
            evidence_dir=args.evidence_dir,
            skip_selftest=args.skip_selftest,
            skip_mcp=args.skip_mcp,
        )
        print(
            f"Smoke qualification succeeded for {args.target} ({report.duration_seconds}s)"
        )
        return 0
    except DesktopSmokeError as err:
        sys.stderr.write(f"Smoke qualification failed: {err}\n")
        return 1
    except Exception as err:  # noqa: BLE001
        sys.stderr.write(f"Unexpected smoke error: {err}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
