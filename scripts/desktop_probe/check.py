"""Run repeatable desktop checks without publishing credentials in reports."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import platform
import sys
import tempfile
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from .config import time_scale


class Results:
    """Keep only test identifiers and outcomes; deliberately discard tracebacks."""

    def __init__(self) -> None:
        self.tests: dict[str, str] = {}
        self.collection_errors = 0
        self.collection_skips = 0
        self.failures: dict[str, dict[str, object]] = {}

    def pytest_exception_interact(self, node: Any, call: Any, report: Any) -> None:
        if call.excinfo is None:
            return
        # Code locations are useful across OSes; exception text and locals can
        # contain session credentials. Never serialize the exception itself.
        self.failures.setdefault(node.nodeid, {}).update(
            {
                "exception": call.excinfo.typename,
                "frames": [
                    {"file": Path(str(frame.path)).name, "line": frame.lineno + 1}
                    for frame in call.excinfo.traceback
                ],
            }
        )

    def pytest_collectreport(self, report: Any) -> None:
        self.collection_errors += int(report.failed)
        self.collection_skips += int(report.skipped)

    def pytest_runtest_logreport(self, report: Any) -> None:
        if report.when == "call" or report.failed or report.skipped:
            self.tests[report.nodeid] = report.outcome
        for name, value in getattr(report, "user_properties", []):
            if (
                name
                in {
                    "child_errors",
                    "child_transport",
                    "browser_errors",
                    "native_result",
                    "native_stages",
                }
                and value
                and self.tests.get(report.nodeid) == "failed"
            ):
                self.failures.setdefault(report.nodeid, {})[name] = value

    def is_success(self, exit_code: int) -> bool:
        return (
            exit_code == 0
            and bool(self.tests)
            and not self.collection_errors
            and not self.collection_skips
            and all(status == "passed" for status in self.tests.values())
        )


def dependency_versions() -> dict[str, str]:
    packages = (
        "textual",
        "textual-serve",
        "pywebview",
        "aiohttp",
        "playwright",
        "psutil",
        "pyOpenSSL",
        "cryptography",
        "pytest",
        "pytest-asyncio",
        "pytest-timeout",
    )
    result = {}
    for package in packages:
        try:
            result[package] = version(package)
        except PackageNotFoundError:
            result[package] = "missing"
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", action="append", choices=("chromium", "webkit"))
    parser.add_argument(
        "--native", action="store_true", help="Open and close a native window"
    )
    parser.add_argument("--renderer", choices=("gtk", "edgechromium", "cocoa"))
    return parser.parse_args()


def run_tests(args: argparse.Namespace, results_dir: Path, results: Results) -> int:
    import pytest

    files = ["tests/test_desktop_probe.py", "tests/test_desktop_probe_check.py"]
    environment = {
        "SERVONAUT_PROBE_RESULTS": str(results_dir),
        # A local -k/-m filter must not make requested browser/native checks vanish.
        "PYTEST_ADDOPTS": "",
    }
    if args.browser:
        environment["SERVONAUT_DESKTOP_BROWSER_TEST"] = "1"
        environment["SERVONAUT_PROBE_BROWSERS"] = ",".join(dict.fromkeys(args.browser))
        files.append("tests/test_desktop_probe_browser.py")
    if args.native:
        environment["SERVONAUT_DESKTOP_NATIVE_TEST"] = "1"
        environment["SERVONAUT_PROBE_RENDERER"] = (
            args.renderer
            or {
                "Linux": "gtk",
                "Windows": "edgechromium",
                "Darwin": "cocoa",
            }[platform.system()]
        )
        files.append("tests/test_desktop_probe_native.py")
    previous = {name: os.environ.get(name) for name in environment}
    try:
        os.environ.update(environment)
        # Failure representations can contain WS headers/bootstrap scripts.
        # Neither raw pytest output nor locals belong in public CI artifacts.
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            return int(
                pytest.main(
                    ["-q", "--tb=no", "--show-capture=no", *files], plugins=[results]
                )
            )
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[2]
    if Path.cwd().resolve() != root:
        print("Run this command from the repository root.")
        return 2
    output_root = root / "local" / "desktop-probe-results"
    output_root.mkdir(parents=True, exist_ok=True)
    results_dir = Path(tempfile.mkdtemp(prefix="run-", dir=output_root))
    versions = dependency_versions()
    results = Results()
    exit_code = 2
    if "missing" not in versions.values():
        exit_code = run_tests(args, results_dir, results)
    report = {
        "success": results.is_success(exit_code),
        "system": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "time_scale": time_scale(),
        "dependencies": versions,
        "requested_browsers": args.browser or [],
        "native_requested": args.native,
        "tests": results.tests,
        "collection_errors": results.collection_errors,
        "collection_skips": results.collection_skips,
        "failures": results.failures,
    }
    (results_dir / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    print(f"Results: {results_dir.relative_to(root).as_posix()}")
    if not report["success"]:
        print(
            "Checks failed (including any skipped checks). See scripts/desktop_probe/README.md for troubleshooting."
        )
    return 0 if report["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
