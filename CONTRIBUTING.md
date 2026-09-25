# Contributing to Servonaut

First off, thank you for considering contributing to Servonaut! Your help is appreciated.

This document provides guidelines for contributing to this project.

## How Can I Contribute?

### Reporting Bugs
*   Ensure the bug was not already reported by searching on GitHub under [Issues](https://github.com/zb-ss/servonaut/issues).
*   If you're unable to find an open issue addressing the problem, [open a new one](https://github.com/zb-ss/servonaut/issues/new). Be sure to include a **title and clear description**, as much relevant information as possible, and a **code sample or an executable test case** demonstrating the expected behavior that is not occurring.

### Suggesting Enhancements
*   Open a new issue to discuss your enhancement. Clearly describe the proposed enhancement and its potential benefits.
*   Provide a step-by-step description of the suggested enhancement in as many details as possible.

### Pull Requests
1.  **Fork the repository**: Click the "Fork" button at the top right of the repository page.
2.  **Clone your fork**: `git clone https://github.com/zb-ss/servonaut.git`.
3.  **Create a new branch**: `git checkout -b name-of-your-new-feature-or-fix`
4.  **Make your changes**: Make your changes in your local repository.
5.  **Follow coding style**:
    *   Ensure your code adheres to the existing style.
    *   If you are adding new features, try to include tests if applicable.
    *   Update documentation (e.g., `README.md`) if your changes affect usage or add new features.
6.  **Commit your changes**: Use clear and descriptive commit messages.
    ```bash
    git add .
    git commit -m "feat: Add new feature X"
    # or "fix: Resolve bug Y"
    # or "docs: Update README for feature Z"
    ```
7.  **Push to your fork**: `git push origin name-of-your-new-feature-or-fix`
8.  **Open a Pull Request**: Go to the original repository on GitHub and click the "New pull request" button. Fill out the pull request template.

## Avoiding accidental disclosure

This is a public repository — anything that lands in a commit, test, fixture, PR title/body, or release note is permanent and world-readable. Before opening a PR, please make sure neither your **code** nor your **prose** contains:

- Real customer / client / brand names, real hostnames, or real infrastructure identifiers (account IDs, ARNs, bucket / security-group / instance names). Use neutral examples (`example.com`, `web-1`, `9.9.9.9`, RFC1918 addresses).
- Real IP addresses tied to anyone's infrastructure, or details of a specific real-world incident.
- Personal data (real emails, home-directory paths) — use `user@example.com`, `/home/user`.
- Secrets of any kind (keys, tokens, passwords, private keys).
- Tooling artifacts: assistant session links, attribution trailers, or coordination identifiers (agent names, thread ids). Describe the change itself.

A **Leak Guard** CI check scans each PR's diff, commit messages, title, and body for these patterns and a maintained denylist; it reports only *where* a match was found, never the value. It's a backstop, not a substitute for care while writing.

If the guard flags a line that is a genuinely safe, vetted fixture (e.g. a documentation example key), add `leak-guard:allow` in a comment on that line to exempt it, or add the exact safe token to `.github/leak-allowlist.txt`.

## Release channels and notes

Stable publishing requires a published, non-draft, non-prerelease GitHub release
with a `vX.Y.Z` tag matching both package version declarations. Desktop previews
must be marked as GitHub prereleases; they do not publish to PyPI or the MCP
registry. Experimental CI artifacts are not stable downloads. The existing
pip/pipx update behaviour is unchanged.

Release candidates are assembled and verified by the Release candidate workflow.
A stable candidate uses a `vX.Y.Z` tag; a preview candidate uses a
`vX.Y.Z-preview.N` tag and reports the same product version `X.Y.Z` with a
preview packaging revision. Each candidate is pinned to a digest and, when
signing is required, cannot be published without it. The stable publish path
only accepts stable-channel evidence: a preview candidate can never authorize a
stable release. Verification is staged behind the `REQUIRE_RELEASE_CANDIDATE`
repository variable until a real candidate has been produced once.

The Release workflow compares shipped Python source changes against the highest
published stable version reachable from the branch. Preview, draft and unpublished
tags do not set that baseline. CI-, test- and documentation-only changes do not
trigger a version bump. Use its `dry_run` input to inspect the next version without
committing, tagging or publishing. All published releases, including previews,
count towards the one-release-per-UTC-day cadence.

Maintainers can apply `skip-changelog` to development-only PRs to exclude them
from automatically generated release notes. Do not apply it to user-facing fixes
or features. The label affects notes only: it does not hide a PR, change its
release eligibility, or prevent its files from being included in source archives.

## Development Setup
Please refer to the `README.md` for instructions on setting up your development environment and installing dependencies.

## End-to-end tests

The `e2e/` directory holds end-to-end journeys. They start the real TUI, CLI
and MCP server and use them the way a person or an MCP client would: keys and
clicks in the TUI, commands on the command line, tool calls over stdio. They
run as their own pytest process, separate from the unit tests in `tests/`:

```bash
pip install -e ".[test,e2e]"
python -m pytest e2e                            # one process
python -m pytest e2e -n auto --dist loadgroup   # in parallel, as CI runs it
```

A plain `pytest` still runs only `tests/`. Never run `e2e` and `tests` in the
same command: the suite has to set up its environment before Servonaut is
first imported.

Every run is sealed off from your machine:

- A temporary test root holds the home directory, config, caches and temp
  files. Nothing reads or writes your own `~/.servonaut`, and the root is
  deleted at the end (set `SERVONAUT_E2E_KEEP=1` to keep it for inspection,
  and `SERVONAUT_E2E_ROOT` to choose the directory it is created in).
- The environment is rebuilt from an allowlist. `PATH` contains only scripted
  stand-ins for `ssh`, `scp`, `ssh-agent`, the terminal emulator, the browser
  and the editor, so no real session or window is ever opened. A journey can
  add stand-ins for the Bitwarden CLIs (`bws`, `bw`), which answer from a
  fake vault (`e2e/harness/bitwarden.py`).
- Network access is limited to loopback. AWS calls go to a local moto server;
  the Servonaut API and the package index go to a local HTTPS stand-in with a
  throwaway certificate authority. An attempt to reach any other host, to
  write outside the test root or to start any program other than the
  stand-ins, fails the test that made it. Python child processes install the
  same guards at start-up and stop at once if they cannot.

When a journey fails, its diagnostics are written to `e2e-artifacts/<test>/`:
an SVG screenshot of the TUI and `state.json`, the calls the stand-in tools
received, the requests the local API received, and the relevant logs. CI
uploads that folder for failed runs, and the upload is public: paths and
anything shaped like a credential are scrubbed, but keep every fixture neutral
anyway (see [Avoiding accidental disclosure](#avoiding-accidental-disclosure));
the shared inventory in `e2e/harness/fleet.py` is the place to start.
`SERVONAUT_E2E_ARTIFACTS` picks another folder; the suite only ever empties a
folder it created itself.

When you add a journey:

- Use the fixtures in `e2e/conftest.py`: `tui` (the TUI in-process), `seed`
  (config and cache, built through the real config schema), `moto`,
  `fake_cloud`, `cli` and `mcp` (real child processes).
- Wait for conditions (`wait_until`, `wait_for_screen`, `wait_for_toast`),
  never for a fixed time.
- Mark it `e2e_pr` to run it on every pull request. A journey that turns out
  to be flaky gets `e2e_quarantine` until it is fixed. Every journey needs one
  of the two; collection stops with an error otherwise.
- A journey that documents a known bug is marked `xfail(strict=True)`: the fix
  makes it fail as "unexpectedly passing", so remove the marker in the same
  change as the fix.

## Code of Conduct
Please note that this project is released with a Contributor Code of Conduct. By participating in this project you agree to abide by its terms. For now, please be respectful and constructive in all interactions.

## License
By contributing to Servonaut, you agree that your contributions will be licensed under its MIT License.

Thank you for your contribution!
