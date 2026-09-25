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

## Release qualification

Standalone CLI archives and desktop installers are qualified per platform row
on clean machines. `packaging/distribution/qualification-matrix.json` lists the
rows (Windows 10 22H2 and Windows 11 on x64, macOS 13 or later on Intel and
Apple Silicon, Ubuntu 22.04 and 24.04 on x64, and X11 and Wayland sessions for
the desktop app) and the checks each row requires.

After verifying a candidate, the Release candidate workflow uploads a
`qualification-record-template` artifact containing `qualification-record.json`,
with one untested entry per row and artifact. Testers fill in their entries:

- `result`: `pass`, `fail` or `blocked`, and each check as `pass` or `fail`;
- `machine_image`: a short description of the clean machine;
- `tested_on`: the test date as `YYYY-MM-DD` (not a future date);
- `tester`: a short handle, never a name or email address;
- `failure_link`: for a failed or blocked row, a public issue or Actions run in
  this repository; otherwise `null`.

Leave rows that were not tested as `untested`.
`python -m scripts.distribution.qualification summarize --evidence candidate-evidence.json --record qualification-record.json`
refuses a malformed record and prints the rows that pass so far as a Markdown
table. `check --channel stable` applies the release gate; `--channel preview`
validates a preview candidate's record without requiring passes.

A platform is advertised as stable only when its row passes; failing rows stay
preview or absent. To ship while a platform is failing, cut the stable
candidate without that artifact. A record made for a preview tag of the same
version (`vX.Y.Z-preview.N` for `vX.Y.Z`) carries over to the stable candidate
when its candidate digest is identical, so unchanged preview artifacts need no
second round of testing.

The publish workflow enforces qualification only while the
`REQUIRE_RELEASE_CANDIDATE` repository variable is `true`. While it is off,
pip/pipx releases are unaffected. While it is on, every stable release,
including its PyPI upload, needs at least one fully qualified binary artifact:
the release must carry `candidate-evidence.json`, the release files it names,
and a `qualification-record.json` in which every row that applies to those
files passes against the same artifact SHA-256 and candidate digest. The
Release workflow attaches none of these, so before turning the variable on,
the release process must attach them, for example by creating the release as
a draft, uploading the files, and then publishing it.

## Development Setup
Please refer to the `README.md` for instructions on setting up your development environment and installing dependencies.

## Code of Conduct
Please note that this project is released with a Contributor Code of Conduct. By participating in this project you agree to abide by its terms. For now, please be respectful and constructive in all interactions.

## License
By contributing to Servonaut, you agree that your contributions will be licensed under its MIT License.

Thank you for your contribution!
