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
with a `vX.Y.Z` tag matching both package version declarations. A release
candidate is a published GitHub prerelease with a PEP 440 `vX.Y.ZrcN` tag
matching both declarations; it publishes to PyPI but not to the MCP registry.
pip and pipx install a candidate only when asked for pre-releases, and the
in-app update check never offers one to a stable installation. Desktop previews
must be marked as GitHub prereleases; they do not publish to PyPI or the MCP
registry. Experimental CI artifacts are not stable downloads.

Every published `vX.Y.Z` release and `vX.Y.ZrcN` candidate also gets a Linux
desktop preview `.deb`, built from the release's tag commit and qualified by
the Desktop preview .deb workflow before it is attached, with its
`SHA256SUMS` and a build-provenance attestation. That workflow is separate
from the PyPI publish and never holds it back. Re-running it replaces only its
own two assets; run it on the tag itself
(`gh workflow run desktop-preview-deb.yml --ref vX.Y.Z -f tag=vX.Y.Z`), or add
`-f dry_run=true` to build and qualify without attaching anything.

While the desktop app is known to be broken, set the repository variable
`DESKTOP_PREVIEW_PUBLISH` to `off`
(`gh variable set DESKTOP_PREVIEW_PUBLISH --body off --repo zb-ss/servonaut`).
Releases published meanwhile get no preview: the workflow skips the build and
ends with a notice saying so, and the Python release goes ahead as usual. Set
it back to `on`, or delete it, once the app works again. Any other value fails
the run rather than guessing. A manual run ignores the variable, so it can
still attach a preview to a release that went out without one. To take a
broken preview off a release that already carries it, delete its `.deb` and
its `SHA256SUMS`, one command per asset:

```bash
gh release delete-asset <tag> <asset> --yes --repo zb-ss/servonaut
# for example:
gh release delete-asset v2.28.0rc1 servonaut-desktop-preview_2.28.0rc1_amd64.deb --yes --repo zb-ss/servonaut
gh release delete-asset v2.28.0rc1 servonaut-desktop-preview_2.28.0rc1_SHA256SUMS --yes --repo zb-ss/servonaut
```

Every published release and candidate also carries the install scripts,
`install.sh` and `install.ps1`, with `install-scripts_SHA256SUMS`, attached by
the Release install scripts workflow from the release's tag commit. An install
command that downloads them from the latest release gets the scripts of the
newest stable release, so a change to the scripts reaches users with a
release, not when it is merged. The scripts install Servonaut from PyPI only
and stop with pipx's error when that fails. The workflow is separate from the
PyPI publish and replaces only its own three assets. To attach them again,
run `gh workflow run release-install-scripts.yml -f tag=vX.Y.Z`; the tag's own
scripts are used whichever branch runs it. Add `-f dry_run=true` to check
without uploading. Tags from before the workflow existed are refused, since
their scripts fall back to installing the default branch.

Binary release candidates (standalone CLI archives and desktop installers)
are assembled and verified by the Release candidate workflow, separately from
the Python release candidates described under Releasing below.
A stable candidate uses a `vX.Y.Z` tag; a preview candidate uses a
`vX.Y.Z-preview.N` tag and reports the same product version `X.Y.Z` with a
preview packaging revision. Each candidate is pinned to a digest and, when
signing is required, cannot be published without it. The stable publish path
only accepts stable-channel evidence: a preview candidate can never authorize a
stable release. Verification is staged behind the `REQUIRE_RELEASE_CANDIDATE`
repository variable until a real candidate has been produced once.

The Release workflow compares shipped Python source changes against the highest
published stable version. Changes that release already contains, such as fixes
cherry-picked onto its release branch, are not counted again. Candidate, preview,
draft and unpublished tags do not set that baseline. CI-, test- and
documentation-only changes do not trigger a version bump. Only stable releases
count towards the one-release-per-UTC-day cadence: candidates and previews are
never offered to people on a stable version.

Maintainers can apply `skip-changelog` to development-only PRs to exclude them
from automatically generated release notes. Do not apply it to user-facing fixes
or features. The label affects notes only: it does not hide a PR, change its
release eligibility, or prevent its files from being included in source archives.

## Releasing

Every release is published as a release candidate first, and reaches users
only after a maintainer approves it. The Release workflow runs in two stages:

1. **Candidate** (Mondays, or run by hand with `stage: candidate`). It picks
   the next version from the commits since the last stable release (`feat:` or
   a configuration migration makes a minor release, `!` or `BREAKING CHANGE` a
   major one, anything else a patch), opens a `release/X.Y.Z` branch from
   master, sets the version to `X.Y.ZrcN` on that branch, tags `vX.Y.ZrcN` and
   creates a GitHub prerelease, which the publish workflow uploads to PyPI.
   While `release/X.Y.Z` is open, the next run cuts `rcN+1` from the head of
   that branch instead: fix a problem on master, then cherry-pick the fix onto
   the release branch. A run with nothing new to release, or with no change on
   the branch since its last candidate, does nothing.
2. **Final** (Thursdays, or run by hand with `stage: final`). With no open
   candidate it does nothing, and there is no release that week. Otherwise it
   checks that the latest candidate is the head of the release branch, was
   published as a prerelease, is on PyPI and is not yanked there, then waits
   for approval in the `release-approval` environment. Once approved, and only
   if the release branch has not changed meanwhile and PyPI still serves the
   candidate unyanked, it changes nothing but the version to `X.Y.Z`, tags
   `vX.Y.Z` and creates the stable GitHub release
   with generated notes, which the publish workflow ships to PyPI and the MCP
   registry. Master's version is raised to `X.Y.Z` if it is lower, and the
   release branch is deleted. Rejecting the approval, or letting it expire,
   publishes nothing. The final stage refuses when a stable release already
   went out that UTC day.

A week's release is what master held when the Monday run cut `rc1`. A change
merged after that ships the following week, unless it is cherry-picked onto
the open release branch and tested in a new candidate. The first Monday run
after this workflow reaches master cuts the first candidate; until one exists,
the Thursday run has nothing to promote.

Candidate numbers are never reused: PyPI accepts a version only once, even
after it is deleted. To withdraw a candidate, yank it on PyPI and leave its tag
and GitHub release in place; a yanked candidate is never promoted. Cut a new
candidate instead.

If a run pushed its tag but failed to create the GitHub release, run the same
stage again: it creates only the missing release (for the final stage, after
approval). Until a stable tag has a published release, the candidate stage
refuses to start the next release. If the candidate behind such a tag was
yanked meanwhile, either create the release for the tag by hand to ship it
anyway, or delete the never-released tag by hand
(`git push origin :refs/tags/vX.Y.Z`); the next candidate run then starts
over with the next candidate number.

To try a candidate without touching an existing installation, run
`pipx run --spec 'servonaut==X.Y.ZrcN' servonaut`, or install it in its own
environment with `pip install 'servonaut==X.Y.ZrcN'`. Avoid `--pre`: it also
accepts pre-release versions of the dependencies. See
[docs/release-candidates.md](docs/release-candidates.md).

Rehearse either stage without pushing, tagging or publishing anything:

```bash
gh workflow run release.yml -f stage=candidate -f dry_run=true
gh workflow run release.yml -f stage=final -f dry_run=true
```

`bump` overrides the version bump when a candidate opens a new release branch.
`draft` creates the GitHub release as a draft, to edit the notes before
publishing it; publishing the draft is what uploads the package. On the final
stage, `draft` still tags `vX.Y.Z`, raises master's version and deletes the
release branch: only the release itself waits for you to publish it, and the
next candidate run refuses to start until you do. A final run that finds the
draft reports it instead of asking for approval.

The workflow needs a `RELEASE_TOKEN` repository secret (a fine-grained personal
access token with Contents: read/write on this repository) and a
`release-approval` environment with at least one required reviewer; the final
stage refuses to run while that environment requires no reviewer. The token is
never stored in the checkout: only the steps that push, create releases or
look for a draft release receive it.

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
pip/pipx releases are unaffected. Python release candidates (`vX.Y.ZrcN`
prereleases) are never subject to it. While it is on, every stable release,
including its PyPI upload, needs at least one fully qualified binary artifact:
the release must carry `candidate-evidence.json`, the release files it names,
and a `qualification-record.json` in which every row that applies to those
files passes against the same artifact SHA-256 and candidate digest. The
Release workflow attaches none of these, so before turning the variable on,
the release process must attach them, for example by creating the release as
a draft, uploading the files, and then publishing it.

## Development Setup
Please refer to the `README.md` for instructions on setting up your development environment and installing dependencies.

## Screenshot tests

`tests/snapshots/` renders the main screens with the real app and its real
stylesheets, at 160x50 and at 100x30, and compares each rendering with an SVG
stored in `tests/snapshots/__snapshots__/`. A change to layout, styling or
wording on those screens fails the comparison. They are part of the unit
tests, so CI runs them on every Python version. The screen is captured with
Textual's own SVG export and compared as text by a small helper in the
suite (`tests/snapshots/_snapshot.py`); the only extra dependency is
time-machine, in the `test` extra:

```bash
pip install -e ".[test]"
python -m pytest tests/snapshots                      # compare
python -m pytest tests/snapshots --update-snapshots   # accept the current rendering
```

A test fails when its rendering differs from the stored SVG, naming the file,
or when it has no stored SVG yet. On a difference it writes the new rendering
and a unified diff of the two SVGs to `tests/snapshots/__failures__/`
(ignored by Git); open the SVG in a browser to see the screen. Nothing about
your machine goes into these files.

Update the snapshots only when the change on screen is intended: a UI change
you made on purpose, or a Textual upgrade whose new rendering you have
checked. Look at every changed SVG before committing, and commit the SVGs
together with the change that caused them. A failure you did not expect is a
regression to fix, not a snapshot to update.

Textual's rendering can change from one release to the next, and the tests
use whatever Textual is installed, as users do. The snapshots record the
Textual version they were made with
(`tests/snapshots/__snapshots__/TEXTUAL_VERSION`). When the installed version
is a different one, the tests are skipped with the reason ("snapshots
recorded with Textual X, installed Y"), so a new Textual release cannot fail
changes that have nothing to do with it. Set `SERVONAUT_SNAPSHOTS_STRICT=1`
to run them anyway: a screen that renders differently fails as usual, and one
that renders the same fails because the recorded version is out of date.

CI runs the tests in both ways. The test jobs skip them on a version
mismatch; the `screenshots / Python 3.12` job runs them in strict mode on
every pull request and on master, and uploads the new renderings and diffs as
the `screenshot-failures` artifact when it fails. That job is not a required
check: when it fails because Textual changed, install the new version, review
the renderings, and update all the snapshots in one change with
`--update-snapshots`, which also records the new version.

Every screen starts from the same state, so the rendering does not depend on
the machine, the Python version or the time of day:

- Each test runs in an empty home directory with a clean environment. The
  config, the instance cache and one server's memory are written through the
  application's own schema and stores (`tests/snapshots/_harness.py`).
- Nothing reaches the network: the update check and the AWS fetch return
  fixed data, and the OVH and Hetzner services are stand-ins with a fixed
  inventory.
- The wall clock is frozen, so ages such as "Cache: 5m 0s ago" never change,
  and the sidebar shows a fixed version instead of the release number.
- Animations, notifications and tooltips are off, text cursors do not blink,
  and the screen is captured only once two captures in a row are identical.

Fixtures follow the same rules as the rest of the suite (see
[Avoiding accidental disclosure](#avoiding-accidental-disclosure)): generic
server names, RFC1918 private addresses and well-known public resolver
addresses only, since every snapshot is committed. Unset `TEXTUAL_*`
variables such as `TEXTUAL_THEME` before running the tests: Textual reads
them when it is imported.

To add a screen, write a scenario in `tests/snapshots/test_screens.py` that
drives the app there with keys or the app's own navigation, waiting for
conditions rather than for a fixed time, then run it with `--update-snapshots`
and review the new SVGs.

## End-to-end tests

The `e2e/` directory holds end-to-end journeys. They start the real TUI, CLI
and MCP server and use them the way a person or an MCP client would: keys and
clicks in the TUI, commands on the command line, tool calls over stdio. They
run as their own pytest process, separate from the unit tests in `tests/`:

```bash
pip install -e ".[test,e2e,hetzner,ovh]"
python -m playwright install chromium           # once, for the desktop journeys
python -m pytest e2e                            # one process
python -m pytest e2e -n auto --dist loadgroup   # in parallel, as CI runs it
python -m pytest e2e -m "not needs_browser"     # skip the browser journeys
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
- The desktop journeys drive the desktop frontend in headless Chromium.
  Chromium is started so that it cannot resolve or reach anything but
  loopback, and a journey whose page requested any other host fails.

Journeys marked `needs_sshd` use a real remote machine instead of the
scripted `ssh`: two local SSH servers on loopback (a target and a bastion)
and the OpenSSH client installed on your system (`ssh` and `scp` in
`/usr/bin` or `/bin`; install `openssh-client` if they are missing, or
deselect these journeys with `-m "not needs_sshd"`). For those journeys
`ssh` and `scp` on `PATH` run the real client with a generated config file.
Before each call, the settings OpenSSH will actually use are checked: the
destination must be loopback, every file they name must be inside the test
root, and no agent, local command or plugin may be involved, so your own
`~/.ssh` is not used.

Each server plays a small machine whose files live in the test root:
`/var/log` holds fixture logs, `docker`, `journalctl` and `systemctl` are
scripted, and absolute paths such as `/var/...` or `/home/...` in a command
are mapped to the server's folder. Remote commands are still real programs
on your machine. Where bubblewrap (`bwrap`) is installed and allowed to run,
each command runs in a sandbox that sees your system read-only, cannot see
your home directory or the rest of the test root, can write only the
server's folder and has no network. Without it, the path mapping is only
textual: it keeps journeys predictable but does not stop a command that
goes around it (`cd ..`, a program's absolute path). The failure artifacts
(`sshd-commands.jsonl`, `remote-files.txt`) say which mode was used.

When a journey fails, its diagnostics are written to `e2e-artifacts/<test>/`:
an SVG screenshot of the TUI and `state.json`, the calls the stand-in tools
received, the requests the local API received, the SSH servers' command log,
and the relevant logs; for desktop journeys also page screenshots, the
browser console and a Playwright trace. CI
uploads that folder for failed runs, and the upload is public: paths and
anything shaped like a credential are scrubbed, but keep every fixture neutral
anyway (see [Avoiding accidental disclosure](#avoiding-accidental-disclosure));
the shared inventory in `e2e/harness/fleet.py` is the place to start.
`SERVONAUT_E2E_ARTIFACTS` picks another folder; the suite only ever empties a
folder it created itself.

The journeys in `e2e/journeys/packaged/` install Servonaut the way users do:
they build the wheel from the checkout as the next release (with the build
tools in the `e2e` extra, so nothing is downloaded), install it by name from
the local package index with pip into a fresh venv and with pipx, and upgrade
to it from published releases. Dependencies come from the environment you run the suite
in. The published releases have to be downloaded first, because the suite
never reaches the network:

```bash
python e2e/tools/fetch_previous_release.py   # into .e2e-cache/releases
```

It fetches the latest release at or below the checkout's version, checked
against the SHA-256 digest PyPI publishes, and the newest release of each
earlier config schema, pinned to its digest in the script. Without them the upgrade journeys are skipped.
`SERVONAUT_E2E_RELEASE_CACHE` chooses another cache directory (inside the
checkout or outside your home directory, where the suite may read); when it
is set, as in CI, a missing release fails those journeys instead.

When you add a journey:

- Use the fixtures in `e2e/conftest.py`: `tui` (the TUI in-process), `seed`
  (config and cache, built through the real config schema), `moto`,
  `fake_cloud`, `providers` (local stand-ins for the Hetzner Cloud and
  OVHcloud APIs), `cli` and `mcp` (real child processes), `sshd` (the loopback
  SSH servers; see `e2e/harness/remote_fleet.py` for fleet entries that point
  at them), and `desktop` (the desktop frontend in headless Chromium, served
  by the desktop host in-process or by the real desktop child process). A
  journey using `sshd` must be marked `needs_sshd`. Journeys using `desktop`
  are also marked `needs_browser`; CI runs them in a job of their own.
- For AI journeys (`e2e/journeys/ai/`), `fake_ai` stands in for OpenAI,
  Anthropic and Ollama through the provider base-URL setting, and
  `fake_cloud.ai.script(...)` scripts the hosted chat, replaying the recorded
  streams in `tests/fixtures/sse`.
- For several accounts per provider, `fleet.seed_second_accounts(providers)`
  adds a second Hetzner project and OVH account, with their servers, to the
  stand-ins, and `seed.hetzner_account(...)` / `seed.ovh_account(...)` write
  config entries with the credentials those accounts answer; each stand-in
  refuses credentials it does not know, as the real service does. A second
  AWS account is a named profile that assumes a role in another moto
  account: `moto.seed_account(...)`, then `seed.aws_profile(...)` and
  `seed.aws_account(...)`. `providers.requests(..., account="staging")`
  shows which account each call reached.
- Seeded configs list AWS instances from the fleet's regions only
  (`fleet.AWS_REGIONS`): discovering every region costs one call per region
  on each refresh, which is slow on a busy machine. `seed.aws_config(...)`
  and `seed.aws_account(...)` set that list for you; give an AWS config you
  build yourself a `regions` list too, unless the journey is about discovery
  (then pass `regions=[]`).
- Wait for conditions (`wait_until`, `wait_for_screen`, `wait_for_toast`),
  never for a fixed time.
- To prove a secret never reached the service, use
  `fake_cloud.assert_absent_on_wire(...)`: it searches every request
  unredacted, in any encoding. The request log (`fake_cloud.requests()`) is
  redacted for the artifacts, so a check against it proves nothing. Register
  every secret you fabricate with `artifacts.register_secret` so it never
  reaches an artifact.
- Mark it `e2e_pr` to run it on every pull request. A journey that turns out
  to be flaky gets `e2e_quarantine` until it is fixed. Every journey needs one
  of the two; collection stops with an error otherwise.
- A journey that documents a known bug is marked `xfail(strict=True)` through
  `known_bug()` in `e2e/harness/known_bugs.py`, naming the exception the
  journey raises at the exact symptom, so any other failure still fails. The
  fix makes it fail as "unexpectedly passing", so remove the marker in the
  same change as the fix.

## Local QA sandbox

Before you open a pull request, use what you changed the way a user would:
open the screen, run the command, try the wrong input and a narrow terminal.
The QA sandbox makes that safe. It runs the stand-ins of the end-to-end suite
(Servonaut API, package index, AWS, CloudTrail, Hetzner, OVH and the loopback
SSH servers) with a seeded home, under the same guards, and never touches
your own config, credentials or servers.

```bash
python -m e2e.sandbox up &          # or: up --scenario multi-account
python -m e2e.sandbox status        # seeded servers, stand-ins, request logs
```

`up` stays in the foreground until it is stopped; wait for the line
`SANDBOX READY <path to state.json>`. Everything lives in `.qa-sandbox/` in
the checkout. Another directory given with `--root` belongs outside the
checkout, or at `.qa-sandbox-<name>` in its top level: git ignores only
those, and a sandbox holds private keys and tokens (`up` refuses anything
else inside the checkout). One sandbox runs per user at a time: every command finds it
through `${XDG_STATE_HOME:-~/.local/state}/servonaut-qa/current.json`, the
only file the sandbox writes outside its directory. `--signed-in` starts
signed in to the local API.

- `single` is the typical user: one account per provider, the AWS, Hetzner
  and OVH fleets of `e2e/harness/fleet.py` and the custom server `web-1`.
  `multi-account` adds a second account per provider, each with a server
  named `web-1`. `status` lists every server with the reference that picks
  it and whether it accepts SSH (`web-1`, and `app-1` through `bastion-1`).
- CLI: `python -m e2e.sandbox run -- ssh web-1 -- uptime` runs the
  checkout's `servonaut` in the sandbox and exits with its status.
- MCP: `python -m e2e.sandbox mcp-call list_instances '{"account": "prod"}'`
  calls one tool of the real MCP server and prints the result;
  `python -m e2e.sandbox mcp` serves it over stdio for an MCP client.
- TUI: `e2e/sandbox/tpmcp_spec.py` (160x50) and `tpmcp_spec_narrow.py`
  (100x30) are specs for [textual-pilot-mcp](https://github.com/zb-ss/textual-pilot-mcp),
  which drives the TUI over MCP. Its `launch` runs the TUI of the checkout
  that started the sandbox, inside the sandbox. Register each spec once with
  `textual-pilot-mcp install --client <client> --spec <absolute path>`. The
  server's Python needs Servonaut's dependencies with the Hetzner and OVH
  client libraries; for a pipx install run
  `pipx inject textual-pilot-mcp -e "<checkout>[hetzner,ovh]" --force` (again
  after a dependency changes). Snapshots go to
  `${XDG_STATE_HOME:-~/.local/state}/servonaut-qa/captures/`. Start the server
  from the checkout root, and without an empty entry in `PYTHONPATH` (an
  empty entry means the working directory): a directory inside
  `src/servonaut` on the import path puts Servonaut's own modules (such as
  `secrets.py`) in place of the standard library's, and the server fails at
  start-up. A server keeps the checkout and sandbox directory of its first
  `launch`; restart it after starting a sandbox from another checkout.
- Desktop: `python -m e2e.sandbox desktop` starts the desktop child without a
  window and prints its URL, a single-use session token, a snippet that
  starts the session in a browser page (it waits for the first output and
  focuses the terminal), and one that clicks a terminal cell. Keys reach the
  app only while the terminal has focus; `window.servonautQa.focus()` gives
  it back after a click elsewhere. The terminal is drawn on a canvas, so a
  browser's text waits never match: judge states from screenshots, or read
  the visible screen with `window.servonautQa.text()` and
  `window.servonautQa.waitForText(...)`.

`python -m e2e.sandbox down` stops everything and deletes `.qa-sandbox/`;
with `up --keep` the directory is kept for inspection, renamed to
`.qa-sandbox.kept-<time>` (delete it yourself). `down` exits non-zero if a
sandbox process survived. Where there is no `/proc` (macOS), it can only
check the desktop processes the sandbox recorded, by their start time and
command; the others stop by themselves once the sandbox directory is gone.
The sandbox's owner holds a lock on a marker file in that directory for as
long as it runs; only a directory with that marker and nobody holding its
lock is ever removed automatically.

## Code of Conduct
Please note that this project is released with a Contributor Code of Conduct. By participating in this project you agree to abide by its terms. For now, please be respectful and constructive in all interactions.

## License
By contributing to Servonaut, you agree that your contributions will be licensed under its MIT License.

Thank you for your contribution!
