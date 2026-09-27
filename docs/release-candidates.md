# Release candidates

Every Servonaut release is published as a **release candidate** first: a
build of the next version with a number such as `2.28.0rc1`. Trying a
candidate lets you check the next release against your own servers and
report problems before it reaches everyone.

Candidates are opt-in. pip and pipx install one only when you ask for it,
and a stable installation is never offered one.

## How a release comes together

- **Monday:** when there are changes to ship, the next version is published
  to PyPI as a release candidate, `X.Y.Zrc1`.
- **During the week:** fixes for problems found in a candidate can be
  published as new candidates, `rc2`, `rc3` and so on.
- **Thursday:** after the maintainers approve the latest candidate, it is
  published as the stable release `X.Y.Z`. The stable release is that
  candidate with only its version number changed.

Some weeks have no release: when nothing has changed since the last one, or
when no candidate is approved.

A candidate with a serious problem can be **withdrawn** (yanked on PyPI). A
withdrawn candidate never becomes a stable release, the update check stops
offering it, and pip skips it unless you ask for its exact version. A new
candidate follows with the fix.

Current and past candidates are listed on the
[GitHub releases page](https://github.com/zb-ss/servonaut/releases), marked
*Pre-release*, and in the [PyPI release history](https://pypi.org/project/servonaut/#history).

## Who they are for

Candidates are for people who want the next release early and are happy to
report what goes wrong. They pass the same automated tests as a stable
release before they are published, but they have had less use. Run one
where a problem would be an inconvenience rather than an outage, and keep a
stable installation for anything you cannot afford to have break.

## Install a release candidate

Every method below installs Servonaut from PyPI, and each one that replaces
an existing installation keeps your configuration and data in
`~/.servonaut/`.

### With the install script

The install scripts of the latest stable release install the newest
candidate when asked, or the stable release when that is newer than every
candidate. They replace an existing pipx installation.

**Linux / macOS:**

```bash
curl -fsSL https://github.com/zb-ss/servonaut/releases/latest/download/install.sh | bash -s -- --pre
```

**Windows (PowerShell):**

```powershell
$env:SERVONAUT_PRE = "1"; irm https://github.com/zb-ss/servonaut/releases/latest/download/install.ps1 | iex
```

`SERVONAUT_PRE` stays set in that PowerShell window, so running the installer
there again installs a candidate again. Clear it with
`Remove-Item Env:SERVONAUT_PRE`, or open a new window. From a downloaded copy
of the scripts, run `./install.sh --pre` or `.\install.ps1 -Pre`. Each
candidate's release page also carries its own copy of the scripts, with
`install-scripts_SHA256SUMS`.

### With pipx

Install a specific candidate:

```bash
pipx install --force 'servonaut==2.28.0rc1'
```

Or the newest one, whatever its number:

```bash
pipx install --force 'servonaut>=0rc0'
```

`--force` replaces an existing installation. The `>=0rc0` part lets pip pick
a pre-release of Servonaut; when no candidate is newer than the stable
release, you get the stable release. If you installed Servonaut with extras,
name them again, for example `pipx install --force 'servonaut[all]==2.28.0rc1'`.

### With pip

```bash
pip install 'servonaut==2.28.0rc1'          # a specific candidate
pip install --upgrade 'servonaut>=0rc0'     # the newest candidate
```

### Avoid `--pre`

`pip install --pre servonaut` and `pipx install --pip-args=--pre servonaut`
also accept pre-release versions of every package Servonaut depends on, and
some of those do not work with Servonaut. Name the candidate, or use
`>=0rc0` as above, so that only Servonaut itself is a pre-release.

## Try one without changing your installation

```bash
pipx run --spec 'servonaut==2.28.0rc1' servonaut
```

This runs the candidate from a temporary environment and leaves your
installed version as it is. It still uses your configuration in
`~/.servonaut/`, so settings you change while trying it are kept.

## Updates on a release candidate

The update check at startup (and `servonaut --update`) depends on what you
are running:

| You run | You are offered |
|---------|-----------------|
| A stable release | Newer stable releases only — never a candidate |
| A release candidate | The newest candidate or stable release, whichever is newer |

So while you run a candidate you move on to the next candidate as it is
published, and to the stable release once it is out. A withdrawn candidate
is never offered. Once you are on a stable release, you are offered stable
releases only again.

## Go back to the stable release

With pipx (including installations made by the install scripts):

```bash
pipx install --force servonaut
```

This installs the newest stable release, even when it is older than the
candidate you had, and keeps your configuration. If you installed with
extras, name them again: `pipx install --force 'servonaut[all]'`.

With pip:

```bash
pip install --force-reinstall servonaut
```

If the candidate moved your configuration to a newer format, it saved a copy
of the previous one first. `servonaut --list-backups` lists your
configuration backups, and `servonaut --restore-backup N` restores one; a
restored backup does not contain changes you made later.

## Linux desktop preview

Every release and release candidate on the
[GitHub releases page](https://github.com/zb-ss/servonaut/releases) also
carries a preview of the Servonaut desktop app for Ubuntu on 64-bit x86
(amd64), attached a little while after the release is published:

- `servonaut-desktop-preview_<version>_amd64.deb`, the package;
- `servonaut-desktop-preview_<version>_SHA256SUMS`, its checksum.

The desktop app is a **preview**: it is not released yet, and each package is
for trying the desktop app out and reporting problems. It is built on Ubuntu
22.04 and must pass its self-test, open its window and install cleanly before
it is attached. A release can go out without a preview when the desktop app
has a known problem at that version.

Check the download before you install it. Both commands must succeed; the
second needs the [GitHub CLI](https://cli.github.com/):

```bash
sha256sum -c servonaut-desktop-preview_2.28.0rc1_SHA256SUMS
gh attestation verify servonaut-desktop-preview_2.28.0rc1_amd64.deb --repo zb-ss/servonaut
```

The attestation shows that the package was built by a workflow in this
repository, and records the commit it was built from.

Install it with apt, which also installs the system libraries it needs:

```bash
sudo apt install ./servonaut-desktop-preview_2.28.0rc1_amd64.deb
```

Start **Servonaut** from your applications menu, or run `servonaut-desktop`.
The package is named `servonaut` and also provides the `servonaut` command;
if you installed Servonaut with pipx as well, `which servonaut` shows which
one your shell runs. Both use your configuration in `~/.servonaut/`.

A candidate's package version is `2.28.0~rc1`, so apt counts the release
`2.28.0` as newer and installs it over the candidate as an upgrade.

An installed preview does **not** update itself yet. To move to a newer
candidate or release, download its package and install it the same way.

To remove it:

```bash
sudo apt remove servonaut
```

Removing the package keeps your configuration and data in `~/.servonaut/`.

## Report a problem

Open an issue at
[github.com/zb-ss/servonaut/issues](https://github.com/zb-ss/servonaut/issues)
and include:

- the version, from `servonaut --version`,
- how you installed it (install script, pipx or pip) and your operating
  system,
- what you did, what you expected, and what happened instead,
- relevant lines from `~/.servonaut/logs/servonaut.log`. Remove hostnames,
  addresses and anything else you would rather not publish.
