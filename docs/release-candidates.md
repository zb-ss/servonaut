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
second needs the [GitHub CLI](https://cli.github.com/) 2.67 or later:

```bash
sha256sum -c servonaut-desktop-preview_2.28.0rc1_SHA256SUMS
gh attestation verify servonaut-desktop-preview_2.28.0rc1_amd64.deb --repo zb-ss/servonaut
```

The attestation shows that the package was built by a workflow in this
repository, and records the commit it was built from.

If downloads from GitHub are slow for you, the same files are also served
from a download mirror that stays fast on slow or lossy connections. Each
release's notes link its desktop files there, and
[servonaut.dev/download](https://servonaut.dev/download) offers the newest
stable one. The mirrored package is byte-for-byte the GitHub asset, so the
same two commands check it.

Older GitHub CLI versions cannot be relied on here: before 2.49 there is no
`gh attestation` command at all ("unknown command"; some distributions still
package such a version), and from 2.49 to 2.66 `gh attestation verify`
reports success even for a file that has no attestation
([CVE-2025-25204](https://nvd.nist.gov/vuln/detail/CVE-2025-25204)). Install
a current release from [cli.github.com](https://cli.github.com/). Until then
you can look the attestation up through the API, which shows the workflow
and the tag the file was built from (and answers `Not Found` for a file with
no attestation) but does not check the signature itself:

```bash
gh api "repos/zb-ss/servonaut/attestations/sha256:$(sha256sum servonaut-desktop-preview_2.28.0rc1_amd64.deb | cut -d' ' -f1)" \
  --jq '.attestations[].bundle.dsseEnvelope.payload | @base64d | fromjson | .predicate.buildDefinition.externalParameters.workflow'
```

Install it with apt, which also installs the system libraries it needs:

```bash
sudo apt install ./servonaut-desktop-preview_2.28.0rc1_amd64.deb
```

Start **Servonaut** from your applications menu, or run `servonaut-desktop`.
The package is named `servonaut` and also provides the `servonaut` command;
if you installed Servonaut with pipx as well, `which servonaut` shows which
one your shell runs. Both use your configuration in `~/.servonaut/`. If you
later uninstall the pipx copy, the desktop app points coding agents that
still use it as their MCP server at its own `servonaut` command the next time
it starts.

A shortcut made by an earlier `servonaut --install-desktop`, which opens
Servonaut in a terminal, may also be listed as **Servonaut**. Run
`servonaut --install-desktop` from your pipx installation to replace it with
**Servonaut (terminal)**; the packaged `servonaut` command only tells you
where that shortcut is.

A candidate's package version is `2.28.0~rc1`, so apt counts the release
`2.28.0` as newer and installs it over the candidate as an upgrade.

An installed preview tells you when a newer one is out (see
[Updates in the desktop preview](#updates-in-the-desktop-preview)), but never
installs it by itself. To move to a newer candidate or release, install its
package the same way.

To remove it:

```bash
sudo apt remove servonaut
```

Removing the package keeps your configuration and data in `~/.servonaut/`.

## macOS desktop preview

Releases and release candidates can also carry a preview of the desktop app
for macOS 13 (Ventura) or later, attached some time after the release is
published:

- `servonaut-desktop-preview_<version>_macos-arm64.dmg`, for Macs with Apple
  silicon (M1 or later);
- `servonaut-desktop-preview_<version>_macos-x64.dmg`, for Macs with an Intel
  processor;
- `servonaut-desktop-preview_<version>_macos_SHA256SUMS`, the checksums of
  both disk images.

To see which one you need, open the Apple menu and choose **About This Mac**:
a **Chip** line naming Apple M1 or later means Apple silicon, a **Processor**
line naming Intel means an Intel Mac. In Terminal, `uname -m` prints `arm64`
or `x86_64`.

Like the Linux package, it is a **preview** for trying the desktop app out and
reporting problems, and a release can go out without one. The app and its disk
image are signed with an Apple Developer ID and notarized by Apple, so macOS
opens them without a warning. The app must pass its self-test and open its
window both before and after it is signed, or the disk image is not attached.

Check the download before you open it. Set `version` to the version you
downloaded and `image` to `macos-arm64` or `macos-x64`; both checks must
succeed, and the second needs the GitHub CLI 2.67 or later, as above:

```bash
version=X.Y.Z
image=macos-arm64
grep "_${image}.dmg\$" "servonaut-desktop-preview_${version}_macos_SHA256SUMS" | shasum -a 256 -c -
gh attestation verify "servonaut-desktop-preview_${version}_${image}.dmg" --repo zb-ss/servonaut
```

macOS can also show you the signature it checks when you open the image:

```bash
spctl --assess --type open --context context:primary-signature -v "servonaut-desktop-preview_${version}_${image}.dmg"
```

It prints `accepted` and `source=Notarized Developer ID`.

To install it, open the disk image, drag **Servonaut** onto the
**Applications** folder next to it, and eject the image. Start Servonaut from
Launchpad or the Applications folder. It uses your configuration in
`~/.servonaut/`, like any other installation.

The download mirror described above serves the disk images too, and each
release's notes link them. To move to a newer candidate or release, install
its disk image the same way, and let Finder replace the copy you have.

To remove it, drag **Servonaut** from the Applications folder to the Trash.
Your configuration and data in `~/.servonaut/` are kept.

## Updates in the desktop preview

The desktop preview checks for a newer release each time it starts. Previews
published before this check existed never offer an update, so install a newer
one by hand once.

The check reads a small update manifest from the download mirror at
`releases.servonaut.dev`, and acts on it only when it is signed with a release
key built into the app and has not expired. It is a plain HTTPS request that
carries the app's version in its `User-Agent` header and nothing about you or
your servers. What you are offered follows the preview you run, as it does for
pip and pipx installations:

| You run the preview of | You are offered |
|------------------------|-----------------|
| A stable release | Newer stable releases only |
| A release candidate | The newest candidate or stable release, whichever is newer |

A release that has no preview for your system is not offered.

When a newer preview is out, Servonaut shows a notice and an **Update** button
in the sidebar. The button downloads the package or disk image for your
system, checks its size and SHA-256 against the signed manifest, and tells you
how to install it: with `sudo apt install` on Linux, or by opening the disk
image and dragging Servonaut to Applications on macOS. Nothing is installed
for you. On Linux, `servonaut --update` does the same from a terminal.

To check a different manifest, such as your own copy of it, set
`SERVONAUT_RELEASE_MANIFEST_URL` (see
[Configuration](configuration.md)); it must still be signed by a key built into
the app.

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
