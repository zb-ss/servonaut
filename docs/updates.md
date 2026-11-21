# Updating Servonaut

## Automatic updates with pipx

If you installed Servonaut with pipx or the Servonaut install script, opening
Servonaut can start a background check for a newer version. Servonaut
prepares the update in a separate Python environment and checks that it can
start. Once the update is ready and eligible, the next ordinary launch can
use it. Open windows and running MCP servers keep their version until you
restart them. For an MCP server, reconnect it or restart the application
that starts it.

Existing pipx installs get this behavior after they upgrade to a version
that includes it. If you need to upgrade immediately, run
`pipx upgrade servonaut`. `servonaut --update` also requests a manual
update for pipx and pip installations.

### Postpone an update

Open **Settings → Updates** to see the offered version. You can postpone an
offered version once for 24 hours. When that time expires, a later launch
can switch to the ready version. An offer you never see, for example if
you use only the CLI or MCP, can become eligible 24 hours after it was
first offered.

### Choose a channel

In **Settings → Updates**, choose **Stable** for stable releases or
**Release candidates** to also receive previews. Stable is the default for
a stable installation. If you are already running a release candidate and
have yet to save a channel preference, the default is Release candidates.
Your saved choice applies to future updates. Choosing Stable lets you move
to a newer stable release when it is available. [Release candidates](release-candidates.md)

### Choose a version manually

To replace an existing pipx installation with a specific version, use
`pipx install --force 'servonaut==X.Y.Z'` with the version you want. Include
any extras you previously installed, for example
`pipx install --force 'servonaut[mcp]==X.Y.Z'`.

If this changes the pipx-installed version to one older than the version
Servonaut was using, Servonaut starts your manually installed version and
shows the pin in **Settings → Updates**. Automatic updates can resume once
there is a release newer than the version you went back from. A manual
upgrade to a newer version takes effect the next time you launch.

### CI and automation

Set `SERVONAUT_SKIP_AUTO_APPLY=1` in the process environment to run the
pipx-installed copy directly and skip automatic preparation and switching.
This gives scripts the version they installed with pipx, even when
Servonaut has prepared other copies.

## Upgrading a Debian package

Before upgrading from an older Debian package to the first release with
protected upgrades (2.35.0), close Servonaut,
including any running MCP servers and the background relay. Later upgrades
keep the files those sessions are already using.

After APT finishes configuring the package, **Settings → Updates** shows the
running version and offers **Restart Servonaut**. Confirm when you are ready
to close this window and its sessions. Reconnect any separate MCP servers
and restart standalone relay processes when you want them to use the new
version too.

Removing the package keeps any files that open sessions still use. A later
installation can clean up those files after the sessions exit. Purging the
package removes the retained copies and preserves your settings. If you have
mounted a separate filesystem at the generation directory, purge empties it
and leaves the mount in place.

## Disk space and uninstalling

Update copies live under
`~/.servonaut/updates/installs/<installation-id>/generations/`. A standard
copy uses about 110 MiB. Your Python version and installed extras affect its
size. By default, Servonaut needs 256 MiB free to prepare an update. It keeps
the current and previous working copies, plus a pending copy and any copies
that open sessions still use.

Close the windows and MCP servers that use the installation, then run
`pipx uninstall servonaut`. Its update copies remain under
`~/.servonaut/updates/installs/`. Delete the subdirectory for the
installation you removed. If you have more than one installation, the
`.servonaut-generation.json` file inside each copy includes an `anchor`
field with the path to its pipx environment. Keep the rest of
`~/.servonaut/` to preserve your settings and saved data.

## When an update cannot start

If a prepared copy fails its startup check, Servonaut continues with the
working version. If an active copy later fails to start, Servonaut can fall
back to the previous working copy. Repeated early startup failures can take
a few launches to detect. If there is no working update copy, Servonaut
tries the pipx-installed copy. Check **Settings → Updates** for the status
and run `servonaut --version` to see which version launches.

## When servonaut.dev requires a newer version

A message that servonaut.dev needs version X or later means a hosted
feature requires a newer client. SSH with your own keys, your local
configuration and other local tools keep working. The version requirement
applies to team features, the team and personal vaults, SSH certificates,
cloud sync, findings, the relay and Servonaut AI. You can still sign in and
open your account page. Update with the method you used to install
Servonaut, then sign in again if prompted.

| Installation | How to update |
| --- | --- |
| pipx or the install script | Run `pipx upgrade servonaut`. |
| pip | In the environment that runs Servonaut, run `python -m pip install --upgrade servonaut`. |
| Source checkout | Update the checkout to a supported release and reinstall using the same method, such as `python -m pip install .` or `pipx install --force .`. |
| Desktop app | Open the download link shown by the app and install the package or app update for your system. You can also find it on the [Servonaut download page](https://servonaut.dev/download). |

Close and reopen your windows, and restart any MCP servers that need the
update.

## Troubleshooting

- **A ready update has yet to switch.** Start Servonaut normally again and
  check **Settings → Updates** for a postponement or manual pin.
  `servonaut --version` and `servonaut --help` do not activate an update.
- **You are offline or PyPI is unreachable.** Servonaut can keep using the
  current working copy. By default, Servonaut rechecks a ready update
  before switching if its last check was more than five minutes ago.
  The check allows up to two seconds by default. If Servonaut cannot
  verify the update, try again when you are online.
- **Updates are managed elsewhere.** Automatic preparation is for supported
  pipx installations. A custom package index or an unavailable pipx command
  can leave updates to you. Use the update command for your installation.
- **A candidate is missing.** Check the channel in **Settings → Updates**.
  A withdrawn release is removed from the offers.
- **An update needs more space or Python was removed.** Free space for the
  new copy or reinstall Servonaut with pipx using an available Python.
  See the [installation troubleshooting guide](troubleshooting.md#the-install-script-stops).
