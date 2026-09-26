# Desktop renderer checks

This source-only prototype opens Servonaut's Textual interface in a native
window using synthetic data. Instances, Help, and test-only modal/stream
exercises work; cloud operations, user configuration, SSH and voice are not
exercised. It is not a desktop installer.
The normal PyPI installation and its dependencies are unchanged.
The probe uses the upstream Canvas renderer without its redundant WebGL startup,
so a GPU is not required for the terminal interface.

## Get the code

Clone the repository once on each machine:

```sh
git clone https://github.com/zb-ss/servonaut.git
cd servonaut
```

For subsequent checks, use `git pull --ff-only` from a clean checkout and rerun
the dependency installation below. Never copy a virtual environment between OSes.

## Set up an isolated environment

Run all commands from the repository root. On Ubuntu 22.04 or 24.04:

```sh
sudo apt-get update
sudo apt-get install -y python3-venv python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.1 xvfb xauth
/usr/bin/python3 -m venv --system-site-packages local/desktop-probe-venv
source local/desktop-probe-venv/bin/activate
python -m pip install -r scripts/desktop_probe/requirements.txt
python -m playwright install --with-deps chromium webkit
```

Use the distribution's Python on Ubuntu: GTK's `gi` module must match its
interpreter. A separately downloaded Python may not be able to import it.

On macOS, install Python 3.12 and run:

```sh
python3.12 -m venv local/desktop-probe-venv
source local/desktop-probe-venv/bin/activate
python -m pip install -r scripts/desktop_probe/requirements.txt
python -m playwright install chromium webkit
```

On Windows, install Python 3.12 x64 and the
[WebView2 Evergreen Runtime](https://developer.microsoft.com/en-us/microsoft-edge/webview2/),
then use PowerShell (no activation or execution-policy change needed):

```powershell
py -3.12 -m venv local/desktop-probe-venv
& local/desktop-probe-venv/Scripts/python.exe -m pip install -r scripts/desktop_probe/requirements.txt
& local/desktop-probe-venv/Scripts/python.exe -m playwright install chromium webkit
```

Use that full Python path instead of `python` in the following commands on Windows.

## Run the checks

```sh
python -m scripts.desktop_probe.check --browser chromium --browser webkit --native
```

On a slow machine or CI runner, set `SERVONAUT_PROBE_TIME_SCALE` (for example
`3`) to multiply the startup and shutdown budgets. It only lengthens them; the
Intel macOS CI runner uses it.

This opens and closes a native window automatically. It checks authenticated
WebSockets, rejection of invalid tokens/origins and duplicate sessions, real
keyboard navigation and sidebar return, resize traffic, a real confirmation
modal (including its disabled action), Unicode paste-event delivery, RichLog
streaming and scrolling, crashes, parent death, port release and process
cleanup. Requested checks that skip or cannot start **fail** the command. The
native renderer is GTK on Linux, Cocoa/WKWebView on macOS and Edge/WebView2 on
Windows; it does not silently fall back to an older engine.

The browser test dispatches a synthetic browser `paste` event with Unicode text
and observes the resulting terminal WebSocket input. This proves the browser
clipboard-event boundary through the renderer and Textual input. It does **not**
read or write the operating-system clipboard; the native smoke test makes no
claim about OS clipboard integration.

For Linux without a display, prefix the command with `xvfb-run -a`. For quick
headless browser checks, omit `--native`; for socket-only checks, omit both
`--browser` arguments too. To explore the native window manually:

```sh
python -m scripts.desktop_probe
```

Results are written to a fresh directory under `local/desktop-probe-results/`:
`report.json` lists versions, individual outcomes and credential-free exception
locations for failed checks; each browser has Instances, Help, modal and
stream/scroll screenshots. There are no recordings, HARs, traces, credentials
or raw WebSocket dumps. Never enable credential-bearing traces on a real fleet.

If checks fail, inspect the failing test name and screenshots first. Verify
browser installation, GTK dependencies or WebView2 availability. For detailed
local diagnostics only, rerun the indicated test with pytest; browser tests
need `SERVONAUT_DESKTOP_BROWSER_TEST=1`, native tests need
`SERVONAUT_DESKTOP_NATIVE_TEST=1`. Do not publish raw test output: assertion
details can contain the ephemeral session credential. An installed Chrome can
be selected for local Chromium diagnostics using
`SERVONAUT_PROBE_BROWSER_CHANNEL=chrome`; CI uses the bundled engines.

## Automated coverage and milestone checks

The **Desktop probe** GitHub Actions workflow runs on relevant desktop-branch
pushes and pull requests to master. It also supports manual dispatch once the
workflow exists on the default branch. Download its per-OS results from the
workflow run's Artifacts section; those are reports, not installable applications.

| Automated runner | Native renderer | Not a substitute for |
| --- | --- | --- |
| Ubuntu 22.04 / 24.04 x64, Xvfb | GTK/WebKit | Wayland, desktop integration |
| Windows Server 2025 x64 | Edge/WebView2 | Windows 10 22H2 / 11, non-admin behaviour |
| macOS 15 Intel / Apple Silicon | Cocoa/WKWebView | macOS 13 minimum, signed installation |

Playwright's Chromium and WebKit builds test the served interface, not the exact
OS webview. Native smoke checks cover that separate boundary. Neither test layer
qualifies installers, system SSH, microphone permissions, upgrades or signing.

Use physical machines at the first native-renderer milestone, after changes to
OS integration or packaging, and before release qualification—not on every edit.
Docker is useful for Linux headless checks, but does not supply Windows/macOS
native renderers. Hosted runners provide routine cross-OS feedback without local
VM maintenance. Passing this workflow does not declare an OS stable or publish
an unsigned installer.
