#!/usr/bin/env bash
# Forward qualification of the packaged Linux desktop, run as root inside a
# clean container of a newer Ubuntu release, with unprivileged user
# namespaces restricted the way that release restricts them:
#
#   1. install the .deb built from the payload, with only its declared Depends;
#   2. require every library the installed payload links to resolve;
#   3. add the smoke's own tools (Python for the runner, a virtual display and
#      a screenshot tool) and the release's AppArmor, whose installation loads
#      its policy into the host kernel, as booting that release does;
#   4. require an unprivileged user to be refused a user namespace by that
#      policy, so the restriction is really in force;
#   5. open the installed window, as an unprivileged user, with the same
#      window smoke the build host runs, on the virtual X display;
#   6. add a headless Wayland compositor, weston without Xwayland, and open
#      the window again as that user, with GTK held to Wayland and no X
#      display. The smoke requires the window's processes to be connected to
#      the compositor and to no X server, so a fallback to X11 fails it.
#
# Both windows are opened even when the first fails, and the script fails if
# either did not open.
#
# The package ships no AppArmor profile, because nothing it starts needs a
# user namespace: WebKit's bubblewrap sandbox is off. Steps 5 and 6 fail the
# day that changes, on a release whose policy refuses one.
#
# usage: forward_window_smoke.sh DEB TARGET OUTPUT_DIR OWNER_UID:GID
# Run from the repository root; OUTPUT_DIR receives the reports and
# screenshots and is handed back to OWNER when the script ends.
set -euo pipefail

deb=$1
target=$2
output=$3
owner=$4
install_root=/opt/servonaut
smoke_user=servonaut-smoke

trap 'chown -R "${owner}" "${output}"' EXIT
export DEBIAN_FRONTEND=noninteractive

fail() {
  echo "$*" >&2
  exit 1
}

if [[ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)" != 1 ]]; then
  fail "The host kernel does not restrict unprivileged user namespaces."
fi

apt-get update -qq
apt-get install --yes --no-install-recommends "${deb}"

# The launcher puts its contents directory on the library path, so resolve
# with it there, as the running payload does.
unresolved=$(
  find "${install_root}" -type f \( -name '*.so' -o -name '*.so.*' -o -perm -u+x \) -print0 \
    | LD_LIBRARY_PATH="${install_root}/_internal" xargs -0 ldd 2>/dev/null \
    | grep 'not found' | sort -u || true
)
if [[ -n "${unresolved}" ]]; then
  echo "The package's Depends leave payload libraries unresolved:" >&2
  echo "${unresolved}" >&2
  exit 1
fi

apt-get install --yes --no-install-recommends python3 xvfb xauth imagemagick apparmor
useradd --create-home "${smoke_user}"
chmod 0777 "${output}"
host=$(. /etc/os-release && echo "${ID}-${VERSION_ID}")

# The release's policy gives an unprivileged process its namespace without
# capabilities, so setting up the uid map fails. Docker's seccomp filter or
# the bare restriction would refuse the namespace itself instead.
if refusal=$(runuser -u "${smoke_user}" -- unshare --user --map-root-user true 2>&1); then
  fail "An unprivileged user was given a working user namespace, so the restriction is not in force."
fi
[[ "${refusal}" == *"/proc/self/uid_map"* ]] \
  || fail "User namespaces were refused, but not by ${host}'s AppArmor policy: ${refusal}"
echo "${host}'s AppArmor policy refuses unprivileged user namespaces: ${refusal}"

# open_window DISPLAY_SERVER SESSION_RUNNER...: the window smoke, as the
# unprivileged user, in a DISPLAY_SERVER session that SESSION_RUNNER starts.
open_window() {
  local display=$1
  shift
  runuser -u "${smoke_user}" -- env PYTHONDONTWRITEBYTECODE=1 \
    "$@" \
    python3 -m scripts.desktop_shell.window_smoke \
    --payload-root "${install_root}" \
    --target "${target}" \
    --display "${display}" \
    --evidence-dir "${output}" \
    --screenshot "${output}/desktop-window-${target}-on-${host}-${display}.png"
}

# describe DISPLAY_SERVER: what the window's processes ran as and reached.
describe() {
  python3 -c '
import json, sys
report = json.load(open(sys.argv[1]))
print("The window processes ran as:", json.dumps(report["process_security_labels"], sort_keys=True))
print("They were connected to:", ", ".join(report["display_protocols"]))
' "${output}/window-smoke-report-${target}-on-${host}-$1.json"
}

failed=()
if open_window x11 xvfb-run --auto-servernum --server-args="-screen 0 1280x800x24"; then
  describe x11
else
  failed+=(X11)
fi

# The compositor is installed after the X11 window has opened, so that window
# had nothing more than before.
apt-get install --yes --no-install-recommends weston
if [[ -e /usr/bin/Xwayland ]]; then
  fail "Installing weston brought Xwayland, so the Wayland window could fall back to X11."
fi
if open_window wayland bash scripts/desktop_shell/weston_run.sh; then
  describe wayland
else
  failed+=(Wayland)
fi

if ((${#failed[@]})); then
  fail "The window did not open on ${failed[*]} while ${host} restricts unprivileged" \
    "user namespaces. If WebKit now needs one (its bubblewrap sandbox), ship an" \
    "AppArmor profile that grants the launcher userns."
fi
