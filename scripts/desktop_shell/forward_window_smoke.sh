#!/usr/bin/env bash
# Forward qualification of the packaged Linux desktop, run as root inside a
# clean container of a newer Ubuntu release. The host kernel restricts
# unprivileged user namespaces the way that release does, and the container
# shares the host's AppArmor: its processes are unconfined, as in a desktop
# session, and it may load policy.
#
#   1. install the .deb built from the payload, with only its declared Depends,
#      and require every library the installed payload links to resolve;
#   2. add the smoke's own tools (Python for the runner, a virtual display and
#      a screenshot tool) and the release's AppArmor, which loads its policy
#      and, through the package's trigger, the launcher's profile;
#   3. without that profile the window must fail, with bubblewrap refused the
#      user namespace WebKit's sandbox needs;
#   4. reconfigured, the package loads the profile again and the window must
#      open, as an unprivileged user, with the same window smoke the build
#      host runs, and with bubblewrap running under the profile;
#   5. removing the package must take the profile out of the kernel, and
#      purging it must delete the profile.
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
profile_name=servonaut-desktop
profile=/etc/apparmor.d/${profile_name}
disable_link=/etc/apparmor.d/disable/${profile_name}
loaded_profiles=/sys/kernel/security/apparmor/profiles
# What bubblewrap prints when AppArmor refuses it a user namespace.
refused_namespace='^bwrap: .*(uid map|namespace)'

trap 'chown -R "${owner}" "${output}"' EXIT
export DEBIAN_FRONTEND=noninteractive

fail() {
  echo "$*" >&2
  exit 1
}

profile_loaded() {
  grep -qx "${profile_name} (unconfined)" "${loaded_profiles}"
}

window_smoke() {
  runuser -u "${smoke_user}" -- env PYTHONDONTWRITEBYTECODE=1 \
    xvfb-run --auto-servernum --server-args="-screen 0 1280x800x24" \
    python3 -m scripts.desktop_shell.window_smoke \
    --payload-root "${install_root}" \
    --target "${target}" \
    "$@"
}

if [[ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)" != 1 ]]; then
  fail "The host kernel does not restrict unprivileged user namespaces."
fi
[[ -r "${loaded_profiles}" ]] || fail "The host's AppArmor policy is not visible here."

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
# Without AppArmor 4 the package keeps its profile disabled and unloaded.
[[ -L "${disable_link}" ]] || fail "Without AppArmor 4 the package did not disable its profile."
! profile_loaded || fail "The profile was loaded without AppArmor 4."

apt-get install --yes --no-install-recommends python3 xvfb xauth imagemagick apparmor
[[ ! -e "${disable_link}" ]] || fail "AppArmor 4 arrived, but the package kept its profile disabled."
profile_loaded || fail "AppArmor 4 arrived, but the package's trigger did not load its profile."
useradd --create-home "${smoke_user}"
chmod 0777 "${output}"
host=$(. /etc/os-release && echo "${ID}-${VERSION_ID}")

apparmor_parser --remove "${profile}"
! profile_loaded || fail "The profile could not be unloaded."
without_profile=$(mktemp)
if window_smoke --screenshot "${output}/desktop-window-${target}-on-${host}-without-profile.png" \
  >"${without_profile}" 2>&1; then
  cat "${without_profile}"
  fail "The window opened without the profile, so the restriction was not exercised."
fi
echo "--- window smoke without the profile ---"
cat "${without_profile}"
refusal=$(grep -m1 -E "${refused_namespace}" "${without_profile}") \
  || fail "The window failed without the profile, but not because bubblewrap was refused its namespace."
echo "Without the profile the window failed; bubblewrap reported: ${refusal}"

dpkg-reconfigure servonaut
profile_loaded || fail "Reconfiguring the package did not load its profile."
window_smoke \
  --evidence-dir "${output}" \
  --screenshot "${output}/desktop-window-${target}-on-${host}.png"
bwrap_labels=$(python3 -c '
import json, sys
labels = json.load(open(sys.argv[1]))["process_security_labels"]
print(" ".join(labels.get("bwrap", [])))
' "${output}/window-smoke-report-${target}-on-${host}.json")
[[ "${bwrap_labels}" == "${profile_name} (unconfined)" ]] \
  || fail "Bubblewrap ran as '${bwrap_labels}', not under the launcher's profile."
echo "With the profile the window opened; bubblewrap ran as ${bwrap_labels}"

apt-get remove --yes servonaut
! profile_loaded || fail "Removing the package left its profile loaded."
[[ -f "${profile}" ]] || fail "Removing the package deleted its conffile before purge."
apt-get purge --yes servonaut
[[ ! -e "${profile}" ]] || fail "Purging the package left its profile behind."

REFUSAL="${refusal}" BWRAP_LABEL="${bwrap_labels}" python3 -c '
import json, os, sys
report = {
    "schema_version": 1,
    "target": sys.argv[1],
    "host_platform": sys.argv[2],
    "restrict_unprivileged_userns": True,
    "window_failed_without_profile": True,
    "bubblewrap_error_without_profile": os.environ["REFUSAL"],
    "window_opened_with_profile": True,
    "bubblewrap_label_with_profile": os.environ["BWRAP_LABEL"],
    "profile_unloaded_on_remove": True,
    "profile_deleted_on_purge": True,
}
with open(sys.argv[3], "w", encoding="utf-8") as handle:
    json.dump(report, handle, indent=2)
    handle.write("\n")
' "${target}" "${host}" "${output}/apparmor-userns-report-${target}-on-${host}.json"
