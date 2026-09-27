#!/usr/bin/env bash
# Forward qualification of the packaged Linux desktop, run as root inside a
# clean container of a newer Ubuntu release:
#
#   1. install the .deb built from the payload, with only its declared Depends;
#   2. require every library the installed payload links to resolve;
#   3. add the smoke's own tools (Python for the runner, a virtual display and
#      a screenshot tool) and open the installed window, as an unprivileged
#      user, with the same window smoke the build host runs.
#
# usage: forward_window_smoke.sh DEB TARGET OUTPUT_DIR OWNER_UID:GID
# Run from the repository root; OUTPUT_DIR receives the report and screenshot
# and is handed back to OWNER when the script ends.
set -euo pipefail

deb=$1
target=$2
output=$3
owner=$4
install_root=/opt/servonaut
smoke_user=servonaut-smoke

trap 'chown -R "${owner}" "${output}"' EXIT
export DEBIAN_FRONTEND=noninteractive

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

apt-get install --yes --no-install-recommends python3 xvfb xauth imagemagick
useradd --create-home "${smoke_user}"
chmod 0777 "${output}"
host=$(. /etc/os-release && echo "${ID}-${VERSION_ID}")

runuser -u "${smoke_user}" -- env PYTHONDONTWRITEBYTECODE=1 \
  xvfb-run --auto-servernum --server-args="-screen 0 1280x800x24" \
  python3 -m scripts.desktop_shell.window_smoke \
  --payload-root "${install_root}" \
  --target "${target}" \
  --evidence-dir "${output}" \
  --screenshot "${output}/desktop-window-${target}-on-${host}.png"
