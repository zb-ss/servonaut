#!/usr/bin/env bash
# Install Ubuntu packages on a GitHub-hosted runner without stalling on a slow
# mirror. Usage: apt-install.sh [apt-get install options] PACKAGE...
#
# The runners use an Ubuntu mirror inside their own cloud, which now and then
# serves a runner at tens of kB/s: an install that takes 30 seconds then
# outlasts the job's time limit. So the packages are downloaded first, each
# attempt with a time limit. When an attempt runs out or fails, the next one
# uses the main Ubuntu archive, and a last attempt has no limit. Finished
# downloads stay in apt's cache, so a retry only fetches the rest; only
# downloads are ever stopped, never dpkg.
set -euo pipefail

attempt_seconds="${APT_ATTEMPT_SECONDS:-120}"
apt_dir="${APT_DIR:-/etc/apt}"
fallback_mirror="http://archive.ubuntu.com/ubuntu/"

download() {
  local limit="$1"
  shift
  sudo timeout --kill-after=10 "$limit" apt-get update -q \
    && sudo timeout --kill-after=10 "$limit" apt-get install -y -q --download-only "$@"
}

# Regional and cloud mirrors are subdomains of archive.ubuntu.com.
mirror_host='https?://[a-z0-9.-]+\.archive\.ubuntu\.com/'

use_fallback_mirror() {
  local sources=() lists=() list
  shopt -s nullglob
  sources=("$apt_dir"/sources.list "$apt_dir"/sources.list.d/*.list "$apt_dir"/sources.list.d/*.sources)
  shopt -u nullglob
  echo "::warning::The Ubuntu mirror did not deliver within ${attempt_seconds}s; switching to the main Ubuntu archive"
  [ "${#sources[@]}" -gt 0 ] || return 0
  sudo sed -i -E "s#${mirror_host}ubuntu/?#${fallback_mirror}#g" "${sources[@]}"
  # GitHub's runners name a mirror list instead (mirror+file:/etc/apt/apt-mirrors.txt),
  # with their cloud mirror first. Drop that entry and keep the main archive.
  mapfile -t lists < <(grep -ohE 'mirror\+file:[^[:space:]]+' "${sources[@]}" | sed 's/^mirror+file://' | sort -u || true)
  for list in "${lists[@]}"; do
    [ -f "$list" ] || continue
    sudo sed -i -E "\\#^${mirror_host}#d" "$list"
    if ! grep -qE '^https?://archive\.ubuntu\.com/' "$list"; then
      { echo "$fallback_mirror"; cat "$list"; } | sudo tee "$list.fallback" > /dev/null
      sudo mv "$list.fallback" "$list"
    fi
  done
}

if ! download "$attempt_seconds" "$@"; then
  use_fallback_mirror
  if ! download "$attempt_seconds" "$@"; then
    echo "::warning::The fallback mirror did not deliver within ${attempt_seconds}s either; retrying without a time limit"
    download 0 "$@"
  fi
fi
sudo apt-get install -y -q "$@"
