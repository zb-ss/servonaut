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

use_fallback_mirror() {
  local sources=()
  shopt -s nullglob
  sources=("$apt_dir"/sources.list "$apt_dir"/sources.list.d/*.list "$apt_dir"/sources.list.d/*.sources)
  shopt -u nullglob
  echo "::warning::The Ubuntu mirror did not deliver within ${attempt_seconds}s; switching to ${fallback_mirror}"
  if [ "${#sources[@]}" -gt 0 ]; then
    sudo sed -i -E "s#https?://[a-z0-9.-]*archive\.ubuntu\.com/ubuntu/?#${fallback_mirror}#g" "${sources[@]}"
  fi
}

if ! download "$attempt_seconds" "$@"; then
  use_fallback_mirror
  if ! download "$attempt_seconds" "$@"; then
    echo "::warning::The fallback mirror did not deliver within ${attempt_seconds}s either; retrying without a time limit"
    download 0 "$@"
  fi
fi
sudo apt-get install -y -q "$@"
