#!/usr/bin/env bash
# Run a command on a headless Wayland compositor, as xvfb-run does on a
# virtual X display.
#
# Starts weston with its headless backend and software renderer on a private
# runtime dir, runs COMMAND with WAYLAND_DISPLAY and XDG_RUNTIME_DIR naming it
# and without DISPLAY, and stops the compositor afterwards. Weston starts no
# Xwayland unless asked to, so nothing COMMAND starts can reach an X server.
# The kiosk shell shows each window full-screen on the 1280x800 output, and
# --debug lets weston-screenshooter photograph it.
#
# usage: weston_run.sh COMMAND [ARG...]
# Exits with COMMAND's status; prints the compositor's log when that fails.
set -euo pipefail

if (($# == 0)); then
  echo "usage: $0 COMMAND [ARG...]" >&2
  exit 2
fi

socket_name=wayland-smoke
startup_seconds=10
# Short, because a Unix socket path must fit in 108 bytes.
runtime_dir=$(mktemp -d /tmp/weston.XXXXXX)
log="${runtime_dir}/weston.log"

stop_compositor() {
  kill "${weston_pid}" 2>/dev/null || true
  wait "${weston_pid}" 2>/dev/null || true
  rm -f "${runtime_dir}/${socket_name}" "${runtime_dir}/${socket_name}.lock" "${log}"
  rmdir "${runtime_dir}" 2>/dev/null || true
}

XDG_RUNTIME_DIR="${runtime_dir}" weston \
  --backend=headless --renderer=pixman --width=1280 --height=800 \
  --shell=kiosk --socket="${socket_name}" --idle-time=0 --no-config \
  --debug --log="${log}" &
weston_pid=$!
trap stop_compositor EXIT

deadline=$((SECONDS + startup_seconds))
until [[ -S "${runtime_dir}/${socket_name}" ]]; do
  if ! kill -0 "${weston_pid}" 2>/dev/null || ((SECONDS >= deadline)); then
    echo "weston did not start its headless compositor within ${startup_seconds}s:" >&2
    cat "${log}" >&2 || true
    exit 1
  fi
  sleep 0.1
done

status=0
env -u DISPLAY -u XAUTHORITY \
  XDG_RUNTIME_DIR="${runtime_dir}" WAYLAND_DISPLAY="${socket_name}" \
  "$@" || status=$?
if ((status != 0)); then
  echo "--- weston log (tail) ---" >&2
  tail -n 40 "${log}" >&2 || true
fi
exit "${status}"
