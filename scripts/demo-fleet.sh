#!/usr/bin/env bash
# Spin up + tear down a 4-server Hetzner demo fleet for marketing
# recordings + smoke verification. Wraps scripts/demo_fleet.py so the
# operator-facing entry point is the conventional shell script the
# kickoff brief references.
#
# Usage:
#   ./scripts/demo-fleet.sh                # 4 servers, full create+destroy
#   ./scripts/demo-fleet.sh --keep         # leave the fleet up (manual cleanup later)
#   ./scripts/demo-fleet.sh --reset        # nuke any leftover demo-* first
#   ./scripts/demo-fleet.sh --count 6      # different fleet size
#
# Prereqs:
#   - python3 with the hcloud SDK installed (the project venv has it).
#   - $HCLOUD_TOKEN set in the environment OR ~/.config/hcloud/token.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${REPO_ROOT}/.venv/bin/python"
if [[ ! -x "${PY}" ]]; then
    PY="$(command -v python3)"
fi

exec "${PY}" "${REPO_ROOT}/scripts/demo_fleet.py" "$@"
