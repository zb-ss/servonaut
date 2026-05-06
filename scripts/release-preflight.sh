#!/usr/bin/env bash
# Pre-flight check before tagging a Servonaut release.
#
# Builds the wheel + sdist into ./dist/, then asserts the artefacts
# contain none of the things that should never reach PyPI:
#
#   - Compiled bytecode and __pycache__ directories.
#   - Local development files (.env, .env.local, .DS_Store, .vscode/, .idea/).
#   - Editor backups and swap files.
#   - Active debug breakpoints (pdb.set_trace, breakpoint(), ipdb).
#   - Test fixtures (tests/, conftest.py) — only source code ships.
#
# Usage: ./scripts/release-preflight.sh
# Exit codes:
#   0 — clean, safe to tag.
#   1 — at least one forbidden artefact found, review the report above.
#   2 — `python -m build` itself failed.

set -uo pipefail

cd "$(dirname "$0")/.."

DIST_DIR="dist"
PASS=0
FAIL=1
BUILD_FAIL=2

print_section() { printf "\n=== %s ===\n" "$1"; }

# --- 1. Clean previous artefacts ------------------------------------------
print_section "Cleaning previous build artefacts"
rm -rf "${DIST_DIR}" build *.egg-info src/*.egg-info 2>/dev/null
echo "Cleaned."

# --- 2. Build -------------------------------------------------------------
print_section "Building wheel + sdist"
if ! python -m build >/tmp/servonaut-preflight-build.log 2>&1; then
    echo "FAIL: python -m build returned non-zero. Tail of log:"
    tail -40 /tmp/servonaut-preflight-build.log
    exit $BUILD_FAIL
fi
echo "Build succeeded."

# --- 3. Inventory artefacts -----------------------------------------------
print_section "Built artefacts in ${DIST_DIR}/"
ls -la "${DIST_DIR}/"

WHEEL=$(ls "${DIST_DIR}"/*.whl 2>/dev/null | head -1)
SDIST=$(ls "${DIST_DIR}"/*.tar.gz 2>/dev/null | head -1)

if [[ -z "${WHEEL}" || -z "${SDIST}" ]]; then
    echo "FAIL: missing wheel or sdist in ${DIST_DIR}/."
    exit $FAIL
fi

# --- 4. Forbidden-content scan --------------------------------------------
# Each pattern: "label|forbidden grep pattern". Non-zero hit => failure.
PATTERNS=(
    "compiled bytecode|\\.pyc$"
    "pycache|__pycache__"
    "env file|^.env$"
    "env file (local)|^.env\\.local$"
    "DS_Store|\\.DS_Store$"
    "vscode dir|^\\.vscode/"
    "idea dir|^\\.idea/"
    "editor swap|\\.swp$"
    "vim swap|\\.swo$"
    "pytest cache|\\.pytest_cache"
    "test fixtures|^tests/"
    "test fixtures (sdist)|/tests/"
    "conftest|conftest\\.py$"
)

# Source-code patterns that warrant a grep through the wheel's .py files.
SOURCE_BAD=(
    "pdb breakpoint|pdb\\.set_trace"
    "builtin breakpoint|breakpoint("
    "ipdb breakpoint|ipdb\\.set_trace"
)

print_section "Scanning wheel manifest"
WHEEL_LIST=$(unzip -l "${WHEEL}" | awk 'NR>3 && NF>3 {print $4}')
print_section "Scanning sdist manifest"
SDIST_LIST=$(tar -tzf "${SDIST}")

found_any=0

scan_paths() {
    local label="$1"
    local pat="$2"
    local hits
    hits=$(printf "%s\n%s\n" "${WHEEL_LIST}" "${SDIST_LIST}" |
           grep -E "${pat}" || true)
    if [[ -n "${hits}" ]]; then
        echo "[FAIL] ${label}:"
        echo "${hits}" | head -10 | sed 's/^/    /'
        return 1
    fi
    return 0
}

for entry in "${PATTERNS[@]}"; do
    label="${entry%%|*}"
    pat="${entry#*|}"
    if ! scan_paths "${label}" "${pat}"; then
        found_any=1
    fi
done

# --- 5. Source-code scan inside the wheel ---------------------------------
print_section "Scanning .py files inside the wheel"
TMP_EXTRACT=$(mktemp -d)
trap 'rm -rf "${TMP_EXTRACT}"' EXIT
unzip -q "${WHEEL}" -d "${TMP_EXTRACT}"

for entry in "${SOURCE_BAD[@]}"; do
    label="${entry%%|*}"
    pat="${entry#*|}"
    hits=$(grep -RE --include='*.py' "${pat}" "${TMP_EXTRACT}" 2>/dev/null || true)
    if [[ -n "${hits}" ]]; then
        echo "[FAIL] ${label}:"
        echo "${hits}" | head -10 | sed 's/^/    /'
        found_any=1
    fi
done

# --- 6. Verdict ----------------------------------------------------------
print_section "Verdict"
if [[ $found_any -ne 0 ]]; then
    echo "FAIL — fix the items above before tagging the release."
    exit $FAIL
fi

echo "PASS — wheel and sdist look clean."
echo "Wheel:  ${WHEEL}"
echo "Sdist:  ${SDIST}"
exit $PASS
