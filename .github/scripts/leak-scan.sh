#!/usr/bin/env bash
# Leak Guard — fail a PR if its diff, title, or body contains internal /
# coordination markers that must not enter this PUBLIC repo. Plain grep, no
# external dependencies, no AI/Copilot. This is a backstop; the first line of
# defence is genericizing content while you write it (see CLAUDE.md).
#
# It checks two tiers:
#   1. Built-in, NON-sensitive structural markers (coordination phrases, peer
#      names, deploy-SHA shapes). These are safe to keep in this file.
#   2. An optional confidential denylist supplied via the LEAK_DENYLIST repo
#      secret (newline-separated customer names / real IPs). Those terms are
#      NEVER printed — CI logs on a public repo are themselves public.
set -uo pipefail

BASE_SHA="${BASE_SHA:-}"
HEAD_SHA="${HEAD_SHA:-}"
PR_TITLE="${PR_TITLE:-}"
PR_BODY="${PR_BODY:-}"
EXTRA_DENYLIST="${EXTRA_DENYLIST:-}"

# Built-in case-insensitive ERE markers. Kept generic on purpose so this file
# is itself safe to commit to the public repo.
PATTERNS=(
  'backend team'
  'backend owner'
  'dev agent'
  'agent[- ]?bus'
  'heads[- ]?up sent'
  'coordinated with'
  'decided with (the )?(backend|server|dev|infra|ops)'
  'pinged (the )?(backend|server|dev|infra|ops)'
  'per the thread'
  'cross[- ]team'
  'the (backend|server|dev|infra|ops) team'
  'prod-[0-9a-f]{7,}'
)

fail=0
report() { echo "::error::$1"; fail=1; }

# --- 1. Diff (added lines only), excluding the guard's own files ----------
DIFF=""
if [ -n "$BASE_SHA" ] && [ -n "$HEAD_SHA" ]; then
  DIFF="$(git diff --unified=0 "${BASE_SHA}...${HEAD_SHA}" -- . \
      ':(exclude).github/workflows/leak-guard.yml' \
      ':(exclude).github/scripts/leak-scan.sh' \
      2>/dev/null | grep -E '^\+' | grep -vE '^\+\+\+' || true)"
fi

# Title + body come from the event payload via env (never interpolated into a
# shell command), so a hostile PR body can't inject anything here.
HAYSTACK="$(printf 'TITLE: %s\nBODY: %s\n%s\n' "$PR_TITLE" "$PR_BODY" "$DIFF")"

for p in "${PATTERNS[@]}"; do
  hits="$(printf '%s\n' "$HAYSTACK" | grep -inE "$p" || true)"
  if [ -n "$hits" ]; then
    report "Internal-marker pattern '/$p/i' found — genericize it:"
    printf '%s\n' "$hits" | sed 's/^/    /'
  fi
done

# --- 2. Confidential denylist via repo secret (values never echoed) -------
if [ -n "$EXTRA_DENYLIST" ]; then
  while IFS= read -r term; do
    [ -z "$term" ] && continue
    if printf '%s\n' "$HAYSTACK" | grep -iqF -- "$term"; then
      report "A confidential denylist term matched (value hidden). Genericize it before merging."
    fi
  done <<< "$EXTRA_DENYLIST"
fi

if [ "$fail" -ne 0 ]; then
  echo "::error::Leak Guard failed — this is a PUBLIC repo. Genericize the flagged content (code AND prose) before merging. See the pre-publish leak check in CLAUDE.md."
  exit 1
fi
echo "Leak Guard: no internal markers detected. ✓"
