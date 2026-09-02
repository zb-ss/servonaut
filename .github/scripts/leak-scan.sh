#!/usr/bin/env bash
# Leak Guard — fail a PR whose diff, title, body, or commit messages contain internal /
# coordination markers or secret-shaped values that must not enter this PUBLIC
# repo. Plain grep, no external deps, no AI/Copilot. A deterministic BACKSTOP;
# the first line of defence is genericizing while writing (see CONTRIBUTING.md
# → "Avoiding accidental disclosure"). An optional LLM advisory reviewer
# (separate, non-blocking) covers the unbounded/semantic classes this can't
# (novel customer names, reworded phrasing).
#
# IMPORTANT: CI logs on a public repo are themselves public, so this script
# reports only METADATA (source + line numbers + pattern name) and NEVER the
# matched content — printing the match would re-leak the very value it caught.
#
# Detection tiers:
#   1. Structural markers  — generic coordination phrases / deploy-id shapes.
#   2. Secret/PII shapes   — emails, private keys, AKIA keys, ARN account-ids,
#                            real home paths, UUIDs (allowlist-filtered).
#   3. Confidential denylist — exact customer names / real IPs from the
#                            LEAK_DENYLIST repo secret (same-repo PRs only).
set -uo pipefail

BASE_SHA="${BASE_SHA:-}"
HEAD_SHA="${HEAD_SHA:-}"
PR_TITLE="${PR_TITLE:-}"
PR_BODY="${PR_BODY:-}"
EXTRA_DENYLIST="${EXTRA_DENYLIST:-}"
ALLOWLIST_FILE="${ALLOWLIST_FILE:-.github/leak-allowlist.txt}"

fail=0
# Emit metadata only — sources/patterns, never matched content.
flag() { echo "::error::LEAK GUARD — $1"; fail=1; }

# --- Tier 1: structural markers (name|ERE). Generic, safe to keep here. -----
PHRASE_PATTERNS=(
  "coordination-phrase|backend team"
  "coordination-phrase|backend owner"
  "coordination-phrase|dev agent"
  "coordination-phrase|agent[- ]?bus"
  "coordination-phrase|heads[- ]?up sent"
  "coordination-phrase|coordinated with"
  "coordination-phrase|decided with (the )?(backend|server|dev|infra|ops)"
  "coordination-phrase|pinged (the )?(backend|server|dev|infra|ops)"
  "coordination-phrase|per the thread"
  "coordination-phrase|cross[- ]team"
  "coordination-phrase|the (backend|server|dev|infra|ops) team"
  "deploy-identifier|prod-[0-9a-f]{7,}"
  # Assistant-session links and attribution trailers are tooling artifacts,
  # not part of a public change description.
  "assistant-session-link|claude\.ai/code/session"
  "assistant-session-trailer|^[A-Za-z]+-Session: *https?://"
)

# --- Tier 2: secret/PII shapes (name|PCRE). Matched value is never printed. -
# example.com/.org/.net, /home/user, /home/runner are excluded inline; the
# canonical AWS example key and other fixtures go in the allowlist file.
SHAPE_PATTERNS=(
  "email|[A-Za-z0-9._%+-]+@(?!example\.(?:com|org|net))[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
  "aws-access-key|AKIA[0-9A-Z]{16}"
  "private-key|-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"
  "aws-arn-account-id|arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:[0-9]{12}:"
  "home-path|/home/(?!user\b|runner\b)[a-z_][a-z0-9_-]*"
  "uuid|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)

# Allowlist: literal known-safe tokens (redaction fixtures, doc examples) — one
# per line, '#' comments allowed. Shape hits made up solely of these are dropped.
ALLOW=()
if [ -f "$ALLOWLIST_FILE" ]; then
  while IFS= read -r line; do
    line="${line%$'\r'}"
    line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
    [ -z "$line" ] && continue
    case "$line" in \#*) continue ;; esac
    ALLOW+=("$line")
  done < "$ALLOWLIST_FILE"
fi
is_allowlisted() {  # $1 = token
  local t
  for t in "${ALLOW[@]:-}"; do [ -n "$t" ] && [ "$1" = "$t" ] && return 0; done
  return 1
}

TMPDIR_SCAN="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_SCAN"' EXIT
printf '%s' "$PR_TITLE" > "$TMPDIR_SCAN/__pr_title"
printf '%s' "$PR_BODY"  > "$TMPDIR_SCAN/__pr_body"

# Per-file added-diff lines, excluding the guard's own files so a guard PR
# doesn't self-trip on the literal patterns above.
DIFF_OK=1
CHANGED=()
if [ -n "$BASE_SHA" ] && [ -n "$HEAD_SHA" ]; then
  if CHANGED_RAW="$(git diff --name-only "${BASE_SHA}...${HEAD_SHA}" -- . \
        ':(exclude).github/workflows/leak-guard.yml' \
        ':(exclude).github/scripts/leak-scan.sh' \
        ':(exclude).github/leak-allowlist.txt' 2>"$TMPDIR_SCAN/__differr")"; then
    while IFS= read -r f; do [ -n "$f" ] && CHANGED+=("$f"); done <<< "$CHANGED_RAW"
  else
    DIFF_OK=0
  fi
fi

# Fail CLOSED: if SHAs were provided but the diff could not be computed (e.g. a
# fork head we couldn't fetch), do NOT pass vacuously.
if [ -n "$BASE_SHA" ] && [ -n "$HEAD_SHA" ] && [ "$DIFF_OK" -ne 1 ]; then
  flag "could not compute the PR diff (failing closed): $(head -1 "$TMPDIR_SCAN/__differr" 2>/dev/null)"
fi

scan_blob() {  # $1 = source label, $2 = file of text to scan
  local label="$1" file="$2" name re hits tok kept entry scanf
  [ -s "$file" ] || return 0
  # Inline escape hatch: a line containing `leak-guard:allow` is exempt from
  # tiers 1 & 2 (for vetted fixtures). The confidential denylist (tier 3)
  # cannot be silenced this way.
  scanf="$file.flt"
  # grep -v exits 1 when it filters out EVERY line (the intended "all exempt"
  # case) and 2 on real error — only fall back to the unfiltered file on error,
  # otherwise an all-exempt blob would be wrongly restored and re-scanned.
  grep -vF 'leak-guard:allow' "$file" > "$scanf" 2>/dev/null
  [ "$?" -gt 1 ] && cp "$file" "$scanf"
  for entry in "${PHRASE_PATTERNS[@]}"; do
    name="${entry%%|*}"; re="${entry#*|}"
    hits="$(grep -inE "$re" "$scanf" 2>/dev/null | cut -d: -f1 | paste -sd, - || true)"
    [ -n "$hits" ] && flag "[$label] $name on line(s) $hits"
  done
  for entry in "${SHAPE_PATTERNS[@]}"; do
    name="${entry%%|*}"; re="${entry#*|}"
    kept=0
    while IFS= read -r tok; do
      [ -z "$tok" ] && continue
      is_allowlisted "$tok" || kept=$((kept+1))
    done < <(grep -oiP "$re" "$scanf" 2>/dev/null || true)
    [ "$kept" -gt 0 ] && flag "[$label] $name shape matched ($kept occurrence(s), value hidden)"
  done
}

scan_blob "pr-title" "$TMPDIR_SCAN/__pr_title"
scan_blob "pr-body"  "$TMPDIR_SCAN/__pr_body"
# Commit messages travel with the merge and are never re-editable, so they get
# the same tiers as the PR body.
: > "$TMPDIR_SCAN/__commits"
if [ -n "$BASE_SHA" ] && [ -n "$HEAD_SHA" ]; then
  git log --format=%B "${BASE_SHA}..${HEAD_SHA}" > "$TMPDIR_SCAN/__commits" 2>/dev/null || true
fi
scan_blob "commit-messages" "$TMPDIR_SCAN/__commits"
for f in "${CHANGED[@]:-}"; do
  [ -z "$f" ] && continue
  git diff "${BASE_SHA}...${HEAD_SHA}" -- "$f" 2>/dev/null \
    | grep -E '^\+' | grep -vE '^\+\+\+' | sed 's/^\+//' > "$TMPDIR_SCAN/__cur" || true
  scan_blob "$f" "$TMPDIR_SCAN/__cur"
done

# --- Tier 3: confidential denylist (values never echoed) -------------------
if [ -n "$EXTRA_DENYLIST" ]; then
  {
    cat "$TMPDIR_SCAN/__pr_title" "$TMPDIR_SCAN/__pr_body" "$TMPDIR_SCAN/__commits" 2>/dev/null
    if [ -n "$BASE_SHA" ] && [ -n "$HEAD_SHA" ]; then
      git diff "${BASE_SHA}...${HEAD_SHA}" 2>/dev/null | grep -E '^\+' | grep -vE '^\+\+\+'
    fi
  } > "$TMPDIR_SCAN/__all"
  while IFS= read -r term; do
    term="${term%$'\r'}"
    term="${term#"${term%%[![:space:]]*}"}"; term="${term%"${term##*[![:space:]]}"}"
    [ -z "$term" ] && continue
    case "$term" in \#*) continue ;; esac
    [ "${#term}" -lt 4 ] && continue   # reject ultra-short terms (broad matches)
    if grep -iqF -- "$term" "$TMPDIR_SCAN/__all"; then
      flag "[denylist] a confidential term matched (value hidden). Genericize it."
    fi
  done <<< "$EXTRA_DENYLIST"
fi

if [ "$fail" -ne 0 ]; then
  echo "::error::Leak Guard failed — this is a PUBLIC repo. Genericize the flagged content (code AND prose) before merging. See CONTRIBUTING.md → 'Avoiding accidental disclosure'. To exempt a vetted fixture line, add 'leak-guard:allow' in a comment on it."
  exit 1
fi
echo "Leak Guard: no internal markers or secret shapes detected. ✓"
