#!/usr/bin/env bash
# Refuse to promote a candidate that PyPI does not serve, has yanked, or that
# cannot be checked. Usage: candidate-on-pypi.sh vX.Y.ZrcN [vX.Y.Z]
#
# Pass the stable tag as the second argument when it was already pushed
# without its release, so a refusal names the way out.
set -euo pipefail
candidate="$1"
tag="${2:-}"
url="https://pypi.org/pypi/servonaut/${candidate#v}/json"
if ! meta="$(curl -sf --retry 3 "$url")"; then
  echo "::error::$candidate is not on PyPI, or PyPI could not be read, so it cannot be promoted. Check its publish run, or try again later."
  exit 1
fi
yanked="$(jq -r '.info.yanked' <<< "$meta" 2> /dev/null)" || yanked=""
if [ "$yanked" != "true" ] && [ "$yanked" != "false" ]; then
  echo "::error::PyPI's answer for $candidate could not be read (no yanked status), so it cannot be promoted. Try again later."
  exit 1
fi
if [ "$yanked" = "true" ]; then
  if [ -n "$tag" ]; then
    echo "::error::$candidate is yanked on PyPI, but $tag was already tagged from it and has no release. Either create the $tag release by hand to ship it anyway, or delete the never-released tag by hand (git push origin :refs/tags/$tag) and cut a new candidate."
  else
    echo "::error::$candidate is yanked on PyPI, so it will not be promoted. Cut and test a new candidate."
  fi
  exit 1
fi
echo "PyPI serves $candidate, and it is not yanked."
