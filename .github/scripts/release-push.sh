#!/usr/bin/env bash
# git push authenticated with the release token in GH_TOKEN.
#
# The release jobs check out without persisting credentials, so the token is
# never written to .git/config for later steps to find. For this one push,
# git reads the authorization header from its environment, which also keeps
# the token out of the process list. Arguments are passed to git push as is.
set -euo pipefail
: "${GH_TOKEN:?GH_TOKEN must hold the release token}"
auth="$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 | tr -d '\n')"
echo "::add-mask::$auth"
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0="http.https://github.com/.extraheader"
export GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $auth"
exec git push "$@"
