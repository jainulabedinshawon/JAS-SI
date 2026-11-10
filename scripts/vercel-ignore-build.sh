#!/bin/sh
set -eu

branch="${VERCEL_GIT_COMMIT_REF:-}"
pull_request_id="${VERCEL_GIT_PULL_REQUEST_ID:-}"

# Keep Production builds and real pull-request previews.
# Skip branch-only deployments that have no associated open pull request.
if [ "$branch" = "main" ] || [ -n "$pull_request_id" ]; then
    printf '%s\n' "JAS-SI: build allowed (main or GitHub pull request)."
    exit 1
fi

printf '%s\n' "JAS-SI: build skipped (branch has no GitHub pull request)."
exit 0
