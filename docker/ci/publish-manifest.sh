#!/usr/bin/env bash
# Create + push the multi-arch GHCR manifest list from the per-arch digests.
#
# Expects the per-arch digest files in the current directory (one empty file
# named after each `sha256:<digest>` sans prefix; produced by the build jobs).
#
# Inputs (environment):
#   IMAGE     - target repo, e.g. ghcr.io/<owner>/messaging-mediator
#   VERSION   - version tag to publish, e.g. v0.16.44
#   IS_LATEST - "true" to also tag :latest (highest release only; see version job)
#   EVENT_NAME - github.event_name. For a `workflow_dispatch`, an existing
#               ${IMAGE}:${VERSION} is replaced only when OVERWRITE is `true`
#               (checked again here, right before the tag moves, since another
#               run may have published it after check-dispatch.sh looked).
#   OVERWRITE - the dispatch's `overwrite` input
# Output: appends `digest=` to $GITHUB_OUTPUT (or stdout when unset).
set -euo pipefail

: "${IMAGE:?IMAGE must be set}"
: "${VERSION:?VERSION must be set}"
: "${IS_LATEST:=false}"
: "${EVENT_NAME:=}"
: "${OVERWRITE:=false}"

# shellcheck source=docker/ci/registry-lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/registry-lib.sh"

if [ "$EVENT_NAME" = "workflow_dispatch" ] && [ "$OVERWRITE" != "true" ]; then
  if ! state=$(registry_tag_state "${IMAGE}:${VERSION}"); then
    echo "::error::could not check whether ${IMAGE}:${VERSION} exists" >&2
    exit 1
  fi
  if [ "$state" = present ]; then
    echo "::error::${IMAGE}:${VERSION} already exists; re-run with overwrite=true to replace it" >&2
    exit 1
  fi
fi

tags=(--tag "${IMAGE}:${VERSION}")
if [ "$IS_LATEST" = "true" ]; then
  tags+=(--tag "${IMAGE}:latest")
fi

# One source ref per digest file. An unmatched glob would otherwise expand to a
# literal `*` and hand imagetools a bogus `<image>@sha256:*` ref, so refuse to
# publish an empty (or partial) digest set rather than fail obscurely downstream.
shopt -s nullglob
sources=()
for digest in *; do
  sources+=("${IMAGE}@sha256:${digest}")
done
if [ "${#sources[@]}" -eq 0 ]; then
  echo "::error::no digest files found in $PWD — the build jobs produced nothing to publish" >&2
  exit 1
fi

docker buildx imagetools create "${tags[@]}" "${sources[@]}"

digest=$(docker buildx imagetools inspect "${IMAGE}:${VERSION}" --format '{{json .Manifest.Digest}}' | tr -d '"')

out="${GITHUB_OUTPUT:-/dev/stdout}"
echo "digest=${digest}" >> "$out"
echo "Published ${IMAGE}:${VERSION} (latest=${IS_LATEST}) (${digest})" >&2
