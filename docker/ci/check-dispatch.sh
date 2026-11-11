#!/usr/bin/env bash
# Decide whether a manual (workflow_dispatch) run of publish-images may publish
# VERSION. Run by the `version` job before anything is built.
#
#   * A dispatch on a release tag (`refs/tags/vX.Y.Z[-rc.N]`) publishes only
#     that tag's version.
#   * A dispatch on a branch may not publish a release-shaped version
#     (`vX.Y.Z` / `vX.Y.Z-rc.N`) or the name of any existing git tag: those
#     are published from their tag. Its default is `v<workspace>-dev.<sha>`.
#   * A version already present in the registry is replaced only when
#     OVERWRITE is `true`.
#
# Inputs (environment):
#   VERSION    - resolved image version (from resolve-version.sh)
#   REF_TYPE   - github.ref_type (`tag` or `branch`)
#   REF_NAME   - github.ref_name
#   OVERWRITE  - the dispatch's `overwrite` input (`true` / `false`)
#   IMAGE      - registry repository, e.g. ghcr.io/<owner>/messaging-mediator.
#                Empty skips the registry lookup (local runs).
#   INSPECT    - command used to look the tag up (default:
#                `docker buildx imagetools inspect`); tests replace it.
# Diagnostics go to stderr; a refusal exits 1.
set -euo pipefail

: "${VERSION:?VERSION must be set}"
: "${REF_TYPE:?REF_TYPE must be set}"
: "${REF_NAME:?REF_NAME must be set}"
: "${OVERWRITE:=false}"
: "${IMAGE:=}"
: "${INSPECT:=docker buildx imagetools inspect}"

refuse() {
  echo "::error::$*" >&2
  exit 1
}

release_re='^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$'

if [ "$REF_TYPE" = "tag" ]; then
  [ "$VERSION" = "$REF_NAME" ] ||
    refuse "a dispatch on tag $REF_NAME publishes only :$REF_NAME, not :$VERSION"
else
  if [[ "$VERSION" =~ $release_re ]]; then
    refuse "$VERSION is a release version; release images are published from their tag (dispatch on refs/tags/$VERSION), not from branch $REF_NAME"
  fi
  if git rev-parse -q --verify "refs/tags/$VERSION" > /dev/null; then
    refuse "$VERSION is an existing git tag; publish it by dispatching on that tag"
  fi
fi

if [ -n "$IMAGE" ]; then
  # Read the registry's answer rather than the exit code alone: a lookup that
  # fails for any reason other than "not found" must not read as "absent".
  if out=$($INSPECT "${IMAGE}:${VERSION}" 2>&1); then
    if [ "$OVERWRITE" != "true" ]; then
      refuse "${IMAGE}:${VERSION} already exists; re-run with overwrite=true to replace it"
    fi
    echo "Replacing existing ${IMAGE}:${VERSION} (overwrite=true)" >&2
  elif grep -qi 'not found\|manifest unknown' <<< "$out"; then
    :
  else
    echo "$out" >&2
    refuse "could not check whether ${IMAGE}:${VERSION} exists"
  fi
fi

echo "Dispatch may publish ${VERSION} from ${REF_TYPE} ${REF_NAME}" >&2
