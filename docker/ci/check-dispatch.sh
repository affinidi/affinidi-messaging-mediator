#!/usr/bin/env bash
# Decide whether a manual (workflow_dispatch) run of publish-images may publish
# VERSION. Run by the `version` job before anything is built.
#
#   * A dispatch on a release tag (`vX.Y.Z` / `vX.Y.Z-rc.N`) publishes only
#     that tag's version.
#   * A dispatch on a branch must be on `main` or `release/*`, and publishes
#     only a dev version, `vX.Y.Z-dev.<hex sha>` (its default). Release
#     versions are published from their tag.
#   * A version already present in the registry is replaced only when
#     OVERWRITE is `true` (publish-manifest.sh checks again just before it
#     moves the tag).
#
# Inputs (environment):
#   VERSION    - resolved image version (from resolve-version.sh)
#   REF_TYPE   - github.ref_type (`tag` or `branch`)
#   REF_NAME   - github.ref_name
#   OVERWRITE  - the dispatch's `overwrite` input (`true` / `false`)
#   IMAGE      - registry repository, e.g. ghcr.io/<owner>/messaging-mediator.
#                Empty skips the registry lookup (local runs).
#   INSPECT    - registry lookup command (see registry-lib.sh); tests replace it.
# Diagnostics go to stderr; a refusal exits 1.
set -euo pipefail

: "${VERSION:?VERSION must be set}"
: "${REF_TYPE:?REF_TYPE must be set}"
: "${REF_NAME:?REF_NAME must be set}"
: "${OVERWRITE:=false}"
: "${IMAGE:=}"

# shellcheck source=docker/ci/registry-lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/registry-lib.sh"

refuse() {
  echo "::error::$*" >&2
  exit 1
}

release_re='^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$'
dev_re='^v[0-9]+\.[0-9]+\.[0-9]+-dev\.[0-9a-f]{7,40}$'

if [ "$REF_TYPE" = "tag" ]; then
  [[ "$REF_NAME" =~ $release_re ]] ||
    refuse "tag $REF_NAME is not a release tag (vX.Y.Z or vX.Y.Z-rc.N); nothing to publish"
  [ "$VERSION" = "$REF_NAME" ] ||
    refuse "a dispatch on tag $REF_NAME publishes only :$REF_NAME, not :$VERSION"
else
  case "$REF_NAME" in
    main | release/*) ;;
    *) refuse "images are published only from main, release/* or a release tag, not from branch $REF_NAME" ;;
  esac
  [[ "$VERSION" =~ $dev_re ]] ||
    refuse "invalid version $VERSION for a branch dispatch: a branch publishes only vX.Y.Z-dev.<hex sha> (the default); release versions are published from their tag"
fi

if [ -n "$IMAGE" ]; then
  state=$(registry_tag_state "${IMAGE}:${VERSION}") ||
    refuse "could not check whether ${IMAGE}:${VERSION} exists"
  if [ "$state" = present ]; then
    [ "$OVERWRITE" = "true" ] ||
      refuse "${IMAGE}:${VERSION} already exists; re-run with overwrite=true to replace it"
    echo "Replacing existing ${IMAGE}:${VERSION} (overwrite=true)" >&2
  fi
fi

echo "Dispatch may publish ${VERSION} from ${REF_TYPE} ${REF_NAME}" >&2
