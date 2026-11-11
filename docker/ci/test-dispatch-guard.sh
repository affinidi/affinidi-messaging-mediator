#!/usr/bin/env bash
# Self-test for resolve-version.sh and check-dispatch.sh, run by the
# publish-images `version` job and runnable locally:
#   bash docker/ci/test-dispatch-guard.sh
# Builds a throwaway git repository with release tags and a stub registry.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cd "$work"
work="$(pwd)"
git init -q
git config user.email ci@example.invalid
git config user.name ci
printf '[workspace.package]\nversion = "0.52.0"\n' > Cargo.toml
git add Cargo.toml
git commit -q -m init
git tag v0.51.0
git tag v0.52.0-rc.1

# Stub registry: `registry/<tag>` present = image tag exists.
mkdir registry
touch registry/v0.51.0
cat > inspect <<'STUB'
#!/usr/bin/env bash
tag="${1##*:}"
if [ "$tag" = "v0.52.0-dev.badbadbad" ]; then echo "unauthorized: authentication required" >&2; exit 1; fi
if [ -e "$(dirname "$0")/registry/$tag" ]; then echo "Name: $1"; exit 0; fi
echo "ERROR: $1: not found" >&2
exit 1
STUB
chmod +x inspect

fail=0
resolve() { # EVENT REF_TYPE REF_NAME INPUT -> version
  EVENT_NAME="$1" REF_TYPE="$2" REF_NAME="$3" INPUT_VERSION="$4" SHA=0123456789abcdef0123 \
    GITHUB_OUTPUT=/dev/stdout bash "$here/resolve-version.sh" 2>/dev/null | sed -n 's/^version=//p'
}
check() { # expect(ok|refuse) VERSION REF_TYPE REF_NAME OVERWRITE
  local expect="$1"
  if VERSION="$2" REF_TYPE="$3" REF_NAME="$4" OVERWRITE="$5" IMAGE=ghcr.io/o/m INSPECT=./inspect \
    bash "$here/check-dispatch.sh" 2>/dev/null; then got=ok; else got=refuse; fi
  if [ "$got" != "$expect" ]; then
    echo "FAIL: check $* -> $got" >&2
    fail=1
  fi
}
expect_version() { # expected EVENT REF_TYPE REF_NAME INPUT
  local want="$1"; shift
  local got
  got="$(resolve "$@")"
  if [ "$got" != "$want" ]; then
    echo "FAIL: resolve $* -> '$got', want '$want'" >&2
    fail=1
  fi
}

# Version resolution.
expect_version v0.51.0 push tag v0.51.0 ""
expect_version v0.51.0 workflow_dispatch tag v0.51.0 ""
expect_version v0.52.0-dev.0123456789ab workflow_dispatch branch main ""
expect_version v0.51.0 workflow_dispatch branch feature/x v0.51.0
expect_version v0.52.0 pull_request branch 1/merge ""

# Dispatch on a tag: only that tag's version; an existing image needs overwrite.
check refuse v0.51.0 tag v0.51.0 false
check ok v0.51.0 tag v0.51.0 true
check refuse v0.50.0 tag v0.51.0 true
check ok v0.52.0-rc.1 tag v0.52.0-rc.1 false
check refuse custom tag custom true

# Dispatch on a branch: main or release/* only, and only a dev version.
dev=v0.52.0-dev.0123456789ab
check ok "$dev" branch main false
check ok "$dev" branch release/0.52 false
check refuse "$dev" branch feature/x false
for v in v0.51.0 v0.53.0 v0.53.0-rc.1 v0.53.0-rc1 v0.53.0-beta.1 v0.53.0-RC.1 \
  vV0.53.0 0.53.0-dev.0123456789ab v0.53.0-dev.XYZ1234 v0.53.0-dev.12 custom-name; do
  check refuse "$v" branch main true
done
touch "registry/$dev"
check refuse "$dev" branch main false
check ok "$dev" branch main true

# A registry lookup that fails for another reason refuses.
check refuse v0.52.0-dev.badbadbad branch main true

# publish-manifest.sh re-checks right before it moves the tag.
mkdir bin digests
cat > bin/docker <<'STUB'
#!/usr/bin/env bash
case "$*" in
  "buildx imagetools create"*) echo created >> "$CALLS" ;;
  "buildx imagetools inspect"*) echo '"sha256:feed"' ;;
  *) exit 2 ;;
esac
STUB
chmod +x bin/docker
touch digests/aaaa
manifest() { # expect(ok|refuse) EVENT VERSION OVERWRITE
  local expect="$1" got
  : > calls
  if (cd digests && PATH="$work/bin:$PATH" CALLS="$work/calls" INSPECT="$work/inspect" \
    IMAGE=ghcr.io/o/m EVENT_NAME="$2" VERSION="$3" OVERWRITE="$4" GITHUB_OUTPUT=/dev/null \
    bash "$here/publish-manifest.sh" 2>/dev/null); then got=ok; else got=refuse; fi
  if [ "$got" != "$expect" ]; then
    echo "FAIL: manifest $* -> $got" >&2
    fail=1
  fi
  if [ "$got" = refuse ] && [ -s calls ]; then
    echo "FAIL: manifest $* moved the tag before refusing" >&2
    fail=1
  fi
}
manifest refuse workflow_dispatch "$dev" false
manifest ok workflow_dispatch "$dev" true
manifest ok workflow_dispatch v0.52.0-dev.abcdef0 false
manifest ok push v0.51.0 false
manifest refuse workflow_dispatch v0.52.0-dev.badbadbad false

if [ "$fail" -ne 0 ]; then
  echo "dispatch guard self-test FAILED" >&2
  exit 1
fi
echo "dispatch guard self-test passed" >&2
