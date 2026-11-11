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
touch registry/v0.51.0 registry/v0.52.0-dev.existing
cat > inspect <<'STUB'
#!/usr/bin/env bash
tag="${1##*:}"
if [ "$tag" = "broken" ]; then echo "unauthorized: authentication required" >&2; exit 1; fi
if [ -e "registry/$tag" ]; then echo "Name: $1"; exit 0; fi
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

# Dispatch on a branch: never a release version or an existing git tag.
check refuse v0.51.0 branch feature/x true
check refuse v0.53.0 branch main true
check refuse v0.53.0-rc.1 branch main false
git tag custom-name
check refuse custom-name branch main true
check ok v0.52.0-dev.0123456789ab branch main false
check refuse v0.52.0-dev.existing branch main false
check ok v0.52.0-dev.existing branch main true

# A registry lookup that fails for another reason refuses.
check refuse broken branch main true

if [ "$fail" -ne 0 ]; then
  echo "dispatch guard self-test FAILED" >&2
  exit 1
fi
echo "dispatch guard self-test passed" >&2
