#!/usr/bin/env bash
#
# Fail if a workspace member is ALSO resolved from crates.io.
#
# WHY THIS EXISTS
#
# A workspace member that another crate depends on *by version* (rather than by
# path) is only redirected to local source if it is listed in the root
# `[patch.crates-io]`. Miss the entry and cargo silently resolves the published
# copy **alongside** the local one. Two things then go wrong, both quietly:
#
#   1. Local changes to that crate do not take effect in workspace builds. You
#      edit source, rebuild, and nothing happens.
#   2. Two copies of the same types exist, so a value produced by one cannot be
#      passed to the other:
#
#        error[E0308]: expected `affinidi_did_common::Document`,
#                      found a different `affinidi_did_common::Document`
#
#      or, more confusingly, an unsatisfied trait bound naming a type that
#      obviously does implement the trait — because the trait came from the
#      other copy.
#
# External consumers make this worse: a crates.io crate that depends on our
# crates (e.g. `vta-sdk`) drags the registry copies in even when every internal
# reference uses a path.
#
# This has bitten repeatedly, and the symptom never points at the cause:
#   * `did-example`                (PR #629)
#   * `affinidi-messaging-core`    (PR #630) — spent a long time written off as
#                                   an unrelated, unfixable `vta-sdk` failure
#   * `affinidi-vc`, `affinidi-sd-jwt`, `affinidi-oid4vc-core`,
#     `affinidi-openid4vci`, `affinidi-openid4vp`,
#     `affinidi-messaging-delivery` (all found by this script's first run)
#
# WHAT IT CHECKS
#
# The *symptom*, not the cause: any package whose name is a workspace member and
# which also appears in the resolved graph with a registry source. That catches
# both a missing `[patch.crates-io]` entry and a patch entry whose version no
# longer satisfies an external consumer's requirement — the two ways a redirect
# falls through — with no false positives from members nothing depends on.
#
# It ALSO checks the ecosystem crates this workspace shares types with — any
# registry crate named `affinidi-*`, `trust-tasks-*`, `vta-*` or `didwebvh-rs` —
# and fails when one resolves at more than one version. Two copies of the
# messaging SDK or the Trust Task stack mean two sets of types (a value from
# `vta-sdk`'s copy will not pass where the direct dependency's is expected),
# twice the compile time and memory, and a bigger binary.
#
# ALLOWLISTS
#
# `scripts/workspace-duplicates-allow.txt` lists workspace members known to be
# shadowed and not fixable from this repository, one crate name per line.
#
# `scripts/version-duplicates-allow.txt` lists ecosystem crates known to resolve
# at two versions, as `<crate> <review-by YYYY-MM-DD> <reason>`. An entry past
# its review-by date fails the guard, so a duplicate cannot be forgotten: clear
# it, or re-date it with a fresh reason.
#
# Keep both short and keep the reason in the file; an entry is a debt marker,
# not a resolution.

set -euo pipefail

ALLOW_FILE="$(dirname "$0")/workspace-duplicates-allow.txt"
VERSION_ALLOW_FILE="$(dirname "$0")/version-duplicates-allow.txt"
# Overridable so the expiry logic can be tested; defaults to today (UTC).
TODAY="${DUPLICATE_GUARD_TODAY:-$(date -u +%Y-%m-%d)}"

echo "=== Workspace duplicate guard ==="
echo

allowed=""
if [[ -f "$ALLOW_FILE" ]]; then
    allowed="$(grep -vE '^\s*(#|$)' "$ALLOW_FILE" || true)"
fi

# cargo metadata resolves the full graph; a workspace member has a null source,
# so a non-null source for a member's name means a second, registry-sourced copy.
# NOTE: `python3 -c` (not `python3 -`), so stdin stays free for the pipe.
read -r -d '' EXTRACT <<'PY' || true
import json, sys

meta = json.load(sys.stdin)
members = {p["name"] for p in meta["packages"] if p["id"] in meta["workspace_members"]}
for pkg in sorted(meta["packages"], key=lambda p: (p["name"], p["version"])):
    if pkg["name"] in members and pkg.get("source"):
        print(pkg["name"], pkg["version"], sep="\t")
PY

# --all-features: a duplicate reached only through an optional dependency is
# still a duplicate. Without it the guard resolved default features only and
# missed one: during the data-integrity 0.8 wave (#917), affinidi-tdk's
# optional `did-scid` pulled a registry did-scid 0.2.8 beside the workspace's
# 0.3.0, under every --all-features build, and the guard reported clean.
metadata="$(cargo metadata --format-version 1 --all-features)"
duplicates="$(python3 -c "$EXTRACT" <<<"$metadata")"

status=0
unexpected=""

while IFS=$'\t' read -r name version; do
    [[ -z "$name" ]] && continue
    if grep -qxF "$name" <<<"$allowed" 2>/dev/null; then
        echo "  allow  $name $version (known, see $(basename "$ALLOW_FILE"))"
    else
        echo "  DUP    $name $version is resolved from crates.io as well as locally"
        unexpected="${unexpected}${name}"$'\n'
        status=1
    fi
done <<<"$duplicates"

if [[ -z "$duplicates" ]]; then
    echo "  ok     no workspace member is shadowed by a crates.io copy"
fi

echo
if [[ $status -ne 0 ]]; then
    cat <<EOF
Some workspace members are ALSO being pulled from crates.io.

Local edits to these crates will not take effect in workspace builds, and having
two copies of their types in the graph produces mismatched-type or unsatisfied-
trait errors that point anywhere but here.

Fix: add each to '[patch.crates-io]' in the root Cargo.toml, e.g.

  <crate-name> = { path = "crates/<crate-name>" }

Then confirm with:

  cargo tree --workspace --all-features -i "registry+https://github.com/rust-lang/crates.io-index#<crate>@<version>"

If a duplicate genuinely cannot be resolved from this repository — an external
consumer pinning an incompatible version range, say — add it to
$ALLOW_FILE with a note explaining why and what would clear it.
EOF
else
    echo "All workspace members resolve to local source."
fi

# ── Ecosystem crates resolved at more than one version ─────────────────────
echo
echo "=== Ecosystem version-duplicate guard ==="
echo

read -r -d '' MULTI <<'PY' || true
import collections, json, re, sys

meta = json.load(sys.stdin)
prefix = re.compile(r"^(affinidi-|trust-tasks-|vta-)|^didwebvh-rs$")
versions = collections.defaultdict(set)
for pkg in meta["packages"]:
    if pkg.get("source") and prefix.search(pkg["name"]):
        versions[pkg["name"]].add(pkg["version"])
for name in sorted(versions):
    if len(versions[name]) > 1:
        print(name, " ".join(sorted(versions[name])), sep="\t")
PY

multi="$(python3 -c "$MULTI" <<<"$metadata")"
version_status=0

while IFS=$'\t' read -r name versions; do
    [[ -z "$name" ]] && continue
    entry=""
    if [[ -f "$VERSION_ALLOW_FILE" ]]; then
        entry="$(grep -E "^${name}[[:space:]]" "$VERSION_ALLOW_FILE" | head -1 || true)"
    fi
    if [[ -z "$entry" ]]; then
        echo "  DUP    $name resolves at $versions"
        version_status=1
        continue
    fi
    review_by="$(awk '{print $2}' <<<"$entry")"
    if [[ ! "$review_by" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        echo "  BAD    $name: allowlist entry has no review-by date (YYYY-MM-DD): $entry"
        version_status=1
    elif [[ "$review_by" < "$TODAY" ]]; then
        echo "  EXPIRED $name resolves at $versions; its allowlist entry was due for review on $review_by"
        version_status=1
    else
        echo "  allow  $name at $versions (until $review_by, see $(basename "$VERSION_ALLOW_FILE"))"
    fi
done <<<"$multi"

if [[ -z "$multi" ]]; then
    echo "  ok     every affinidi-* / trust-tasks-* / vta-* / didwebvh-rs crate resolves once"
fi

# Entries that no longer match anything are noise; say so (without failing).
if [[ -f "$VERSION_ALLOW_FILE" ]]; then
    while read -r name _; do
        [[ -z "$name" || "$name" == \#* ]] && continue
        if ! grep -qE "^${name}"$'\t' <<<"$multi"; then
            echo "  stale  $name is allow-listed but resolves once now: delete its entry"
        fi
    done <"$VERSION_ALLOW_FILE"
fi

if [[ $version_status -ne 0 ]]; then
    cat <<EOF

An ecosystem crate resolves at more than one version, so the build compiles
and links two copies of it, and its types from one copy do not match the
other's. Find what pulls each copy with

  cargo tree --workspace --all-features -i <crate>@<version>

then align the requirements (usually: wait for, or ask for, an upstream
release on the newer version, and bump ours). If it cannot be fixed from this
repository yet, add it to $VERSION_ALLOW_FILE as
'<crate> <review-by YYYY-MM-DD> <what pulls it and what clears it>'.
EOF
    status=1
fi

exit $status
