# shellcheck shell=bash
# Shared by check-dispatch.sh and publish-manifest.sh (sourced, not run).
#
# registry_tag_state REF -> prints `present` or `absent`; returns 1 (after
# printing the lookup's output to stderr) when the registry gives any other
# answer, so a failed lookup never reads as "absent".
# INSPECT (default `docker buildx imagetools inspect`) can be replaced by tests.
registry_tag_state() {
  local ref="$1" out
  if out=$(${INSPECT:-docker buildx imagetools inspect} "$ref" 2>&1); then
    echo present
  elif grep -qi 'not found\|manifest unknown' <<< "$out"; then
    echo absent
  else
    echo "$out" >&2
    return 1
  fi
}
