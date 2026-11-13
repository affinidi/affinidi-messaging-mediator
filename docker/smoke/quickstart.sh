#!/usr/bin/env bash
# Smoke test for docker/quickstart/docker-compose.yml.
#
# Brings the quickstart stack up from nothing, and checks that:
#   1. the setup service generates an identity and exits cleanly;
#   2. the mediator turns `healthy` through the image's own HEALTHCHECK
#      (`mediator healthcheck`), and answers livez on 127.0.0.1;
#   3. a restart reuses the generated identity instead of minting a new one.
# Tears the stack (and its volumes) down at the end unless KEEP_UP=1.
#
# Usage: docker/smoke/quickstart.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

COMPOSE="docker compose -f docker/quickstart/docker-compose.yml"
LIVEZ="http://127.0.0.1:7037/mediator/v1/livez"

cleanup() {
  if [ "${KEEP_UP:-0}" != "1" ]; then
    echo "==> tearing down (with volumes)"
    $COMPOSE down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_healthy() {
  local cid status
  cid="$($COMPOSE ps -q mediator)"
  for i in $(seq 1 60); do
    status="$(docker inspect --format '{{.State.Health.Status}}' "$cid" 2>/dev/null || echo missing)"
    if [ "$status" = "healthy" ]; then
      echo "    mediator healthy after ${i} check(s)"
      return 0
    fi
    sleep 5
  done
  echo "ERROR: mediator never turned healthy (last status: $status)" >&2
  $COMPOSE logs setup mediator | tail -60 >&2 || true
  return 1
}

echo "==> first start: build, generate an identity, start"
$COMPOSE down -v >/dev/null 2>&1 || true
$COMPOSE up -d --build
$COMPOSE logs setup | grep -q "generating a new mediator identity" || {
  echo "ERROR: setup did not generate an identity" >&2
  $COMPOSE logs setup >&2
  exit 1
}
wait_healthy
curl -fsS "$LIVEZ" >/dev/null
first_did="$($COMPOSE exec -T mediator sh -c 'grep "^mediator_did" conf/mediator.toml')"
echo "    $first_did" | cut -c1-80

echo "==> restart: the identity in the volume is reused"
$COMPOSE down
$COMPOSE up -d
$COMPOSE logs setup | grep -q "reusing that identity" || {
  echo "ERROR: setup did not reuse the existing identity" >&2
  $COMPOSE logs setup >&2
  exit 1
}
wait_healthy
second_did="$($COMPOSE exec -T mediator sh -c 'grep "^mediator_did" conf/mediator.toml')"
if [ "$first_did" != "$second_did" ]; then
  echo "ERROR: the mediator DID changed across a restart" >&2
  exit 1
fi
echo "OK: quickstart generates once, turns healthy, and keeps its identity."
