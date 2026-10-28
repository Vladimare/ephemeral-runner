#!/usr/bin/env bash
set -euo pipefail
umask 077

INSTANCE=${1:?Usage: runner-once.sh INSTANCE}
[[ "$INSTANCE" =~ ^[a-z][a-z0-9-]{0,19}$ ]] || { echo 'Invalid instance' >&2; exit 2; }
BASE="/etc/ephemeral-runner/instances/$INSTANCE"
CONF="$BASE/config.env"
AUTH="$BASE/auth.curl.conf"
STATE_DIR="/var/lib/ephemeral-runner/$INSTANCE"
RUNTIME=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ENTRYPOINT="$RUNTIME/docker/entrypoint.sh"

[[ -f "$CONF" && -f "$AUTH" ]] || { echo 'Missing instance configuration or auth file' >&2; exit 2; }
[[ $(stat -c %u "$CONF") == 0 && $(stat -c %u "$AUTH") == 0 ]] || { echo 'Config must be owned by root' >&2; exit 2; }
[[ $(stat -c %a "$CONF") == 600 && $(stat -c %a "$AUTH") == 600 ]] || { echo 'Config and auth file must have mode 0600' >&2; exit 2; }
# The installer writes only validated root-controlled simple KEY=VALUE lines.
# These config files must never be writable by an unprivileged user.
# shellcheck source=/dev/null
source "$CONF"

[[ "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || exit 2
[[ "$RUNNER_PREFIX" =~ ^er-[a-z0-9-]{3,32}$ ]] || exit 2
[[ "$RUNNER_LABEL" =~ ^[a-z][a-z0-9-]{1,62}$ ]] || exit 2
[[ "$DOCKER_NETWORK" != bridge && "$DOCKER_NETWORK" != host && "$DOCKER_NETWORK" != none ]] || exit 2
[[ -n "$RUNNER_IMAGE" && "$RUNNER_IMAGE" != -* ]] || exit 2

# Validate all required Docker configuration before requesting a GitHub token.
[[ $(docker network inspect --format '{{.Driver}}' "$DOCKER_NETWORK") == bridge ]] || {
    echo 'Expected an existing dedicated Docker bridge network' >&2; exit 2;
}
docker image inspect "$RUNNER_IMAGE" >/dev/null

TOKEN=$(
    curl -fsS --connect-timeout 5 --max-time 20 \
      --config "$AUTH" -X POST \
      -H 'Accept: application/vnd.github+json' \
      "https://api.github.com/repos/$REPOSITORY/actions/runners/registration-token" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])'
)

NAME="${RUNNER_PREFIX}-$(date +%s)-$$"
install -d -o root -g root -m 0700 "$STATE_DIR"
printf '%s\n' "$NAME" > "$STATE_DIR/current-name"

# Backstop if docker run exits unexpectedly. Host cleanup is responsible
# for API deregistration and state removal; this trap never removes state.
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Registration token never appears in docker inspect, arguments, or container
# environment. Only a root-owned script is bind-mounted, read-only.
printf '%s\n' "$TOKEN" | docker run --rm -i \
    --init \
    --name "$NAME" \
    --network "$DOCKER_NETWORK" \
    --user 10001:10001 \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit 512 \
    -e RUNNER_URL="https://github.com/$REPOSITORY" \
    -e RUNNER_NAME="$NAME" \
    -e RUNNER_LABELS="$RUNNER_LABEL" \
    -e RUNNER_MANUALLY_TRAP_SIG=1 \
    --mount "type=bind,src=$ENTRYPOINT,dst=/tmp/runner-entrypoint.sh,readonly" \
    --entrypoint /bin/bash \
    "$RUNNER_IMAGE" /tmp/runner-entrypoint.sh
