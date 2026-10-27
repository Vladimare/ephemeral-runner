#!/usr/bin/env bash
set -euo pipefail
umask 077

: "${RUNNER_URL:?required}"
: "${RUNNER_NAME:?required}"
: "${RUNNER_LABELS:?required}"

cd /home/runner/actions-runner
# Token travels through the container's stdin and is not persisted in Docker
# metadata (unlike -e RUNNER_TOKEN). Each container registers only once.
IFS= read -r RUNNER_TOKEN || { echo 'Registration token missing from stdin' >&2; exit 2; }
[[ -n "$RUNNER_TOKEN" ]] || exit 2
./config.sh --unattended --ephemeral --disableupdate \
    --url "$RUNNER_URL" \
    --token "$RUNNER_TOKEN" \
    --name "$RUNNER_NAME" \
    --labels "$RUNNER_LABELS" \
    --work _work
unset RUNNER_TOKEN
exec ./run.sh
