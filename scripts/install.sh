#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo 'Usage: sudo ./scripts/install.sh --instance ID --repo OWNER/REPO --network BRIDGE --image IMAGE' >&2
    exit 2
}
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 2; }
INSTANCE= REPOSITORY= NETWORK= IMAGE=
while (($#)); do
    case "$1" in
        --instance) (($# >= 2)) || usage; INSTANCE=$2; shift 2 ;;
        --repo) (($# >= 2)) || usage; REPOSITORY=$2; shift 2 ;;
        --network) (($# >= 2)) || usage; NETWORK=$2; shift 2 ;;
        --image) (($# >= 2)) || usage; IMAGE=$2; shift 2 ;;
        *) usage ;;
    esac
done
[[ "$INSTANCE" =~ ^[a-z][a-z0-9-]{0,19}$ ]] || usage
[[ "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || usage
[[ "$NETWORK" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]+$ && "$NETWORK" != bridge && "$NETWORK" != host && "$NETWORK" != none ]] || usage
[[ "$IMAGE" =~ ^[a-zA-Z0-9][a-zA-Z0-9_./:@-]+$ ]] || usage
[[ $(docker network inspect --format '{{.Driver}}' "$NETWORK") == bridge ]] || {
    echo 'Requires an existing dedicated Docker bridge network; see docs/NETWORK_SECURITY.md' >&2
    exit 2
}
docker image inspect "$IMAGE" >/dev/null

DEST=/etc/ephemeral-runner
CONF="$DEST/$INSTANCE.env"
AUTH="$DEST/$INSTANCE.curl.conf"
if [[ -e "$CONF" || -e "$AUTH" ]]; then
    echo "Instance $INSTANCE already exists; refusing overwrite ($CONF)" >&2
    exit 1
fi
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SUFFIX=$(python3 -c 'import secrets; print(secrets.token_hex(4))')
LABEL="er-${INSTANCE}-${SUFFIX}"
install -d -o root -g root -m 0700 "$DEST" \
    "/var/lib/ephemeral-runner/$INSTANCE" \
    /usr/local/libexec/ephemeral-runner
install -o root -g root -m 0755 "$ROOT/scripts/runner-once.sh" /usr/local/libexec/ephemeral-runner/runner-once.sh
install -o root -g root -m 0755 "$ROOT/scripts/runner-cleanup.py" /usr/local/libexec/ephemeral-runner/runner-cleanup.py
install -o root -g root -m 0755 "$ROOT/docker/entrypoint.sh" /usr/local/libexec/ephemeral-runner/entrypoint.sh
install -o root -g root -m 0644 "$ROOT/systemd/ephemeral-runner@.service" /etc/systemd/system/
install -o root -g root -m 0644 "$ROOT/systemd/ephemeral-runner-cleanup@.service" /etc/systemd/system/
install -o root -g root -m 0644 "$ROOT/systemd/ephemeral-runner-cleanup@.timer" /etc/systemd/system/

(umask 077; printf 'REPOSITORY=%s\nRUNNER_LABEL=%s\nRUNNER_PREFIX=%s\nDOCKER_NETWORK=%s\nRUNNER_IMAGE=%s\n' \
    "$REPOSITORY" "$LABEL" "$LABEL" "$NETWORK" "$IMAGE" > "$CONF")
install -o root -g root -m 0600 /dev/null "$AUTH"
systemctl daemon-reload
printf '\nInstalled instance %s for %s\n' "$INSTANCE" "$REPOSITORY"
printf 'Dedicated runner label: %s\n' "$LABEL"
printf 'Next: add fine-grained token to %s (root only).\n' "$AUTH"
printf 'Then: sudo systemctl enable --now ephemeral-runner@%s.service ephemeral-runner-cleanup@%s.timer\n' "$INSTANCE" "$INSTANCE"
