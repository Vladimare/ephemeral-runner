# Ephemeral self-hosted GitHub Actions runners

Repository-configurable, disposable GitHub Actions runners in Linux Docker containers. Each instance targets one `OWNER/REPO`, runs at most one GitHub Actions job, then disposes its container; systemd automatically starts a fresh runner. A repository-scoped host-side cleanup removes stale registrations after shutdown or power loss.

**Status:** Reusable implementation with transactional installation, private-file validation and per-instance resource policies. Python regression tests and per-file shell syntax checks are included. The generic image, installer, systemd integration and network policy require validation on your own host before production use.

## Requirements

- Linux `x86_64`, systemd, Docker Engine, bash, Python 3, curl; root for installing/running the service.
- A **dedicated Docker bridge network** whose outbound and host/LAN access you have restricted. `docker network create er-ci` creates a bridge but **does not secure it**. See [network security](docs/NETWORK_SECURITY.md).
- A fine-grained GitHub PAT limited to the target repository with repository **Administration (read/write)**; obtain it in GitHub Settings. This token is needed to create registration tokens and delete orphaned runners.
- A pinned Docker image containing the GitHub Actions runner at `/home/runner/actions-runner`, owned by UID `10001`. The provided Dockerfile is a minimal Linux x64 example; project-specific toolchains should be added in a derived image. GitHub may require runner image updates to continue accepting jobs.

## Install for a repository

```bash
# On the runner host after cloning this repo:
sudo docker build -f docker/Dockerfile -t ephemeral-runner:2.338.0 .
# Create and SECURE a dedicated Docker bridge, per docs/NETWORK_SECURITY.md.
sudo docker network create er-ci # only if not already present; NOT isolated yet

sudo ./scripts/install.sh runtime-install --version v1
sudo ./scripts/install.sh instance-install --version v1 \
  --instance loom \
  --repo Vladimare/loom \
  --network er-ci \
  --image ephemeral-runner:2.338.0
```

Runtime installation is a separate operation: it publishes an immutable, checksummed
release in `/usr/local/libexec/ephemeral-runner/releases/v1`. Repeating it with the
same bytes is harmless; reusing a version with different bytes is rejected. Choose
an explicit new version for new code. Installing another instance never replaces
shared scripts or template units used by an existing instance.

Instance installation generates a **unique label** such as `er-loom-abcdef12` in
`/etc/ephemeral-runner/instances/loom/config.env` and an empty `auth.curl.conf`
(both mode 0600). Each instance pins its release through its `current` profile;
concrete systemd units retain the documented `ephemeral-runner@loom.service` and
`ephemeral-runner-cleanup@loom.timer` names. A root-only `resources.json` records
bounded per-instance defaults (2 GiB RAM, one CPU, no swap, 4 GiB writable layer and rotated logs).
Services remain stopped. Use another instance identifier and repository to provision another independent runner.
Existing instances, credentials, state and legacy flat configuration are never
overwritten. Legacy installations require a separately planned manual migration.

Fill the dedicated root-only curl config file:

```bash
sudoedit /etc/ephemeral-runner/instances/loom/auth.curl.conf
```

Example file content (**replace the placeholder and never commit a real PAT**):

```text
header = "Authorization: Bearer YOUR_FINE_GRAINED_PAT"
```

Validate restrictive permissions:

```bash
sudo chmod 0600 /etc/ephemeral-runner/instances/loom/auth.curl.conf
sudo chmod 0600 /etc/ephemeral-runner/instances/loom/config.env
sudo /usr/local/libexec/ephemeral-runner/releases/v1/scripts/runner-cleanup.py --instance loom --audit
# Verify quota/cgroup enforcement before enabling (creates a disposable probe):
sudo /usr/local/libexec/ephemeral-runner/releases/v1/scripts/runner-resources.py --instance loom
sudo systemctl enable --now ephemeral-runner@loom.service ephemeral-runner-cleanup@loom.timer
```

Find the actual label in `/etc/ephemeral-runner/instances/loom/config.env` and route repository workflows to it:

```yaml
runs-on: [self-hosted, Linux, X64, er-loom-abcdef12]
```

Run a *trusted* CI job to verify registration, execution and one-shot replacement. The label is illustrative, not a fixed value.

## Resource policy

Read [resource limits and supported hosts](docs/RESOURCE_LIMITS.md) before enabling
any instance. New releases require Linux cgroup v2 and overlay2 on XFS with project
quotas; unsupported hosts fail before requesting a GitHub token. CPU, memory,
swap, rotated logs, writable-layer and temporary-storage budgets apply to the
Docker job container. Edit only the intended instance's private JSON policy while
stopped; older instances require an explicit policy and versioned upgrade.
No deployment or migration of the existing Loom runner is automatic.

## Operations

```bash
systemctl status ephemeral-runner@loom.service
sudo journalctl -u ephemeral-runner@loom.service -f
sudo /usr/local/libexec/ephemeral-runner/releases/v1/scripts/runner-cleanup.py --instance loom --audit
sudo /usr/local/libexec/ephemeral-runner/releases/v1/scripts/runner-cleanup.py --instance loom --sweep --dry-run
sudo /usr/local/libexec/ephemeral-runner/releases/v1/scripts/runner-cleanup.py --instance loom --sweep

# ONLY when the runner is Idle in GitHub:
sudo systemctl stop ephemeral-runner@loom.service
sudo systemctl start ephemeral-runner@loom.service
```

Expected idle state: `systemctl is-active` returns `active`, one `Idle` registration on GitHub. On job completion: runner unregisters itself, container is removed, systemd restarts after 15 seconds. On intentional stop: `docker stop` sends SIGTERM to the runner; the host cleanup verifies API deletion and clears state. Docker may report 143 (128 + SIGTERM), whitelisted in `SuccessExitStatus=143`; code 137 remains a failure.

The cleanup timer sweeps orphan registrations after crashes and reboots, and tolerates GitHub responses that omit the `ephemeral` field. It fails closed on unknown Docker errors and preserves the current-name file if GitHub deletion cannot be confirmed.

**Do not simultaneously run the old `loom-ephemeral-test.service` and a newly installed `ephemeral-runner@loom.service`** unless you explicitly intend two independent runner instances. This repository does not migrate the running LOOM host configuration automatically.

## Upgrade / revoke

Install new source as a **new immutable version**; then explicitly select it for
one stopped instance. Rollback selects the previous retained version using the
same command. Configuration, PAT, image selection, labels and state remain intact:

```bash
sudo ./scripts/install.sh runtime-install --version v2
# Only after verifying GitHub reports Idle; stopping a busy runner cancels its job:
sudo systemctl stop ephemeral-runner-cleanup@loom.timer ephemeral-runner@loom.service ephemeral-runner-cleanup@loom.service
sudo ./scripts/install.sh upgrade --instance loom --version v2
# Roll back while still stopped, if needed:
sudo ./scripts/install.sh upgrade --instance loom --version v1
# Explicit operator action, after verification:
sudo systemctl start ephemeral-runner@loom.service ephemeral-runner-cleanup@loom.timer
```

The installer refuses active/transitioning services or timers and fails closed on
unknown systemd states. Coordinate maintenance with other administrators: do not
start units concurrently with installation, recovery or upgrade. Installer locks
serialize runtime publication and same-instance transactions; they do not lock out
external `systemctl` commands. No command implicitly starts/restarts a runner.
Use the cleanup binary from the instance's selected release for manual operations.
Retain old releases for rollback; automatic garbage collection is not provided.
Image upgrades remain a separate explicit configuration/validation operation.

Instance transactions retain a root-only journal until `daemon-reload` succeeds.
Caught failures roll back automatically. If rollback/reload fails or a process is
killed, stop all three units, then run:

```bash
sudo ./scripts/install.sh recover --instance loom
```

Recovery restores the previous profile for an upgrade. A partial new installation
is moved to `/etc/ephemeral-runner/instances/.recovered-loom-*`, preserving any
credentials/configuration for operator inspection; its managed unit links are
removed. Retry installation only after successful recovery. Orphan `.stage-*`
runtime/profile/instance directories and `.journal-*` files are unpublished and can be
removed during coordinated, stopped maintenance; never delete retained releases
or recovered credentials blindly. Recovery is idempotent and never deletes runner
state. Power-loss guarantees depend on local filesystem rename/fsync semantics;
validate on the intended Linux filesystem before production deployment.

When retiring an instance, stop it when Idle, audit/sweep registrations, disable
its service/timer and revoke its PAT. This tooling does not modify or migrate the
deployed LOOM runner.

## Security

This is a constrained container runner, **not a hardened VM**. Untrusted PRs can still attack the shared host kernel; restrict permissions and triggers. For strict isolation use a disposable VM or dedicated runner machine. Read [network security and threat model](docs/NETWORK_SECURITY.md) before enabling any runner. Do not mount Docker's socket or repository secrets into the job container.

Config and PAT files must be regular files owned by root with **exactly 0600**
permissions. Both launcher and cleanup reject symbolic links (including parent
components), non-root owners and group/world writable parent directories. The
shared validator traverses using directory descriptors and no-follow opens before
config parsing or Docker/GitHub access. Validation does not make later Bash,
Python and curl pathname reads atomic: trusted root administrators must not
replace files or change directory permissions concurrently with runner use.
Other root processes remain trusted; ACLs and mount changes require host policy.

## Development

```bash
python3 -m unittest discover -s tests -v
for file in scripts/*.sh docker/entrypoint.sh; do
  bash -n "$file" || exit 1
done
```

Installer tests use real temporary files and process locks, with mocked Docker and
systemd commands and dummy credentials. They cover failure boundaries, version
isolation, concurrency, upgrade and recovery; they do not establish production
readiness. Linux Docker/systemd validation must still check unit loading/enabling,
idle stop/restart, timer activation, interrupted transactions and power loss. The
existing cleanup safety tests remain required. Resource-policy and private-file
regressions and per-file shell checks are included. Live Linux resource, systemd
lifecycle and network validation remain deployment gates.

MIT licensed. See [LICENSE](LICENSE).
