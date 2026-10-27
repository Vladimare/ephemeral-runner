# Ephemeral self-hosted GitHub Actions runners

Repository-configurable, disposable GitHub Actions runners in Linux Docker containers. Each instance targets one `OWNER/REPO`, runs at most one GitHub Actions job, then disposes its container; systemd automatically starts a fresh runner. A repository-scoped host-side cleanup removes stale registrations after shutdown or power loss.

**Status:** Initial reusable implementation extracted from an operational LOOM setup. Python unit tests and shell syntax checks are included. The generic image, installer, systemd integration and network policy require validation on your own host before production use.

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

sudo ./scripts/install.sh \
  --instance loom \
  --repo Vladimare/loom \
  --network er-ci \
  --image ephemeral-runner:2.338.0
```

The installer prints a **unique label** such as `er-loom-abcdef12` and creates `/etc/ephemeral-runner/loom.env` (mode 0600). It refuses to overwrite existing instances. `--instance` is a local, unique identifier; use `gsd` or `myproject` for additional repositories. Run the installer again for each repository, with its corresponding `--repo` value. A single host may run multiple instances, each with isolated configuration, state and registration namespace.

Fill the dedicated root-only curl config file:

```bash
sudoedit /etc/ephemeral-runner/loom.curl.conf
```

Example file content (**replace the placeholder and never commit a real PAT**):

```text
header = "Authorization: Bearer YOUR_FINE_GRAINED_PAT"
```

Validate restrictive permissions:

```bash
sudo chmod 0600 /etc/ephemeral-runner/loom.curl.conf
sudo chmod 0600 /etc/ephemeral-runner/loom.env
sudo /usr/local/libexec/ephemeral-runner/runner-cleanup.py --instance loom --audit
sudo systemctl enable --now ephemeral-runner@loom.service ephemeral-runner-cleanup@loom.timer
```

Find the actual label in `/etc/ephemeral-runner/loom.env` and route repository workflows to it:

```yaml
runs-on: [self-hosted, Linux, X64, er-loom-abcdef12]
```

Run a *trusted* CI job to verify registration, execution and one-shot replacement. The label is illustrative, not a fixed value.

## Operations

```bash
systemctl status ephemeral-runner@loom.service
sudo journalctl -u ephemeral-runner@loom.service -f
sudo /usr/local/libexec/ephemeral-runner/runner-cleanup.py --instance loom --audit
sudo /usr/local/libexec/ephemeral-runner/runner-cleanup.py --instance loom --sweep --dry-run
sudo /usr/local/libexec/ephemeral-runner/runner-cleanup.py --instance loom --sweep

# ONLY when the runner is Idle in GitHub:
sudo systemctl stop ephemeral-runner@loom.service
sudo systemctl start ephemeral-runner@loom.service
```

Expected idle state: `systemctl is-active` returns `active`, one `Idle` registration on GitHub. On job completion: runner unregisters itself, container is removed, systemd restarts after 15 seconds. On intentional stop: `docker stop` sends SIGTERM to the runner; the host cleanup verifies API deletion and clears state. Docker may report 143 (128 + SIGTERM), whitelisted in `SuccessExitStatus=143`; code 137 remains a failure.

The cleanup timer sweeps orphan registrations after crashes and reboots, and tolerates GitHub responses that omit the `ephemeral` field. It fails closed on unknown Docker errors and preserves the current-name file if GitHub deletion cannot be confirmed.

**Do not simultaneously run the old `loom-ephemeral-test.service` and a newly installed `ephemeral-runner@loom.service`** unless you explicitly intend two independent runner instances. This repository does not migrate the running LOOM host configuration automatically.

## Upgrade / revoke

Stop the service when Idle; update the image and scripts by rerunning the installer **only for a fresh instance** (the installer intentionally does not overwrite existing configuration). For manual upgrades, replace `/usr/local/libexec/ephemeral-runner` scripts and systemd units and run `systemctl daemon-reload`. Rebuild images for security patches and newer runner releases, verifying release checksums; do not use `latest` implicitly. When permanently retiring an instance, stop it, check `--audit`/`--sweep`, disable the service and timer, and revoke its GitHub PAT.

## Security

This is a constrained container runner, **not a hardened VM**. Untrusted PRs can still attack the shared host kernel; restrict permissions and triggers. For strict isolation use a disposable VM or dedicated runner machine. Read [network security and threat model](docs/NETWORK_SECURITY.md) before enabling any runner. Do not mount Docker's socket or repository secrets into the job container.

## Development

```bash
python3 -m unittest discover -s tests -v
bash -n scripts/*.sh docker/entrypoint.sh
```

MIT licensed. See [LICENSE](LICENSE).
