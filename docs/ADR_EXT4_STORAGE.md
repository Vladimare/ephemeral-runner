# ADR: ext4 storage compatibility — NO-GO for a production backend

Status: **Proposed NO-GO for enabling an ext4 backend in this change** (issue #13).
This is not a finding that bounded ext4 runners are impossible. The current image
and evidence do not satisfy the required write compatibility, lifecycle and live
validation gates. Keep the existing XFS backend and ext4 rejection unchanged.
No host was inspected or reconfigured by this work. The issue reports overlay2,
cgroup v2 and an ext4 Docker data filesystem; that report is input, not a new
independent observation. No disposable Linux Docker environment was provided or exercised
in the local macOS session. The permitted NO-GO deliverable is chosen explicitly;
the component-proof script below is unexecuted live, not production support.

## Alternatives

| Design | Enforcement and workflow fit | Memory / image impact | Host privilege and recovery | Decision |
| --- | --- | --- | --- | --- |
| Read-only root + bounded tmpfs mounts | Kernel read-only root and byte/inode-bounded writable mounts can contain small jobs; cannot simply reuse current image with only `/tmp` writable | Workspace, cache and any copied runner distribution compete with compiler RSS inside the memory cap; needs a purpose-built image/layout | No host loop/mount manager; Docker owns tmpfs lifetime. Retained containers and daemon/reboot recovery still need tests | Most promising small-job candidate; not enabled without image/write-path and live proof |
| Read-only root + per-job fixed-size filesystem image | Disk-backed workspace could fit large builds; ordinary ext4 bind mount or free-space monitor provides no quota | Preallocated filesystem image needs host capacity reservation; runner metadata/cache paths must also be bounded | Adds root loop setup, formatting, mount/unmount, inode/device identity checks, journaling, locking, orphan recovery and safe resource ownership | Reject for this scoped implementation: no validated lifecycle manager; do not prototype it on an existing host |
| Separate disposable VM with its own XFS quota Docker store | Existing implemented quota path; disk capacity can be provisioned independently | Fits disk-heavy Rust/C++ workloads without making workspace consume RAM | Separate host provisioning is explicit; never migrate/restart the shared daemon | Recommended alternative for disk-heavy work after separate authorization and live proof |

A separate Docker daemon is only an alternative if its privileged control plane,
data disk, sockets and lifecycle are deliberately isolated and independently
managed. Do not change an existing daemon's data-root/storage driver, start a
second daemon or attach loop devices as an implicit installer action.

[Docker tmpfs documentation](https://docs.docker.com/engine/storage/tmpfs/) explains
that tmpfs uses the memory cgroup and hides files at its mount destination. Docker
requires XFS project quotas for overlay2's per-container size option; see
[storage options](https://docs.docker.com/reference/cli/docker/container/run/#set-storage-driver-options-per-container---storage-opt).
Neither an advisory `df` check nor an ext4 bind mount substitutes for enforcement.

## Concrete write-path audit of the current image

The image installs runner v2.338.0 directly under
`/home/runner/actions-runner`, sets that workdir, and runs as UID/GID 10001. The
entrypoint executes `./config.sh` and then `./run.sh` there, with `_work` relative
to the runner directory. A read-only image plus `/tmp` alone cannot satisfy this:

| Paths | Reason writes are required / candidate treatment |
| --- | --- |
| Runner root `.env`, `.path` | `env.sh` writes them; require writable runner root or a proven image adaptation |
| Runner root `.runner`, `.credentials*` and other configured state | Registration/configuration persists state near the runner root; single-file mounts must survive replacement semantics and version changes, not merely exist |
| `_diag`, `_work`, action checkout, `_temp`, tool downloads | Diagnostics/job directories need bounded writable capacity |
| `$HOME` caches, language caches, `/tmp`, `/dev/shm` | Tool-specific caches and temporary files need explicit placement and limits; arbitrary write attempts elsewhere must fail |
| Runner binaries/scripts under the same root | Mounting an empty tmpfs over this directory hides the installed distribution; copying the distribution consumes bounded RAM and changes startup/image design |

This table is a minimum audit, not an exhaustive write contract for arbitrary
images, actions or future runner versions. Source anchors for v2.338.0:
[environment writes](https://github.com/actions/runner/blob/v2.338.0/src/Misc/layoutroot/env.sh),
[configuration persistence](https://github.com/actions/runner/blob/v2.338.0/src/Runner.Common/ConfigurationStore.cs),
and [directory/config resolution](https://github.com/actions/runner/blob/v2.338.0/src/Runner.Common/HostContext.cs).
The local image and entrypoint are [Dockerfile](../docker/Dockerfile) and
[entrypoint.sh](../docker/entrypoint.sh). No registration or network request was
executed to obtain this evidence.

## Candidate contract and threat model (not accepted runtime semantics)

Consider an explicitly versioned `readonly-tmpfs-v1` backend only in a future
reviewed release. That identifier remains **unsupported and rejected** today.
The existing `overlay2-xfs-quota` policy identifier and defaults remain unchanged.
No automatic migration, fallback or silent change to another instance is allowed.
Future schema must make workspace bytes, inodes, image layout/version and memory
headroom explicit; do not reinterpret `storage_mib` as free RAM or reuse its disk
range for tmpfs without a versioned contract.

A hostile non-root job may fill every writable byte/inode, try other directories,
forge cleanup names and trigger OOM/crashes. Kernel, Docker/root administrators,
image provenance and immutable runtime files remain trusted. Kernel escape,
network isolation, aggregate capacity and busy-job draining are separate gates.

A credible tmpfs candidate needs a trusted image with immutable source assets in
an independent location and a tested bootstrap into bounded writable runtime
space, or a complete supported configuration relocation. Keep `/` read-only; map
all mutable runner state, work and caches to explicitly sized mounts with inode
limits. Reject image VOLUME declarations, extra writable binds/volumes/devices,
privileged flags and paths that evade the approved mount map. Keep CPU, memory,
no-swap, PID and rotating-log controls; never expose a host PAT, socket, loop
node or privileged mount helper. Read-only entrypoint remains outside tmpfs.

For capacity planning, require:

`job RSS + touched tmpfs workspace/cache/state + copied runner assets + overhead < memory limit`

A tmpfs size is a maximum, not extra memory. A multi-GiB Rust/Skia/C++ workspace
may OOM a 2 GiB runner well before disk-like capacity is available. Raising RAM
limits across instances can exhaust the host; independent admission/headroom
planning remains necessary. Large builds should use a separately provisioned,
disk-backed runner rather than a nominally large tmpfs on a shared host.

A loopback candidate would require fixed, preallocated per-job storage, private
mount namespaces, transaction IDs, exclusive root-owned directories, device and
mount identity verification, per-instance locks and an exact teardown journal.
SIGKILL/reboot can leave loop attachments/mounts/files; never remove resources by
name/prefix alone. Fault tests must cover allocation, format, attach, mount,
container start, deregistration, unmount, detach and unlink, including busy mounts,
daemon outages, concurrency, symlinks and insufficient host capacity. None of
that infrastructure is implemented or claimed here.

## Evidence provided and gates to reconsider NO-GO

Unit tests retain the complete existing suite and additionally show that an ext4
Docker report rejects before token acquisition/container creation, that proposed
unreviewed backend identifiers stay rejected, and that the opt-in experiment
rejects VOLUME/bind bypasses and cleans its own container after injected failures.
These are mocked/temporary-fixture observations, not Linux enforcement proof.

The opt-in component experiment is:

```bash
sudo python3 scripts/check-readonly-tmpfs.py --disposable-host --image LOCAL_TRUSTED_RUNNER_IMAGE
```

Use only a disposable local Linux Docker host and the provided trusted image
layout, with cgroup v2, available controllers, Python 3 and at least 512 MiB free
RAM. It never pulls images, mounts host paths/devices, contacts GitHub or runs a
job. One container has 256 MiB RAM, 0.25 CPU, 64 PIDs, no swap, read-only root,
8 MiB workspace/tmp/shared-memory caps, inode caps and rotating logs. It tries
at most 12 MiB writes and 1100 empty files. It records configured settings
separately from actual cgroups, mount information and ENOSPC observations. It
also checks that the current runner registration directory is unwritable,
illustrating compatibility failure rather than claiming a working runner.

The script uses random container names and removes only its successfully created
container; it allocates no host filesystem images, mounts or loop devices. A
killed experiment or daemon outage can leave a small bounded container: record
its `er-ro-proof-*` identity and remove it explicitly on the disposable host after
inspection. This experiment is not the missing production cleanup/reboot proof.

Reconsider only after all of the following have evidence:

1. Run the component proof on disposable Linux; record kernel/Docker/image IDs,
   host backing filesystem, inspect/cgroup/mount/log settings and failures. Also
   run the existing bounded resource proof on a separately compatible XFS host.
2. Build and pin the candidate image; offline smoke must prove binaries stay
   visible and every required configuration/diagnostic/work/cache path is usable
   and bounded. Negative writes outside approved paths must fail. Test capacity
   exhaustion, competing instances and unsupported images before any token use.
3. Independently review the versioned policy, mount map, failure atomicity and
   owned-resource cleanup. Exercise every setup/teardown failure, launcher kill,
   Docker outage, reboot and races. No host resource may be leaked or misidentified.
4. Obtain **separate explicit authorization** for a disposable repository/token
   and follow [trusted workflow smoke plan](TRUSTED_WORKFLOW_SMOKE.md). A local
   filesystem proof or green unit suite cannot satisfy real registration/one-job
   lifecycle acceptance. Never substitute an existing deployment or credential.

No live Linux proof, filesystem reconfiguration, real registration, deployment,
release or merge was performed. The result is a scoped NO-GO/alternative with
reproducible next gates, not completion of an ext4 runtime backend.
