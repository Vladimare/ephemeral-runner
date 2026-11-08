# Disposable ext4 workspace experiment (issue #15)

Status: **Linux serial container execution failed; NO-GO for production**. This extends the
research in [issue #13](https://github.com/Vladimare/ephemeral-runner/issues/13).
It does not change the ADR's production decision, installer, runner image,
systemd lifecycle or `overlay2-xfs-quota` policy. It never registers a runner.

## Design and trust boundary

The root-only host script `scripts/ext4-workspace-poc.py` allocates a 64 MiB
regular file using `posix_fallocate`, checks allocated blocks, formats ext4 with
1024 requested inodes (observed count must be at most 2048), and attaches a loop
device with an explicit 64 MiB size limit. The resulting filesystem is mounted
`nosuid,nodev` under a fresh root-owned private directory. Only that filesystem
is exposed to UID 10001 at `/work`; the backing file, journal, socket and loop
device are never exposed. No in-container mount helper or privilege is provided.
`noexec` is intentionally absent on `/work`: runner scripts and job binaries
eventually need execution there. This is not a sandbox against a kernel escape.

Formatting explicitly disables discard (`nodiscard`) to preserve preallocation;
pre-format and post-format/pre-attach facts record size, allocated bytes,
UID/mode/link count and device/inode. Verification records each failed predicate
and aborts without reallocating or weakening the allocation threshold.

The filesystem's block/inode geometry enforces capacity; free-space checks are
admission only. The workload attempts at most 66 MiB and 2050 files, requires
ENOSPC separately for bytes and inodes, and checks backing size/allocation after
the probe. Loop identity includes backing device/inode/path, offset, size limit
and block-device rdev. Mount identity includes mount ID, root, device and flags.
Root administrators and the local Docker daemon are trusted. They can resize or
replace resources; this design does not defend against a malicious host root.
Guest writes cannot enlarge a host file it cannot access: the loop address space
is fixed and the guest lacks any device/control-plane access. Post-run stat is
an observation, not protection against a hostile root changing that address space.

The script uses the fixed local `/var/run/docker.sock`, ignoring caller Docker
contexts/config and remote endpoints. Rootful local Docker and cgroup v2 resource
controllers are required. The private parent must already exist on ext4; every
ancestor must be root-owned, non-symlink and not writable by group/others. The
untrusted UID can change files *inside* the mounted filesystem but cannot reach
the root-only host directory or mutate resource paths. No untrusted directory
tree is traversed during host cleanup, and no recursive deletion is used.

Mounts are scoped by the private directory and exact owned block-device identity
in the disposable host namespace. They are intentionally visible to the local
Docker daemon so it can bind the mount. A private unshared mount namespace would
hide the source filesystem from that daemon. This is one reason the script must
never run on an existing or shared deployment host.

Admission is serialized with a root-owned lock through allocation/setup and
cleanup. Independent probes can overlap after setup; each has its own random
128-bit ID and exclusive instance lock. Recovery cannot race an active probe.
Reserve at least 512 MiB free disk plus the 64 MiB allocation and 4096 free host
inodes, and at least 512 MiB available RAM. These are deliberately small test
thresholds, not a production capacity scheduler. Retained allocations consume
disk across failures/reboots; operators must account for them and eventually
destroy the disposable VM. Metadata, ext4 journal and copied assets reduce usable
capacity. Disk page cache, tmpfs, kernel metadata and compiler RSS still consume
cgroup/host memory; the 256 MiB container cap does not reserve host memory.

Unlike tmpfs-only storage, workspace bytes reside on disk and need not remain
resident RAM. `/tmp` and `/dev/shm` remain separate 8 MiB tmpfs mounts; `/tmp` has
1024 inodes. Docker's standard `/dev` tmpfs is root-owned; UID 10001 cannot create
files there. Kernel pseudo-filesystems are recorded in mountinfo. Docker-managed
`/etc/hosts`, `/etc/hostname` and `/etc/resolv.conf` are explicitly allowed only
when UID 10001 has no write access; any other writable ordinary filesystem mount
fails the probe. The script rejects image VOLUME declarations and extra binds/volumes or
devices, checks Docker inspect before start, and verifies actual cgroups and
mountinfo in the container. RAM/no-swap, CPU, PID and rotating log limits remain
mandatory. Network is disabled; no image pulls or GitHub API requests occur.

Known Docker mask handling uses static exact file paths (`/proc/interrupts`,
`/proc/kcore`, `/proc/keys`, `/proc/latency_stats`, `/proc/timer_list`,
`/proc/timer_stats`, `/proc/sched_debug`) and separate directory paths
(`/proc/asound`, `/proc/acpi`, `/proc/scsi`, `/sys/firmware`,
`/sys/devices/virtual/powercap`). Writable tmpfs file masks require
an actual character device with rdev 1:3, or an actual non-directory unwritable
to the job UID. Directory masks require an actual directory unwritable to that
UID. Unknown writable mounts remain rejected; Docker's `MaskedPaths` does not
supply authorization. Actual stat, write access and exact mountinfo are emitted
before policy validation; observed hosted mask identity still needs a new run.
The payload embeds the same policy, identity helper and constants tested locally.

## Offline runner layout

`docker/Dockerfile.ext4-poc` derives from an already loaded trusted runner image
and moves its distribution to root-owned `/opt/actions-runner`. The source
Dockerfile pins runner v2.338.0 and its archive checksum; the experiment requires
an immutable local image ID, never a tag. Building the base image is an explicit
separate preparation step; the experiment does not install anything.

The smoke checks genuine `config.sh`, `run.sh` and `bin/Runner.Listener` access,
copies the two scripts into `/work/runner`, and exercises `.env`, `.path`,
credential-free `.runner`, `_diag`, `_work` and HOME cache paths on bounded disk.
It does **not** execute the scripts/listener, copy the entire distribution or
prove a runnable registration layout. A full per-job distribution copy would
require a larger bounded image and verified capacity accounting; a linked-bin
layout requires upstream runner behavior validation. Neither is enabled here.
The 64 MiB component proof must not be presented as a working GitHub runner.

## Manual invocation — ONLY a fresh disposable Linux VM

Never run these commands against any deployed Docker host or runner. Use a
VM with no credentials, repositories or workloads, local rootful Docker, ext4
scratch storage, util-linux, e2fsprogs, Python 3 and a trusted locally loaded
runner image. Do not change the daemon driver/data-root or restart Docker.

```bash
# On that disposable VM only. Substitute an already loaded base image ID.
docker build --pull=false --network=none \
  --build-arg BASE=sha256:BASE_IMAGE_ID \
  -f docker/Dockerfile.ext4-poc -t er-ext4-poc .
docker image inspect er-ext4-poc --format '{{.Id}}'
sudo install -d -m 0700 -o root -g root /var/lib/ephemeral-ext4-poc
sudo python3 scripts/ext4-workspace-poc.py --disposable-host \
  --image sha256:POC_IMAGE_ID > report.json
```

The script prints the exact recovery journal path to stderr before setup. Keep
stderr and the root-only journal even when stdout is empty after a hard kill.
The JSON report separates configured bounds, observed evidence and test status.
It contains raw inspect/mount/statfs/cgroup data; sanitize host names, paths and
image metadata before sharing. No credential should be present in this VM/image.

## Failure and recovery semantics

Every mutating boundary records intent with fsync before executing it. Journal
updates use atomic rename and directory fsync. A crash between operation success
and its completion record is intentionally ambiguous. Cleanup performs no
lazy/forced unmount and never detaches/unlinks resources by prefix/name alone.

| Failure | Expected response; mocked coverage is not live evidence |
| --- | --- |
| Allocation/format fails | Owned partial backing can be unlinked after no-loop/no-mount checks; unknown identity is retained |
| Attach/mount success with lost completion record | Retain all evidence; require manual reconciliation |
| Docker create succeeds then client times out | Resolve exact nonce/name/image and full container ID before removal |
| Docker absent/unavailable or conflicting identity | Retain filesystem/loop/backing; never infer absence from an inspect error |
| Start/wait/probe failure | Remove verified container before unmount/detach/unlink |
| Busy unmount or daemon outage | Stop cleanup at failure, retain subsequent resources |
| SIGTERM | Best-effort same cleanup; record failure rather than success |
| SIGKILL/reboot | No trap can run; instance lock releases, durable intent remains; conservative recovery |
| Interrupted unmount/detach/unlink/container removal | Retain ambiguous state even if the resource appears absent; manual identity reconciliation |
| Repeated completed recovery | Idempotent; no unrelated resource is selected |

```bash
sudo python3 scripts/ext4-workspace-poc.py --disposable-host \
  --recover /var/lib/ephemeral-ext4-poc/probe-EXACT_32_HEX_ID
```

Recovery validates directory identity and refuses uncertain ownership. After a
reboot, stale mount IDs/device reuse do not authorize removal. An interrupted
operation can require manual read-only inspection of `losetup --json --list`,
`/proc/self/mountinfo`, backing stat and Docker inspect against the journal.
If certainty cannot be established, preserve the artifacts and destroy the
**whole disposable VM**; do not clear pending state or guess a teardown command.
The journal, lock and empty mount directory are deliberately retained as evidence.

## Verification report and remaining gates

Local macOS verification exercises Python fixtures and mocked OS/Docker replies.
It does not mount a filesystem, attach a loop, fill disk, kill a real launcher,
reboot a VM, run Docker or register a runner. Tests cover setup/teardown fault
boundaries, capacity admission, unsafe paths, identity changes, image volumes,
mount bypasses, create-timeout reconciliation and repeated recovery. Mocked
concurrency tests exercise locks/independent identities, not simultaneous Linux
mount or daemon behavior. See the [machine-readable report](examples/ext4-poc-report.json).

Maintainer artifact analysis reports that allocation now passes, Docker creation
succeeds and the serial container fails after start/wait; the exact payload cause
was diagnosed in run 42511506424 as a rejected Docker mask at
`/proc/interrupts`; the later run 42512621158 passed that mask and rejected
`/proc/latency_stats`. See the linked report for attributed run observations. The diagnostic
fix preserves `evidence.post_wait`: exact wait reply, ownership-verified post-run
State, and separate redacted stdout/stderr (16 KiB each, tail 100, three capture
attempts of at most five seconds each). Empty logs are explicit diagnostic failure;
CLI errors remain unknown evidence and never override the original wait reply.
Evidence is saved before identity-checked cleanup. `docker_inspect` remains the
pre-start snapshot. JSON phase markers go to payload stderr; final stdout remains
the JSON result. No new privileged run was triggered by this fix.
Still **NOT RUN**: real byte/inode
ENOSPC, verified fixed loop limit,
Docker read-only/limit/layout smoke, SIGTERM/SIGKILL at each boundary, daemon outage,
busy mount, reboot recovery and two overlapping real probes. Run each in fresh
disposable VM snapshots, preserving before/after mount/loop/container evidence.
For kills/outages, verify cleanup either completes with exact ownership or
retains evidence; require repeated recovery to leave unrelated sentinel resources
unchanged. Normal CI executes only unit tests, never this experiment.

No production backend can be accepted from mocked green tests. If live
preconditions or enforcement fail, record the failing command and observed state
as FAIL/NO-GO; do not replace bounds with monitoring. The separate XFS-backed VM
remains the alternative described in the ADR. Full runner copying/registration,
recurring systemd lifecycle, aggregate capacity scheduling and real one-job E2E
need separate work/authorization. Independent architecture/security review is
required before merge; do not auto-merge, release or deploy this prototype.

## Opt-in GitHub-hosted validation (issue #17)

The dormant [live workflow guide](EXT4_LIVE_VALIDATION.md) describes exact label,
source/head, permission, VM and artifact gates. It runs only after independent
workflow review and a maintainer manually adding `ext4-live-proof` to PR #16.
No opt-in label was applied while implementing this tooling. The checked-out
label-event head is frozen, and normal pushes do not execute privileged tests.
The repository summary records the reported live **FAIL** and remaining
**NOT RUN** gates; no successful enforcement or cleanup is claimed.
The guide includes a separate QEMU fallback if hosted ext4/loop prerequisites
produce SKIP/NO-GO. Do not change a shared Docker host to make the proof pass.
