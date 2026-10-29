# Per-instance resource budgets

New installations contain root-owned, mode **0600**
`/etc/ephemeral-runner/instances/INSTANCE/resources.json`. It is strict JSON:
unknown/missing/duplicate keys, booleans, floats and strings for numeric fields
are rejected. There are no unlimited values or implicit runtime defaults. Example
(the bounded defaults emitted by the installer):

```json
{
  "memory_mib": 2048,
  "cpu_millis": 1000,
  "swap_mib": 0,
  "storage_mib": 4096,
  "tmp_mib": 128,
  "shm_mib": 64,
  "log_mib": 10,
  "log_files": 3,
  "log_driver": "json-file",
  "storage_backend": "overlay2-xfs-quota"
}
```

| Field | Accepted integer range / units | Enforcement |
| --- | --- | --- |
| `memory_mib` | 256–262144 MiB (2^20 bytes) | Container memory hard limit |
| `cpu_millis` | 100–64000; 1000 = one CPU | CFS quota = value × 100 microseconds per 100000 microsecond period |
| `swap_mib` | Exactly 0 | Docker memory+swap equals memory; running cgroup must report `memory.swap.max=0` |
| `storage_mib` | 256–1048576 MiB | XFS project quota on overlay2 writable layer |
| `tmp_mib`, `shm_mib` | Each 16–1024 MiB; sum ≤ half memory | Sized `/tmp` tmpfs and `/dev/shm`; charged against the memory budget |
| `log_mib` | 1–100 MiB per log file | Explicit `json-file` `max-size` |
| `log_files` | 1–10 files | Explicit `max-file` rotation |

Only the two backend/driver strings shown above are accepted. The existing
512-process ceiling remains on the **container**, as do non-root UID/GID,
capability drop, no-new-privileges, token on stdin and read-only entrypoint mount
at `/runner-entrypoint.sh`, outside the `/tmp` tmpfs.
Policy values become separate quoted Docker arguments, never shell code. Memory,
shared memory, log size and writable-layer quota are passed as explicit byte
counts; log-driver SI suffix parsing does not change the declared MiB units.

## Supported host and observable preflight

Require Linux, rootful Docker with the **overlay2 graph driver on XFS mounted
with project quotas (`pquota`/`prjquota`)**, cgroup v2 and usable CPU, memory,
swap-limit and PID controllers. Other backends, including Docker's containerd
snapshotter, overlay2 on ext4 and cgroup v1, fail closed. Do not reformat or
reconfigure a running host just to satisfy these checks; plan a disposable host.

Before enabling an instance, run the helper from its selected immutable release:

```bash
sudo /usr/local/libexec/ephemeral-runner/releases/v2/scripts/runner-resources.py --instance example
```

This requires valid private config/auth files but never reads the PAT contents or
requests a registration token. It reports the pinned local image ID followed by
validated Docker arguments. On every launch it also runs before the token request:

1. Validate the policy and Docker capability/backend reports. Reject image-declared
   volumes, which could bypass the writable-layer quota.
2. Create a disposable network-disabled probe using the same CPU/memory/swap,
   writable-layer, tmpfs, shared-memory and logging options. Docker must accept
   `--storage-opt size`; overlay2 rejects this unless its XFS quota requirement is met.
3. Start the probe, inspect its settings and read its actual cgroup v2 memory,
   swap, CPU and PID limits. Mismatches and probe cleanup failures reject launch.
4. Remove the probe; use the inspected image ID for the actual job container.

The probe uses the trusted image's `/bin/sh`, `sleep` and `cat`, receives no
credentials, and normally lives only a few seconds. It self-exits after 45 seconds
and uses Docker auto-removal as a backstop if the helper is interrupted. Docker
outages or power loss can still require operator cleanup of `er-budget-*` remnants.
Do not count a printed flag or Docker info alone as live enforcement evidence.

Docker describes `--memory-swap` as **memory plus swap**, not swap alone. See
[Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/).
A host without swap can run only if it still exposes the required controller and
reports/executes this policy; otherwise preflight rejects it. Missing controller
support is not silently treated as equivalent to disabled swap. `free` inside a
container is not verification; the running cgroup value is checked instead.

Storage support follows [Docker's storage option requirements](https://docs.docker.com/reference/cli/docker/container/run/#set-storage-driver-options-per-container---storage-opt).
The quota bounds writable-layer blocks, including work files under `/home/runner`.
`/tmp` and `/dev/shm` use bounded memory-backed mounts instead. No persistent job
volumes are supported. Quotas do not reserve capacity or bound shared image layers,
image pulls/build cache, Docker metadata, daemon/system journals or host state.
Rotating container logs are approximately `log_mib × log_files` plus record and
rotation overhead; they are not a byte-exact filesystem quota. Host administrators
must provision/monitor bounded Docker data and journal capacity, prune unused
images safely and retain free-space headroom. There is no generic disk/I/O
bandwidth or inode isolation claim.

## Sizing, policy changes and migration

Budget **all concurrently active instances**, plus transient probes, Docker, the
OS, image/cache storage and other services. Keep total RAM budgets and tmpfs use
within available RAM with deliberate headroom; tmpfs is included in memory, not
an additional reservation. CPU quotas cap throughput but do not reserve CPUs.
Keep aggregate writable quotas plus retained logs, shared images and reserve
below provisioned disk capacity. The installer does not perform global admission
control or promise that overcommitted hosts remain healthy.

Change only the intended instance while its runner, cleanup service and timer are
stopped and GitHub reports Idle. Use `sudoedit` on the private JSON file, preserve
root ownership/mode 0600, run preflight, then explicitly start the instance. Running
containers retain their existing budgets until replaced. Never edit another
instance's policy implicitly.

For an existing installation, install a **new release version** with the new
helper. While stopped, explicitly create `resources.json` using the complete
example above, set root ownership/mode 0600, and invoke the documented `upgrade`
command. Upgrade validates the policy before changing the selected profile. It
does not silently create a policy for existing installations. Six-file releases
from before this feature remain verifiable. Selecting one is rejected by default.
Only a previously retained instance profile can be selected, and only with the
explicit `upgrade --allow-unbounded-legacy-rollback` acknowledgment while all
three units are stopped. A never-used legacy release is rejected even with that
flag. The command warns that this **restores old unbounded semantics** and leaves
services stopped. For an instance that previously used `old-v1`:

```bash
sudo ./scripts/install.sh upgrade --instance example --version old-v1 --allow-unbounded-legacy-rollback
```

Automatic recovery of a failed upgrade restores its journaled prior profile;
this preserves failure atomicity and does not start services. Keep a legacy
rollback stopped until its risk is deliberately accepted. New instances cannot
select those old releases through the updated installer. Other instances and immutable releases
remain unchanged; policy files survive upgrade/recovery/rollback.

## Failure and recovery

Invalid/missing policy, unsupported logging/storage/controller configuration,
failed quota probe or mismatched cgroups stops launch before GitHub registration.
Systemd may retry after 15 seconds; fix the policy/host precondition while stopped.
There is no fallback to unlimited operation.

Memory exhaustion can OOM-kill the runner/job. Exit **137** can also mean another
SIGKILL; inspect `State.OOMKilled` and kernel/container evidence. It remains a
failure, not an accepted intentional-stop status. A failed job may not deregister
cleanly; the existing offline/idle/ownership and container-absence checks govern
cleanup. Preserve current-name until deletion is verified; never force-delete
busy registrations to hide a failure. Low disk/quota produces ENOSPC/EDQUOT and CI
job failure; it does not grant more disk. Check host free space and quotas before
increasing a budget. Log rotation intentionally loses older logs: export required
CI evidence separately within a bounded retention policy.

## Opt-in disposable-host proof

Not run by ordinary CI and never run on the deployed Loom host:

```bash
sudo python3 scripts/check-resource-limits.py --disposable-host --image YOUR_LOCAL_TRUSTED_RUNNER_IMAGE
```

Run on the actual local Docker host with Python 3, at least 1 GiB available RAM
and 2 GiB free Docker data capacity. It uses no GitHub credentials/network and
never pulls an image. The image needs `/bin/sh`, `sleep`, `cat` and `python3`.
It uses 256 MiB RAM, 0.1 CPU, 256 MiB writable quota, small tmpfs and two 1 MiB logs.
It checks inspect/cgroups, observes CPU throttling, attempts at most 384 MiB disk
writes until quota rejection, and attempts 512 MiB allocation inside the bounded
OOM container. It checks OOM/137, neighbor survival and rotation after 8 MiB logs,
then removes its containers. Review the script before opting in. Interruptions
can leave `er-limits-test-*` containers for manual cleanup.

This is an executable test plan, **not a claim that it passed on any host**.
Record Docker/kernel/cgroup/XFS versions, inspect output, quota mount settings,
script results and free-space observations. Independently validate systemd job
lifecycle, cleanup after OOM, multi-instance operation and host capacity before
rollout. Unit/behavioral tests mock Docker and cannot establish kernel isolation.
