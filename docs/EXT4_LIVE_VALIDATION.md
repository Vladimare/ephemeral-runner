# Issue #17: opt-in GitHub-hosted Linux evidence

**Phase A offline component proof PASS; production remains NO-GO.** See the
[verification summary](examples/ext4-poc-report.json) for exact head, successful
run **42514199690**, artifact **13631130445**, historical failures and limitations.
The maintainer's downloaded-artifact audit reports serial/parallel ENOSPC,
isolation, overlap and independent cleanup PASS. The workflow remains dormant
for ordinary pushes and runs only on deliberate opt-in label events. Keep the
verified runtime/harness and security checks; do not rerun rootful validation
for documentation-only changes. Final documentation review remains pending;
registration, real runner jobs, crash/reboot recovery and production integration
are separate gates. No merge or deployment is performed by this update.

## Security and precise trigger

Review `.github/workflows/ext4-live-proof.yml`, `scripts/ext4-live-proof.py`, the
actual PoC and both Dockerfiles at the head you intend to validate. Only a
`pull_request` **labeled** event whose **added label** is exactly
`ext4-live-proof`, on same-repository PR **16**, its expected source branch and
base `main`, passes the job gate. Adding another label, leaving the label attached
while pushing, normal push/synchronize, fork PRs and other PR numbers cannot run
this job. It has no dispatch, schedule or pull_request_target path.

After audit, manually add that label in PR #16's Labels UI. If already present,
remove and re-add it **after re-reviewing the current head**. This is the only
manual trigger. The event's immutable head SHA is checked out and compared with
git HEAD; later commits do not replace it. Re-review and re-label for every new
head. Audit the workflow SHA as well as the head recorded in artifacts.

The runner is explicitly standard `ubuntu-24.04`, never self-hosted or a slim
container runner. Contents permission is read-only, checkout credentials are not
persisted, action commits are pinned, no secrets/PAT/registration tokens are
referenced and the sudo environment is an allowlist excluding GitHub tokens.
Only GitHub's newly provisioned VM receives privileged loop/mount access. The
script additionally checks hosted-runner context, Ubuntu release, PR event and
exact checkout; environment metadata is a guardrail, not cryptographic proof that
a root operator cannot spoof it. Never run it on an existing/shared host.

A fixed concurrency group serializes workflow runs (no cancellation of an active
run); probes within one VM may overlap. The job timeout is 20 minutes. Normal CI
continues to run only mocked/unit tests and syntax checks. This read-only-token
workflow cannot post evidence or apply labels; maintainers attach the run URL and
reviewed report to PR #16 themselves.

## Evidence pipeline

1. Record sanitized kernel/architecture, runner ImageOS/ImageVersion, Docker
   Client/Server version and restricted info, tool versions, cgroup controllers,
   available RAM, scratch free disk/inodes and `findmnt -T` output. Require root,
   Ubuntu 24.04, cgroup v2 controllers, CAP_SYS_ADMIN, a usable free loop device,
   ext4 scratch, 2 GiB available RAM, 1 GiB free disk and 8192 free host inodes.
   Missing prerequisites produce **SKIP / NO-GO** and a nonzero workflow step;
   they are not a PASS or an invitation to change the host.
2. Use the explicitly selected classic local-image-ID builder
   (`DOCKER_BUILDKIT=0` per CLI command, not daemon reconfiguration); BuildKit
   cannot reliably resolve `FROM sha256:<local-image-ID>`. If this builder is
   unavailable, retain the exact build failure; never switch to a mutable tag.
   Build the trusted base with the project's pinned runner archive SHA, then
   derive the offline fixture with `BASE=sha256:...` and no build network/pulls
   for the fixture. Record archive SHA, Dockerfile hashes and both immutable
   image IDs. Building the base may fetch Ubuntu/packages/the pinned archive;
   this is a distinct evidence step, not an implicit proof-script pull. Builds
   have bounded client deadlines; the whole VM is discarded after the job.
3. Run the **actual** 64 MiB PoC once serially and twice independently in parallel.
   Its admission/instance locks, filesystem bounds, cleanup and journal are not
   replaced by harness mocks. The harness first durably assigns a unique random
   128-bit nonce to each attempt, passes it as validated `--nonce`, and reads only
   `probe-NONCE/journal.json`. Missing/inconsistent nonce, name or directory
   dev/inode remains UNRESOLVED; no glob, mtime or stderr fallback is allowed.
   Existing directories cannot be adopted. Poll only exact journal-owned names/labels/IDs and
   loop devices to retain real observations. Mark actual container overlap PASS
   only when two owned containers are observed Running without restarts and both
   start times precede the earliest inspect request in that poll; otherwise
   leave overlap NOT RUN (attempted but unobserved), even if all probes succeed.
   Overall PASS requires witnessed overlap; otherwise the result is FAIL/NO-GO
   while retaining individual probe results.
4. Reject a deliberately invalid image through the actual CLI. Require its
   nonzero pre-setup failure and unchanged scratch entries. This is the first
   non-destructive failure test, not a crash/reboot/drain test.
5. Validate genuine byte and inode ENOSPC, bounded statfs/backing allocation,
   identity/isolation settings, actual cgroups, mountinfo and successful exact
   cleanup. Independently query a successful full Docker container listing, the
   live loop map, host mountinfo and exact backing path after each successful
   attempt. Record exact container ID/name, loop/backing identity and mount
   target/device absence in `cleanup_proof`. Lingering or reused resources fail;
   unavailable observations remain UNRESOLVED and fail the attempt. These checks
   never remove resources. Missing evidence/nonzero PoC/cleanup gives FAIL. Root read-only write
   checks and offline layout are assertions in the actual payload; they do not
   prove registration or a runnable job layout.

The `always()` collector reads exact attempt journals and named log files, never
disk images, arbitrary directories, Docker configuration or the checkout. It
strips daemon identity/proxies/registry data, inspect env/argv and credential
patterns. Raw evidence stays root-only inside the disposable VM. A single
sanitized JSON artifact is uploaded with 7-day retention. On setup failure or
job cancellation some evidence may be absent; the collector reports unresolved
state instead of inventing PASS. Timeout/cancellation can also prevent artifact
upload; no artifact means **unverified**, never success.

There is **no harness cleanup by prefix**, recursive host deletion, forced/lazy
unmount, detach-all, daemon restart, firewall change or storage migration. The
actual PoC alone performs identity-checked teardown. When uncertain it retains
journals/allocations and fails. Collect evidence and let GitHub destroy the VM;
never retry guessed cleanup commands or use a working host as fallback.

## Recording results after a reviewed manual run

Download `ext4-live-HEAD-RUN-ATTEMPT`, inspect its `ext4-live-evidence.json` and the
Actions logs. Record actual run URL/head/workflow SHA, image IDs, provenance,
per-attempt observations, cleanup and explicit status of every gate. Review
redaction before sharing. Only then update `docs/examples/ext4-poc-report.json`
and link the actual report on PR #16. No generated example in the repository is
live proof. FAIL is enforcement/setup failure; SKIP is unmet prerequisites;
NOT RUN is unexecuted or unobserved evidence. SIGKILL, daemon outage, busy mount,
reboot recovery, registration and real jobs stay **NOT RUN** in this first
workflow. Independent review must assess the actual report before merge.

## Separate QEMU fallback plan (no automatic host changes)

If GitHub reports unsuitable storage, loop or mount capabilities, retain the
precise prerequisite error and use a **new Ubuntu 24.04 guest**, after separate
provisioning review. Do not attach physical/shared host disks or Docker sockets.

- Obtain Ubuntu's official image and verify its published checksum/signature.
  Create a disposable qcow2 overlay backed by that read-only image, plus a new
  **virtual** scratch disk. Start QEMU with user-mode networking, no host directory
  passthrough, no production credentials and no guest access to host loop nodes.
- Inside that guest only, identify the new blank scratch disk by recorded virtual
  serial/capacity; format it ext4, mount under a root-owned private path, install
  Docker/util-linux/e2fsprogs/Python and build the pinned images. Never copy a
  `/dev/sdX` formatting command from another machine or format the guest root.
- Snapshot the prepared guest. Run the existing PoC directly using its explicit
  disposable-host flag and parent on scratch; do not forge GitHub environment
  variables to bypass the hosted-only harness. Record equivalent provenance and
  gate evidence with a separate QEMU run identifier.
- Revert/discard snapshots between reviewed fault cases. A separate snapshot
  matrix is needed for SIGKILL, busy mount, daemon outage and reboot. Never run
  those in the first GitHub workflow or against existing deployments.

This is a reproducible provisioning checklist, not a provisioned/validated guest.
No fallback is auto-executed and no backend is enabled by a green component run.


Example disposable-VM preparation on a separately selected hypervisor host (review and reserve sufficient host disk/RAM first;
these commands were not run by this task):

```bash
# Use a separately verified official Ubuntu 24.04 server ISO; no host disk passthrough.
qemu-img create -f qcow2 guest-os.qcow2 24G
qemu-img create -f qcow2 guest-scratch.qcow2 2G
qemu-system-x86_64 -m 4096 -smp 2 -snapshot \
  -cdrom VERIFIED_UBUNTU_24_04_SERVER.iso -boot d \
  -drive file=guest-os.qcow2,format=qcow2,if=virtio \
  -drive file=guest-scratch.qcow2,format=qcow2,if=none,id=scratch \
  -device virtio-blk-pci,drive=scratch,serial=ext4-proof-scratch \
  -nic user,model=virtio-net-pci
```

Install the guest OS onto the OS disk, identify the scratch serial **inside the
guest**, and format only that new empty virtual scratch disk after inspection.
The snapshot option discards writes on exit; export redacted evidence before
closing. Reserve backing capacity for both virtual disks; sparse qcow2 is not a
host reservation. Do not pass through host devices, mounts, credentials or sockets.
