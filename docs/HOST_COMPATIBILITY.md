# Read-only host compatibility inventory (Issue #9, phase 1)

Run directly on the Linux **Docker daemon host**, in its host mount/PID/cgroup
namespaces. This command is an inventory, not a deployment preflight or an
integration proof. It never creates/starts/stops containers, probes endpoints,
registers a runner, reads instance config/PAT files, loads units, or changes a
mount, firewall, network or daemon setting. It does not invoke sudo itself.

```sh
python3 scripts/check-host-compatibility.py --network er-ci > host-compatibility.json
# Retain the exit status even when saving a report:
result=$?
echo "diagnostic exit: $result"
```

The bridge must already exist. Omit `--network` to inventory networks without
selecting one; the runner-network requirement then remains UNKNOWN. Built-in
`bridge`, `host` and `none` are rejected. No bridge name is read from private
instance files and the command never creates one. Read permission for the local
Docker socket and relevant host files is needed; missing access yields UNKNOWN.
Docker socket access remains privileged even for this read-only command.

The tool explicitly selects `unix:///var/run/docker.sock` and removes Docker
context/host/TLS environment overrides in its subprocesses. It does not use a
remote daemon or support rootless/custom-socket deployments. Do not execute it in
a job/container, against a forwarded socket or another host's mounted Docker socket:
local mount/cgroup measurements would describe a different environment. Docker
Desktop is not an inventory of its Linux VM from the macOS host. Current supported
production storage remains overlay2/XFS; no ext4 fallback is enabled.

## Report contract

The JSON report has `format_version: 1`, a list of named `checks`, independent
`integration` gates, and `production_ready: false`. Per-check statuses:

- PASS: the stated *inventory observation* was established.
- FAIL: a known requirement was not met (e.g. ext4/btrfs, rootless Docker, wrong
  architecture, missing tool/controller, or explicitly disabled project quotas).
- UNKNOWN: permissions, missing/malformed metadata, unsupported visibility or an
  inherently untested enforcement property prevent a conclusion.

The overall inventory gives FAIL precedence over UNKNOWN. Exit codes are 1 for
FAIL, 2 for UNKNOWN, 0 for all-PASS inventory. Argument errors also use exit 2 and
produce no report. The current read-only command deliberately keeps quota
enforcement and Docker firewall-backend verification UNKNOWN, so even an otherwise
compatible host returns 2. Consumers must inspect statuses and must never use this
command's output as permission to launch a runner. Existing production preflight
remains mandatory and unchanged.

The report captures distribution/kernel/architecture, required tool availability,
systemd version and PID 1 identity, daemon server version and rootful/cgroup/resource
advertisements, storage driver/backing filesystem, XFS quota mount options, local
cgroup controllers, readable swap limit, available RAM/Docker disk, network counts,
selected network IPv6 configuration, and IPv4/IPv6 firewall frontend identities.
Commands have 15-second timeouts. Successful stdout over 1 MiB is rejected; this
is a post-capture sanity check, not a hard subprocess allocation bound. The local
root-controlled tools/daemon are trusted. Reports omit raw command errors, daemon
hostnames/proxy/registry fields, paths, network names/IDs/subnets and firewall rules.
Review reports before sharing: kernel, distribution, capacity and tool versions
are still machine metadata. No timestamps are invented; attach the commit SHA,
actual host description and invocation when preserving execution evidence.

Interpretation limits:

| Observation | What it does not establish |
| --- | --- |
| XFS mount has `pquota`/`prjquota` and no explicit disable option | Actual per-container storage enforcement; run the bounded disposable proof |
| Docker advertises cgroup v2 CPU/memory/swap/PID capabilities | Delegation, actual container limits, OOM isolation or neighbor survival |
| `memory.swap.max` readable for this diagnostic process | A job's zero-swap policy; the hierarchy root may omit the interface |
| `iptables`/`ip6tables` frontend reports nf_tables/legacy, or nft is installed | Docker's selected firewall backend, rule ordering or IPv4/IPv6 isolation |
| Dedicated bridge exists and reports IPv6 enabled/disabled | Host/LAN/metadata/inter-runner isolation, DNS or public egress |
| Free bytes available | Per-instance reservation, aggregate capacity or workload suitability |
| PID 1 is systemd and CLI exists | Correct unit loading, timer scheduling, shutdown or reboot behavior |

In particular, Docker's nftables backend differs from the iptables-nft frontend;
the tool refuses to infer backend selection from the executable versions. Raw
rules and daemon configuration are intentionally not dumped. Confirm actual
backend/chain ordering with the separately reviewed network-verification work.

## Evidence and remaining work

[host-compatibility.example.json](host-compatibility.example.json) is a **synthetic,
sanitized Linux fixture**, checked against the scenario tests. It is not execution
evidence. It illustrates compatible configuration observations with overall UNKNOWN
and every live integration gate NOT RUN.

Normal GitHub-hosted CI also runs this read-only inventory and uploads
`host-compatibility.json` as the `host-compatibility` artifact. FAIL/UNKNOWN
compatibility observations are expected on unsupported hosted workers and do not
fail CI; crashes, malformed reports and inconsistent exit codes do. This step
creates no container, invokes no resource proof and never registers a runner. Its
report describes only that hosted worker, not the deployed host.

Local validation runs the normal repository tests. The new scenarios include ext4/
btrfs refusal, XFS missing/disabled/enabled quota flags, rootless/wrong architecture,
missing tools/controllers, missing swap interface, daemon failures/malformed data,
IPv6 visibility, remote environment isolation, command allowlist and redaction.
The command can also be executed on macOS to verify an honest unsupported-host
report; that cannot validate Linux runtime behavior.

Phase 2 is still required under [Issue #9](https://github.com/Vladimare/ephemeral-runner/issues/9).
Its gates remain explicitly NOT RUN in this report:

1. Build/check pinned runner archive, image UID and shell/Python dependencies.
2. Opt-in disposable-host cgroup/quota/OOM/log/neighbor proof using
   `scripts/check-resource-limits.py --disposable-host --image LOCAL_TRUSTED_IMAGE`.
3. Real launcher mount shape, cap-drop, non-root user and no-new-privileges.
4. Unit loading, timers, maintenance and one-job replacement; multi-instance tests.
5. Fault injection, interrupted installation, SIGTERM/137 and reboot recovery.
6. Actual IPv4/IPv6 isolation and required egress under the chosen firewall backend.

Do not run destructive tests on a shared/deployed host. Real GitHub registration
and jobs require separate authorization for a throwaway repository and scoped
token. This phase-1 change supplies no PAT or auto-running privileged workflow.
[Issue #10](https://github.com/Vladimare/ephemeral-runner/issues/10) has merged
maintenance code in [PR #18](https://github.com/Vladimare/ephemeral-runner/pull/18),
but its live lifecycle proof remains outstanding as described in
[MAINTENANCE.md](MAINTENANCE.md). Neither issue is closed by this inventory.

References: [Docker per-container storage constraints](https://docs.docker.com/reference/cli/docker/container/run/#set-storage-driver-options-per-container---storage-opt),
[Docker nftables backend](https://docs.docker.com/engine/network/firewall-nftables/),
and [kernel cgroup v2 interfaces](https://docs.kernel.org/admin-guide/cgroup-v2.html).
