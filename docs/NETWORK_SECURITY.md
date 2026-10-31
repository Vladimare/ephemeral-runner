# Network isolation and threat model

This project uses **Docker containers**, not virtual machines. A rootful Docker daemon, kernel, and host network stack are shared with jobs. A container escape or a privileged Docker administrator compromises the host. **Do not treat this configuration as safe for arbitrary untrusted pull-request code.** Use a disposable VM/host for truly untrusted contributions. Limit workflow triggers and repository write access.

## Mandatory deployment precondition

`install.sh` requires a **pre-existing named Docker bridge network** and refuses Docker's built-in `bridge`, `host`, or `none` networks. The installer does **not** install firewall rules, because doing so without examining the host network, interface names, IPv6 and Docker networking backend can disrupt connectivity or expose services. A named bridge alone is *not* an isolation boundary: by default its containers can reach host services, RFC1918 LAN addresses and the public internet.

Configure host-side firewall rules for your own bridge and addresses. Example subnet and interface names are illustrative; do not reuse host-specific network settings without checking the intended host.

On a new host, verify and configure **both INPUT and FORWARD paths** (as appropriate for the local firewall implementation), including IPv6 if enabled. A generic policy for a dedicated runner bridge is:

- Drop new packets from the bridge to the host itself, except explicitly documented necessities.
- Drop forwarded traffic from the runner bridge to loopback, link-local, RFC1918/private and internal address space. Consider IPv6 ULA and link-local too.
- Allow reply traffic (established/related) and only required outbound internet traffic; at minimum GitHub runner needs HTTPS.
- Check how Docker modifies iptables/nftables and the order of the relevant base chains. Do not blindly `flush ruleset` or assume a single nftables rule covers Docker's forwarding rules.
- Verify isolation with an intentionally benign test container on that network before accepting workflows; block access to host SSH, LAN services, and any metadata endpoints.

## Process isolation

Containers run as UID:GID `10001:10001`, with `--cap-drop ALL`, `no-new-privileges`, `--pids-limit 512`, `--init` and no persistent volumes. The host-file mount is a read-only, root-controlled entrypoint; `/tmp` and `/dev/shm` use sized memory-backed mounts. Docker socket, host home, SSH keys and PAT are not mounted. Jobs have the permissions of the unprivileged container user but **can execute arbitrary code within its container** and reach anything permitted by its network policy.

No Docker-based job/service containers: the runner has no Docker socket. For workflows needing them, use a separate appropriately isolated environment.

## Credentials

The host needs a fine-grained PAT restricted to the selected repository with repository **Administration: Read and write** to create registration tokens, list and delete runners. Store it in `/etc/ephemeral-runner/instances/INSTANCE/auth.curl.conf` root-only; never commit it. The token is handled host-side by curl; the short-lived registration token crosses the container stdin, not a Docker environment variable or argument. The runner receives its own registration credentials inside its disposable filesystem until container removal.

Treat all root-owned files and Docker control-plane access as sensitive. Use dedicated least-privilege tokens per repository, rotate them, and audit access to `/etc/ephemeral-runner`.

## Known limitations

- A runner may be forcibly stopped while a job is busy; do not call `systemctl stop` on an active job. The cleanup helper defers deletion when GitHub still reports `busy=true`.
- GitHub's REST API may omit the `ephemeral` property. The deletion guard therefore uses a randomly generated prefix + matching dedicated label, plus `offline`, `busy=false`, and no locally existing container. Never reuse one instance's label/prefix for runners managed by another host.
- Stale registrations can briefly persist after crashes or power failures, until the timer's next successful sweep.
- Docker access is effectively host-root; host compromise is possible from kernel/container vulnerabilities.

## Shared-host availability

[Per-instance resource policies](RESOURCE_LIMITS.md) bound container CPU, RAM,
swap, writable-layer storage, temporary memory and rotated logs on explicitly
supported hosts. Preflight verifies a disposable container before registration;
unsupported quota/controller setups fail closed. These limits do not provide VM
isolation, reserve host capacity, bound host journals/shared images, or protect an
overcommitted host. Size aggregate budgets with OS/Docker/disk headroom and monitor
free space. OOM/SIGKILL 137, disk quota failures and lost rotated logs can fail CI
jobs; use the documented conservative cleanup/recovery process. CPU and memory
constraints do not validate IPv4/IPv6 firewall or host/LAN isolation. Run resource
exhaustion demonstrations only through the opt-in disposable-host test plan.
