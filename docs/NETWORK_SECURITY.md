# Network isolation and threat model

This project uses **Docker containers**, not virtual machines. A rootful Docker daemon, kernel, and host network stack are shared with jobs. A container escape or a privileged Docker administrator compromises the host. **Do not treat this configuration as safe for arbitrary untrusted pull-request code.** Use a disposable VM/host for truly untrusted contributions. Limit workflow triggers and repository write access.

## Mandatory deployment precondition

`install.sh` requires a **pre-existing named Docker bridge network** and refuses Docker's built-in `bridge`, `host`, or `none` networks. The installer does **not** install firewall rules, because doing so without examining the host network, interface names, IPv6 and Docker networking backend can disrupt connectivity or expose services. A named bridge alone is *not* an isolation boundary: by default its containers can reach host services, RFC1918 LAN addresses and the public internet.

For host `loom-ci` the production installation used host-side nftables rules restricting access to localhost/host services and private network ranges, while allowing outbound public HTTPS for GitHub and package downloads. Do not copy `172.20.0.0/16`, `br-loom-ci`, or host-specific addresses to another machine without checking them.

On a new host, verify and configure **both INPUT and FORWARD paths** (as appropriate for the local firewall implementation), including IPv6 if enabled. A generic policy for a dedicated runner bridge is:

- Drop new packets from the bridge to the host itself, except explicitly documented necessities.
- Drop forwarded traffic from the runner bridge to loopback, link-local, RFC1918/private and internal address space. Consider IPv6 ULA and link-local too.
- Allow reply traffic (established/related) and only required outbound internet traffic; at minimum GitHub runner needs HTTPS.
- Check how Docker modifies iptables/nftables and the order of the relevant base chains. Do not blindly `flush ruleset` or assume a single nftables rule covers Docker's forwarding rules.
- Verify isolation with an intentionally benign test container on that network before accepting workflows; block access to host SSH, LAN services, and any metadata endpoints.

## Process isolation

Containers run as UID:GID `10001:10001`, with `--cap-drop ALL`, `no-new-privileges`, `--pids-limit 512`, `--init` and no persistent volumes. The only mount is a read-only, root-controlled entrypoint. Docker socket, host home, SSH keys and PAT are not mounted. Jobs have the permissions of the unprivileged container user but **can execute arbitrary code within its container** and reach anything permitted by its network policy.

No Docker-based job/service containers: the runner has no Docker socket. For workflows needing them, use a separate appropriately isolated environment.

## Credentials

The host needs a fine-grained PAT restricted to the selected repository with repository **Administration: Read and write** to create registration tokens, list and delete runners. Store it in `/etc/ephemeral-runner/INSTANCE.curl.conf` root-only; never commit it. The token is handled host-side by curl; the short-lived registration token crosses the container stdin, not a Docker environment variable or argument. The runner receives its own registration credentials inside its disposable filesystem until container removal.

Treat all root-owned files and Docker control-plane access as sensitive. Use dedicated least-privilege tokens per repository, rotate them, and audit access to `/etc/ephemeral-runner`.

## Known limitations

- A runner may be forcibly stopped while a job is busy; do not call `systemctl stop` on an active job. The cleanup helper defers deletion when GitHub still reports `busy=true`.
- GitHub's REST API may omit the `ephemeral` property. The deletion guard therefore uses a randomly generated prefix + matching dedicated label, plus `offline`, `busy=false`, and no locally existing container. Never reuse one instance's label/prefix for runners managed by another host.
- Stale registrations can briefly persist after crashes or power failures, until the timer's next successful sweep.
- Docker access is effectively host-root; host compromise is possible from kernel/container vulnerabilities.
