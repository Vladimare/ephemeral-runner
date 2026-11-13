# Planned maintenance and forced shutdown (#10)

This version provides a **replacement inhibition and natural-exit** workflow.
It is not an atomic GitHub scheduler drain. No service, container, network or
registration on a deployed host is changed merely by updating this repository.
Install a new immutable release explicitly; older releases do not honor this gate.
Do not use these commands from a different release than the selected instance.

## Supported maintenance procedure

Coordinate a maintenance window with other administrators. Pause workflow routing
and automatic/manual dispatch to this instance externally. This is an operational
prerequisite: the repository runner REST API has no documented transactional
stop-new-assignment-and-finish-current-job operation. Reading `busy=false`, deleting
a label or deleting a registration is not treated as proof that stopping is safe.

Using the cleanup script from the instance's **selected release**:

```sh
sudo /usr/local/libexec/ephemeral-runner/releases/v2/scripts/runner-cleanup.py \
  --instance example --plan-maintenance --ack-maintenance-window
# Stop ONLY cleanup scheduling; do NOT stop/restart the runner service.
sudo systemctl stop ephemeral-runner-cleanup@example.timer ephemeral-runner-cleanup@example.service
sudo /usr/local/libexec/ephemeral-runner/releases/v2/scripts/runner-cleanup.py \
  --instance example --maintenance-status
```

Arming creates/fsyncs a host-only persistent marker, without Docker/GitHub calls
or signals. The launcher checks it before resource probes and token acquisition;
exit 75 prevents automatic restart. The marker survives service restart, reboot
and a versioned upgrade. A launcher already past the check may register and
accept **one job**. An existing idle runner may still accept its one job. Arming
is successful only when the command exits zero; a contended cleanup lock returns
nonzero and must be retried. Never interpret an error as an armed gate.

`--maintenance-status` exits zero with `READY` only after all three units report
inactive/failed, no matching containers exist (including unregistered orphans),
and registration cleanup succeeds. Every other outcome is nonzero: preserve the
gate, resolve the reported condition, and retry later. It can delete confirmed
owned, offline, idle registrations whose containers are absent; it never signals,
stops or removes a container. Docker/API/systemd errors fail closed. The instance
cleanup lock serializes manual cleanup and timer invocations; a competing operation
fails rather than waits. External `systemctl` and installer operations are not
locked: administrators must serialize them throughout maintenance.

After READY, perform the existing stopped-instance upgrade/recovery procedure.
The gate is deliberately outside immutable profiles; interrupted upgrade or
rollback retains it. A rollback to an older release that does not implement this
protocol is safe only while stopped and after READY; starting it discards these
guarantees. No installer auto-starts a service. To resume using a supporting release:

```sh
sudo /usr/local/libexec/ephemeral-runner/releases/v2/scripts/runner-cleanup.py \
  --instance example --resume
sudo systemctl reset-failed ephemeral-runner@example.service
sudo systemctl start ephemeral-runner@example.service ephemeral-runner-cleanup@example.timer
```

Resume repeats readiness checks and removes the gate; it never starts a unit.
Do not manually delete the marker to bypass unresolved state.

| State | Planned behavior |
| --- | --- |
| Configuring/launch already underway | PENDING; allow it to finish or run one job |
| Busy, including busy-to-idle transition | PENDING while launcher/container exists; no signal |
| Idle and online | May wait indefinitely for its one job; no safe idle-stop assertion |
| Stuck/API unavailable | PENDING/error; no deadline-triggered kill |
| Offline or already removed | READY only after units stop and absence/cleanup is verified |
| Container without registration after launcher crash | PENDING; explicit forced recovery required |
| Unknown/transitioning unit or unknown busy/status | Nonzero, gate retained |

## Forced shutdown

`systemctl stop/restart`, host shutdown, Docker failure, OOM, SIGKILL and watchdog
termination are **not planned maintenance** and may cancel a job, even if the last
API sample said idle. Outside maintenance, systemd's explicitly named
`--service-stop` hook performs forced current-container shutdown and logs that risk.
Inside maintenance it does only passive cleanup, so automatic exit-75 processing
cannot kill a leftover container. This does not make an explicit `systemctl stop`
safe: systemd still terminates launcher processes and their pipeline.

An operator accepting job cancellation can explicitly invoke:

```sh
sudo /usr/local/libexec/ephemeral-runner/releases/v2/scripts/runner-cleanup.py \
  --instance example --force-current
```

This stops the current container with a 30-second grace period, then attempts
removal (including force if needed). Timeout, Docker uncertainty, failed removal,
unknown/online/busy registration or failed deletion confirmation preserve state
and return nonzero. Reconcile with audit/sweep after GitHub reports offline and
idle. `--current` is now passive and never stops containers. ExecStopPost is also
passive. Exit 143 is allowed for deliberate SIGTERM; 137 is failure, never success.
A launcher crash can still invoke its preexisting EXIT trap; this protocol does
not promise surviving faults or interrupted shutdown.

Outages retry at a fixed 60-second systemd interval (rather than 15 seconds), with
start rate limiting disabled so long outages do not permanently suppress recovery.
Each launch has bounded curl/Docker operations and at most one registration-token
request; cleanup remains bounded to 100 pages. This limits frequency, not a global
API quota across instances. Observe journals and stop a persistently broken
instance under the forced-shutdown policy. No exponential retry or Retry-After
scheduler is claimed. Required root-only PAT, stdin token transport, resource
limits and per-instance release selection are unchanged.

## Research and verification

Source audit: [GitHub runner REST API](https://docs.github.com/en/rest/actions/self-hosted-runners),
[runner v2.338.0 Runner.cs](https://github.com/actions/runner/blob/v2.338.0/src/Runner.Listener/Runner.cs)
and [JobDispatcher.cs](https://github.com/actions/runner/blob/v2.338.0/src/Runner.Listener/JobDispatcher.cs).
The listener treats ephemeral mode as run-once. SIGTERM invokes runner shutdown;
JobDispatcher shutdown cancels dispatched work. Neither signal handling nor a
REST busy snapshot is used as a planned completion guarantee here. Re-audit these
assumptions when changing the pinned runner image.

Local tests use temporary files, a real advisory lock, an actual Bash gate
subprocess, and mocked API/Docker/systemd boundaries. They cover active/configuring
and unknown units, assignment transitions, orphan containers, API 403/429/5xx and
timeout, explicit force failure, marker persistence/resume, cleanup contention,
state retention and systemd exit/backoff settings. Existing installer interrupted
upgrade/recovery tests still run. They do not establish Linux lifecycle behavior.

**NOT RUN / acceptance outstanding (#9/#10/#12):** disposable Linux systemd
verification, real one-job GitHub lifecycle, reboot/power loss and signal delivery.
Use an independently provisioned disposable Linux host, never the deployed runner.
Real GitHub registration/job execution requires separate disposable-repository/token
authorization. Preserve sanitized unit journal, container IDs, registration IDs,
exit statuses and command outcomes against the exact tested commit for this matrix:

1. Busy job: arm maintenance, stop only cleanup timer/service, show job finishes,
   replacement exits 75, no later registration, status READY, then resume.
2. Idle/configuring assignment race: arm after gate check; show one possible job
   completes without a stop signal, and no replacement appears. Idle indefinitely
   must remain PENDING; never send a dummy job without explicit authorization.
3. Repeat 403/429/5xx/timeouts and Docker daemon loss in disposable fixtures; verify
   no READY, state retained, retries >=60 seconds and eventual recovery.
4. Explicit forced SIGTERM, timeout and 137: record possible job cancellation,
   conservative offline/idle deletion and failed-stop/removal recovery.
5. Kill launcher/interrupt upgrade, reboot, concurrent cleanup timer: gate remains,
   orphan container blocks readiness, other instance is unaffected; verify unit
   loading supports RestartPreventExitStatus and ExecStop/ExecStopPost semantics.

Independent implementation/security review and green CI on the final head are
required before merge. This patch does not close the issue's live acceptance gate
or authorize deployment/release.
