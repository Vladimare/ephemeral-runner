# Separately authorized trusted-workflow smoke

This is a reproducible **plan**, not authorization or a passed test. Do not run
it with an existing host, repository or token. Issue #13's candidate backend is
not enabled; complete its offline image/storage gates first. The current XFS
backend may be tested on a separately provisioned disposable compatible host.

1. Obtain explicit authorization naming the disposable Linux host, disposable
   repository, trusted test commit, image digest, temporary fine-grained token,
   expected API/container actions and teardown. Never print or commit credentials.
2. Independently review the pinned runtime/image and [storage decision](ADR_EXT4_STORAGE.md).
   Run the relevant opt-in bounded proof there and retain inspect/cgroup/mount/
   filesystem evidence. Stop if any bound, write path or cleanup test fails.
3. Provision a new `smoke` instance using the documented installer on that host;
   use the authorized repository and a secured bridge. Create only its own
   root-owned mode-0600 auth and policy files. Run preflight before enabling.
   A future ext4 candidate must use its explicitly accepted backend version;
   do not omit a limit to force the current XFS runtime onto ext4.
4. After authorization, enable the instance and capture redacted registration
   evidence showing its unique label and Idle status. The host requests a
   registration token through curl's private config and sends it on stdin;
   neither PAT nor registration token belongs in workflow YAML, argv or artifacts.
5. Commit this workflow **only to the authorized disposable repository**. Replace
   the label with the newly generated smoke label, then dispatch once:

```yaml
name: Trusted disposable runner smoke
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  smoke:
    runs-on: [self-hosted, Linux, X64, REPLACE_WITH_SMOKE_INSTANCE_LABEL]
    timeout-minutes: 5
    steps:
      - name: Verify approved writable paths
        shell: bash
        run: |
          set -euo pipefail
          id
          test ! -S /var/run/docker.sock
          test -n "$RUNNER_TEMP"
          printf 'bounded trusted fixture\n' > "$RUNNER_TEMP/storage-smoke"
          test -s "$RUNNER_TEMP/storage-smoke"
          rm "$RUNNER_TEMP/storage-smoke"
```

6. Record `config.sh` registration success, one job completion, ephemeral
   deregistration/container disappearance, and one replacement returning Idle.
   Verify the replacement's own cgroups/mounts and the backend's safe cleanup.
   Do not run destructive quota/OOM workloads through this workflow; use the
   dedicated offline bounded proof on the disposable host.
7. Stop only while Idle, audit/sweep using conservative ownership checks, verify
   no current registration/container/storage resources remain, disable the
   smoke units, revoke its temporary token, and remove only authorized test
   resources. Preserve failure evidence; never force-delete busy registrations.

Record commands, exit statuses, image/runtime versions, workflow run URL and
redacted evidence. Keep configured flags distinct from observed enforcement and
actual job success. Independent review must assess failed and unrun gates too.
