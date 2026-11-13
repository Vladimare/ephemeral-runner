#!/usr/bin/env python3
"""Conservative, repository-scoped cleanup for one ephemeral runner installation.

No GitHub token is accepted through argv or environment. The fine-grained token
is read by curl from a root-only config file on the host.
"""

import argparse
import fcntl
from contextlib import contextmanager
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

CONFIG_BASE = Path('/etc/ephemeral-runner/instances')
STATE_BASE = Path('/var/lib/ephemeral-runner')
INSTANCE_RE = re.compile(r'[a-z][a-z0-9-]{0,19}\Z')
REPOSITORY_RE = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z')
LABEL_RE = re.compile(r'[a-z][a-z0-9-]{1,62}\Z')
PREFIX_RE = re.compile(r'er-[a-z0-9-]{3,32}\Z')
CONFIG_LINE_RE = re.compile(r'([A-Z_]+)=([A-Za-z0-9_./:@-]+)\Z')


@dataclass(frozen=True)
class Config:
    instance: str
    repository: str
    label: str
    prefix: str
    network: str
    image: str

    @property
    def auth(self):
        return CONFIG_BASE / self.instance / 'auth.curl.conf'

    @property
    def state(self):
        return STATE_BASE / self.instance / 'current-name'

    @property
    def maintenance(self):
        return CONFIG_BASE / self.instance / "maintenance"

    @property
    def url(self):
        return f'https://api.github.com/repos/{self.repository}/actions/runners'

    def valid_name(self, name):
        return bool(re.fullmatch(re.escape(self.prefix) + r'-[0-9]+-[0-9]+', name))


def check_private_root(path, *, uid=0, root=Path('/')):
    """Validate each component without following links (root/uid are test seams).

    Descriptors pin traversal while checking. Later Python/bash/curl reads reopen
    the path: trusted administrators must serialize replacement with runner use.
    """
    parts = Path(path).relative_to(root).parts
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index in range(len(parts)):
            parent = os.fstat(directory)
            if parent.st_uid != uid or parent.st_mode & 0o022:
                raise RuntimeError('Config/auth parents must be root-owned and not group/world writable')
            final = index == len(parts) - 1
            flags = os.O_RDONLY | os.O_NOFOLLOW | (os.O_NONBLOCK if final else os.O_DIRECTORY)
            child = os.open(parts[index], flags, dir_fd=directory)
            if final:
                try:
                    st = os.fstat(child)
                    if not stat.S_ISREG(st.st_mode) or st.st_uid != uid or stat.S_IMODE(st.st_mode) != 0o600:
                        raise RuntimeError('Config/auth must be root-owned regular files with mode 0600')
                finally:
                    os.close(child)
            else:
                os.close(directory)
                directory = child
    finally:
        os.close(directory)


def load_config(instance):
    if not INSTANCE_RE.fullmatch(instance):
        raise ValueError(f'Invalid instance name: {instance!r}')
    path = CONFIG_BASE / instance / 'config.env'
    check_private_root(path)
    data = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        match = CONFIG_LINE_RE.fullmatch(line)
        if not match or match[1] in data:
            raise ValueError(f'Invalid or duplicate configuration key in {path}')
        data[match[1]] = match[2]
    expected = {'REPOSITORY', 'RUNNER_LABEL', 'RUNNER_PREFIX', 'DOCKER_NETWORK', 'RUNNER_IMAGE'}
    if set(data) != expected:
        raise ValueError(f'Config fields must be exactly {sorted(expected)}')
    if not REPOSITORY_RE.fullmatch(data['REPOSITORY']):
        raise ValueError('Invalid GitHub repository (expected OWNER/REPO)')
    if not LABEL_RE.fullmatch(data['RUNNER_LABEL']) or not PREFIX_RE.fullmatch(data['RUNNER_PREFIX']):
        raise ValueError('Invalid dedicated runner label/name prefix')
    if data['DOCKER_NETWORK'] in ('host', 'bridge', 'none'):
        raise ValueError('A dedicated Docker network must be configured')
    check_private_root(CONFIG_BASE / instance / 'auth.curl.conf')
    return Config(instance, data['REPOSITORY'], data['RUNNER_LABEL'],
                  data['RUNNER_PREFIX'], data['DOCKER_NETWORK'], data['RUNNER_IMAGE'])


def command(argv, *, check=True, timeout=60):
    proc = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    if check and proc.returncode:
        # argv is not printed: a curl auth-config path is harmless, but keeping
        # diagnostics to the program and stderr avoids accidental secret output.
        raise RuntimeError(f'{argv[0]} failed (rc={proc.returncode}): {proc.stderr.strip()}')
    return proc


def github(cfg, method, url):
    proc = command([
        'curl', '-fsS', '--connect-timeout', '5', '--max-time', '20',
        '--config', str(cfg.auth), '-H', 'Accept: application/vnd.github+json',
        '-X', method, url,
    ], timeout=30)
    return json.loads(proc.stdout) if method == 'GET' else None


def runners(cfg):
    result = []
    for page in range(1, 101):
        data = github(cfg, 'GET', f'{cfg.url}?per_page=100&page={page}')
        if not isinstance(data, dict) or not isinstance(data.get('runners'), list):
            raise RuntimeError('Unexpected GitHub API response: expected runners list')
        batch = data['runners']
        result.extend(batch)
        if len(batch) < 100:
            return result
    raise RuntimeError('Too many repository runners; refusing partial listing')


def labels(runner):
    return {v.get('name') for v in runner.get('labels', []) if isinstance(v, dict)}


def owned(cfg, runner):
    # GitHub REST often omits the ephemeral property, returning None.
    # A unique, installation-generated prefix + dedicated label provide scope.
    return (cfg.valid_name(str(runner.get('name', '')))
            and cfg.label in labels(runner)
            and runner.get('ephemeral') is not False)


def docker_exists(name):
    proc = command(['docker', 'container', 'inspect', '--format', '{{.Id}}', name], check=False)
    if proc.returncode == 0:
        return True
    err = proc.stderr.lower()
    if 'no such object' in err or 'no such container' in err:
        return False
    raise RuntimeError(f'Docker inspect failed for {name}: {proc.stderr.strip()}')


def delete(cfg, runner, dry_run):
    name = runner['name']
    if docker_exists(name):
        print(f'SKIP {name}: container exists', flush=True)
        return False
    if dry_run:
        print(f'DRY RUN: DELETE runner {name} id={runner["id"]}', flush=True)
        return True
    print(f'DELETE runner {name} id={runner["id"]}', flush=True)
    try:
        github(cfg, 'DELETE', f'{cfg.url}/{runner["id"]}')
    except RuntimeError:
        if any(r.get('id') == runner['id'] for r in runners(cfg)):
            raise
    if any(r.get('id') == runner['id'] for r in runners(cfg)):
        raise RuntimeError(f'Registration still exists: {name}')
    print(f'DELETED {name}', flush=True)
    return True


def audit(cfg):
    found = [r for r in runners(cfg) if cfg.valid_name(str(r.get('name', '')))]
    print(f'{cfg.repository}: {len(found)} name-matching registrations', flush=True)
    for r in found:
        name = r['name']
        exists = docker_exists(name)
        ok = owned(cfg, r) and r.get('status') == 'offline' and r.get('busy') is False and not exists
        print(f'{name} id={r.get("id")} status={r.get("status")} busy={r.get("busy")} '
              f'ephemeral={r.get("ephemeral")} labels={sorted(labels(r))} '
              f'container={exists} sweep_eligible={ok}', flush=True)


def sweep(cfg, dry_run):
    count = 0
    for r in runners(cfg):
        if not cfg.valid_name(str(r.get('name', ''))):
            continue
        if not owned(cfg, r):
            print(f'SKIP {r["name"]}: ownership label/prefix/ephemeral check failed', flush=True)
            continue
        if r.get('status') != 'offline' or r.get('busy') is not False:
            print(f'SKIP {r["name"]}: status={r.get("status")} busy={r.get("busy")}', flush=True)
            continue
        count += bool(delete(cfg, r, dry_run))
    print(f'Sweep: {count} {"eligible" if dry_run else "deleted"}', flush=True)


def stop_container(name):
    if not docker_exists(name):
        return
    print(f'Stopping Docker container {name}', flush=True)
    result = command(['docker', 'stop', '--time', '30', name], check=False, timeout=50)
    if result.returncode:
        print(f'WARNING: docker stop rc={result.returncode}: {result.stderr.strip()}', file=sys.stderr)
    if docker_exists(name):
        removed = command(['docker', 'rm', name], check=False)
        if removed.returncode and docker_exists(name):
            command(['docker', 'rm', '-f', name])
    if docker_exists(name):
        raise RuntimeError(f'Container remains after stop: {name}')


def current(cfg, dry_run, *, force=False):
    if not cfg.state.is_file():
        print('No current runner state; nothing to remove', flush=True)
        return
    name = cfg.state.read_text().strip()
    if not cfg.valid_name(name):
        raise RuntimeError(f'Invalid current runner name: {name!r}')
    if dry_run:
        print(f'DRY RUN: current {name}, container_exists={docker_exists(name)}', flush=True)
    elif force:
        print(f'FORCED SHUTDOWN {name}: may cancel an assigned/running job', flush=True)
        stop_container(name)
    elif docker_exists(name):
        raise RuntimeError(f'PENDING {name}: container exists; no stop attempted')
    found = [r for r in runners(cfg) if r.get('name') == name]
    for r in found:
        if not owned(cfg, r):
            raise RuntimeError(f'Refusing to delete registration not owned by instance: {name}')
        if r.get('status') != 'offline' or r.get('busy') is not False:
            print(f'DEFER {name}: busy={r.get("busy")}; state preserved', flush=True)
            raise RuntimeError('Registration is not confirmed offline and idle; retry later')
        if not delete(cfg, r, dry_run):
            raise RuntimeError('Container appeared; state preserved')
    if not dry_run:
        if docker_exists(name):
            raise RuntimeError('Container exists; state preserved')
        if any(r.get('name') == name for r in runners(cfg)):
            raise RuntimeError(f'GitHub registration still exists: {name}; state preserved')
        cfg.state.unlink(missing_ok=True)
        print(f'Registration absent; cleared state for {name}', flush=True)


@contextmanager
def instance_lock(cfg):
    # Config traversal has already established trusted parents. All host-side
    # cleanup/maintenance operations serialize; the launcher only reads the gate.
    path = CONFIG_BASE / cfg.instance / 'lifecycle.lock'
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError('Untrusted lifecycle lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def maintenance(cfg, operation):
    if operation == 'plan':
        # Exclusive create: an existing marker (even a damaged/symlink marker)
        # inhibits launch. Never overwrite or follow it.
        try:
            fd = os.open(cfg.maintenance, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, 'w') as stream:
                stream.write('Maintenance requested; replacements inhibited\n')
                stream.flush()
                os.fsync(stream.fileno())
            directory = os.open(cfg.maintenance.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        print('ARMED: no signals sent. A launch already in progress may still accept one job.', flush=True)
        return
    if not os.path.lexists(cfg.maintenance):
        raise RuntimeError('Maintenance is not armed; use --plan-maintenance first')
    # Never infer quiescence from GitHub busy=false. The launcher must have
    # exited. Administrators must serialize external systemctl start operations.
    for unit in (f'ephemeral-runner@{cfg.instance}.service',
                 f'ephemeral-runner-cleanup@{cfg.instance}.service',
                 f'ephemeral-runner-cleanup@{cfg.instance}.timer'):
        state = command(['systemctl', 'show', '--property=ActiveState', '--value', unit]).stdout.strip()
        if state not in ('inactive', 'failed'):
            raise RuntimeError(f'PENDING {unit}: {state}; wait, do not stop the runner')
    command(['docker', 'info', '--format', '{{.ServerVersion}}'])
    # Check *all* instance registrations/containers, including orphans. An API
    # outage or incomplete listing cannot produce READY.
    for runner in runners(cfg):
        if cfg.valid_name(str(runner.get('name', ''))):
            if (not owned(cfg, runner) or runner.get('status') != 'offline'
                    or runner.get('busy') is not False):
                raise RuntimeError('PENDING: registration not confirmed owned/offline/idle')
            if not delete(cfg, runner, False):
                raise RuntimeError('PENDING: registered container remains')
    # Unregistered orphan containers also prevent readiness (e.g. killed launcher).
    containers = command(['docker', 'ps', '-a', '--format', '{{.Names}}']).stdout.splitlines()
    if any(cfg.valid_name(name) for name in containers):
        raise RuntimeError('PENDING: instance container remains; no stop attempted')
    current(cfg, False)
    if operation == 'resume':
        cfg.maintenance.unlink()
        print('RESUMED: gate removed; services remain stopped', flush=True)
    else:
        print('READY: stopped, containers absent, registrations absent; gate retained', flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--instance', required=True)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--audit', action='store_true')
    group.add_argument('--sweep', action='store_true')
    group.add_argument('--current', action='store_true', help='Passive cleanup; never stops a container')
    group.add_argument('--service-stop', action='store_true', help='Systemd hook: passive while maintenance is armed, forced otherwise')
    group.add_argument('--force-current', action='store_true', help='Forced shutdown; may cancel a job')
    group.add_argument('--plan-maintenance', action='store_true', help='Inhibit replacements without signalling current runner')
    group.add_argument('--maintenance-status', action='store_true', help='Verify quiescence; nonzero means pending/unknown')
    group.add_argument('--resume', action='store_true', help='Remove gate after verified quiescence; does not start services')
    group.add_argument('--validate-config', action='store_true',
                       help='Validate config/auth without contacting Docker or GitHub')
    p.add_argument('--ack-maintenance-window', action='store_true',
                   help='Acknowledge routing must be paused externally; a current launch may accept a job')
    p.add_argument('--dry-run', action='store_true')
    args = p.parse_args()
    if args.plan_maintenance and not args.ack_maintenance_window:
        p.error('--plan-maintenance requires --ack-maintenance-window; pause workflow routing externally')
    if args.ack_maintenance_window and not args.plan_maintenance:
        p.error('--ack-maintenance-window requires --plan-maintenance')
    cfg = load_config(args.instance)
    if args.validate_config:
        return
    if args.dry_run and (args.plan_maintenance or args.maintenance_status or args.resume):
        p.error('--dry-run is only supported for audit/sweep/current/force-current')
    with instance_lock(cfg):
        if args.plan_maintenance or args.maintenance_status or args.resume:
            maintenance(cfg, 'plan' if args.plan_maintenance else 'resume' if args.resume else 'status')
            return
        command(['docker', 'info', '--format', '{{.ServerVersion}}'])
        if args.audit:
            audit(cfg)
        elif args.sweep:
            sweep(cfg, args.dry_run)
        else:
            current(cfg, args.dry_run, force=args.force_current or (args.service_stop and not os.path.lexists(cfg.maintenance)))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as exc:
        print(f'ERROR: {exc}', file=sys.stderr, flush=True)
        sys.exit(1)
