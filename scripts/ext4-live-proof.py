#!/usr/bin/env python3
"""Issue #17: dormant hosted-VM validation harness. No local/dispatched fallback."""
import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import time

REPO = 'Vladimare/ephemeral-runner'
BRANCH = 'codex/issue-15-ext4-workspace-poc'
MIB = 1024 * 1024
HEX = r'[0-9a-f]{40}'
IMAGE = r'sha256:[0-9a-f]{64}'
DOCKER_INFO = ('OSType', 'Architecture', 'KernelVersion', 'ServerVersion', 'Driver',
               'DriverStatus', 'CgroupVersion', 'CgroupDriver', 'MemoryLimit', 'SwapLimit',
               'CpuCfsQuota', 'CpuCfsPeriod', 'PidsLimit', 'NCPU', 'MemTotal')


class Skip(RuntimeError):
    pass


def redact(value):
    """Defense in depth; no credentials are passed to builders/probes in the first place."""
    if isinstance(value, dict):
        return {k: ('[REDACTED]' if re.search(r'(?i)token|password|secret|authorization', k) else redact(v))
                for k, v in value.items() if k not in ('Env', 'Args', 'Cmd', 'Entrypoint')}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        value = re.sub(r'(?i)((?:bearer|basic)\s+)[^\s"\\]+', r'\1[REDACTED]', value)
        value = re.sub(r'\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)', '[REDACTED]', value)
        return re.sub(r'(https?://)[^/\s@]+@', r'\1[REDACTED]@', value)
    return value


def docker_info(value):
    return {key: value[key] for key in DOCKER_INFO if key in value}


def sanitize_state(state):
    state = json.loads(json.dumps(state))
    evidence = state.get('evidence', {})
    if 'docker_info' in evidence:
        evidence['docker_info'] = docker_info(evidence['docker_info'])
    # Exclude image environment, payload argv, daemon names, proxy and registry data.
    if 'docker_inspect' in evidence:
        c = evidence['docker_inspect']
        evidence['docker_inspect'] = {k: c[k] for k in ('Id', 'Name', 'Image', 'HostConfig', 'Mounts', 'State') if k in c}
        evidence['docker_inspect']['Config'] = {k: c.get('Config', {}).get(k) for k in ('User', 'Labels')}
    return redact(state)


def guard(env, event, head, *, system=None, uid=None):
    system = platform.system() if system is None else system
    uid = os.geteuid() if uid is None else uid
    pr = event.get('pull_request', {})
    if (uid != 0 or system != 'Linux' or env.get('GITHUB_ACTIONS') != 'true'
            or env.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or env.get('RUNNER_OS') != 'Linux' or env.get('RUNNER_ARCH') != 'X64'
            or env.get('ImageOS') != 'ubuntu24'
            or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', env.get('ImageVersion', ''))
            or env.get('ImageVersion') == 'unknown' or env.get('GITHUB_REPOSITORY') != REPO
            or env.get('GITHUB_EVENT_NAME') != 'pull_request' or event.get('action') != 'labeled'
            or event.get('label', {}).get('name') != 'ext4-live-proof' or pr.get('number') != 16
            or pr.get('head', {}).get('repo', {}).get('full_name') != REPO
            or pr.get('head', {}).get('ref') != BRANCH or pr.get('base', {}).get('ref') != 'main'
            or not re.fullmatch(HEX, head) or pr.get('head', {}).get('sha') != head
            or env.get('PROOF_HEAD_SHA') != head
            or not re.fullmatch(HEX, env.get('GITHUB_WORKFLOW_SHA', ''))):
        raise RuntimeError('Refuse execution: require exact labeled same-repository PR #16 head on GitHub-hosted Ubuntu 24.04 VM')
    for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        if not re.fullmatch(r'[1-9][0-9]*', env.get(key, '')):
            raise RuntimeError('Invalid run identity')


def command(args, timeout=120):
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/nonexistent',
           'DOCKER_CONFIG': '/nonexistent', 'LC_ALL': 'C'}
    if args[:2] == ['docker', 'build']:
        # BuildKit cannot reliably resolve FROM by local image ID. Never use a tag fallback.
        env['DOCKER_BUILDKIT'] = '0'
    if args[0] == 'docker':
        args = ['docker', '--host', 'unix:///var/run/docker.sock', *args[1:]]
    p = subprocess.run(args, env=env, text=True, capture_output=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f'{args[0]} {args[1]} failed ({p.returncode}): {redact(p.stderr[-4096:])}')
    return p.stdout.strip()


def write_json(path, value):
    pending = path.with_suffix('.next')
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(pending, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        s = os.fstat(stream.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o077:
            raise RuntimeError('Unsafe evidence/journal file')
        return json.load(stream)


def prerequisites(base, run=command, record=None):
    record = {} if record is None else record
    versions = record.setdefault('tools', {})
    for tool, args in {'losetup': ['--version'], 'mkfs.ext4': ['-V'],
                       'mount': ['--version'], 'umount': ['--version'], 'findmnt': ['--version']}.items():
        if not shutil.which(tool):
            raise Skip('Missing prerequisite: ' + tool)
        # mkfs -V writes its version to stderr; capture a bounded version record.
        if tool == 'mkfs.ext4':
            p = subprocess.run([tool, *args], capture_output=True, text=True, timeout=10)
            if p.returncode:
                raise Skip('Cannot execute mkfs.ext4 -V')
            versions[tool] = (p.stdout + p.stderr).strip()[:512]
        else:
            versions[tool] = run([tool, *args]).splitlines()[0]
    controllers = Path('/sys/fs/cgroup/cgroup.controllers').read_text().split()
    record['cgroup_controllers'] = controllers
    if not {'cpu', 'memory', 'pids'} <= set(controllers):
        raise Skip('Required cgroup v2 controllers unavailable')
    info = json.loads(run(['docker', 'info', '--format', '{{json .}}']))
    record['docker_info'] = docker_info(info)
    if any('rootless' in x for x in info.get('SecurityOptions', [])) or info.get('OSType') != 'linux' or info.get('CgroupVersion') != '2' or not all(
            info.get(k) is True for k in ('MemoryLimit', 'SwapLimit', 'CpuCfsQuota', 'CpuCfsPeriod', 'PidsLimit')):
        raise Skip('Docker cannot enforce required Linux cgroup v2 bounds')
    version = json.loads(run(['docker', 'version', '--format', '{{json .}}']))
    record['docker_version'] = {side: {k: version.get(side, {}).get(k) for k in
                                 ('Version', 'ApiVersion', 'GoVersion', 'Os', 'Arch', 'KernelVersion')}
                               for side in ('Client', 'Server')}
    fs = run(['findmnt', '-n', '-o', 'FSTYPE,OPTIONS', '--target', str(base)])
    record['scratch_findmnt'] = fs
    if not fs.split() or fs.split()[0] != 'ext4':
        raise Skip('Scratch filesystem is not ext4: ' + fs)
    v = os.statvfs(base)
    record.update(free_bytes=v.f_bavail * v.f_frsize, free_inodes=v.f_favail)
    if v.f_bavail * v.f_frsize < 1024 * MIB or v.f_favail < 8192:
        raise Skip('Need 1 GiB disk and 8192 free inodes for independent bounded probes')
    mem = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    available = int(mem['MemAvailable'].split()[0]) * 1024
    record['available_ram_bytes'] = available
    if available < 2 * 1024 * MIB:
        raise Skip('Need 2 GiB available RAM/headroom for overlapping 256 MiB probes')
    cap = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if not int(cap['CapEff'].strip(), 16) & (1 << 21):
        raise Skip('CAP_SYS_ADMIN unavailable; mount operations unsupported')
    loop = run(['losetup', '--find'])
    if not re.fullmatch(r'/dev/loop[0-9]+', loop) or not stat.S_ISBLK(os.stat(loop).st_mode):
        raise Skip('No usable free loop block device')
    return record


def build_images(workspace, base, record, run=command, checkpoint=lambda: None):
    dockerfile = workspace / 'docker/Dockerfile'
    checksum = re.search(r'^ARG RUNNER_SHA256=([a-f0-9]{64})$', dockerfile.read_text(), re.M)
    if not checksum:
        raise RuntimeError('Missing project-pinned runner archive checksum')
    record['builder'] = 'classic local image-ID builder (DOCKER_BUILDKIT=0); no mutable-tag fallback'
    record['archive_sha256'] = checksum[1]
    record['fixture_dockerfile_sha256'] = hashlib.sha256((workspace / 'docker/Dockerfile.ext4-poc').read_bytes()).hexdigest()
    record['dockerfile_sha256'] = hashlib.sha256(dockerfile.read_bytes()).hexdigest()
    checkpoint()
    for label, filename in (('base', 'Dockerfile'), ('poc', 'Dockerfile.ext4-poc')):
        extra = []
        # Construct the fixture args after the base build has produced an ID.
        if label == 'poc':
            extra = ['--network=none', '--build-arg', 'BASE=' + record['base_id']]
        iidfile = base / (label + '.iid')
        run(['docker', 'build', '--pull=false', '--iidfile', str(iidfile), *extra,
             '-f', str(workspace / 'docker' / filename), str(workspace)], timeout=420)
        image_id = iidfile.read_text().strip()
        if not re.fullmatch(IMAGE, image_id):
            raise RuntimeError('Build did not yield immutable image ID')
        actual = json.loads(run(['docker', 'image', 'inspect', image_id]))[0]
        if actual.get('Id') != image_id or actual.get('Config', {}).get('Volumes'):
            raise RuntimeError('Built image identity/VOLUME mismatch')
        record[label + '_id'] = image_id
        checkpoint()
    record['fixture_dockerfile_sha256'] = hashlib.sha256((workspace / 'docker/Dockerfile.ext4-poc').read_bytes()).hexdigest()
    return record['poc_id']


def locate_attempt(base, attempt):
    candidate_paths = []
    try:
        text = (base / (attempt['key'] + '.stderr')).read_text()
    except OSError:
        text = ''
    for match in re.findall(r'^Recovery journal: (.+/journal.json)$', text, re.M):
        candidate_paths.append(Path(match))
    if not candidate_paths:
        candidate_paths = [
            path for path in sorted(base.glob('probe-*/journal.json'))
            if path.parent.parent == base and re.fullmatch(r'probe-[a-f0-9]{32}', path.parent.name)
        ]
    valid = []
    fallback = []
    seen = set()
    for journal in candidate_paths:
        if journal.parent.parent != base or not re.fullmatch(r'probe-[a-f0-9]{32}', journal.parent.name):
            continue
        key = str(journal)
        if key in seen:
            continue
        seen.add(key)
        try:
            info = journal.parent.lstat()
        except OSError:
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            continue
        try:
            state = private_json(journal)
        except (OSError, ValueError, TypeError, KeyError):
            continue
        if not isinstance(state, dict):
            continue
        nonce = state.get('nonce')
        if nonce is not None and not re.fullmatch(r'[a-f0-9]{32}', str(nonce)):
            continue
        directory_ok = state.get('directory') == str(journal.parent)
        nonce_ok = True if nonce is None else nonce == journal.parent.name.removeprefix('probe-')
        name = state.get('name')
        name_ok = True if name is None else name == 'er-ext4-' + (nonce or journal.parent.name.removeprefix('probe-'))
        identity = state.get('directory_identity')
        identity_ok = identity is None or identity == [info.st_dev, info.st_ino] or identity == (info.st_dev, info.st_ino)
        exact = directory_ok and nonce_ok and name_ok
        if exact and identity_ok:
            valid.append((journal, state, info))
        elif exact or (directory_ok and nonce_ok and name_ok):
            fallback.append((journal, state, info))
    candidates = valid or fallback
    if not candidates:
        raise RuntimeError('Missing or ambiguous exact recovery journal; retained state unresolved')
    _, state, _ = sorted(candidates, key=lambda item: item[2].st_mtime_ns, reverse=True)[0]
    return state


def observe(base, attempt, image, run=command):
    """Read only exact journal-owned resources; never perform helper cleanup."""
    state = locate_attempt(base, attempt)
    if state.get('image_id') != image:
        raise RuntimeError('Probe image changed')
    observation = {}
    if state.get('loop'):
        loop = state['loop']
        if not re.fullmatch(r'/dev/loop[0-9]+', loop) or os.stat(loop).st_rdev != state.get('loop_rdev'):
            raise RuntimeError('Loop identity changed')
        loops = json.loads(run(['losetup', '--json', '--list', '--output',
            'NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,OFFSET,SIZELIMIT', loop]))
        entries = loops['loopdevices']
        dev, ino = state['backing_identity']
        if (len(entries) != 1 or entries[0].get('name') != loop
                or entries[0].get('back-file') != str(Path(state['directory']) / 'disk.img')
                or int(entries[0].get('back-ino', -1)) != ino
                or entries[0].get('back-maj:min') != f'{os.major(dev)}:{os.minor(dev)}'
                or int(entries[0].get('offset', -1)) != 0 or int(entries[0].get('sizelimit', -1)) != 64 * MIB):
            raise RuntimeError('Observed loop ownership or size mismatch')
        observation['loop'] = loops
    if state.get('create_attempted') or state.get('container_id'):
        observation['query_started'] = time.time()
        c = json.loads(run(['docker', 'inspect', '--type', 'container', state['name']]))[0]
        if (c.get('Name') != '/' + state['name'] or c.get('Image') != image
                or c.get('Config', {}).get('Labels', {}).get('io.ephemeral-runner.ext4-poc') != state['nonce']
                or not re.fullmatch(r'[a-f0-9]{64}', c.get('Id', ''))
                or (state.get('container_id') and c['Id'] != state['container_id'])):
            raise RuntimeError('Observed container ownership mismatch')
        observation['container'] = {k: c.get(k) for k in ('Id', 'Name', 'Image', 'State', 'RestartCount')}
    return observation


def observed_overlap(samples):
    """Avoid claiming overlap from two sequential Running snapshots alone."""
    try:
        active = [s for s in samples if s.get('container', {}).get('State', {}).get('Running') is True
                  and s['container'].get('RestartCount') == 0]
        if len(active) < 2:
            return False
        starts = [datetime.fromisoformat(s['container']['State']['StartedAt'].replace('Z', '+00:00')).timestamp()
                  for s in active]
        return max(starts) <= min(s['query_started'] for s in active)
    except (KeyError, ValueError, TypeError):
        return False


def validate_result(state, image, poc):
    evidence = state['evidence']
    observed = evidence['probe']
    c = evidence['docker_inspect']
    if (state.get('pending') is not None or state.get('failure') or state.get('cleanup_failure')
            or state['tests'].get('linux_enforcement') != 'PASS' or state['tests'].get('cleanup') != 'PASS'
            or state.get('container_id') is not None or state.get('loop') is not None or state.get('mount_id') is not None
            or state.get('image_id') != image or c.get('Image') != image
            or c.get('Name') != '/' + state['name']
            or c.get('Config', {}).get('Labels', {}).get(poc.LABEL) != state['nonce']
            or not re.fullmatch(r'[a-f0-9]{64}', c.get('Id', ''))):
        raise RuntimeError('Experiment/cleanup/identity gates did not pass')
    poc.validate_container(c, Path(state['directory']) / 'mnt')
    if (observed.get('bytes') != 'ENOSPC' or observed.get('inodes', {}).get('result') != 'ENOSPC'
            or not 0 <= observed['inodes']['created'] < 2050
            or not 0 < observed['statfs']['bytes'] <= 64 * MIB
            or not 0 < observed['statfs']['inodes'] <= 2048
            or evidence['backing']['size'] != 64 * MIB or evidence['backing']['allocated'] < 64 * MIB
            or any(observed.get(k) != value for k, value in {'memory.max': '268435456',
                       'memory.swap.max': '0', 'cpu.max': '25000 100000', 'pids.max': '64'}.items())
            or not evidence.get('host_mountinfo') or not observed.get('mountinfo')):
        raise RuntimeError('Missing actual ENOSPC/cgroup/storage/mount evidence')
    return 'PASS'


def verify_cleanup(state, attempt, proof, run=command):
    """Independent read-only host queries; errors never establish absence."""
    proof.update(status='UNRESOLVED', checked_at=time.time())
    directory = Path(state['directory'])
    backing = directory / 'disk.img'
    owned_id = state['evidence']['docker_inspect']['Id']
    if not re.fullmatch(r'[a-f0-9]{64}', owned_id):
        raise RuntimeError('Missing exact container identity for cleanup proof')
    containers = [json.loads(line) for line in run(
        ['docker', 'ps', '--all', '--no-trunc', '--format', '{{json .}}']).splitlines() if line]
    if any(not isinstance(c.get('ID'), str) or not re.fullmatch(r'[a-f0-9]{64}', c['ID'])
           or not isinstance(c.get('Names'), str) for c in containers):
        raise RuntimeError('Malformed Docker absence listing')
    matches = [c for c in containers if c['ID'] == owned_id
               or state['name'] in c['Names'].split(',')]
    proof['container'] = dict(id=owned_id, name=state['name'], matches=matches)
    loops = json.loads(run(['losetup', '--json', '--list', '--output',
                           'NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,OFFSET,SIZELIMIT']))['loopdevices']
    dev, ino = state['backing_identity']
    device = f'{os.major(dev)}:{os.minor(dev)}'
    observed_names = {entry['name'] for sample in attempt['observations']
                      for entry in sample.get('loop', {}).get('loopdevices', [])}
    if not observed_names:
        raise RuntimeError('Missing observed loop identity for cleanup proof')
    loop_matches = [entry for entry in loops if entry['name'] in observed_names
                    or entry.get('back-file') == str(backing)
                    or (int(entry.get('back-ino', -1)) == ino and entry.get('back-maj:min') == device)]
    proof['loops'] = dict(observed_names=sorted(observed_names), matches=loop_matches)
    loop_dev = state['loop_rdev']
    mount_device = f'{os.major(loop_dev)}:{os.minor(loop_dev)}'
    mount_matches = []
    mountinfo = Path('/proc/self/mountinfo').read_text()
    if not mountinfo.strip():
        raise RuntimeError('Empty mount table cannot establish cleanup')
    for line in mountinfo.splitlines():
        left, right = line.split(' - ', 1)
        fields = left.split()
        if fields[4] == str(directory / 'mnt') or fields[2] == mount_device:
            mount_matches.append(line)
    proof['mounts'] = dict(target=str(directory / 'mnt'), device=mount_device, matches=mount_matches)
    try:
        st = backing.lstat()  # includes dangling symlinks; permission errors remain unresolved
        proof['backing'] = dict(path=str(backing), absent=False, device=st.st_dev, inode=st.st_ino)
    except FileNotFoundError:
        # The retained probe directory must still exist; a missing parent is ambiguous.
        directory.lstat()
        proof['backing'] = dict(path=str(backing), absent=True)
    if matches or loop_matches or mount_matches or not proof['backing']['absent']:
        proof['status'] = 'FAIL'
        raise RuntimeError('Independent cleanup check found lingering or reused resources; retain evidence')
    proof['status'] = 'PASS'


def probe_group(base, workspace, image, keys, report, poc):
    active = []
    for key in keys:
        attempt = dict(key=key, status='NOT RUN', started=time.time(), observations=[])
        report['attempts'].append(attempt)
        stdout = open(base / (key + '.stdout'), 'x')
        stderr = open(base / (key + '.stderr'), 'x')
        process = subprocess.Popen(['/usr/bin/python3', str(workspace / 'scripts/ext4-workspace-poc.py'),
            '--disposable-host', '--parent', str(base), '--image', image], stdout=stdout, stderr=stderr,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/nonexistent', 'LC_ALL': 'C'})
        stdout.close(); stderr.close()
        active.append((process, attempt))
    deadline = time.monotonic() + 120
    while any(process.poll() is None for process, _ in active):
        if time.monotonic() > deadline:
            raise RuntimeError('Probe observation deadline exceeded; no forced teardown; retain VM evidence')
        batch = []
        for process, attempt in active:
            if process.poll() is None:
                try:
                    sample = observe(base, attempt, image)
                    if sample:
                        attempt['observations'].append(sample)
                    batch.append(sample)
                except (OSError, ValueError, RuntimeError, KeyError, TypeError, IndexError, subprocess.SubprocessError) as error:
                    # Setup/create/cleanup races can transiently hide a resource.
                    attempt['last_observation_error'] = redact(str(error))
        if observed_overlap(batch):
            report['container_overlap'] = 'PASS'
        write_json(base / 'harness.json', report)
        time.sleep(0.5)
    failures = []
    for process, attempt in active:
        attempt.update(returncode=process.wait(), finished=time.time())
        try:
            state = locate_attempt(base, attempt)
            if attempt['returncode'] != 0:
                raise RuntimeError('Actual PoC exited nonzero; retain journal')
            attempt['status'] = validate_result(state, image, poc)
            verify_cleanup(state, attempt, attempt.setdefault('cleanup_proof', {}))
            if not any(sample.get('loop') for sample in attempt['observations']):
                raise RuntimeError('No exact live loop observation retained; evidence incomplete')
        except (OSError, ValueError, RuntimeError, KeyError, TypeError, IndexError, subprocess.SubprocessError) as error:
            attempt.update(status='FAIL', reason=redact(str(error)))
            failures.append(attempt['key'])
    write_json(base / 'harness.json', report)
    if failures:
        raise RuntimeError('Probe gates failed: ' + ', '.join(failures))


def failure_probe(base, workspace, report):
    before = set(p.name for p in base.iterdir())
    result = subprocess.run(['/usr/bin/python3', str(workspace / 'scripts/ext4-workspace-poc.py'),
        '--disposable-host', '--parent', str(base), '--image', 'deliberately-invalid-image'],
        text=True, capture_output=True, timeout=30,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/nonexistent', 'LC_ALL': 'C'})
    after = set(p.name for p in base.iterdir())
    if result.returncode == 0 or 'Require trusted local immutable sha256 image ID' not in result.stderr or after != before:
        raise RuntimeError('Non-destructive rejection path failed or created unexpected files')
    report['invalid_image_rejected_before_setup'] = dict(status='PASS', returncode=result.returncode,
                                                       stderr=redact(result.stderr))


def collect(base):
    report = private_json(base / 'harness.json')
    for attempt in report.get('attempts', []):
        if attempt.get('key') not in ('serial', 'parallel-a', 'parallel-b'):
            raise RuntimeError('Unknown evidence attempt')
        try:
            attempt['journal'] = sanitize_state(locate_attempt(base, attempt))
        except (OSError, ValueError, RuntimeError, KeyError, TypeError, IndexError) as error:
            attempt['journal'] = {'status': 'UNRESOLVED', 'reason': redact(str(error))}
        # Only exact known outputs; never upload raw disks, Docker config or workspace.
        try:
            attempt['stdout'] = sanitize_state(json.loads((base / (attempt['key'] + '.stdout')).read_text()))
        except (OSError, ValueError, TypeError) as error:
            attempt['stdout'] = {'status': 'UNRESOLVED', 'reason': redact(str(error))}
        try:
            attempt['stderr'] = redact((base / (attempt['key'] + '.stderr')).read_text()[-16384:])
        except OSError as error:
            attempt['stderr'] = 'UNRESOLVED: ' + redact(str(error))
    return redact(report)


def context(env):
    # Cheap guard before reading event files, invoking git/Docker or creating paths.
    if (os.geteuid() != 0 or platform.system() != 'Linux' or env.get('GITHUB_ACTIONS') != 'true'
            or env.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise RuntimeError('Hosted-VM opt-in only; no setup attempted')
    event = json.loads(Path(env['GITHUB_EVENT_PATH']).read_text())
    head = env.get('PROOF_HEAD_SHA', '')
    guard(env, event, head)
    workspace = Path(env['GITHUB_WORKSPACE'])
    actual = command(['git', '-c', 'safe.directory=' + str(workspace), '-C', str(workspace), 'rev-parse', 'HEAD'])
    if actual != head:
        raise RuntimeError('Checked-out commit differs from exact label-event head')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if release.get('ID', '').strip('"') != 'ubuntu' or release.get('VERSION_ID', '').strip('"') != '24.04':
        raise Skip('Require actual Ubuntu 24.04 OS release')
    spec = importlib.util.spec_from_file_location('ext4_actual_poc', workspace / 'scripts/ext4-workspace-poc.py')
    poc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(poc)
    base = Path('/var/lib') / ('ephemeral-ext4-live-' + env['GITHUB_RUN_ID'] + '-' + env['GITHUB_RUN_ATTEMPT'])
    return workspace, base, poc


def execute(env, workspace, base, poc):
    for parent in reversed(base.parents):
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise RuntimeError('Unsafe scratch ancestor')
    base.mkdir(mode=0o700)  # exclusive: never adopt or overwrite an old run
    poc.private_directory(base)
    report = dict(schema=1, status='NOT RUN', head=env['PROOF_HEAD_SHA'],
                  workflow_sha=env.get('GITHUB_WORKFLOW_SHA'), run_attempt=int(env['GITHUB_RUN_ATTEMPT']), attempts=[], images={},
                  run_url='https://github.com/' + REPO + '/actions/runs/' + env['GITHUB_RUN_ID'],
                  provenance=dict(kernel=platform.release(), architecture=platform.machine(),
                                  ImageOS=env['ImageOS'], ImageVersion=env.get('ImageVersion')),
                  container_overlap='NOT RUN', independent_live_review='NOT RUN', sigterm='NOT RUN',
                  production_decision='NO-GO; isolated component evidence only', invalid_image_rejected_before_setup={'status': 'NOT RUN'},
                  sigkill_daemon_outage_busy_mount_reboot='NOT RUN', registration='NOT RUN',
                  real_job='NOT RUN', production_integration='NOT RUN')
    write_json(base / 'harness.json', report)
    try:
        try:
            prerequisites(base, record=report['provenance'])
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
            raise Skip('Prerequisite NO-GO: ' + str(error)) from error
        write_json(base / 'harness.json', report)
        image = build_images(workspace, base, report['images'],
                             checkpoint=lambda: write_json(base / 'harness.json', report))
        write_json(base / 'harness.json', report)
        probe_group(base, workspace, image, ['serial'], report, poc)
        probe_group(base, workspace, image, ['parallel-a', 'parallel-b'], report, poc)
        failure_probe(base, workspace, report)
        if report['container_overlap'] != 'PASS':
            raise RuntimeError('Required container overlap was not observed; component proof incomplete/NO-GO')
        report['status'] = 'PASS'
        report['scope'] = 'Component filesystem/limits/cleanup only; independent review still required'
    except Skip as error:
        report.update(status='SKIP', decision='NO-GO on this VM', reason=redact(str(error)))
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError) as error:
        report.update(status='FAIL', reason=redact(str(error)))
    finally:
        write_json(base / 'harness.json', report)
    print(json.dumps(redact(report), indent=2))
    return 0 if report['status'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--run', action='store_true')
    group.add_argument('--collect', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        workspace, base, poc = context(os.environ)
        if args.collect:
            poc.private_directory(base)
            print(json.dumps(collect(base), indent=2))
            return 0
        return execute(os.environ, workspace, base, poc)
    except Skip as error:
        print(json.dumps(dict(status='SKIP', decision='NO-GO on this VM', reason=redact(str(error)), live_evidence='NOT RUN')))
        return 1
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError) as error:
        # Always emit an artifact-compatible failure, including pre-checkout/guard failures.
        print(json.dumps(dict(status='FAIL', reason=redact(str(error)), live_evidence='NOT RUN')))
        return 1


if __name__ == '__main__':
    sys.exit(main())
