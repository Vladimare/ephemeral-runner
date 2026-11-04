#!/usr/bin/env python3
"""Disposable Linux ONLY: offline bounded-disk experiment, never a runner backend."""
import argparse
import errno
import fcntl
import inspect
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys

MIB = 1024 * 1024
SIZE = 64 * MIB
LABEL = 'io.ephemeral-runner.ext4-poc'
SOCKET = 'unix:///var/run/docker.sock'
TMPFS = '/tmp:rw,nosuid,nodev,noexec,size=8m,nr_inodes=1024,mode=1777'
PSEUDO_FILESYSTEMS = {'proc', 'sysfs', 'cgroup2', 'devpts', 'mqueue'}
APPROVED_RW_MOUNTS = {'/work', '/tmp', '/dev', '/dev/shm'}
DOCKER_MANAGED_FILES = {'/etc/hosts', '/etc/hostname', '/etc/resolv.conf'}


def command(args):
    # Ignore remote Docker contexts and caller CLI configuration/plugins.
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/nonexistent',
           'DOCKER_CONFIG': '/nonexistent', 'LC_ALL': 'C'}
    if args[0] == 'docker':
        args = ['docker', '--host', SOCKET, *args[1:]]
    result = subprocess.run(args, env=env, check=True, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    return result.stdout.strip()


def identity(path):
    s = os.lstat(path)
    if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_nlink != 1:
        raise RuntimeError('Backing must be a root-owned single-link regular file')
    return [s.st_dev, s.st_ino]


def private_directory(path):
    """Every ancestor must be root owned, non-symlink and not group/world writable."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or path == Path('/'):
        raise RuntimeError('Require an absolute private directory')
    for p in [*reversed(path.parents), path]:
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise RuntimeError('Unsafe parent: ' + str(p))
    if path.stat().st_mode & 0o077:
        raise RuntimeError('Scratch parent must be mode 0700')
    return path


def gate(disposable, platform=sys.platform, uid=None):
    if not disposable or platform != 'linux' or (os.geteuid() if uid is None else uid) != 0:
        raise RuntimeError('Require --disposable-host and root on disposable Linux; no setup attempted')


def safe_lock(path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    s = os.fstat(fd)
    if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_nlink != 1 or s.st_mode & 0o077:
        os.close(fd)
        raise RuntimeError('Unsafe lock file')
    return fd

def acquire_lock(path, nonblocking=False):
    fd = safe_lock(path)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
    except BaseException:
        os.close(fd)
        raise
    return fd


def abort_signal(signum, frame):
    raise RuntimeError('Signal '+str(signum))


def capacity(vfs):
    if vfs.f_bavail * vfs.f_frsize < SIZE + 512 * MIB or vfs.f_favail < 4096:
        raise RuntimeError('Insufficient disk/inode headroom (64 MiB + 512 MiB reserve)')


def mount_record(text, target):
    matches = []
    for line in text.splitlines():
        left, right = line.split(' - ', 1)
        fields = left.split()
        # Our generated paths contain no mountinfo escapes.
        if fields[4] == str(target):
            matches.append({'id': fields[0], 'dev': fields[2], 'root': fields[3],
                            'options': fields[5], 'fs': right.split()[0],
                            'source': right.split()[1], 'line': line})
    if len(matches) > 1:
        raise RuntimeError('Stacked mounts: retain evidence')
    return matches[0] if matches else None


def enforce_mount_policy(mounts, nonroot_writable):
    """Reject unbounded writable mounts and Docker-managed files writable by job UID."""
    for path, (opts, fs) in mounts.items():
        if 'rw' not in opts or fs in PSEUDO_FILESYSTEMS:
            continue
        if path in APPROVED_RW_MOUNTS:
            continue
        if path in DOCKER_MANAGED_FILES:
            if nonroot_writable(path):
                raise RuntimeError('Docker-managed file writable by non-root UID: ' + path)
            continue
        raise RuntimeError('Unapproved writable mount: ' + path + ' (' + fs + ')')


def payload_mount_policy_source():
    def set_literal(items):
        return '{' + ', '.join(repr(x) for x in sorted(items)) + '}'
    return '\n'.join([
        f'PSEUDO_FILESYSTEMS = {set_literal(PSEUDO_FILESYSTEMS)}',
        f'APPROVED_RW_MOUNTS = {set_literal(APPROVED_RW_MOUNTS)}',
        f'DOCKER_MANAGED_FILES = {set_literal(DOCKER_MANAGED_FILES)}',
        inspect.getsource(enforce_mount_policy).strip(),
    ])


class Experiment:
    def __init__(self, directory, run=command):
        self.directory = Path(directory)
        self.run = run
        self.journal = self.directory / 'journal.json'
        self.image = self.directory / 'disk.img'
        self.mount = self.directory / 'mnt'
        self.state = {}

    def save(self):
        tmp = self.directory / 'journal.next'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(self.state, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.journal)
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def intent(self, operation):
        self.state['pending'] = operation
        self.save()

    def done(self):
        self.state['pending'] = None
        self.save()

    def load(self):
        private_directory(self.directory)
        fd = os.open(self.journal, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as f:
            s = os.fstat(f.fileno())
            if s.st_uid != 0 or s.st_mode & 0o077 or not stat.S_ISREG(s.st_mode):
                raise RuntimeError('Unsafe journal')
            self.state = json.load(f)
        if self.state.get('directory') != str(self.directory) or self.state.get('schema') != 1:
            raise RuntimeError('Journal path/schema mismatch')
        s = self.directory.stat()
        if self.state['directory_identity'] != [s.st_dev, s.st_ino]:
            raise RuntimeError('Directory identity changed')

    def loops(self):
        return json.loads(self.run(['losetup', '--json', '--list', '--output',
                                   'NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,OFFSET,SIZELIMIT']))['loopdevices']

    def verify_backing(self):
        if identity(self.image) != self.state['backing_identity']:
            raise RuntimeError('Backing identity changed')
        s = self.image.stat()
        if s.st_size != SIZE or s.st_blocks * 512 < SIZE or s.st_mode & 0o077:
            raise RuntimeError('Backing size/allocation/mode changed')

    def verify_loop(self):
        self.verify_backing()
        entries = [x for x in self.loops() if x['name'] == self.state['loop']]
        if len(entries) != 1:
            raise RuntimeError('Loop absent or ambiguous')
        x = entries[0]
        dev, ino = self.state['backing_identity']
        if (x.get('back-file') != str(self.image) or int(x.get('back-ino', -1)) != ino
                or x.get('back-maj:min') != f'{os.major(dev)}:{os.minor(dev)}'
                or int(x.get('offset', -1)) != 0 or int(x.get('sizelimit', -1)) != SIZE):
            raise RuntimeError('Loop backing changed; refuse detach/unmount')
        s = os.stat(x['name'])
        if not stat.S_ISBLK(s.st_mode) or s.st_rdev != self.state['loop_rdev']:
            raise RuntimeError('Loop device identity changed')

    def mounts(self):
        return Path('/proc/self/mountinfo').read_text()

    def verify_mount(self):
        self.verify_loop()
        m = mount_record(self.mounts(), self.mount)
        rdev = self.state['loop_rdev']
        if (not m or m['id'] != self.state['mount_id'] or m['root'] != '/'
                or m['dev'] != f'{os.major(rdev)}:{os.minor(rdev)}' or m['fs'] != 'ext4'
                or not {'rw', 'nosuid', 'nodev'} <= set(m['options'].split(','))):
            raise RuntimeError('Mount identity/options changed')
        return m

    def container(self):
        s = self.state
        records = json.loads(self.run(['docker', 'inspect', '--type', 'container', s['name']]))
        if len(records) != 1:
            raise RuntimeError('Ambiguous container')
        c = records[0]
        if (not re.fullmatch('[0-9a-f]{64}', c.get('Id', '')) or c.get('Name') != '/' + s['name']
                or c.get('Image') != s['image_id'] or c.get('Config', {}).get('Labels', {}).get(LABEL) != s['nonce']
                or (s.get('container_id') and c['Id'] != s['container_id'])):
            raise RuntimeError('Container identity mismatch; retain evidence')
        return c

    def setup(self):
        self.intent('allocate')
        fd = os.open(self.image, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            # Record ownership before allocation so an allocation failure is recoverable.
            self.state['backing_identity'] = identity(self.image)
            self.save()
            os.posix_fallocate(fd, 0, SIZE)
            os.fsync(fd)
        finally:
            os.close(fd)
        self.done()
        self.verify_backing()
        self.intent('format')
        self.run(['mkfs.ext4', '-q', '-F', '-m', '0', '-N', '1024', '-E',
                  'lazy_itable_init=0,lazy_journal_init=0', str(self.image)])
        self.done()
        self.intent('attach')
        loop = self.run(['losetup', '--find', '--show', '--nooverlap', '--sizelimit', str(SIZE), str(self.image)])
        if not re.fullmatch(r'/dev/loop[0-9]+', loop):
            raise RuntimeError('Unexpected loop reply')
        self.state.update(loop=loop, loop_rdev=os.stat(loop).st_rdev)
        self.done()
        self.verify_loop()
        self.mount.mkdir(mode=0o700)
        self.intent('mount')
        self.run(['mount', '-t', 'ext4', '-o', 'rw,nosuid,nodev', loop, str(self.mount)])
        m = mount_record(self.mounts(), self.mount)
        if not m:
            raise RuntimeError('Mount not observed')
        self.state['mount_id'] = m['id']
        self.done()
        self.verify_mount()
        os.chown(self.mount, 10001, 10001)
        v = os.statvfs(self.mount)
        self.state['evidence']['statfs'] = dict(bytes=v.f_blocks * v.f_frsize,
                                                available=v.f_bavail * v.f_frsize, inodes=v.f_files)
        if not 0 < v.f_blocks * v.f_frsize <= SIZE or not 0 < v.f_files <= 2048:
            raise RuntimeError('Unexpected filesystem bounds')
        self.save()

    def launch(self):
        s = self.state
        self.verify_mount()
        s['evidence']['host_mountinfo'] = self.verify_mount()['line']
        self.intent('create')
        reply = self.run(['docker', 'create', '--name', s['name'], '--label', LABEL + '=' + s['nonce'],
                         *docker_flags(self.mount), '--entrypoint', 'python3', s['image_id'], '-c', PAYLOAD])
        if not re.fullmatch('[0-9a-f]{64}', reply):
            raise RuntimeError('Unknown create response')
        s['container_id'] = reply
        self.done()
        c = self.container()
        validate_container(c, self.mount)
        s['evidence']['docker_inspect'] = c
        self.save()
        self.run(['docker', 'start', reply])
        if self.run(['docker', 'wait', reply]) != '0':
            raise RuntimeError('Probe failed: ' + self.run(['docker', 'logs', reply]))
        s['evidence']['probe'] = json.loads(self.run(['docker', 'logs', reply]))
        observed = s['evidence']['probe']
        if observed.get('bytes') != 'ENOSPC' or observed.get('inodes', {}).get('result') != 'ENOSPC':
            raise RuntimeError('Missing observed byte/inode enforcement evidence')
        self.verify_backing()
        s['evidence']['backing'] = dict(identity=identity(self.image), size=self.image.stat().st_size,
                                         allocated=self.image.stat().st_blocks * 512)
        s['tests']['linux_enforcement'] = 'PASS'
        self.save()

    def cleanup(self):
        """No recursive removal. Any unknown/partial ownership retains evidence."""
        s = self.state
        pending = s.get('pending')
        if s.get('create_attempted') or pending == 'create' or s.get('container_id'):
            # Even timeout-after-success is resolved by exact nonce + immutable image + full ID.
            c = self.container()
            s['container_id'] = c['Id']
            self.intent('remove_container')
            self.run(['docker', 'rm', '-f', c['Id']])
            s['container_id'] = None
            s['create_attempted'] = False
            self.done()
        if pending in ('attach', 'mount', 'remove_container', 'unmount', 'detach', 'unlink'):
            raise RuntimeError('Interrupted operation requires manual identity reconciliation: ' + pending)
        if s.get('mount_id'):
            self.verify_mount()
            self.intent('unmount')
            self.run(['umount', str(self.mount)])
            if mount_record(self.mounts(), self.mount):
                raise RuntimeError('Mount still present')
            s['mount_id'] = None
            self.done()
        if s.get('loop'):
            self.verify_loop()
            # Reject any reference, including a mount outside the expected mountpoint.
            dev = f"{os.major(s['loop_rdev'])}:{os.minor(s['loop_rdev'])}"
            if any(line.split()[2] == dev for line in self.mounts().splitlines()):
                raise RuntimeError('Loop remains mounted; retain evidence')
            self.intent('detach')
            self.run(['losetup', '--detach', s['loop']])
            if any(x['name'] == s['loop'] for x in self.loops()):
                raise RuntimeError('Loop detach not completed')
            s['loop'] = None
            self.done()
        if self.image.exists() or self.image.is_symlink():
            if identity(self.image) != s.get('backing_identity'):
                raise RuntimeError('Unknown backing file; refuse unlink')
            dev, ino = s['backing_identity']
            if any(x.get('back-file') == str(self.image) or
                   (int(x.get('back-ino', -1)) == ino and x.get('back-maj:min') == f'{os.major(dev)}:{os.minor(dev)}')
                   for x in self.loops()):
                raise RuntimeError('Backing still attached; refuse unlink')
            if mount_record(self.mounts(), self.mount):
                raise RuntimeError('Unknown mount; refuse unlink')
            self.intent('unlink')
            self.image.unlink()
            self.done()
        s['tests']['cleanup'] = 'PASS'
        self.save()


def docker_flags(mount):
    return ['--pull', 'never', '--read-only', '--network', 'none', '--cgroupns', 'private',
            '--user', '10001:10001', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
            '--no-healthcheck', '--memory', str(256 * MIB), '--memory-swap', str(256 * MIB),
            '--cpu-period', '100000', '--cpu-quota', '25000', '--pids-limit', '64',
            '--log-driver', 'json-file', '--log-opt', 'max-size=1m', '--log-opt', 'max-file=2',
            '--tmpfs', TMPFS, '--shm-size', str(8 * MIB), '--env', 'HOME=/work/home',
            '--workdir', '/work', '--mount', f'type=bind,src={mount},dst=/work,bind-propagation=rprivate']


def validate_container(c, mount):
    h, config = c['HostConfig'], c['Config']
    expected = dict(ReadonlyRootfs=True, NetworkMode='none', CgroupnsMode='private', Privileged=False,
                    Memory=256 * MIB, MemorySwap=256 * MIB, CpuPeriod=100000, CpuQuota=25000,
                    PidsLimit=64, ShmSize=8 * MIB, CapDrop=['ALL'], CapAdd=None,
                    SecurityOpt=['no-new-privileges:true'], Tmpfs={'/tmp': TMPFS.split(':', 1)[1]},
                    LogConfig={'Type': 'json-file', 'Config': {'max-size': '1m', 'max-file': '2'}})
    if any(h.get(k) != v for k, v in expected.items()):
        raise RuntimeError('Ignored isolation flags')
    if (config.get('User') != '10001:10001' or config.get('Volumes') or h.get('Binds')
            or any(h.get(k) for k in ('Devices', 'DeviceRequests', 'VolumesFrom', 'DeviceCgroupRules'))
            or h.get('PidMode') or h.get('IpcMode') not in ('private', '') or h.get('UTSMode')):
        raise RuntimeError('Unexpected privilege/device/volume/namespace')
    mounts = c.get('Mounts', [])
    binds = [m for m in mounts if m.get('Type') != 'tmpfs']
    if (len(binds) != 1 or binds[0].get('Type') != 'bind' or binds[0].get('Source') != str(mount)
            or binds[0].get('Destination') != '/work' or binds[0].get('RW') is not True
            or binds[0].get('Propagation') != 'rprivate'
            or any(m.get('Destination') not in ('/tmp', '/dev/shm') for m in mounts if m.get('Type') == 'tmpfs')):
        raise RuntimeError('Unexpected actual writable mount map')


PAYLOAD = r'''
import errno, json, os, shutil
from pathlib import Path
report = {}
assert os.getuid() == 10001
for name, expected in [('memory.max','268435456'), ('memory.swap.max','0'),
                       ('cpu.max','25000 100000'), ('pids.max','64')]:
    value = Path('/sys/fs/cgroup', name).read_text().strip()
    assert value == expected, (name, value)
    report[name] = value
report['mountinfo'] = Path('/proc/self/mountinfo').read_text()
mounts = {}
for line in report['mountinfo'].splitlines():
    left, right = line.split(' - ', 1)
    f = left.split(); mounts[f[4]] = (set(f[5].split(',')), right.split()[0])
assert 'ro' in mounts['/'][0]
assert mounts['/work'][1] == 'ext4' and {'rw','nosuid','nodev'} <= mounts['/work'][0]
for p in ['/tmp', '/dev/shm']:
    assert mounts[p][1] == 'tmpfs'
    Path(p, 'probe').write_text('bounded'); Path(p, 'probe').unlink()
# Docker creates /dev (64 MiB) and masks /proc subtrees; inspect all ordinary
# writable filesystem mounts, while kernel pseudo-filesystems are recorded.
__MOUNT_POLICY_SOURCE__
enforce_mount_policy(mounts, lambda path: os.access(path, os.W_OK))
for p in ['/', '/etc', '/var/tmp', '/home', '/opt/actions-runner']:
    try: Path(p, 'forbidden-probe').write_text('x')
    except OSError as e: assert e.errno in (errno.EROFS, errno.EACCES)
    else: raise AssertionError('write escaped bounds: '+p)
assert not Path('/var/run/docker.sock').exists()
source = Path('/opt/actions-runner')
for name in ['config.sh', 'run.sh', 'bin/Runner.Listener']:
    assert (source/name).is_file() and os.access(source/name, os.R_OK | os.X_OK)
# Do not invoke config.sh/run.sh/Listener or register anything. Copy genuine
# scripts/binaries into bounded disk; the immutable distribution stays visible.
target = Path('/work/runner')
target.mkdir()
for name in ['config.sh','run.sh']:
    shutil.copy2(source/name, target/name)
assert (source/'bin/Runner.Listener').is_file()
for path in ['runner/_diag','runner/_work','home/.cache']:
    Path('/work',path).mkdir(parents=True, exist_ok=True)
    Path('/work',path,'probe').write_text('offline only')
for name in ['.env','.path','.runner']:
    (target/name).write_text('credential-free fixture')
report['layout'] = 'script copy + binary access + mutable path smoke ONLY; runner execution NOT RUN'
shutil.rmtree(target); shutil.rmtree('/work/home')
v=os.statvfs('/work'); report['statfs']={'bytes':v.f_blocks*v.f_frsize,'inodes':v.f_files}
assert 0 < v.f_blocks*v.f_frsize <= 67108864 and 0 < v.f_files <= 2048
# Hard attempt ceilings even when enforcement is defective. This cannot fill
# the host: the container sees only the 64 MiB loop block device.
try:
    with open('/work/bytes','wb',buffering=0) as f:
        for _ in range(66):
            f.write(b'x'*1048576)
        os.fsync(f.fileno())
except OSError as e:
    assert e.errno == errno.ENOSPC; report['bytes']='ENOSPC'
else: raise AssertionError('byte exhaustion not observed')
finally: Path('/work/bytes').unlink(missing_ok=True)
count=0
try:
    for i in range(2050):
        Path('/work','inode-'+str(i)).touch(); count+=1
except OSError as e:
    assert e.errno == errno.ENOSPC; report['inodes']={'result':'ENOSPC','created':count}
else: raise AssertionError('inode exhaustion not observed')
finally:
    for i in range(count): Path('/work','inode-'+str(i)).unlink()
print(json.dumps(report))
'''
PAYLOAD = PAYLOAD.replace('__MOUNT_POLICY_SOURCE__', payload_mount_policy_source())


def preflight(image, run=command):
    if not re.fullmatch('sha256:[0-9a-f]{64}', image):
        raise RuntimeError('Require trusted local immutable sha256 image ID')
    info = json.loads(run(['docker', 'info', '--format', '{{json .}}']))
    if (info.get('OSType') != 'linux' or info.get('CgroupVersion') != '2'
            or not all(info.get(k) is True for k in ('MemoryLimit','SwapLimit','CpuCfsQuota','CpuCfsPeriod','PidsLimit'))):
        raise RuntimeError('Require working Linux cgroup v2 controllers')
    img = json.loads(run(['docker', 'image', 'inspect', image]))[0]
    if img.get('Id') != image or img.get('Config', {}).get('Volumes'):
        raise RuntimeError('Image identity/VOLUME rejected')
    return info


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--disposable-host', action='store_true')
    p.add_argument('--parent', default='/var/lib/ephemeral-ext4-poc')
    p.add_argument('--image', help='Trusted local immutable PoC image ID; never pulled')
    p.add_argument('--recover', help='Exact retained experiment directory; conservative cleanup only')
    a = p.parse_args()
    gate(a.disposable_host)
    os.umask(0o077)
    parent = private_directory(a.parent)
    if not re.fullmatch(r'/[a-zA-Z0-9_./-]+', str(parent)):
        raise RuntimeError('Unsupported scratch path characters')
    # One parent lock serializes admission AND setup/cleanup; containers still
    # run independently. No two allocations can race the free-space check.
    lockfd = acquire_lock(parent/'admission.lock')
    with os.fdopen(lockfd, 'w') as lock:
        if a.recover:
            directory = Path(a.recover)
            if directory.parent != parent or not re.fullmatch('probe-[0-9a-f]{32}', directory.name):
                raise RuntimeError('Recovery directory outside private parent')
            e = Experiment(directory)
            e.load()
        else:
            if not a.image:
                p.error('--image is required for a new experiment')
            info = preflight(a.image)
            if command(['findmnt', '-n', '-o', 'FSTYPE', '--target', str(parent)]) != 'ext4':
                raise RuntimeError('Require scratch on ext4 for this experiment')
            mem = dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
            if int(mem['MemAvailable'].split()[0]) < 512*1024:
                raise RuntimeError('Require 512 MiB available RAM')
            capacity(os.statvfs(parent))
            nonce = secrets.token_hex(16)
            directory = parent/('probe-'+nonce)
            directory.mkdir(mode=0o700)
            e = Experiment(directory)
            d = directory.stat()
            e.state = dict(schema=1, directory=str(directory), directory_identity=[d.st_dev,d.st_ino],
                           nonce=nonce, name='er-ext4-'+nonce, image_id=a.image, pending=None,
                           tests={'linux_enforcement':'NOT RUN', 'cleanup':'NOT RUN',
                                  'runner_execution':'NOT RUN', 'real_registration':'SKIP'},
                           configured={'backing_bytes':SIZE,'max_inodes':2048}, evidence={'docker_info':info})
            e.save()
        instance_lock = acquire_lock(e.directory/'experiment.lock', nonblocking=True)
        print('Recovery journal: '+str(e.journal), file=sys.stderr, flush=True)
        # Per-directory lock prevents recovery racing this instance. Admission
        # stays serialized through allocation, then independent probes may overlap.
        failure = None
        signal.signal(signal.SIGTERM, abort_signal)
        try:
            if not a.recover:
                e.setup()
                fcntl.flock(lock, fcntl.LOCK_UN)
                e.state['create_attempted'] = True
                e.save()
                e.launch()
        except BaseException as error:
            failure = error
            e.state['failure'] = str(error)
            e.state['tests']['linux_enforcement'] = 'FAIL'
            e.save()
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            e.cleanup()
        except BaseException as error:
            e.state['cleanup_failure'] = str(error)
            e.state['tests']['cleanup'] = 'FAIL'
            e.save()
            failure = failure or error
        os.close(instance_lock)
        print(json.dumps(e.state, indent=2))
        if failure:
            raise RuntimeError('Experiment failed; retain journal: '+str(failure))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
