#!/usr/bin/env python3
"""Storage-primitives experiment only; NOT an ext4 runner backend or registration test."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

spec = importlib.util.spec_from_file_location('resource_probe', Path(__file__).with_name('runner-resources.py'))
resources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resources)
MIB = 1024 * 1024

# Fixed, deliberately small bounds. No configurable bind mounts or host paths.
FLAGS = ['--pull', 'never', '--read-only', '--network', 'none', '--cgroupns', 'private',
         '--user', '10001:10001', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
         '--no-healthcheck', '--init', '--memory', str(256 * MIB), '--memory-swap', str(256 * MIB),
         '--cpu-period', '100000', '--cpu-quota', '25000', '--pids-limit', '64',
         '--log-driver', 'json-file', '--log-opt', f'max-size={MIB}', '--log-opt', 'max-file=2',
         '--tmpfs', '/work:rw,nosuid,nodev,size=8m,nr_inodes=1024,uid=10001,gid=10001,mode=0700',
         '--tmpfs', '/tmp:rw,nosuid,nodev,size=8m,nr_inodes=1024,mode=1777', '--shm-size', str(8 * MIB)]

PAYLOAD = r'''
import errno, json, os
from pathlib import Path
report = {}
for name, expected in [('memory.max', '268435456'), ('memory.swap.max', '0'), ('cpu.max', '25000 100000'), ('pids.max', '64')]:
    actual = Path('/sys/fs/cgroup', name).read_text().strip()
    assert actual == expected, (name, actual)
    report[name] = actual
# This is the current image's mutable registration directory. It must remain
# visible but fail writes on a read-only root: mounting tmpfs over it is not tested.
root = Path('/home/runner/actions-runner')
assert (root / 'config.sh').is_file(), 'Require the provided runner image layout'
for directory in (root, Path('/home/runner'), Path('/var/tmp')):
    try:
        (directory / 'readonly-probe').write_text('no credentials')
    except OSError as error:
        assert error.errno in (errno.EROFS, errno.EACCES), (directory, error)
    else:
        raise AssertionError('Unbounded write path: ' + str(directory))
report['existing_runner_layout'] = 'write paths unavailable; registration compatibility NOT proven'
work = Path('/work')
(work / 'state').write_text('temporary fixture')
(work / 'state').unlink()
# At most 12 MiB attempted even if the 8 MiB limit is defective.
try:
    with (work / 'budget').open('wb', buffering=0) as stream:
        for _ in range(12): stream.write(b'x' * (1024 * 1024))
except OSError as error:
    assert error.errno == errno.ENOSPC, error
else:
    raise AssertionError('tmpfs byte bound not enforced')
finally:
    (work / 'budget').unlink(missing_ok=True)
report['tmpfs_bytes'] = 'ENOSPC below 12 MiB attempted'
try:
    for index in range(1100): (work / ('inode-' + str(index))).touch()
except OSError as error:
    assert error.errno == errno.ENOSPC, error
else:
    raise AssertionError('tmpfs inode bound not enforced')
finally:
    for file in work.glob('inode-*'): file.unlink()
report['tmpfs_inodes'] = 'ENOSPC below 1100 attempted files'
report['mounts'] = []
for line in Path('/proc/self/mountinfo').read_text().splitlines():
    left, right = line.split(' - ', 1)
    fields = left.split()
    if fields[4] in ('/', '/work', '/tmp', '/dev/shm'):
        report['mounts'].append(dict(path=fields[4], options=fields[5], fs=right.split()[0], super_options=right.split()[2]))
print(json.dumps(report, indent=2))
'''


def probe(image, run=resources.command):
    info = json.loads(run(['docker', 'info', '--format', '{{json .}}']))
    if (info.get('OSType') != 'linux' or info.get('CgroupVersion') != '2'
            or any(info.get(key) is not True for key in ('MemoryLimit', 'SwapLimit', 'CpuCfsQuota', 'CpuCfsPeriod', 'PidsLimit'))):
        raise RuntimeError('Require Linux cgroup v2 controllers; no storage backend enabled')
    image_info = json.loads(run(['docker', 'image', 'inspect', image]))[0]
    if image_info.get('Config', {}).get('Volumes'):
        raise RuntimeError('Image VOLUME would bypass read-only-root accounting')
    image_id = image_info.get('Id', '')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        raise RuntimeError('Require immutable local image ID')
    name = 'er-ro-proof-' + secrets.token_hex(12)
    created = False
    try:
        run(['docker', 'create', '--name', name, *FLAGS, '--entrypoint', 'python3', image_id, '-c', PAYLOAD])
        created = True
        config = json.loads(run(['docker', 'inspect', name]))[0]
        host = config['HostConfig']
        if (host.get('ReadonlyRootfs') is not True or host.get('Binds')
                or host.get('Mounts') or host.get('VolumesFrom')
                or any(mount.get('Type') != 'tmpfs' or mount.get('Destination') not in ('/work', '/tmp', '/dev/shm')
                       for mount in config.get('Mounts', []))
                or host.get('Memory') != 256 * MIB or host.get('MemorySwap') != 256 * MIB
                or host.get('CpuPeriod') != 100000 or host.get('CpuQuota') != 25000
                or host.get('PidsLimit') != 64 or host.get('ShmSize') != 8 * MIB
                or host.get('LogConfig') != {'Type': 'json-file', 'Config': {'max-size': str(MIB), 'max-file': '2'}}
                or host.get('Tmpfs') != {
                    '/work': 'rw,nosuid,nodev,size=8m,nr_inodes=1024,uid=10001,gid=10001,mode=0700',
                    '/tmp': 'rw,nosuid,nodev,size=8m,nr_inodes=1024,mode=1777'}):
            raise RuntimeError('Unexpected writable mounts or ignored limits; refusing proof')
        run(['docker', 'start', name])
        if run(['docker', 'wait', name]) != '0':
            raise RuntimeError('Primitives proof failed; inspect bounded container logs on disposable host')
        result = json.loads(run(['docker', 'logs', name]))
        # Return configured settings separately from observations made in-container.
        return dict(status='PRIMITIVES ONLY; NO RUNNER BACKEND ACCEPTANCE',
                    configured=dict(HostConfig=host), observed=result)
    finally:
        if created:
            run(['docker', 'rm', '-f', '-v', name])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-host', action='store_true')
    parser.add_argument('--image', required=True, help='Local trusted provided runner image; never pulled')
    args = parser.parse_args()
    if not args.disposable_host or not sys.platform.startswith('linux') or os.geteuid() != 0:
        raise RuntimeError('Require explicit --disposable-host and root on disposable Linux; Docker was not contacted')
    mem = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    if int(mem['MemAvailable'].split()[0]) < 512 * 1024:
        raise RuntimeError('Require at least 512 MiB available RAM before creating a 256 MiB probe')
    print(json.dumps(probe(args.image), indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, IndexError, subprocess.SubprocessError) as error:
        print(f'Proof failed (no backend enabled): {error}', file=sys.stderr)
        sys.exit(1)
