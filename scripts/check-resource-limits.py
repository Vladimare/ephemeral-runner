#!/usr/bin/env python3
"""Opt-in bounded tests. Run ONLY as root on a disposable Linux Docker host."""
import argparse
import errno
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import sys

spec = importlib.util.spec_from_file_location('resources', Path(__file__).with_name('runner-resources.py'))
resources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resources)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-host', action='store_true', help='Explicitly acknowledge disposable host only')
    parser.add_argument('--image', required=True, help='Local trusted runner image with /bin/sh, cat, sleep, python3; never pulled')
    args = parser.parse_args()
    require(args.disposable_host and sys.platform.startswith('linux') and os.geteuid() == 0,
            'Require --disposable-host and root on disposable Linux; no Docker access attempted')
    run = resources.command
    info = json.loads(run(['docker', 'info', '--format', '{{json .}}']))
    require(shutil.disk_usage(info['DockerRootDir']).free >= 2 * 1024**3, 'Need at least 2 GiB free on local Docker data filesystem')
    mem = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    require(int(mem['MemAvailable'].split()[0]) >= 1024**2, 'Need at least 1 GiB available RAM')
    policy = dict(resources.DEFAULT, memory_mib=256, cpu_millis=100, storage_mib=256,
                  tmp_mib=16, shm_mib=16, log_mib=1, log_files=2)
    image = resources.preflight(policy, args.image)
    names = []

    def start(payload):
        name = 'er-limits-test-' + secrets.token_hex(12)
        run(['docker', 'create', '--name', name, '--network', 'none', '--user', '10001:10001',
             '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--no-healthcheck',
             *resources.options(policy), '--entrypoint', 'python3', image, '-c', payload])
        names.append(name)
        run(['docker', 'start', name])
        return name

    def inspect(name):
        return json.loads(run(['docker', 'inspect', name]))[0]

    def execute(name, payload):
        return run(['docker', 'exec', name, 'python3', '-c', payload])

    try:
        neighbor = start('import time; time.sleep(180)')
        # CPU throttle evidence from a bounded 2-second workload inside its cgroup.
        cpu = execute(neighbor, '''import time
from pathlib import Path
before = dict(line.split() for line in Path('/sys/fs/cgroup/cpu.stat').read_text().splitlines())
end = time.monotonic() + 2
while time.monotonic() < end: pass
after = dict(line.split() for line in Path('/sys/fs/cgroup/cpu.stat').read_text().splitlines())
print(int(after['nr_throttled']) - int(before['nr_throttled']))''')
        require(int(cpu) > 0, 'CPU throttling was not observed')
        # At most 384 MiB is attempted, even if quota enforcement is defective.
        quota = execute(neighbor, f'''import errno, os
try:
    with open('/home/runner/quota-test', 'wb', buffering=0) as stream:
        for _ in range(384): stream.write(b'x' * (1024 * 1024))
        os.fsync(stream.fileno())
except OSError as error:
    if error.errno not in ({errno.EDQUOT}, {errno.ENOSPC}): raise
    print('quota-enforced')
else:
    print('UNBOUNDED')
finally:
    if os.path.exists('/home/runner/quota-test'): os.unlink('/home/runner/quota-test')''')
        require(quota == 'quota-enforced', 'Writable-layer quota did not reject bounded excess writes')
        oom = start('blocks = [bytearray(1024 * 1024) for _ in range(512)]')
        require(run(['docker', 'wait', oom]) == '137', 'Expected OOM exit 137')
        require(inspect(oom)['State']['OOMKilled'] is True, 'Exit 137 alone does not prove OOM')
        require(inspect(neighbor)['State']['Running'] is True, 'Neighbor was affected')
        logs = start("import sys; [sys.stdout.write('x' * 1023 + '\\n') for _ in range(8192)]; sys.stdout.flush()")
        require(run(['docker', 'wait', logs]) == '0', 'Log producer failed')
        log_path = Path(inspect(logs)['LogPath'])
        files = list(log_path.parent.glob(log_path.name + '*'))
        require(files and len(files) <= 2 and sum(p.stat().st_size for p in files) <= 4 * resources.MIB,
                'Rotated logs exceeded conservative 4 MiB envelope or 2 files')
        print('PASS: inspect/cgroup preflight, CPU throttling, writable quota, OOM/137, neighbor survival and bounded log rotation')
    finally:
        errors = []
        for name in reversed(names):
            try:
                run(['docker', 'rm', '-f', '-v', name])
            except RuntimeError:
                errors.append(name)
        if errors:
            raise RuntimeError('Manual cleanup needed for: ' + ', '.join(errors))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        sys.exit(1)
