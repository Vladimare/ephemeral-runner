#!/usr/bin/env python3
"""Validated container budgets and fail-closed Docker deployment preflight."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys

DEFAULT = dict(memory_mib=2048, cpu_millis=1000, swap_mib=0, storage_mib=4096,
               tmp_mib=128, shm_mib=64, log_mib=10, log_files=3,
               log_driver='json-file', storage_backend='overlay2-xfs-quota')
RANGES = dict(memory_mib=(256, 262144), cpu_millis=(100, 64000), swap_mib=(0, 0),
              storage_mib=(256, 1048576), tmp_mib=(16, 1024), shm_mib=(16, 1024),
              log_mib=(1, 100), log_files=(1, 10))
MIB = 1024 * 1024


def cleanup():
    spec = importlib.util.spec_from_file_location('budget_cleanup', Path(__file__).with_name('runner-cleanup.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate policy key')
        result[key] = value
    return result


def validate(policy):
    if not isinstance(policy, dict) or set(policy) != set(DEFAULT):
        raise ValueError('Resource policy must contain exactly: ' + ', '.join(DEFAULT))
    for key, (low, high) in RANGES.items():
        if type(policy[key]) is not int or not low <= policy[key] <= high:
            raise ValueError(f'{key} must be an integer in [{low}, {high}]')
    for key in ('log_driver', 'storage_backend'):
        if policy[key] != DEFAULT[key]:
            raise ValueError(f'Unsupported {key}; required: {DEFAULT[key]}')
    if policy['tmp_mib'] + policy['shm_mib'] > policy['memory_mib'] // 2:
        raise ValueError('tmp_mib + shm_mib must not exceed half memory_mib')
    return policy


def read_policy(path, *, uid=0, root=Path('/')):
    cleanup().check_private_root(path, uid=uid, root=root)
    return validate(json.loads(Path(path).read_text(), object_pairs_hook=unique_object))


def options(policy):
    validate(policy)
    memory = str(policy['memory_mib'] * MIB)
    return ['--pull', 'never', '--cgroupns', 'private', '--memory', memory, '--memory-swap', memory,
            '--cpu-period', '100000', '--cpu-quota', str(policy['cpu_millis'] * 100),
            '--pids-limit', '512', '--log-driver', 'json-file',
            '--log-opt', f'max-size={policy["log_mib"] * MIB}',
            '--log-opt', f'max-file={policy["log_files"]}',
            '--storage-opt', f'size={policy["storage_mib"] * MIB}',
            '--tmpfs', f'/tmp:rw,nosuid,nodev,size={policy["tmp_mib"]}m,mode=1777',
            '--shm-size', str(policy['shm_mib'] * MIB)]


def command(args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=60)
    if result.returncode:
        # No credentials are used here; keep errors independent of image output.
        raise RuntimeError(f'{args[0]} {args[1]} failed; check Docker/cgroup/quota support')
    return result.stdout.strip()


def preflight(policy, image, run=command):
    validate(policy)
    info = json.loads(run(['docker', 'info', '--format', '{{json .}}']))
    if (any('rootless' in option for option in info.get('SecurityOptions', []))
            or info.get('OSType') != 'linux' or info.get('CgroupVersion') != '2'
            or info.get('Driver') != 'overlay2'
            or dict(info.get('DriverStatus', [])).get('Backing Filesystem') != 'xfs'
            or any(info.get(key) is not True for key in ('MemoryLimit', 'SwapLimit', 'CpuCfsQuota', 'CpuCfsPeriod', 'PidsLimit'))):
        raise RuntimeError('Require Linux cgroup v2 CPU/memory/swap/PID controllers and overlay2 on XFS with project quotas')
    image_info = json.loads(run(['docker', 'image', 'inspect', image]))[0]
    image_id = image_info.get('Id', '')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        raise RuntimeError('Cannot pin inspected image ID')
    if image_info.get('Config', {}).get('Volumes'):
        raise RuntimeError('Image-declared volumes bypass writable-layer quotas; use an image without VOLUME')
    # Probe the exact quota/log/memory/CPU options before requesting a token.
    # Docker refuses overlay2 size unless XFS project quota is enabled. No
    # network, secrets or job execution; the caller-selected image is trusted.
    name = 'er-budget-' + secrets.token_hex(12)
    created = False
    try:
        run(['docker', 'create', '--rm', '--name', name, '--network', 'none',
             '--user', '10001:10001', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
             '--no-healthcheck', *options(policy), '--entrypoint', '/bin/sh', image_id, '-c', 'sleep 45'])
        created = True
        run(['docker', 'start', name])
        settings = json.loads(run(['docker', 'inspect', name]))[0]['HostConfig']
        expected = dict(Memory=policy['memory_mib'] * MIB, MemorySwap=policy['memory_mib'] * MIB,
                        CpuPeriod=100000, CpuQuota=policy['cpu_millis'] * 100, PidsLimit=512)
        if any(settings.get(key) != value for key, value in expected.items()):
            raise RuntimeError('Docker did not retain requested resource settings')
        if settings.get('LogConfig') != {'Type': 'json-file', 'Config': {
                'max-size': str(policy["log_mib"] * MIB), 'max-file': str(policy['log_files'])}}:
            raise RuntimeError('Docker logging policy mismatch')
        if settings.get('StorageOpt', {}).get('size') != str(policy["storage_mib"] * MIB):
            raise RuntimeError('Docker writable-storage policy mismatch')
        if settings.get('ShmSize') != policy['shm_mib'] * MIB or settings.get('Tmpfs') != {
                '/tmp': f'rw,nosuid,nodev,size={policy["tmp_mib"]}m,mode=1777'}:
            raise RuntimeError('Docker temporary-storage policy mismatch')
        # Read the running probe's actual cgroup, not merely requested flags.
        actual = run(['docker', 'exec', name, '/bin/sh', '-c',
                      'cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.swap.max /sys/fs/cgroup/cpu.max /sys/fs/cgroup/pids.max']).splitlines()
        if actual != [str(expected['Memory']), '0', f'{expected["CpuQuota"]} 100000', '512']:
            raise RuntimeError('Actual cgroup v2 limits differ (including memory.swap.max=0); refusing launch')
    finally:
        if created:
            # Failure to remove the probe is itself a failed preflight.
            run(['docker', 'rm', '-f', '-v', name])
    return image_id


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--instance', required=True)
    args = parser.parse_args()
    module = cleanup()
    cfg = module.load_config(args.instance)
    policy = read_policy(module.CONFIG_BASE / args.instance / 'resources.json')
    image_id = preflight(policy, cfg.image)
    print('\n'.join([image_id, *options(policy)]))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, IndexError, TypeError, subprocess.SubprocessError) as error:
        print(f'Resource preflight failed: {error}', file=sys.stderr)
        sys.exit(1)
