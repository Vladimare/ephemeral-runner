#!/usr/bin/env python3
"""Read-only local Linux compatibility inventory; never proves live enforcement."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

DOCKER = ('docker', '--host', 'unix:///var/run/docker.sock')
TOOLS = ('bash', 'python3', 'curl', 'docker', 'systemctl', 'findmnt', 'install')
LIVE_GATES = ('image_build_checksum', 'resource_enforcement', 'launcher_mounts',
              'systemd_lifecycle', 'github_one_job', 'multi_instance',
              'fault_recovery', 'reboot_recovery', 'network_isolation')


class Unavailable(Exception):
    pass


class Host:
    """Only read-only commands are issued. Raw errors/output never enter reports."""
    def run(self, argv):
        env = dict(os.environ)
        # Correlate local /proc and mounts with the local daemon, regardless of
        # a caller's remote context/TLS settings. No credential inventory is requested.
        for key in ('DOCKER_CONTEXT', 'DOCKER_HOST', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
            env.pop(key, None)
        try:
            result = subprocess.run(argv, text=True, capture_output=True, timeout=15,
                                    env=env, stdin=subprocess.DEVNULL)
        except (OSError, UnicodeError, subprocess.SubprocessError) as error:
            raise Unavailable('command unavailable or timed out') from error
        if result.returncode or len(result.stdout) > 1024 * 1024:
            raise Unavailable('command failed or output exceeded inventory budget')
        return result.stdout

    def read(self, path):
        try:
            with Path(path).open() as stream:
                data = stream.read(65537)
            if len(data) > 65536:
                raise Unavailable('file exceeded inventory budget')
            return data
        except (OSError, UnicodeError) as error:
            raise Unavailable('file unavailable') from error

    def disk(self, path):
        try:
            return shutil.disk_usage(path).free
        except OSError as error:
            raise Unavailable('filesystem unavailable') from error

    def tool(self, name):
        return shutil.which(name) is not None

    def system(self):
        return platform.system(), platform.machine(), platform.release()


def safe_text(value):
    # Only expected version/enum values are reported; not hostnames or paths.
    if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.+() -]{1,120}', value):
        return value
    return 'unavailable'


def collect(host, network=None):
    checks = []

    def add(name, status, detail, observed=None):
        item = dict(name=name, status=status, detail=detail)
        if observed is not None:
            item['observed'] = observed
        checks.append(item)

    def check(name, condition, detail, observed=None):
        add(name, 'PASS' if condition else 'FAIL', detail, observed)

    system, arch, kernel = host.system()
    check('platform', system == 'Linux' and arch in ('x86_64', 'amd64'),
          'Current runner image requires local Linux x86_64',
          dict(system=safe_text(system), architecture=safe_text(arch), kernel=safe_text(kernel)))
    try:
        release = dict(line.split('=', 1) for line in host.read('/etc/os-release').splitlines()
                       if '=' in line and not line.startswith('#'))
        add('os_release', 'PASS', 'Distribution metadata only',
            {key: safe_text(release.get(key, '').strip('"')) for key in ('ID', 'VERSION_ID')})
    except Unavailable:
        add('os_release', 'UNKNOWN', 'Distribution metadata unavailable')
    for tool in TOOLS:
        check('tool_' + tool, host.tool(tool), 'Required userspace executable present')
    try:
        version = host.run(['systemctl', '--version']).splitlines()[0]
        if not re.match(r'^systemd [0-9]+(?: |$)', version):
            raise Unavailable('invalid systemd identity')
        pid1 = host.read('/proc/1/comm').strip()
        check('systemd', pid1 == 'systemd', 'PID 1 must be systemd; no units loaded or changed', safe_text(version))
    except (Unavailable, IndexError):
        add('systemd', 'UNKNOWN', 'Cannot establish systemd PID 1 and version')
    try:
        controllers = set(host.read('/sys/fs/cgroup/cgroup.controllers').split())
        check('cgroup_v2', {'cpu', 'memory', 'pids'} <= controllers,
              'Controllers visible in local hierarchy; delegation/enforcement still untested',
              sorted(controllers & {'cpu', 'memory', 'pids', 'io', 'cpuset', 'hugetlb', 'rdma', 'misc'}))
    except Unavailable:
        add('cgroup_v2', 'UNKNOWN', 'Cannot read cgroup v2 controllers')
    try:
        group = [line[3:] for line in host.read('/proc/self/cgroup').splitlines() if line.startswith('0::')]
        if len(group) != 1 or not group[0].startswith('/') or '..' in Path(group[0]).parts:
            raise Unavailable('invalid unified cgroup path')
        swap = host.read(Path('/sys/fs/cgroup') / group[0].lstrip('/') / 'memory.swap.max').strip()
        if swap != 'max' and not swap.isdecimal():
            raise Unavailable('invalid swap value')
        add('memory_swap_interface', 'PASS', 'Readable in diagnostic process cgroup; not a job-container limit', swap)
    except Unavailable:
        add('memory_swap_interface', 'UNKNOWN', 'No readable swap limit for diagnostic cgroup; root cgroup may omit it')
    try:
        memory = dict(line.split(':', 1) for line in host.read('/proc/meminfo').splitlines() if ':' in line)
        available = memory['MemAvailable'].split()
        if len(available) != 2 or available[1] != 'kB' or not available[0].isdecimal():
            raise ValueError()
        add('available_memory', 'PASS', 'Available bytes observed; no workload capacity guarantee', int(available[0]) * 1024)
    except (Unavailable, KeyError, ValueError):
        add('available_memory', 'UNKNOWN', 'MemAvailable unavailable or malformed')

    info = None
    try:
        # Project fields at source: do not collect Names, Labels, proxies,
        # registry credentials or host identifying data from docker info.
        fields = ('ServerVersion', 'OSType', 'Architecture', 'Driver', 'DriverStatus', 'DockerRootDir',
                  'CgroupVersion', 'SecurityOptions', 'MemoryLimit', 'SwapLimit', 'CpuCfsQuota', 'CpuCfsPeriod', 'PidsLimit')
        template = '{' + ','.join('"' + key + '":{{json .' + key + '}}' for key in fields) + '}'
        info = json.loads(host.run([*DOCKER, 'info', '--format', template]))
        if not isinstance(info, dict):
            raise ValueError()
        required = ('MemoryLimit', 'SwapLimit', 'CpuCfsQuota', 'CpuCfsPeriod', 'PidsLimit')
        security = info.get('SecurityOptions')
        if not isinstance(security, list) or not all(isinstance(item, str) for item in security):
            raise ValueError()
        check('docker_server', info.get('OSType') == 'linux' and info.get('Architecture') in ('x86_64', 'amd64')
              and bool(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?', str(info.get('ServerVersion', ''))))
              and not any('rootless' in option for option in security),
              'Local rootful Linux x64 daemon required', safe_text(info.get('ServerVersion')))
        check('docker_cgroup_support', info.get('CgroupVersion') == '2' and all(info.get(key) is True for key in required),
              'Daemon advertised capabilities, not observed container enforcement',
              {key: info.get(key) is True for key in required})
        driver_status = info.get('DriverStatus')
        if not isinstance(driver_status, list) or any(not isinstance(pair, list) or len(pair) != 2 for pair in driver_status):
            raise ValueError()
        backing = dict(driver_status).get('Backing Filesystem')
        if not isinstance(backing, str):
            raise ValueError()
        check('docker_storage', info.get('Driver') == 'overlay2' and backing == 'xfs',
              'Production backend requires overlay2 on XFS; ext4/btrfs are unsupported',
              dict(driver=safe_text(info.get('Driver')), backing_filesystem=safe_text(backing)))
    except (Unavailable, ValueError, TypeError):
        info = None
        add('docker_inventory', 'UNKNOWN', 'Local daemon inventory unavailable or malformed; no stderr included')
    root = info.get('DockerRootDir') if info else None
    if not isinstance(root, str) or not root.startswith('/'):
        root = None
    try:
        if not root:
            raise Unavailable('no local data path')
        mount = json.loads(host.run(['findmnt', '--json', '--target', root, '--output', 'FSTYPE,OPTIONS']))['filesystems']
        if not isinstance(mount, list) or len(mount) != 1 or not isinstance(mount[0], dict) or not isinstance(mount[0].get('options'), str):
            raise ValueError()
        fs, options = mount[0].get('fstype'), set(mount[0]['options'].split(','))
        if fs != 'xfs':
            add('xfs_project_quota', 'FAIL', 'Local Docker data filesystem is not XFS', safe_text(fs))
        elif options & {'prjquota', 'pquota'} and not options & {'noquota', 'pqnoenforce'}:
            add('xfs_project_quota', 'PASS', 'XFS mount advertises project quota enforcement; live quota test still required')
        elif options & {'noquota', 'pqnoenforce'}:
            add('xfs_project_quota', 'FAIL', 'Mount explicitly disables project quota enforcement')
        else:
            add('xfs_project_quota', 'UNKNOWN', 'XFS project quota enforcement not established from mount options')
    except (Unavailable, ValueError, KeyError, TypeError, IndexError):
        add('xfs_project_quota', 'UNKNOWN', 'Local Docker backing mount unavailable or malformed')
    try:
        if not root:
            raise Unavailable('no local data path')
        add('available_docker_disk', 'PASS', 'Free bytes on local Docker data filesystem; no reservation guarantee', host.disk(root))
    except Unavailable:
        add('available_docker_disk', 'UNKNOWN', 'Local Docker filesystem capacity unavailable')
    try:
        rows = [json.loads(line) for line in host.run([*DOCKER, 'network', 'ls', '--format', '{{json .}}']).splitlines()]
        if not all(isinstance(row, dict) and isinstance(row.get('Driver'), str) for row in rows):
            raise ValueError()
        add('docker_network_inventory', 'PASS', 'Inventory counts only; names, IDs and subnets omitted',
            dict(total=len(rows), bridge=sum(row['Driver'] == 'bridge' for row in rows)))
    except (Unavailable, ValueError, TypeError):
        add('docker_network_inventory', 'UNKNOWN', 'Cannot inventory local Docker networks')
    try:
        if not network:
            raise Unavailable('no selected network')
        rows = json.loads(host.run([*DOCKER, 'network', 'inspect', '--format', '{{json .}}', network]))
        if not isinstance(rows, dict) or type(rows.get('EnableIPv6')) is not bool:
            raise ValueError()
        check('runner_network', rows.get('Driver') == 'bridge' and rows.get('Scope') == 'local',
              'Selected network shape only; a bridge does not prove isolation',
              dict(ipv6_enabled=rows['EnableIPv6']))
    except (Unavailable, ValueError, TypeError):
        add('runner_network', 'UNKNOWN', 'Select --network to inspect an existing dedicated bridge; no network is created')
    # Frontend identity is observable without dumping rules. It cannot establish
    # which backend Docker uses or whether IPv4/IPv6 isolation works.
    for family, executable in (('ipv4', 'iptables'), ('ipv6', 'ip6tables')):
        try:
            version = host.run([executable, '--version']).strip()
            if not re.fullmatch(r'ip6?tables v[0-9.]+ \((nf_tables|legacy)\)', version):
                raise Unavailable('unknown frontend')
            add(family + '_firewall_frontend', 'PASS', 'Frontend identity only; not Docker backend or enforcement', version)
        except Unavailable:
            add(family + '_firewall_frontend', 'UNKNOWN', 'Firewall frontend identity unavailable')
    try:
        nft = host.run(['nft', '--version']).strip()
        if not re.match(r'^nftables v[0-9]+\.[0-9]+\.[0-9]+(?: |$)', nft):
            raise Unavailable('invalid nft identity')
        add('nft_userspace', 'PASS', 'nft executable identity only', safe_text(nft))
    except Unavailable:
        add('nft_userspace', 'UNKNOWN', 'nft executable unavailable')
    add('docker_firewall_backend', 'UNKNOWN', 'Not inferred from frontend versions; verify daemon configuration and live chain ordering separately')
    add('quota_enforcement', 'UNKNOWN', 'Read-only inventory cannot establish actual project quota or cgroup enforcement')
    statuses = {item['status'] for item in checks}
    return dict(format_version=1, scope='local-read-only-inventory',
                overall='FAIL' if 'FAIL' in statuses else 'UNKNOWN' if 'UNKNOWN' in statuses else 'PASS',
                production_ready=False, checks=checks,
                integration=[dict(name=name, status='NOT RUN') for name in LIVE_GATES])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--network', help='Existing dedicated local Docker bridge to inspect')
    args = parser.parse_args()
    if args.network and (args.network in ('bridge', 'host', 'none') or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', args.network)):
        parser.error('network must name an existing dedicated bridge, not a built-in network')
    report = collect(Host(), args.network)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report['overall'] == 'FAIL' else 2 if report['overall'] == 'UNKNOWN' else 0


if __name__ == '__main__':
    sys.exit(main())
