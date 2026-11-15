"""Scenario tests for read-only diagnostics, including redaction and uncertainty."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('host_compatibility', ROOT / 'scripts/check-host-compatibility.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class FixtureHost:
    def __init__(self):
        self.info = dict(ServerVersion='28.0.4', OSType='linux', Architecture='x86_64',
                         Driver='overlay2', DriverStatus=[['Backing Filesystem', 'xfs']],
                         DockerRootDir='/private/secret-docker-path', CgroupVersion='2',
                         SecurityOptions=['name=seccomp,profile=builtin'], MemoryLimit=True,
                         SwapLimit=True, CpuCfsQuota=True, CpuCfsPeriod=True, PidsLimit=True)
        self.mount = {'filesystems': [{'fstype': 'xfs', 'options': 'rw,relatime,prjquota'}]}
        self.network = dict(Driver='bridge', Scope='local', EnableIPv6=True,
                            Name='private-network', IPAM={'Config': [{'Subnet': '10.99.0.0/16'}]})
        self.files = {'/etc/os-release': 'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="secret-machine"',
                      '/proc/1/comm': 'systemd\n', '/sys/fs/cgroup/cgroup.controllers': 'cpu memory pids io',
                      '/proc/self/cgroup': '0::/user.slice/test.scope\n',
                      '/sys/fs/cgroup/user.slice/test.scope/memory.swap.max': 'max\n',
                      '/proc/meminfo': 'MemAvailable: 4194304 kB\n'}
        self.calls = []

    def system(self):
        return 'Linux', 'x86_64', '6.8.0-generic'

    def tool(self, name):
        return True

    def disk(self, path):
        assert path == self.info['DockerRootDir']
        return 30 * 1024**3

    def read(self, path):
        try:
            return self.files[str(path)]
        except KeyError as error:
            raise mod.Unavailable('denied at SECRET-PATH with TOKEN') from error

    def run(self, argv):
        self.calls.append(argv)
        if argv[0] == 'docker':
            assert argv[1:3] == ['--host', 'unix:///var/run/docker.sock']
            if argv[3] == 'info':
                return json.dumps(self.info)
            if argv[3:5] == ['network', 'ls']:
                return json.dumps(dict(Driver='bridge', Name='SECRET-NETWORK', ID='SECRET-ID'))
            if argv[3:5] == ['network', 'inspect']:
                return json.dumps(self.network)
        if argv[0] == 'findmnt':
            return json.dumps(self.mount)
        return {'systemctl': 'systemd 255 (255.4-1ubuntu8)\n', 'iptables': 'iptables v1.8.10 (nf_tables)',
                'ip6tables': 'ip6tables v1.8.10 (nf_tables)', 'nft': 'nftables v1.0.9 (Old Doc Yak)'}[argv[0]]


def checks(report):
    return {item['name']: item for item in report['checks']}


class HostCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.host = FixtureHost()

    def collect(self):
        return mod.collect(self.host, 'er-test')

    def test_supported_inventory_never_claims_live_acceptance(self):
        report = self.collect()
        result = checks(report)
        for key in ('platform', 'systemd', 'docker_server', 'docker_storage', 'docker_cgroup_support', 'xfs_project_quota', 'runner_network'):
            self.assertEqual('PASS', result[key]['status'], key)
        self.assertEqual('UNKNOWN', report['overall'])
        self.assertFalse(report['production_ready'])
        self.assertEqual({'NOT RUN'}, {item['status'] for item in report['integration']})

    def test_ext4_and_btrfs_are_explicit_failures(self):
        for backing in ('ext4', 'btrfs'):
            with self.subTest(backing=backing):
                self.host.info['DriverStatus'] = [['Backing Filesystem', backing]]
                self.host.mount['filesystems'][0]['fstype'] = backing
                report = self.collect()
                self.assertEqual('FAIL', report['overall'])
                self.assertEqual('FAIL', checks(report)['docker_storage']['status'])
                self.assertEqual('FAIL', checks(report)['xfs_project_quota']['status'])

    def test_quota_options_missing_disabled_and_valid_alias(self):
        for options, expected in [('rw', 'UNKNOWN'), ('rw,noquota', 'FAIL'), ('rw,pqnoenforce', 'FAIL'),
                                  ('rw,pquota', 'PASS'), ('rw,prjquota,pqnoenforce', 'FAIL')]:
            with self.subTest(options=options):
                self.host.mount['filesystems'][0]['options'] = options
                self.assertEqual(expected, checks(self.collect())['xfs_project_quota']['status'])

    def test_frontend_does_not_establish_docker_backend_or_ipv6_isolation(self):
        result = checks(self.collect())
        self.assertEqual('PASS', result['ipv6_firewall_frontend']['status'])
        self.assertEqual('UNKNOWN', result['docker_firewall_backend']['status'])
        self.assertEqual('NOT RUN', next(item['status'] for item in self.collect()['integration'] if item['name'] == 'network_isolation'))

    def test_daemon_outage_is_unknown_without_error_leak(self):
        original = self.host.run
        def run(argv):
            if argv[0] == 'docker':
                raise mod.Unavailable('secret://credential@host')
            return original(argv)
        self.host.run = run
        report = self.collect()
        self.assertEqual('UNKNOWN', checks(report)['docker_inventory']['status'])
        self.assertEqual('UNKNOWN', checks(report)['xfs_project_quota']['status'])
        self.assertNotIn('credential', json.dumps(report))

    def test_malformed_daemon_and_mount_fail_closed(self):
        original = self.host.run
        for value in ('[', 'null', '[]', '{"SecurityOptions":null}', '{"SecurityOptions":[2]}'):
            with self.subTest(value=value):
                self.host.run = lambda argv: value if argv[0] == 'docker' and argv[3] == 'info' else original(argv)
                report = self.collect()
                self.assertEqual('UNKNOWN', checks(report)['docker_inventory']['status'])
                self.assertNotEqual('PASS', report['overall'])
        self.host.run = original
        for mount in ({}, {'filesystems': []}, {'filesystems': [None]}, {'filesystems': [{'options': 42}]}):
            with self.subTest(mount=mount):
                self.host.mount = mount
                self.assertEqual('UNKNOWN', checks(self.collect())['xfs_project_quota']['status'])

    def test_private_names_paths_subnets_and_raw_config_are_redacted(self):
        text = json.dumps(self.collect())
        for private in ('secret-docker-path', 'secret-machine', 'private-network', 'SECRET-NETWORK', 'SECRET-ID', '10.99.0.0', 'user.slice', 'TOKEN'):
            self.assertNotIn(private, text)

    def test_missing_swap_root_interface_is_unknown_not_false_unsupported(self):
        self.host.files['/proc/self/cgroup'] = '0::/\n'
        result = checks(self.collect())
        self.assertEqual('PASS', result['cgroup_v2']['status'])
        self.assertEqual('UNKNOWN', result['memory_swap_interface']['status'])

    def test_cgroup_v1_missing_controllers_and_daemon_capability_reject(self):
        self.host.files['/sys/fs/cgroup/cgroup.controllers'] = 'cpu io'
        self.host.info['CgroupVersion'] = '1'
        self.host.info['SwapLimit'] = False
        result = checks(self.collect())
        self.assertEqual('FAIL', result['cgroup_v2']['status'])
        self.assertEqual('FAIL', result['docker_cgroup_support']['status'])

    def test_rootless_arm_and_non_systemd_host_reject(self):
        self.host.info['SecurityOptions'] = ['name=rootless']
        self.host.files['/proc/1/comm'] = 'bash\n'
        self.host.system = lambda: ('Linux', 'aarch64', '6.8.0')
        result = checks(self.collect())
        for name in ('platform', 'docker_server', 'systemd'):
            self.assertEqual('FAIL', result[name]['status'])

    def test_no_selected_network_does_not_invent_isolation(self):
        report = mod.collect(self.host)
        self.assertEqual('UNKNOWN', checks(report)['runner_network']['status'])
        self.assertFalse(any(argv[3:5] == ['network', 'inspect'] for argv in self.host.calls if argv[0] == 'docker'))

    def test_ipv6_disabled_stays_visible(self):
        self.host.network['EnableIPv6'] = False
        report = self.collect()
        self.assertFalse(checks(report)['runner_network']['observed']['ipv6_enabled'])
        self.assertFalse(report['production_ready'])

    def test_read_only_command_surface(self):
        self.collect()
        allowed = {('systemctl', '--version'), ('iptables', '--version'), ('ip6tables', '--version'), ('nft', '--version')}
        for argv in self.host.calls:
            if argv[0] == 'docker':
                self.assertTrue(argv[3] == 'info' or argv[3:5] in (['network', 'ls'], ['network', 'inspect']))
            elif argv[0] == 'findmnt':
                self.assertEqual(['findmnt', '--json', '--target', '/private/secret-docker-path', '--output', 'FSTYPE,OPTIONS'], argv)
            else:
                self.assertIn(tuple(argv), allowed)

    def test_required_tools_missing_are_failures(self):
        self.host.tool = lambda name: name != 'curl'
        self.assertEqual('FAIL', checks(self.collect())['tool_curl']['status'])

    def test_reader_cgroup_path_traversal_never_read(self):
        self.host.files['/proc/self/cgroup'] = '0::/../../etc\n'
        self.assertEqual('UNKNOWN', checks(self.collect())['memory_swap_interface']['status'])

    def test_cli_exit_statuses_and_bad_network_before_io(self):
        for network in ('host', 'bridge', 'none', '--bad', 'a/b'):
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/check-host-compatibility.py'), '--network', network], capture_output=True, text=True)
            self.assertEqual(2, result.returncode)
            self.assertEqual('', result.stdout)
        with patch.object(mod, 'Host', return_value=self.host), patch.object(sys, 'argv', ['diagnostic', '--network', 'er-test']), patch('builtins.print'):
            self.assertEqual(2, mod.main())
            self.host.info['Driver'] = 'btrfs'
            self.assertEqual(1, mod.main())

    def test_timeout_nonzero_and_invalid_unicode_do_not_expose_command_errors(self):
        for error in (subprocess.TimeoutExpired('docker SECRET', 15), FileNotFoundError('SECRET'), UnicodeError('SECRET')):
            with self.subTest(error=error), patch.object(mod.subprocess, 'run', side_effect=error):
                with self.assertRaises(mod.Unavailable) as caught:
                    mod.Host().run(['docker', '--version'])
                self.assertNotIn('SECRET', str(caught.exception))
        with patch.object(mod.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'SECRET')):
            with self.assertRaises(mod.Unavailable) as caught:
                mod.Host().run(['docker', '--version'])
            self.assertNotIn('SECRET', str(caught.exception))

    def test_remote_environment_is_not_used_for_local_mount_correlation(self):
        with patch.dict(os.environ, {'DOCKER_CONTEXT': 'remote', 'DOCKER_HOST': 'tcp://secret', 'DOCKER_TLS_VERIFY': '1'}), patch.object(mod.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
            mod.Host().run([*mod.DOCKER, 'info'])
            self.assertNotIn('DOCKER_CONTEXT', run.call_args.kwargs['env'])
            self.assertNotIn('DOCKER_HOST', run.call_args.kwargs['env'])
            self.assertNotIn('DOCKER_TLS_VERIFY', run.call_args.kwargs['env'])
            self.assertEqual(15, run.call_args.kwargs['timeout'])

    def test_sample_report_matches_supported_fixture_and_keeps_not_run(self):
        sample = json.loads((ROOT / 'docs/host-compatibility.example.json').read_text())
        self.assertEqual(sample, self.collect())
