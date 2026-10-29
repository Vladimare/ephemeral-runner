import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('resources', ROOT / 'scripts/runner-resources.py')
resources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resources)
IMAGE = 'sha256:' + 'a' * 64


class Docker:
    """Models external responses; never contacts a real daemon."""
    def __init__(self, policy=None):
        self.policy = dict(policy or resources.DEFAULT)
        self.calls = []
        self.info = dict(OSType='linux', CgroupVersion='2', Driver='overlay2',
                         DriverStatus=[['Backing Filesystem', 'xfs']],
                         MemoryLimit=True, SwapLimit=True, CpuCfsQuota=True, CpuCfsPeriod=True, PidsLimit=True)
        self.image = {'Id': IMAGE, 'Config': {'Volumes': None}}
        p = self.policy
        self.host = dict(Memory=p['memory_mib'] * resources.MIB, MemorySwap=p['memory_mib'] * resources.MIB,
                         CpuPeriod=100000, CpuQuota=p['cpu_millis'] * 100, PidsLimit=512,
                         StorageOpt={'size': str(p["storage_mib"] * resources.MIB)},
                         LogConfig={'Type': 'json-file', 'Config': {'max-size': str(p["log_mib"] * resources.MIB), 'max-file': str(p['log_files'])}},
                         ShmSize=p['shm_mib'] * resources.MIB,
                         Tmpfs={'/tmp': f'rw,nosuid,nodev,size={p["tmp_mib"]}m,mode=1777'})
        self.cgroup = f'{self.host["Memory"]}\n0\n{self.host["CpuQuota"]} 100000\n512'
        self.fail = None

    def __call__(self, args):
        self.calls.append(args)
        if args[1] == self.fail:
            raise RuntimeError('injected daemon failure')
        if args[1] == 'info':
            return json.dumps(self.info)
        if args[1:3] == ['image', 'inspect']:
            return json.dumps([self.image])
        if args[1] == 'inspect':
            return json.dumps([{'HostConfig': self.host}])
        if args[1] == 'exec':
            return self.cgroup
        return 'probe'


class ResourceTests(unittest.TestCase):
    def test_defaults_and_independent_policy_options(self):
        self.assertEqual(resources.DEFAULT, resources.validate(dict(resources.DEFAULT)))
        a = dict(resources.DEFAULT)
        b = dict(a, memory_mib=4096, cpu_millis=2500, storage_mib=8192, log_mib=5, log_files=2)
        first, second = resources.options(a), resources.options(b)
        self.assertEqual('2147483648', first[first.index('--memory') + 1])
        self.assertEqual('2147483648', first[first.index('--memory-swap') + 1])
        self.assertEqual('4294967296', second[second.index('--memory') + 1])
        self.assertEqual('250000', second[second.index('--cpu-quota') + 1])
        self.assertIn('size=8589934592', second)
        self.assertIn('max-size=5242880', second)
        self.assertIn('max-file=2', second)
        self.assertEqual(IMAGE, resources.preflight(b, 'runner:v2', Docker(b)))

    def test_missing_unknown_and_unbounded_fields_rejected(self):
        for key in resources.DEFAULT:
            p = dict(resources.DEFAULT)
            del p[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                resources.validate(p)
        for change in ({'unknown': 1}, {'memory_mib': 0}, {'cpu_millis': -1}, {'swap_mib': -1},
                       {'swap_mib': 1}, {'log_files': 0}, {'storage_mib': 0}, {'log_driver': 'none'},
                       {'log_driver': 'journald'}, {'storage_backend': 'assumed-external'},
                       {'memory_mib': '2048;touch /tmp/no'}, {'memory_mib': True}, {'cpu_millis': 1.5},
                       {'memory_mib': 256, 'tmp_mib': 128, 'shm_mib': 64}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                resources.options(dict(resources.DEFAULT, **change))

    def test_every_numeric_range_boundary(self):
        for key, (low, high) in resources.RANGES.items():
            for value in (low - 1, high + 1):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    resources.validate(dict(resources.DEFAULT, **{key: value}))
        for change in ({'memory_mib': 256, 'tmp_mib': 16, 'shm_mib': 16}, {'cpu_millis': 100},
                       {'memory_mib': 262144, 'cpu_millis': 64000, 'storage_mib': 1048576,
                        'tmp_mib': 1024, 'shm_mib': 1024, 'log_mib': 100, 'log_files': 10}):
            resources.validate(dict(resources.DEFAULT, **change))

    def test_private_policy_missing_unsafe_and_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'resources.json'
            def load():
                return resources.read_policy(path, uid=os.getuid(), root=root)
            with self.assertRaises(OSError):
                load()
            path.write_text(json.dumps(resources.DEFAULT))
            path.chmod(0o600)
            self.assertEqual(resources.DEFAULT, load())
            path.chmod(0o644)
            with self.assertRaises(RuntimeError):
                load()
            path.chmod(0o600)
            path.write_text('{"cpu_millis": 100, "cpu_millis": 200}')
            with self.assertRaises(ValueError):
                load()
            path.unlink()
            path.symlink_to(root / 'missing')
            with self.assertRaises(OSError):
                load()

    def test_supported_host_exact_probe_options_and_cleanup(self):
        docker = Docker()
        self.assertEqual(IMAGE, resources.preflight(resources.DEFAULT, 'runner:v1', docker))
        create = next(call for call in docker.calls if call[1] == 'create')
        begin = create.index('--pull')
        end = create.index('--entrypoint')
        self.assertEqual(resources.options(resources.DEFAULT), create[begin:end])
        self.assertEqual(['/bin/sh', IMAGE, '-c', 'sleep 45'], create[end + 1:])
        self.assertIn('none', create)
        self.assertEqual(['docker', 'rm', '-f', '-v'], docker.calls[-1][:-1])

    def test_unsupported_controller_or_backend_fails_before_container(self):
        for key, value in (('OSType', 'windows'), ('SecurityOptions', ['name=rootless']), ('CgroupVersion', '1'), ('Driver', 'btrfs'),
                           ('DriverStatus', [['Backing Filesystem', 'extfs']]), ('SwapLimit', False),
                           ('MemoryLimit', False), ('CpuCfsQuota', False), ('CpuCfsPeriod', False), ('PidsLimit', False)):
            docker = Docker()
            docker.info[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                resources.preflight(resources.DEFAULT, 'runner:v1', docker)
            self.assertFalse(any(call[1] == 'create' for call in docker.calls))
        docker = Docker()
        docker.image['Config']['Volumes'] = {'/home/runner': {}}
        with self.assertRaises(RuntimeError):
            resources.preflight(resources.DEFAULT, 'runner:v1', docker)

    def test_quota_logging_or_actual_cgroup_mismatch_fails_closed(self):
        for key, value in (('Memory', 0), ('MemorySwap', -1), ('CpuQuota', 0), ('PidsLimit', 0),
                           ('LogConfig', {'Type': 'none'}), ('StorageOpt', {}), ('ShmSize', 0), ('Tmpfs', {})):
            docker = Docker()
            docker.host[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                resources.preflight(resources.DEFAULT, 'runner:v1', docker)
            self.assertEqual('rm', docker.calls[-1][1])
        for actual in ('max\n0\n100000 100000\n512', '2147483648\nmax\n100000 100000\n512',
                       '2147483648\n0\nmax 100000\n512'):
            docker = Docker()
            docker.cgroup = actual
            with self.assertRaises(RuntimeError):
                resources.preflight(resources.DEFAULT, 'runner:v1', docker)
            self.assertEqual('rm', docker.calls[-1][1])

    def test_driver_rejecting_project_quota_fails_and_start_failure_cleans(self):
        for stage in ('create', 'start', 'exec', 'rm'):
            docker = Docker()
            docker.fail = stage
            with self.subTest(stage=stage), self.assertRaises(RuntimeError):
                resources.preflight(resources.DEFAULT, 'runner:v1', docker)
            if stage in ('start', 'exec'):
                self.assertEqual('rm', docker.calls[-1][1])

    def launcher_fixture(self):
        from test_private_files import PrivateFiles
        fixture = PrivateFiles('test_0600_config_and_auth_accepted_by_both')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.launcher.write_text(fixture.launcher.read_text().replace(
            'STATE_DIR="/var/lib/ephemeral-runner/$INSTANCE"', f'STATE_DIR="{fixture.root}/state"'))
        self.call_log = fixture.root / 'calls.jsonl'
        self.curl_marker = fixture.root / 'curl-called'
        docker = fixture.bin / 'docker'
        docker.write_text(
            '#!/usr/bin/env python3\nimport json, sys\nfrom pathlib import Path\n'
            f'sys.path.insert(0, {str(ROOT / "tests")!r})\nfrom test_resources import Docker\n'
            f'policy = json.loads(Path({str(fixture.home / "resources.json")!r}).read_text())\n'
            'args = ["docker", *sys.argv[1:]]\n'
            'record = {"argv": args}\n'
            'if args[1] == "run": record["stdin"] = sys.stdin.read()\n'
            f'with open({str(self.call_log)!r}, "a") as log: log.write(json.dumps(record) + "\\n")\n'
            'if args[1:3] == ["network", "inspect"]: print("bridge")\n'
            'else: print(Docker(policy)(args))\n')
        for name, content in {
            'curl': f'#!/bin/sh\ntouch "{self.curl_marker}"\nprintf \'%s\\n\' \'{{"token":"fixture-registration"}}\'\n',
            'install': '#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\nPath(sys.argv[-1]).mkdir(parents=True, exist_ok=True)\n',
        }.items():
            path = fixture.bin / name
            path.write_text(content)
            path.chmod(0o755)
        return fixture

    def test_launcher_applies_exact_budgets_to_job_container_and_token_only_stdin(self):
        fixture = self.launcher_fixture()
        result, _ = fixture.launcher_validate()
        self.assertEqual(0, result.returncode, result.stderr.decode())
        records = [json.loads(line) for line in self.call_log.read_text().splitlines()]
        job = next(record for record in records if record['argv'][1] == 'run')
        args = job['argv']
        for flag, value in (('--memory', '2147483648'), ('--memory-swap', '2147483648'),
                            ('--cpu-period', '100000'), ('--cpu-quota', '100000'), ('--pids-limit', '512'),
                            ('--log-driver', 'json-file'), ('--storage-opt', 'size=4294967296'),
                            ('--cgroupns', 'private'), ('--shm-size', '67108864')):
            self.assertEqual(value, args[args.index(flag) + 1])
        self.assertIn('max-size=10485760', args)
        self.assertIn('max-file=3', args)
        self.assertIn('/tmp:rw,nosuid,nodev,size=128m,mode=1777', args)
        self.assertEqual(['--entrypoint', '/bin/bash', IMAGE, '/runner-entrypoint.sh'], args[-4:])
        mount = args[args.index('--mount') + 1]
        self.assertTrue(mount.endswith('dst=/runner-entrypoint.sh,readonly'))
        self.assertNotIn('dst=/tmp/', mount)
        self.assertEqual('fixture-registration\n', job['stdin'])
        self.assertFalse(any('fixture-registration' in arg for arg in args))
        self.assertEqual('10001:10001', args[args.index('--user') + 1])
        self.assertEqual('ALL', args[args.index('--cap-drop') + 1])
        self.assertIn('no-new-privileges:true', args)

    def test_launcher_bad_or_missing_policy_fails_before_github_token(self):
        fixture = self.launcher_fixture()
        policy = fixture.home / 'resources.json'
        for content in (None, '{}', json.dumps(dict(resources.DEFAULT, storage_backend='unverified')),
                        json.dumps(dict(resources.DEFAULT, memory_mib=0)),
                        json.dumps(dict(resources.DEFAULT, log_driver='none'))):
            with self.subTest(content=content):
                if content is None:
                    policy.unlink()
                else:
                    policy.write_text(content)
                    policy.chmod(0o600)
                result, _ = fixture.launcher_validate()
                self.assertNotEqual(0, result.returncode)
                self.assertFalse(self.curl_marker.exists())

    def test_launcher_unsupported_host_and_quota_fail_before_token(self):
        fixture = self.launcher_fixture()
        docker = fixture.bin / 'docker'
        original = docker.read_text()
        cases = (
            original.replace('else: print(Docker(policy)(args))',
                             'else:\n    model = Docker(policy)\n    model.info["Driver"] = "btrfs"\n    print(model(args))'),
            original.replace('record = {"argv": args}',
                             'if args[1] == "create": sys.exit(1)\nrecord = {"argv": args}'),
            original.replace('else: print(Docker(policy)(args))',
                             'else:\n    model = Docker(policy)\n    model.cgroup = "max"\n    print(model(args))'),
        )
        for content in cases:
            with self.subTest(content=content[-70:]):
                docker.write_text(content)
                result, _ = fixture.launcher_validate()
                self.assertNotEqual(0, result.returncode)
                self.assertFalse(self.curl_marker.exists())

    def test_live_harness_requires_opt_in_before_docker_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / 'docker-called'
            stub = root / 'docker'
            stub.write_text(f'#!/bin/sh\ntouch "{marker}"\nexit 1\n')
            stub.chmod(0o755)
            result = subprocess.run(['python3', str(ROOT / 'scripts/check-resource-limits.py'), '--image', 'unused'],
                                    env={**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH']},
                                    capture_output=True, timeout=10)
            self.assertNotEqual(0, result.returncode)
            self.assertFalse(marker.exists())
