"""NO-GO regressions and mocks for the explicitly opt-in component experiment."""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_resources as support

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('readonly_proof', ROOT / 'scripts/check-readonly-tmpfs.py')
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)


class Docker:
    def __init__(self):
        self.calls = []
        self.fail = None
        self.image = {'Id': support.IMAGE, 'Config': {'Volumes': {}}}
        self.host = dict(ReadonlyRootfs=True, Memory=268435456, MemorySwap=268435456,
                         CpuPeriod=100000, CpuQuota=25000, PidsLimit=64, ShmSize=8388608,
                         LogConfig={'Type': 'json-file', 'Config': {'max-size': '1048576', 'max-file': '2'}},
                         Tmpfs={'/work': 'rw,nosuid,nodev,size=8m,nr_inodes=1024,uid=10001,gid=10001,mode=0700',
                                '/tmp': 'rw,nosuid,nodev,size=8m,nr_inodes=1024,mode=1777'})
        self.mounts = [{'Type': 'tmpfs', 'Destination': '/work'}]
        self.status = '0'

    def __call__(self, args):
        self.calls.append(args)
        stage = 'image' if args[1:3] == ['image', 'inspect'] else args[1]
        if stage == self.fail:
            raise RuntimeError('injected ' + stage)
        if stage == 'info':
            data = support.Docker().info
            data['DriverStatus'] = [['Backing Filesystem', 'extfs']]
            return json.dumps(data)
        if stage == 'image':
            return json.dumps([self.image])
        if stage == 'inspect':
            return json.dumps([dict(HostConfig=self.host, Mounts=self.mounts)])
        if stage == 'wait':
            return self.status
        if stage == 'logs':
            return json.dumps({'fixture': 'mock observations, not live enforcement'})
        return 'created'


class Ext4DecisionTests(unittest.TestCase):
    def test_production_ext4_rejects_before_container_or_token(self):
        for filesystem in ('ext4', 'extfs'):
            docker = support.Docker()
            docker.info['DriverStatus'] = [['Backing Filesystem', filesystem]]
            with self.subTest(filesystem=filesystem), self.assertRaises(RuntimeError):
                support.resources.preflight(support.resources.DEFAULT, 'runner:v1', docker)
            self.assertEqual(['info'], [args[1] for args in docker.calls])
        harness = support.ResourceTests('test_launcher_unsupported_host_and_quota_fail_before_token')
        self.addCleanup(harness.doCleanups)
        fixture = harness.launcher_fixture()
        path = fixture.bin / 'docker'
        source = path.read_text().replace('else: print(Docker(policy)(args))',
            'else:\n    model = Docker(policy)\n    model.info["DriverStatus"] = [["Backing Filesystem", "extfs"]]\n    print(model(args))')
        path.write_text(source)
        result, _ = fixture.launcher_validate()
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(harness.curl_marker.exists())
        records = [json.loads(line)['argv'] for line in harness.call_log.read_text().splitlines()]
        self.assertFalse(any(args[1] in ('create', 'start', 'run') for args in records))

    def test_unreviewed_backend_versions_and_unbounded_binds_remain_rejected(self):
        for backend in ('readonly-tmpfs-v1', 'ext4-bind', 'loopback-v1', 'ext4-monitor'):
            with self.subTest(backend=backend), self.assertRaises(ValueError):
                support.resources.options(dict(support.resources.DEFAULT, storage_backend=backend))

    def test_probe_observations_are_not_production_acceptance(self):
        docker = Docker()
        result = proof.probe('local:v1', docker)
        self.assertIn('NO RUNNER BACKEND ACCEPTANCE', result['status'])
        self.assertTrue(result['configured']['HostConfig']['ReadonlyRootfs'])
        self.assertEqual('mock observations, not live enforcement', result['observed']['fixture'])
        args = next(args for args in docker.calls if args[1] == 'create')
        self.assertIn('--read-only', args)
        self.assertEqual('none', args[args.index('--network') + 1])
        self.assertEqual('10001:10001', args[args.index('--user') + 1])
        self.assertNotIn('--privileged', args)
        self.assertNotIn('--mount', args)
        self.assertNotIn('--volume', args)
        self.assertEqual('rm', docker.calls[-1][1])
        self.assertEqual(args[args.index('--name') + 1], docker.calls[-1][-1])
        compile(proof.PAYLOAD, '<component-proof-payload>', 'exec')

    def test_probe_rejects_image_volumes_and_writable_bind_bypass(self):
        docker = Docker()
        docker.image['Config']['Volumes'] = {'/work': {}}
        with self.assertRaises(RuntimeError):
            proof.probe('local:v1', docker)
        self.assertFalse(any(args[1] == 'create' for args in docker.calls))
        for key, value in (('Binds', ['/arbitrary:/work']), ('Mounts', [{'Type': 'bind'}]),
                           ('ReadonlyRootfs', False), ('Memory', 0), ('MemorySwap', -1),
                           ('Tmpfs', {'/work': 'rw'}), ('LogConfig', {'Type': 'none'})):
            docker = Docker()
            docker.host[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                proof.probe('local:v1', docker)
            self.assertFalse(any(args[1] == 'start' for args in docker.calls))
            self.assertEqual('rm', docker.calls[-1][1])
        docker = Docker()
        docker.mounts = [{'Type': 'volume', 'Destination': '/work'}]
        with self.assertRaises(RuntimeError):
            proof.probe('local:v1', docker)

    def test_probe_failures_clean_only_its_created_container(self):
        for stage in ('info', 'image', 'create', 'inspect', 'start', 'wait', 'logs', 'rm'):
            docker = Docker()
            docker.fail = stage
            with self.subTest(stage=stage), self.assertRaises(RuntimeError):
                proof.probe('local:v1', docker)
            created = stage not in ('info', 'image', 'create')
            self.assertEqual(created, any(args[1] == 'rm' for args in docker.calls))
        docker = Docker()
        docker.status = '7'  # unusable path, quota assertion or cgroup mismatch in payload
        with self.assertRaises(RuntimeError):
            proof.probe('local:v1', docker)
        self.assertEqual('rm', docker.calls[-1][1])

    def test_opt_in_and_capacity_guard_before_any_docker_call(self):
        with patch.object(proof.sys, 'platform', 'linux'), patch.object(proof.os, 'geteuid', return_value=0), \
                patch.object(proof.sys, 'argv', ['proof', '--image', 'unused']), \
                patch.object(proof, 'probe', side_effect=AssertionError('unexpected Docker proof')) as probe:
            with self.assertRaises(RuntimeError):
                proof.main()
            probe.assert_not_called()
        with patch.object(proof.sys, 'platform', 'linux'), patch.object(proof.os, 'geteuid', return_value=0), \
                patch.object(proof.sys, 'argv', ['proof', '--disposable-host', '--image', 'unused']), \
                patch.object(proof.Path, 'read_text', return_value='MemAvailable: 128 kB\n'), \
                patch.object(proof, 'probe', side_effect=AssertionError('unexpected Docker proof')) as probe:
            with self.assertRaises(RuntimeError):
                proof.main()
            probe.assert_not_called()

    def test_concurrent_proofs_share_no_names_or_host_mounts(self):
        models = [Docker(), Docker()]
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda model: proof.probe('local:v1', model), models))
        self.assertEqual(2, len(results))
        names = [next(args for args in model.calls if args[1] == 'create')[3] for model in models]
        self.assertEqual(2, len(set(names)))
        for name, model in zip(names, models):
            self.assertEqual(name, model.calls[-1][-1])
