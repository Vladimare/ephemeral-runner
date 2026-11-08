"""No live Linux operations: exercise exact workflow gates and harness evidence policy."""
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_ext4_poc as support

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('live_harness', ROOT / 'scripts/ext4-live-proof.py')
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)
HEAD = 'a' * 40


def event():
    return dict(action='labeled', label={'name': 'ext4-live-proof'}, pull_request=dict(number=16,
        head={'sha': HEAD, 'ref': live.BRANCH, 'repo': {'full_name': live.REPO}}, base={'ref': 'main'}))


def environment():
    return dict(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='Linux',
                RUNNER_ARCH='X64', ImageOS='ubuntu24', ImageVersion='fixture-version', GITHUB_REPOSITORY=live.REPO,
                GITHUB_EVENT_NAME='pull_request', PROOF_HEAD_SHA=HEAD, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1',
                GITHUB_WORKFLOW_SHA='b' * 40)


def evaluate_gate(node, context):
    """Restricted evaluator for the actual Actions if-expression; never eval code."""
    if isinstance(node, ast.Expression): return evaluate_gate(node.body, context)
    if isinstance(node, ast.Name): return context[node.id]
    if isinstance(node, ast.Constant): return node.value
    if isinstance(node, ast.Attribute): return evaluate_gate(node.value, context)[node.attr]
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        return all(evaluate_gate(x, context) for x in node.values)
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
        return evaluate_gate(node.left, context) == evaluate_gate(node.comparators[0], context)
    raise AssertionError('Unreviewed workflow expression node')


class LiveValidationTests(unittest.TestCase):
    def test_exact_workflow_gate_rejects_forks_other_prs_labels_and_events(self):
        workflow = (ROOT / '.github/workflows/ext4-live-proof.yml').read_text()
        expression = workflow.split('    if: >-\n', 1)[1].split('    runs-on:', 1)[0]
        tree = ast.parse(' '.join(expression.split()).replace('&&', 'and'), mode='eval')
        def allowed(e, **overrides):
            context = dict(event_name='pull_request', repository=live.REPO, event=e)
            context.update(overrides)
            return evaluate_gate(tree, {'github': context})
        self.assertTrue(allowed(event()))
        cases = []
        for field, value in (('action', 'synchronize'), ('action', 'opened')):
            e = event(); e[field] = value; cases.append(e)
        e = event(); e['label']['name'] = 'Ext4-live-proof'; cases.append(e)
        e = event(); e['label']['name'] = 'other'; cases.append(e)
        e = event(); e['pull_request']['number'] = 17; cases.append(e)
        e = event(); e['pull_request']['head']['repo']['full_name'] = 'attacker/fork'; cases.append(e)
        e = event(); e['pull_request']['head']['ref'] = 'other'; cases.append(e)
        e = event(); e['pull_request']['base']['ref'] = 'other'; cases.append(e)
        for e in cases:
            with self.subTest(event=e): self.assertFalse(allowed(e))
        self.assertFalse(allowed(event(), event_name='push'))
        self.assertFalse(allowed(event(), repository='attacker/fork'))

    def test_workflow_dormancy_host_permissions_and_artifact_contract(self):
        text = (ROOT / '.github/workflows/ext4-live-proof.yml').read_text()
        trigger = text.split('on:\n', 1)[1].split('\npermissions:', 1)[0]
        self.assertEqual('  pull_request:\n    types: [labeled]', trigger.strip('\n'))
        self.assertIn('    runs-on: ubuntu-24.04\n', text)
        self.assertNotIn('self-hosted', text)
        self.assertNotIn('ubuntu-slim', text)
        self.assertNotIn('pull_request_target', text)
        self.assertNotIn('secrets.', text)
        self.assertIn('permissions:\n  contents: read', text)
        self.assertIn('timeout-minutes: 20', text)
        self.assertIn('cancel-in-progress: false', text)
        self.assertIn('persist-credentials: false', text)
        self.assertIn('ref: ${{ github.event.pull_request.head.sha }}', text)
        for action in re.findall(r'uses: (\S+)', text):
            self.assertRegex(action, r'^actions/(checkout|upload-artifact)@[a-f0-9]{40}$')
        self.assertEqual(2, text.count('if: ${{ always() }}'))
        self.assertIn('retention-days: 7', text)
        self.assertIn('path: ${{ runner.temp }}/ext4-live-evidence.json', text)
        self.assertNotIn('gh pr', text)
        self.assertNotIn('workflow_dispatch', text)

    def test_root_hosted_guard_exact_head_and_run_identity(self):
        live.guard(environment(), event(), HEAD, system='Linux', uid=0)
        for key, value in (('RUNNER_ENVIRONMENT', 'self-hosted'), ('ImageOS', 'ubuntu22'),
                           ('RUNNER_ARCH', 'ARM64'), ('GITHUB_EVENT_NAME', 'push'),
                           ('GITHUB_RUN_ID', '../unsafe'), ('PROOF_HEAD_SHA', 'b' * 40)):
            env = environment(); env[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                live.guard(env, event(), HEAD, system='Linux', uid=0)
        for system, uid in (('Darwin', 0), ('Linux', 1000)):
            with self.assertRaises(RuntimeError): live.guard(environment(), event(), HEAD, system=system, uid=uid)

    def test_ungated_cli_has_no_host_side_effects(self):
        result = subprocess.run(['python3', str(ROOT / 'scripts/ext4-live-proof.py'), '--run'],
                                env={'PATH': os.environ['PATH']}, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual('NOT RUN', json.loads(result.stdout)['live_evidence'])

    def test_redaction_and_daemon_inspect_allowlist(self):
        state = {'evidence': {'docker_info': {'OSType': 'linux', 'Name': 'host', 'HTTPProxy': 'secret'},
                 'docker_inspect': {'Id': 'id', 'Config': {'User': '10001:10001', 'Env': ['PASSWORD=secret']},
                                    'Args': ['secret']}}}
        result = live.sanitize_state(state)
        self.assertEqual({'OSType': 'linux'}, result['evidence']['docker_info'])
        self.assertNotIn('Env', result['evidence']['docker_inspect']['Config'])
        text = json.dumps(live.redact({'token': 'private', 'log': 'Bearer ABC ghp_abcdef https://user:pw@host/path'}))
        for private in ('private', 'ABC', 'ghp_abcdef', 'user:pw'):
            self.assertNotIn(private, text)

    def successful_state(self):
        c = support.container('/owned/mnt')
        observed = {'bytes': 'ENOSPC', 'inodes': {'result': 'ENOSPC', 'created': 1000},
                    'statfs': {'bytes': 64 * live.MIB, 'inodes': 1024},
                    'memory.max': '268435456', 'memory.swap.max': '0',
                    'cpu.max': '25000 100000', 'pids.max': '64', 'mountinfo': 'actual fixture mountinfo'}
        return dict(directory='/owned', name='test', nonce='nonce', image_id=support.IMAGE, pending=None,
                    tests={'linux_enforcement': 'PASS', 'cleanup': 'PASS'},
                    evidence={'probe': observed, 'docker_inspect': c, 'host_mountinfo': 'fixture',
                              'backing': {'size': 64 * live.MIB, 'allocated': 64 * live.MIB}})

    def test_report_requires_observations_not_just_pass_status(self):
        state = self.successful_state()
        self.assertEqual('PASS', live.validate_result(state, support.IMAGE, support.poc))
        for key in ('bytes', 'inodes', 'statfs', 'mountinfo', 'memory.swap.max'):
            broken = copy.deepcopy(state); del broken['evidence']['probe'][key]
            with self.subTest(key=key), self.assertRaises((RuntimeError, KeyError)):
                live.validate_result(broken, support.IMAGE, support.poc)
        for change in ({'cleanup_failure': 'busy mount'}, {'loop': '/dev/loop7'}, {'pending': 'detach'}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                live.validate_result(dict(state, **change), support.IMAGE, support.poc)
        broken = copy.deepcopy(state); broken['evidence']['probe']['memory.swap.max'] = 'max'
        with self.assertRaises(RuntimeError): live.validate_result(broken, support.IMAGE, support.poc)
        broken = copy.deepcopy(state); broken['evidence']['docker_inspect']['Config']['Labels'] = {}
        with self.assertRaises(RuntimeError): live.validate_result(broken, support.IMAGE, support.poc)

    def test_builder_uses_immutable_iid_and_no_tag_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            calls = []
            def fake(args, **kwargs):
                calls.append(args)
                if args[1] == 'build':
                    Path(args[args.index('--iidfile') + 1]).write_text(support.IMAGE)
                else:
                    return json.dumps([{'Id': support.IMAGE, 'Config': {}}])
                return ''
            record = {}
            self.assertEqual(support.IMAGE, live.build_images(ROOT, base, record, fake))
            builds = [args for args in calls if args[1] == 'build']
            self.assertIn('BASE=' + support.IMAGE, builds[1])
            self.assertIn('--network=none', builds[1])
            self.assertNotIn('-t', builds[1])
            self.assertRegex(record['archive_sha256'], r'^[a-f0-9]{64}$')
            self.assertEqual(support.IMAGE, record['base_id'])

    def test_command_scrubs_environment_and_pins_local_daemon(self):
        with patch.object(live.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='', stderr='')) as run:
            live.command(['docker', 'build', '.'])
            args = run.call_args.args[0]
            self.assertEqual(['docker', '--host', 'unix:///var/run/docker.sock'], args[:3])
            env = run.call_args.kwargs['env']
            self.assertEqual('0', env['DOCKER_BUILDKIT'])
            self.assertNotIn('GITHUB_TOKEN', env)
            self.assertEqual('/nonexistent', env['DOCKER_CONFIG'])

    def test_nonext4_prerequisite_is_skip_not_silent_fallback(self):
        record = {}
        with patch.object(live.shutil, 'which', return_value='/usr/bin/tool'), \
                patch.object(live.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='version', stderr='')), \
                patch.object(live.Path, 'read_text', return_value='cpu memory pids'):
            def fake(args):
                if args[:2] == ['docker', 'info']:
                    return json.dumps(dict(OSType='linux', CgroupVersion='2', MemoryLimit=True, SwapLimit=True, CpuCfsQuota=True, CpuCfsPeriod=True, PidsLimit=True))
                if args[:2] == ['docker', 'version']: return json.dumps({'Client': {}, 'Server': {}})
                return 'overlay rw' if args[0] == 'findmnt' else 'tool version'
            with self.assertRaises(live.Skip): live.prerequisites(Path('/unused'), fake, record)
        self.assertEqual('overlay rw', record['scratch_findmnt'])
        self.assertIn('losetup', record['tools'])

    def test_locate_attempt_falls_back_to_owned_journal_when_stderr_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            nonce = 'a' * 32
            directory = base / ('probe-' + nonce)
            directory.mkdir(mode=0o700)
            journal = directory / 'journal.json'
            real = directory.lstat()
            state = dict(directory=str(directory), directory_identity=[real.st_dev, real.st_ino],
                         nonce=nonce, name='er-ext4-' + nonce)
            journal.write_text(json.dumps(state))
            (base / 'serial.stderr').write_text('')
            patched = SimpleNamespace(st_mode=real.st_mode, st_uid=0, st_dev=real.st_dev, st_ino=real.st_ino,
                                     st_mtime_ns=10)
            with patch.object(live, 'private_json', return_value=state), \
                    patch.object(Path, 'lstat', return_value=patched):
                self.assertEqual(state, live.locate_attempt(base, {'key': 'serial'}))

    def test_locate_attempt_chooses_latest_exact_owned_journal_when_multiple_are_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            newest = base / ('probe-' + ('a' * 32))
            stale = base / ('probe-' + ('b' * 32))
            for directory in (newest, stale):
                directory.mkdir(mode=0o700)
            newest_journal = newest / 'journal.json'
            stale_journal = stale / 'journal.json'
            newest_state = dict(directory=str(newest), directory_identity=[newest.lstat().st_dev, newest.lstat().st_ino],
                               nonce='a' * 32, name='er-ext4-' + ('a' * 32))
            stale_state = dict(directory=str(stale), directory_identity=[stale.lstat().st_dev, stale.lstat().st_ino],
                              nonce='b' * 32, name='er-ext4-' + ('b' * 32))
            newest_journal.write_text(json.dumps(newest_state))
            stale_journal.write_text(json.dumps(stale_state))
            (base / 'serial.stderr').write_text('')
            with patch.object(live, 'private_json', side_effect=[newest_state, stale_state]), \
                    patch.object(Path, 'lstat', side_effect=[
                        SimpleNamespace(st_mode=0o40700, st_uid=0, st_dev=newest.lstat().st_dev, st_ino=newest.lstat().st_ino,
                                       st_mtime_ns=20),
                        SimpleNamespace(st_mode=0o40700, st_uid=0, st_dev=stale.lstat().st_dev, st_ino=stale.lstat().st_ino,
                                       st_mtime_ns=10),
                    ]):
                self.assertEqual(newest_state, live.locate_attempt(base, {'key': 'serial'}))

    def test_collect_rejects_unknown_paths_and_preserves_unresolved_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with patch.object(live, 'private_json', return_value={'status': 'FAIL', 'attempts': [{'key': '../unowned'}]}):
                with self.assertRaises(RuntimeError): live.collect(base)
            report = {'status': 'FAIL', 'attempts': [{'key': 'serial'}]}
            with patch.object(live, 'private_json', return_value=report):
                result = live.collect(base)
            self.assertEqual('FAIL', result['status'])
            self.assertEqual('UNRESOLVED', result['attempts'][0]['journal']['status'])
            self.assertIn('UNRESOLVED', result['attempts'][0]['stderr'])

    def test_safe_failure_probe_requires_real_rejection_and_no_new_entries(self):
        report = {}
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with patch.object(live.subprocess, 'run', return_value=SimpleNamespace(returncode=1,
                    stderr='Require trusted local immutable sha256 image ID', stdout='')):
                live.failure_probe(base, ROOT, report)
            self.assertEqual('PASS', report['invalid_image_rejected_before_setup']['status'])
            with patch.object(live.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stderr='', stdout='')):
                with self.assertRaises(RuntimeError): live.failure_probe(base, ROOT, report)
            def changes_path(*args, **kwargs):
                (base / 'unexpected-allocation').touch()
                return SimpleNamespace(returncode=1, stderr='Require trusted local immutable sha256 image ID', stdout='')
            with patch.object(live.subprocess, 'run', side_effect=changes_path):
                with self.assertRaises(RuntimeError): live.failure_probe(base, ROOT, report)

    def test_atomic_evidence_write_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            path = base / 'report.json'
            live.write_json(path, {'status': 'NOT RUN'})
            live.write_json(path, {'status': 'FAIL'})
            self.assertEqual('FAIL', json.loads(path.read_text())['status'])
            (base / 'report.next').symlink_to(base / 'unowned')
            with self.assertRaises(OSError): live.write_json(path, {})
            self.assertFalse((base / 'unowned').exists())

    def test_execute_retains_skip_no_go_without_building(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / 'new'
            poc = SimpleNamespace(private_directory=lambda _: None)
            env = dict(environment(), ImageVersion='fixture', GITHUB_WORKFLOW_SHA='b' * 40)
            with patch.object(live.Path, 'lstat', return_value=SimpleNamespace(st_mode=0o40700, st_uid=0)), \
                    patch.object(live, 'prerequisites', side_effect=live.Skip('loop unavailable')), \
                    patch.object(live, 'build_images') as build, patch('sys.stdout'):
                self.assertEqual(1, live.execute(env, ROOT, base, poc))
            saved = json.loads((base / 'harness.json').read_text())
            self.assertEqual('SKIP', saved['status'])
            self.assertEqual('NO-GO on this VM', saved['decision'])
            self.assertEqual('NOT RUN', saved['sigkill_daemon_outage_busy_mount_reboot'])
            self.assertEqual([], saved['attempts'])
            build.assert_not_called()

    def test_overlap_requires_real_start_times_not_sequential_running_snapshots(self):
        first = {'query_started': 20, 'container': {'RestartCount': 0,
                 'State': {'Running': True, 'StartedAt': '1970-01-01T00:00:10Z'}}}
        second = {'query_started': 21, 'container': {'RestartCount': 0,
                  'State': {'Running': True, 'StartedAt': '1970-01-01T00:00:12Z'}}}
        self.assertTrue(live.observed_overlap([first, second]))
        second['container']['State']['StartedAt'] = '1970-01-01T00:00:20.5Z'
        self.assertFalse(live.observed_overlap([first, second]))
        self.assertFalse(live.observed_overlap([first]))
        second['container']['State']['StartedAt'] = 'invalid'
        self.assertFalse(live.observed_overlap([first, second]))

    def test_probe_group_invokes_actual_cli_and_retains_parallel_evidence(self):
        class Process:
            def __init__(self): self.polls = 0
            def poll(self):
                self.polls += 1
                return None if self.polls < 4 else 0
            def wait(self): return 0
        sample = {'loop': {'loopdevices': ['fixture']}, 'query_started': 20,
                  'container': {'RestartCount': 0, 'State': {'Running': True, 'StartedAt': '1970-01-01T00:00:10Z'}}}
        with tempfile.TemporaryDirectory() as tmp:
            report = {'attempts': [], 'container_overlap': 'NOT RUN'}
            with patch.object(live.subprocess, 'Popen', side_effect=lambda *a, **kw: Process()) as popen, \
                    patch.object(live, 'observe', return_value=sample), \
                    patch.object(live, 'verify_cleanup'), \
                    patch.object(live, 'locate_attempt', return_value=self.successful_state()), \
                    patch.object(live.time, 'sleep'):
                live.probe_group(Path(tmp), ROOT, support.IMAGE, ['parallel-a', 'parallel-b'], report, support.poc)
            self.assertEqual(['PASS', 'PASS'], [a['status'] for a in report['attempts']])
            self.assertEqual('PASS', report['container_overlap'])
            for call in popen.call_args_list:
                argv = call.args[0]
                self.assertIn(str(ROOT / 'scripts/ext4-workspace-poc.py'), argv)
                self.assertIn('--disposable-host', argv)
                self.assertEqual(support.IMAGE, argv[-1])
                self.assertNotIn('GITHUB_TOKEN', call.kwargs['env'])

    def test_group_nonzero_is_failure_even_with_pass_journal(self):
        class Process:
            def poll(self): return 1
            def wait(self): return 1
        with tempfile.TemporaryDirectory() as tmp:
            report = {'attempts': []}
            with patch.object(live.subprocess, 'Popen', return_value=Process()), \
                    patch.object(live, 'locate_attempt', return_value=self.successful_state()):
                with self.assertRaises(RuntimeError):
                    live.probe_group(Path(tmp), ROOT, support.IMAGE, ['serial'], report, support.poc)
            self.assertEqual('FAIL', report['attempts'][0]['status'])
            self.assertEqual(1, report['attempts'][0]['returncode'])

    def test_loop_observation_rejects_mismatched_backing_or_size(self):
        state = dict(image_id=support.IMAGE, loop='/dev/loop7', loop_rdev=os.makedev(7, 7),
                     backing_identity=[os.makedev(8, 1), 42], directory='/owned')
        entries = {'loopdevices': [{'name': '/dev/loop7', 'back-file': '/unowned/disk.img',
                   'back-ino': 42, 'back-maj:min': '8:1', 'offset': 0, 'sizelimit': 64 * live.MIB}]}
        with patch.object(live, 'locate_attempt', return_value=state), \
                patch.object(live.os, 'stat', return_value=SimpleNamespace(st_rdev=os.makedev(7, 7))):
            with self.assertRaises(RuntimeError):
                live.observe(Path('/unused'), {'key': 'serial'}, support.IMAGE, lambda _: json.dumps(entries))

    def test_successful_probes_without_witnessed_overlap_fail_overall(self):
        for overlap, expected in [('NOT RUN', 1), ('PASS', 0)]:
            with self.subTest(overlap=overlap), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp) / 'new'
                def probes(base, workspace, image, keys, report, poc):
                    report['attempts'].extend({'key': k, 'status': 'PASS'} for k in keys)
                    report['container_overlap'] = overlap
                with patch.object(live.Path, 'lstat', return_value=SimpleNamespace(st_mode=0o40700, st_uid=0)), \
                        patch.object(live, 'prerequisites'), patch.object(live, 'build_images', return_value=support.IMAGE), \
                        patch.object(live, 'probe_group', side_effect=probes), patch.object(live, 'failure_probe'), patch('sys.stdout'):
                    result = live.execute(environment(), ROOT, base, SimpleNamespace(private_directory=lambda _: None))
                self.assertEqual(expected, result)
                report = json.loads((base / 'harness.json').read_text())
                self.assertEqual('PASS' if expected == 0 else 'FAIL', report['status'])
                self.assertTrue(all(a['status'] == 'PASS' for a in report['attempts']))

    def test_independent_cleanup_absence_lingering_and_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            state = self.successful_state()
            state.update(directory=str(directory), backing_identity=[os.makedev(8, 1), 42], loop_rdev=os.makedev(7, 7))
            attempt = {'observations': [{'loop': {'loopdevices': [{'name': '/dev/loop7'}]}}]}
            unrelated_container = {'ID': 'f' * 64, 'Names': 'unrelated'}
            unrelated_loop = {'name': '/dev/loop8', 'back-file': '/unrelated/disk.img',
                              'back-ino': 43, 'back-maj:min': '8:1'}
            cases = ['absent', 'container-id', 'container-name', 'loop-name', 'loop-inode',
                     'loop-path', 'mount-target', 'mount-device', 'backing', 'daemon-unavailable']
            for case in cases:
                with self.subTest(case=case):
                    backing = directory / 'disk.img'
                    if case == 'backing': backing.touch()
                    containers = [dict(unrelated_container)]
                    loops = [dict(unrelated_loop)]
                    mount = '99 1 7:8 / /unrelated rw - ext4 /dev/loop8 rw'
                    if case == 'container-id': containers[0]['ID'] = state['evidence']['docker_inspect']['Id']
                    if case == 'container-name': containers[0]['Names'] = state['name']
                    if case == 'loop-name': loops[0]['name'] = '/dev/loop7'
                    if case == 'loop-inode': loops[0]['back-ino'] = 42
                    if case == 'loop-path': loops[0]['back-file'] = str(backing)
                    if case == 'mount-target': mount = f'99 1 7:8 / {directory}/mnt rw - ext4 /dev/loop8 rw'
                    if case == 'mount-device': mount = '99 1 7:7 / /elsewhere rw - ext4 /dev/loop7 rw'
                    def run(args):
                        if args[0] == 'docker':
                            if case == 'daemon-unavailable': raise RuntimeError('daemon unavailable')
                            return '\n'.join(json.dumps(c) for c in containers)
                        return json.dumps({'loopdevices': loops})
                    proof = {}
                    with patch.object(live.Path, 'read_text', return_value=mount):
                        if case == 'absent':
                            live.verify_cleanup(state, attempt, proof, run)
                            self.assertEqual('PASS', proof['status'])
                            self.assertEqual([], proof['container']['matches'])
                        else:
                            with self.assertRaises(RuntimeError): live.verify_cleanup(state, attempt, proof, run)
                            self.assertNotEqual('PASS', proof['status'])
                    if backing.exists(): backing.unlink()

    def test_cleanup_query_timeout_fails_attempt_despite_poc_pass(self):
        process = SimpleNamespace(poll=lambda: 0, wait=lambda: 0)
        with tempfile.TemporaryDirectory() as tmp:
            report = {'attempts': []}
            with patch.object(live.subprocess, 'Popen', return_value=process), \
                    patch.object(live, 'locate_attempt', return_value=self.successful_state()), \
                    patch.object(live, 'verify_cleanup', side_effect=subprocess.TimeoutExpired('docker', 120)):
                with self.assertRaises(RuntimeError):
                    live.probe_group(Path(tmp), ROOT, support.IMAGE, ['serial'], report, support.poc)
            self.assertEqual('FAIL', report['attempts'][0]['status'])
            self.assertIn('timed out', report['attempts'][0]['reason'])
