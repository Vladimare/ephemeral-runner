"""Behavioral installer tests: real temporary files/locks; fake external commands."""
import contextlib
import importlib.util
import io
import multiprocessing
import os
from pathlib import Path
import shutil
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('installer', Path(__file__).resolve().parents[1] / 'scripts/installer.py')
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)
SOURCE = Path(__file__).resolve().parents[1]


def command(args):
    if args[:2] == ['systemctl', 'show']:
        return 'inactive'
    if args[:3] == ['docker', 'network', 'inspect']:
        return 'bridge'
    return ''


def concurrent(root, source, barrier, results):
    installer = mod.Installer(source, Path(root), os.getuid(), command)
    barrier.wait()
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            installer.instance('instance-install', 'same', 'v1', 'owner/repo', 'ci-net', 'runner:v1')
        results.put('installed')
    except RuntimeError:
        results.put('refused')


def concurrent_runtime(root, source, barrier, results):
    installer = mod.Installer(source, Path(root), os.getuid(), command)
    barrier.wait()
    try:
        installer.runtime_install('racing')
        results.put('installed')
    except RuntimeError:
        results.put('refused')


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'host'
        self.root.mkdir()
        self.source = Path(self.temp.name) / 'source'
        shutil.copytree(SOURCE, self.source, ignore=shutil.ignore_patterns('.git', '__pycache__'))
        self.calls = []
        def run(args):
            self.calls.append(args)
            return command(args)
        self.installer = mod.Installer(self.source, self.root, os.getuid(), run)
        self.installer.runtime_install('v1')

    def install(self, name='a', version='v1'):
        with contextlib.redirect_stdout(io.StringIO()):
            self.installer.instance('instance-install', name, version, 'owner/' + name, 'ci-net', 'runner:v1')

    def home(self, name='a'):
        return self.installer.base / 'instances' / name

    def snapshot(self, path):
        return {str(p.relative_to(path)): (os.readlink(p) if p.is_symlink() else p.read_bytes(), p.lstat().st_mode)
                for p in path.rglob('*') if p.is_symlink() or p.is_file()}

    def test_instances_and_versions_are_isolated(self):
        self.install()
        (self.home() / 'auth.curl.conf').write_text('dummy PAT')
        before = self.snapshot(self.home())
        release = self.snapshot(self.installer.releases / 'v1')
        self.install('b')
        (self.source / 'docker/entrypoint.sh').write_text('# changed v2\n')
        with self.assertRaises(RuntimeError):
            self.installer.runtime_install('v1')
        self.installer.runtime_install('v2')
        self.install('c', 'v2')
        self.assertEqual(before, self.snapshot(self.home()))
        self.assertEqual(release, self.snapshot(self.installer.releases / 'v1'))
        self.assertEqual('profiles/v2', os.readlink(self.home('c') / 'current'))
        self.assertNotEqual((self.home() / 'config.env').read_text(), (self.home('b') / 'config.env').read_text())
        self.assertEqual(0o600, (self.home() / 'auth.curl.conf').stat().st_mode & 0o777)
        for name in self.installer.names('a'):
            text = (self.installer.units / name).read_text()
            if name.endswith('.service'):
                self.assertIn('/releases/v1/scripts/', text)
        self.assertFalse(any('start' in call or 'restart' in call for call in self.calls))

    def test_each_instance_boundary_is_retryable_and_preserves_a(self):
        self.install()
        before = self.snapshot(self.home())
        stages = ['config', 'auth', 'instance-publish', 'reload'] + ['unit:' + n for n in self.installer.names('b')] + ['publish:' + n for n in self.installer.names('b')]
        for stage in stages:
            with self.subTest(stage=stage):
                def fail(current):
                    if current == stage:
                        raise RuntimeError('injected ' + current)
                self.installer.checkpoint = fail
                with self.assertRaises(RuntimeError):
                    self.install('b')
                self.assertFalse(self.home('b').exists())
                self.assertEqual(before, self.snapshot(self.home()))
                self.installer.checkpoint = lambda _: None
                self.install('b')
                # Remove this test instance under the same recovery mechanism.
                journal = self.installer.base / 'transaction-b.json'
                self.installer.write(journal, '{"previous": null}')
                self.installer.instance('recover', 'b')

    def test_shared_script_failures_retry_and_leave_existing_instance(self):
        self.install()
        before = self.snapshot(self.home())
        for name in mod.FILES:
            with self.subTest(name=name):
                def fail(stage):
                    if stage == 'shared:' + name:
                        raise RuntimeError('injected')
                self.installer.checkpoint = fail
                with self.assertRaises(RuntimeError):
                    self.installer.runtime_install('v2')
                self.assertFalse((self.installer.releases / 'v2').exists())
                self.assertEqual(before, self.snapshot(self.home()))
        self.installer.checkpoint = lambda _: None
        self.installer.runtime_install('v2')

    def test_upgrade_rollback_preserves_credentials_config_and_state(self):
        self.install()
        home = self.home()
        (home / 'auth.curl.conf').write_text('dummy credential')
        state = self.installer.path('/var/lib/ephemeral-runner/a')
        state.mkdir(parents=True)
        (state / 'current-name').write_text('keep state')
        self.installer.runtime_install('v2')
        config = (home / 'config.env').read_bytes()
        self.installer.instance('upgrade', 'a', 'v2')
        self.assertEqual('profiles/v2', os.readlink(home / 'current'))
        self.installer.instance('upgrade', 'a', 'v1')
        self.assertEqual('profiles/v1', os.readlink(home / 'current'))
        self.assertEqual(config, (home / 'config.env').read_bytes())
        self.assertEqual('dummy credential', (home / 'auth.curl.conf').read_text())
        self.assertEqual('keep state', (state / 'current-name').read_text())

    def test_reload_failure_and_interrupted_recovery(self):
        self.install()
        self.installer.runtime_install('v2')
        def fail(args):
            if args == ['systemctl', 'daemon-reload']:
                raise RuntimeError('reload unavailable')
            return command(args)
        self.installer.run = fail
        with self.assertRaises(RuntimeError):
            self.installer.instance('upgrade', 'a', 'v2')
        self.assertEqual('profiles/v1', os.readlink(self.home() / 'current'))
        self.assertTrue((self.installer.base / 'transaction-a.json').exists())
        self.installer.run = command
        self.installer.instance('recover', 'a')
        self.assertFalse((self.installer.base / 'transaction-a.json').exists())

    def test_new_instance_daemon_reload_failure_recovers_then_retries(self):
        failures = 1
        def fail_once(args):
            nonlocal failures
            if args == ['systemctl', 'daemon-reload'] and failures:
                failures -= 1
                raise RuntimeError('reload failed')
            return command(args)
        self.installer.run = fail_once
        with self.assertRaises(RuntimeError):
            self.install()
        self.assertFalse(self.home().exists())
        self.assertFalse((self.installer.base / 'transaction-a.json').exists())
        self.install()

    def test_live_and_unknown_states_fail_closed(self):
        self.install()
        self.installer.runtime_install('v2')
        before = self.snapshot(self.home())
        for state in ('active', 'activating', 'deactivating', '', 'reloading'):
            self.installer.run = lambda args: state
            with self.assertRaises(RuntimeError):
                self.installer.instance('upgrade', 'a', 'v2')
            self.assertEqual(before, self.snapshot(self.home()))

    def test_active_cleanup_timer_or_service_blocks_upgrade(self):
        self.install()
        self.installer.runtime_install('v2')
        for busy in self.installer.names('a')[1:]:
            self.installer.run = lambda args: 'active' if args[-1] == busy else command(args)
            with self.assertRaises(RuntimeError):
                self.installer.instance('upgrade', 'a', 'v2')
            self.assertEqual('profiles/v1', os.readlink(self.home() / 'current'))

    def test_existing_pat_and_legacy_config_never_overwritten(self):
        legacy = self.installer.base / 'a.curl.conf'
        legacy.write_text('secret')
        with self.assertRaises(RuntimeError):
            self.install()
        self.assertEqual('secret', legacy.read_text())
        legacy.unlink()
        self.install()
        before = self.snapshot(self.home())
        with self.assertRaises(RuntimeError):
            self.install()
        self.assertEqual(before, self.snapshot(self.home()))

    def test_symlink_lock_directory_and_instance_are_rejected(self):
        external = Path(self.temp.name) / 'outside'
        external.mkdir()
        os.symlink(external, self.installer.base / 'instances')
        with self.assertRaises(RuntimeError):
            self.install()
        self.assertEqual([], list(external.iterdir()))
        (self.installer.base / 'instances').unlink()
        lock = self.installer.base / 'locks' / 'instance-a'
        lock.unlink()
        os.symlink(external / 'untouched', lock)
        with self.assertRaises(OSError):
            self.install()
        self.assertFalse((external / 'untouched').exists())

    def test_missing_or_damaged_release_rejected_before_instance_publication(self):
        with self.assertRaises(RuntimeError):
            self.install(version='missing')
        self.assertFalse((self.installer.releases / 'missing').exists())
        (self.installer.releases / 'v1/docker/entrypoint.sh').write_text('tampered')
        with self.assertRaises(RuntimeError):
            self.install()
        self.assertFalse(self.home().exists())

    def test_interruption_preserves_published_auth_and_recovery_is_idempotent(self):
        class PowerLoss(BaseException):
            pass
        def crash(stage):
            if stage == 'publish:' + self.installer.names('a')[0]:
                raise PowerLoss()
        self.installer.checkpoint = crash
        with self.assertRaises(PowerLoss):
            self.install()
        (self.home() / 'auth.curl.conf').write_text('credential entered after crash')
        self.installer.instance('recover', 'a')
        self.installer.instance('recover', 'a')
        recovered = list(self.home().parent.glob('.recovered-a-*'))
        self.assertEqual(1, len(recovered))
        self.assertEqual('credential entered after crash', (recovered[0] / 'auth.curl.conf').read_text())
        self.installer.checkpoint = lambda _: None
        self.install()

    def test_upgrade_unit_failure_can_retry_without_changing_selected_release(self):
        self.install()
        self.installer.runtime_install('v2')
        def fail(stage):
            if stage.startswith('unit:'):
                raise RuntimeError('unit write failure')
        self.installer.checkpoint = fail
        with self.assertRaises(RuntimeError):
            self.installer.instance('upgrade', 'a', 'v2')
        self.assertEqual('profiles/v1', os.readlink(self.home() / 'current'))
        self.installer.checkpoint = lambda _: None
        self.installer.instance('upgrade', 'a', 'v2')
        self.assertEqual('profiles/v2', os.readlink(self.home() / 'current'))

    def test_restrictive_umask_preserves_container_readable_entrypoint(self):
        previous = os.umask(0o077)
        try:
            self.installer.runtime_install('private')
        finally:
            os.umask(previous)
        entrypoint = self.installer.releases / 'private/docker/entrypoint.sh'
        self.assertEqual(0o755, entrypoint.stat().st_mode & 0o777)
        self.installer.verify('private')

    def test_concurrent_different_content_cannot_replace_same_release(self):
        other = Path(self.temp.name) / 'other'
        shutil.copytree(self.source, other)
        (other / 'docker/entrypoint.sh').write_text('# distinct release\n')
        ctx = multiprocessing.get_context('fork')
        barrier, results = ctx.Barrier(2), ctx.Queue()
        workers = [ctx.Process(target=concurrent_runtime, args=(str(self.root), str(source), barrier, results)) for source in (self.source, other)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(10)
            self.assertFalse(worker.is_alive())
            self.assertEqual(0, worker.exitcode)
        self.assertEqual(['installed', 'refused'], sorted([results.get(timeout=1), results.get(timeout=1)]))
        self.installer.verify('racing')

    def test_concurrent_same_instance_has_single_winner(self):
        # fork keeps the test module importable on macOS and Linux, without Docker.
        ctx = multiprocessing.get_context('fork')
        barrier, results = ctx.Barrier(2), ctx.Queue()
        workers = [ctx.Process(target=concurrent, args=(str(self.root), str(self.source), barrier, results)) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(10)
            self.assertFalse(worker.is_alive())
            self.assertEqual(0, worker.exitcode)
        self.assertEqual(['installed', 'refused'], sorted([results.get(timeout=1), results.get(timeout=1)]))


if __name__ == '__main__':
    unittest.main()
