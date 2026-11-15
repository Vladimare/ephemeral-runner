"""Lifecycle behavior using disposable files and controlled Docker/API boundaries."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import test_cleanup
mod = test_cleanup.mod


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        fixture = test_cleanup.CleanupTests()
        fixture.setUp()
        self.cfg, self.name = fixture.cfg, fixture.name
        self.row = fixture.record()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        (self.base / 'example').mkdir()
        self.state = self.base / 'state'
        self.state.write_text(self.name)
        self.enterContext(patch.object(mod, 'CONFIG_BASE', self.base))
        self.enterContext(patch.object(mod.Config, 'state', property(lambda _: self.state)))
        self.original_stop = mod.stop_container
        self.stop = self.enterContext(patch.object(mod, 'stop_container'))
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    def arm(self):
        mod.maintenance(self.cfg, 'plan')

    def test_arm_never_contacts_systemd_docker_or_github(self):
        with patch.object(mod, 'command') as cmd, patch.object(mod, 'runners') as api:
            self.arm()
            self.arm()
            cmd.assert_not_called()
            api.assert_not_called()
        self.assertEqual(0o600, self.cfg.maintenance.stat().st_mode & 0o777)
        self.stop.assert_not_called()

    def test_passive_busy_to_idle_does_not_stop_even_when_api_reports_idle(self):
        for busy in (True, False):
            with self.subTest(busy=busy), patch.object(mod, 'docker_exists', return_value=True), patch.object(mod, 'runners') as api:
                with self.assertRaisesRegex(RuntimeError, 'PENDING'):
                    mod.current(self.cfg, False)
                api.assert_not_called()
                self.assertTrue(self.state.exists())
        self.stop.assert_not_called()

    def test_offline_unknown_busy_and_online_idle_preserve_state(self):
        for values in ({'busy': True}, {'busy': None}, {'status': 'online'}):
            with self.subTest(values=values), patch.object(mod, 'docker_exists', return_value=False), patch.object(mod, 'runners', return_value=[dict(self.row, **values)]), patch.object(mod, 'delete') as delete:
                with self.assertRaises(RuntimeError):
                    mod.current(self.cfg, False)
                delete.assert_not_called()
                self.assertTrue(self.state.exists())
        self.stop.assert_not_called()

    def test_container_appearing_after_absence_keeps_state(self):
        with patch.object(mod, 'docker_exists', side_effect=[False, True]), patch.object(mod, 'runners', return_value=[]):
            with self.assertRaises(RuntimeError):
                mod.current(self.cfg, False)
        self.assertTrue(self.state.exists())

    def test_active_configuring_stopping_and_unknown_units_are_pending(self):
        self.arm()
        for state in ('active', 'activating', 'deactivating', '', 'unknown', 'reloading'):
            with self.subTest(state=state), patch.object(mod, 'command', return_value=subprocess.CompletedProcess([], 0, state, '')), patch.object(mod, 'runners') as api:
                with self.assertRaisesRegex(RuntimeError, 'PENDING'):
                    mod.maintenance(self.cfg, 'status')
                api.assert_not_called()
        self.stop.assert_not_called()

    def command(self, argv, **kwargs):
        output = 'inactive' if argv[0] == 'systemctl' else ''
        return subprocess.CompletedProcess(argv, 0, output, '')

    def test_ready_and_resume_require_natural_exit_and_absence(self):
        self.arm()
        with patch.object(mod, 'command', side_effect=self.command), patch.object(mod, 'runners', return_value=[]), patch.object(mod, 'docker_exists', return_value=False):
            mod.maintenance(self.cfg, 'status')
            self.assertTrue(self.cfg.maintenance.exists())
            self.assertFalse(self.state.exists())
            mod.maintenance(self.cfg, 'resume')
            self.assertFalse(self.cfg.maintenance.exists())
        self.stop.assert_not_called()

    def test_api_outages_never_clear_state_or_resume_gate(self):
        self.arm()
        for error in (RuntimeError('403'), RuntimeError('429'), RuntimeError('500'), subprocess.TimeoutExpired('curl', 20)):
            with self.subTest(error=error), patch.object(mod, 'command', side_effect=self.command), patch.object(mod, 'runners', side_effect=error):
                with self.assertRaises(type(error)):
                    mod.maintenance(self.cfg, 'resume')
                self.assertTrue(self.state.exists())
                self.assertTrue(self.cfg.maintenance.exists())
        self.stop.assert_not_called()

    def test_orphan_unregistered_container_prevents_ready(self):
        self.arm()
        def command(argv, **kwargs):
            if argv[:2] == ['docker', 'ps']:
                return subprocess.CompletedProcess(argv, 0, self.name + '\n', '')
            return self.command(argv, **kwargs)
        with patch.object(mod, 'command', side_effect=command), patch.object(mod, 'runners', return_value=[]):
            with self.assertRaisesRegex(RuntimeError, 'container remains'):
                mod.maintenance(self.cfg, 'status')
        self.stop.assert_not_called()

    def test_force_is_explicit_and_failure_keeps_state(self):
        self.stop.side_effect = RuntimeError('stop/rm failed')
        with self.assertRaises(RuntimeError):
            mod.current(self.cfg, False, force=True)
        self.stop.assert_called_once_with(self.name)
        self.assertTrue(self.state.exists())

    def test_force_timeout_keeps_state(self):
        self.stop.side_effect = subprocess.TimeoutExpired('docker', 50)
        with self.assertRaises(subprocess.TimeoutExpired):
            mod.current(self.cfg, False, force=True)
        self.assertTrue(self.state.exists())

    def test_no_gate_rejects_resume(self):
        with self.assertRaisesRegex(RuntimeError, 'not armed'):
            mod.maintenance(self.cfg, 'resume')

    def test_instance_lock_excludes_timer_and_rejects_symlink(self):
        # Use current uid for the root ownership seam; real advisory locking.
        original = mod.os.fstat
        def metadata(fd):
            info = original(fd)
            class Info:
                st_mode = info.st_mode
                st_uid = 0
            return Info()
        with patch.object(mod.os, 'fstat', side_effect=metadata):
            with mod.instance_lock(self.cfg):
                with self.assertRaises(BlockingIOError):
                    with mod.instance_lock(self.cfg):
                        self.fail('acquired competing lock')
        lock = self.base / 'example' / 'lifecycle.lock'
        lock.unlink()
        lock.symlink_to(self.state)
        with self.assertRaises(OSError):
            with mod.instance_lock(self.cfg):
                self.fail('followed symlink')

    def test_real_launcher_gate_precedes_docker_and_token(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / 'scripts/runner-once.sh').read_text()
        # Only redirect host paths and replace file validator with its test seam.
        source = source.replace('BASE="/etc/ephemeral-runner/instances/$INSTANCE"', f'BASE="{self.base}/$INSTANCE"')
        source = source.replace('python3 "$RUNTIME/scripts/runner-cleanup.py" --instance "$INSTANCE" --validate-config', 'true')
        config = self.base / 'example' / 'config.env'
        config.write_text('REPOSITORY=example/project\nRUNNER_PREFIX=er-example-abc12345\nRUNNER_LABEL=er-example-abc12345\nDOCKER_NETWORK=ci\nRUNNER_IMAGE=runner:v1\n')
        launcher = self.base / 'launcher.sh'
        launcher.write_text(source)
        self.arm()
        result = subprocess.run(['bash', str(launcher), 'example'], capture_output=True, text=True)
        self.assertEqual(75, result.returncode, result.stderr)
        self.assertIn('Maintenance armed', result.stderr)

    def test_service_stop_is_passive_when_armed(self):
        self.arm()
        with patch.object(mod, 'load_config', return_value=self.cfg), patch.object(mod, 'instance_lock', return_value=contextlib.nullcontext()), patch.object(mod, 'command'), patch.object(mod, 'current') as current, patch.object(mod.sys, 'argv', ['cleanup', '--instance', 'example', '--service-stop']):
            mod.main()
            current.assert_called_once_with(self.cfg, False, force=False)

    def test_plan_requires_explicit_window_ack_before_any_io(self):
        with patch.object(mod.sys, 'argv', ['cleanup', '--instance', 'example', '--plan-maintenance']), patch.object(mod, 'load_config') as load, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                mod.main()
            self.assertEqual(2, error.exception.code)
            load.assert_not_called()

    def test_busy_forced_shutdown_is_logged_but_registration_is_retained(self):
        with patch.object(mod, 'runners', return_value=[dict(self.row, busy=True)]):
            with self.assertRaises(RuntimeError):
                mod.current(self.cfg, False, force=True)
        self.stop.assert_called_once_with(self.name)
        self.assertTrue(self.state.exists())

    def test_actual_stop_rm_failure_and_timeout_are_errors(self):
        # Override setUp's mock to exercise actual stop/remove control flow.
        original = self.original_stop
        failed = subprocess.CompletedProcess([], 1, '', 'Docker failure')
        with patch.object(mod, 'docker_exists', return_value=True), patch.object(mod, 'command', return_value=failed) as cmd:
            with self.assertRaisesRegex(RuntimeError, 'Container remains'):
                original(self.name)
            self.assertIn(['docker', 'stop', '--time', '30', self.name], [call.args[0] for call in cmd.call_args_list])
            self.assertIn(['docker', 'rm', '-f', self.name], [call.args[0] for call in cmd.call_args_list])
        with patch.object(mod, 'docker_exists', return_value=True), patch.object(mod, 'command', side_effect=subprocess.TimeoutExpired('docker', 50)):
            with self.assertRaises(subprocess.TimeoutExpired):
                original(self.name)

    def test_systemd_exit_and_backoff_contract(self):
        unit = (Path(__file__).resolve().parents[1] / 'systemd/ephemeral-runner@.service').read_text()
        self.assertIn('RestartPreventExitStatus=75', unit)
        self.assertIn('RestartSec=60', unit)
        self.assertIn('SuccessExitStatus=143', unit)
        self.assertNotIn('SuccessExitStatus=137', unit)
        self.assertIn('--service-stop', unit)
        self.assertIn('ExecStopPost=-/usr/local/libexec/ephemeral-runner/runner-cleanup.py --instance %i --current', unit)
