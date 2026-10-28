import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / 'scripts' / 'runner-cleanup.py'
spec = importlib.util.spec_from_file_location('runner_cleanup', MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.cfg = mod.Config('loom', 'Vladimare/loom', 'er-loom-abc12345',
                              'er-loom-abc12345', 'loom-ci', 'runner:v1')
        self.name = 'er-loom-abc12345-1793132445-5892'

    def record(self, **kwargs):
        r = {'name': self.name, 'id': 50, 'status': 'offline', 'busy': False,
             'labels': [{'name': self.cfg.label}]}
        r.update(kwargs)
        return r

    def test_omitted_ephemeral_is_owned(self):
        self.assertTrue(mod.owned(self.cfg, self.record()))
        self.assertFalse(mod.owned(self.cfg, self.record(ephemeral=False)))

    def test_different_repo_instance_label_not_owned(self):
        self.assertFalse(mod.owned(self.cfg, self.record(labels=[{'name': 'er-gsd-abc12345'}])))
        self.assertFalse(mod.owned(self.cfg, self.record(name='er-other-abc12345-1793132445-5892')))
        self.assertFalse(mod.owned(self.cfg, self.record(name='er-loom-abc12345;rm -rf /')))

    def test_sweep_only_offline_idle_missing_container(self):
        rows = [self.record(), self.record(id=51, status='online'),
                self.record(id=52, busy=True), self.record(id=53, ephemeral=False),
                self.record(id=54, labels=[{'name': 'other'}])]
        with patch.object(mod, 'runners', return_value=rows), \
                patch.object(mod, 'docker_exists', return_value=False), \
                patch.object(mod, 'delete', return_value=True) as delete:
            mod.sweep(self.cfg, dry_run=True)
            self.assertEqual(delete.call_count, 1)
            self.assertEqual(delete.call_args.args[1]['id'], 50)

    def test_docker_errors_fail_closed(self):
        result = type('Process', (), {'returncode': 1, 'stderr': 'daemon unavailable'})()
        with patch.object(mod, 'command', return_value=result):
            with self.assertRaises(RuntimeError):
                mod.docker_exists(self.name)

    def test_existing_container_never_deleted(self):
        with patch.object(mod, 'docker_exists', return_value=True), \
                patch.object(mod, 'github') as gh:
            self.assertFalse(mod.delete(self.cfg, self.record(), dry_run=False))
            gh.assert_not_called()

    def test_current_preserves_state_on_github_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            filename = Path(tmp) / 'current-name'
            filename.write_text(self.name)
            with patch.object(mod.Config, 'state', property(lambda _: filename)), \
                    patch.object(mod, 'stop_container'), \
                    patch.object(mod, 'runners', return_value=[self.record()]), \
                    patch.object(mod, 'delete', side_effect=RuntimeError('403')):
                with self.assertRaises(RuntimeError):
                    mod.current(self.cfg, dry_run=False)
                self.assertEqual(filename.read_text(), self.name)

    def test_current_deletes_and_clears_state_when_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            filename = Path(tmp) / 'current-name'
            filename.write_text(self.name)
            with patch.object(mod.Config, 'state', property(lambda _: filename)), \
                    patch.object(mod, 'stop_container'), \
                    patch.object(mod, 'runners', side_effect=[[self.record()], []]), \
                    patch.object(mod, 'delete', return_value=True) as delete:
                mod.current(self.cfg, dry_run=False)
                delete.assert_called_once()
                self.assertFalse(filename.exists())

    def test_config_parses_generated_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / 'loom').mkdir()
            (base / 'loom' / 'config.env').write_text(
                'REPOSITORY=Vladimare/loom\nRUNNER_LABEL=er-loom-abc12345\n'
                'RUNNER_PREFIX=er-loom-abc12345\nDOCKER_NETWORK=loom-ci\n'
                'RUNNER_IMAGE=ephemeral-runner:2.338.0\n'
            )
            (base / 'loom' / 'auth.curl.conf').write_text('header = "Authorization: Bearer TEST"\n')
            with patch.object(mod, 'CONFIG_BASE', base), patch.object(mod, 'check_private_root'):
                cfg = mod.load_config('loom')
                self.assertEqual(cfg.repository, 'Vladimare/loom')
                self.assertTrue(cfg.valid_name(self.name))

    def test_dangerous_instance_rejected_before_io(self):
        for name in ('../file', 'LOOM', '', 'loom/other'):
            with self.assertRaises(ValueError):
                mod.load_config(name)

    def test_config_rejects_extra_shell_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / 'loom').mkdir()
            (base / 'loom' / 'config.env').write_text('REPOSITORY=$(curl.example.com)\n')
            with patch.object(mod, 'CONFIG_BASE', base), patch.object(mod, 'check_private_root'):
                with self.assertRaises(ValueError):
                    mod.load_config('loom')


if __name__ == '__main__':
    unittest.main()
