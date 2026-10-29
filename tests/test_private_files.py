"""Real file validation and launcher subprocesses; no host service/API access."""
import functools
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

# Reuse the loaded cleanup module from the original regression suite.
from test_cleanup import mod

ROOT = Path(__file__).resolve().parents[1]


class PrivateFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.base = self.root / 'instances'
        self.home = self.base / 'test'
        self.home.mkdir(parents=True, mode=0o700)
        self.conf = self.home / 'config.env'
        self.auth = self.home / 'auth.curl.conf'
        self.conf.write_text('REPOSITORY=owner/repo\nRUNNER_LABEL=er-test-12345678\n'
                             'RUNNER_PREFIX=er-test-12345678\nDOCKER_NETWORK=ci-net\n'
                             'RUNNER_IMAGE=runner:v1\n')
        self.auth.write_text('# dummy credentials only\n')
        for file in (self.conf, self.auth):
            file.chmod(0o600)
        self.validate = functools.partial(mod.check_private_root, uid=os.getuid(), root=self.root)
        runtime = self.root / 'runtime'
        scripts = runtime / 'scripts'
        scripts.mkdir(parents=True)
        # Only redirect filesystem roots and validation uid for an unprivileged
        # fixture; the production launcher and validator control flow is exercised.
        launcher = (ROOT / 'scripts/runner-once.sh').read_text().replace(
            'BASE="/etc/ephemeral-runner/instances/$INSTANCE"',
            f'BASE="{self.base}/$INSTANCE"')
        self.launcher = scripts / 'runner-once.sh'
        self.launcher.write_text(launcher)
        (scripts / 'runner-cleanup.py').write_text(
            'import functools, importlib.util, os, sys\nfrom pathlib import Path\n'
            f'spec = importlib.util.spec_from_file_location("fixture_cleanup", {str(ROOT / "scripts/runner-cleanup.py")!r})\n'
            'mod = importlib.util.module_from_spec(spec)\nsys.modules[spec.name] = mod\nspec.loader.exec_module(mod)\n'
            f'mod.CONFIG_BASE = Path({str(self.base)!r})\n'
            f'mod.check_private_root = functools.partial(mod.check_private_root, uid=os.getuid(), root=Path({str(self.root)!r}))\n'
            'mod.main()\n')
        (scripts / 'runner-resources.py').write_text(
            'import functools, importlib.util, os, sys\nfrom pathlib import Path\n'
            f'spec = importlib.util.spec_from_file_location("fixture_resources", {str(ROOT / "scripts/runner-resources.py")!r})\n'
            'res = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(res)\n'
            'real_cleanup = res.cleanup\n'
            'def fixture_cleanup():\n'
            '    mod = real_cleanup()\n'
            f'    mod.CONFIG_BASE = Path({str(self.base)!r})\n'
            f'    mod.check_private_root = functools.partial(mod.check_private_root, uid=os.getuid(), root=Path({str(self.root)!r}))\n'
            '    return mod\n'
            'res.cleanup = fixture_cleanup\n'
            'read = res.read_policy\n'
            f'res.read_policy = functools.partial(read, uid=os.getuid(), root=Path({str(self.root)!r}))\n'
            'res.main()\n')
        import json
        from test_resources import resources
        (self.home / 'resources.json').write_text(json.dumps(resources.DEFAULT))
        (self.home / 'resources.json').chmod(0o600)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.marker = self.root / 'docker-called'
        docker = self.bin / 'docker'
        docker.write_text(f'#!/bin/sh\ntouch "{self.marker}"\nexit 1\n')
        docker.chmod(0o755)

    def cleanup_validate(self):
        with patch.object(mod, 'CONFIG_BASE', self.base), patch.object(mod, 'check_private_root', self.validate):
            return mod.load_config('test')

    def launcher_validate(self):
        self.marker.unlink(missing_ok=True)
        result = subprocess.run(['bash', str(self.launcher), 'test'], capture_output=True,
                                env={**os.environ, 'PATH': str(self.bin) + os.pathsep + os.environ['PATH']}, timeout=10)
        return result, self.marker.exists()

    def rejected_by_both(self):
        with self.assertRaises((RuntimeError, OSError)):
            self.cleanup_validate()
        result, docker_called = self.launcher_validate()
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(docker_called)
        self.assertNotIn(b'dummy credentials', result.stdout + result.stderr)

    def test_0600_config_and_auth_accepted_by_both(self):
        self.assertEqual('owner/repo', self.cleanup_validate().repository)
        result, docker_called = self.launcher_validate()
        # The Docker stub deliberately stops execution before any API request.
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(docker_called)

    def test_non_0600_modes_rejected_by_both(self):
        for file in (self.conf, self.auth):
            for mode in (0o644, 0o640, 0o400, 0o666):
                with self.subTest(file=file.name, mode=oct(mode)):
                    file.chmod(mode)
                    self.rejected_by_both()
            file.chmod(0o600)

    def test_file_symlinks_rejected_by_both(self):
        for file in (self.conf, self.auth):
            with self.subTest(file=file.name):
                target = file.with_suffix('.target')
                file.rename(target)
                file.symlink_to(target)
                self.rejected_by_both()
                file.unlink()
                target.rename(file)

    def test_directory_and_fifo_rejected_by_both_without_blocking(self):
        for file in (self.conf, self.auth):
            contents = file.read_bytes()
            for kind in ('directory', 'fifo'):
                with self.subTest(file=file.name, kind=kind):
                    file.unlink()
                    if kind == 'directory':
                        file.mkdir(mode=0o600)
                    else:
                        os.mkfifo(file, 0o600)
                    self.rejected_by_both()
                    if kind == 'directory':
                        file.rmdir()
                    else:
                        file.unlink()
                    file.write_bytes(contents)
                    file.chmod(0o600)

    def test_writable_parents_rejected_by_both(self):
        for parent in (self.root, self.base, self.home):
            original = parent.stat().st_mode & 0o777
            parent.chmod(0o777)
            self.rejected_by_both()
            parent.chmod(original)

    def test_parent_symlink_rejected_by_both(self):
        real = self.home.with_name('actual')
        self.home.rename(real)
        self.home.symlink_to(real, target_is_directory=True)
        self.rejected_by_both()

    def test_wrong_owner_rejected_for_files_and_parents(self):
        # chown to another uid is unavailable to unprivileged developers. Inject
        # only fstat ownership; real traversal/type/mode checks still run.
        original = os.fstat
        for target in (self.conf, self.auth, self.home):
            inode = target.stat().st_ino
            def wrong_owner(fd):
                value = original(fd)
                return SimpleNamespace(st_uid=os.getuid() + 1, st_mode=value.st_mode) if value.st_ino == inode else value
            with self.subTest(target=target.name), patch.object(mod.os, 'fstat', side_effect=wrong_owner):
                with self.assertRaises(RuntimeError):
                    self.cleanup_validate()

    def test_validation_mode_does_not_contact_docker(self):
        with patch.object(mod, 'CONFIG_BASE', self.base), patch.object(mod, 'check_private_root', self.validate), \
                patch.object(mod.sys, 'argv', ['cleanup', '--instance', 'test', '--validate-config']), \
                patch.object(mod, 'command') as command:
            mod.main()
            command.assert_not_called()
