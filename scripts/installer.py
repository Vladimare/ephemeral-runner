#!/usr/bin/env python3
"""Root-only, immutable releases and recoverable per-instance transactions."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile

INSTANCE = r'[a-z][a-z0-9-]{0,19}'
VERSION = r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}'
FILES = ('scripts/runner-once.sh', 'scripts/runner-cleanup.py', 'docker/entrypoint.sh',
         'systemd/ephemeral-runner@.service', 'systemd/ephemeral-runner-cleanup@.service',
         'systemd/ephemeral-runner-cleanup@.timer')


class Installer:
    # root/uid/run/checkpoint are test seams; the CLI always uses real / and uid 0.
    def __init__(self, source, root=Path('/'), uid=0, run=None, checkpoint=None):
        self.source, self.root, self.uid = Path(source), Path(root), uid
        self.run = run or self.command
        self.checkpoint = checkpoint or (lambda stage: None)
        self.base = self.path('/etc/ephemeral-runner')
        self.releases = self.path('/usr/local/libexec/ephemeral-runner/releases')
        self.units = self.path('/etc/systemd/system')

    def path(self, value):
        return self.root / value.lstrip('/')

    @staticmethod
    def command(args):
        return subprocess.run(args, check=True, text=True, capture_output=True, timeout=60).stdout.strip()

    def directory(self, path, *, create=True):
        # Traverse without following symlinks. Existing ancestors must be trusted;
        # only root (same uid in tests) may replace entries while locks are held.
        relative = path.relative_to(self.root)
        current = self.root
        for part in relative.parts:
            current /= part
            if create:
                try:
                    current.mkdir(mode=0o700)
                except FileExistsError:
                    pass
            info = current.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.uid or info.st_mode & 0o022:
                raise RuntimeError(f'Untrusted directory: {current}')

    @contextmanager
    def lock(self, name, shared=False):
        locks = self.base / 'locks'
        self.directory(locks)
        fd = os.open(locks / name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or info.st_mode & 0o077 or info.st_nlink != 1:
                raise RuntimeError('Untrusted lock file')
            fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def write(self, path, content, mode=0o600):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content if isinstance(content, bytes) else content.encode())
            stream.flush()
            os.fsync(stream.fileno())

    def sync(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def manifest(self, directory):
        return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in FILES}

    def release(self, version):
        if not re.fullmatch(VERSION, version) or version in ('.', '..'):
            raise ValueError('Invalid runtime version')
        path = self.releases / version
        self.directory(path.parent)
        return path

    def verify(self, version):
        path = self.release(version)
        if not path.exists():
            raise RuntimeError("Runtime is not installed; run runtime-install first")
        self.directory(path, create=False)
        # Verify files as well as metadata; refuse damaged or replaced releases.
        for name in (*FILES, 'manifest.json'):
            info = (path / name).lstat()
            expected_mode = 0o600 if name == 'manifest.json' else (0o755 if name.startswith(('scripts/', 'docker/')) else 0o644)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or stat.S_IMODE(info.st_mode) != expected_mode:
                raise RuntimeError(f'Untrusted release file: {name}')
        if json.loads((path / 'manifest.json').read_text()) != self.manifest(path):
            raise RuntimeError('Runtime manifest mismatch')
        return path

    def runtime_install(self, version):
        target = self.release(version)
        with self.lock('runtime'):
            expected = self.manifest(self.source)
            if target.exists() or target.is_symlink():
                self.verify(version)
                if expected != self.manifest(target):
                    raise RuntimeError('Version already exists with different content; choose a new version')
                return
            stage = Path(tempfile.mkdtemp(prefix='.stage-', dir=self.releases))
            try:
                for name in FILES:
                    (stage / name).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    self.write(stage / name, (self.source / name).read_bytes(),
                               0o755 if name.startswith(('scripts/', 'docker/')) else 0o644)
                    self.checkpoint('shared:' + name)
                if self.manifest(stage) != expected:
                    raise RuntimeError('Source changed during runtime staging; retry from a stable checkout')
                self.write(stage / 'manifest.json', json.dumps(expected, sort_keys=True))
                for directory, _, _ in os.walk(stage, topdown=False):
                    self.sync(Path(directory))
                os.rename(stage, target)
                self.sync(self.releases)
            finally:
                if stage.exists():
                    shutil.rmtree(stage)

    @staticmethod
    def names(instance):
        return (f'ephemeral-runner@{instance}.service',
                f'ephemeral-runner-cleanup@{instance}.service',
                f'ephemeral-runner-cleanup@{instance}.timer')

    def stopped(self, instance):
        for name in self.names(instance):
            # Unknown/error states fail closed; fresh units report LoadState=not-found
            # and ActiveState=inactive through systemctl show, not is-active exit codes.
            state = self.run(['systemctl', 'show', '--property=ActiveState', '--value', name])
            if state not in ('inactive', 'failed'):
                raise RuntimeError(f'Stop runner, cleanup service and timer first: {name} ({state})')

    def profile(self, home, version, instance):
        runtime = self.verify(version)
        profiles = home / 'profiles'
        self.directory(profiles)
        target = profiles / version
        if target.exists():
            raise RuntimeError('Profile unexpectedly exists')
        stage = Path(tempfile.mkdtemp(prefix='.stage-', dir=profiles))
        try:
            for source, name in zip(FILES[3:], self.names(instance)):
                text = (runtime / source).read_text().replace(
                    '/usr/local/libexec/ephemeral-runner/',
                    f'/usr/local/libexec/ephemeral-runner/releases/{version}/scripts/')
                self.write(stage / name, text, 0o644)
                self.checkpoint('unit:' + name)
            self.sync(stage)
            os.rename(stage, target)
            self.sync(profiles)
        finally:
            if stage.exists():
                shutil.rmtree(stage)

    def pointer(self, home, version):
        temporary = home / ('.current-' + secrets.token_hex(8))
        os.symlink(f'profiles/{version}', temporary)
        os.replace(temporary, home / 'current')
        self.sync(home)

    def rollback(self, instance, journal):
        home = self.base / 'instances' / instance
        self.stopped(instance)
        data = json.loads(journal.read_text())
        if data['previous'] is None:
            for name in self.names(instance):
                link = self.units / name
                if link.is_symlink() and os.readlink(link) == str(home / 'current' / name):
                    link.unlink()
            self.sync(self.units)
            if home.exists():
                # Preserve credentials/configuration even after an interrupted install.
                os.rename(home, home.with_name('.recovered-' + instance + '-' + secrets.token_hex(8)))
                self.sync(home.parent)
        else:
            self.pointer(home, data['previous'])
        self.run(['systemctl', 'daemon-reload'])
        journal.unlink()
        self.sync(journal.parent)

    def instance(self, action, instance, version=None, repository=None, network=None, image=None):
        if not re.fullmatch(INSTANCE, instance):
            raise ValueError('Invalid instance')
        with self.lock('runtime', shared=True), self.lock('instance-' + instance):
            self.directory(self.base / 'instances')
            self.directory(self.units)
            home = self.base / 'instances' / instance
            journal = self.base / ('transaction-' + instance + '.json')
            if action == 'recover':
                if journal.exists():
                    self.rollback(instance, journal)
                return
            if journal.exists():
                raise RuntimeError('Interrupted transaction: run recover --instance ' + instance)
            runtime = self.verify(version)
            self.stopped(instance)
            if action == 'instance-install':
                if home.exists() or home.is_symlink() or any(
                    (self.base / (instance + suffix)).exists() or (self.base / (instance + suffix)).is_symlink()
                    for suffix in ('.env', '.curl.conf')):
                    raise RuntimeError('Instance exists; legacy installations require manual migration')
                if any((self.units / name).exists() or (self.units / name).is_symlink() for name in self.names(instance)):
                    raise RuntimeError('Existing systemd unit; refusing overwrite')
                if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository or ''):
                    raise ValueError('Invalid repository')
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]+', network or '') or network in ('bridge', 'host', 'none'):
                    raise ValueError('Invalid dedicated network')
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./:@-]+', image or ''):
                    raise ValueError('Invalid image')
                if self.run(['docker', 'network', 'inspect', '--format', '{{.Driver}}', network]) != 'bridge':
                    raise RuntimeError('Expected a dedicated bridge')
                self.run(['docker', 'image', 'inspect', image])
                previous = None
            else:
                self.directory(home, create=False)
                current = os.readlink(home / 'current')
                if not current.startswith('profiles/'):
                    raise RuntimeError('Invalid current profile')
                previous = current.removeprefix('profiles/')
                if not re.fullmatch(VERSION, previous) or previous in ('.', '..'):
                    raise RuntimeError('Invalid current profile')
                self.directory(home / 'profiles' / previous, create=False)
                self.verify(previous)
                if previous == version:
                    return
                for name in self.names(instance):
                    if not (self.units / name).is_symlink() or os.readlink(self.units / name) != str(home / 'current' / name):
                        raise RuntimeError('Unexpected systemd unit; refusing upgrade')
            pending = self.base / ('.journal-' + secrets.token_hex(8))
            try:
                self.write(pending, json.dumps({'previous': previous}))
                os.rename(pending, journal)
                self.sync(journal.parent)
            finally:
                if pending.exists():
                    pending.unlink()
            stage_home = None
            try:
                working = home
                if previous is None:
                    stage_home = Path(tempfile.mkdtemp(prefix='.stage-' + instance + '-', dir=home.parent))
                    working = stage_home
                    label = f'er-{instance}-{secrets.token_hex(4)}'
                    self.write(working / 'config.env', f'REPOSITORY={repository}\nRUNNER_LABEL={label}\nRUNNER_PREFIX={label}\nDOCKER_NETWORK={network}\nRUNNER_IMAGE={image}\n')
                    self.checkpoint('config')
                    self.write(working / 'auth.curl.conf', '')
                    self.checkpoint('auth')
                profile = working / 'profiles' / version
                if not profile.exists():
                    self.profile(working, version, instance)
                else:
                    # Reuse only byte-identical profiles on rollback/retry.
                    self.directory(profile, create=False)
                    for source, name in zip(FILES[3:], self.names(instance)):
                        expected = (runtime / source).read_text().replace('/usr/local/libexec/ephemeral-runner/', f'/usr/local/libexec/ephemeral-runner/releases/{version}/scripts/')
                        if (profile / name).is_symlink() or (profile / name).read_text() != expected:
                            raise RuntimeError('Existing profile mismatch')
                self.pointer(working, version)
                if previous is None:
                    os.rename(working, home)
                    self.sync(home.parent)
                    self.checkpoint('instance-publish')
                    for name in self.names(instance):
                        os.symlink(str(home / 'current' / name), self.units / name)
                        self.checkpoint('publish:' + name)
                    self.sync(self.units)
                self.run(['systemctl', 'daemon-reload'])
                self.checkpoint('reload')
                journal.unlink()
                self.sync(journal.parent)
            except Exception:
                # If rollback itself fails, retain the journal for explicit recovery.
                self.rollback(instance, journal)
                raise
            finally:
                if stage_home is not None and stage_home.exists():
                    shutil.rmtree(stage_home)
            print(f'{instance}: runtime {version}; config/auth in {home}; services remain stopped')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    runtime = sub.add_parser('runtime-install')
    runtime.add_argument('--version', required=True)
    for name in ('instance-install', 'upgrade', 'recover'):
        command = sub.add_parser(name)
        command.add_argument('--instance', required=True)
        if name != 'recover':
            command.add_argument('--version', required=True)
        if name == 'instance-install':
            for flag in ('repo', 'network', 'image'):
                command.add_argument('--' + flag, required=True)
    args = vars(parser.parse_args())
    if os.geteuid() != 0:
        parser.error('Run as root')
    installer = Installer(Path(__file__).resolve().parents[1])
    action = args.pop('action')
    try:
        if action == 'runtime-install':
            installer.runtime_install(**args)
        else:
            for program in ('bash', 'python3', 'curl', 'docker', 'systemctl'):
                if shutil.which(program) is None:
                    raise RuntimeError(f'Missing prerequisite: {program}')
            if 'repo' in args:
                args['repository'] = args.pop('repo')
            installer.instance(action, **args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'Installation failed: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
