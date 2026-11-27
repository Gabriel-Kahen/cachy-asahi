#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Fixed minimal206 metadata CI; never acquire packages or authenticate/build."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import stat
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = ROOT / 'scripts/port/minimal-native-builder-inputs'
CHECKER = 'scripts/checks/package_checks.py'
HELD_CHECKER = ('scripts/ci/llhttp-minimal-native-source-data/fixtures/Source95/held-source/'
                'scripts/ci/llhttp-reference-native-source/base/runtime/' + CHECKER)
LOCK_PIN = {'bytes': 2377, 'sha256': '6fac7419f32e2c370840dc9ee587b0cdf9d265f2dc9b57ff38bb945a468d090f'}
OLD349_PATH = ROOT / 'scripts/ci/hyprland03-native-source-v1/fixtures/expected349.lock'
OLD349_PIN = {'bytes': 6800, 'sha256': '579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'}
ATTEMPTS = []


def need(value, why):
    if not value: raise ValueError(why)


def pin(raw): return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def checked(path, expected):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve(), 'canonical nonaliased metadata leaf')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == expected.get('mode', 0o644)
             and before.st_size == expected['bytes'] <= 20 * 1024**2, 'ordinary bounded exact metadata file')
        raw = stream.read(expected['bytes'] + 1)
        identity = lambda s: tuple(getattr(s, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
        need(identity(before) == identity(os.fstat(stream.fileno())) == identity(path.stat(follow_symlinks=False))
             and pin(raw) == {k: expected[k] for k in ('bytes', 'sha256')}, 'stable whole metadata pin')
    return raw


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


def stage_source(output):
    def stage(member, expected, source=None):
        raw = checked(ROOT / (source or member), expected)
        target = output / member
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(raw)
        target.chmod(expected.get('mode', 0o644))
        return raw

    prefix = SOURCE.relative_to(ROOT)
    lock = json.loads(stage(prefix / 'source.lock.json', LOCK_PIN))
    names = {p.relative_to(SOURCE).as_posix() for p in SOURCE.rglob('*') if p.is_file() or p.is_symlink()}
    need(names == set(lock['files']) | {'source.lock.json'}, 'closed exact author family')
    for name, row in lock['files'].items(): stage(prefix / name, row)
    source = output / prefix
    profile = json.loads((source / 'profile.DATA.json').read_bytes())
    for name, row in profile['engines'].items():
        stage(name, row, HELD_CHECKER if name == CHECKER else name)
    boot = profile['bootstrap_manifest']; stage(boot['path'], boot)
    manifest = json.loads(checked(source / 'builder.lock.json', profile['builder_lock']))
    for recipe in manifest['recipe_inputs'].values():
        area = ROOT / recipe['path']
        need({p.relative_to(area).as_posix() for p in area.rglob('*') if p.is_file() or p.is_symlink()} == set(recipe['files']), 'complete original recipe namespace')
        for name, row in recipe['files'].items(): stage(Path(recipe['path']) / name, row)
    return source


def verify_catalogs(directory):
    proof = json.loads((HERE / 'catalogs.DATA.json').read_bytes())
    fixed = json.loads((SOURCE / 'primary.DATA.json').read_bytes())['snapshot_catalogs']
    need([{k: row[k] for k in fixed[0]} for row in proof['catalogs']] == fixed, 'genuine author-pinned catalog provenance')
    need({p.name for p in directory.iterdir()} == {row['repo'] + '.db' for row in fixed}, 'only three exact public catalogs')
    for row in fixed: checked(directory / (row['repo'] + '.db'), row)
    return directory


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.spawn', 'os.fork', 'os.posix_spawn')) or event in (
            'os.system', 'os.kill', 'os.killpg', 'os.pidfd_open', 'fcntl.flock', 'resource.setrlimit'):
        ATTEMPTS.append(event); raise AssertionError('MINIMAL_BUILDER_DATA_NO_ACTOR: ' + event)


def run():
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (180,) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024**2,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (128,) * 2)
    sys.addaudithook(fence)
    checked(OLD349_PATH, OLD349_PIN); verify_catalogs(HERE / 'catalogs')
    with tempfile.TemporaryDirectory(prefix='minimal206-held-source-') as name:
        source = stage_source(Path(name))
        author = module(source / 'test_inputs.py', 'minimal206_original_author_tests')
        focused = module(HERE / 'test_graph.py', 'minimal206_focused_ci_tests')
        focused.CI = sys.modules[__name__]
        focused.SOURCE = source
        suite = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromModule(author),
                                    unittest.defaultTestLoader.loadTestsFromModule(focused)])
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    passed = result.wasSuccessful() and result.testsRun == 17 and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses and not ATTEMPTS
    print(json.dumps(dict(status='PASS_FIXED206_METADATA_DATA_ONLY' if passed else 'FAIL', tests=result.testsRun,
                         author_controls=11, focused_controls=6, skips=len(result.skipped), actor_attempts=len(ATTEMPTS),
                         actual_package_or_rootfs_bodies_read=False, signature_authentication=None, project_llhttp_provider='UNISSUED',
                         Root_selection=None, Root_native_authority=None, native=None, M2=None, old349_admission=None), sort_keys=True))
    return passed


if __name__ == '__main__':
    need(__debug__ and sys.flags.isolated and sys.dont_write_bytecode, 'use unoptimized Python -I -B')
    sys.exit(0 if run() else 1)
