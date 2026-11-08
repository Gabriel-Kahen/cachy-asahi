#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private staged-package/GPG controls; no host install, ALPM or hardware credit."""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
RECIPE_ROOT = HERE
NAME = 'cachy-asahi-release-tools'
RUNTIME = 'usr/lib/cachy-asahi/release-tools-v3'
CURRENT = RUNTIME + '/endpoint-current/scripts'
COPY = CURRENT + '/release/endpoint_copy_v1/copy_endpoint.py'
LEGACY = RUNTIME + '/legacy-v2'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def snapshot(root):
    return {p.relative_to(root).as_posix(): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode))
            for p in root.rglob('*') if p.is_file() and not p.is_symlink()}


def recipe_copy(root, output):
    match = re.search(r'^source=\(([^)]*)\)', (root / 'PKGBUILD').read_text(), re.M)
    if match is None:
        raise AssertionError('finite literal package sources required')
    names = ['PKGBUILD', '.SRCINFO', *shlex.split(match[1])]
    if len(names) > 64 or len(names) != len(set(names)):
        raise AssertionError('bounded unique package source list')
    output.mkdir()
    for name in names:
        if Path(name).is_absolute() or '..' in Path(name).parts:
            raise AssertionError('relative package source only')
        source = root / name
        if not source.is_file() or source.is_symlink():
            raise AssertionError('regular package source only')
        target = output / name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return output


# Observer of Python file access and selected external execution. It does not
# survive execv or sandbox GPG/bsdtar/vercmp children. The real launcher is tested
# separately for legacy routing; endpoint dispatch stays in-process, so this
# driver also observes the real installed primary launcher for endpoint-copy.
AUDIT = r'''
import os, pathlib, runpy, shutil, socket, subprocess, sys, sysconfig
entry, prefix, case, outside, mode = sys.argv[1:6]
paths = sysconfig.get_paths(vars={'base': sys.base_prefix, 'platbase': sys.base_exec_prefix})
stdlib = {os.path.realpath(paths[k]) for k in ('stdlib', 'platstdlib')}
thirdparty = {os.path.realpath(paths[k]) for k in ('purelib', 'platlib')}
thirdparty.update(os.path.join(p, leaf) for p in stdlib for leaf in ('site-packages', 'dist-packages'))
prefix, case = os.path.realpath(prefix), os.path.realpath(case)
private_gpg = set()
executables = {os.path.realpath(shutil.which(x)) for x in ('gpg', 'bsdtar', 'vercmp')}
def within(path, roots):
    return any(path == root or path.startswith(root + os.sep) for root in roots)
def check(path, flags=0):
    if isinstance(path, int):
        return
    path = os.path.realpath(os.fsdecode(path))
    writing = flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
    standard = within(path, stdlib) and not within(path, thirdparty)
    if writing:
        if not within(path, {case} | private_gpg):
            raise RuntimeError('write outside explicit fixture/output/private GPG: ' + path)
    elif not (standard or within(path, {prefix, case} | private_gpg) or path == '/dev/null'):
        raise RuntimeError('read outside selected stdlib/moved prefix/explicit fixtures: ' + path)
original_open = os.open
def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
    effective = os.path.join(os.readlink('/proc/self/fd/' + str(dir_fd)), os.fsdecode(path)) if dir_fd is not None else path
    # Canonical traversal may open ancestor directory descriptors. File content
    # and directory enumeration still require an explicit permitted root.
    if not flags & os.O_DIRECTORY:
        check(effective, flags)
    return original_open(path, flags, mode, dir_fd=dir_fd)
os.open = guarded_open
def audit(event, args):
    if event == 'tempfile.mkdtemp':
        path = os.path.realpath(args[0])
        if os.path.dirname(path) == '/tmp' and os.path.basename(path).startswith('cachy-asahi-endpoint-') and not os.path.lexists(path):
            private_gpg.add(path)
        else:
            check(path, os.O_CREAT)
    elif event == 'open' and isinstance(args[0], (str, bytes)):
        if args[1] is not None or os.path.isabs(args[0]):
            if not args[2] & os.O_DIRECTORY:
                check(args[0], args[2])
    elif event == 'os.scandir' and not isinstance(args[0], int):
        check(args[0])
    elif event in ('os.mkdir', 'os.remove', 'os.rmdir', 'os.chmod', 'os.chown', 'os.truncate'):
        path = args[0]
        if not isinstance(path, int):
            dir_fd = args[-1] if event in ('os.mkdir', 'os.remove', 'os.rmdir', 'os.chmod', 'os.chown') else -1
            if isinstance(dir_fd, int) and dir_fd != -1:
                path = os.path.join(os.readlink('/proc/self/fd/' + str(dir_fd)), os.fsdecode(path))
            check(path, os.O_CREAT)
    elif event in ('os.rename', 'os.link', 'os.symlink'):
        if event == 'os.symlink':
            check(args[1], os.O_CREAT)
        else:
            for path, fd in zip(args[:2], args[2:4]):
                if fd != -1:
                    path = os.path.join(os.readlink('/proc/self/fd/' + str(fd)), os.fsdecode(path))
                check(path, os.O_CREAT)
    elif event == 'subprocess.Popen':
        executable = os.path.realpath(shutil.which(os.fsdecode(args[0])) or os.fsdecode(args[0]))
        if executable not in executables:
            raise RuntimeError('unlisted external executable')
    elif event.startswith('socket.') or event in ('os.system', 'os.posix_spawn', 'os.exec'):
        raise RuntimeError('unlisted actor: ' + event)
sys.addaudithook(audit)
if mode == 'probe':
    def refused(fn):
        try:
            fn()
        except RuntimeError:
            return
        raise AssertionError('observer allowed prohibited operation')
    refused(lambda: open(outside, 'rb'))
    refused(lambda: open(os.path.join(prefix, 'forbidden-write'), 'wb'))
    refused(socket.socket)
    refused(lambda: subprocess.run(['/usr/bin/true']))
    print('PASS_OUTSIDE_READ_RUNTIME_WRITE_SOCKET_UNLISTED_CHILD_DENIED')
else:
    sys.argv = [entry, *sys.argv[6:]]
    runpy.run_path(entry, run_name='__main__')
'''


class InstalledPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared = tempfile.TemporaryDirectory(prefix='release-tools-v3-package-')
        cls.addClassCleanup(cls.shared.cleanup)
        cls.workspace = Path(cls.shared.name)
        recipe = recipe_copy(RECIPE_ROOT, cls.workspace / 'finite-build-inputs')
        cls.checker = module('v3_package_checker', recipe / 'check_package.py')
        cls.checker.verify_sources(recipe)
        cls.payload = json.loads((recipe / 'payload-map.json').read_bytes())['files']
        cls.source_bytes = {n: (recipe / row['source']).read_bytes() for n, row in cls.payload.items()}
        stage = cls.workspace / 'stage'
        cls.checker.stage(recipe, stage)
        cls.checker.verify_payload(recipe, stage)
        cls.prefix = cls.workspace / 'relocated prefix'
        stage.rename(cls.prefix)
        cls.cli = cls.prefix / 'usr/bin' / NAME
        cls.legacy_cli = cls.prefix / LEGACY / 'bin' / NAME
        cls.copy_module = module('installed_endpoint_copy', cls.prefix / COPY)
        cls.cwd = cls.workspace / 'unrelated-poisoned-cwd'; cls.cwd.mkdir()
        for name in ('copy', 'endpoint', 'client', 'source_delivery', 'release', 'offline_kit', 'sitecustomize'):
            (cls.cwd / (name + '.py')).write_text("raise RuntimeError('CHECKOUT_OR_CWD_IMPORT_FORBIDDEN')\n")
        support = json.loads((recipe / 'fixture__provenance.json').read_bytes())
        fixture_root = cls.workspace / 'private-fixture-view/scripts'
        for part in ('client', 'release'):
            (fixture_root / part).mkdir(parents=True)
        for leaf, row in support['files'].items():
            body = (recipe / ('fixture__' + leaf)).read_bytes()
            if len(body) != row['bytes'] or sha(body) != row['sha256']:
                raise AssertionError('fixture provenance mismatch')
            destination = fixture_root / ('client' if leaf == 'test_endpoint.py' else 'release') / leaf
            destination.write_bytes(body)
        for name in ('client', 'endpoint', 'export_repository', 'release', 'source_delivery', 'offline_kit'):
            part = 'client' if name in ('client', 'endpoint') else 'release'
            shutil.copyfile(recipe / ('endpoint__' + name + '.py'), fixture_root / part / (name + '.py'))
        cls.fixture = module('private_endpoint_fixture', fixture_root / 'client/test_endpoint.py')
        cls.fixture.EndpointTests.setUpClass.__func__(cls)
        cls.addClassCleanup(lambda: cls.fixture.EndpointTests.tearDownClass.__func__(cls))
        legacy = support['legacy_v2']; archive = recipe / ('fixture__' + legacy['archive'])
        if archive.stat().st_size != legacy['bytes'] or sha(archive.read_bytes()) != legacy['sha256']:
            raise AssertionError('sealed legacy fixture archive mismatch')
        old_recipe = cls.workspace / 'closed-v2-recipe'; old_recipe.mkdir()
        with tarfile.open(archive, 'r:gz') as tar:
            members = tar.getmembers()
            if {m.name for m in members} != set(legacy['files']) or len(members) != 19:
                raise AssertionError('closed legacy fixture membership')
            for member in members:
                if not member.isfile() or Path(member.name).name != member.name:
                    raise AssertionError('regular flat legacy fixture required')
                with tar.extractfile(member) as stream:
                    body = stream.read()
                row = legacy['files'][member.name]
                if len(body) != row['bytes'] or sha(body) != row['sha256']:
                    raise AssertionError('legacy source body pin')
                (old_recipe / member.name).write_bytes(body)
        cls.legacy_fixture = module('legacy_comparison_fixture_only', old_recipe / 'test_package.py')
        cls.old_payload = json.loads((old_recipe / 'payload-map.json').read_bytes())['files']
        cls.old_prefix = cls.workspace / 'actual-v2-stage'
        run = subprocess.run(['bash', '--noprofile', '--norc', '-c',
            'set -eu; umask 022; source "$1/PKGBUILD"; srcdir=$1; startdir=$1; pkgdir=$2; package',
            'private-v2-stage', str(old_recipe), str(cls.old_prefix)], cwd=cls.workspace,
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, capture_output=True, timeout=30)
        if run.returncode:
            raise AssertionError((run.stdout + run.stderr).decode())
        old_checker = module('closed_v2_checker', old_recipe / 'check_package.py')
        old_checker.check_source(old_recipe); old_checker.check_stage(old_recipe, cls.old_prefix)
        cls.old_rows = snapshot(cls.old_prefix)
        # Both actual package() outputs and the fixture view now stand alone.
        shutil.rmtree(recipe); shutil.rmtree(old_recipe)
        cls.removed_recipes = (recipe, old_recipe)

    def setUp(self):
        self.fixture.EndpointTests.setUp(self)
        self.output = self.base / 'copied endpoint'

    def put(self, *a, **kw): return self.fixture.EndpointTests.put(self, *a, **kw)
    def ref(self, *a, **kw): return self.fixture.EndpointTests.ref(self, *a, **kw)
    def save_spec(self, *a, **kw): return self.fixture.EndpointTests.save_spec(self, *a, **kw)
    def stage(self, *a, **kw): return self.fixture.EndpointTests.stage(self, *a, **kw)
    def promote(self, *a, **kw): return self.fixture.EndpointTests.promote(self, *a, **kw)
    def export(self, *a, **kw): return self.fixture.EndpointTests.export(self, *a, **kw)
    def snapshot(self, *a, **kw): return self.fixture.EndpointTests.snapshot(self, *a, **kw)
    def add_sources(self, *a, **kw): return self.fixture.EndpointTests.add_sources(self, *a, **kw)
    def generation(self, *a, **kw): return self.fixture.EndpointTests.generation(self, *a, **kw)
    def withdraw(self, *a, **kw): return self.fixture.EndpointTests.withdraw(self, *a, **kw)
    def edit(self, *a, **kw): return self.fixture.EndpointTests.edit(self, *a, **kw)
    def rehash(self, *a, **kw): return self.fixture.EndpointTests.rehash(self, *a, **kw)

    def args(self, output=None):
        return ['--generation', str(self.gen), '--expected-generation', self.ident,
            '--public-keyring', str(self.keyring), '--signer', self.key, '--output', str(output or self.output)]

    def command(self, args, *, legacy=False, audited=False, output=None):
        target = self.legacy_cli if legacy else self.cli
        command = [str(target), *map(str, args)]
        if audited:
            command = [sys.executable, '-I', '-B', '-c', AUDIT, str(self.cli),
                str(self.prefix), str(self.base), str(self.workspace / 'outside-private-input'), 'run',
                'endpoint-copy', *self.args(output), '--apply']
        return subprocess.run(command, cwd=self.cwd, capture_output=True, timeout=45,
            env={**os.environ, 'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
                 'PYTHONPATH': str(self.cwd), 'PYTHONHOME': '/no-python-home'})

    def modeled_copy(self, **changes):
        m = self.copy_module
        args = dict(generation=self.gen, expected_generation=self.ident, public_keyring=self.keyring,
                    signer=self.key, output=self.output, apply=True)
        args.update(changes)
        with mock.patch.object(m.e.r, 'gates_check', side_effect=lambda *a: m.e.r.load(a[-1])):
            return m.copy_generation(**args)

    def test_exact_finite_staging_and_closed_runtime_bytes(self):
        self.assertTrue(all(not p.exists() for p in self.removed_recipes))
        rows = snapshot(self.prefix)
        self.assertEqual(set(rows), set(self.payload))
        for name, row in self.payload.items():
            self.assertEqual(rows[name], (self.source_bytes[name], row['mode']))
        self.assertFalse(list(self.prefix.rglob('*.pyc')))
        self.assertFalse(any(Path(n).name.startswith('fixture__') for n in rows))
        legacy_sources = {row['source'] for row in self.payload.values() if row['source'].startswith('legacy__')}
        self.assertEqual(len(legacy_sources), 8)
        self.assertEqual(len([n for n in rows if '/endpoint-current/scripts/' in n]), 7)

    def test_version_six_commands_and_no_endpoint_bypass(self):
        version = self.command(['--version'])
        self.assertEqual((version.returncode, version.stdout), (0, b'cachy-asahi-release-tools 0.3.0\n'))
        help_run = self.command(['--help'])
        self.assertEqual(help_run.returncode, 0, help_run.stderr)
        for name in ('sbom', 'source-export', 'recipe-pack', 'recipe-unpack', 'sbom-compare', 'endpoint-copy'):
            self.assertIn(name.encode(), help_run.stdout)
        endpoint = self.command(['endpoint-copy', '--help'])
        self.assertEqual(endpoint.returncode, 0, endpoint.stderr)
        self.assertIn(b'--expected-generation', endpoint.stdout)
        self.assertIn(b'--apply', endpoint.stdout)
        for flag in (b'--skip', b'--model', b'--no-verify', b'--accept-synthetic'):
            self.assertNotIn(flag, endpoint.stdout)
        old = self.command(['--version'], legacy=True)
        self.assertEqual(old.stdout, b'cachy-asahi-release-tools 0.2.0\n')

    def test_previous_five_commands_have_exact_legacy_help_and_refusals(self):
        for name in ('sbom', 'source-export', 'recipe-pack', 'recipe-unpack', 'sbom-compare'):
            for args in ([name, '--help'], [name]):
                with self.subTest(args=args):
                    current, old = self.command(args), self.command(args, legacy=True)
                    self.assertEqual((current.returncode, current.stdout, current.stderr),
                                     (old.returncode, old.stdout, old.stderr))

    def test_legacy_comparison_returns_exact_previous_output(self):
        f = self.legacy_fixture
        args = ['sbom-compare']
        for side in ('before', 'after'):
            path = self.base / side; path.mkdir()
            document, coverage = f.fixture('synthetic-' + side, names=('alpha',))
            raw = f.encoded(document); coverage['spdx_sha256'] = f.sha(raw)
            raw_coverage = f.encoded(coverage)
            (path / 'sbom.spdx.json').write_bytes(raw); (path / 'coverage.json').write_bytes(raw_coverage)
            pins = [path, coverage['release_id'], coverage['release_sha256'], f.sha(raw), f.sha(raw_coverage)]
            for field, value in zip(('', '-release-id', '-release-sha256', '-spdx-sha256', '-coverage-sha256'), pins):
                args += ['--' + side + field, str(value)]
        current, old = self.command(args), self.command(args, legacy=True)
        self.assertEqual(current.returncode, 0, current.stderr)
        self.assertEqual((current.returncode, current.stdout, current.stderr), (old.returncode, old.stdout, old.stderr))
        self.assertEqual(json.loads(current.stdout)['release_acceptance'], 'NOT_ADMITTED')

    def test_complete_installed_api_copy_and_relocated_aliases(self):
        self.generation(sources=True)
        before = self.snapshot(self.endpoint)
        result = self.modeled_copy()
        self.assertEqual(result['status'], 'copied-local-endpoint')
        self.assertEqual(self.snapshot(self.output), self.snapshot(self.gen))
        self.assertTrue(result['stable_contract_checked'])
        self.assertGreater(result['symlinks'], 0)
        moved = self.base / 'second location'; self.output.rename(moved)
        m = self.copy_module
        with mock.patch.object(m.e.r, 'gates_check', side_effect=lambda *a: m.e.r.load(a[-1])):
            verified = m.p.verify(moved, self.ident, self.keyring, self.key)
        self.assertEqual(verified['selected_release'], 'fixture-1')
        self.assertEqual(self.snapshot(self.endpoint), before)
        for flag in ('installation_authorized', 'production_accepted', 'network_used', 'trust_changed'):
            self.assertFalse(result[flag])

    def test_real_withdrawal_copy_from_moved_prefix_and_audited_runtime(self):
        self.generation(); self.withdraw()
        before = self.snapshot(self.endpoint)
        preview = self.command(['endpoint-copy', *self.args()])
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertEqual(json.loads(preview.stdout)['status'], 'planned-local-endpoint-copy')
        self.assertFalse(self.output.exists())
        copied = self.command(['endpoint-copy', *self.args(), '--apply'])
        self.assertEqual(copied.returncode, 0, copied.stderr)
        self.assertEqual(copied.stderr, b'')
        result = json.loads(copied.stdout)
        self.assertEqual(result['status'], 'copied-local-endpoint')
        self.assertEqual(result['withdrawn_releases'], ['fixture-1'])
        self.assertIsNone(result['selected_release'])
        self.assertEqual(self.snapshot(self.output), self.snapshot(self.gen))
        audited_out = self.base / 'audited copy'
        audited = self.command([], audited=True, output=audited_out)
        self.assertEqual(audited.returncode, 0, audited.stderr)
        expected = dict(result, output=str(audited_out))
        self.assertEqual(json.loads(audited.stdout), expected)
        self.assertEqual(self.snapshot(audited_out), self.snapshot(self.gen))
        self.assertEqual(self.snapshot(self.endpoint), before)

    def test_unmocked_installed_cli_refuses_synthetic_stable(self):
        self.generation()
        before = self.snapshot(self.endpoint)
        run = self.command(['endpoint-copy', *self.args(), '--apply'])
        self.assertEqual(run.returncode, 1)
        self.assertEqual(run.stdout, b'')
        self.assertEqual(json.loads(run.stderr)['status'], 'endpoint-copy-refused')
        self.assertFalse(self.output.exists())
        self.assertEqual(self.snapshot(self.endpoint), before)

    def test_installed_copy_refuses_tampered_package_and_retained_source(self):
        self.generation(sources=True)
        for path in (self.gen / 'release/repo' / self.archive.name, self.gen / 'release/evidence/source.tar'):
            original = path.read_bytes()
            self.edit(path, original + b'changed')
            self.rehash()
            before = self.snapshot(self.endpoint)
            m = self.copy_module
            with self.assertRaises((m.c.Error, m.e.r.Error, OSError, ValueError)):
                self.modeled_copy()
            self.assertFalse(self.output.exists())
            self.assertEqual(self.snapshot(self.endpoint), before)
            self.edit(path, original); self.rehash()

    def test_wrong_external_pins_and_existing_destination_preserved(self):
        self.generation(); self.withdraw()
        m = self.copy_module
        for changes in (dict(expected_generation='f' * 64), dict(signer='F' * 40)):
            with self.subTest(changes=changes), self.assertRaises((m.c.Error, m.e.r.Error, OSError, ValueError)):
                m.copy_generation(self.gen, changes.get('expected_generation', self.ident), self.keyring,
                                  changes.get('signer', self.key), self.output, apply=True)
            self.assertFalse(self.output.exists())
        self.output.mkdir(); (self.output / 'operator-data').write_bytes(b'held')
        run = self.command(['endpoint-copy', *self.args(), '--apply'])
        self.assertEqual(run.returncode, 1)
        self.assertEqual(run.stdout, b'')
        self.assertEqual(self.snapshot(self.output), {'operator-data': ('file', b'held')})

    def test_source_checksum_and_installed_payload_tamper_refused(self):
        recipe = recipe_copy(RECIPE_ROOT, self.base / 'recipe')
        checker = module('tamper_package_checker', recipe / 'check_package.py')
        runtime = recipe / 'endpoint__copy_endpoint.py'
        runtime.write_bytes(runtime.read_bytes() + b'\n# tampered\n')
        with self.assertRaises((ValueError, OSError)):
            checker.verify_sources(recipe)
        runtime.write_bytes(self.source_bytes[COPY])
        changed = self.base / 'changed prefix'; shutil.copytree(self.prefix, changed)
        path = changed / COPY; original = path.read_bytes(); path.write_bytes(original + b'\n# tampered\n')
        with self.assertRaises((ValueError, OSError)):
            checker.verify_payload(recipe, changed)
        path.write_bytes(original); path.chmod(0o755)
        with self.assertRaises((ValueError, OSError)):
            checker.verify_payload(recipe, changed)
        path.chmod(0o644); (changed / 'unlisted').write_bytes(b'unknown')
        with self.assertRaises((ValueError, OSError)):
            checker.verify_payload(recipe, changed)

    def test_privacy_observer_denies_outside_reads_and_unlisted_actors(self):
        outside = self.workspace / 'outside-private-input'; outside.write_bytes(b'PRIVATE OUTSIDE CONTENT')
        run = subprocess.run([sys.executable, '-I', '-B', '-c', AUDIT, str(self.prefix / COPY),
            str(self.prefix), str(self.base), str(outside), 'probe'], cwd=self.cwd,
            capture_output=True, timeout=15)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout, b'PASS_OUTSIDE_READ_RUNTIME_WRITE_SOCKET_UNLISTED_CHILD_DENIED\n')
        self.assertNotIn(b'PRIVATE OUTSIDE CONTENT', run.stdout + run.stderr)
        self.assertFalse((self.prefix / 'forbidden-write').exists())

    def test_actual_v2_package_private_upgrade_downgrade_remove_inverse(self):
        root = self.base / 'private-lifecycle'; shutil.copytree(self.old_prefix, root)
        users = {'var/lib/operator/history': b'keep operator state\n', 'etc/pacman.conf': b'keep operator configuration\n',
                 'home/operator/public.gpg': self.keyring.read_bytes()}
        for name, body in users.items():
            p = root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(body)
        baseline = snapshot(root)
        def write_rows(rows):
            for name, (body, mode) in rows.items():
                p = root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(body); p.chmod(mode)
        def remove_rows(names):
            for name in names:
                (root / name).unlink()
            for directory in sorted(root.rglob('*'), key=lambda p: len(p.parts), reverse=True):
                if directory.is_dir() and not any(directory.iterdir()):
                    directory.rmdir()
        new_rows = snapshot(self.prefix)
        remove_rows(set(self.old_rows) - set(new_rows)); write_rows(new_rows)
        upgraded = snapshot(root)
        self.assertEqual(set(upgraded), set(new_rows) | set(users))
        for name, row in new_rows.items(): self.assertEqual(upgraded[name], row)
        run = subprocess.run([str(root / 'usr/bin' / NAME), '--version'], capture_output=True, timeout=10)
        self.assertEqual(run.stdout, b'cachy-asahi-release-tools 0.3.0\n')
        remove_rows(set(new_rows) - set(self.old_rows)); write_rows(self.old_rows)
        self.assertEqual(snapshot(root), baseline)
        old = subprocess.run([str(root / 'usr/bin' / NAME), '--version'], capture_output=True, timeout=10)
        self.assertEqual(old.stdout, b'cachy-asahi-release-tools 0.2.0\n')
        remove_rows(self.old_rows)
        self.assertEqual({name: row[0] for name, row in snapshot(root).items()}, users)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, default=HERE)
    options, rest = parser.parse_known_args()
    RECIPE_ROOT = options.recipe_root.resolve()
    unittest.main(argv=[sys.argv[0], *rest])
