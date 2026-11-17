#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-fenced synthetic archive DATA controls; no native/build/Root authority."""
import argparse
import ast
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
BASE = Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-fish48-source-r1/closed-source-tree/held-source32/scripts/ci/fish-config02-native-source')
RUNTIME = BASE / 'runtime/scripts'
ACTORS = []
TEMP_ROOT = Path(os.environ.get('TMPDIR', '/tmp'))
if TEMP_ROOT not in (Path('/tmp'), Path('/dev/shm')):
    raise SystemExit('XZ DATA TMPDIR must be /tmp or /dev/shm')
MODEL_PREFIX = str(TEMP_ROOT / 'FISH-XZ-DATA.')


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'fcntl.')) or event in {
        'os.system', 'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn', 'resource.setrlimit', 'os.kill', 'os.killpg',
    }:
        ACTORS.append(event)
        raise RuntimeError('XZ DATA controls prohibit actor: ' + event)
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        flags = args[2] or 0
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            if not str(Path(os.fsdecode(args[0])).absolute()).startswith(MODEL_PREFIX):
                raise RuntimeError('XZ DATA writes require disposable synthetic fixture')


sys.addaudithook(fence)


def load(raw, filename):
    scope = dict(__file__=str(filename), __name__='fish_xz_inert_data')
    exec(compile(raw, str(filename), 'exec'), scope)
    return scope


def functions(raw, names, scope):
    nodes = [node for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in nodes} != set(names): raise ValueError('exact known frozen function set')
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<frozen-known-DATA-functions>', 'exec'), scope)
    return scope


X = load((HERE / 'xz_projection.py').read_bytes(), HERE / 'xz_projection.py')
C = load((BASE / 'contract.py').read_bytes(), BASE / 'contract.py')
PROJECTED = X['projected_contract']((BASE / 'contract.py').read_bytes())
NEW = load(PROJECTED, BASE / 'contract.py')
BUILDER = NEW['projected_build']((RUNTIME / 'build/build_v2.py').read_bytes())
COMPARATOR = NEW['projected_compare']((RUNTIME / 'build/compare_v2.py').read_bytes())
CHECKS = load((RUNTIME / 'checks/package_checks.py').read_bytes(), RUNTIME / 'checks/package_checks.py')
IMAGE = 'sha256:' + 'a' * 64


def archive(path, bodies, mode='w:xz'):
    with tarfile.open(path, mode, format=tarfile.USTAR_FORMAT) as stream:
        for name, body in bodies.items():
            item = tarfile.TarInfo(name)
            item.mode, item.uid, item.gid, item.mtime, item.size = 0o644, 0, 0, 1791748800, len(body)
            stream.addfile(item, io.BytesIO(body))


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def builder_gate():
    main = next(node for node in ast.parse(BUILDER).body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    body = next(node for node in main.body if isinstance(node, ast.Try)).body
    start = next(index for index, node in enumerate(body) if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'paths' for target in node.targets))
    stop = next(index for index in range(start, len(body)) if isinstance(body[index], ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'reports' for target in body[index].targets))
    return compile(ast.Module(body=body[start:stop + 1], type_ignores=[]), '<actual-projected-builder-DATA-gates>', 'exec')


class XZControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='FISH-XZ-DATA.', dir=TEMP_ROOT)
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.assertEqual, ACTORS, [], 'actual subprocess/network/lease actors must remain zero')
        self.pidfd = patch.object(os, 'pidfd_open', create=True, side_effect=AssertionError('no actual PIDFD'))
        self.pidfd.start()
        self.addCleanup(self.pidfd.stop)
        self.inputs = json.loads((BASE / 'reviewed-inputs.json').read_bytes())
        self.metadata = CHECKS['metadata']((BASE / 'recipe/.SRCINFO').read_text())
        self.bodies = {
            '.PKGINFO': b'pkgname = cachy-asahi-fish-config\npkgbase = cachy-asahi-fish-config\npkgver = 0.1.0-2\narch = any\nlicense = MIT\ndepend = fish\ndepend = coreutils\ncheckdepend = python>=3.11\n',
            '.BUILDINFO': ('format = 2\npkgname = cachy-asahi-fish-config\npkgver = 0.1.0-2\npkgarch = any\npkgbuild_sha256sum = ' + self.inputs['PKGBUILD'] + '\n').encode(),
            '.MTREE': gzip.compress(b'#mtree\n./usr/share/fish/vendor_conf.d/cachy-asahi.fish type=file\n', mtime=0),
            'usr/share/fish/vendor_conf.d/cachy-asahi.fish': (BASE / 'recipe/config.fish').read_bytes(),
            'usr/share/licenses/cachy-asahi-fish-config/LICENSE': (BASE / 'recipe/LICENSE').read_bytes(),
        }

    def package(self, directory=None, name=None, mode='w:xz'):
        directory = self.root if directory is None else directory
        path = directory / (name or X['PACKAGE'])
        archive(path, self.bodies, mode)
        return path

    def comparator(self, raw=COMPARATOR, inspector=None):
        scope = dict(Path=Path, json=json, digest=CHECKS['digest'], package=CHECKS['package'] if inspector is None else inspector,
                     PACKAGE_METADATA=CHECKS['PACKAGE_METADATA'], FIELDS=CHECKS['FIELDS'], ARCH_FIELDS=CHECKS['ARCH_FIELDS'])
        functions((RUNTIME / 'build/build_v2.py').read_bytes(), ['normalize_metadata', 'bind_artifact'], scope)
        return functions(raw, ['verify', 'compare'], scope)

    def pair(self, name=None, mode='w:xz'):
        name = X['PACKAGE'] if name is None else name
        roots = [self.root / 'first', self.root / 'second']
        marker = load((BASE / 'finish_pair.py').read_bytes(), BASE / 'finish_pair.py')['MARKER']
        for index, root in enumerate(roots):
            (root / 'artifacts').mkdir(parents=True)
            (root / 'inputs').mkdir()
            artifact = self.package(root / 'artifacts', name, mode)
            for filename in self.inputs:
                (root / 'inputs' / filename).write_bytes((BASE / 'recipe' / filename).read_bytes())
            required = ['build.log', 'validation.json', 'expected-packages.lock', 'artifacts/packages.lock', 'artifacts/generated.SRCINFO',
                        'artifacts/environment.txt', 'artifacts/config.sha256', 'artifacts/makepkg.conf', 'artifacts/pacman.conf']
            for filename in required: (root / filename).write_bytes(b'SYNTHETIC DATA evidence\n')
            (root / 'artifacts/cachy-asahi-fish-config-0.1.0-2-any-check.log').write_bytes(marker + b'\n')
            (root / 'artifacts' / (name + '.sig')).write_bytes(b'SYNTHETIC signature placeholder; no signature authority claimed')
            record = dict(status='built-package-static-pass', exit_code=0, mode='native', image_id=IMAGE, image=IMAGE,
                          recipe_inputs=self.inputs, recipe_metadata=self.metadata, expected_packages_sha256=hashlib.sha256((BASE / 'expected349.lock').read_bytes()).hexdigest(),
                          clean_environment_id='SYNTHETIC-DATA-' + str(index), source_date_epoch=1791748800, entry_script_sha256='b' * 64,
                          artifacts={name: CHECKS['digest'](artifact)}, files={filename: CHECKS['digest'](root / filename) for filename in required})
            write_json(root / 'provenance.json', record)
        comparison = self.root / 'comparison.json'
        write_json(comparison, dict(status='contents-reproduced', errors=[], packages={name: dict(installed_contents_equal=True, pkginfo_equal=True, buildinfo_equal=True, bytes_equal=True)}))
        return *roots, comparison

    def finisher(self, projected=True):
        raw = (BASE / 'finish_pair.py').read_bytes()
        return load(X['projected_finisher'](raw) if projected else raw, BASE / 'finish_pair.py')['finish']

    def test_finite_projection_preserves_three_edits_and_full_inverses(self):
        self.assertEqual(len(NEW['BUILD_EDITS']), 4)
        self.assertEqual(NEW['BUILD_EDITS'][:3], C['BUILD_EDITS'])
        inverse = BUILDER.decode()
        for before, after in reversed(NEW['BUILD_EDITS']):
            self.assertEqual(inverse.count(after), 1)
            inverse = inverse.replace(after, before)
        self.assertEqual(inverse.encode(), (RUNTIME / 'build/build_v2.py').read_bytes())
        self.assertEqual(COMPARATOR.replace(X['COMPARE_AFTER'].encode(), X['COMPARE_BEFORE'].encode()), (RUNTIME / 'build/compare_v2.py').read_bytes())
        original = (BASE / 'finish_pair.py').read_bytes()
        restored = X['projected_finisher'](original).replace(X['FINISH_GATE'].encode(), b'').replace(X['FINISH_AFTER'].encode(), X['FINISH_BEFORE'].encode())
        self.assertEqual(restored, original)
        self.assertEqual(X['projected_compare']((RUNTIME / 'build/compare_v2.py').read_bytes()), COMPARATOR)
        for function, raw in ((X['projected_contract'], PROJECTED), (X['projected_compare'], COMPARATOR), (X['projected_finisher'], X['projected_finisher'](original))):
            with self.assertRaises(ValueError): function(raw)
        builds, compare = NEW['plans'](Path('/DATA/source'), Path('/DATA/output'), IMAGE)
        self.assertTrue(all('build_fish02.py' in command[3] for command in builds))
        self.assertTrue(compare[3].endswith('/compare_fish_xz.py'))
        self.assertEqual(compare[-1], '--require-bytes')

    def test_actual_projected_builder_gates_precede_any_inspection(self):
        gate = builder_gate()
        for mode in ('empty', 'zst', 'gzip', 'wrongmagic', 'extra', 'good'):
            directory = self.root / mode
            directory.mkdir()
            if mode != 'empty':
                name = X['PACKAGE'].removesuffix('xz') + ('zst' if mode == 'zst' else 'gz' if mode == 'gzip' else 'xz')
                path = self.package(directory, name, 'w:gz' if mode in ('gzip', 'wrongmagic') else 'w:xz')
                if mode == 'extra': self.package(directory, 'extra.pkg.tar.xz')
                (directory / (name + '.sig')).write_bytes(b'SYNTHETIC ignored signature sidecar')
            inspector = Mock(return_value={})
            scope = dict(artifacts=directory, package=inspector)
            with self.subTest(mode=mode):
                if mode == 'good':
                    exec(gate, scope)
                    inspector.assert_called_once_with(path)
                else:
                    with self.assertRaises(ValueError): exec(gate, scope)
                    inspector.assert_not_called()

    def test_real_xz_frozen_package_and_native_readers(self):
        path = self.package()
        self.assertEqual(path.read_bytes()[:6], X['MAGIC'])
        report = CHECKS['package'](path)
        self.assertEqual(report['errors'], [])
        native = functions((RUNTIME / 'ci/native_arm.py').read_bytes(), ['pkginfo', 'inspect_package', 'rootfs_inventory'], dict(Path=Path, tarfile=tarfile))
        expected = dict(name='cachy-asahi-fish-config', version='0.1.0-2', arch='any', license=['MIT'], depends=['fish', 'coreutils'], provides=[], conflicts=[], replaces=[])
        self.assertEqual(native['inspect_package'](path, expected)['metadata'], report['metadata']['.PKGINFO'])
        rootfs = self.root / 'rootfs.tar.gz'
        archive(rootfs, {'var/lib/pacman/local/fish-1/desc': b'%NAME%\nfish\n\n%VERSION%\n4.0-1\n\n%ARCH%\naarch64\n'}, 'w:gz')
        self.assertEqual(native['rootfs_inventory'](rootfs)[0]['name'], ['fish'])

    def test_real_strict_comparator_preserves_binding_and_evidence_checks(self):
        first, second, unused = self.pair()
        comparator = self.comparator()
        result = comparator['compare'](first, second)
        self.assertEqual(result['status'], 'contents-reproduced')
        self.assertTrue(all(value is True for value in result['packages'][X['PACKAGE']].values()))
        provenance = second / 'provenance.json'
        record = json.loads(provenance.read_bytes())
        bad = copy.deepcopy(record)
        bad['recipe_metadata']['depends'] = ['different-dependency']
        write_json(provenance, bad)
        with self.assertRaisesRegex(ValueError, 'reviewed metadata'): comparator['verify'](second)
        write_json(provenance, record)
        (second / 'build.log').write_bytes(b'CHANGED DATA')
        with self.assertRaisesRegex(ValueError, 'changed evidence'): comparator['verify'](second)

    def test_actual_projected_comparator_refuses_formats_before_inspector(self):
        first, second, unused = self.pair()
        for mode in ('zst', 'gzip', 'wrongmagic', 'extra'):
            directory = self.root / ('compare-' + mode)
            directory.mkdir()
            (directory / 'artifacts').mkdir()
            record = json.loads((first / 'provenance.json').read_bytes())
            # Keep all earlier strict evidence checks real; only the inspector is a spy.
            for filename in record['files']:
                target = directory / filename
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((first / filename).read_bytes())
            name = X['PACKAGE'].removesuffix('xz') + ('zst' if mode == 'zst' else 'gz' if mode == 'gzip' else 'xz')
            path = self.package(directory / 'artifacts', name, 'w:gz' if mode in ('gzip', 'wrongmagic') else 'w:xz')
            if mode == 'extra': self.package(directory / 'artifacts', 'extra.pkg.tar.xz')
            record['artifacts'] = {name: CHECKS['digest'](path)}
            write_json(directory / 'provenance.json', record)
            inspector = Mock(side_effect=AssertionError('format reached inspector'))
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.comparator(inspector=inspector)['verify'](directory)
            inspector.assert_not_called()

    def test_nonregular_and_symlink_refusal_precedes_open_digest_and_inspection(self):
        first, second, comparison = self.pair()
        artifact = first / 'artifacts' / X['PACKAGE']
        target = self.package(self.root, 'target.xz')
        original_open = Path.open
        for mode in ('fifo', 'symlink', 'directory'):
            artifact.unlink()
            if mode == 'fifo': os.mkfifo(artifact)
            elif mode == 'symlink': artifact.symlink_to(target)
            else: artifact.mkdir()
            opened = []
            def guarded_open(path, *args, **kwargs):
                if path == artifact:
                    opened.append(str(path))
                    raise AssertionError('nonregular archive must never be opened')
                return original_open(path, *args, **kwargs)
            inspector = Mock(side_effect=AssertionError('nonregular archive reached inspector'))
            digest = Mock(side_effect=AssertionError('format gate must precede every comparator digest'))
            comparator = self.comparator(inspector=inspector)
            comparator['digest'] = digest
            finish = self.finisher()
            with self.subTest(mode=mode), patch.object(Path, 'open', guarded_open):
                with self.assertRaisesRegex(ValueError, 'ordinary Fish XZ'):
                    exec(builder_gate(), dict(artifacts=first / 'artifacts', package=inspector))
                with self.assertRaisesRegex(ValueError, 'ordinary Fish XZ'):
                    comparator['verify'](first)
                with self.assertRaisesRegex(ValueError, 'ordinary Fish XZ'):
                    finish(first, second, comparison, IMAGE)
            self.assertEqual(opened, [])
            digest.assert_not_called()
            inspector.assert_not_called()
            if mode == 'directory': artifact.rmdir()
            else: artifact.unlink()
            self.package(first / 'artifacts')

    def test_old_finisher_accepts_wrong_format_new_finisher_refuses(self):
        for mode in ('wrong-suffix', 'wrong-magic'):
            # Distinct synthetic pair directory per subcase, without any native execution.
            previous = self.root
            self.root = previous / mode
            self.root.mkdir()
            name = X['PACKAGE'].removesuffix('xz') + 'gz' if mode == 'wrong-suffix' else X['PACKAGE']
            first, second, comparison = self.pair(name, 'w:gz')
            self.assertEqual(self.finisher(False)(first, second, comparison, IMAGE)['builds'], 2)
            with self.assertRaises(ValueError): self.finisher()(first, second, comparison, IMAGE)
            self.root = previous

    def test_projected_finisher_preserves_semantics_provenance_ids_and_four_bools(self):
        first, second, comparison = self.pair()
        finish = self.finisher()
        self.assertEqual(finish(first, second, comparison, IMAGE)['Root_acceptance'], None)
        original = json.loads((second / 'provenance.json').read_bytes())
        for field, value in (('status', 'failed'), ('exit_code', 1), ('mode', 'emulated'), ('image_id', 'wrong'),
                             ('recipe_inputs', {}), ('expected_packages_sha256', 'wrong'), ('clean_environment_id', 'SYNTHETIC-DATA-0')):
            record = copy.deepcopy(original)
            record[field] = value
            write_json(second / 'provenance.json', record)
            with self.subTest(field=field), self.assertRaises(ValueError): finish(first, second, comparison, IMAGE)
        write_json(second / 'provenance.json', original)
        result = json.loads(comparison.read_bytes())
        for field in ('installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal', 'bytes_equal'):
            bad = copy.deepcopy(result)
            bad['packages'][X['PACKAGE']][field] = False
            write_json(comparison, bad)
            with self.subTest(field=field), self.assertRaises(ValueError): finish(first, second, comparison, IMAGE)
        write_json(comparison, result)
        (second / 'artifacts/cachy-asahi-fish-config-0.1.0-2-any-check.log').write_bytes(b'STALE OR DISABLED SYNTHETIC CHECK')
        with self.assertRaisesRegex(ValueError, 'semantic check'): finish(first, second, comparison, IMAGE)


if __name__ == '__main__':
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode or not __debug__:
        raise SystemExit('run DATA controls with Python -I -B, unoptimized')
    unittest.main(verbosity=2)
