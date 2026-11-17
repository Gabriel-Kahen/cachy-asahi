# SPDX-License-Identifier: MIT
"""CI integrity DATA controls; genuine archive/commit inputs are mandatory.

These tests do not launch workers or Source programs. The separately executed
runner proves all65 original controls; runner self-controls are counted apart.
"""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import tempfile
import unittest

ACTORS = []


def fence(event, args):
    denied = event.startswith(('subprocess.', 'socket.', 'os.exec', 'os.spawn', 'os.fork', 'os.posix_spawn')) or event in ('os.system', 'fcntl.flock')
    if event == 'ctypes.dlopen': denied = not args or args[0] is not None
    if event in ('ctypes.dlsym', 'ctypes.dlsym/handle'): denied = len(args) < 2 or args[1] != 'renameat2'
    if denied:
        ACTORS.append(event)
        raise AssertionError('CI_SELF_CONTROL_NO_ROLE: ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('project19_ci_self_controls', HERE / 'ci.py')
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
SOURCE367 = dict(files=367, bytes=43757093, tree='f846369139e03239d500cb737092b5eeb358c260',
                 map_sha256='189430cae42422e8f50d8de38a41976d87a8b4a0fcec527a3949d6031eccc2f6')
COMMIT = '8fb13c028cf043119f8324eb089c51d74e3891ee'


class ResultControls(unittest.TestCase):
    def good(self):
        result = unittest.TestResult(); result.testsRun = 65
        return result

    def test_success_requires_exact65_without_double_counting_interface38(self):
        report = C.require_result(self.good(), [], 65)
        self.assertEqual(report['tests'], 65)
        self.assertEqual(report['skips'], 0)
        self.assertEqual(report['actor_attempts'], 0)
        self.assertEqual(report['status'], 'PASS_ACTOR_FREE_DATA_ONLY')

    def test_count_drift_failure_error_and_skip_never_become_success(self):
        for mutation in ('count', 'failure', 'error', 'skip', 'expected-failure', 'unexpected-success'):
            result = self.good()
            if mutation == 'count': result.testsRun = 64
            elif mutation == 'failure': result.failures = [(None, 'MODEL_FAILED_ASSERTION')]
            elif mutation == 'error': result.errors = [(None, 'MODEL_IMPORT_FAILURE')]
            elif mutation == 'skip': result.skipped = [(None, 'MODEL_MISSING_GENUINE_SOURCE')]
            elif mutation == 'expected-failure': result.expectedFailures = [(None, 'MODEL_EXPECTED_FAILURE')]
            else: result.unexpectedSuccesses = [None]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): C.require_result(result, [], 65)

    def test_caught_actor_attempt_refuses_even_if_suite_claims_all_passed(self):
        for attempts in (['subprocess.Popen'], ['socket.connect'], ['ctypes.dlopen:package.so']):
            with self.subTest(attempts=attempts), self.assertRaises(ValueError): C.require_result(self.good(), attempts, 65)

    def test_checkout_evidence_refuses_before_missing_inputs_or_workers(self):
        output = C.ROOT / 'MODEL_CI_EVIDENCE_FORBIDDEN'
        self.assertFalse(output.exists())
        with self.assertRaises(ValueError): C.run(HERE / 'MODEL_ABSENT.tar', HERE / 'MODEL_ABSENT.commit', output)
        self.assertFalse(output.exists())
        self.assertEqual(ACTORS, [])


class GenuineExtraction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selected = {name: os.environ.get(name) for name in ('RUST199_CI_SOURCE_ARCHIVE', 'RUST199_CI_SOURCE_COMMIT')}
        if not all(selected.values()):
            raise AssertionError('genuine CI controls require explicit RUST199_CI_SOURCE_ARCHIVE and RUST199_CI_SOURCE_COMMIT; no local Root fallback or skip')
        cls.archive = Path(selected['RUST199_CI_SOURCE_ARCHIVE']); cls.commit = Path(selected['RUST199_CI_SOURCE_COMMIT'])
        cls.original = {p: (hashlib.sha256(p.read_bytes()).hexdigest(), stat.S_IMODE(p.stat().st_mode)) for p in (cls.archive, cls.commit)}
        raw = cls.commit.read_bytes()
        if hashlib.sha1(b'commit ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() != COMMIT:
            raise AssertionError('explicit zero-parent Source367 commit bytes differ')
        if any(line.startswith(b'parent ') for line in raw.split(b'\n\n', 1)[0].splitlines()):
            raise AssertionError('published Source367 must remain zero-parent')

    @classmethod
    def tearDownClass(cls):
        for p, expected in cls.original.items():
            if (hashlib.sha256(p.read_bytes()).hexdigest(), stat.S_IMODE(p.stat().st_mode)) != expected:
                raise AssertionError('original Source367 archive/commit DATA changed')
        if ACTORS: raise AssertionError('actual role attempt observed')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='project19-ci-self-DATA-')
        self.addCleanup(temporary.cleanup); self.root = Path(temporary.name)

    def extract(self, archive=None, commit=None, output=None):
        return C.extract_source(archive or self.archive, commit or self.commit, output or self.root / 'parent367')

    def test_published_zero_parent_archive_extracts_exact_closed367_without_execution(self):
        identity = self.extract()
        self.assertEqual(identity, SOURCE367)
        output = self.root / 'parent367'
        self.assertEqual(len([p for p in output.rglob('*') if p.is_file()]), 367)
        raw = (output / 'source-map.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), SOURCE367['map_sha256'])
        self.assertFalse((output / '.git').exists()); self.assertEqual(ACTORS, [])

    def test_mutated_commit_or_truncated_archive_refuses_before_output(self):
        commit = self.root / 'wrong-commit.raw'; commit.write_bytes(self.commit.read_bytes() + b'MODEL_CHANGED')
        with self.assertRaises((ValueError, KeyError)): self.extract(commit=commit)
        self.assertFalse((self.root / 'parent367').exists())
        archive = self.root / 'truncated.tar'; archive.write_bytes(self.archive.read_bytes()[:1024])
        with self.assertRaises((ValueError, KeyError, tarfile.TarError)): self.extract(archive=archive)
        self.assertFalse((self.root / 'parent367').exists())

    def test_foreign_nodes_modes_links_and_paths_cannot_enter_genuine_export(self):
        for mutation in ('foreign', 'empty-dir', 'symlink', 'path-escape', 'mode0664'):
            archive = self.root / (mutation + '.tar'); shutil.copyfile(self.archive, archive)
            if mutation == 'mode0664':
                with tarfile.open(self.archive, 'r:') as source, tarfile.open(archive, 'w:') as target:
                    changed = False
                    for member in source:
                        if member.isfile() and not changed: member.mode = 0o664; changed = True
                        if member.isfile():
                            with source.extractfile(member) as body: target.addfile(member, body)
                        else: target.addfile(member)
                self.assertTrue(changed)
            else:
                member = tarfile.TarInfo('../MODEL_ESCAPE' if mutation == 'path-escape' else 'MODEL_FOREIGN')
                member.mode = 0o644
                if mutation == 'empty-dir': member.type = tarfile.DIRTYPE; member.mode = 0o755
                elif mutation == 'symlink': member.type = tarfile.SYMTYPE; member.linkname = '/MODEL_DO_NOT_READ'
                else: member.size = 5
                with tarfile.open(archive, 'a') as package: package.addfile(member, io.BytesIO(b'MODEL') if member.isfile() else None)
            output = self.root / ('output-' + mutation)
            with self.subTest(mutation=mutation):
                with self.assertRaises((ValueError, KeyError)): self.extract(archive=archive, output=output)
                self.assertFalse(output.exists())

    def test_existing_or_aliased_output_never_clobbers_caller_state(self):
        output = self.root / 'occupied'; output.mkdir(); sentinel = output / 'KEEP'; sentinel.write_bytes(b'CALLER_OWNED_DATA')
        with self.assertRaises((ValueError, FileExistsError)): self.extract(output=output)
        self.assertEqual(sentinel.read_bytes(), b'CALLER_OWNED_DATA')
        alias = self.root / 'alias'; alias.symlink_to(output, target_is_directory=True)
        with self.assertRaises((ValueError, FileExistsError)): self.extract(output=alias)
        self.assertEqual(sentinel.read_bytes(), b'CALLER_OWNED_DATA')


if __name__ == '__main__': unittest.main(verbosity=2)
