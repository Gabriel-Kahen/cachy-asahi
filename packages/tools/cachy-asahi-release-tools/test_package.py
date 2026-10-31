#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Synthetic moved-prefix controls; no install, ALPM or hardware actors."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
RECIPE_ROOT = HERE
NAME = 'cachy-asahi-topmem'
REVISION = '1' * 40


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def tar(rows):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for key, body, mode in sorted(rows):
            node = tarfile.TarInfo(key)
            node.size, node.mode, node.uid, node.gid, node.mtime = len(body), mode, 0, 0, 0
            archive.addfile(node, io.BytesIO(body))
    return out.getvalue()


class SyntheticRelease:
    """Original inert data with explicit source/archive bytes and release hashes."""
    def __init__(self, root):
        self.root = root
        self.root.mkdir()
        self.recipe = b'# Synthetic inert demo recipe; never executed.\n'
        self.license = b'Synthetic license evidence only; no legal acceptance.\n'
        self.sources = {'PKGBUILD': self.recipe, 'LICENSE': self.license,
                        'demo.txt': b'Synthetic inert source payload.\n'}
        self.pkginfo = b'pkgname = demo\npkgver = 1.0-1\narch = any\nlicense = MIT\n'
        self.buildinfo = ('pkgname = demo\npkgver = 1.0-1\npkgarch = any\n' +
                          'pkgbuild_sha256sum = ' + sha(self.recipe) + '\n' +
                          'installed = compiler-1-1-aarch64\n').encode()
        self.rows = [('.PKGINFO', self.pkginfo, 0o644), ('.BUILDINFO', self.buildinfo, 0o644),
                     ('usr/share/licenses/demo/LICENSE', self.license, 0o644),
                     ('usr/bin/demo', b'Synthetic inert archive payload.\n', 0o755)]
        self.package = dict(name='demo', version='1.0-1', arch='any',
                            filename='demo-1.0-1-any.pkg.tar.gz', sha256='',
                            provenance='provenance/demo.json', license=['MIT'])
        self.provenance = dict(schema_version=1, package=dict(name='demo', version='1.0-1', arch='any'),
            artifact_sha256='', source_commit=REVISION, recipe_sha256=sha(self.recipe), licenses=['MIT'],
            sources=[dict(url='https://example.invalid/synthetic-demo.tar.gz', sha256='2' * 64)],
            build=dict(execution='synthetic', architecture='aarch64', environment='inert', snapshot_id='synthetic'))
        self.manifest = dict(schema_version=1, release_id='synthetic-demo-release',
            created_utc='2026-10-28T00:00:00Z', packages=[self.package], files={}, symlinks={})
        self.spec = dict(schema_version=1, release_id='synthetic-demo-release', source_commit=REVISION,
            synthetic=True, policy=dict(selected_packages=['demo']), packages=[], evidence=[])
        self.record = dict(package={}, recipe_key='PKGBUILD', review_status='SYNTHETIC; no legal approval')
        self.index = dict(schema_version=1, purpose='release-source-delivery', synthetic=True, packages=[self.record])
        self.refresh_archive()
        self.refresh_source()
        self.refresh()

    def put(self, path, raw):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        self.manifest['files'][path] = sha(raw)

    def material(self, key, body):
        self.put('evidence/' + key, body)
        return dict(id=key, path=key, sha256=sha(body), bytes=len(body))

    def refresh_archive(self):
        self.archive = gzip.compress(tar(self.rows), mtime=0)
        self.package['sha256'] = self.provenance['artifact_sha256'] = sha(self.archive)
        self.put('repo/' + self.package['filename'], self.archive)
        self.record['package'] = {k: self.package[k] for k in ('name', 'version', 'arch', 'sha256')}

    def refresh_source(self):
        self.record['recipe'] = self.material('recipe', self.recipe)
        self.record['bundle'] = self.material('bundle', tar([(k, v, 0o644) for k, v in self.sources.items()]))
        self.record['notices'] = [self.material('license', self.license)]
        self.record['authorization'] = self.material('review', b'Synthetic opaque review; no permission conferred.\n')
        self.record['source_map'] = self.material('map', encoded({k: sha(v) for k, v in self.sources.items()}))

    def refresh(self, source=True):
        if source:
            raw = encoded(self.index)
            self.put('evidence/index', raw)
            self.spec['source_delivery'] = dict(schema_version=1,
                index=dict(id='index', path='index', sha256=sha(raw)))
            materials = [self.record[k] for k in ('recipe', 'bundle', 'authorization', 'source_map')]
            materials += self.record['notices']
            self.spec['evidence'] = [self.spec['source_delivery']['index']] + [
                {k: r[k] for k in ('id', 'path', 'sha256')} for r in materials]
        else:
            self.spec.pop('source_delivery', None)
            self.spec['evidence'] = []
        self.put(self.package['provenance'], encoded(self.provenance))
        self.spec['packages'] = [dict(artifact=dict(path=self.package['filename'], sha256=self.package['sha256']),
            provenance=dict(path='original-provenance.json', sha256=self.manifest['files'][self.package['provenance']]))]
        self.put('spec.json', encoded(self.spec))
        raw = encoded(self.manifest)
        (self.root / 'release.json').write_bytes(raw)
        self.pin = sha(raw)


# Runs the actual launcher in isolated Python. Reads outside the moved prefix,
# explicit temporary inputs and interpreter trees fail, as do network/children.
AUDIT_DRIVER = r'''
import os, runpy, sys, sysconfig
target, work = sys.argv[1:3]
paths = sysconfig.get_paths(vars={'base': sys.base_prefix, 'platbase': sys.base_exec_prefix})
stdlib = {os.path.realpath(paths[key]) for key in ('stdlib', 'platstdlib')}
third_party = {os.path.realpath(paths[key]) for key in ('purelib', 'platlib')}
third_party.update(os.path.join(root, leaf) for root in stdlib for leaf in ('site-packages', 'dist-packages'))
allowed = {os.path.realpath(os.path.dirname(os.path.dirname(os.path.dirname(target)))), os.path.realpath(work)}
def within(path, roots):
    return any(path == root or path.startswith(root + os.sep) for root in roots)
def check(path, flags=0):
    # The transport walks ancestor directories with openat; directory opens
    # permit traversal while file content stays within the allowed trees.
    if flags & os.O_DIRECTORY:
        return
    path = os.path.realpath(os.fsdecode(path))
    standard = within(path, stdlib) and not within(path, third_party)
    if not (within(path, allowed) or standard or path == '/dev/null'):
        raise RuntimeError('read outside moved runtime/explicit inputs: ' + path)
original_open = os.open
def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
    effective = os.path.join(os.readlink('/proc/self/fd/' + str(dir_fd)), os.fsdecode(path)) if dir_fd is not None else path
    check(effective, flags)
    return original_open(path, flags, mode, dir_fd=dir_fd)
os.open = guarded_open
def audit(event, args):
    if event.startswith(('socket.', 'subprocess.')) or event in ('os.system', 'os.posix_spawn'):
        raise RuntimeError('offline test forbids actor: ' + event)
    if event == 'open' and isinstance(args[0], (str, bytes)):
        # os.open's audit event omits dir_fd; guarded_open checks its effective
        # path. Builtin file opens and import reads carry absolute names/modes.
        if args[1] is not None or os.path.isabs(args[0]):
            check(args[0], args[2])
sys.addaudithook(audit)
sys.argv = [target, *sys.argv[3:]]
runpy.run_path(target, run_name='__main__')
'''


class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared = tempfile.TemporaryDirectory(prefix='release-tools-moved-prefix-')
        cls.addClassCleanup(cls.shared.cleanup)
        cls.base = Path(cls.shared.name)
        copied = cls.base / 'build-inputs'
        copied.mkdir()
        match = re.search(r'^source=\(([^)]*)\)', (RECIPE_ROOT / 'PKGBUILD').read_text(), re.M)
        if match is None:
            raise AssertionError('literal package source array required')
        leaves = ['PKGBUILD', '.SRCINFO', *shlex.split(match[1])]
        if len(leaves) > 64 or len(leaves) != len(set(leaves)):
            raise AssertionError('source count/duplicates')
        for leaf in leaves:
            path = RECIPE_ROOT / leaf
            if Path(leaf).name != leaf or not path.is_file() or path.is_symlink():
                raise AssertionError('flat regular package source required: ' + leaf)
            shutil.copyfile(path, copied / leaf)
        cls.recipe = cls.base / 'synthetic-recipe-input'
        cls.recipe.mkdir()
        pins = json.loads((copied / 'fixtures.json').read_bytes())['recipe_fixture']['files']
        seen = set()
        with tarfile.open(copied / 'recipe-fixture.tar', 'r:') as archive:
            for node in archive:
                if node.name not in pins or node.name in seen or not node.isfile() or node.size > 65536:
                    raise AssertionError('unexpected recipe fixture member: ' + node.name)
                raw = archive.extractfile(node).read()
                if sha(raw) != pins[node.name]:
                    raise AssertionError('recipe fixture checksum mismatch: ' + node.name)
                (cls.recipe / Path(node.name).name).write_bytes(raw)
                seen.add(node.name)
        if seen != set(pins):
            raise AssertionError('recipe fixture member set differs')
        stage = cls.base / 'staging'
        run = subprocess.run(['bash', '--noprofile', '--norc', '-c',
            'set -eu; umask 022; source "$1/PKGBUILD"; srcdir=$1; startdir=$1; pkgdir=$2; package',
            'stage', str(copied), str(stage)], cwd=cls.base,
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, capture_output=True, timeout=30)
        if run.returncode:
            raise AssertionError((run.stdout + run.stderr).decode())
        cls.prefix = cls.base / 'moved prefix'
        stage.rename(cls.prefix)
        shutil.rmtree(copied)
        cls.cli = cls.prefix / 'usr/bin/cachy-asahi-release-tools'
        cls.cwd = cls.base / 'unrelated-cwd'
        cls.cwd.mkdir()
        for name in ('sitecustomize', 'source_delivery', 'release_sbom', 'recipe_source_delivery',
                     'recipe_source_delivery_v2', 'archive_stream', 'package_checks'):
            (cls.cwd / (name + '.py')).write_text("raise RuntimeError('CWD/PYTHONPATH IMPORT FORBIDDEN')\n")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='case-', dir=self.base)
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.fixture = SyntheticRelease(self.work / 'release')

    def run_cli(self, *args, status=0, audited=False):
        command = [str(self.cli), *map(str, args)]
        if audited:
            command = [sys.executable, '-I', '-B', '-c', AUDIT_DRIVER,
                       str(self.cli), str(self.work), *map(str, args)]
        run = subprocess.run(command, cwd=self.cwd,
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'PYTHONPATH': str(self.cwd),
                 'PYTHONHOME': '/nonexistent-python-home'}, capture_output=True, timeout=30)
        self.assertEqual(run.returncode, status, (run.stdout + run.stderr).decode())
        return run

    def release_args(self, command, output, *extra):
        return (command, '--release-dir', self.fixture.root, '--release-sha256', self.fixture.pin,
                '--output', output, *extra)

    def sbom(self, output='sbom', **options):
        out = self.work / output
        self.run_cli(*self.release_args('sbom', out), **options)
        return json.loads((out / 'sbom.spdx.json').read_bytes()), json.loads((out / 'coverage.json').read_bytes())

    def recipe_pack_args(self, output, *extra):
        return ('recipe-pack', '--recipe', self.recipe, '--package', NAME,
                '--source-revision', REVISION, '--output', output, *extra)

    def test_help_version_and_subcommand_help_from_moved_prefix(self):
        self.assertIn(b'0.1.0', self.run_cli('--version').stdout)
        self.assertIn(b'source-export', self.run_cli('--help').stdout)
        for command in ('sbom', 'source-export', 'recipe-pack', 'recipe-unpack'):
            with self.subTest(command=command):
                self.assertIn(b'--output', self.run_cli(command, '--help').stdout)

    def test_auditor_selected_stdlib_and_privacy_boundaries(self):
        outside = self.base / 'unrelated-private-file'
        outside.write_bytes(b'PRIVATE CONTENT MUST NOT BE READ OR PRINTED\n')
        escape = self.work / 'escape'; escape.symlink_to(outside)
        # Exercise the identical auditor before runpy, including pkgutil's
        # lazy import from the actual selected interpreter's standard library.
        preamble, separator, _ = AUDIT_DRIVER.partition("sys.argv = [target, *sys.argv[3:]]")
        self.assertTrue(separator)
        probe = preamble + r'''
import json, pkgutil, socket, subprocess
assert within(os.path.realpath(pkgutil.__file__), stdlib)
denied = []
def refuse(label, action, reason):
    try:
        action()
    except RuntimeError as error:
        assert reason in str(error), str(error)
        denied.append(label)
    else:
        raise AssertionError('auditor allowed ' + label)
outside, escape = sys.argv[3:5]
for label, path in (
    ('unrelated-existing-file', outside),
    ('input-symlink-escape', escape),
    ('interpreter-prefix-file', os.path.join(paths['include'], 'Python.h')),
    ('stdlib-prefix-sibling', paths['stdlib'] + '-unrelated/private'),
    ('third-party', os.path.join(paths['purelib'], 'not-stdlib.py'))):
    refuse(label, lambda path=path: open(path, 'rb'), 'read outside moved runtime/explicit inputs')
parent = os.open(os.path.dirname(outside), os.O_RDONLY | os.O_DIRECTORY)
try:
    refuse('unrelated-openat', lambda: os.open(os.path.basename(outside), os.O_RDONLY, dir_fd=parent),
           'read outside moved runtime/explicit inputs')
finally:
    os.close(parent)
refuse('network-socket', socket.socket, 'offline test forbids actor: socket.')
refuse('nested-subprocess', lambda: subprocess.Popen(['/usr/bin/true']), 'offline test forbids actor: subprocess.')
print(json.dumps(dict(stdlib=sorted(stdlib), pkgutil=os.path.realpath(pkgutil.__file__), denied=denied), sort_keys=True))
'''
        run = subprocess.run([sys.executable, '-I', '-B', '-c', probe,
            str(self.cli), str(self.work), str(outside), str(escape)], cwd=self.cwd,
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'PYTHONPATH': str(self.cwd),
                 'PYTHONHOME': '/nonexistent-python-home'}, capture_output=True, timeout=30)
        self.assertEqual(run.returncode, 0, (run.stdout + run.stderr).decode())
        result = json.loads(run.stdout)
        self.assertEqual(len(result['denied']), 8)
        self.assertNotIn(b'PRIVATE CONTENT', run.stdout + run.stderr)

    def test_sbom_exact_identity_deterministic_bytes_and_offline_reads(self):
        document, report = self.sbom(audited=True)
        self.assertEqual(document['spdxVersion'], 'SPDX-2.3')
        self.assertEqual(document['packages'][0]['checksums'][0]['checksumValue'], sha(self.fixture.archive))
        self.assertEqual(document['packages'][0]['licenseDeclared'], 'MIT')
        self.assertEqual(document['packages'][0]['licenseConcluded'], 'NOASSERTION')
        self.assertTrue(report['synthetic'])
        self.assertFalse(report['legal_acceptance'])
        self.assertEqual(report['corresponding_source_completeness'], 'NOT_ASSERTED')
        self.assertEqual(report['packages'][0]['buildinfo']['installed'], ['compiler-1-1-aarch64'])
        self.assertIn('UNRESOLVED_UNRECOGNIZED_BUNDLE_PROFILE', report['packages'][0]['unresolved'])
        self.sbom('second')
        for leaf in ('coverage.json', 'sbom.spdx.json'):
            self.assertEqual((self.work / 'sbom' / leaf).read_bytes(), (self.work / 'second' / leaf).read_bytes())

    def test_source_export_exact_bytes_receipt_and_no_replace(self):
        out = self.work / 'source-export'
        args = self.release_args('source-export', out, '--package', 'demo')
        self.run_cli(*args, audited=True)
        materials = [self.fixture.record[k] for k in ('recipe', 'bundle', 'authorization', 'source_map')]
        materials += self.fixture.record['notices']
        self.assertEqual({p.name for p in out.iterdir()}, {r['id'] for r in materials} | {'source-delivery-receipt.json'})
        for row in materials:
            self.assertEqual((out / row['id']).read_bytes(), (self.fixture.root / 'evidence' / row['id']).read_bytes())
            self.assertEqual((out / row['id']).stat().st_mode & 0o777, 0o600)
        receipt = json.loads((out / 'source-delivery-receipt.json').read_bytes())
        self.assertEqual(receipt['release_sha256'], self.fixture.pin)
        self.assertFalse(receipt['legal_acceptance'])
        before = {p.name: p.read_bytes() for p in out.iterdir()}
        self.run_cli(*args, status=2)
        self.assertEqual(before, {p.name: p.read_bytes() for p in out.iterdir()})

    def test_missing_source_and_license_evidence_remain_explicit(self):
        self.fixture.rows = [r for r in self.fixture.rows if not r[0].startswith('usr/share/licenses/')]
        self.fixture.refresh_archive()
        self.fixture.refresh(source=False)
        document, report = self.sbom()
        issues = report['packages'][0]['unresolved']
        self.assertIn('BUNDLED_LICENSE_TEXT_MISSING', issues)
        self.assertIn('RETAINED_SOURCE_ASSOCIATION_MISSING', issues)
        self.assertEqual(document['packages'][0]['licenseConcluded'], 'NOASSERTION')
        out = self.work / 'missing-source'
        self.run_cli(*self.release_args('source-export', out, '--package', 'demo'), status=2)
        self.assertFalse(out.exists())

    def test_license_conflict_yields_noassertion(self):
        self.fixture.provenance['licenses'] = ['Apache-2.0']
        self.fixture.refresh()
        document, report = self.sbom()
        self.assertEqual(document['packages'][0]['licenseDeclared'], 'NOASSERTION')
        self.assertIn('LICENSE_DECLARATIONS_DIFFER', report['packages'][0]['unresolved'])

    def test_release_profile_sets_and_absent_package_refusal(self):
        outputs = []
        for profile in ('v1', 'v2'):
            out = self.work / ('profile-' + profile)
            self.run_cli(*self.release_args('sbom', out, '--profile-set', profile))
            outputs.append({p.name: p.read_bytes() for p in out.iterdir()})
        self.assertEqual(*outputs)
        out = self.work / 'absent-package'
        self.run_cli(*self.release_args('source-export', out, '--package', 'absent'), status=2)
        self.assertFalse(out.exists())

    def test_tampered_release_archive_or_source_refused_before_output(self):
        for kind in ('release', 'archive', 'source'):
            with self.subTest(kind=kind):
                fixture = SyntheticRelease(self.work / ('input-' + kind))
                path = {'release': fixture.root / 'release.json',
                        'archive': fixture.root / 'repo' / fixture.package['filename'],
                        'source': fixture.root / 'evidence/license'}[kind]
                path.write_bytes(path.read_bytes() + b'tampered')
                out = self.work / ('refused-' + kind)
                self.run_cli('sbom', '--release-dir', fixture.root, '--release-sha256', fixture.pin,
                             '--output', out, status=2)
                self.assertFalse(out.exists())

    def test_output_existing_and_symlink_refused_without_mutation(self):
        occupied = self.work / 'occupied'
        occupied.mkdir()
        sentinel = occupied / 'sentinel'
        sentinel.write_bytes(b'preserve me\n')
        link = self.work / 'output-link'
        link.symlink_to(occupied, target_is_directory=True)
        for out in (occupied, link):
            self.run_cli(*self.release_args('sbom', out), status=2)
        self.assertEqual({p.name for p in occupied.iterdir()}, {'sentinel'})
        self.assertEqual(sentinel.read_bytes(), b'preserve me\n')

    def test_recipe_unbound_roundtrip_exact_bytes_both_profile_sets(self):
        expected = {p.name: p.read_bytes() for p in self.recipe.iterdir() if p.is_file()}
        for profile in ('v1', 'v2'):
            with self.subTest(profile=profile):
                out = self.work / ('pack-' + profile)
                result = json.loads(self.run_cli(*self.recipe_pack_args(out, '--profile-set', profile)).stdout)
                self.assertEqual(result['archive_status'], 'UNBOUND_NO_ARCHIVE_SUPPLIED')
                manifest = json.loads((out / 'bundle.json').read_bytes())
                self.assertIsNone(manifest['archive_binding'])
                self.assertEqual(manifest['physical_m2'], 'NOT_RUN')
                target = self.work / ('unpack-' + profile)
                self.run_cli('recipe-unpack', '--profile-set', profile, '--bundle', out / 'source.tar',
                    '--sha256', sha((out / 'source.tar').read_bytes()), '--output', target, audited=True)
                self.assertEqual(expected, {p.name: p.read_bytes() for p in target.iterdir()})

    def synthetic_recipe_archive(self, extra=False, tamper=False):
        info = {}
        for line in (self.recipe / '.SRCINFO').read_text().splitlines():
            if ' = ' in line:
                key, value = line.strip().split(' = ', 1)
                info.setdefault(key, []).append(value)
        fields = dict(pkgname=[NAME], pkgbase=[NAME], pkgver=['0.1.0-1'], arch=['any'], license=['MIT'],
                      depend=info.get('depends', []), optdepend=info.get('optdepends', []))
        def metadata(values):
            return ''.join(k + ' = ' + x + '\n' for k, entries in values.items() for x in entries).encode()
        build = dict(format=['2'], pkgname=[NAME], pkgver=['0.1.0-1'], pkgarch=['any'],
                     pkgbuild_sha256sum=[sha((self.recipe / 'PKGBUILD').read_bytes())])
        rows = [('usr/bin/' + NAME, b'tampered\n' if tamper else (self.recipe / NAME).read_bytes(), 0o755),
                ('usr/share/doc/' + NAME + '/README.md', (self.recipe / 'README.md').read_bytes(), 0o644),
                ('usr/share/licenses/' + NAME + '/NOTICE', (self.recipe / 'NOTICE').read_bytes(), 0o644),
                ('usr/share/licenses/' + NAME + '/LICENSE', (self.recipe / 'LICENSE').read_bytes(), 0o644),
                ('.PKGINFO', metadata(fields), 0o644), ('.BUILDINFO', metadata(build), 0o644),
                ('.MTREE', b'SYNTHETIC archive; no native build or ALPM installation ran.\n', 0o644)]
        if extra:
            rows.append(('usr/bin/unexpected', b'foreign payload\n', 0o755))
        path = self.work / ('synthetic-' + str(extra) + '-' + str(tamper) + '.pkg.tar')
        path.write_bytes(tar(rows))
        return path

    def test_recipe_bound_synthetic_archive_and_explicit_association(self):
        archive = self.synthetic_recipe_archive()
        review = self.work / 'review'
        review.write_bytes(b'SYNTHETIC opaque review; no legal permission.\n')
        out = self.work / 'bound'
        self.run_cli(*self.recipe_pack_args(out, '--archive', archive, '--review', review,
            '--review-status', 'SYNTHETIC ONLY; no legal approval', '--synthetic'))
        manifest = json.loads((out / 'bundle.json').read_bytes())
        self.assertEqual(manifest['archive_status'], 'BOUND')
        self.assertEqual(manifest['archive_binding']['archive_sha256'], sha(archive.read_bytes()))
        self.assertEqual(manifest['archive_binding']['native_execution'], 'NOT_ESTABLISHED')
        index = json.loads((out / 'source-delivery.json').read_bytes())
        self.assertTrue(index['synthetic'])
        self.assertEqual(index['packages'][0]['package']['sha256'], sha(archive.read_bytes()))
        self.assertEqual((out / 'existing-review').read_bytes(), review.read_bytes())

    def test_recipe_foreign_payload_and_changed_source_refused(self):
        for extra, tamper in ((True, False), (False, True)):
            out = self.work / ('bad-archive-' + str(extra))
            archive = self.synthetic_recipe_archive(extra=extra, tamper=tamper)
            self.run_cli(*self.recipe_pack_args(out, '--archive', archive), status=2)
            self.assertFalse(out.exists())
        changed = self.work / 'changed-recipe'
        shutil.copytree(self.recipe, changed)
        (changed / NAME).write_bytes(b'changed declared source\n')
        out = self.work / 'changed-source'
        self.run_cli('recipe-pack', '--recipe', changed, '--package', NAME,
            '--source-revision', REVISION, '--output', out, status=2)
        self.assertFalse(out.exists())

    def test_recipe_bundle_digest_and_no_replace(self):
        out = self.work / 'recipe'
        args = self.recipe_pack_args(out)
        self.run_cli(*args)
        before = {p.name: p.read_bytes() for p in out.iterdir()}
        self.run_cli(*args, status=2)
        self.assertEqual(before, {p.name: p.read_bytes() for p in out.iterdir()})
        target = self.work / 'wrong-hash'
        self.run_cli('recipe-unpack', '--bundle', out / 'source.tar', '--sha256', '0' * 64,
                     '--output', target, status=2)
        self.assertFalse(target.exists())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, default=HERE)
    options, rest = parser.parse_known_args()
    RECIPE_ROOT = options.recipe_root.resolve()
    unittest.main(argv=[sys.argv[0], *rest])
