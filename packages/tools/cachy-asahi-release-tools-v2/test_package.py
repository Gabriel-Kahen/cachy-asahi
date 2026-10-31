#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Focused synthetic comparison CLI controls; no installation or hardware actors."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
RECIPE_ROOT = HERE
NAME = 'cachy-asahi-release-tools'


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fixture(release_id='synthetic-before', names=('alpha', 'beta')):
    document = dict(spdxVersion='SPDX-2.3', dataLicense='CC0-1.0', SPDXID='SPDXRef-DOCUMENT',
        name='cachy-asahi-' + release_id, documentNamespace='https://spdx.org/spdxdocs/cachy-asahi-' + '1' * 64,
        packages=[], relationships=[])
    coverage = dict(schema_version=1, purpose='release-sbom-coverage', release_id=release_id,
        release_sha256=sha(release_id.encode()), synthetic=True, packages=[], input_files=[],
        package_count=len(names), unresolved_package_count=len(names))
    for name in names:
        identity = dict(name=name, version='1.0-1', arch='any', sha256=sha(name.encode()))
        sid = 'SPDXRef-Package-' + sha(encoded(identity))
        archive = dict(path='repo/' + name + '-1.0-1-any.pkg.tar.xz', sha256=identity['sha256'], bytes=100)
        provenance = dict(path='provenance/' + name + '.json', sha256=sha((name + '-synthetic-provenance').encode()), bytes=50)
        sources = [dict(url='https://example.invalid/synthetic-' + name + '.tar.gz',
            sha256=sha((name + '-synthetic-source').encode()), commit=None,
            status='PINNED_REMOTE_REFERENCE_NOT_FETCHED', unresolved_reason=None,
            remote_retrievability='NOT_CHECKED_OFFLINE')]
        row = dict(package=identity, spdx_id=sid, archive=archive, provenance=provenance,
            recipe_sha256=sha(b'synthetic recipe'), declared_license='MIT',
            raw_license_declarations=dict(pkginfo=['MIT'], release=['MIT'], provenance=['MIT']),
            bundled_license_evidence=[dict(path='usr/share/licenses/' + name + '/LICENSE',
                sha256=sha(b'synthetic license evidence'), bytes=26)],
            pinned_source_references=sources, retained_source=None, build_context=None,
            retained_build_record=None, buildinfo=None, status='UNRESOLVED',
            unresolved=['BUILDINFO_MISSING', 'RETAINED_SOURCE_ASSOCIATION_MISSING'])
        coverage['packages'].append(row)
        coverage['input_files'].extend([archive, provenance])
        document['packages'].append(dict(SPDXID=sid, name=name, versionInfo='1.0-1',
            packageFileName=archive['path'][5:], checksums=[dict(algorithm='SHA256', checksumValue=identity['sha256'])],
            licenseDeclared='MIT', licenseConcluded='NOASSERTION', sourceInfo=json.dumps(dict(architecture='any',
                provenance=provenance['path'], retained_source_bundle=None, references=sources), sort_keys=True)))
        document['relationships'].append(dict(spdxElementId='SPDXRef-DOCUMENT',
            relationshipType='DESCRIBES', relatedSpdxElement=sid))
    return document, coverage


def human(report):
    total = report['summary']
    lines = [report['before']['release_id'] + ' -> ' + report['after']['release_id'],
        '{added} added, {removed} removed, {changed} changed; {held_unknowns} held unknown.'.format(**total)]
    for row in report['packages']:
        fields = ': ' + ', '.join(field['name'] for field in row['fields']) if 'fields' in row else ''
        lines.append(row['change'] + ' ' + row['name'] + fields)
    rel = report['relationships']
    lines.append('Recorded relationships: %d added, %d removed; dependency completeness NOT_ESTABLISHED.' %
        (len(rel['added']), len(rel['removed'])))
    lines.append('Evidence comparison only; legal/security/source-completeness/release acceptance not asserted.')
    return ('\n'.join(lines) + '\n').encode()


# Only selected stdlib, moved runtime and explicit input content can be read.
# Directory descriptors permit transport traversal; all file writes and actors
# are refused. This is a test observer, not a general sandbox claim.
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
    if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
        raise RuntimeError('comparison test forbids file write')
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
        raise RuntimeError('comparison test forbids actor: ' + event)
    if event in ('os.mkdir', 'os.remove', 'os.rmdir', 'os.rename', 'os.link', 'os.symlink', 'os.chmod', 'os.chown', 'os.truncate'):
        raise RuntimeError('comparison test forbids mutation: ' + event)
    if event == 'open' and isinstance(args[0], (str, bytes)):
        if args[1] is not None or os.path.isabs(args[0]):
            check(args[0], args[2])
sys.addaudithook(audit)
sys.argv = [target, *sys.argv[3:]]
runpy.run_path(target, run_name='__main__')
'''


class ComparisonPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared = tempfile.TemporaryDirectory(prefix='release-tools-v2-comparison-')
        cls.addClassCleanup(cls.shared.cleanup)
        cls.base = Path(cls.shared.name)
        copied = cls.base / 'finite-build-inputs'
        copied.mkdir()
        match = re.search(r'^source=\(([^)]*)\)', (RECIPE_ROOT / 'PKGBUILD').read_text(), re.M)
        if match is None:
            raise AssertionError('literal source array required')
        leaves = ['PKGBUILD', '.SRCINFO', *shlex.split(match[1])]
        if len(leaves) > 64 or len(leaves) != len(set(leaves)):
            raise AssertionError('source count/duplicates')
        for leaf in leaves:
            source = RECIPE_ROOT / leaf
            if Path(leaf).name != leaf or not source.is_file() or source.is_symlink():
                raise AssertionError('flat regular source required: ' + leaf)
            shutil.copyfile(source, copied / leaf)
        stage = cls.base / 'staging'
        result = subprocess.run(['bash', '--noprofile', '--norc', '-c',
            'set -eu; umask 022; source "$1/PKGBUILD"; srcdir=$1; startdir=$1; pkgdir=$2; package',
            'stage', str(copied), str(stage)], cwd=cls.base,
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, capture_output=True, timeout=30)
        if result.returncode:
            raise AssertionError((result.stdout + result.stderr).decode())
        cls.prefix = cls.base / 'moved prefix'
        stage.rename(cls.prefix)
        shutil.rmtree(copied)
        cls.cli = cls.prefix / ('usr/bin/' + NAME)
        cls.comparator = cls.prefix / 'usr/lib/cachy-asahi/release-tools-v2/scripts/release/compare_sboms.py'
        cls.cwd = cls.base / 'unrelated-cwd'
        cls.cwd.mkdir()
        for name in ('sitecustomize', 'compare_sboms', 'source_delivery', 'release_sbom', 'recipe_source_delivery',
                     'recipe_source_delivery_v2', 'archive_stream', 'package_checks'):
            (cls.cwd / (name + '.py')).write_text("raise RuntimeError('CWD/PYTHONPATH IMPORT FORBIDDEN')\n")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='case-', dir=self.base)
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)

    def save(self, values, leaf):
        document, coverage = values
        out = self.work / leaf
        out.mkdir()
        spdx = encoded(document)
        coverage['spdx_sha256'] = sha(spdx)
        raw_coverage = encoded(coverage)
        (out / 'sbom.spdx.json').write_bytes(spdx)
        (out / 'coverage.json').write_bytes(raw_coverage)
        return [out, coverage['release_id'], coverage['release_sha256'], sha(spdx), sha(raw_coverage)]

    def arguments(self, before, after, format='json'):
        result = []
        for side, pins in (('before', before), ('after', after)):
            for field, value in zip(('', '-release-id', '-release-sha256', '-spdx-sha256', '-coverage-sha256'), pins):
                result.extend(['--' + side + field, str(value)])
        return [*result, '--format', format]

    def run_command(self, args, status=0, audited=False, standalone=False):
        target = self.comparator if standalone else self.cli
        command = [sys.executable, '-I', '-B', str(target)] if standalone else [str(target)]
        if audited:
            command = [sys.executable, '-I', '-B', '-c', AUDIT_DRIVER, str(target), str(self.work)]
        command += [*([] if standalone else ['sbom-compare']), *map(str, args)]
        run = subprocess.run(command, cwd=self.cwd, capture_output=True, timeout=30,
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'PYTHONPATH': str(self.cwd), 'PYTHONHOME': '/missing-python-home'})
        self.assertEqual(run.returncode, status, (run.stdout + run.stderr).decode())
        if status == 1:
            self.assertEqual(run.stdout, b'')
            self.assertEqual(json.loads(run.stderr)['status'], 'REFUSED')
        return run

    def test_version_comparison_help_and_argparse_exit(self):
        run = subprocess.run([str(self.cli), '--version'], cwd=self.cwd, capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 0)
        self.assertEqual(run.stdout, b'cachy-asahi-release-tools 0.2.0\n')
        help_run = self.run_command(['--help'])
        self.assertIn(b'--before-coverage-sha256', help_run.stdout)
        self.assertIn(b'--after-release-id', help_run.stdout)
        invalid = self.run_command([], status=2)
        self.assertEqual(invalid.stdout, b'')
        self.assertIn(b'--before', invalid.stderr)

    def test_exact_json_human_and_held_null_noassertion(self):
        values = fixture(names=('alpha',))
        values[0]['packages'][0]['licenseDeclared'] = 'NOASSERTION'
        values[1]['packages'][0]['declared_license'] = 'NOASSERTION'
        before = self.save(values, 'before')
        args = self.arguments(before, before)
        first = self.run_command(args)
        second = self.run_command(args)
        self.assertEqual(first.stdout, second.stdout)
        report = json.loads(first.stdout)
        self.assertEqual(first.stdout, encoded(report))
        self.assertEqual(report['summary'], dict(added=0, removed=0, changed=0, held_unknowns=1))
        self.assertEqual(report['packages'], [])
        self.assertEqual(report['held_unknowns'][0]['after_license'], 'NOASSERTION')
        self.assertEqual(report['held_unknowns'][0]['after']['status'], 'UNRESOLVED')
        self.assertIsNone(values[1]['packages'][0]['build_context'])
        self.assertFalse(report['legal_acceptance'])
        self.assertEqual(report['release_acceptance'], 'NOT_ADMITTED')
        self.assertEqual(self.run_command(args, standalone=True).stdout, first.stdout)
        human_args = self.arguments(before, before, 'human')
        rendered = self.run_command(human_args)
        self.assertEqual(rendered.stdout, human(report))
        self.assertEqual(rendered.stdout, self.run_command(human_args, standalone=True).stdout)

    def test_package_and_recorded_relationship_changes(self):
        before_values = fixture(names=('alpha', 'beta'))
        after_values = fixture('synthetic-after', names=('alpha', 'gamma'))
        before_values[0]['relationships'].append(dict(spdxElementId=before_values[0]['packages'][0]['SPDXID'],
            relationshipType='DEPENDS_ON', relatedSpdxElement=before_values[0]['packages'][1]['SPDXID']))
        before = self.save(before_values, 'before')
        after = self.save(after_values, 'after')
        report = json.loads(self.run_command(self.arguments(before, after)).stdout)
        self.assertEqual([(r['name'], r['change']) for r in report['packages']], [('beta', 'removed'), ('gamma', 'added')])
        self.assertEqual(report['relationships']['removed'], [dict(subject='alpha', relationship='DEPENDS_ON', object='beta'),
            dict(subject='$document', relationship='DESCRIBES', object='beta')])
        self.assertEqual(report['relationships']['dependency_relationship_count'], dict(before=1, after=0))
        self.assertEqual(report['relationships']['dependency_completeness'], 'NOT_ESTABLISHED')
        self.assertFalse(report['relationships']['build_lock_is_dependency_graph'])

    def test_exact_caller_pins_and_semantic_join_refusal(self):
        before = self.save(fixture(), 'before')
        after = self.save(fixture('synthetic-after'), 'after')
        for side in ('before', 'after'):
            for index in (1, 2, 3, 4):
                with self.subTest(side=side, pin=index):
                    left, right = before.copy(), after.copy()
                    (left if side == 'before' else right)[index] = 'foreign-release' if index == 1 else 'f' * 64
                    self.run_command(self.arguments(left, right), status=1)
        crossed = fixture('synthetic-crosswired')
        crossed[1]['packages'][0]['provenance'] = dict(crossed[1]['packages'][0]['provenance'], sha256='c' * 64)
        crossed_pins = self.save(crossed, 'crosswired')
        run = self.run_command(self.arguments(before, crossed_pins), status=1)
        self.assertIn(b'unbound evidence reference', run.stderr)
        crossed_source = fixture('synthetic-source-crosswired')
        crossed_source[0]['packages'][0]['sourceInfo'] = '{}'
        source_pins = self.save(crossed_source, 'source-crosswired')
        run = self.run_command(self.arguments(before, source_pins), status=1)
        self.assertIn(b'source evidence mismatch', run.stderr)

    def test_stale_image_provider_crosswire_refused_valid_diff_is_data(self):
        old = fixture(names=('alpha',))
        old[1]['packages'][0]['build_context'] = dict(image='synthetic-image-A', provider='synthetic-provider-A', actual_binding=None)
        new = fixture('synthetic-after', names=('alpha',))
        new[1]['packages'][0]['build_context'] = dict(image='synthetic-image-B', provider='synthetic-provider-B', actual_binding=None)
        before = self.save(old, 'before')
        after = self.save(new, 'after')
        report = json.loads(self.run_command(self.arguments(before, after)).stdout)
        fields = report['packages'][0]['fields']
        self.assertEqual([field['name'] for field in fields], ['build_evidence'])
        context = fields[0]['after']['build_context']
        self.assertEqual(context, new[1]['packages'][0]['build_context'])
        self.assertIsNone(context['actual_binding'])
        self.assertEqual(report['native_build_validation'], 'NOT_PERFORMED')
        self.assertEqual(report['hardware_validation'], 'NOT_RUN')
        self.assertEqual(report['release_acceptance'], 'NOT_ADMITTED')
        pinned = (after[0] / 'coverage.json').read_bytes()
        for key in ('image', 'provider'):
            with self.subTest(stale_context=key):
                changed = json.loads(pinned)
                changed['packages'][0]['build_context'][key] = 'synthetic-crosswire-' + key
                (after[0] / 'coverage.json').write_bytes(encoded(changed))
                refusal = self.run_command(self.arguments(before, after), status=1)
                self.assertIn(b'coverage checksum mismatch', refusal.stderr)

    def test_audited_comparison_denies_writes_actors_and_checkout_reads(self):
        before = self.save(fixture(), 'before')
        after = self.save(fixture('synthetic-after'), 'after')
        ordinary = self.run_command(self.arguments(before, after))
        audited = self.run_command(self.arguments(before, after), audited=True)
        self.assertEqual(audited.stdout, ordinary.stdout)
        outside = self.base / 'private-read-probe'
        outside.write_bytes(b'PRIVATE CONTENT MUST STAY UNREAD\n')
        preamble, separator, _ = AUDIT_DRIVER.partition("sys.argv = [target, *sys.argv[3:]]")
        self.assertTrue(separator)
        probe = preamble + r'''
import socket, subprocess
outside = sys.argv[3]
def refused(action):
    try:
        action()
    except RuntimeError:
        return
    raise AssertionError('auditor allowed prohibited operation')
refused(lambda: open(outside, 'rb'))
refused(lambda: open(os.path.join(work, 'forbidden-write'), 'wb'))
refused(lambda: os.mkdir(os.path.join(work, 'forbidden-directory')))
refused(socket.socket)
refused(lambda: subprocess.Popen(['/usr/bin/true']))
print('PASS_DENIED_READ_WRITE_MUTATION_NETWORK_CHILD')
'''
        run = subprocess.run([sys.executable, '-I', '-B', '-c', probe, str(self.cli), str(self.work), str(outside)],
            cwd=self.cwd, capture_output=True, timeout=20)
        self.assertEqual(run.returncode, 0, (run.stdout + run.stderr).decode())
        self.assertEqual(run.stdout, b'PASS_DENIED_READ_WRITE_MUTATION_NETWORK_CHILD\n')
        self.assertFalse((self.work / 'forbidden-write').exists())
        self.assertFalse((self.work / 'forbidden-directory').exists())
        self.assertNotIn(b'PRIVATE CONTENT', run.stdout + run.stderr)

    def test_input_bytes_and_tree_untouched_on_success_and_refusal(self):
        before = self.save(fixture(), 'before')
        after = self.save(fixture('synthetic-after'), 'after')
        snapshot = {p.relative_to(self.work).as_posix(): p.read_bytes() for p in self.work.rglob('*') if p.is_file()}
        self.run_command(self.arguments(before, after), audited=True)
        self.run_command(self.arguments(before, after, 'human'))
        wrong = after.copy()
        wrong[3] = 'e' * 64
        self.run_command(self.arguments(before, wrong), status=1)
        current = {p.relative_to(self.work).as_posix(): p.read_bytes() for p in self.work.rglob('*') if p.is_file()}
        self.assertEqual(current, snapshot)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, default=HERE)
    options, rest = parser.parse_known_args()
    RECIPE_ROOT = options.recipe_root.resolve()
    unittest.main(argv=[sys.argv[0], *rest])
