#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Original inert fixtures and one current exporter round trip; local only."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

HERE = Path(__file__).absolute().parent
ROOT = next(p for p in HERE.parents if (p / 'scripts/release/source_delivery.py').is_file())


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


c = module('compare_sboms_test', HERE / 'compare_sboms.py')
s = c.helpers(ROOT / 'scripts/release/source_delivery.py')
owned = module('compare_sboms_owned', ROOT / 'scripts/virtual/owned_process.py')


def fixture(release_id='fixture-1', names=('alpha', 'beta')):
    document = dict(spdxVersion='SPDX-2.3', dataLicense='CC0-1.0', SPDXID='SPDXRef-DOCUMENT',
        name='cachy-asahi-' + release_id, documentNamespace='https://spdx.org/spdxdocs/cachy-asahi-' + '1'*64,
        packages=[], relationships=[])
    coverage = dict(schema_version=1, purpose='release-sbom-coverage', release_id=release_id,
        release_sha256=s.digest(release_id.encode()), synthetic=True, packages=[], input_files=[],
        package_count=len(names), unresolved_package_count=0)
    for name in names:
        identity = dict(name=name, version='1.0-1', arch='any', sha256=s.digest(name.encode()))
        sid = 'SPDXRef-Package-' + s.digest(c.encoded(identity))
        archive = dict(path='repo/' + name + '-1.0-1-any.pkg.tar.xz', sha256=identity['sha256'], bytes=100)
        provenance = dict(path='provenance/' + name + '.json', sha256=s.digest((name+'provenance').encode()), bytes=50)
        refs = [dict(url='https://example.invalid/' + name + '.tar.gz', sha256=s.digest((name+'source').encode()),
                     commit=None, status='PINNED_REMOTE_REFERENCE_NOT_FETCHED', unresolved_reason=None,
                     remote_retrievability='NOT_CHECKED_OFFLINE')]
        license_ref = dict(path='usr/share/licenses/'+name+'/LICENSE', sha256=s.digest(b'license'), bytes=7)
        row = dict(package=identity, spdx_id=sid, archive=archive, provenance=provenance,
            recipe_sha256=s.digest(b'recipe'), declared_license='MIT', raw_license_declarations=dict(
                pkginfo=['MIT'], release=['MIT'], provenance=['MIT']), bundled_license_evidence=[license_ref],
            pinned_source_references=refs, retained_source=None, build_context=None,
            retained_build_record=None, buildinfo=None, status='UNRESOLVED',
            unresolved=['BUILDINFO_MISSING', 'RETAINED_SOURCE_ASSOCIATION_MISSING'])
        coverage['packages'].append(row); coverage['input_files'].extend([archive, provenance])
        coverage['unresolved_package_count'] += 1
        document['packages'].append(dict(SPDXID=sid, name=name, versionInfo='1.0-1', packageFileName=archive['path'][5:],
            checksums=[dict(algorithm='SHA256', checksumValue=identity['sha256'])], licenseDeclared='MIT',
            licenseConcluded='NOASSERTION', sourceInfo=json.dumps(dict(architecture='any', provenance=provenance['path'],
                retained_source_bundle=None, references=refs), sort_keys=True)))
        document['relationships'].append(dict(spdxElementId='SPDXRef-DOCUMENT', relationshipType='DESCRIBES', relatedSpdxElement=sid))
    return document, coverage


def synchronize(document, coverage):
    replacements = {}
    for package, row in zip(document['packages'], coverage['packages']):
        old = package['SPDXID']; identity = row['package']
        sid = 'SPDXRef-Package-' + s.digest(c.encoded(identity)); replacements[old] = sid
        row['spdx_id'] = package['SPDXID'] = sid
        package['versionInfo'] = identity['version']
        package['checksums'][0]['checksumValue'] = row['archive']['sha256'] = identity['sha256']
        package['licenseDeclared'] = row['declared_license']
        package['sourceInfo'] = json.dumps(dict(architecture=identity['arch'], provenance=row['provenance']['path'],
            retained_source_bundle=row['retained_source']['bundle'] if row['retained_source'] else None,
            references=row['pinned_source_references']), sort_keys=True)
        for source in coverage['input_files']:
            if source['path'] == row['archive']['path']:
                source['sha256'] = identity['sha256']
    for rel in document['relationships']:
        for key in ('spdxElementId', 'relatedSpdxElement'):
            rel[key] = replacements.get(rel[key], rel[key])


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='sbom-compare-')
        self.addCleanup(self.tmp.cleanup); self.root = Path(self.tmp.name)

    def save(self, values, leaf='export'):
        document, coverage = values
        target = self.root / leaf; target.mkdir(exist_ok=True)
        spdx_raw = c.encoded(document); coverage['spdx_sha256'] = s.digest(spdx_raw)
        coverage_raw = c.encoded(coverage)
        (target/'sbom.spdx.json').write_bytes(spdx_raw); (target/'coverage.json').write_bytes(coverage_raw)
        return (target, coverage['release_id'], coverage['release_sha256'], s.digest(spdx_raw), s.digest(coverage_raw))

    def load(self, values, leaf='export'):
        return c.load_export(*self.save(values, leaf), s)

    def refused(self, values, reason):
        with self.assertRaisesRegex((ValueError, OSError, TypeError), reason): self.load(values)

    def test_identical_and_unknowns_held(self):
        loaded = self.load(fixture()); report = c.compare(loaded, loaded)
        self.assertEqual(report['packages'], [])
        self.assertEqual(report['summary'], dict(added=0, removed=0, changed=0, held_unknowns=2))
        self.assertEqual(report['relationships']['dependency_relationship_count'], dict(before=0, after=0))
        self.assertEqual(report['relationships']['dependency_completeness'], 'NOT_ESTABLISHED')
        self.assertFalse(report['legal_acceptance'])

    def test_added_removed_packages(self):
        report = c.compare(self.load(fixture(names=('alpha',)), 'before'),
                           self.load(fixture('fixture-2', ('beta',)), 'after'))
        self.assertEqual([(r['name'], r['change']) for r in report['packages']], [('alpha', 'removed'), ('beta', 'added')])

    def test_version_artifact_source_license_changes(self):
        old, new = fixture(), fixture('fixture-2')
        row = new[1]['packages'][0]
        row['package'].update(version='2.0-1', sha256='a'*64)
        row['recipe_sha256'] = 'b'*64; row['pinned_source_references'][0]['sha256'] = 'c'*64
        row['declared_license'] = 'NOASSERTION'; row['raw_license_declarations']['pkginfo'] = ['custom/unknown']
        row['bundled_license_evidence'][0]['sha256'] = 'd'*64
        synchronize(*new)
        report = c.compare(self.load(old, 'before'), self.load(new, 'after'))
        fields = {r['name']: r for r in report['packages'][0]['fields']}
        self.assertEqual(fields['identity']['after']['version'], '2.0-1')
        self.assertEqual(fields['artifact']['after']['sha256'], 'a'*64)
        self.assertEqual(fields['source_evidence']['after']['references'][0]['sha256'], 'c'*64)
        self.assertEqual(fields['license_evidence']['after']['declared'], 'NOASSERTION')

    def test_relationship_change_and_stable_names(self):
        old, new = fixture(), fixture('fixture-2')
        rel = dict(spdxElementId=old[0]['packages'][0]['SPDXID'], relationshipType='DEPENDS_ON',
                   relatedSpdxElement=old[0]['packages'][1]['SPDXID'])
        old[0]['relationships'].append(rel); new[0]['relationships'].append(copy.deepcopy(rel))
        new[1]['packages'][0]['package']['sha256'] = 'd'*64; synchronize(*new)
        report = c.compare(self.load(old, 'before'), self.load(new, 'after'))
        self.assertEqual(report['relationships']['added'], [])
        new[0]['relationships'].pop()
        report = c.compare(self.load(old, 'before'), self.load(new, 'after'))
        self.assertEqual(report['relationships']['removed'], [dict(subject='alpha', relationship='DEPENDS_ON', object='beta')])

    def test_shuffled_order_changes_no_semantics(self):
        values = fixture(); shuffled = copy.deepcopy(values)
        for group in (shuffled[0]['packages'], shuffled[0]['relationships'], shuffled[1]['packages'], shuffled[1]['input_files']):
            group.reverse()
        for row in shuffled[1]['packages']: row['unresolved'].reverse()
        old, new = self.load(values, 'before'), self.load(shuffled, 'after')
        report = c.compare(old, new)
        self.assertEqual(report['packages'], []); self.assertEqual(report['relationships']['added'], [])
        self.assertEqual(c.encoded(report), c.encoded(c.compare(old, new)))

    def test_duplicate_and_foreign_packages(self):
        for location in (0, 1):
            values = fixture(); values[location]['packages'].append(copy.deepcopy(values[location]['packages'][0]))
            self.refused(values, 'duplicate')
        values = fixture(); values[1]['packages'][0]['package']['name'] = 'foreign'
        self.refused(values, 'foreign')

    def test_release_identity_counts_and_pins(self):
        pins = list(self.save(fixture()))
        for index, replacement in ((1, 'foreign-release'), (2, 'e'*64), (3, 'e'*64), (4, 'e'*64)):
            selected = pins.copy(); selected[index] = replacement
            with self.assertRaisesRegex(ValueError, 'identity|checksum'): c.load_export(*selected, s)
        for key in ('package_count', 'unresolved_package_count'):
            values = fixture(); values[1][key] = 0; self.refused(values, 'count')

    def test_spdx_coverage_binding_refused(self):
        pins = list(self.save(fixture())); path = pins[0]/'coverage.json'
        coverage = json.loads(path.read_bytes()); coverage['spdx_sha256'] = 'f'*64
        raw = c.encoded(coverage); path.write_bytes(raw); pins[4] = s.digest(raw)
        with self.assertRaisesRegex(ValueError, 'identity binding'): c.load_export(*pins, s)

    def test_tamper_refusal(self):
        for leaf in ('sbom.spdx.json', 'coverage.json'):
            pins = self.save(fixture()); (pins[0]/leaf).write_bytes(b'{}')
            with self.assertRaisesRegex(ValueError, 'checksum'): c.load_export(*pins, s)

    def test_package_disagreement(self):
        for key, value in (('versionInfo', 'wrong'), ('checksums', []), ('SPDXID', 'SPDXRef-foreign'),
                           ('licenseDeclared', 'GPL-3.0-only')):
            values = fixture(); values[0]['packages'][0][key] = value
            self.refused(values, 'identity|digest|license')

    def test_source_and_archive_bindings(self):
        values = fixture(); values[1]['input_files'].pop(); self.refused(values, 'unbound evidence')
        values = fixture(); values[1]['packages'][0]['pinned_source_references'][0]['sha256'] = 'bad'
        self.refused(values, 'SHA-256')
        values = fixture(); values[0]['packages'][0]['sourceInfo'] = '{}'
        self.refused(values, 'source evidence mismatch')

    def test_relationship_refusals(self):
        values = fixture(); values[0]['relationships'].append(values[0]['relationships'][0].copy())
        self.refused(values, 'duplicate relationship')
        values = fixture(); values[0]['relationships'][0]['relatedSpdxElement'] = 'SPDXRef-unknown'
        self.refused(values, 'unbound relationship')
        values = fixture(); values[0]['relationships'].pop(); self.refused(values, 'incomplete document')

    def test_duplicate_sources_and_paths(self):
        values = fixture(); values[1]['input_files'].append(values[1]['input_files'][0].copy())
        self.refused(values, 'duplicate input')
        values = fixture(); refs = values[1]['packages'][0]['pinned_source_references']; refs.append(refs[0].copy())
        synchronize(*values); self.refused(values, 'duplicate source')
        values = fixture(); refs = values[1]['packages'][0]['bundled_license_evidence']; refs.append(dict(refs[0], sha256='a'*64))
        self.refused(values, 'duplicate.*license')

    def test_noassertion_held(self):
        values = fixture(names=('alpha',)); row = values[1]['packages'][0]
        row.update(status='EVIDENCE_LINKED', unresolved=[], declared_license='NOASSERTION')
        values[1]['unresolved_package_count'] = 0; synchronize(*values)
        loaded = self.load(values); report = c.compare(loaded, loaded)
        self.assertEqual(report['held_unknowns'][0]['after_license'], 'NOASSERTION')

    def test_json_bounds(self):
        for raw, reason in ((b'{"a":1,"a":2}', 'duplicate'), (b'{"a":NaN}', 'nonfinite'),
                            (b'{"a":1.0}', 'float'), (b'{"a":'+b'['*49+b'0'+b']'*49+b'}', 'depth'),
                            (b'{"a":"\\u0000"}', 'control'), (b'{"a":9223372036854775808}', 'integer')):
            with self.assertRaisesRegex(ValueError, reason): c.decode(raw, s)
        with patch.object(c, 'MAX_NODES', 4):
            with self.assertRaisesRegex(ValueError, 'node'): c.decode(b'{"a":[1,2,3,4]}', s)

    def test_file_and_package_bounds(self):
        pins = self.save(fixture()); (pins[0]/'sbom.spdx.json').write_bytes(b' '* (s.MAX_JSON+1))
        with self.assertRaisesRegex(ValueError, 'oversized'): c.load_export(*pins, s)
        values = fixture(); values[0]['packages'] *= 129; self.refused(values, 'list bound')

    def test_unsafe_input_files(self):
        for kind in ('symlink', 'hardlink', 'fifo'):
            pins = self.save(fixture()); target = pins[0]/'coverage.json'; raw = target.read_bytes(); target.unlink()
            outside = self.root / ('outside-'+kind); outside.write_bytes(raw)
            if kind == 'symlink': target.symlink_to(outside)
            elif kind == 'hardlink': os.link(outside, target)
            else: os.mkfifo(target)
            with self.assertRaises((ValueError, OSError)): c.load_export(*pins, s)
            target.unlink()
        pins = self.save(fixture()); alias = self.root/'alias'; alias.symlink_to(pins[0], target_is_directory=True)
        with self.assertRaises((ValueError, OSError)): c.load_export(alias, *pins[1:], s)

    def test_no_network_subprocess_or_write(self):
        pins = self.save(fixture()); before = {p.name:p.read_bytes() for p in pins[0].iterdir()}
        with patch.object(socket, 'socket', side_effect=AssertionError('network')), patch.object(
                socket, 'getaddrinfo', side_effect=AssertionError('DNS')), patch.object(
                subprocess, 'Popen', side_effect=AssertionError('subprocess')):
            loaded = c.load_export(*pins, s); c.compare(loaded, loaded)
        self.assertEqual(before, {p.name:p.read_bytes() for p in pins[0].iterdir()})

    def test_current_exporter_round_trip(self):
        existing = module('current_sbom_fixture', ROOT/'scripts/release/test_release_sbom.py')
        case = existing.SBOMTests(); case.setUp()
        try:
            loaded = self.load(case.export())
            self.assertEqual(list(loaded['packages']), ['demo'])
            self.assertEqual(c.compare(loaded, loaded)['packages'], [])
        finally: case.doCleanups()

    def test_cli_json_human_and_refusal(self):
        before, after = self.save(fixture(), 'before'), self.save(fixture('fixture-2'), 'after')
        stage = self.root/'stage'; stage.mkdir()
        shutil.copyfile(HERE/'compare_sboms.py', stage/'compare_sboms.py')
        shutil.copyfile(ROOT/'scripts/release/source_delivery.py', stage/'source_delivery.py')
        argv = ['/usr/bin/python3', '-I', '-B', str(stage/'compare_sboms.py')]
        for side, pins in (('before', before), ('after', after)):
            for key, value in zip(('', '-release-id', '-release-sha256', '-spdx-sha256', '-coverage-sha256'), pins):
                argv.extend(['--'+side+key, str(value)])
        def run(args):
            owned.prepare()
            child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     start_new_session=True)
            result = owned.supervise(child, cap=10, max_output=32768)
            self.assertTrue(result['reaped']); self.assertIsNone(result['error'])
            return result
        result = run(argv); self.assertEqual(result['exit'], 0, result['output'])
        self.assertEqual(json.loads(result['output'])['summary']['held_unknowns'], 2)
        result = run(argv+['--format', 'human']); self.assertEqual(result['exit'], 0, result['output'])
        self.assertIn(b'dependency completeness NOT_ESTABLISHED', result['output'])
        (before[0]/'coverage.json').write_bytes(b'tamper')
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err): status = c.main(argv[4:], s)
        self.assertEqual(status, 1); self.assertEqual(out.getvalue(), '')
        self.assertEqual(json.loads(err.getvalue())['status'], 'REFUSED')

    def retained_fixture(self, release_id='fixture-1', checksum='a'*64):
        values = fixture(release_id, ('alpha',)); row = values[1]['packages'][0]
        refs = {key: dict(path='evidence/'+key, sha256=checksum, bytes=12) for key in ('bundle', 'recipe', 'source_map')}
        row['recipe_sha256'] = checksum
        row['retained_source'] = dict(**refs, notices=[], profile='UNRESOLVED_UNRECOGNIZED_BUNDLE_PROFILE',
            issues=['UNRESOLVED_UNRECOGNIZED_BUNDLE_PROFILE'], matched_license_sha256=[])
        values[1]['input_files'].extend(refs.values()); synchronize(*values)
        return values

    def test_retained_source_digest_change(self):
        before = self.load(self.retained_fixture(), 'before')
        after = self.load(self.retained_fixture('fixture-2', 'b'*64), 'after')
        fields = {r['name']:r for r in c.compare(before, after)['packages'][0]['fields']}
        self.assertEqual(fields['source_evidence']['after']['retained']['bundle']['sha256'], 'b'*64)

    def test_retained_recipe_and_bundle_joins(self):
        values = self.retained_fixture(); values[1]['packages'][0]['recipe_sha256'] = 'f'*64
        self.refused(values, 'retained recipe digest')
        for values in (self.retained_fixture(), fixture()):
            values[1]['packages'][0]['pinned_source_references'][0]['resolved_by_bundle_sha256'] = 'f'*64
            synchronize(*values); self.refused(values, 'resolved bundle digest')

    def test_long_sourceinfo_supported(self):
        values = fixture(names=('alpha',)); refs = values[1]['packages'][0]['pinned_source_references']
        for number in range(40):
            refs.append(dict(refs[0], url='https://example.invalid/long-source-%d.tar.gz'%number))
        synchronize(*values)
        self.assertGreater(len(values[0]['packages'][0]['sourceInfo']), 4096)
        self.assertEqual(len(self.load(values)['packages']), 1)

    def test_duplicate_notices_and_archive_digests(self):
        values = self.retained_fixture(); notice = dict(path='evidence/notice', sha256='b'*64, bytes=10)
        values[1]['input_files'].append(notice)
        values[1]['packages'][0]['retained_source']['notices'] = [notice, notice.copy()]
        self.refused(values, 'duplicate source notice')
        values = fixture(); values[1]['packages'][1]['package']['sha256'] = values[1]['packages'][0]['package']['sha256']
        synchronize(*values); self.refused(values, 'duplicate archive digest')

    def test_malformed_buildinfo(self):
        values = fixture(); values[1]['packages'][0]['buildinfo'] = 'malformed'
        self.refused(values, 'unexpected.*fields')
        values = fixture(); values[1]['packages'][0]['buildinfo'] = dict(sha256='a'*64,
            installed=['compiler-1-1-any'], installed_lock_sha256='b'*64)
        self.refused(values, 'buildinfo installed lock digest')


if __name__ == '__main__':
    unittest.main()
