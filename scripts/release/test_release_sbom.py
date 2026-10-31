#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Bounded original fixtures; no remote, installation or hardware actors."""
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).absolute().parent
ROOT = next(p for p in HERE.parents if (p / 'scripts/release/source_delivery.py').is_file())
spec = importlib.util.spec_from_file_location('release_sbom_under_test', HERE / 'release_sbom.py')
sbom = importlib.util.module_from_spec(spec); spec.loader.exec_module(sbom)
DEPS = sbom.dependencies(ROOT / 'scripts/release')
s = DEPS[0]
owned = sbom.module('sbom_test_owned_process', ROOT / 'scripts/virtual/owned_process.py')


def tar(rows):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, body in rows:
            node = tarfile.TarInfo(name); node.size = len(body); node.mode = 0o644
            archive.addfile(node, io.BytesIO(body))
    return output.getvalue()


class SBOMTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='sbom-tests-')
        self.addCleanup(self.tmp.cleanup); self.root = Path(self.tmp.name)
        self.release = self.root / 'release'; self.release.mkdir()
        self.recipe = b'# Original inert fixture recipe\n'
        self.license = b'Original fixture license evidence; no legal conclusion.\n'
        self.pkginfo = b'pkgname = demo\npkgver = 1.0-1\narch = any\nlicense = MIT\n'
        self.buildinfo = ('pkgname = demo\npkgver = 1.0-1\npkgarch = any\npkgbuild_sha256sum = ' +
                          s.digest(self.recipe) + '\ninstalled = compiler-1-1-aarch64\n').encode()
        self.archive_rows = [('.PKGINFO', self.pkginfo), ('.BUILDINFO', self.buildinfo),
                             ('usr/share/licenses/demo/LICENSE', self.license), ('usr/bin/demo', b'inert payload\n')]
        self.p = dict(name='demo', version='1.0-1', arch='any', filename='demo-1.0-1-any.pkg.tar.gz',
                      sha256='', provenance='provenance/demo.json', license=['MIT'])
        self.prov = dict(schema_version=1, package=dict(name='demo', version='1.0-1', arch='any'),
                         artifact_sha256='', source_commit='1' * 40, recipe_sha256=s.digest(self.recipe), licenses=['MIT'],
                         sources=[dict(url='https://example.invalid/demo.tar.gz', sha256='2' * 64)],
                         build=dict(execution='synthetic', architecture='aarch64', environment='inert', snapshot_id='fixture'))
        self.manifest = dict(schema_version=1, release_id='demo-release', created_utc='2026-10-27T00:00:00Z',
                             packages=[self.p], files={}, symlinks={})
        self.spec = dict(schema_version=1, release_id='demo-release', source_commit='1' * 40, synthetic=True,
                         policy=dict(selected_packages=['demo']), packages=[], evidence=[])
        self.source_bodies = {'PKGBUILD': self.recipe, 'LICENSE': self.license, 'demo.c': b'/* original fixture */\n'}
        self.record = dict(package={}, recipe_key='PKGBUILD', review_status='Fixture only; no legal approval')
        self.index = dict(schema_version=1, purpose='release-source-delivery', synthetic=True, packages=[self.record])
        self.refresh_archive()
        self.refresh_source()
        self.refresh()

    def put(self, path, raw):
        target = self.release / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
        self.manifest['files'][path] = s.digest(raw)

    def material(self, key, body):
        self.put('evidence/' + key, body)
        return dict(id=key, path=key, sha256=s.digest(body), bytes=len(body))

    def refresh_archive(self):
        raw = gzip.compress(tar(self.archive_rows), mtime=0)
        self.p['sha256'] = self.prov['artifact_sha256'] = s.digest(raw)
        self.put('repo/' + self.p['filename'], raw)
        self.record['package'] = {key: self.p[key] for key in ('name', 'version', 'arch', 'sha256')}

    def refresh_source(self):
        self.record['recipe'] = self.material('recipe', self.recipe)
        self.record['bundle'] = self.material('bundle', tar(sorted(self.source_bodies.items())))
        self.record['notices'] = [self.material('license', self.license)]
        self.record['authorization'] = self.material('review', b'Existing inert fixture review.\n')
        self.record['source_map'] = self.material('map', sbom.encoded({k:s.digest(v) for k,v in self.source_bodies.items()}))

    def refresh(self):
        if 'source_delivery' not in self.spec or self.spec['source_delivery'] is not None:
            raw = sbom.encoded(self.index)
            self.put('evidence/index', raw)
            self.spec['source_delivery'] = dict(schema_version=1, index=dict(id='index', path='index', sha256=s.digest(raw)))
            self.spec['evidence'] = [self.spec['source_delivery']['index']] + [
                {k:r[k] for k in ('id', 'path', 'sha256')} for record in self.index['packages'] for r in s.materials(record)]
        else:
            self.spec.pop('source_delivery'); self.spec['evidence'] = []
        self.put(self.p['provenance'], sbom.encoded(self.prov))
        self.spec['packages'] = [dict(artifact=dict(path=self.p['filename'], sha256=self.p['sha256']),
                                     provenance=dict(path='original-prov.json', sha256=self.manifest['files'][self.p['provenance']]))]
        self.put('spec.json', sbom.encoded(self.spec))
        (self.release / 'release.json').write_bytes(sbom.encoded(self.manifest))
        self.pin = s.digest(sbom.encoded(self.manifest))

    def export(self):
        return sbom.export(self.release, self.pin, DEPS)

    def refused(self, pattern):
        with self.assertRaisesRegex((ValueError, OSError), pattern):
            self.export()

    def test_exact_identity_spdx_semantics_and_raw_evidence(self):
        document, report = self.export()
        self.assertEqual(document['spdxVersion'], 'SPDX-2.3')
        self.assertEqual(document['dataLicense'], 'CC0-1.0')
        package = document['packages'][0]; row = report['packages'][0]
        self.assertRegex(package['SPDXID'], r'^SPDXRef-[A-Za-z0-9.-]+$')
        self.assertEqual(package['checksums'][0]['checksumValue'], self.p['sha256'])
        self.assertEqual(package['licenseDeclared'], 'MIT')
        self.assertEqual(package['licenseConcluded'], 'NOASSERTION')
        self.assertFalse(package['filesAnalyzed']); self.assertNotIn('packageVerificationCode', package)
        self.assertEqual(row['package']['arch'], 'any')
        self.assertEqual(row['bundled_license_evidence'][0]['sha256'], s.digest(self.license))
        self.assertIn('UNRESOLVED_UNRECOGNIZED_BUNDLE_PROFILE', row['unresolved'])
        self.assertEqual(row['buildinfo']['installed'], ['compiler-1-1-aarch64'])
        self.assertEqual(row['retained_source']['matched_license_sha256'], [s.digest(self.license)])
        self.assertFalse(report['legal_acceptance'])
        self.assertEqual(report['corresponding_source_completeness'], 'NOT_ASSERTED')

    def test_deterministic_and_offline(self):
        with patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')), \
             patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS forbidden')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('subprocess forbidden')):
            first = tuple(map(sbom.encoded, self.export()))
            self.assertEqual(first, tuple(map(sbom.encoded, self.export())))
            other = self.root / 'relocated'; shutil.copytree(self.release, other)
            self.assertEqual(first, tuple(map(sbom.encoded, sbom.export(other, self.pin, DEPS))))

    def test_missing_source_index_reported(self):
        self.spec['source_delivery'] = None; self.refresh()
        row = self.export()[1]['packages'][0]
        self.assertIsNone(row['retained_source'])
        self.assertIn('RETAINED_SOURCE_ASSOCIATION_MISSING', row['unresolved'])
        self.assertEqual(row['pinned_source_references'][0]['remote_retrievability'], 'NOT_CHECKED_OFFLINE')

    def test_partial_empty_source_index_reported(self):
        self.index['packages'] = []; self.refresh()
        self.assertIn('RETAINED_SOURCE_ASSOCIATION_MISSING', self.export()[1]['packages'][0]['unresolved'])

    def test_partial_index_keeps_entire_two_package_release(self):
        other = dict(self.p, name='other', filename='other-1.0-1-any.pkg.tar.gz', provenance='provenance/other.json')
        bodies = [(key, body.replace(b'pkgname = demo', b'pkgname = other')) for key,body in self.archive_rows]
        raw = gzip.compress(tar(bodies), mtime=0); other['sha256'] = s.digest(raw)
        self.put('repo/' + other['filename'], raw)
        prov = copy.deepcopy(self.prov); prov['package']['name'] = 'other'; prov['artifact_sha256'] = other['sha256']
        self.put(other['provenance'], sbom.encoded(prov))
        self.manifest['packages'].append(other); self.spec['policy']['selected_packages'].append('other')
        self.spec['packages'].append(dict(artifact=dict(path=other['filename'], sha256=other['sha256']),
             provenance=dict(path='other.json', sha256=self.manifest['files'][other['provenance']])))
        self.put('spec.json', sbom.encoded(self.spec))
        (self.release / 'release.json').write_bytes(sbom.encoded(self.manifest)); self.pin = s.digest(sbom.encoded(self.manifest))
        document, report = self.export()
        self.assertEqual([p['name'] for p in document['packages']], ['demo', 'other'])
        self.assertIn('RETAINED_SOURCE_ASSOCIATION_MISSING', report['packages'][1]['unresolved'])
        self.assertEqual(report['package_count'], 2)

    def test_opaque_retained_bundle_stays_unresolved(self):
        self.record['bundle'] = self.material('bundle', b'opaque retained source format\n'); self.refresh()
        row = self.export()[1]['packages'][0]
        self.assertIn('UNRESOLVED_OPAQUE_BUNDLE_FORMAT', row['unresolved'])
        self.assertEqual(row['retained_source']['bundle']['sha256'], self.record['bundle']['sha256'])

    def test_xz_and_zstd_no_external_decoder(self):
        raw = tar(self.archive_rows)
        encodings = [lzma.compress(raw)]
        if DEPS[2].zstd is not None:
            encodings.append(DEPS[2].zstd.compress(raw))
        for compressed in encodings:
            self.assertEqual(sbom.tar_entries(compressed, s, DEPS[2])['.PKGINFO']['raw'], self.pkginfo)

    def test_source_bundle_declares_foreign_package(self):
        self.source_bodies['bundle.json'] = sbom.encoded(dict(package=dict(name='foreign', version='1.0-1', arch='any')))
        self.refresh_source(); self.refresh(); self.refused('bundle package identity mismatch')

    def test_source_license_declaration_disagrees(self):
        self.source_bodies['bundle.json'] = sbom.encoded(dict(package=self.prov['package'], license='Apache-2.0'))
        self.refresh_source(); self.refresh()
        document, report = self.export()
        self.assertEqual(document['packages'][0]['licenseDeclared'], 'NOASSERTION')
        self.assertIn('SOURCE_LICENSE_DECLARATION_DIFFERS', report['packages'][0]['unresolved'])

    def test_missing_source_references_reported(self):
        self.prov['sources'] = []; self.refresh()
        self.assertIn('PROVENANCE_SOURCES_MISSING', self.export()[1]['packages'][0]['unresolved'])

    def test_unpinned_source_remains_unresolved(self):
        self.prov['sources'] = [dict(url='https://example.invalid/moving')]; self.refresh()
        self.assertIn('PROVENANCE_SOURCE_REFERENCE_UNRESOLVED', self.export()[1]['packages'][0]['unresolved'])

    def test_ambiguous_legacy_and_missing_license_noassertion(self):
        for licenses in (['GPL'], ['MIT', 'Apache-2.0'], [], ['Made-Up-License']):
            with self.subTest(licenses=licenses):
                self.p['license'] = self.prov['licenses'] = licenses
                raw = b'pkgname = demo\npkgver = 1.0-1\narch = any\n' + ''.join('license = ' + x + '\n' for x in licenses).encode()
                self.archive_rows[0] = ('.PKGINFO', raw); self.refresh_archive(); self.refresh()
                document, report = self.export()
                self.assertEqual(document['packages'][0]['licenseDeclared'], 'NOASSERTION')
                self.assertIn('MISSING_OR_UNSUPPORTED_OR_AMBIGUOUS_LICENSE_DECLARATION', report['packages'][0]['unresolved'])

    def test_license_declarations_disagree(self):
        self.prov['licenses'] = ['Apache-2.0']; self.refresh()
        document, report = self.export()
        self.assertEqual(document['packages'][0]['licenseDeclared'], 'NOASSERTION')
        self.assertIn('LICENSE_DECLARATIONS_DIFFER', report['packages'][0]['unresolved'])

    def test_bundled_license_missing(self):
        self.archive_rows.pop(2); self.refresh_archive(); self.refresh()
        self.assertIn('BUNDLED_LICENSE_TEXT_MISSING', self.export()[1]['packages'][0]['unresolved'])

    def test_buildinfo_missing(self):
        self.archive_rows.pop(1); self.refresh_archive(); self.refresh()
        self.assertIn('BUILDINFO_MISSING', self.export()[1]['packages'][0]['unresolved'])

    def test_archive_tamper(self):
        (self.release / 'repo' / self.p['filename']).write_bytes(b'tampered')
        self.refused('checksum mismatch')

    def test_release_pin(self):
        self.pin = 'a' * 64; self.refused('manifest checksum mismatch')

    def test_source_material_tamper(self):
        (self.release / 'evidence/license').write_bytes(b'tampered'); self.refused('checksum mismatch')

    def test_unsafe_manifest_path(self):
        self.manifest['files']['../outside'] = 'a' * 64; self.refresh(); self.refused('path')

    def test_symlink_hardlink_fifo_and_ancestor_refused(self):
        target = self.release / 'repo' / self.p['filename']; body = target.read_bytes()
        for kind in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind):
                target.unlink(); external = self.root / ('outside-' + kind); external.write_bytes(body)
                if kind == 'symlink': target.symlink_to(external)
                elif kind == 'hardlink': os.link(external, target)
                else: os.mkfifo(target)
                self.refused('source input|symbolic link|Too many levels')
                target.unlink(); target.write_bytes(body)
        original = self.release / 'repo'; renamed = self.release / 'moved'; original.rename(renamed); original.symlink_to(renamed)
        self.refused('directory|symbolic link|Too many levels')

    def test_duplicate_json_key_refused(self):
        raw = (self.release / 'release.json').read_bytes().replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1')
        (self.release / 'release.json').write_bytes(raw); self.pin = s.digest(raw); self.refused('duplicate')

    def test_duplicate_conflicting_package(self):
        second = dict(self.p, version='2-1'); self.manifest['packages'].append(second)
        self.refresh(); self.refused('duplicate/conflicting')

    def test_duplicate_selected_and_spec_archive(self):
        self.spec['policy']['selected_packages'].append('demo'); self.refresh(); self.refused('selected package set')

    def test_source_archive_identity_mismatch(self):
        self.record['package']['sha256'] = 'b' * 64; self.refresh(); self.refused('source package identity mismatch')

    def test_source_recipe_mismatch(self):
        self.prov['recipe_sha256'] = 'b' * 64; self.refresh(); self.refused('recipe mismatch')

    def test_source_bundle_map_mismatch(self):
        self.source_bodies['demo.c'] = b'other source\n'
        self.record['bundle'] = self.material('bundle', tar(sorted(self.source_bodies.items())))
        self.refresh(); self.refused('source bundle/map mismatch')

    def test_source_notice_absent_from_bundle(self):
        self.source_bodies.pop('LICENSE')
        self.refresh_source(); self.refresh(); self.refused('notice absent')

    def test_buildinfo_recipe_and_identity_mismatch(self):
        for body in (self.buildinfo.replace(s.digest(self.recipe).encode(), b'a' * 64),
                     self.buildinfo.replace(b'pkgver = 1.0-1', b'pkgver = 2-1')):
            self.archive_rows[1] = ('.BUILDINFO', body); self.refresh_archive(); self.refresh(); self.refused('BUILDINFO')

    def test_build_lock_duplicates_and_conflicting_versions(self):
        for entry in (b'compiler-1-1-aarch64', b'compiler-2-1-aarch64'):
            self.archive_rows[1] = ('.BUILDINFO', self.buildinfo + b'installed = ' + entry + b'\n')
            self.refresh_archive(); self.refresh(); self.refused('BUILDINFO installed')

    def test_duplicate_archive_member(self):
        self.archive_rows.append(self.archive_rows[0]); self.refresh_archive(); self.refresh(); self.refused('duplicate')

    def test_archive_path_traversal(self):
        self.archive_rows.append(('../escape', b'inert')); self.refresh_archive(); self.refresh(); self.refused('path')

    def test_decoded_bomb_and_member_bound(self):
        with patch.object(sbom, 'MAX_TAR', 1000): self.refused('decoded byte|tar byte')
        with patch.object(sbom, 'MAX_MEMBERS', 1): self.refused('header/member')
        with patch.object(sbom, 'MAX_ARCHIVE', 10): self.refused('oversized|byte bound')

    def test_trailing_or_concatenated_compressed_frames(self):
        path = 'repo/' + self.p['filename']; raw = (self.release / path).read_bytes() + gzip.compress(b'foreign')
        self.put(path, raw); self.p['sha256'] = self.prov['artifact_sha256'] = s.digest(raw)
        self.record['package']['sha256'] = s.digest(raw); self.refresh(); self.refused('trailing or concatenated')

    def test_source_uri_credentials_and_duplicate_rejected(self):
        self.prov['sources'] = [dict(url='https://user:secret@example.invalid/demo', sha256='a' * 64)]
        self.refresh(); self.refused('credential-bearing')
        self.prov['sources'] = [dict(url='https://example.invalid/demo', sha256='a' * 64)] * 2
        self.refresh(); self.refused('duplicate/conflicting source')

    def test_cli_fresh_output_and_no_overwrite_or_output_on_refusal(self):
        # Stage the intended canonical layout; helper files remain unchanged.
        stage = self.root / 'stage/scripts'; (stage / 'release').mkdir(parents=True); (stage / 'update').mkdir()
        for leaf in ('source_delivery.py', 'recipe_source_delivery.py'):
            shutil.copyfile(ROOT / 'scripts/release' / leaf, stage / 'release' / leaf)
        shutil.copyfile(ROOT / 'scripts/update/archive_stream.py', stage / 'update/archive_stream.py')
        shutil.copyfile(HERE / 'release_sbom.py', stage / 'release/release_sbom.py')
        output = self.root / 'output'
        argv = ['/usr/bin/python3', '-I', '-B', str(stage / 'release/release_sbom.py'),
                '--release-dir', str(self.release), '--release-sha256', self.pin, '--output', str(output)]
        def run(args):
            owned.prepare()
            proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    start_new_session=True)
            result = owned.supervise(proc, cap=10, max_output=8192)
            self.assertTrue(result['reaped'], result)
            self.assertIsNone(result['error'], result)
            return result
        first = run(argv); self.assertEqual(first['exit'], 0, first['output'])
        files = {p.name:p.read_bytes() for p in output.iterdir()}
        self.assertEqual(set(files), {'sbom.spdx.json', 'coverage.json'})
        self.assertEqual(json.loads(files['coverage.json'])['spdx_sha256'], hashlib.sha256(files['sbom.spdx.json']).hexdigest())
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in output.iterdir()))
        again = run(argv); self.assertEqual(again['exit'], 1)
        self.assertEqual(files, {p.name:p.read_bytes() for p in output.iterdir()})
        argv[-1] = str(self.root / 'refused-output'); argv[-3] = 'a' * 64
        self.assertEqual(run(argv)['exit'], 1)
        self.assertFalse((self.root / 'refused-output').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
