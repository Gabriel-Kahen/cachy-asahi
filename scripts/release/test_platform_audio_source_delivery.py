#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real retained-source controls; archive fixtures are explicitly synthetic."""
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('platform_audio_delivery_test_subject', HERE / 'platform_audio_source_delivery.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
ROOT = Path(os.environ.get('CACHY_ASAHI_SOURCE_ROOT', HERE.parents[1])).absolute()
REV = 'e5814001fe64147eadbb7c69650a9771f53c976e'


class Delivery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.saved = {}
        for name in a.profiles():
            bodies = a.source_set(name, lambda key, row: a.s.local_read(ROOT, row['path'], a.MAX_FILE))
            saved = a.manifest(name, bodies, REV, None)
            raw = a.tar_bytes(dict(bodies, **{'bundle.json': a.encoded(saved)}))
            cls.saved[name] = (bodies, saved, raw)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='audio-source-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def altered(self, name, edit):
        bodies, saved, _ = self.saved[name]
        material = dict(bodies, **{'bundle.json': a.encoded(saved)})
        edit(material)
        raw = a.tar_bytes(material)
        return a.verified(raw, a.s.digest(raw))

    def copied_inputs(self):
        target = self.root / 'relocated checkout'
        target.mkdir()
        for p in a.profiles().values():
            for row in p['inputs'].values():
                destination = target / row['path']
                destination.parent.mkdir(parents=True, exist_ok=True)
                if not destination.exists():
                    shutil.copyfile(ROOT / row['path'], destination)
        return target

    def test_all_five_exact_retained_bundles_verify(self):
        self.assertEqual(len(self.saved), 5)
        for name, (bodies, saved, raw) in self.saved.items():
            with self.subTest(name=name):
                got, exact = a.verified(raw, a.s.digest(raw))
                self.assertEqual((got, exact), (saved, bodies))
                self.assertTrue(saved['finite_recipe_inputs_complete'])
                self.assertFalse(saved['complete_corresponding_source_accepted'])
                self.assertFalse(saved['legal_acceptance'])
                self.assertEqual(saved['physical_m2'], 'NOT_RUN')

    def test_relocated_input_checkout_is_byte_deterministic(self):
        target = self.copied_inputs()
        for name in a.profiles():
            original = a.pack(ROOT, name, REV, self.root / ('original-' + name))
            relocated = a.pack(target, name, REV, self.root / ('moved-' + name))
            self.assertEqual(original, relocated)
            self.assertEqual((self.root / ('original-' + name) / 'source.tar').read_bytes(),
                             (self.root / ('moved-' + name) / 'source.tar').read_bytes())

    def test_relocated_bundle_cli_verifies_and_unpacks(self):
        raw = self.saved['speakersafetyd'][2]
        directory = self.root / 'another location'
        directory.mkdir()
        bundle = directory / 'bundle.tar'
        bundle.write_bytes(raw)
        destination = directory / 'unpacked'
        result = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'platform_audio_source_delivery.py'),
                                 'unpack', '--bundle', str(bundle), '--sha256', a.s.digest(raw),
                                 '--output', str(destination)], cwd='/', text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)['code_executed'])
        for key, body in self.saved['speakersafetyd'][0].items():
            self.assertEqual((destination / key).read_bytes(), body)
        self.assertEqual((destination / 'PKGBUILD').stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads((destination/'source-map.json').read_bytes())['PKGBUILD'],
                         a.profile('speakersafetyd')['inputs']['PKGBUILD']['sha256'])

    def test_preserves_whole_source_vendor_notice_patch(self):
        for name in ('speakersafetyd', 'bankstown', 'triforce-lv2'):
            bodies = self.saved[name][0]
            for key in a.profile(name)['metadata']['source']:
                self.assertEqual(bodies[key], (ROOT / a.profile(name)['recipe_directory'] / key).read_bytes())
            self.assertIn('COMPONENTS.json', bodies)
            self.assertEqual(json.loads(bodies['COMPONENTS.json'])['vendor']['crates'], 117)
        self.assertIn('0001-j504-Write-the-full-speaker-names-in-conf.patch', self.saved['speakersafetyd'][0])

    def test_license_and_upstream_grants_preserved(self):
        for name in self.saved:
            bodies = self.saved[name][0]
            self.assertTrue(bodies['LICENSE.upstream'])
            self.assertEqual(bodies['PACKAGING.LICENSE'], (ROOT / 'LICENSE').read_bytes())
        self.assertIn(b'GNU GENERAL PUBLIC LICENSE', self.saved['triforce-lv2'][0]['GPL-3.0.txt'])
        self.assertIn(b'wmidi', self.saved['bankstown'][0]['THIRD-PARTY.md'])

    def test_no_legal_or_relink_promotion(self):
        for name, (_, saved, _) in self.saved.items():
            self.assertEqual(saved['relinking_obligations'], 'NOT_ADJUDICATED')
            self.assertEqual(bool(saved['publication_blockers']), name not in ('asahi-audio', 'alsa-ucm-conf-asahi'))
        self.assertTrue(any('wmidi' in x for x in self.saved['triforce-lv2'][1]['publication_blockers']))
        self.assertTrue(any('nalgebra' in x for x in self.saved['triforce-lv2'][1]['publication_blockers']))

    def test_speakersafetyd_revision_uses_retained_acquisition_receipt(self):
        p=a.profile('speakersafetyd')
        self.assertEqual(p['upstream_revision'],'63a92658a4daec170c6472e38162374206e593fb')
        self.assertEqual(p['upstream_revision'],json.loads(self.saved['speakersafetyd'][0]['UPSTREAM.json'])['revision'])
        self.assertEqual(p['upstream_acquisition_receipt']['sha256'],p['inputs']['speakersafetyd-2.0.1.tar.gz']['sha256'])

    def test_profile_tamper_refused(self):
        (self.root/'platform_audio_source_profiles.json').write_bytes(b'{}')
        with mock.patch.object(a,'HERE',self.root):
            with self.assertRaisesRegex(ValueError,'profiles changed'): a.profiles()

    def test_binding_rechecked_against_supplied_archive(self):
        path=self.synthetic_archive()
        a.pack(ROOT,'alsa-ucm-conf-asahi',REV,self.root/'bound-again',path)
        raw=(self.root/'bound-again/source.tar').read_bytes()
        saved,_=a.verified(raw,a.s.digest(raw),path)
        self.assertIsNotNone(saved['archive_binding'])
        def edit(d): d['usr/share/licenses/alsa-ucm-conf-asahi/LICENSE.asahi']=b'changed'
        bad=self.synthetic_archive(edit)
        with self.assertRaisesRegex(ValueError,'payload bytes'): a.verified(raw,a.s.digest(raw),bad)

    def test_unbound_bundle_cannot_claim_archive_recheck(self):
        raw=self.saved['alsa-ucm-conf-asahi'][2]
        with self.assertRaisesRegex(ValueError,'saved binding'):
            a.verified(raw,a.s.digest(raw),self.synthetic_archive())

    def test_changed_recipe_even_with_rehashed_bundle_refused(self):
        with self.assertRaisesRegex(ValueError, 'pinned input'):
            self.altered('bankstown', lambda d: d.update(PKGBUILD=d['PKGBUILD'] + b'\n'))

    def test_changed_vendor_even_with_rehashed_bundle_refused(self):
        with self.assertRaisesRegex(ValueError, 'pinned input'):
            self.altered('speakersafetyd', lambda d: d.update({'cargo-vendor-117.tar.xz': b'changed'}))

    def test_missing_patch_refused(self):
        with self.assertRaises(KeyError):
            self.altered('speakersafetyd', lambda d: d.pop('0001-j504-Write-the-full-speaker-names-in-conf.patch'))

    def test_missing_notice_archive_refused(self):
        with self.assertRaises(KeyError):
            self.altered('triforce-lv2', lambda d: d.pop('audio-rust-notices-v1.tar.xz'))

    def test_license_convenience_copy_tamper_refused(self):
        with self.assertRaisesRegex(ValueError, 'derived material'):
            self.altered('bankstown', lambda d: d.update({'LICENSE.upstream': b'another grant'}))

    def test_unexpected_file_refused(self):
        with self.assertRaisesRegex(ValueError, 'coverage'):
            self.altered('asahi-audio', lambda d: d.update({'extra': b'x'}))

    def test_manifest_acceptance_forgery_refused(self):
        def edit(d):
            value=json.loads(d['bundle.json']);value['legal_acceptance']=True;d['bundle.json']=a.encoded(value)
        with self.assertRaisesRegex(ValueError, 'manifest mismatch'):
            self.altered('bankstown', edit)

    def test_wrong_checksum_refused(self):
        with self.assertRaisesRegex(ValueError, 'checksum'):
            a.verified(self.saved['bankstown'][2], '0' * 64)

    def test_noncanonical_tar_metadata_refused(self):
        raw = self.saved['asahi-audio'][2]
        stream = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(raw)) as src, tarfile.open(fileobj=stream, mode='w') as out:
            for member in src:
                member.mtime=123
                out.addfile(member, src.extractfile(member))
        altered=stream.getvalue()
        with self.assertRaisesRegex(ValueError, 'noncanonical'):
            a.verified(altered, a.s.digest(altered))

    def unsafe_tar(self, member):
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as out:
            out.addfile(member,io.BytesIO(b'x') if member.isfile() else None)
        raw=stream.getvalue()
        with self.assertRaises(ValueError): a.verified(raw,a.s.digest(raw))

    def test_traversal_member_refused(self):
        m=tarfile.TarInfo('../escape');m.size=1;self.unsafe_tar(m)

    def test_symlink_member_refused(self):
        m=tarfile.TarInfo('PKGBUILD');m.type=tarfile.SYMTYPE;m.linkname='/etc/passwd';self.unsafe_tar(m)

    def test_duplicate_tar_member_refused(self):
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as out:
            for _ in range(2):
                m=tarfile.TarInfo('same');m.size=1;out.addfile(m,io.BytesIO(b'x'))
        raw=stream.getvalue()
        with self.assertRaisesRegex(ValueError,'duplicate'): a.verified(raw,a.s.digest(raw))

    def test_missing_input_does_not_block_other_packages(self):
        root=self.copied_inputs()
        (root/'packages/audio/bankstown/cargo-vendor-117.tar.xz').unlink()
        result=a.pack_all(root,REV,self.root/'partial')
        self.assertEqual(result['status'],'PARTIAL_INPUT_EXPORT')
        self.assertEqual([r['package']['name'] for r in result['packages'] if r['status']=='INPUT_REFUSED'],['bankstown'])
        for name in set(self.saved)-{'bankstown'}: self.assertTrue((self.root/'partial'/name/'source.tar').is_file())
        self.assertIn('cargo-vendor-117.tar.xz',next(r['error'] for r in result['packages'] if r['status']=='INPUT_REFUSED'))

    def test_symlink_source_refused(self):
        root=self.copied_inputs();p=root/'packages/audio/bankstown/PKGBUILD';p.unlink();p.symlink_to(ROOT/'packages/audio/bankstown/PKGBUILD')
        with self.assertRaises(OSError): a.pack(root,'bankstown',REV,self.root/'out')
        self.assertFalse((self.root/'out').exists())

    def test_existing_output_is_preserved(self):
        out=self.root/'out';out.mkdir();(out/'sentinel').write_bytes(b'keep')
        with self.assertRaises(FileExistsError): a.pack(ROOT,'bankstown',REV,out)
        self.assertEqual({p.name for p in out.iterdir()},{'sentinel'})

    def test_symlink_output_parent_refused(self):
        (self.root/'target').mkdir();(self.root/'link').symlink_to(self.root/'target')
        with self.assertRaises(OSError): a.pack(ROOT,'asahi-audio',REV,self.root/'link/out')
        self.assertEqual(list((self.root/'target').iterdir()),[])

    def synthetic_archive(self, mutate=None):
        name='alsa-ucm-conf-asahi';p=a.profile(name);bodies=self.saved[name][0]
        files={}
        with tarfile.open(fileobj=io.BytesIO(bodies['alsa-ucm-conf-asahi-10.tar.gz'])) as src:
            for m in src:
                if m.isfile():
                    relative=m.name.split('/',1)[1]
                    if relative.startswith('ucm2/conf.d/'):
                        files['usr/share/alsa/'+relative]=src.extractfile(m).read()
        for leaf in ('NOTICE','PACKAGING.LICENSE'):
            files['usr/share/licenses/'+name+'/'+leaf]=bodies[leaf]
        files['usr/share/licenses/'+name+'/LICENSE.asahi']=bodies['LICENSE.upstream']
        for leaf in ('README.md','source-provenance.json'):
            files['usr/share/doc/'+name+'/'+leaf]=bodies[leaf]
        self.assertEqual(set(files),set(p['payload']))
        fields=dict(pkgname=[name],pkgbase=[name],pkgver=[p['version']],arch=[p['arch']],license=p['metadata']['license'],depend=p['metadata']['depends'])
        fields2=dict(format=['2'],pkgname=[name],pkgver=[p['version']],pkgarch=[p['arch']],pkgbuild_sha256sum=[p['inputs']['PKGBUILD']['sha256']])
        def text(d): return ''.join(k+' = '+v+'\n' for k,values in d.items() for v in values).encode()
        files.update({'.PKGINFO':text(fields),'.BUILDINFO':text(fields2),'.MTREE':b'synthetic fixture only\n'})
        if mutate: mutate(files)
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w',format=tarfile.PAX_FORMAT) as out:
            for key,body in sorted(files.items()):
                member=tarfile.TarInfo(key);member.size=len(body);member.mode=0o644
                out.addfile(member,io.BytesIO(body))
        raw=stream.getvalue();path=self.root/'synthetic.pkg.tar';path.write_bytes(raw)
        return path

    def test_synthetic_archive_metadata_payload_binding(self):
        binding=a.bind_archive(self.synthetic_archive(),'alsa-ucm-conf-asahi')
        self.assertEqual(binding['status'],'METADATA_FIXED_DATA_AND_ELF_STRUCTURE_BOUND')
        self.assertTrue(binding['generic_guard_errors'])
        self.assertEqual(binding['compiled_source_correspondence'],'NOT_ESTABLISHED')
        result=a.pack(ROOT,'alsa-ucm-conf-asahi',REV,self.root/'bound',self.root/'synthetic.pkg.tar')
        self.assertEqual(result['archive_status'],'BOUND_STATIC_ONLY')

    def test_archive_wrong_recipe_hash_refused(self):
        def edit(d): d['.BUILDINFO']=d['.BUILDINFO'].replace(a.profile('alsa-ucm-conf-asahi')['inputs']['PKGBUILD']['sha256'].encode(),b'0'*64)
        with self.assertRaisesRegex(ValueError,'BUILDINFO'): a.bind_archive(self.synthetic_archive(edit),'alsa-ucm-conf-asahi')

    def test_archive_wrong_package_version_refused(self):
        def edit(d): d['.PKGINFO']=d['.PKGINFO'].replace(b'pkgver = 10-2',b'pkgver = 10-9')
        with self.assertRaisesRegex(ValueError,'identity'): a.bind_archive(self.synthetic_archive(edit),'alsa-ucm-conf-asahi')

    def test_archive_modified_license_refused(self):
        def edit(d): d['usr/share/licenses/alsa-ucm-conf-asahi/LICENSE.asahi']=b'modified'
        with self.assertRaisesRegex(ValueError,'payload bytes'): a.bind_archive(self.synthetic_archive(edit),'alsa-ucm-conf-asahi')

    def test_archive_extra_payload_refused(self):
        with self.assertRaisesRegex(ValueError,'coverage'): a.bind_archive(self.synthetic_archive(lambda d:d.update({'usr/bin/extra':b'x'})),'alsa-ucm-conf-asahi')

    def test_source_delivery_record_transport_compatibility(self):
        a.pack(ROOT,'alsa-ucm-conf-asahi',REV,self.root/'transport',self.synthetic_archive())
        out=self.root/'transport'
        (out/'review').write_bytes(b'SYNTHETIC TEST REVIEW - NO RELEASE APPROVAL\n')
        def desc(key):
            raw=(out/key).read_bytes();return dict(id='alsa-'+key,path=key,sha256=a.s.digest(raw),bytes=len(raw))
        record=dict(package=dict(name='alsa-ucm-conf-asahi',version='10-2',arch='any',sha256=a.s.digest((self.root/'synthetic.pkg.tar').read_bytes())),
                    bundle=desc('source.tar'),source_map=desc('source-map.json'),recipe=desc('PKGBUILD'),recipe_key='PKGBUILD',
                    notices=[desc('LICENSE.upstream'),desc('PACKAGING.LICENSE')],authorization=desc('review'),review_status='SYNTHETIC NOT APPROVED')
        a.s.record_check(record,lambda key,limit:a.s.local_read(out,key[len('alsa-'):],limit),
                         {'recipe_sha256':a.profile('alsa-ucm-conf-asahi')['inputs']['PKGBUILD']['sha256']})


if __name__=='__main__': unittest.main(verbosity=2)
