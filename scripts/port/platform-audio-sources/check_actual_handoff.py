#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Explicit integration controls requiring the actual five-package handoff.

No native payload or source code executes. Refuses absent actual input instead
of skipping the integration tests or substituting synthetic native evidence.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('audio_actual_handoff_tests',HERE/'intake.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
PIN='e2ab9b6cc2810bf5d5b6454abdb9bcdeea6567797247c745b0d04541cb99c6c8'


class ActualHandoff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original=Path(ARGS.handoff).absolute();cls.original_index=ARGS.index_sha256
        result=a.verify(cls.original,cls.original_index,PIN)
        if result['packages']!=5:raise AssertionError('five actual inputs required')
        cls.value=a.profile((cls.original/'native-inputs.json').read_bytes(),PIN);cls.api=a.load_api(cls.value)

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='audio-actual-handoff-test-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.handoff=self.root/'relocated handoff'
        shutil.copytree(self.original,self.handoff);self.index=self.original_index

    def rewrite(self,path,raw):
        (self.handoff/path).write_bytes(raw)

    def resign_index(self,edit=None):
        saved=json.loads((self.handoff/'delivery.json').read_bytes())
        if edit:edit(saved)
        raw=a.encoded(saved);self.rewrite('delivery.json',raw);self.index=a.sha(raw)

    def refused(self):
        with self.assertRaises((ValueError,KeyError,OSError)):a.verify(self.handoff,self.index,PIN)

    def test_relocated_all_five_without_retained_sources_or_actors(self):
        original=self.api.s.local_read
        def only_delivered_material(root,key,limit):
            profile_read=Path(root).absolute()==self.api.HERE and key=='platform_audio_source_profiles.json'
            copied_archive=Path(root).absolute()==self.handoff/'archives' and key in {row['archive']['filename']for row in self.value['packages'].values()}
            if not(profile_read or copied_archive):raise AssertionError('retained source read forbidden')
            return original(root,key,limit)
        with mock.patch.object(a,'load_api',return_value=self.api),mock.patch.object(self.api.s,'local_read',side_effect=only_delivered_material),\
             mock.patch('subprocess.Popen',side_effect=AssertionError('actor forbidden')),\
             mock.patch('socket.socket',side_effect=AssertionError('network forbidden')):
            result=a.verify(self.handoff,self.index,PIN)
        self.assertEqual(result['status'],'VERIFIED_FIVE_NATIVE_BOUND_FINITE_SOURCE_EXPORTS')
        saved=json.loads((self.handoff/'delivery.json').read_bytes())
        self.assertEqual(len(saved['files']),41)
        self.assertEqual(sum(len(v['compiled_payloads'])for v in saved['packages'].values()),3)
        self.assertNotIn(b'/home/',a.encoded(saved));self.assertNotIn(b'/tmp/',a.encoded(saved))
        self.assertEqual([len(saved['packages'][k]['archive_binding']['generic_guard_errors'])for k in sorted(a.VERSIONS)],[54,10,0,5,0])
        self.assertTrue(all(not saved[k]for k in ('legal_acceptance','complete_corresponding_source_accepted','payload_execution','native_build_replayed')))

    def test_relocated_cli_from_unrelated_working_directory(self):
        result=subprocess.run([sys.executable,'-I','-B',str(HERE/'intake.py'),'verify','--handoff',str(self.handoff),
            '--index-sha256',self.index,'--profile-sha256',PIN],cwd='/',capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['packages'],5)

    def test_missing_native_archive_refused(self):
        (self.handoff/'archives'/self.value['packages']['bankstown']['archive']['filename']).unlink();self.refused()

    def test_native_archive_tamper_refused(self):
        path='archives/'+self.value['packages']['speakersafetyd']['archive']['filename']
        self.rewrite(path,(self.handoff/path).read_bytes()+b'altered');self.refused()

    def test_wrong_index_digest_refused(self):
        self.index='0'*64;self.refused()

    def test_missing_source_archive_refused(self):
        (self.handoff/'sources/triforce-lv2/source.tar').unlink();self.refused()

    def replace_bundle(self,edit):
        path='sources/bankstown/source.tar';raw=(self.handoff/path).read_bytes()
        saved,bodies=self.api.verified(raw,a.sha(raw));edit(saved,bodies)
        self.rewrite(path,self.api.tar_bytes(dict(bodies,**{'bundle.json':self.api.encoded(saved)})))
        self.rewrite('sources/bankstown/bundle.json',self.api.encoded(saved));self.resign_index()

    def test_valid_finite_source_bundle_without_native_association_refused(self):
        def unbind(saved,bodies):
            replacement=self.api.manifest('bankstown',bodies,saved['observed_checkout_revision'],None)
            saved.clear();saved.update(replacement)
        self.replace_bundle(unbind);self.refused()

    def test_tampered_internal_generic_errors_refused(self):
        self.replace_bundle(lambda saved,bodies:saved['archive_binding']['generic_guard_errors'].append('invented waiver'))
        self.refused()

    def test_missing_vendor_input_refused_even_with_new_outer_digest(self):
        self.replace_bundle(lambda saved,bodies:bodies.pop('cargo-vendor-117.tar.xz'));self.refused()

    def test_index_cannot_remove_protected_guard_errors(self):
        self.resign_index(lambda saved:saved['packages']['alsa-ucm-conf-asahi']['archive_binding'].update(generic_guard_errors=[]));self.refused()

    def test_index_cannot_promote_acceptance(self):
        self.resign_index(lambda saved:saved.update(legal_acceptance=True,complete_corresponding_source_accepted=True));self.refused()

    def test_changed_convenience_license_refused(self):
        self.rewrite('sources/asahi-audio/LICENSE.upstream',b'altered');self.resign_index();self.refused()

    def test_extra_material_cannot_be_authorized_by_index(self):
        self.rewrite('extra',b'#!/bin/sh\nexit 99\n');(self.handoff/'extra').chmod(0o600)
        self.resign_index(lambda saved:saved['files'].update(extra=dict(mode=0o600,**a.descriptor(b'#!/bin/sh\nexit 99\n'))));self.refused()

    def test_handoff_symlink_refused(self):
        path=self.handoff/'sources/asahi-audio/LICENSE.upstream';path.unlink();path.symlink_to('/etc/passwd');self.refused()

    def test_altered_profile_cannot_change_native_association(self):
        value=json.loads((self.handoff/'native-inputs.json').read_bytes());value['packages']['bankstown']['native_record']['run']='1'
        self.rewrite('native-inputs.json',a.encoded(value));self.resign_index();self.refused()

    def test_missing_association_in_index_refused(self):
        self.resign_index(lambda saved:saved['packages']['bankstown'].pop('archive_binding'));self.refused()

    def test_tampered_intake_archive_refused_before_output_created(self):
        path=self.handoff/'archives'/self.value['packages']['bankstown']['archive']['filename'];path.write_bytes(b'altered')
        output=self.root/'must-not-exist'
        with self.assertRaisesRegex(a.Refused,'NATIVE_ARCHIVE_PIN'):
            a.export(a.ROOT,self.handoff/'archives',output,'0'*40,PIN)
        self.assertFalse(output.exists())

    def test_existing_output_preserved(self):
        original=(self.handoff/'delivery.json').read_bytes()
        with self.assertRaises(FileExistsError):
            a.export(a.ROOT,self.handoff/'archives',self.handoff,'0'*40,PIN)
        self.assertEqual((self.handoff/'delivery.json').read_bytes(),original)

    def test_missing_source_input_leaves_unaccepted_partial(self):
        source=self.root/'empty source checkout';source.mkdir(mode=0o700);output=self.root/'partial'
        with self.assertRaises(OSError):a.export(source,self.handoff/'archives',output,'0'*40,PIN)
        self.assertTrue(output.is_dir());self.assertFalse((output/'delivery.json').exists())
        with self.assertRaises(a.Refused):a.verify(output,'0'*64,PIN)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--handoff',required=True);parser.add_argument('--index-sha256',required=True)
    ARGS,remaining=parser.parse_known_args();unittest.main(argv=[sys.argv[0],*remaining],verbosity=2)
