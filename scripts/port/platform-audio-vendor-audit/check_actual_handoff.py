#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Explicit controls on the actual delivered vendor material; never skip inputs."""
import argparse
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('audio_vendor_actual',HERE/'audit.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
PIN='e2ab9b6cc2810bf5d5b6454abdb9bcdeea6567797247c745b0d04541cb99c6c8'


class Actual(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handoff=Path(ARGS.handoff).absolute();cls.index=ARGS.index_sha256
        cls.report,_=a.delivered(cls.handoff,cls.index,PIN)
        intake=a.intake_module();value=intake.profile(intake.ordinary(cls.handoff/'native-inputs.json'),PIN);api=intake.load_api(value)
        cls.materials={}
        for name in a.PACKAGES:
            raw=intake.ordinary(cls.handoff/'sources'/name/'source.tar');_,cls.materials[name]=api.verified(raw,a.digest(raw))
        cls.raw=cls.materials['bankstown']['cargo-vendor-117.tar.xz'];cls.vendor,cls.files,cls.ids=a.vendor_data(cls.raw)

    def repack(self,files):
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w:gz',compresslevel=1,format=tarfile.USTAR_FORMAT)as out:
            for name,raw in sorted(files.items()):
                info=tarfile.TarInfo(name);info.size=len(raw);out.addfile(info,io.BytesIO(raw))
        return stream.getvalue()

    def test_actual_all_files_locks_edges_and_shared_coverage(self):
        r=self.report;self.assertEqual(r['errors'],[]);self.assertEqual(r['status'],'AUDITED_DATA_WITH_HOLDS')
        self.assertEqual((len(r['vendor']['crates']),r['vendor']['declared_files_verified'],r['vendor']['regular_files']),(117,4292,4409))
        self.assertEqual(len(r['union_locked_vendor_roots']),117);self.assertEqual(r['unbound_vendor_roots'],[])
        self.assertEqual({name:p['registry_packages']for name,p in r['packages'].items()},{'bankstown':17,'speakersafetyd':75,'triforce-lv2':38})
        self.assertEqual({name:len(p['lock_edges'])for name,p in r['packages'].items()},{'bankstown':37,'speakersafetyd':124,'triforce-lv2':80})
        self.assertTrue(all(edge['status']=='LEXICALLY_JOINED'for p in r['packages'].values()for edge in p['lock_edges']))
        self.assertEqual(len(r['vendor_declarations']),557)

    def test_actual_license_declaration_text_and_holds_stay_distinct(self):
        r=self.report;wmidi=r['vendor']['crates']['vendor/wmidi-3.1.0']['license']
        self.assertEqual(wmidi['declared_expression'],'MIT');self.assertFalse(wmidi['text_presence']);self.assertTrue(wmidi['holds'])
        self.assertEqual(sum(c['license']['text_presence']for c in r['vendor']['crates'].values()),116)
        self.assertTrue(any('nalgebra'in text for text in r['source_bundles']['triforce-lv2']['publication_blockers']))
        self.assertEqual(r['raw_crate_authentication'],'NOT_ESTABLISHED_NO_RAW_CRATE_BYTES')
        self.assertFalse(r['complete_corresponding_source_accepted']);self.assertFalse(r['legal_acceptance'])

    def test_full_check_without_original_sources_subprocesses_or_network(self):
        intake=a.intake_module();value=intake.profile(intake.ordinary(self.handoff/'native-inputs.json'),PIN);api=intake.load_api(value);original=api.s.local_read
        def only_delivered(root,key,limit):
            permitted=(Path(root).absolute()==api.HERE and key=='platform_audio_source_profiles.json')or(
                Path(root).absolute()==self.handoff/'archives'and key in {row['archive']['filename']for row in value['packages'].values()})
            if not permitted:raise AssertionError('original source reads forbidden')
            return original(root,key,limit)
        with mock.patch.object(a,'intake_module',return_value=intake),mock.patch.object(intake,'load_api',return_value=api),\
             mock.patch.object(api.s,'local_read',side_effect=only_delivered),\
             mock.patch('subprocess.Popen',side_effect=AssertionError('actor forbidden')),mock.patch('socket.socket',side_effect=AssertionError('network forbidden')):
            report,_=a.delivered(self.handoff,self.index,PIN)
        self.assertEqual(a.encoded(report),a.encoded(self.report))

    def test_actual_changed_vendor_member_refused_independently_of_outer_pin(self):
        files=dict(self.files);files['vendor/wmidi-3.1.0/Cargo.toml']+=b'\n# altered\n'
        with self.assertRaisesRegex(a.Refused,'FILE_CHECKSUM_DIFFERS'):a.vendor_data(self.repack(files))

    def test_actual_omitted_crate_flagged_independently_of_outer_pin(self):
        files={key:raw for key,raw in self.files.items()if not key.startswith('vendor/wmidi-3.1.0/')}
        vendor,parsed,ids=a.vendor_data(self.repack(files));bodies=self.materials['bankstown']
        report,_=a.audit_project(bodies[a.PACKAGES['bankstown']],vendor,parsed,ids,a.json_data(bodies['COMPONENTS.json']))
        missing=[row for row in report['errors']if row['code']=='LOCKED_REGISTRY_PACKAGE_MISSING']
        self.assertEqual([row['package'][:2]for row in missing],[['wmidi','3.1.0']])

    def test_actual_undeclared_extra_file_refused(self):
        files=dict(self.files);files['vendor/wmidi-3.1.0/unbound']=b'not declared'
        with self.assertRaisesRegex(a.Refused,'MISSING_OR_EXTRA_FILE'):a.vendor_data(self.repack(files))

    def test_cli_report_is_reproducible_private_and_has_no_operator_paths(self):
        with tempfile.TemporaryDirectory(prefix='audio-vendor-cli-test-')as directory:
            output=Path(directory)/'report'
            cmd=[sys.executable,'-I','-B',str(HERE/'audit.py'),'--handoff',str(self.handoff),'--index-sha256',self.index,'--profile-sha256',PIN,'--output',str(output)]
            result=subprocess.run(cmd,cwd='/',capture_output=True,text=True);self.assertEqual(result.returncode,0,result.stderr+result.stdout)
            raw=(output/'vendor-audit.json').read_bytes();self.assertEqual(raw,a.encoded(self.report));self.assertEqual(json.loads(result.stdout)['report'],a.desc(raw))
            self.assertEqual(output.stat().st_mode&0o777,0o700);self.assertEqual((output/'vendor-audit.json').stat().st_mode&0o777,0o600)
            self.assertNotIn(b'/home/',raw);self.assertNotIn(b'/tmp/',raw)
            second=subprocess.run(cmd,cwd='/',capture_output=True,text=True);self.assertEqual(second.returncode,2)
            self.assertEqual((output/'vendor-audit.json').read_bytes(),raw)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--handoff',required=True);parser.add_argument('--index-sha256',required=True)
    ARGS,remaining=parser.parse_known_args();unittest.main(argv=[sys.argv[0],*remaining],verbosity=2)
