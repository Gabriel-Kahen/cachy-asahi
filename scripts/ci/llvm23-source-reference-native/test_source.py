# SPDX-License-Identifier: MIT
"""Author-only Source/parser controls. No native role, Reader role, network or Docker."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
FROZEN=Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-perl-hosted-source-r1/source-tree')
CANDIDATE=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-llvm23-source-reference-20261115/packages/port/llvm23-source-reference')
EVIDENCE=Path('/home/gabe/Documents/ChatGPT/cachy-asahi')

def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

ctor=module('llvm_source_constructor',HERE/'prepare.py')
producer=module('llvm_source_producer_data',HERE/'payload/hosted/producer.py')
parser=module('llvm_export_parser_data',HERE/'payload/hosted/reader.py')


class SourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.files=ctor.render(FROZEN,CANDIDATE,EVIDENCE)

    def test_closed_packet_map_inverse_new_operation_no_archive(self):
        files=self.files;manifest=json.loads(files['source-map.json'][0]);inverse=json.loads(files['inverse.json'][0])
        self.assertEqual(ctor.fs.descriptors({n:v for n,v in files.items() if n!='source-map.json'}),manifest['files'])
        undo={n:v for n,v in files.items() if n not in inverse['additions']}
        self.assertEqual(len(undo),200)
        self.assertEqual(ctor.fs.descriptors(undo),inverse['held'])
        self.assertTrue(all(v is None for v in manifest['actual'].values()))
        self.assertNotIn('llvm-project-23.1.1.src.tar.xz',files)
        self.assertEqual(files['.github/workflows/native-arm-build.yml'],files['.github/workflows/native-arm-llvm23-source-reference-v1.yml'])
        common=files['hosted/common.py'][0]
        self.assertIn(b"OPERATION='llvm23-source-reference-native-v1'",common)
        self.assertNotIn(b"OPERATION='perl5423-native-pair-v2'",common)

    def test_frozen_whole_leaf_drift_refused_even_with_same_map(self):
        before=ctor.fs.snapshot(FROZEN);name=next(n for n in before if n.startswith('original/') and n.endswith('.py'));before[name]=(before[name][0]+b'\n#changed\n',before[name][1])
        with patch.object(ctor.fs,'snapshot',return_value=before):
            with self.assertRaisesRegex(ValueError,'complete frozen Source'):ctor.render(FROZEN,CANDIDATE,EVIDENCE)

    def test_finite_held_helper_and_bootstrap_inverse(self):
        deriv=json.loads((HERE/'derivation.json').read_bytes())
        for name,row in deriv['reused_files'].items():
            original=(FROZEN/row['source']).read_bytes();self.assertEqual(hashlib.sha256(original).hexdigest(),row['source_sha256'])
            result=original.decode()
            for r in row['replacements']:
                self.assertEqual(result.count(r['before']),r['count']);result=result.replace(r['before'],r['after'])
            emitted=(HERE/'payload'/name).read_text()
            self.assertEqual(result,emitted)
        helper=self.files['helpers/owned_child.py'][0]
        self.assertIn(b'0<timeout<=14400',helper)
        self.assertIn(b'0<v<=4*1024**3',helper)

    def test_all_new_python_syntax_and_workflow_guard_pins(self):
        for name,(raw,_) in self.files.items():
            if name.endswith('.py') and not name.startswith('original/'):compile(raw,name,'exec')
        workflow=self.files['.github/workflows/native-arm-build.yml'][0]
        for key in ['hosted/common.py','hosted/entry.py']:self.assertIn(hashlib.sha256(self.files[key][0]).hexdigest().encode(),workflow)
        self.assertIn(b'root_admission_json',workflow)
        self.assertNotIn(b'--privileged',workflow)

    def test_docker_domain_create_operands(self):
        argv=producer.options('llvm-test','vol-test','sha256:'+'a'*64,Path('/private/input'),Path('/private/source'),'b'*64)
        for flag in ['--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=8g','--memory-swap=8g','--pids-limit=512']:self.assertIn(flag,argv)
        self.assertEqual(sum('readonly' in item for item in argv),2)
        self.assertNotIn('--privileged',argv)
        self.assertNotIn('/var/run/docker.sock',argv)

    def test_flat_export_good_and_trailing_garbage_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);stream=io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w:') as tar:
                item=tarfile.TarInfo('output');item.type=tarfile.DIRTYPE;tar.addfile(item)
                item=tarfile.TarInfo('output/test.json');item.size=3;item.mode=0o644;tar.addfile(item,io.BytesIO(b'{}\n'))
            path=root/'export.tar';path.write_bytes(stream.getvalue());parser.unpack_export(path,root/'good');self.assertEqual((root/'good/test.json').read_bytes(),b'{}\n')
            path.write_bytes(stream.getvalue()+b'nonzero')
            with self.assertRaisesRegex(ValueError,'zero-only'):parser.unpack_export(path,root/'bad')

    def test_pax_allocation_refused_before_payload_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);item=tarfile.TarInfo('pax');item.type=tarfile.XHDTYPE;item.size=65537
            path=root/'large-pax.tar';path.write_bytes(item.tobuf()+bytes(1024))
            with self.assertRaisesRegex(ValueError,'PAX metadata bound'):parser.unpack_export(path,root/'out')

    def test_old_operation_and_ref_bindings_refuse(self):
        common=module('llvm_context_data',HERE/'payload/hosted/common.py')
        source='a'*40;ref='refs/heads/codex/llvm23-source-reference-native-test'
        env=dict(GITHUB_REF=ref,GITHUB_RUN_ID='123',GITHUB_SHA=source,GITHUB_WORKFLOW_SHA=source,GITHUB_RUN_ATTEMPT='1',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',GITHUB_WORKFLOW_REF='Gabriel-Kahen/cachy-asahi/.github/workflows/native-arm-llvm23-source-reference-v1.yml@'+ref,GITHUB_ACTIONS='true',RUNNER_ARCH='ARM64',RUNNER_OS='Linux',LLVM23_OPERATION='perl5423-native-pair-v2')
        with patch.object(common.os,'getuid',return_value=1001),patch.object(common.os,'geteuid',return_value=1001),patch.object(common.os,'getgid',return_value=1001),patch.object(common.os,'getegid',return_value=1001):
            with self.assertRaisesRegex(ValueError,'ambient policy'):common.context(source,'b'*64,'c'*64,env)
            env['LLVM23_OPERATION']='llvm23-source-reference-native-v1';env['GITHUB_RUN_ATTEMPT']='2'
            with self.assertRaisesRegex(ValueError,'first dedicated'):common.context(source,'b'*64,'c'*64,env)

    def test_checkpoint_profile_matches_and_wrong_digest_refuses(self):
        handoff=json.loads((HERE/'handoff.json').read_bytes())
        expected=handoff['current_checkpoint']['constructor_profile_sha256']
        profile=ctor.verify_profile(expected)
        self.assertEqual(profile['expected_source_map_sha256'],handoff['current_checkpoint']['source_map_sha256'])
        self.assertEqual(profile['expected_prospective_tree'],handoff['current_checkpoint']['prospective_tree'])
        with self.assertRaisesRegex(ValueError,'profile SHA differs'):ctor.verify_profile('0'*64)

    def test_default_unadmitted_template_remains_inert(self):
        template=json.loads((HERE/'root-admission.TEMPLATE.json').read_bytes())
        self.assertEqual(template['status'],'UNADMITTED');self.assertIsNone(template['authority']);self.assertIsNone(template['source'])
        self.assertFalse(template['source_reviewed'])
        audit=json.loads((HERE/'builder-audit.json').read_bytes());self.assertEqual(audit['missing_package_names'],[]);self.assertEqual(audit['separate_additions'],[])


if __name__=='__main__':unittest.main()
