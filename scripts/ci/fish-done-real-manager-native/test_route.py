# SPDX-License-Identifier: MIT
"""Source/workflow/ownership models only; never invokes Docker or native actors."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import closed as C
import job
import root_contract as ROOT
import run

class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=WORK);self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'source';shutil.copytree(SOURCE,self.root)

    def test_whole_context_and_dependency_roots(self):
        meta=C.verify(self.root);self.assertIsNone(meta['actual_source'])
        self.assertEqual(len(json.loads(C.read(self.root/C.DATA/'context.json'))['files']),24)
        self.assertEqual(len(json.loads(C.read(self.root/C.DATA/'build.lock.json'))['required_packages']),26)

    def test_unexpected_source_and_alias_refused(self):
        p=self.root/'unexpected';p.write_text('extra')
        with self.assertRaisesRegex(ValueError,'membership'):C.verify(self.root)
        p.unlink();p.symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ValueError,'ordinary'):C.verify(self.root)

    def test_empty_unknown_source_directory_refused(self):
        (self.root/'unexpected-empty').mkdir()
        with self.assertRaisesRegex(ValueError,'directory membership'):C.verify(self.root)

    def test_archive_drift_refused(self):
        p=self.root/C.DATA/'done.pkg.tar.xz';p.write_bytes(p.read_bytes()+b'drift')
        with self.assertRaisesRegex(ValueError,'leaf differs'):C.verify(self.root)

    def test_external_manifest_and_null_selectors(self):
        with self.assertRaisesRegex(ValueError,'reviewed manifest'):C.verify(self.root,'0'*64)
        p=self.root/C.MANIFEST;m=json.loads(p.read_bytes());m['actual_run']=123;C.save(p,m)
        with self.assertRaisesRegex(ValueError,'NULL'):C.verify(self.root)

    def test_full_workflow_alias_drift_refused(self):
        p=self.root/C.WORKFLOWS[0];p.write_text(p.read_text()+'# changed\n')
        with self.assertRaisesRegex(ValueError,'workflow/alias'):C.verify(self.root)

    def test_source_caller_proof_no_actors(self):
        env=dict(SOURCE_SHA='a'*40,GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40,
                 RUNNER_ARCH='ARM64',RUNNER_OS='Linux',GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1')
        output=Path(self.tmp.name)/'proof.json'
        with patch.dict(os.environ,env,clear=True),patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
            result=job.prove(self.root,output)
        self.assertEqual(result['status'],'SOURCE_PROOF_PASS');self.assertNotIn('installed_delivery',result)
        env['GITHUB_WORKFLOW_SHA']='b'*40
        with patch.dict(os.environ,env,clear=True):
            with self.assertRaisesRegex(ValueError,'source/workflow'):job.prove(self.root,output)

    def test_native_consumer_flags_and_scoped_userns(self):
        args=(self.root,'sha256:'+'1'*64,'cachy-asahi-product-'+'2'*32,Path('/tmp/output'))
        a,label=run.command_for(*args,'build','3'*32)
        for flag in ('--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--pull=never'):
            self.assertIn(flag,a)
        b,other=run.command_for(*args,'trial','3'*32,Path('/tmp/built'))
        self.assertEqual(label,other)
        self.assertIn('--security-opt=seccomp=unconfined',b);self.assertIn('--security-opt=apparmor=unconfined',b)
        self.assertIn('type=bind,src=/tmp/built,dst=/built,readonly',b)
        for flags in (a,b):
            self.assertFalse(any(s in flags for s in ('--privileged','--network=host','--pid=host')))
            self.assertFalse(any('--device' in s or 'SYS_ADMIN' in s or '/run/user' in s or '/dev/dri' in s for s in flags))

    def cleanup_fixture(self):
        held=C.held_job(self.root);runtime=Path(self.tmp.name)/'runtime';runtime.mkdir()
        base=Path(self.tmp.name)/'base';base.mkdir();(runtime/'consumer.lock').write_bytes(b'')
        names=['cachy-asahi-product-'+'2'*32,'cachy-asahi-product-lifecycle-'+'3'*32]
        token,image='4'*32,'sha256:'+'1'*64
        C.save(runtime/'owner.json',dict(schema_version=1,token=token,image=image,label=held.C.LABEL,containers=names))
        C.save(base/'report.json',dict(image=image));return held,runtime,base,names,token,image

    def test_accepted_cleanup_foreign_refusal_no_remove(self):
        held,runtime,base,names,token,image=self.cleanup_fixture();calls=[]
        def command(argv):
            calls.append(argv);v=[dict(Image='sha256:'+'9'*64,Config=dict(Labels={held.C.LABEL:token}),Id='5'*64,Name='/'+names[-1])]
            return subprocess.CompletedProcess(argv,0,json.dumps(v).encode(),b'')
        with self.assertRaisesRegex(ValueError,'foreign consumer'):
            held.retire_consumers(runtime,base,dict(consumer_token=token),command)
        self.assertEqual(len(calls),1)

    def test_accepted_cleanup_model_reverse_confirmed_ids(self):
        held,runtime,base,names,token,image=self.cleanup_fixture()
        ids={n:str(i+5)*64 for i,n in enumerate(names)};present=set(names);removed=[]
        def command(argv):
            if argv[1:3]==['container','inspect']:
                n=argv[3]
                if n not in present:return subprocess.CompletedProcess(argv,1,b'',('No such container: '+n).encode())
                v=[dict(Image=image,Config=dict(Labels={held.C.LABEL:token}),Id=ids[n],Name='/'+n)]
                return subprocess.CompletedProcess(argv,0,json.dumps(v).encode(),b'')
            self.assertEqual(argv[1:3],['rm','-f']);removed.append(argv[3]);present.remove(next(n for n,i in ids.items() if i==argv[3]))
            return subprocess.CompletedProcess(argv,0,b'',b'')
        result=held.retire_consumers(runtime,base,dict(consumer_token=token),command)
        self.assertEqual([r['container'] for r in result['containers']],list(reversed(names)))
        self.assertEqual(removed,[ids[n] for n in reversed(names)])

    def test_x86_or_staged_cannot_receive_native_installed_credit(self):
        v=dict(native_arch=dict(name='x86_64',elf_machine=62),package_context='archive-staged',native_arm='NOT_RUN')
        b=dict(package_context='archive-staged',installed=None);o=dict(exit=0,process_group_absent=True)
        with self.assertRaisesRegex(ValueError,'native installed'):ROOT.actual_delivery(v,b,o)
        v.update(native_arch=dict(name='aarch64',elf_machine=183),native_arm='ACTUAL_AARCH64_ONLY')
        with self.assertRaisesRegex(ValueError,'native installed'):ROOT.actual_delivery(v,b,o)

    def test_host_runner_refuses_before_output_or_daemon(self):
        out=Path(self.tmp.name)/'never-created'
        with patch.object(run.platform,'machine',return_value='x86_64'),patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
            with self.assertRaisesRegex(ValueError,'ordinary local native ARM'):run.execute(self.root,Path('/missing'),out,Path('/missing'))
        self.assertFalse(out.exists())

    def test_phase_export_map_rejects_alias(self):
        d=Path(self.tmp.name)/'phase';d.mkdir();e=d/'export';e.mkdir();(e/'receipt').write_text('exact')
        C.save(d/'export-map.json',{'receipt':C.pin(b'exact')});run.export_gate(d)
        (e/'extra').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ValueError,'alias'):run.export_gate(d)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--work',type=Path,required=True)
    a,rest=p.parse_known_args();SOURCE,WORK=a.source.absolute(),a.work.absolute();unittest.main(argv=[sys.argv[0],*rest])
