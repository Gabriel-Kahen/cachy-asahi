#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Small closed-source and real held cleanup refusals; no Docker/native actors."""
import argparse
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import closed as C
import construct
import run


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=WORK);self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'source';shutil.copytree(SOURCE,self.root)

    def test_constructor_refuses_output_inside_held_packet(self):
        output=self.root/C.DATA/'must-not-exist'
        with self.assertRaisesRegex(ValueError,'disjoint'):
            construct.construct(self.root/C.DATA,self.root/C.HELD,Path('/nonexistent'),output)
        self.assertFalse(output.exists())

    def test_complete_closed_source_and_data(self):
        m=C.verify(self.root);self.assertEqual((m['data_files'],m['held_sources']),(155,6))

    def test_emitted_data_passes_exact_held_context_gate(self):
        module=C.load(self.root/C.HELD/'common.py','held_context_gate_test')
        self.assertEqual(len(module.verify_context(self.root/C.DATA)['files']),154)

    def test_extra_source_refused(self):
        (self.root/'unexpected.py').write_text('pass\n')
        with self.assertRaisesRegex(ValueError,'membership'):C.verify(self.root)

    def test_data_tamper_refused(self):
        (self.root/C.DATA/'stage/usr/share/cachy-asahi/fish/config.fish').write_text('# substituted\n')
        with self.assertRaisesRegex(ValueError,'leaf differs'):C.verify(self.root)

    def test_held_source_tamper_refused(self):
        (self.root/C.HELD/'native.py').write_text('# substituted\n')
        with self.assertRaisesRegex(ValueError,'leaf differs'):C.verify(self.root)

    def test_full_workflow_alias_drift_refused(self):
        p=self.root/C.WORKFLOWS[0];p.write_text(p.read_text()+'# drift\n')
        with self.assertRaisesRegex(ValueError,'workflow'):C.verify(self.root)

    def test_nonnull_default_selector_refused(self):
        p=self.root/C.MANIFEST;m=json.loads(p.read_text());m['actual_source']='1'*40;C.save(p,m)
        with self.assertRaisesRegex(ValueError,'NULL'):C.verify(self.root)

    def test_external_reviewed_manifest_hash_required(self):
        with self.assertRaisesRegex(ValueError,'digest'):C.verify(self.root,'0'*64)

    def test_held_root_docker_resources_and_capabilities(self):
        argv,label=C.held_docker(self.root,'sha256:'+'1'*64,'cachy-asahi-product-lifecycle-'+'2'*32,Path('/tmp/output'))
        for flag in ('--network=none','--pull=never','--pids-limit=256','--memory=3g','--cpus=4','--cap-drop=ALL','--security-opt=no-new-privileges'):
            self.assertIn(flag,argv)
        self.assertEqual(label,'org.cachy-asahi.setup8-native.job')
        self.assertNotIn('--privileged',argv)
        self.assertIn('type=bind,src=/tmp/output,dst=/out',argv)

    def test_real_held_cleanup_refuses_foreign_image_without_remove(self):
        held=C.held_job(self.root);runtime=Path(self.temp.name)/'runtime';runtime.mkdir()
        base=Path(self.temp.name)/'base';base.mkdir()
        (runtime/'consumer.lock').write_bytes(b'')
        name='cachy-asahi-product-lifecycle-'+'2'*32;token='3'*32;image='sha256:'+'1'*64
        C.save(runtime/'owner.json',dict(schema_version=1,token=token,image=image,label=held.C.LABEL,containers=[name]))
        C.save(base/'report.json',dict(image=image));calls=[]
        def command(argv):
            calls.append(argv)
            value=[dict(Image='sha256:'+'4'*64,Config=dict(Labels={held.C.LABEL:token}),Id='5'*64,Name='/'+name)]
            return subprocess.CompletedProcess(argv,0,json.dumps(value).encode(),b'')
        with self.assertRaisesRegex(ValueError,'foreign consumer'):
            held.retire_consumers(runtime,base,dict(consumer_token=token),command)
        self.assertEqual(len(calls),1);self.assertEqual(calls[0][1:3],['container','inspect'])

    def test_pid1_drain_body_reaps_real_isolated_terminated_child(self):
        parsed=ast.parse(C.read(self.root/'scripts/ci/setup8-real-shells-native/container.py'))
        node=next(n for n in ast.walk(parsed) if isinstance(n,ast.FunctionDef) and n.name=='drain_adopted')
        namespace=dict(os=os,time=time)
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<exact-drain-body>','exec'),namespace)
        pid=os.fork()
        if pid==0:os._exit(0)
        rows=namespace['drain_adopted']()
        self.assertEqual(rows,[dict(pid=pid,wait_status=0)])
        with self.assertRaises(ChildProcessError):os.waitpid(pid,os.WNOHANG)

    def test_native_consumer_refuses_this_host_before_output(self):
        output=Path(self.temp.name)/'never-created'
        with self.assertRaisesRegex(ValueError,'ordinary local native ARM'):
            run.execute(self.root,Path('/nonexistent'),output,Path('/nonexistent'))
        self.assertFalse(output.exists())


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--work',type=Path,required=True)
    a,rest=p.parse_known_args();SOURCE=a.source.absolute();WORK=a.work.absolute()
    unittest.main(argv=[sys.argv[0],*rest])
