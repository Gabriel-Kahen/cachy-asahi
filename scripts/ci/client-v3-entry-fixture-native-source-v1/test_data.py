# SPDX-License-Identifier: MIT
"""Six new DATA boundaries; actual Source/Reader/native execution is forbidden."""
import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser(add_help=False);p.add_argument('--source15b',type=Path,required=True);p.add_argument('--trusted-root',type=Path,required=True);args,rest=p.parse_known_args()
def deny(event,values):
    if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn'))or event in('os.system','pty.spawn','os.kill','os.killpg'):raise RuntimeError('entry fixture DATA actor denied '+event)
sys.addaudithook(deny)
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
F=load('_trusted_entry_factory',HERE/'prepare.py');R=load('_trusted_entry_reader_text',HERE/'reader.py');P=F.trusted(args.trusted_root)
BASE={n:F.ordinary(args.source15b/n)for n in P['base_Source']};FIX=F.ordinary(HERE/'producer/test_entry_failures.py');OLD='2dbe7fe5623fae9ed5940a26385400958c3ffb42';NEW=P['recipe_source']
class Controls(unittest.TestCase):
    def test_only_one_fixture_literal_changes(self):
        old=BASE[P['fixture_path']];self.assertEqual(old.count(OLD.encode()),1);self.assertEqual(FIX,old.replace(OLD.encode(),NEW.encode(),1));self.assertEqual(FIX.replace(NEW.encode(),OLD.encode(),1),old)
    def test_full82_three_delta_79held_and_inverse(self):
        out,proof=F.project(BASE,FIX);self.assertEqual((proof['files'],len(proof['delta']),proof['held']),(82,3,79));restored=dict(out)
        for n,w in proof['delta'].items():self.assertEqual(F.row(out[n]),w['after']);restored[n]=BASE[n]
        self.assertEqual(restored,BASE);self.assertIsNone(proof['actual_source']);self.assertIsNone(proof['run'])
    def test_policy_recipe_and_all_native_caps_byteheld(self):
        out,_=F.project(BASE,FIX)
        for n in BASE:
            if n not in(P['fixture_path'],F.MANIFEST,F.WORKFLOW):self.assertEqual(out[n],BASE[n],n)
        before=F.pin(BASE[F.MANIFEST])['sha256'].encode();after=F.pin(out[F.MANIFEST])['sha256'].encode();self.assertEqual(out[F.WORKFLOW].replace(after,before,1),BASE[F.WORKFLOW])
    def test_wrong_parent_and_fixture_refuse(self):
        wrong=dict(BASE);wrong[P['fixture_path']]+=b'x'
        with self.assertRaises(ValueError):F.project(wrong,FIX)
        for fixture in(BASE[P['fixture_path']],FIX+b'x'):
            with self.assertRaises(ValueError):F.project(BASE,fixture)
    def test_runtime_product_placeholder_and_null_guards_remain_strict(self):
        # Extract only the qualified maintained pure guard, never Source code.
        body=F.ordinary(args.trusted_root/'scripts/ci/client-v3-makepkg-native-source-v1/producer/test_source.py');node=next(n for n in ast.parse(body).body if isinstance(n,ast.FunctionDef)and n.name=='workflow_controls');ns=dict(json=json,hashlib=hashlib);exec(compile(ast.Module(body=[node],type_ignores=[]),'<qualified-maintained-workflow-controls>','exec'),ns)
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);here=root/F.LANE;here.mkdir(parents=True);(root/'.github/workflows').mkdir(parents=True)
            for n in('input-policy.json','source-manifest.json','job.py'):(here/n).write_bytes(BASE[F.LANE+'/'+n])
            wf=root/F.WORKFLOW;wf.write_bytes(BASE[F.WORKFLOW]);ns['workflow_controls'](here,root,True)
            policy=json.loads((here/'input-policy.json').read_bytes());policy['candidate_source']=OLD;(here/'input-policy.json').write_bytes(F.wire(policy))
            with self.assertRaisesRegex(ValueError,'explicit closed component Source'):ns['workflow_controls'](here,root,True)
            policy['candidate_source']=NEW;(here/'input-policy.json').write_bytes(F.wire(policy));wf.write_bytes(b'@MANIFEST_SHA256@')
            with self.assertRaisesRegex(ValueError,'placeholders'):ns['workflow_controls'](here,root,True)
            policy['actual_run']=1;(here/'input-policy.json').write_bytes(F.wire(policy))
            with self.assertRaisesRegex(ValueError,'selectors must remain NULL'):ns['workflow_controls'](here,root,True)
    def test_matching_reader_exact_third_override_inverse(self):
        raw=F.ordinary(args.trusted_root/'scripts/ci/client-v3-native-intake-v1/reader.py');M=load('_held_reader_text_adapter',args.trusted_root/'scripts/ci/client-v3-makepkg-native-source-v1/reader.py');held=M.derive(raw);new=R.derive(raw,args.trusted_root);self.assertEqual(new.decode().replace(R.ADDITION,M.ADDITION,1).encode(),held)
        def nodes(raw):return {n.name:ast.dump(n,include_attributes=False)for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        a,b=nodes(held),nodes(new)
        for n in a:
            if n!='_trusted_producer_body':self.assertEqual(a[n],b[n],n)
        self.assertIn("path.name == 'test_entry_failures.py'",new.decode())
        with self.assertRaises(ValueError):R.derive(raw+b'x',args.trusted_root)
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest])
