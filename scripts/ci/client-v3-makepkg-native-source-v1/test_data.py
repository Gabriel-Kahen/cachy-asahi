# SPDX-License-Identifier: MIT
"""Eight exact successor DATA controls; never construct Source or invoke Reader."""
import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser(add_help=False);p.add_argument('--source82',type=Path,required=True);p.add_argument('--recipe-root',type=Path,required=True);p.add_argument('--reader-body',type=Path,required=True);args,rest=p.parse_known_args()
def deny(event,values):
    if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn'))or event in('os.system','pty.spawn','os.kill','os.killpg'):raise RuntimeError('successor DATA actor denied '+event)
sys.addaudithook(deny)
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
F=load('trusted_successor_factory',HERE/'prepare.py');M=load('trusted_reader_text_adapter',HERE/'reader.py');profile=F.profile()
BASE={n:F.ordinary(args.source82/n)for n in profile['base_Source']}
RECIPE={n:F.ordinary(args.recipe_root/n)for n in profile['recipe_files']}
OVER={n:F.ordinary(HERE/'producer'/n)for n in profile['producer_overrides']}
READER=F.ordinary(args.reader_body)

class Controls(unittest.TestCase):
    def test_actual_genuine_three_recipe_leaves_only(self):
        self.assertEqual(sorted(n for n in RECIPE if RECIPE[n]!=BASE[n]),profile['approved_recipe_delta'])
        self.assertEqual(len(profile['approved_recipe_delta']),3)
        self.assertEqual(RECIPE['packages/tools/cachy-asahi-repository-client-v3/client_v3.py'],BASE['packages/tools/cachy-asahi-repository-client-v3/client_v3.py'])

    def test_full82_eight_deltas_74_held_and_actual_eight_marker(self):
        out,proof=F.project(BASE,RECIPE,OVER);self.assertEqual(set(out),set(BASE));self.assertEqual((proof['files'],len(proof['delta']),proof['held']),(82,8,74))
        policy=json.loads(out[F.LANE+'/input-policy.json']);self.assertEqual(policy['candidate_source'],profile['recipe_source']);self.assertIn('Ran 8 tests',policy['products']['client']['check_markers']);self.assertNotIn('Ran 6 tests',policy['products']['client']['check_markers'])
        self.assertEqual(len(json.loads(out[F.MANIFEST])['files']),80);self.assertIsNone(proof['actual_source']);self.assertIsNone(proof['run'])

    def test_complete_inverse_restores_exact_Source82(self):
        out,proof=F.project(BASE,RECIPE,OVER);restored=dict(out)
        for n,row in proof['delta'].items():self.assertEqual(F.row(out[n]),row['after']);restored[n]=BASE[n]
        self.assertEqual(restored,BASE)
        old=json.loads(BASE[F.LANE+'/input-policy.json']);self.assertEqual(old['candidate_source'],'2dbe7fe5623fae9ed5940a26385400958c3ffb42')

    def test_parent_or_recipe_body_tamper_refused(self):
        base=dict(BASE);name=next(iter(base));base[name]+=b'x'
        with self.assertRaises(ValueError):F.project(base,RECIPE,OVER)
        recipe=dict(RECIPE);name=next(iter(recipe));recipe[name]+=b'x'
        with self.assertRaises(ValueError):F.project(BASE,recipe,OVER)

    def test_missing_extra_or_untrusted_override_refused(self):
        for variant in ({},dict(OVER,unknown=b'x'),dict(OVER,**{'prepare.py':OVER['prepare.py']+b'x'})):
            with self.assertRaises(ValueError):F.project(BASE,RECIPE,variant)
        recipe=dict(RECIPE,unknown=b'x')
        with self.assertRaises(ValueError):F.project(BASE,recipe,OVER)

    def test_workflow_only_manifest_hash_and_all_caps_held(self):
        out,_=F.project(BASE,RECIPE,OVER);before=F.pin(BASE[F.MANIFEST])['sha256'].encode();after=F.pin(out[F.MANIFEST])['sha256'].encode()
        self.assertEqual(out[F.WORKFLOW].replace(after,before,1),BASE[F.WORKFLOW])
        for name in('installed.py','installed_v3.py','lifecycle.py','runtime_image.py','retained574.py'):self.assertEqual(out[F.LANE+'/'+name],BASE[F.LANE+'/'+name])

    def test_matching_reader_exact_binding_and_other_functions_held(self):
        new=M.derive(READER);self.assertIn(M.NEW.encode(),new);self.assertNotIn(M.OLD.encode(),new)
        before=ast.parse(READER);after=ast.parse(new)
        def functions(tree):return {n.name:ast.dump(n,include_attributes=False)for n in tree.body if isinstance(n,ast.FunctionDef)}
        a=functions(before);b=functions(after)
        for n in a:self.assertEqual(a[n],b[n],n)
        self.assertEqual(new.decode().replace(M.NEW,M.OLD,1).replace(M.REPLACEMENT,M.BODY,1).replace(M.ADDITION,'',1).encode(),READER)

    def test_wrong_reader_and_constructor_without_genuine_merge_refused(self):
        with self.assertRaises(ValueError):M.derive(READER+b'x')
        with self.assertRaises(ValueError):F.construct(type('Args',(),dict(Root_construct=False,merge_proof=None,merge_sha256=None))())

if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest])
