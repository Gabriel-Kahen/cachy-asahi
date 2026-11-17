#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Actor-fenced finite Fish consumer controls; no key, private Git or native run."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def load(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
# Reuse the same finite MODEL material and syscall fence; this is a named local
# source-control dependency, never a private repository or actor executor.
FENCE=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-native349-pinned-input-carrier-20261117/scripts/ci/native349-pinned-input-carrier/test_data.py')
assert len(FENCE.read_bytes())==18619 and hashlib.sha256(FENCE.read_bytes()).hexdigest()=='ebe4d9861657396b36eb01a6382b436f45858ce3faa22dc0feccb928cfd7df8d','whole frozen public MODEL fixture/fence'
D=load(FENCE,'native349_finite_fixture_fence');P=load(HERE/'prepare.py','fish_exact_consumer_prepare');F=load(HERE/'case.py','fish_exact_carrier_case')
PARENT=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-fish-source-ro-v8-20261117/work/fish-source-ro-DATA-20261117-r1/closed-source-tree')

class Controls(unittest.TestCase):
 setUp=D.Controls.setUp
 clean=D.Controls.clean
 fixture=D.Controls.fixture
 def model(self,expected,binding):
  return patch.multiple(F.N,EXPECTED=expected,BINDING=binding,TOTAL=sum(r['bytes']for r in expected['files'].values()),LARGEST=max(r['bytes']for r in expected['files'].values()))
 def test_exact501_lock_whole_helper_and_all_unissued_before_secret(self):
  old=P.parent_bodies(PARENT);self.assertEqual(P.P.pin(old[P.LOCK]),P.LOCK_PIN);self.assertEqual(P.P.pin(F.CORE),P.CORE_PIN)
  self.assertEqual(len(F.N.EXPECTED['files']),182);self.assertEqual(len(F.N.EXPECTED['package_provenance']),91)
  self.assertEqual(sum(r['bytes']for r in F.N.EXPECTED['files'].values()),544634853)
  for n in('commit','tree','manifest','Root_receipt'):self.assertIsNone(F.N.BINDING[n])
  class NoSecret(dict):
   def pop(self,*_):raise AssertionError('no credential before all actual Root bindings')
  with self.assertRaises(ValueError):F.N.fetch(PARENT,self.area/'fetch',environment=NoSecret())
  with self.assertRaises(ValueError):F.project(F.CORE+b'\n')
 def test_five_literal_operands_inverse_all_other_helper_functions_identical(self):
  raw=F.project(F.CORE);text=raw.decode()
  for before,after in reversed(F.SEAMS):text=text.replace(after,before)
  self.assertEqual(text.encode(),F.CORE);self.assertEqual(len(F.SEAMS),5)
  funcs=lambda b:{n.name:ast.dump(n,include_attributes=False)for n in ast.parse(b).body if isinstance(n,ast.FunctionDef)}
  old,new=funcs(F.CORE),funcs(raw)
  for n in old:
   if n not in('admitted_source','fetch','seed'):self.assertEqual(old[n],new[n],n)
  self.assertIn(b"cache.parent.name == 'fish02-native'",raw)
  for token in(b'ROOT_FISH02_ADMISSION_JSON',b'ROOT_FISH02_RUNTIME_JSON',b'held-source32/scripts/ci/fish-config02-native-source/runtime/owned_process.py'):self.assertIn(token,raw)
 def test_full62_inverse_source_ro_semantic_recipe_and_resource_guard_preservation(self):
  out=self.area/'source';r=P.construct(PARENT,out);b={str(p.relative_to(out)):p.read_bytes()for p in out.rglob('*')if p.is_file()};old=P.parent_bodies(PARENT)
  self.assertEqual(P.inverse(b),old);self.assertEqual(r['files'],62);self.assertLess(r['bytes'],2*1024**2)
  self.assertEqual(set(b)-set(old),{P.HELPER,P.NEW_WF});self.assertEqual(set(old)-set(b),{P.OLD_WF,P.REMOVED})
  self.assertTrue(all(b[n]==raw for n,raw in old.items()if n.startswith('held-source32/')))
  policy=json.loads(b[P.PREFIX+'policy.json']);policy.pop('private_pinned_input_carrier');self.assertEqual(policy,json.loads(old[P.PREFIX+'policy.json']))
  funcs=lambda raw:{n.name:ast.dump(n,include_attributes=False)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
  for name in('data.py','hosted_owner.py','payload.py'):
   a,c=funcs(old[P.PREFIX+name]),funcs(b[P.PREFIX+name])
   changed={'source'}if name=='data.py'else{'main'}
   for n in a:
    if n not in changed:self.assertEqual(a[n],c[n],name+'/'+n)
  recipe=old['held-source32/scripts/ci/fish-config02-native-source/recipe/PKGBUILD'];self.assertIn(b'pkgrel=2',recipe);self.assertIn(b'python -I -B "$srcdir/check-config.py"',recipe)
  entry=old['held-source32/scripts/ci/fish-config02-native-source/entry.py'];projected=F.project_entry(entry)
  self.assertEqual(projected.replace(b"\n        PINNED_CARRIER.seed(PINNED_INPUTS,output/'cache')",b''),entry);self.assertLess(projected.index(b'PINNED_CARRIER.seed'),projected.index(b'native.audit('))
  for n in(P.HELPER,P.MARKER,P.PREFIX+'data.py',P.NEW_WF):
   with self.assertRaises((ValueError,KeyError,json.JSONDecodeError)):P.inverse(dict(b,**{n:b[n]+b'\nMODEL-corruption'}))
 def test_public182_model_seed_fish_cache_only_no_wrong_overwrite(self):
  source,expected,binding,_=self.fixture();work=self.area/'volume/work';work.mkdir(parents=True);stage=work/'native349-pinned-inputs';cache=work/'fish02-native/cache';cache.mkdir(parents=True)
  with self.model(expected,binding):
   F.N.copy_public(source,stage);r=F.seed(stage,cache);self.assertEqual(r['files'],182);self.assertTrue(r['all501_required']);self.assertFalse(r['URL_overrides'])
   p=next(cache.iterdir());p.write_bytes(b'wrong-retained')
   with self.assertRaises(ValueError):F.seed(stage,cache)
   self.assertEqual(p.read_bytes(),b'wrong-retained')
   with self.assertRaises(ValueError):F.seed(stage,work/'llhttp-reference-native/cache')
 def test_dedicated_workflow_same_five_inputs_group_key_fetch_only_zero_apt(self):
  w=(HERE/'workflow.yml.in').read_text();self.assertEqual(w,(HERE.parents[2]/P.NEW_WF).read_text())
  self.assertEqual(w.count('required: true'),5);self.assertIn('group: native-arm-fish-config02-source-v2',w)
  fetch,controller=w.split('      - name: Existing native host tools then owned current Fish02 XZ pair',1)
  self.assertEqual(fetch.count('${{ secrets.CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY }}'),1);self.assertNotIn(F.N.SECRET,controller)
  self.assertIn('--carrier-root',controller);self.assertIn('timeout-minutes: 4',fetch)
  self.assertIn('--property=MemoryMax=536870912 --property=MemorySwapMax=0 --property=CPUQuota=100%',controller);self.assertIn('--property=TasksMax=64',controller)
  for bad in('apt-get','apt install','--nodeps','--nocheck','ssh-agent','StrictHostKeyChecking=no','set -x'):self.assertNotIn(bad,w)

if __name__=='__main__':
 if not sys.flags.isolated or not sys.flags.dont_write_bytecode or not __debug__:raise SystemExit('Use python -I -B unoptimized')
 unittest.main(verbosity=2)
