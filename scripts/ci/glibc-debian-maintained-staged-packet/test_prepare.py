#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert packet/refusal controls; synthetic decisions never publish a packet."""
import copy,importlib.util,json,os,subprocess,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('staged_prepare',HERE/'prepare.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
ROOT=next(p for p in HERE.parents if (p/'scripts/ci/glibc-debian-maintained-lifecycle/candidate_gate.py').is_file())
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
 def fixture(self):
  load,_=P.helpers(ROOT);G=load(ROOT,P.GATE);common=dict(candidate=G.EXPECTED,run_id=P.RUN,source_sha=P.SOURCE,artifact_sha256='1'*64,retention_sha256='2'*64)
  pair=dict(common,status='ROOT_ACCEPTED_PROVIDER_NATIVE_PAIR',hardware='NOT_RUN',provider_pkgbuild_sha256=G.EXPECTED['pkgbuild_sha256'],archive_sha256='3'*64)
  probes={n:dict(path='runtime/a/normal-clients/bin/'+n,bytes=1,sha256='4'*64) for n in P.CLIENTS};compiles={s:dict(path='runtime/'+s+'/normal-clients/receipt.json',bytes=1,sha256='5'*64) for s in ('a','b')}
  normal=dict(common,status='ROOT_ACCEPTED_NORMAL_INTERPRETER_PROBES',files=probes,compile_receipts=compiles,normal_source_sha256='a766bc7cd31cce18fe7e564432de4e4b63db49763608ae70ef8fab61cd29116c')
  return G,pair,normal,probes,compiles
 def check(self,v):
  G,pair,normal,probes,compiles=v;P.decisions(pair,normal,G,'1'*64,'2'*64,probes,compiles)
 def test_exact_decision_shape_and_wrong_authority_version_source_refuse(self):
  v=self.fixture();self.check(v)
  for key,value in [('candidate',dict(v[0].EXPECTED,version='2.43.caa1-1')),('source_sha','0'*40),('run_id',38960150458),('status','SOURCE_ONLY'),('artifact_sha256','0'*64)]:
   bad=[v[0],*copy.deepcopy(v[1:])];bad[1][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):self.check(bad)
 def test_normal_receipts_probe_and_prior16k_refuse(self):
  for role,key,value in [(2,'compile_receipts',{}),(2,'files',{}),(2,'normal_source_sha256','0'*64),(1,'private16k',{})]:
   v=self.fixture();bad=[v[0],*copy.deepcopy(v[1:])];bad[role][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):self.check(bad)
 def test_missing_decision_never_creates_output_or_actor(self):
  from types import SimpleNamespace
  a=SimpleNamespace(repo=ROOT,output=self.root/'output',pair_decision=self.root/'MISSING')
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actors')),self.assertRaises(FileNotFoundError):P.prepare(a)
  self.assertEqual(list(self.root.iterdir()),[])
 def test_ordinary_inputs_reject_alias_and_caps(self):
  p=self.root/'file';p.write_bytes(b'abc');self.assertEqual(P.read(p,3),b'abc')
  with self.assertRaises(ValueError):P.read(p,2)
  q=self.root/'alias';q.symlink_to(p)
  with self.assertRaises(ValueError):P.read(q)
  q.unlink();os.link(p,q)
  with self.assertRaises(ValueError):P.read(p)
 def test_closed_names_duplicate_and_nonfinite_json_refuse(self):
  for n in ('../escape','/absolute','a//b','a/./b','a\\b','a\n'):
   with self.subTest(n=n),self.assertRaises(ValueError):P.safe(n)
  for raw in (b'{"x":1,"x":2}',b'{"x":NaN}'):
   with self.assertRaises(ValueError):P.obj(raw)
 def test_retained_closed_bytes_and_truncated_selected_proof(self):
  for truncated,corrupt in ((False,False),(True,False),(False,True)):
   p=self.root/('sample'+str(truncated)+str(corrupt)+'.zip');raw=b'synthetic parser control';row=dict(P.pin(raw),source_bytes=len(raw)+int(truncated),truncated=truncated)
   if corrupt:row['sha256']='0'*64
   report=dict(status='PASS_UNSELECTED_MAINTAINED_DEBIAN_PROVIDER_NATIVE_PAIR_EVIDENCE',errors=[],files={'proof.json':row},total_bytes=len(raw))
   with zipfile.ZipFile(p,'w') as z:z.writestr('retention.json',P.encoded(report));z.writestr('proof.json',raw)
   if corrupt:
    with self.assertRaises(ValueError):P.Original(p)
   else:
    original=P.Original(p)
    try:
     if truncated:
      with self.assertRaises(ValueError):original.get('proof.json',1024)
     else:self.assertEqual(original.get('proof.json',1024),raw)
    finally:original.close()
 def test_complete_pinned_helpers_import_without_actors(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actors')):
   load,pins=P.helpers(ROOT)
   for n in (P.GATE,P.PHASE,P.OWNER,P.NORMAL):load(ROOT,n)
   self.assertEqual(len(pins),16)
   with self.assertRaises(ValueError):load(ROOT,'unknown.py')
if __name__=='__main__':unittest.main()
