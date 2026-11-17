# SPDX-License-Identifier: MIT
"""Local DATA controls only: no actor, package operation, Raw or private path."""
import hashlib,importlib.util,json,struct,subprocess,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-perl-ldcache-lifecycle-successor-readiness-20261117-r2/constructed-source/guest/root.sh')
def load(n):
 s=importlib.util.spec_from_file_location('diagnostic_'+n,HERE/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=load('proposal');A=load('auxiliary')
def auxiliary(rows,pad=b'\0'*4):
 strings=bytearray(b'\0');entries=[]
 for inode,name in rows:
  offset=0 if name is None else len(strings)
  if name is not None:strings.extend(name.encode()+b'\0')
  entries.append(struct.pack('<QQQQiII4s',inode,1700000000,65536,254,0xa03,offset,0,pad))
 return struct.pack('<24sII',A.MAGIC,len(rows),len(strings))+b''.join(entries)+strings
class Controls(unittest.TestCase):
 def test_exact_one_leaf_transform_and_inverse(self):
  old=ROOT.read_bytes();new=P.transform(old);self.assertEqual(P.inverse(new),old);self.assertEqual(new.count(P.NEW),1);self.assertEqual(new.count(P.BASE_NEW),1)
 def test_wrong_preimage_and_extra_delta_refuse(self):
  self.assertRaises(ValueError,P.transform,ROOT.read_bytes()+b' ');self.assertRaises(ValueError,P.inverse,P.transform(ROOT.read_bytes())+b' ')
 def test_original_cache_snapshot_stream_and_private_guards_unchanged(self):
  old=ROOT.read_bytes();new=P.transform(old);a=old.index(b'cache_snapshot() (');b=old.index(b'\n)\n',a)+3;self.assertIn(old[a:b],new)
  for call in(b'initialized_cache_transaction_restored\n',b'initialized_guard\n',b'cache_snapshot > "$S/after.cache"\n',b'same_bytes "$S/before.cache" "$S/after.cache"\n'):self.assertEqual(P.NEW.count(call),1)
  self.assertIn(b'payload_snapshot after',new);self.assertIn(b'same_bytes "$S/before.meta-equality" "$S/after.meta-equality"',new)
 def test_eight_substages_preserve_each_call_exit_status(self):
  stages=('RESTORED_ENTER','RESTORED_DONE','GUARD_ENTER','GUARD_DONE','SNAPSHOT_ENTER','SNAPSHOT_DONE','COMPARE_ENTER','COMPARE_DONE')
  with tempfile.TemporaryDirectory()as d:
   for target,code,last in(('none',0,'COMPARE_DONE'),('restored',2,'RESTORED_ENTER'),('guard',2,'GUARD_ENTER'),('snapshot',1,'SNAPSHOT_ENTER'),('compare',1,'COMPARE_ENTER')):
    log=Path(d)/target;script='set -Eeuo pipefail\nS=$1\nlog=$2\ncheckpoint_phase(){ :; }\n_cr_mark(){ printf "%s\\n" "$1" >> "$log"; }\n_cr_public(){ :; }\n'
    for name,label in(('initialized_cache_transaction_restored','restored'),('initialized_guard','guard'),('cache_snapshot','snapshot'),('same_bytes','compare')):script+=name+'(){ return '+str(code if target==label else 0)+'; }\n'
    result=subprocess.run(['/usr/bin/bash','-c',script+P.NEW.decode(),'DATA',d,str(log)],capture_output=True,timeout=5);self.assertEqual(result.returncode,code,result.stderr);seen=log.read_text().splitlines();self.assertEqual(seen[-1],last);self.assertEqual(seen,list(stages[:stages.index(last)+1]))
 def test_diagnostic_syntax_and_fixed_public_whitelist(self):
  helper=(HERE/'diagnostics.sh').read_bytes();result=subprocess.run(['/usr/bin/bash','-n'],input=helper,capture_output=True,timeout=5);self.assertEqual(result.returncode,0,result.stderr)
  for p in(b'/etc/ld.so.cache',b'/var/cache/ldconfig',b'/var/cache/ldconfig/aux-cache'):self.assertIn(p,helper)
  for forbidden in(b'find ',b'ls ',b'/root',b'/dev/vda',b'touch ',b'chmod ',b'rm ',b'cp '):self.assertNotIn(forbidden,helper)
  self.assertIn(b'od -An -tx1 -N32',helper);self.assertIn(b'1048576',helper);self.assertIn(b'STABLE=',helper)
 def test_observed_phase_does_not_claim_failed_predicate(self):
  v=json.loads((HERE/'inputs.DATA.json').read_bytes());self.assertEqual(v['actual_r94']['exit_status'],1);self.assertEqual(v['actual_r94']['initialized_guard_marker_count'],0);self.assertIsNone(v['actual_r94']['exact_failed_predicate']);self.assertTrue(all(x is None for x in v['actual'].values()))
 def test_auxiliary_schema_positive_facts_only(self):
  v=A.decode(auxiliary([(1,'libA.so.1'),(2,'libB.so.2')]));self.assertEqual(v['entries'],2);self.assertEqual(len(v['rows']),2);self.assertIsNone(v['lifecycle_acceptance']);self.assertIsNone(v['actual_cause'])
 def test_auxiliary_order_or_undefined_padding_not_semantic_identity(self):
  a=A.decode(auxiliary([(1,'libA.so.1'),(2,'libB.so.2')]));b=A.decode(auxiliary([(2,'libB.so.2'),(1,'libA.so.1')],b'abcd'));self.assertNotEqual(a['body'],b['body']);self.assertEqual(a['unordered_defined_fields'],b['unordered_defined_fields']);self.assertNotEqual(a['abi_padding'],b['abi_padding'])
 def test_auxiliary_provider_stat_identity_change_remains_visible(self):
  a=A.decode(auxiliary([(1,'libA.so.1')]));b=A.decode(auxiliary([(2,'libA.so.1')]));self.assertNotEqual(a['unordered_defined_fields'],b['unordered_defined_fields'])
 def test_auxiliary_bad_counts_offsets_flags_geometry_refuse(self):
  good=auxiliary([(1,'libA.so.1')])
  for offset,fmt,value in((24,'<I',4097),(28,'<I',9999),(64,'<i',0x303),(68,'<I',2),(72,'<I',1)):
   bad=bytearray(good);struct.pack_into(fmt,bad,offset,value)
   with self.subTest(offset=offset),self.assertRaises(ValueError):A.decode(bytes(bad))
  self.assertRaises(ValueError,A.decode,good+b' ');self.assertRaises(ValueError,A.decode,auxiliary([(1,'libA.so.1'),(1,'libB.so.2')]))
 def test_auxiliary_string_escape_private_names_and_header_refuse(self):
  for name in('../secret','/root/key','BAD\nNAME','no-soname'):
   with self.assertRaises(ValueError):A.decode(auxiliary([(1,name)]))
  self.assertRaises(ValueError,A.decode,b'x'*33);self.assertRaises(ValueError,A.decode,b'x'*(A.CAP+1));self.assertEqual(A.decode(auxiliary([(1,None)]))['rows'][0]['soname'],None)
if __name__=='__main__':unittest.main(verbosity=2)
