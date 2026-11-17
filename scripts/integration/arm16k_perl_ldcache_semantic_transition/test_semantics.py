# SPDX-License-Identifier: MIT
"""Actual public DATA + hostile format/provider cases; no disk/actor entry."""
import copy,importlib.util,json,struct,subprocess,tempfile,unittest
from unittest.mock import patch
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(n):
 s=importlib.util.spec_from_file_location('test_'+n,HERE/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
C=load('cache');P=load('providers');T=load('transition');X=load('transform')
class Controls(unittest.TestCase):
 def setUp(self):self.actual=(HERE/'actual-r90-cache.bin').read_bytes();self.data=json.loads((HERE/'providers.DATA.json').read_bytes());self.rows=C.decode(self.actual)['entries']
 def mutate(self,offset,fmt,value):
  b=bytearray(self.actual);struct.pack_into(fmt,b,offset,value)
  with self.assertRaises(ValueError):C.decode(bytes(b))
 def test_actual_primary_format_full_canonical_roundtrip(self):
  result=C.decode(self.actual);self.assertEqual(len(result['entries']),361);self.assertEqual(C.encode(result['entries']),self.actual);self.assertEqual(result['cache'],dict(bytes=17695,sha256='eeb01c0c2d393aa9bf526a673fedfa331173573722827ec2f68849ccf997412c'));self.assertIsNone(result['lifecycle_acceptance'])
 def test_all_actual_targets_join_pinned_provider_and_alias_evidence(self):
  nodes=dict(self.data['baseline_nodes'],**self.data['db_nodes']);rows=P.join(self.rows,nodes);self.assertEqual(len(rows),361);self.assertEqual(sum(r['provider']['package']['name']=='db5.3'for r in rows),3);self.assertEqual({r['name']for r in rows if r['provider']['package']['name']=='db5.3'},T.EXPECTED_DB_NAMES)
 def test_projection_is_not_learned_from_actual_cache(self):
  self.assertEqual(len(self.data['baseline_nodes']),540);self.assertGreater(len(self.data['baseline_nodes']),len(self.rows));self.assertEqual(T.qualified_providers(),self.data)
 def test_primary_numeric_sort_and_suffix_shared_strings(self):
  a=[C.row('libX.so.9','/usr/lib/libX.so.9'),C.row('libX.so.10','/usr/lib/libX.so.10')];v=C.decode(C.encode(a));self.assertEqual([r['name']for r in v['entries']],['libX.so.10','libX.so.9']);self.assertLess(C.libcmp('libX.so.9','libX.so.10'),0)
  b=C.encode(a);key=struct.unpack_from('<I',b,52)[0];self.assertNotEqual(b[key-1],0)
 def test_bad_header_endian_reserved_counts_and_geometry_refuse(self):
  for off,fmt,value in((20,'<I',0),(20,'<I',4097),(24,'<I',2**32-1),(28,'<B',0),(28,'<B',3),(29,'<B',1),(36,'<I',1),(32,'<I',49)):
   with self.subTest(off=off,value=value):self.mutate(off,fmt,value)
 def test_all_entry_fields_offsets_and_overlap_refuse(self):
  for off,fmt,value in((48,'<i',0x303),(52,'<I',0),(56,'<I',48),(60,'<I',1),(64,'<Q',1),(52,'<I',len(self.actual)),(56,'<I',17624)):
   with self.subTest(off=off,value=value):self.mutate(off,fmt,value)
 def test_extension_bounds_count_magic_tag_flags_and_length_refuse(self):
  e=struct.unpack_from('<I',self.actual,32)[0]
  for delta,value in((0,0),(4,2),(8,1),(12,1),(16,e),(20,48)):
   with self.subTest(delta=delta):self.mutate(e+delta,'<I',value)
  self.assertRaises(ValueError,C.decode,self.actual+b'\0')
 def test_missing_nul_non_ascii_bad_paths_and_sort_refuse(self):
  for field,raw in(('name','lib/escape.so.1'),('name','libX.so.1234567890'),('path','/usr/lib/../secret.so'),('path','/etc/libX.so.1')):
   rows=copy.deepcopy(self.rows);rows[0][field]=raw
   with self.subTest(field=field,raw=raw),self.assertRaises(ValueError):C.encode(rows)
  b=bytearray(self.actual);b[48:72],b[72:96]=b[72:96],b[48:72];self.assertRaises(ValueError,C.decode,bytes(b))
  b=bytearray(self.actual);k=struct.unpack_from('<I',b,52)[0];b[k]=255;self.assertRaises(ValueError,C.decode,bytes(b))
 def test_duplicate_keys_mapping_and_unaccounted_strings_refuse(self):
  self.assertRaises(ValueError,C.encode,[self.rows[0],self.rows[0]])
  rows=copy.deepcopy(self.rows);rows[1]['name']=rows[0]['name'];self.assertRaises(ValueError,C.encode,rows)
  b=bytearray(self.actual);struct.pack_into('<I',b,52,struct.unpack_from('<I',b,76)[0]);self.assertRaises(ValueError,C.decode,bytes(b))
 def test_provider_missing_alias_cycle_wrong_owner_or_target_refuse(self):
  row=next(r for r in self.rows if r['name']=='libz.so');path=row['path'][1:]
  for edit in(lambda n:n.pop(path),lambda n:n[path].__setitem__('uid',1),lambda n:n[path].__setitem__('target_b64','L2V0Yy9zaGFkb3c='),lambda n:n[path].__setitem__('target_b64','bGliei5zbw=='),lambda n:n[path].__setitem__('owners',['other'])):
   nodes=copy.deepcopy(self.data['baseline_nodes']);edit(nodes)
   with self.assertRaises(ValueError):P.join([row],nodes)
  bad=dict(row,name='libWrong.so');self.assertRaises(ValueError,P.join,[bad],self.data['baseline_nodes'])
 def test_baseline_hash_only_and_observed_sample_cannot_derive_acceptance(self):
  for body in(b'',self.actual,json.dumps(T.BASELINE).encode()):
   with self.assertRaisesRegex(ValueError,'baseline bytes'):T.derive(body,self.data['baseline_nodes'],self.data['db_nodes'],self.data['db_elf_sonames'])
 def test_r90_metadata_omits_xattrs_so_cannot_pass_live_metadata_guard(self):
  before=json.loads((HERE/'baseline-public.DATA.json').read_bytes())['nodes'];after=json.loads((HERE/'actual-r90-observation.DATA.json').read_bytes())['cache_observation']['nodes']
  with self.assertRaisesRegex(ValueError,'xattrs'):T.metadata(before,after)
 def test_typed_cache_and_parent_metadata_constraints(self):
  before=json.loads((HERE/'baseline-public.DATA.json').read_bytes())['nodes'];after=copy.deepcopy(before);after['etc']['mtime']+=10;after['etc/ld.so.cache']['mtime']+=10;after['etc/ld.so.cache']['inode']+=10;self.assertTrue(T.metadata(before,after))
  for path,key,val in(('etc','inode',999),('etc','mode',0o777),('etc','xattrs',{'x':'y'}),('etc/ld.so.cache','links',2),('etc/ld.so.cache','mode',0o600),('etc/ld.so.cache','uid',True),('etc/ld.so.cache','mtime',0)):
   rows=copy.deepcopy(after);rows[path][key]=val
   with self.subTest(path=path,key=key),self.assertRaises(ValueError):T.metadata(before,rows)
 def test_whole_source_and_provider_projection_corruption_refuse(self):
  X.verify()
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);(root/'providers.DATA.json').write_bytes((HERE/'providers.DATA.json').read_bytes()+b' ')
   with patch.object(T,'HERE',root):self.assertRaises(ValueError,T.qualified_providers)
 def test_source_transform_refuses_missing_baseline_and_wrong_predecessor(self):
  a=(HERE/'predecessor-initialized-state.sh').read_bytes();b=(HERE/'predecessor-root.sh').read_bytes();self.assertRaises(ValueError,X.apply,a,b,b'');self.assertRaises(ValueError,X.apply,a+b' ',b,b'')
 def test_finite_shell_phase_checks_with_model_data_only(self):
  helper=(HERE/'guest-cache-transition.sh').read_text()
  prelude='\nD=/MODEL\n_initialized_identity(){ printf MODEL; }\n_initialized_cache_clock(){ printf 1794904000000000000; }\ninitialized_cache_manifest_identity=MODEL\ninitialized_cache_started_ns=1794903900000000000\ninitialized_cache_phase=INSTALLED\ninitialized_paths=();initialized_paths[5]=etc/ld.so.cache;initialized_paths[9]=etc\ninitialized_cache_sizes=(17551 17695 17551)\ninitialized_cache_hashes=(0000000000000000000000000000000000000000000000000000000000000000 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0000000000000000000000000000000000000000000000000000000000000000)\n'
  good='N etc/ld.so.cache 32714 1 f 644 0 0 17695 1794903943.636000000 '+'a'*64
  expected='N etc/ld.so.cache 29322 1 f 644 0 0 17551 1794860506.164000000 '+'0'*64
  cases=[(5,good,expected,0),(5,good.replace('17695','17551'),expected,2),(5,good.replace(' 1 f ',' 2 f '),expected,2),(5,expected,expected,2),(13,good,expected,2)]
  for index,current,old,code in cases:
   script=helper+prelude+'\n_initialized_cache_phase_view "$1" "$2" "$3"'
   result=subprocess.run(['/usr/bin/bash','-c',script,'DATA',str(index),current,old],capture_output=True,timeout=5);self.assertEqual(result.returncode,code,result.stderr);self.assertEqual(result.stdout,b'')
 def test_model_exact_transform_inverse_and_shell_syntax(self):
  a=(HERE/'predecessor-initialized-state.sh').read_bytes();b=(HERE/'predecessor-root.sh').read_bytes();model=b'MODEL_ONLY_NO_ROOT_AUTHORITY\n'
  with patch.object(X,'manifest',return_value=(model,{},b'MODEL')):
   result=X.apply(a,b,b'MODEL');self.assertEqual(X.inverse(result,b'MODEL'),(a,b))
   for name in('initialized','root'):
    test=subprocess.run(['/usr/bin/bash','-n'],input=result[name],capture_output=True,timeout=5);self.assertEqual(test.returncode,0,test.stderr)
   self.assertIn(b'[[ $attrs == "${initialized_attrs[$i]}"',result['initialized']);self.assertIn(b'_initialized_empty "$initialized_prefix/root/.ssh"',result['initialized']);self.assertIn(b'same_bytes "$S/before.cache" "$S/after.cache"',result['root'])
 def test_original_private_guards_and_restoration_checks_retained(self):
  s=(HERE/'transform.py').read_text();self.assertIn('current=$(_initialized_view',s);self.assertIn('current=$(_initialized_view \"$i\") || { _ig_diagnostic R21',s);self.assertIn('$i == 5 || $i == 9',s)
  old=(HERE/'predecessor-initialized-state.sh').read_text();self.assertIn('_initialized_empty "$initialized_prefix/root/.ssh"',old);self.assertIn('[[ $attrs == "${initialized_attrs[$i]}"',old)
  helper=(HERE/'guest-cache-transition.sh').read_text();self.assertNotIn('touch ',helper);self.assertNotIn('rm ',helper);self.assertNotIn('cp ',helper);self.assertIn('RESTORED',helper);self.assertIn('1500000000000',helper)
if __name__=='__main__':unittest.main(verbosity=2)
