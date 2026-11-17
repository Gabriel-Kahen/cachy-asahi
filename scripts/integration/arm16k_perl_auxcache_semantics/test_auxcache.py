# SPDX-License-Identifier: MIT
"""MODEL primary-layout controls plus explicitly labeled ACTUAL baseline DATA."""
import base64,builtins,copy,hashlib,importlib.util,json,struct,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('strict_auxcache_semantics',HERE/'auxcache.py');A=importlib.util.module_from_spec(s);s.loader.exec_module(A)

def model(entries,pad=b'\0'*4,string_order=None):
 # MODEL bytes assembled from primary field positions, never accepted guest DATA.
 nonnull=[i for i,e in enumerate(entries)if e.get('name')is not None];order=nonnull if string_order is None else string_order;table=bytearray(b'\0');offsets={}
 for i in order:offsets[i]=len(table);table.extend(entries[i]['name']+b'\0')
 records=[]
 for i,e in enumerate(entries):records.append(struct.pack('<QQQQiII4s',e['ino'],e.get('ctime',1700000000),e.get('size',65536),e.get('device',254),e.get('flags',0xa03),offsets.get(i,0),e.get('isa',0),pad))
 return struct.pack('<24sII',A.MAGIC,len(entries),len(table))+b''.join(records)+table

def source_hash(e):
 value=(((e['ino']*11+e.get('ctime',1700000000))*11+e.get('size',65536))*11+e.get('device',254))&((1<<64)-1);return(value^(value>>32))&0xffffffff

def source_save(entries,buckets):
 rows={}
 for e in entries:rows.setdefault(source_hash(e)%buckets,[]).insert(0,e)
 return model([e for h in sorted(rows)for e in rows[h]])
class Controls(unittest.TestCase):
 def setUp(self):self.entries=[dict(ino=1,name=b'libA.so.1'),dict(ino=1022,name=b'libB.so.2'),dict(ino=2043,name=b'libC.so.3')]
 def test_ACTUAL_baseline_strict_primary_layout(self):
  blob=(HERE/'baseline-aux.ACTUAL.bin').read_bytes();self.assertEqual(A.pin(blob),dict(bytes=12313,sha256='bf57218ea22ca530decf18bf8ec548c22ec96afb0afc423088a97fbb148149ed'));v,canonical=A.normalize(blob);self.assertEqual(v['count'],190);self.assertEqual(sum(e['soname_b64']is None for e in v['entries']),1);self.assertEqual(v['defined_fields'],dict(bytes=11373,sha256='101a81b8720aeb3f5994f133226c19f06a3b9073d51cee7d419c2ceb96184f1d'));self.assertIsNone(v['Root_acceptance']);self.assertEqual(v['selection'],'UNSELECTED')
 def test_MODEL_bucket_reload_changes_bytes_preserves_defined_membership(self):
  before=source_save(self.entries,8191);decoded=A.decode(before);rows=[dict(ino=e['inode'],ctime=e['ctime'],size=e['size'],device=e['device'],flags=e['flags'],isa=e['isa_level'],name=None if e['soname_b64']is None else base64.b64decode(e['soname_b64']))for e in decoded['entries']];after=source_save(rows,1021);result=A.compare(before,after);self.assertFalse(result['raw_bytes_equal']);self.assertTrue(result['defined_fields_equal']);self.assertEqual(result['removed'],[]);self.assertEqual(result['added'],[]);self.assertIsNone(result['actual_cause'])
 def test_MODEL_only_ABI_padding_is_ignored(self):
  a=model(self.entries);b=model(self.entries,pad=b'\xff\x01\x02\x03');result=A.compare(a,b);self.assertTrue(result['defined_fields_equal']);self.assertFalse(result['raw_bytes_equal']);self.assertNotEqual(A.decode(a)['opaque_padding'],A.decode(b)['opaque_padding'])
 def test_MODEL_record_and_complete_string_layout_relocation(self):
  a=model(self.entries);b=model(self.entries,string_order=[2,0,1]);self.assertTrue(A.compare(a,b)['defined_fields_equal']);self.assertNotEqual(a,b);self.assertTrue(A.compare(a,model(list(reversed(self.entries))))['defined_fields_equal'])
 def test_every_defined_stat_field_change_is_visible(self):
  a=model(self.entries)
  for field in('ino','ctime','size','device','isa'):
   e=copy.deepcopy(self.entries);e[0][field]=e[0].get(field,{'ctime':1700000000,'size':65536,'device':254,'isa':0}.get(field,0))+1
   with self.subTest(field=field):self.assertFalse(A.compare(a,model(e))['defined_fields_equal'])
 def test_full_binary_names_NULL_empty_and_versions_are_distinct(self):
  rows=[dict(ino=1,name=None),dict(ino=2,name=b''),dict(ino=3,name=b'libX.so.09'),dict(ino=4,name=b'\xfflib/full.so.01')];v=A.decode(model(rows));self.assertIsNone(v['entries'][0]['soname_b64']);self.assertEqual(v['entries'][1]['soname_b64'],'');self.assertEqual(base64.b64decode(v['entries'][3]['soname_b64']),b'\xfflib/full.so.01');changed=copy.deepcopy(rows);changed[0]['name']=b'';self.assertFalse(A.compare(model(rows),model(changed))['defined_fields_equal']);changed=copy.deepcopy(rows);changed[2]['name']=b'libX.so.9';self.assertFalse(A.compare(model(rows),model(changed))['defined_fields_equal'])
 def test_unsigned64_values_and_all_ISA_bits_are_preserved(self):
  rows=[dict(ino=(1<<64)-1,ctime=(1<<64)-2,size=(1<<64)-3,device=(1<<64)-4,name=b'libU.so.1',isa=1023)];e=A.decode(model(rows))['entries'][0];self.assertEqual((e['inode'],e['ctime'],e['size'],e['device']),tuple((1<<64)-i for i in(1,2,3,4)));self.assertEqual(e['isa_level'],1023);self.assertEqual(len(A.canonical_bytes(A.decode(model(rows)))),len(A.CANONICAL_MAGIC)+4+44+len(b'libU.so.1'))
 def test_zero_entry_cache_is_valid_and_membership_not_deduplicated(self):
  self.assertEqual(A.decode(model([]))['count'],0);self.assertFalse(A.compare(model([]),model([self.entries[0]]))['defined_fields_equal']);self.assertRaises(ValueError,A.decode,model([self.entries[0],self.entries[0]]))
 def test_unknown_magic_version_ABI_flags_and_ISA_refuse(self):
  good=model(self.entries)
  for byte in(b'glibc-ld.so.auxcache-1.0',b'glibc-ld.so.auxcache-3.0'):
   with self.assertRaises(ValueError):A.decode(byte+good[24:])
  self.assertRaises(ValueError,A.decode,good,abi='X86_64');e=copy.deepcopy(self.entries);e[0]['flags']=0x303;self.assertRaises(ValueError,A.decode,model(e));e[0]['flags']=0xa03;e[0]['isa']=1024;self.assertRaises(ValueError,A.decode,model(e))
 def test_header_counts_size_trailing_and_big_endian_refuse(self):
  good=model(self.entries)
  for offset,value in((24,4097),(28,0),(28,0xffffffff)):
   bad=bytearray(good);struct.pack_into('<I',bad,offset,value)
   with self.assertRaises(ValueError):A.decode(bytes(bad))
  self.assertRaises(ValueError,A.decode,good+b'\0');self.assertRaises(ValueError,A.decode,good[:-1]);self.assertRaises(ValueError,A.decode,A.MAGIC+struct.pack('>II',3,len(good)-32-3*48)+good[32:]);self.assertRaises(ValueError,A.decode,b'x'*(A.CAP+1))
 def test_offset_overlap_reuse_middle_unreferenced_and_missing_NUL_refuse(self):
  good=model(self.entries)
  for offset,value in((68,2),(68,0xffffffff),(116,1)):
   bad=bytearray(good);struct.pack_into('<I',bad,offset,value)
   with self.assertRaises(ValueError):A.decode(bytes(bad))
  bad=bytearray(good);bad[-1]=1;self.assertRaises(ValueError,A.decode,bytes(bad));bad=bytearray(good);struct.pack_into('<I',bad,68,0);self.assertRaises(ValueError,A.decode,bytes(bad))
 def test_canonical_entry_types_flags_or_hidden_fields_refuse(self):
  original=A.decode(model(self.entries))
  for key,value in(('inode',True),('ctime',-1),('flags',True),('isa_level',1<<32),('soname_b64','not base64'),('hidden',1)):
   v=copy.deepcopy(original);v['entries'][0][key]=value
   with self.assertRaises((ValueError,TypeError)):A.canonical_bytes(v)
  v=copy.deepcopy(original);v['count']=True;self.assertRaises(ValueError,A.canonical_bytes,v)
 def test_pure_decoder_never_opens_name_as_path_or_enters_actor(self):
  blob=model([dict(ino=9,name=b'/MODEL/private/never-read.so')])
  with patch('builtins.open',side_effect=AssertionError('no filesystem')),patch('os.open',side_effect=AssertionError('no filesystem')),patch('subprocess.Popen',side_effect=AssertionError('no actor')),patch('socket.socket',side_effect=AssertionError('no network')):self.assertTrue(A.compare(blob,blob)['defined_fields_equal'])
if __name__=='__main__':unittest.main(verbosity=2)
