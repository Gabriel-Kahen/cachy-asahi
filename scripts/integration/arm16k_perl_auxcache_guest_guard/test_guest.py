# SPDX-License-Identifier: MIT
"""Host-executed guest interpreter projection: MODEL plus genuine r96 baseline."""
import ast,copy,hashlib,importlib.util,random,struct,subprocess,tempfile,unittest
from pathlib import Path
H=Path(__file__).resolve().parent;P=H.parent/'arm16k_perl_auxcache_semantics'
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
A=module('host_aux',P/'auxcache.py');T=module('host_models',P/'test_auxcache.py')
def guest(b):return subprocess.run(['/usr/bin/bash',str(H/'canonicalize.sh')],input=b,capture_output=True,timeout=10)
class Controls(unittest.TestCase):
 def joined(self,b):
  r=guest(b);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stderr,b'');self.assertEqual(r.stdout,A.normalize(b)[1]);return r.stdout
 def refused(self,b):
  self.assertRaises(ValueError,A.decode,b);r=guest(b);self.assertNotEqual(r.returncode,0);self.assertEqual(r.stdout,b'');self.assertIn(b'AUXCACHE_REFUSED',r.stderr)
 def test_ACTUAL_baseline_bf57_exact_host_canonical(self):
  b=(P/'baseline-aux.ACTUAL.bin').read_bytes();self.assertEqual(A.pin(b),dict(bytes=12313,sha256='bf57218ea22ca530decf18bf8ec548c22ec96afb0afc423088a97fbb148149ed'));c=self.joined(b);self.assertEqual(A.pin(c),dict(bytes=11373,sha256='101a81b8720aeb3f5994f133226c19f06a3b9073d51cee7d419c2ceb96184f1d'))
 def test_MODEL_full_U64_above_double_precision_and_binary_names(self):
  rows=[dict(ino=2**64-i,ctime=2**64-11-i,size=2**63+1+i,device=2**53+i,name=n,isa=1023)for i,n in enumerate((None,b'',b'\xff/full\n\t.so.009',bytes(range(1,256))),1)]
  a=self.joined(T.model(rows));rows[0]['ino']-=1;self.assertNotEqual(a,self.joined(T.model(rows)))
 def test_MODEL_deterministic_U64_order_matches_numeric_host(self):
  r=random.Random(387);rows=[dict(ino=r.getrandbits(64),ctime=r.getrandbits(64),size=r.getrandbits(64),device=r.getrandbits(64),name=bytes([1+i])+b'.so.1')for i in range(100)];self.joined(T.model(rows));r.shuffle(rows);self.joined(T.model(rows))
 def test_MODEL_only_padding_order_offsets_normalized(self):
  rows=[dict(ino=i,name=b'lib'+bytes([64+i])+b'.so.1')for i in(1,2,3)]
  a=self.joined(T.model(rows));b=self.joined(T.model(list(reversed(rows)),pad=b'\xff\x01\x02\x03',string_order=[1,2,0]));self.assertEqual(a,b)
 def test_MODEL_NULL_empty_name_full_versions_and_membership_differ(self):
  rows=[dict(ino=1,name=None),dict(ino=2,name=b''),dict(ino=3,name=b'lib.so.09')];a=self.joined(T.model(rows))
  for index,name in((0,b''),(1,b'x'),(2,b'lib.so.9')):
   changed=copy.deepcopy(rows);changed[index]['name']=name;self.assertNotEqual(a,self.joined(T.model(changed)))
  self.assertNotEqual(a,self.joined(T.model(rows[:-1])))
 def test_MODEL_each_defined_stat_field_and_ISA_preserved(self):
  row=dict(ino=2**64-1,ctime=2**64-2,size=2**64-3,device=2**64-4,isa=1023,name=b'lib.so.1');a=self.joined(T.model([row]))
  for key in('ino','ctime','size','device','isa'):
   changed=dict(row);changed[key]-=1;self.assertNotEqual(a,self.joined(T.model([changed])))
 def test_MODEL_empty_cache_and_maximum_name(self):self.joined(T.model([]));self.joined(T.model([dict(ino=0,name=b'\xff'*4096)]))
 def test_MODEL_bounded_maximum_entry_count_and_near_cap(self):self.joined(T.model([dict(ino=i,name=b'x'*206)for i in range(4096)]))
 def test_MODEL_duplicate_identity_refuses(self):self.refused(T.model([dict(ino=1,name=b'a'),dict(ino=1,name=b'b')]))
 def test_MODEL_flags_ISA_magic_endian_refuse(self):
  for key,value in(('flags',0x303),('flags',-1),('isa',1024)):
   row=dict(ino=1,name=b'a');row[key]=value;self.refused(T.model([row]))
  b=T.model([dict(ino=1,name=b'a')]);self.refused(b'X'+b[1:]);self.refused(b[:24]+struct.pack('>II',1,3)+b[32:])
 def test_MODEL_counts_geometry_trailing_overcap_refuse(self):
  b=T.model([dict(ino=1,name=b'a')])
  for offset,value in((24,4097),(28,0),(28,2**32-1)):
   bad=bytearray(b);struct.pack_into('<I',bad,offset,value);self.refused(bytes(bad))
  for bad in(b[:-1],b+b'\0',b'x'*(A.CAP+1),b'x'*(A.CAP+9)):self.refused(bad)
 def test_MODEL_offsets_aliases_unreferenced_NUL_refuse(self):
  b=T.model([dict(ino=1,name=b'abc'),dict(ino=2,name=b'd')])
  for at,v in((68,2),(68,0),(116,1),(68,2**32-1)):
   bad=bytearray(b);struct.pack_into('<I',bad,at,v);self.refused(bytes(bad))
  bad=bytearray(b);bad[-1]=1;self.refused(bytes(bad));self.refused(T.model([dict(ino=1,name=b'x'*4097)]))
 def test_no_arguments_or_filesystem_name_execution(self):
  r=subprocess.run(['/usr/bin/bash',str(H/'canonicalize.sh'),'/MODEL/never-open'],input=b'',capture_output=True,timeout=5);self.assertEqual(r.returncode,2);self.assertEqual(r.stdout,b'');self.joined(T.model([dict(ino=1,name=b'/MODEL/never-open\n$(false)')]))
class ComponentControls(unittest.TestCase):
 def test_whole389_inverse_and_tamper_refusals(self):
  C=module('component',H/'project.py');source=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-perl-restoration-observed-successor-readiness-20261117-r2/constructed-source');bodies={p.relative_to(source).as_posix():p.read_bytes()for p in source.rglob('*')if p.is_file()};out=C.project(bodies);self.assertEqual(C.inverse(out),bodies);self.assertEqual(set(out)-set(bodies),set(C.runtime()));self.assertEqual({n for n in bodies if bodies[n]!=out[n]},{'guest/root.sh','adapter.py'});self.assertLess(sum(map(len,out.values())),4194304)
  for name in('guest/root.sh','adapter.py','source.lock.json','_auxcache_guest/canonicalize.awk'):
   bad=dict(out);bad[name]+=b'x';self.assertRaises(ValueError,C.inverse,bad)
  bad=dict(bodies);bad['guest/root.sh']+=b'x';self.assertRaises(ValueError,C.project,bad)
 def test_actual_added_adapter_statement_delivers_runtime_and_snapshot_reads_it(self):
  C=module('component_delivery',H/'project.py');source=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-perl-restoration-observed-successor-readiness-20261117-r2/constructed-source');adapter=C.replace((source/'adapter.py').read_bytes(),C.SEAM,C.SEAM+C.DELIVERY);tree=ast.parse(adapter);fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='contents');statement=next(n for n in fn.body if isinstance(n,ast.For)and ast.get_source_segment(adapter.decode(),n).startswith("for name in('canonicalize.sh','canonicalize.awk')"))
  with tempfile.TemporaryDirectory(prefix='aux-delivery-')as t:
   d=Path(t);fixture=d/'fixture';fixture.mkdir();src=d/'source';(src/'_auxcache_guest').mkdir(parents=True)
   for n,b in C.runtime().items():(src/n).write_bytes(b)
   rows={};exec(compile(ast.fix_missing_locations(ast.Module(body=[statement],type_ignores=[])),'actual-adapter-delivery','exec'),dict(HERE=src,put=lambda n,b:rows.__setitem__(n,b)))
   for n,b in rows.items():p=fixture/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
   self.assertEqual(rows,{'auxcache/'+n:(H/n).read_bytes()for n in('canonicalize.sh','canonicalize.awk')})
   root=C.replace((source/'guest/root.sh').read_bytes(),C.OLD,C.NEW);text=root.decode();start=text.index('cache_snapshot() (');end=text.index('\ncheckpoint_phase users',start);function=text[start:end]
   paths={p:str(d/('public'+str(i)))for i,p in enumerate(('/etc/ld.so.cache','/var/cache/ldconfig/aux-cache','/var/cache/ldconfig'))}
   # Fixed test-only mapping of the three public operands into owned temp DATA.
   for old in sorted(paths,key=len,reverse=True):function=function.replace(old,paths[old])
   Path(paths['/etc/ld.so.cache']).write_bytes(b'MODEL main cache');Path(paths['/var/cache/ldconfig']).mkdir();Path(paths['/var/cache/ldconfig/aux-cache']).write_bytes((P/'baseline-aux.ACTUAL.bin').read_bytes())
   # getfattr's existing metadata stream is outside this canonicalizer test.
   script='set -euo pipefail;export LC_ALL=C;D='+str(fixture)+'; getfattr(){ :; };'+function+'\ncache_snapshot\n'
   r=subprocess.run(['/usr/bin/bash','-c',script],capture_output=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr);self.assertIn(b'AUX_DEFINED_FIELDS_V1 101a81b8720aeb3f5994f133226c19f06a3b9073d51cee7d419c2ceb96184f1d ',r.stdout)
   (fixture/'auxcache/canonicalize.awk').unlink();r=subprocess.run(['/usr/bin/bash','-c',script],capture_output=True,timeout=10);self.assertNotEqual(r.returncode,0)
if __name__=='__main__':unittest.main(verbosity=2)
