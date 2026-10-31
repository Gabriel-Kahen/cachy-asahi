# SPDX-License-Identifier: MIT
"""Whole Apps7 inverses, lexical parity and two fresh source-shaped606 scans."""
import argparse,ast,hashlib,itertools,json,os,random,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
q=argparse.ArgumentParser(add_help=False);q.add_argument('--repository-source',type=Path,required=True);options,rest=q.parse_known_args()
def load(raw,name):
 m=types.ModuleType(name);m.__file__=str(HERE/('apps.py'if name.endswith('apps')else'inventory.py'));exec(compile(raw,m.__file__,'exec'),m.__dict__);return m
def digest(raw):return hashlib.sha256(raw).hexdigest()
APP_EDIT=("if key=='files':need(item not in ('.','..') and not item.startswith('/') and '..' not in Path(item).parts and Path(item).as_posix()==item,'unsafe payload path')","if key=='files':need(all(part not in ('','.','..') for part in item.split('/')),'unsafe payload path')")
INVENTORY_EDITS=[("    directory=value.endswith('/');name=value[:-1] if directory else value;path=PurePosixPath(name)\n    need(name not in ('','.','..') and not path.is_absolute() and path.as_posix()==name and '..' not in path.parts,'noncanonical ALPM ownership path')","    directory=value.endswith('/');name=value[:-1] if directory else value\n    need(all(part not in ('','.','..') for part in name.split('/')),'noncanonical ALPM ownership path')"),("            for path in owners:\n                need(not any(parent.as_posix() in owners for parent in PurePosixPath(path).parents),'regular file/ancestor ownership conflict')","            for path in owners:\n                parent=path.rpartition('/')[0]\n                while parent:\n                    need(parent not in owners,'regular file/ancestor ownership conflict')\n                    parent=parent.rpartition('/')[0]\n                need('.' not in owners,'regular file/ancestor ownership conflict')")]
APPS9_EDITS=[("need(not any(ord(v)<32 and v not in '\\n\\t' or ord(v)==127 for v in text),'ALPM record control character')", "need(re.search(r'[\\x00-\\x08\\x0b-\\x1f\\x7f]',text)is None,'ALPM record control character')"), ('not any(ord(v)<32 or ord(v)==127 for v in value)', "re.search(r'[\\x00-\\x1f\\x7f]',value)is None")]
INVENTORY_EDITS+=APPS9_EDITS

def invert(raw,edits,want):
 text=raw.decode()
 for before,after in edits:
  assert text.count(after)==1;text=text.replace(after,before,1)
 assert digest(text.encode())==want,'whole exact original Apps7 source inverse';return text.encode()

def parent9(raw,kind):
    if kind=='inventory':
        raw=raw.split(b'\n# BEGIN_APPS10_OPTIONAL_STAGE_DIAGNOSTIC\n')[0]
        assert digest(raw)=='8bb0e7374882d4b74f50cadf5a1d3d1524627e10714b53848b8b27eb6da30837'
        return raw
    text=raw.decode()
    for before,after in reversed(APP10_EDITS):
        assert text.count(after)==1;text=text.replace(after,before,1)
    assert digest(text.encode())=='8b575e25226463834a45b3f679ee4ddf5ef124976b008494a4944c0252cdf1f5'
    return text.encode()
APP10_EDITS=[("    if args.command=='inventory':return inventory_reader().publish(args.dbpath,args.output,c,lambda row:package(row,r))", "    if args.command=='inventory':\n        reader=inventory_reader();publish=reader.publish_diagnostic if getattr(args,'diagnostic_stage',False) else reader.publish\n        return publish(args.dbpath,args.output,c,lambda row:package(row,r))"), ("    inventory.add_argument('--dbpath',type=Path,required=True);inventory.add_argument('--output',type=Path,required=True)", "    inventory.add_argument('--dbpath',type=Path,required=True);inventory.add_argument('--output',type=Path,required=True)\n    inventory.add_argument('--diagnostic-stage',action='store_true',help='explicit fresh0600 sibling stage JSON with finite phases/timing only; never acceptance')")]

A=load((HERE/'apps.py').read_bytes(),'new_apps');I=load((HERE/'inventory.py').read_bytes(),'new_inventory');OLD_A=load(invert(parent9((HERE/'apps.py').read_bytes(),'apps'),[APP_EDIT],'c12f8548d5fd3007a61fb366ca279dd061917cc5320ba81ce5e2ab0d02c7d9a6'),'old_apps');OLD_I=load(invert(parent9((HERE/'inventory.py').read_bytes(),'inventory'),INVENTORY_EDITS,'68f9b0bc6bd5c494ebfc10bdc1e243c014d7fa8e56b1386491b75cdb9ee2e3df'),'old_inventory');C,R,_=A.helpers(options.repository_source)
def outcome(call):
 try:return ('PASS',call())
 except ValueError as e:return ('REFUSE',str(e))
def package(path):return dict(name='fixture',version='1-1',arch='aarch64',depend=[],provides=[],conflict=[],replaces=[],files=[path])
def fixture(db,count=606,files=192):
 local=db/'local';local.mkdir(parents=True);(local/'ALPM_DB_VERSION').write_bytes(b'9\n')
 for index in range(count):
  name='fixture-'+str(index).zfill(3);root=local/(name+'-1:2.3-4');root.mkdir();desc={'NAME':[name],'VERSION':['1:2.3-4'],'ARCH':['aarch64'],'BASE':[name],'DESC':['source-shaped606 control'],'BUILDDATE':['1791748800'],'INSTALLDATE':['1791748801'],'DEPENDS':['runtime>=1','runtime>=1'],'PROVIDES':[name+'-api=1']};(root/'desc').write_text(''.join('%'+k+'%\n'+'\n'.join(v)+'\n\n'for k,v in desc.items()));paths=['usr/share/'+name+'/f'+str(n).zfill(3)for n in range(files)];paths += ['usr/share/'+name+'/'+('x'*230)+'/'+('y'*230),r'usr/share/'+name+r'/literal\backslash'];(root/'files').write_text('%FILES%\n'+'\n'.join(paths)+'\n\n');(root/'mtree').write_bytes(b'source-shaped opaque exact bytes\n')
 return count*(files+2)
class Controls(unittest.TestCase):
 def test_exhaustive_lexical_and_payload_refusal_parity(self):
  values=[''.join(parts)for n in range(7)for parts in itertools.product('a./\\',repeat=n)]+['a'*512,'a'*513,'usr/東京/Café',r'usr/system-systemd\x2dcryptsetup.slice','a\0b','a\nb','a\tb',None,False,17];rng=random.Random(602);values += [''.join(rng.choice('ab./\\:- _é')for _ in range(rng.randrange(1,65)))for _ in range(4096)]
  for value in values:
   self.assertEqual(outcome(lambda:OLD_I.relative(value)),outcome(lambda:I.relative(value)),repr(value))
   if type(value)is str:self.assertEqual(outcome(lambda:OLD_A.package(package(value),R)),outcome(lambda:A.package(package(value),R)),repr(value))
 def test_complete_source_shaped606_twofresh_scans_raw_hashes_and_normalization(self):
  with tempfile.TemporaryDirectory()as td:
   db=Path(td)/'db';paths=fixture(db);calls=[];scan=I.scan
   def track(*args):calls.append(args[-1]);return scan(*args)
   with patch.object(I,'scan',track):new=I.collect(db,C,lambda row:A.package(row,R))
   old=OLD_I.collect(db,C,lambda row:OLD_A.package(row,R));self.assertEqual(I.encoded(new),OLD_I.encoded(old));self.assertEqual(len(calls),2);self.assertEqual(calls[0],calls[1]);self.assertEqual(len(new['packages']),606);self.assertEqual(sum(len(r['files'])for r in new['packages']),paths);self.assertEqual(len(new['observation']['inputs']),1819);self.assertEqual(I.validate(new,lambda row:A.package(row,R)),I.QUALIFICATION)
 def test_raw_second_read_mutation_lock_ancestry_ambiguity_and_deadline_refuse(self):
  with tempfile.TemporaryDirectory()as td:
   db=Path(td)/'db';fixture(db,2,2);scan=I.scan;calls=[]
   def mutate(*args):
    value=scan(*args);calls.append(1)
    if len(calls)==1:(db/'local/fixture-000-1:2.3-4/mtree').write_bytes(b'changed fresh raw record\n')
    return value
   with patch.object(I,'scan',mutate),self.assertRaisesRegex(ValueError,'two complete'):I.collect(db,C,lambda row:A.package(row,R))
   self.assertEqual(len(calls),2);(db/'db.lck').touch()
   for module in(OLD_I,I):
    with self.assertRaisesRegex(ValueError,'db.lck'):module.collect(db,C,lambda row:A.package(row,R))
   (db/'db.lck').unlink()
   for module in(OLD_I,I):
    with self.assertRaisesRegex(ValueError,'deadline'):module.scan(db,C,lambda row:A.package(row,R),0)
   (db/'local/fixture-001-1:2.3-4/files').write_text('%FILES%\nusr/share/fixture-000/f000/child\n\n')
   for module in(OLD_I,I):
    with self.assertRaisesRegex(ValueError,'ancestor ownership'):module.collect(db,C,lambda row:A.package(row,R))
   for value in('a//b','./a','a/./b','a/../b','/a','a//'):
    self.assertEqual(outcome(lambda:OLD_I.relative(value)),outcome(lambda:I.relative(value)));self.assertEqual(outcome(lambda:OLD_I.relative(value))[0],'REFUSE')
 def test_all_other_inventory_functions_and_30second_budget_byteheld(self):
  def functions(raw):return {n.name:ast.get_source_segment(raw,n)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
  old=functions(invert(parent9((HERE/'inventory.py').read_bytes(),'inventory'),INVENTORY_EDITS,'68f9b0bc6bd5c494ebfc10bdc1e243c014d7fa8e56b1386491b75cdb9ee2e3df').decode());new=functions(parent9((HERE/'inventory.py').read_bytes(),'inventory').decode());self.assertEqual({n for n in old if old[n]!=new[n]},{'relative','scan','sections'});self.assertIn('deadline=time.monotonic()+30',new['collect']);self.assertIn('first=scan(dbpath,c,normalize,deadline);second=scan(dbpath,c,normalize,deadline)',new['collect'])
# Apps9 retains the whole Apps8 inventory as an exact two-predicate inverse.
APPS8_RAW=invert(parent9((HERE/'inventory.py').read_bytes(),'inventory'),APPS9_EDITS,'bf0068a57240094dba2eb860c48a0f7f547a9b8e7c675ef847834423de2dda9f')
EIGHT=load(APPS8_RAW,'eight_inventory')
class CCharacterPredicateControls(unittest.TestCase):
 def test_every_ascii_unicode_surrogate_and_invalid_utf8_policy_parity(self):
  values=[chr(n)for n in range(128)]+[chr(n)for n in(0x80,0x85,0xa0,0x7ff,0x800,0x2028,0x2029,0xd7ff,0xd800,0xdbff,0xdc00,0xdfff,0xe000,0xffff,0x10000,0x10ffff)]+['東京','Cafe\u0301','literal\\escape','a'*511,'a'*512,'a'*513]
  for char in values:
   for position in('', 'usr/', 'usr/share/'):
    value=position+char+'/leaf'
    with self.subTest(value=repr(value)):self.assertEqual(outcome(lambda:EIGHT.relative(value)),outcome(lambda:I.relative(value)))
   raw=('%FILES%\nusr/'+char+'/leaf\n\n').encode('utf8','surrogatepass');self.assertEqual(outcome(lambda:EIGHT.sections(raw,{'FILES'})),outcome(lambda:I.sections(raw,{'FILES'})))
  for raw in(b'\x80',b'\xff',b'\xc0\x80',b'\xed\xa0\x80',b'%FILES%\na\r\n\n',b'%FILES%\na\x00b\n\n'):self.assertEqual(outcome(lambda:EIGHT.sections(raw,{'FILES'})),outcome(lambda:I.sections(raw,{'FILES'})))
 def test_whole_apps8_inverse_all_scans_caps_hash_and_descriptor_bodies_held(self):
  before=APPS8_RAW.decode();after=parent9((HERE/'inventory.py').read_bytes(),'inventory').decode();sections=lambda text:{n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)};a,b=sections(before),sections(after);self.assertEqual({n for n in a if a[n]!=b[n]},{'relative','sections'})
  self.assertEqual(a['scan'],b['scan']);self.assertEqual(a['collect'],b['collect']);self.assertEqual(a['publish'],b['publish']);self.assertEqual(a['validate'],b['validate']);self.assertEqual((I.MAX_BYTES,I.MAX_RECORD,I.MAX_PACKAGES,I.MAX_INSTALLED_JSON),(64*1024**2,4*1024**2,4096,16*1024**2));self.assertEqual(digest(parent9((HERE/'apps.py').read_bytes(),'apps')),'8b575e25226463834a45b3f679ee4ddf5ef124976b008494a4944c0252cdf1f5')
 def test_whole606_old8_new9_outputs_two_fresh_scans_and_raw_mutation_refusal(self):
  with tempfile.TemporaryDirectory()as td:
   db=Path(td)/'db';paths=fixture(db);old=EIGHT.collect(db,C,lambda row:A.package(row,R));calls=[];scan=I.scan
   def track(*args):calls.append(args[-1]);return scan(*args)
   with patch.object(I,'scan',track):new=I.collect(db,C,lambda row:A.package(row,R))
   self.assertEqual(I.encoded(new),EIGHT.encoded(old));self.assertEqual(len(new['packages']),606);self.assertEqual(sum(len(r['files'])for r in new['packages']),paths);self.assertEqual(len(calls),2);self.assertEqual(calls[0],calls[1]);calls=[]
   def mutate(*args):
    result=scan(*args);calls.append(1)
    if len(calls)==1:(db/'local/fixture-000-1:2.3-4/mtree').write_bytes(b'actual changed next complete scan\n')
    return result
   with patch.object(I,'scan',mutate),self.assertRaisesRegex(ValueError,'two complete'):I.collect(db,C,lambda row:A.package(row,R))
   self.assertEqual(len(calls),2)
 def test_actual_publish_preserves_private_mode_full_bytes_and_drift_refusals(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);db=root/'db';fixture(db,606,192);old=root/'old.json';new=root/'new.json';r=EIGHT.publish(db,old,C,lambda row:A.package(row,R));s=I.publish(db,new,C,lambda row:A.package(row,R));self.assertEqual(old.read_bytes(),new.read_bytes());self.assertEqual((r['sha256'],r['bytes'],r['package_count']),(s['sha256'],s['bytes'],606));self.assertEqual(new.stat().st_mode&0o777,0o600)
   with self.assertRaisesRegex(ValueError,'fresh inventory'):I.publish(db,new,C,lambda row:A.package(row,R))
   (db/'db.lck').touch()
   with self.assertRaisesRegex(ValueError,'db.lck'):I.collect(db,C,lambda row:A.package(row,R))

if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
