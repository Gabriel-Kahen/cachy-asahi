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
def invert(raw,edits,want):
 text=raw.decode()
 for before,after in edits:
  assert text.count(after)==1;text=text.replace(after,before,1)
 assert digest(text.encode())==want,'whole exact original Apps7 source inverse';return text.encode()
A=load((HERE/'apps.py').read_bytes(),'new_apps');I=load((HERE/'inventory.py').read_bytes(),'new_inventory');OLD_A=load(invert((HERE/'apps.py').read_bytes(),[APP_EDIT],'c12f8548d5fd3007a61fb366ca279dd061917cc5320ba81ce5e2ab0d02c7d9a6'),'old_apps');OLD_I=load(invert((HERE/'inventory.py').read_bytes(),INVENTORY_EDITS,'68f9b0bc6bd5c494ebfc10bdc1e243c014d7fa8e56b1386491b75cdb9ee2e3df'),'old_inventory');C,R,_=A.helpers(options.repository_source)
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
  old=functions(invert((HERE/'inventory.py').read_bytes(),INVENTORY_EDITS,'68f9b0bc6bd5c494ebfc10bdc1e243c014d7fa8e56b1386491b75cdb9ee2e3df').decode());new=functions((HERE/'inventory.py').read_text());self.assertEqual({n for n in old if old[n]!=new[n]},{'relative','scan'});self.assertIn('deadline=time.monotonic()+30',new['collect']);self.assertIn('first=scan(dbpath,c,normalize,deadline);second=scan(dbpath,c,normalize,deadline)',new['collect'])
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
