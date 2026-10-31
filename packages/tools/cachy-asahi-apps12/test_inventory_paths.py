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


# Full finite Apps11 CPU delta; before helpers remain exact qualified Apps10.
APPS11_EDITS={'apps': [('def package(row,r):', '\ndef package(row,r):'), ("            if key=='files':need(all(part not in ('','.','..') for part in item.split('/')),'unsafe payload path')", "            if key=='files':\n                parts=item.split('/')\n                need(''not in parts and'.'not in parts and'..'not in parts,'unsafe payload path')")], 'inventory': [('MAX_INSTALLED_JSON=16*1024**2', "MAX_INSTALLED_JSON=16*1024**2\n_RECORD_CONTROL=re.compile(r'[\\x00-\\x08\\x0b-\\x1f\\x7f]')\n_PATH_CONTROL=re.compile(r'[\\x00-\\x1f\\x7f]')\n_SECTION=re.compile(r'%[A-Z][A-Z0-9_]*%')"), ("re.search(r'[\\x00-\\x08\\x0b-\\x1f\\x7f]',text)is None", '_RECORD_CONTROL.search(text)is None'), ("elif re.fullmatch('%[A-Z][A-Z0-9_]*%',line):", "elif line.startswith('%')and _SECTION.fullmatch(line):"), ("re.search(r'[\\x00-\\x1f\\x7f]',value)is None", '_PATH_CONTROL.search(value)is None'), ("    need(all(part not in ('','.','..') for part in name.split('/')),'noncanonical ALPM ownership path')", "    parts=name.split('/')\n    need(''not in parts and'.'not in parts and'..'not in parts,'noncanonical ALPM ownership path')"), ("            for path in owners:\n                parent=path.rpartition('/')[0]\n                while parent:\n                    need(parent not in owners,'regular file/ancestor ownership conflict')\n                    parent=parent.rpartition('/')[0]\n                need('.' not in owners,'regular file/ancestor ownership conflict')", "            # owners is complete and immutable here; memoize only already\n            # checked prefixes in THIS scan, never observations across scans.\n            checked_ancestors=set()\n            for path in owners:\n                parent=path.rpartition('/')[0]\n                while parent and parent not in checked_ancestors:\n                    need(parent not in owners,'regular file/ancestor ownership conflict')\n                    checked_ancestors.add(parent);parent=parent.rpartition('/')[0]\n            need('.' not in owners,'regular file/ancestor ownership conflict')")]}
APPS10_PINS={'apps': {'bytes': 22826, 'sha256': 'de9118c7ea98d0ea0263a0615b1ad1e4ed3402c9ea6f1dcbf43d4e75258975dc'}, 'inventory': {'bytes': 20286, 'sha256': '0f9dae65da1411548e5083ebdc14cc0d7f5f342ea0940dbcc2fd560e80b59888'}}
def before11(raw,kind):
 text=raw.decode()
 for old,new in reversed(APPS11_EDITS[kind]):
  assert text.count(new)==1;text=text.replace(new,old,1)
 result=text.encode();assert dict(bytes=len(result),sha256=hashlib.sha256(result).hexdigest())==APPS10_PINS[kind],'whole exact Apps10 CPU predecessor inverse';return result

def parent9(raw,kind):
    raw=before11(raw,kind)
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


class Apps11CPUControls(unittest.TestCase):
 def baseline(self):return load(before11((HERE/'apps.py').read_bytes(),'apps'),'baseline10_apps'),load(before11((HERE/'inventory.py').read_bytes(),'inventory'),'baseline10_inventory')
 def test_complete_inverse_and_all_descriptor_crypto_deadline_publication_bodies_held(self):
  import ast
  old_app,old_inv=self.baseline();functions=lambda text:{n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  for name,changed in(('apps.py',{'package'}),('inventory.py',{'sections','relative','scan'})):
   kind='apps'if name=='apps.py'else'inventory';before=functions(before11((HERE/name).read_bytes(),kind).decode());after=functions((HERE/name).read_text());self.assertEqual(before.keys(),after.keys());self.assertEqual({n for n in before if before[n]!=after[n]},changed)
  self.assertIn('deadline=time.monotonic()+30',(HERE/'inventory.py').read_text());self.assertEqual(old_inv.collect.__code__.co_code,I.collect.__code__.co_code)
 def test_all_component_ASCII_Unicode_surrogate_path_and_package_parity(self):
  old_app,old_inv=self.baseline();values=[''.join(v)for n in range(6)for v in itertools.product('ab./\\',repeat=n)];rng=random.Random(1102026)
  for cp in [*range(256),0x2028,0x2029,0xd800,0xdfff,0x10ffff,*rng.sample(range(0x110000),512)]:values.extend((chr(cp),'usr/'+chr(cp)+'/file','a'*511+chr(cp)))
  for value in values:
   self.assertEqual(outcome(lambda:old_inv.relative(value)),outcome(lambda:I.relative(value)),repr(value));self.assertEqual(outcome(lambda:old_app.package(package(value),R)),outcome(lambda:A.package(package(value),R)),repr(value))
 def test_section_header_prefix_duplicate_control_and_invalid_UTF8_parity(self):
  _,old=self.baseline();raws=[b'',b'%FILES%\na\na\n\n',b'%DEPENDS%\na\na\n\n',b'%NAME%\na\na\n\n',b'%BAD%\na\n\n',b'%NAME%\na',b'\xff\n',b'%NAME%\n\xed\xa0\x80\n\n']
  for c in range(256):
   for prefix in('%NAME%\na','%FILES%\nusr/a','%DEPENDS%\na','%bad'):
    raws.append((prefix+chr(c)+'b\n\n').encode())
  def answer(m,raw):
   try:return 'PASS',m.sections(raw,m.FIELDS|{'FILES','BACKUP'})
   except (ValueError,UnicodeError)as e:return'REFUSE',type(e).__name__,str(e)
  for raw in raws:self.assertEqual(answer(old,raw),answer(I,raw),repr(raw))
 def test_complete_immutable_owners_map_ancestor_conflicts_and_shared_prefixes(self):
  old_app,old=self.baseline()
  for paths,okay in((['usr/a/b/c','usr/a/d/e'],True),(['usr/a/b/c','usr/a'],False),(['usr/a','usr/a/b/c'],False),(['usr/a/b/c','usr/a/d/e','usr/a/b'],False),(['usr/z','usr/a','usr/z/child'],False)):
   with self.subTest(paths=paths),tempfile.TemporaryDirectory()as td:
    db=Path(td)/'db';fixture(db,2,2);q=db/'local/fixture-000-1:2.3-4/files';q.write_text('%FILES%\n'+'\n'.join(paths)+'\n\n');other=db/'local/fixture-001-1:2.3-4/files';other.write_text('%FILES%\nusr/other/file\n\n')
    if okay:self.assertEqual(old.collect(db,C,lambda row:old_app.package(row,R)),I.collect(db,C,lambda row:A.package(row,R)))
    else:
     for module,app in((old,old_app),(I,A)):
      with self.assertRaisesRegex(ValueError,'ancestor ownership'):module.collect(db,C,lambda row:app.package(row,R))
 def test_real_descriptor_links_locks_record_root_and_between_scan_drift_refused(self):
  import shutil
  old_app,old=self.baseline()
  for module,app in((old,old_app),(I,A)):
   for kind in('symlink','hardlink','lock','record','between','root','deadline'):
    with self.subTest(kind=kind),tempfile.TemporaryDirectory()as td:
     root=Path(td);db=root/'db';fixture(db,2,2);path=db/'local/fixture-000-1:2.3-4/desc';raw=path.read_bytes();read=C.read_member;scan=module.scan;seen=[]
     if kind in('symlink','hardlink'):
      held=root/'held';held.write_bytes(raw);path.unlink()
      if kind=='symlink':path.symlink_to(held)
      else:os.link(held,path)
     elif kind=='lock':(db/'db.lck').symlink_to(root/'absent')
     def reader(*args,**kwargs):
      value=read(*args,**kwargs)
      if args[1]=='desc'and not seen:
       seen.append(1)
       if kind=='record':path.write_bytes(raw+b'\n')
       elif kind=='root':db.rename(root/'retained');shutil.copytree(root/'retained',db)
      return value
     def scanning(*args):
      if kind=='deadline':return scan(*args[:-1],0)
      value=scan(*args);seen.append(1)
      if len(seen)==1:path.write_bytes(raw+b'\n')
      return value
     fds=len(os.listdir('/proc/self/fd'))
     with patch.object(module,'scan',scanning)if kind in('between','deadline')else patch.object(C,'read_member',reader):
      with self.assertRaises((ValueError,OSError,C.Error)):module.collect(db,C,lambda row:app.package(row,R))
     self.assertEqual(len(os.listdir('/proc/self/fd')),fds)
 def test_full606_publish_validate_twofresh_read_counts_and_output_security_parity(self):
  old_app,old=self.baseline()
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);db=root/'db';fixture(db);out=root/'inventory.json';before=old.publish(db,out,C,lambda row:old_app.package(row,R));raw=out.read_bytes();out.unlink();calls=[];reads=[];scan=I.scan;read=C.read_member
   def observed(*args):calls.append(args[-1]);return scan(*args)
   def record(*args,**kwargs):reads.append(args[1]);return read(*args,**kwargs)
   with patch.object(I,'scan',observed),patch.object(C,'read_member',record):new=I.publish(db,out,C,lambda row:A.package(row,R))
   self.assertEqual(before,new);self.assertEqual(out.read_bytes(),raw);self.assertEqual(len(calls),2);self.assertEqual(calls[0],calls[1]);self.assertEqual(len(reads),3638);self.assertEqual(I.validate(json.loads(raw),lambda row:A.package(row,R)),I.QUALIFICATION);self.assertEqual(out.stat().st_mode&0o777,0o600)
   with self.assertRaisesRegex(ValueError,'fresh inventory'):I.publish(db,out,C,lambda row:A.package(row,R))
   self.assertEqual(out.read_bytes(),raw);insecure=root/'insecure';insecure.mkdir();insecure.chmod(0o777)
   with self.assertRaisesRegex(ValueError,'caller-owned'):I.publish(db,insecure/'never',C,lambda row:A.package(row,R))
   insecure.chmod(0o700)

class PackagedProvenanceControls(unittest.TestCase):
 def test_every_packaged_runtime_source_matches_actual_files_and_apps11_stale_table_refuses(self):
  checker=types.ModuleType('_apps12_packaged_source_checker');checker.__file__=str(HERE/'check_source.py')
  exec(compile((HERE/'check_source.py').read_bytes(),checker.__file__,'exec'),checker.__dict__)
  value=json.loads((HERE/'source-provenance.json').read_bytes());declared=checker.runtime_sources(HERE)
  self.assertEqual(set(declared),{'apps.py','inventory.py','helper-pins.json','cachy-asahi-apps'})
  self.assertEqual(declared,{n:dict(bytes=len((HERE/n).read_bytes()),sha256=digest((HERE/n).read_bytes()))for n in declared})
  self.assertEqual(value['version'],'0.1.0-12');self.assertEqual(value['apps12_parent']['source'],'31bc46cdd58840e5c4337d2270a307d23a171373')
  with tempfile.TemporaryDirectory(prefix='apps12-packaged-provenance-')as td:
   root=Path(td)
   for n in declared:(root/n).write_bytes((HERE/n).read_bytes())
   original=json.loads(json.dumps(value))
   for name in('apps.py','inventory.py'):
    bad=json.loads(json.dumps(value));bad['runtime_sources'][name]=original['apps12_parent']['runtime_sources'][name]
    self.assertNotEqual(bad['runtime_sources'][name],declared[name]);(root/'source-provenance.json').write_bytes(A.encoded(bad))
    with self.assertRaisesRegex(AssertionError,'packaged runtime source differs: '+name):checker.runtime_sources(root)
   (root/'source-provenance.json').write_bytes(A.encoded(value));self.assertEqual(checker.runtime_sources(root),declared)
   for name in declared:
    raw=(root/name).read_bytes();(root/name).write_bytes(raw+b'\n')
    with self.assertRaisesRegex(AssertionError,'packaged runtime source differs: '+name):checker.runtime_sources(root)
    (root/name).write_bytes(raw)


if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
