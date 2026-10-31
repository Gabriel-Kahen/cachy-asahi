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

# Whole Apps13 pure-processing delta, invertible to exact Apps12 runtime.
APPS13_EDITS={'apps': [['        for item in entries:\n', "        # The prior exact type/count/uniqueness gate already holds. A slash\n        # join concatenates the same component lists as split('/') per item.\n        # Every metadata length and every component predicate is checked in C;\n        # uncertain/invalid input retains the complete ordered loop below.\n        if key=='files' and entries and min(map(len,entries))>0 and max(map(len,entries))<=512:\n            joined='/'+ '/'.join(entries)+'/'\n            if '//'not in joined and'/./'not in joined and'/../'not in joined:\n                value[key]=sorted(entries)\n                continue\n        for item in entries:\n"]], 'inventory': [["_SECTION=re.compile(r'%[A-Z][A-Z0-9_]*%')", "_SECTION=re.compile(r'%[A-Z][A-Z0-9_]*%')"], ['    result={};current=None;seen={}\n', "    # A canonical file-list block is checked in full by the same C string/regex\n    # operations and complete uniqueness set, without a Python call per value.\n    # Uncertain headers, separators, duplicates or Unicode line breaks retain\n    # the complete original ordered parser below. This is never an I/O cache.\n    if (type(allowed)is set and allowed=={'FILES','BACKUP'} and\n            text.startswith('%FILES%\\n')and text.endswith('\\n\\n')and\n            '\\x85'not in text and'\\u2028'not in text and'\\u2029'not in text):\n        blocks=text.split('\\n\\n')\n        if len(blocks)in(2,3)and blocks[-1]=='':\n            bulk={}\n            for key,block in zip(('FILES','BACKUP'),blocks[:-1]):\n                header='%'+key+'%\\n'\n                if not block.startswith(header):break\n                values=block[len(header):]\n                if not values or values.startswith(('%','\\n'))or values.endswith('\\n')or'\\n%'in values:break\n                values=values.split('\\n')\n                if len(values)!=len(set(values)):break\n                bulk[key]=values\n            else:return bulk\n    result={};current=None;seen={}\n"]]}
APPS12_PINS={'apps': {'bytes': 22877, 'sha256': '7d671c4c354b985756b0d074504d4ebe3047c50dd7478ae20057153d0d0d154a'}, 'inventory': {'bytes': 20687, 'sha256': 'a6c98f987bf8fce66f961056320f80d17a51548391f2a4ca338f42f9fd51a893'}}

# Whole Apps14 per-call codec delta, exact Apps13 runtime inverse.
APPS14_EDITS=[('def collect(dbpath,c,normalize):', 'def _collect_encoded(dbpath,c,normalize):'), ("    need(len(encoded(result))<=MAX_INSTALLED_JSON,'inventory exceeds installed input byte bound')\n    return result\n\n\ndef validate", "    raw=encoded(result)\n    need(len(raw)<=MAX_INSTALLED_JSON,'inventory exceeds installed input byte bound')\n    return result,raw\n\n\ndef collect(dbpath,c,normalize):\n    return _collect_encoded(dbpath,c,normalize)[0]\n\n\ndef validate"), ('        value=collect(dbpath,c,normalize);raw=encoded(value)', '        value,raw=_collect_encoded(dbpath,c,normalize)'), ('# Every original Apps9 function above this marker remains byte-identical.', '# The full Apps13 inverse retains every original observation/publication check.'), ('def _collect_diagnostic(dbpath,c,normalize,stage):', 'def _collect_diagnostic_encoded(dbpath,c,normalize,stage):'), ("    need(len(encoded(result))<=MAX_INSTALLED_JSON,'inventory exceeds installed input byte bound')\n    return result\n\ndef _publish_diagnostic", "    raw=encoded(result)\n    need(len(raw)<=MAX_INSTALLED_JSON,'inventory exceeds installed input byte bound')\n    return result,raw\n\ndef _collect_diagnostic(dbpath,c,normalize,stage):\n    return _collect_diagnostic_encoded(dbpath,c,normalize,stage)[0]\n\ndef _publish_diagnostic"), ("        value=_collect_diagnostic(dbpath,c,normalize,stage);stage('ENCODE_PUBLICATION');raw=encoded(value)", "        value,raw=_collect_diagnostic_encoded(dbpath,c,normalize,stage);stage('ENCODE_PUBLICATION')")]
APPS13_PINS={'apps': {'bytes': 23473, 'sha256': '912d87a9871f20545fb8470f84a799918168830b320afe3648c8781de29abcaa'}, 'inventory': {'bytes': 21784, 'sha256': '9b3069ce885453d2a94c61fa1c6a5f4d0353f3cdc3375e88e9ae1ba162a46a02'}}

# Whole Apps15 record-local path batch delta; exact Apps14 runtime inverse.
APPS15_EDITS=[("                    files=[]\n                    for value in paths:\n                        item,is_directory=relative(value)\n                        if not is_directory:\n                            need(item not in owners,'duplicate regular file ownership');owners[item]=name;files.append(item)\n", '                    files=_owned_paths(paths,owners,name)\n'), ('def scan(', "def _owned_paths(paths,owners,name):\n    # Batch only string predicates within this freshly read record. Invalid or\n    # uncertain inputs retain the original ordered path validator below.\n    if (paths and all(type(value)is str for value in paths) and\n            min(map(len,paths))>0 and max(map(len,paths))<=512 and\n            _PATH_CONTROL.search('/'.join(paths))is None):\n        names=[value[:-1]if value.endswith('/')else value for value in paths]\n        joined='/'+ '/'.join(names)+'/'\n        if '//'not in joined and'/./'not in joined and'/../'not in joined:\n            files=[value for value in paths if not value.endswith('/')]\n            if len(files)==len(set(files)) and owners.keys().isdisjoint(files):\n                owners.update(dict.fromkeys(files,name))\n                return files\n    files=[]\n    for value in paths:\n        item,is_directory=relative(value)\n        if not is_directory:\n            need(item not in owners,'duplicate regular file ownership');owners[item]=name;files.append(item)\n    return files\n\n\ndef scan(")]
APPS14_PINS={'apps': {'bytes': 23473, 'sha256': '912d87a9871f20545fb8470f84a799918168830b320afe3648c8781de29abcaa'}, 'inventory': {'bytes': 22032, 'sha256': 'f5de0fc3d5067cb97986152385c37c2ec9c51237c5b37bc566b766d906405080'}}

# Whole Apps16 ancestor traversal inverse to exact Apps15.
APPS16_EDITS=[("        for path,name in sorted(owners.items()):\n            for parent in Path(path).parents:\n                if parent.as_posix() in owners:\n                    result.append(dict(kind='file-directory-conflict',path=path,package=name,other=owners[parent.as_posix()]))\n            need(len(result)<=1024,'too many inconsistent inventory records')", "        # indexed() proves canonical relative strings; retain the original Path\n        # traversal for uncertain direct callers, including its issue order.\n        for path,name in sorted(owners.items()):\n            if (type(path)is str and path and not path.startswith('/')and not path.endswith('/')and\n                    path not in ('.','..')and'//'not in path and'/./'not in path and'/../'not in path and\n                    not path.startswith(('./','../'))and not path.endswith(('/.','/..'))):\n                parent=path.rpartition('/')[0]\n                while parent:\n                    if parent in owners:\n                        result.append(dict(kind='file-directory-conflict',path=path,package=name,other=owners[parent]))\n                    parent=parent.rpartition('/')[0]\n            else:\n                for parent in Path(path).parents:\n                    if parent.as_posix() in owners:\n                        result.append(dict(kind='file-directory-conflict',path=path,package=name,other=owners[parent.as_posix()]))\n            need(len(result)<=1024,'too many inconsistent inventory records')")]
APPS15_PINS={'apps': {'bytes': 23473, 'sha256': '912d87a9871f20545fb8470f84a799918168830b320afe3648c8781de29abcaa'}, 'inventory': {'bytes': 22839, 'sha256': '033bbdb368d6bf7fcbd0d469274247f15d577a3f18b86f6baced69c07d5938da'}}
def before16(raw,kind):
 text=raw.decode()
 if kind=='apps':
  for before,after in reversed(APPS16_EDITS):
   assert text.count(after)==1;text=text.replace(after,before,1)
 result=text.encode();assert dict(bytes=len(result),sha256=hashlib.sha256(result).hexdigest())==APPS15_PINS[kind],'whole exact Apps15 ancestor inverse';return result

def before15(raw,kind):
 text=raw.decode()
 if kind=='inventory':
  for old,new in reversed(APPS15_EDITS):
   assert text.count(new)==1;text=text.replace(new,old,1)
 result=text.encode();assert dict(bytes=len(result),sha256=hashlib.sha256(result).hexdigest())==APPS14_PINS[kind],'whole exact Apps14 predecessor inverse';return result

def before14(raw,kind):
 raw=before15(raw,kind)
 text=raw.decode()
 if kind=='inventory':
  for old,new in reversed(APPS14_EDITS):
   assert text.count(new)==1;text=text.replace(new,old,1)
 result=text.encode();assert dict(bytes=len(result),sha256=hashlib.sha256(result).hexdigest())==APPS13_PINS[kind],'whole exact Apps13 predecessor inverse';return result

def before13(raw,kind):
 raw=before14(raw,kind)
 text=raw.decode()
 for old,new in reversed(APPS13_EDITS[kind]):
  assert text.count(new)==1;text=text.replace(new,old,1)
 result=text.encode();assert dict(bytes=len(result),sha256=hashlib.sha256(result).hexdigest())==APPS12_PINS[kind],'whole exact Apps12 processing predecessor inverse';return result

def before11(raw,kind):
 raw=before13(raw,kind)
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

A=load(before16((HERE/'apps.py').read_bytes(),'apps'),'new_apps');I=load((HERE/'inventory.py').read_bytes(),'new_inventory');OLD_A=load(invert(parent9(before16((HERE/'apps.py').read_bytes(),'apps'),'apps'),[APP_EDIT],'c12f8548d5fd3007a61fb366ca279dd061917cc5320ba81ce5e2ab0d02c7d9a6'),'old_apps');OLD_I=load(invert(parent9((HERE/'inventory.py').read_bytes(),'inventory'),INVENTORY_EDITS,'68f9b0bc6bd5c494ebfc10bdc1e243c014d7fa8e56b1386491b75cdb9ee2e3df'),'old_inventory');C,R,_=A.helpers(options.repository_source)
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
  self.assertEqual(a['scan'],b['scan']);self.assertEqual(a['collect'],b['collect']);self.assertEqual(a['publish'],b['publish']);self.assertEqual(a['validate'],b['validate']);self.assertEqual((I.MAX_BYTES,I.MAX_RECORD,I.MAX_PACKAGES,I.MAX_INSTALLED_JSON),(64*1024**2,4*1024**2,4096,16*1024**2));self.assertEqual(digest(parent9(before16((HERE/'apps.py').read_bytes(),'apps'),'apps')),'8b575e25226463834a45b3f679ee4ddf5ef124976b008494a4944c0252cdf1f5')
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
 def baseline(self):return load(before11(before16((HERE/'apps.py').read_bytes(),'apps'),'apps'),'baseline10_apps'),load(before11((HERE/'inventory.py').read_bytes(),'inventory'),'baseline10_inventory')
 def test_complete_inverse_and_all_descriptor_crypto_deadline_publication_bodies_held(self):
  import ast
  old_app,old_inv=self.baseline();functions=lambda text:{n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  for name,changed in(('apps.py',{'package'}),('inventory.py',{'sections','relative','scan'})):
   kind='apps'if name=='apps.py'else'inventory';before=functions(before11(before16((HERE/name).read_bytes(),kind),kind).decode());after=functions(before14(before16((HERE/name).read_bytes(),kind),kind).decode());self.assertEqual(before.keys(),after.keys());self.assertEqual({n for n in before if before[n]!=after[n]},changed)
  self.assertIn('deadline=time.monotonic()+30',(HERE/'inventory.py').read_text());self.assertEqual(old_inv.collect.__code__.co_code,load(before14((HERE/'inventory.py').read_bytes(),'inventory'),'held13_collect').collect.__code__.co_code)
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
  self.assertEqual(value['version'],'0.1.0-16');self.assertEqual(value['apps12_parent']['source'],'31bc46cdd58840e5c4337d2270a307d23a171373')
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



TWELVE_A=load(before13(before16((HERE/'apps.py').read_bytes(),'apps'),'apps'),'twelve_apps')
TWELVE_I=load(before13((HERE/'inventory.py').read_bytes(),'inventory'),'twelve_inventory')
def bulk_outcome(raw,allowed):
 def call(module):
  try:return('PASS',module.sections(raw,allowed))
  except(ValueError,TypeError,AttributeError)as e:return('REFUSE',type(e).__name__,str(e))
 return call(TWELVE_I),call(I)

def bulk_small_fixture(db):
 local=db/'local';local.mkdir(parents=True);(local/'ALPM_DB_VERSION').write_bytes(b'9\n')
 for name in('alpha','beta'):
  p=local/(name+'-1-1');p.mkdir();(p/'desc').write_text('%NAME%\n'+name+'\n\n%VERSION%\n1-1\n\n%ARCH%\naarch64\n\n')
  (p/'files').write_text('%FILES%\nusr/share/'+name+'/a\nusr/share/'+name+'/b\n\n');(p/'mtree').write_bytes(b'opaque complete raw record\n')

class BulkMetadataControls(unittest.TestCase):
 def test_every_ascii_unicode_invalid_utf8_header_separator_duplicate_and_ordered_refusal_parity(self):
  cases=[b'',b'\n',b'%FILES%\n\n',b'%FILES%\na\n\n',b'%FILES%\na\n\n%BACKUP%\na\t' + b'0'*32 + b'\n\n']
  for char in list(map(chr,range(256)))+['\u2028','\u2029','\ud800','\udfff','\U0010ffff','東京','Cafe\u0301']:
   cases.append(('%FILES%\na'+char+'b\n\n').encode('utf8','surrogatepass'))
  cases +=[b'\xff',b'\xc0\x80',b'\xed\xa0\x80',b'%FILES%\na\na\n%BACKUP%\nb\n',b'%FILES%\na\na\n\n%UNKNOWN%\nb\n\n']
  for header,value,separator in itertools.product(('%FILES%','%BACKUP%','%UNKNOWN%','%%','%FILES%x'),('a','a\nb','a\na','%BACKUP%','', 'a\u0085b'),('\n','\n\n','\n\n\n','')):
   cases.append((header+'\n'+value+separator).encode())
  rng=random.Random(13012);parts=['%FILES%','%BACKUP%','%DEPENDS%','%BAD%','a','b','a/b','\n','\t','\x85','\u2028','\u2029','']
  cases +=['\n'.join(rng.choice(parts)for _ in range(rng.randrange(1,15))).encode()for _ in range(5000)]
  for allowed in({'FILES','BACKUP'},TWELVE_I.FIELDS,{'FILES'},'FILES',{'FILES':True,'BACKUP':True}):
   for raw in cases:self.assertEqual(*bulk_outcome(raw,allowed),(repr(raw[:150]),allowed))
  # Verify the real canonical fast branch avoids the original per-value loop.
  raw=b'%FILES%\na\nb\n\n%BACKUP%\na\t'+b'0'*32+b'\n\n'
  with patch.object(I,'_SECTION',types.SimpleNamespace(fullmatch=lambda _:(_ for _ in()).throw(AssertionError('old loop invoked')))):
   self.assertEqual(I.sections(raw,{'FILES','BACKUP'}),TWELVE_I.sections(raw,{'FILES','BACKUP'}))
  # Bulk package validation must equal the original ordered predicate, even
  # for controls/Unicode that inventory.relative later refuses independently.
  def normalize(app,files):
   try:return('PASS',app.package(dict(name='fixture',version='1-1',arch='any',files=files,depend=[],provides=[],conflict=[],replaces=[]),R))
   except ValueError as e:return('REFUSE',type(e).__name__,str(e),e.issues)
  paths=[''.join(parts)for n in range(7)for parts in itertools.product('a./\\',repeat=n)]
  paths +=[chr(n)for n in range(256)]+['\u2028','\u2029','\ud800','\udfff','\U0010ffff','東京','a'*512,'a'*513,None,False,17]
  for path in paths:
   for files in([path],['usr/before',path,'usr/after']):self.assertEqual(normalize(TWELVE_A,files),normalize(A,files),repr(files))
  for files in([],['a','a'],['a','a/b'],['a/', 'b'],['a', '/b'],['a','.', 'b'],['a','..','b'],['a','', 'b'],['a/..','b'],['a','../b'],['a'*513,'../b'],['../b','a'*513]):self.assertEqual(normalize(TWELVE_A,files),normalize(A,files))
 def test_whole_source_inverse_only_pure_processing_changed_all_security_scans_deadline_publication_held(self):
  old=before13((HERE/'inventory.py').read_bytes(),'inventory').decode();new=before14((HERE/'inventory.py').read_bytes(),'inventory').decode();proof=dict(edits=APPS13_EDITS['inventory'],app_edits=APPS13_EDITS['apps'])
  inverse=new
  for before,after in reversed(proof['edits']):self.assertEqual(inverse.count(after),1);inverse=inverse.replace(after,before,1)
  self.assertEqual(inverse,old)
  functions=lambda text:{n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
  a,b=functions(old),functions(new);self.assertEqual(a.keys(),b.keys());self.assertEqual({n for n in a if a[n]!=b[n]},{'sections'})
  old_app=before13(before16((HERE/'apps.py').read_bytes(),'apps'),'apps').decode();new_app=before16((HERE/'apps.py').read_bytes(),'apps').decode();back=new_app
  for before,after in reversed(proof['app_edits']):self.assertEqual(back.count(after),1);back=back.replace(after,before,1)
  self.assertEqual(back,old_app);x,y=functions(old_app),functions(new_app);self.assertEqual(x.keys(),y.keys());self.assertEqual({n for n in x if x[n]!=y[n]},{'package'});self.assertIn('deadline=time.monotonic()+30',b['collect'])
 def test_real_two_scan_complete_bytes_and_descriptor_lock_mutation_deadline_refusals(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);db=root/'db';bulk_small_fixture(db);out=root/'inventory.json'
   before=TWELVE_I.publish(db,out,C,lambda row:TWELVE_A.package(row,R));raw=out.read_bytes();out.unlink();reads=[];scans=[];read=C.read_member;scan=I.scan
   def record(*args,**kwargs):reads.append(args[1]);return read(*args,**kwargs)
   def observe(*args):scans.append(args[-1]);return scan(*args)
   with patch.object(C,'read_member',record),patch.object(I,'scan',observe):after=I.publish(db,out,C,lambda row:A.package(row,R))
   self.assertEqual(before,after);self.assertEqual(out.read_bytes(),raw);self.assertEqual(len(reads),14);self.assertEqual(len(scans),2);self.assertEqual(scans[0],scans[1]);I.validate(json.loads(raw),lambda row:A.package(row,R));out.unlink()
   for module in(TWELVE_I,I):
    seen=[];original=module.scan
    def drift(*args):
     result=original(*args);seen.append(1)
     if len(seen)==1:(db/'local/alpha-1-1/mtree').write_bytes(os.urandom(32))
     return result
    with patch.object(module,'scan',drift),self.assertRaisesRegex(ValueError,'two complete'):module.collect(db,C,lambda row:A.package(row,R))
    with self.assertRaisesRegex(ValueError,'deadline'):module.scan(db,C,lambda row:A.package(row,R),0)
   (db/'db.lck').touch()
   for module in(TWELVE_I,I):
    with self.assertRaisesRegex(ValueError,'db.lck'):module.collect(db,C,lambda row:A.package(row,R))
   (db/'db.lck').unlink();p=db/'local/alpha-1-1/files';p.unlink();p.symlink_to(db/'local/beta-1-1/files')
   for module in(TWELVE_I,I):
    with self.assertRaises((ValueError,OSError,C.Error)):module.collect(db,C,lambda row:A.package(row,R))

# The entire old suites above remain active. These cases exercise the new
# per-call codec route and original publication/scan failures directly.
class SingleEncoding(unittest.TestCase):
 def old(self):return load(before14((HERE/'inventory.py').read_bytes(),'inventory'),'codec_parent_inventory')
 def calls(self,db,out,diagnostic=False):
  encoded=I.encoded;scan=I.scan;complete=[];scans=[]
  def encode(value):
   if type(value)is dict and value.get('kind')=='complete-installed-inventory':complete.append(value)
   return encoded(value)
  def observe(*args):scans.append(args[-1]);return scan(*args)
  with patch.object(I,'encoded',side_effect=encode),patch.object(I,'scan',side_effect=observe):value=(I.publish_diagnostic if diagnostic else I.publish)(db,out,C,lambda row:A.package(row,R))
  self.assertEqual(len(complete),1);self.assertEqual(len(scans),2);self.assertEqual(scans[0],scans[1]);self.assertEqual(I.encoded(complete[0]),out.read_bytes());return value
 def test_exact_whole13_inverse_and_unchanged_scan_validate_write_bodies(self):
  now=before15((HERE/'inventory.py').read_bytes(),'inventory');before=before14((HERE/'inventory.py').read_bytes(),'inventory');self.assertEqual(digest(before),APPS13_PINS['inventory']['sha256'])
  funcs=lambda raw:{n.name:ast.get_source_segment(raw.decode(),n)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
  old,current=funcs(before),funcs(now)
  self.assertEqual(set(current)-set(old),{'_collect_encoded','_collect_diagnostic_encoded'})
  self.assertEqual({n for n in old if old[n]!=current[n]},{'collect','publish','_collect_diagnostic','_publish_diagnostic'})
  self.assertEqual(current['encoded'],old['encoded']);self.assertEqual(current['scan'],old['scan']);self.assertEqual(current['validate'],old['validate'])
 def test_normal_and_diagnostic_publish_encode_full_result_once(self):
  with tempfile.TemporaryDirectory()as td:
   db=Path(td)/'db';fixture(db,4,32);out=Path(td)/'out.json';prior=self.old();reference=prior.publish(db,out,C,lambda row:A.package(row,R));raw=out.read_bytes();out.unlink()
   self.assertEqual(self.calls(db,out),reference);self.assertEqual(out.read_bytes(),raw);out.unlink()
   self.assertEqual(self.calls(db,out,True),reference);self.assertEqual(out.read_bytes(),raw)
   stage=json.loads(out.with_name(out.name+'.stage.json').read_bytes());self.assertEqual((stage['status'],stage['phase'],stage['sequence']),('DONE','DONE',14))
 def test_public_collect_apis_still_dict_and_fresh_raw_is_per_call(self):
  with tempfile.TemporaryDirectory()as td:
   db=Path(td)/'db';fixture(db,2,2);normalize=lambda row:A.package(row,R)
   ordinary=I.collect(db,C,normalize);self.assertIs(type(ordinary),dict)
   phases=[];diagnostic=I._collect_diagnostic(db,C,normalize,phases.append);self.assertIs(type(diagnostic),dict);self.assertEqual(diagnostic,ordinary)
   value,raw=I._collect_encoded(db,C,normalize);self.assertIs(type(raw),bytes);self.assertEqual(I.encoded(value),raw)
   value['packages'].clear();again,raw2=I._collect_encoded(db,C,normalize);self.assertEqual(again,ordinary);self.assertEqual(raw2,raw)
   v,raw3=I._collect_diagnostic_encoded(db,C,normalize,lambda phase:None);self.assertEqual(v,ordinary);self.assertEqual(raw3,raw)
 def test_no_stale_result_or_bytes_across_changed_database_calls(self):
  with tempfile.TemporaryDirectory()as td:
   db=Path(td)/'db';fixture(db,2,2);out=Path(td)/'out.json';self.calls(db,out);first=out.read_bytes();out.unlink()
   files=next((db/'local').glob('fixture-*/files'));files.write_bytes(files.read_bytes().replace(b'/f000',b'/fresh'))
   self.calls(db,out,True);second=out.read_bytes();self.assertNotEqual(first,second);out.unlink()
   old=self.old();old.publish(db,out,C,lambda row:A.package(row,R));self.assertEqual(out.read_bytes(),second)
 def test_bound_and_encoding_failure_before_output_preserve_stage(self):
  for error in('bound','codec'):
   for diagnostic in(False,True):
    with self.subTest(error=error,diagnostic=diagnostic),tempfile.TemporaryDirectory()as td:
     db=Path(td)/'db';fixture(db,2,2);out=Path(td)/'out.json';encode=I.encoded
     def fail(value):
      if type(value)is dict and value.get('kind')=='complete-installed-inventory':raise ValueError('CONTROL_ONLY_CODEC')
      return encode(value)
     context=patch.object(I,'MAX_INSTALLED_JSON',1)if error=='bound'else patch.object(I,'encoded',side_effect=fail)
     with context,self.assertRaises(ValueError):(I.publish_diagnostic if diagnostic else I.publish)(db,out,C,lambda row:A.package(row,R))
     self.assertFalse(out.exists())
     if diagnostic:
      stage=json.loads(out.with_name(out.name+'.stage.json').read_bytes());self.assertEqual((stage['status'],stage['phase']),('FAILED','ENCODE_RESULT_BOUND'))
 def test_reused_raw_preserves_original_write_fsync_retirement(self):
  for diagnostic in(False,True):
   with self.subTest(diagnostic=diagnostic),tempfile.TemporaryDirectory()as td:
    db=Path(td)/'db';fixture(db,2,2);out=Path(td)/'out.json';fds=set(os.listdir('/proc/self/fd'));error=OSError('CONTROL_ONLY_FSYNC')
    with patch.object(I.os,'fsync',side_effect=error),self.assertRaises(OSError)as caught:(I.publish_diagnostic if diagnostic else I.publish)(db,out,C,lambda row:A.package(row,R))
    self.assertIs(caught.exception,error);self.assertFalse(out.exists());self.assertEqual(set(os.listdir('/proc/self/fd')),fds)
    if diagnostic:self.assertEqual(json.loads(out.with_name(out.name+'.stage.json').read_bytes())['phase'],'FSYNC_OUTPUT')

# All older suites stay active on their exact projected predecessor context;
# these eight tests exercise live15 and its whole14 inverse directly.
class RecordBulk(unittest.TestCase):
 def old(self):return load(before15((HERE/'inventory.py').read_bytes(),'inventory'),'exact14_inventory')
 def serial(self,paths,owners,name):
  old=self.old();files=[]
  for value in paths:
   item,directory=old.relative(value)
   if not directory:old.need(item not in owners,'duplicate regular file ownership');owners[item]=name;files.append(item)
  return files
 def outcome(self,fn,paths,owners):
  current=dict(owners)
  try:result=('PASS',fn(paths,current,'selected'))
  except Exception as e:result=(type(e).__name__,str(e))
  return result,current
 def test_exact_whole14_inverse_every_other_function_and_scan_observation_held(self):
  raw=(HERE/'inventory.py').read_bytes();prior=before15(raw,'inventory');self.assertEqual(digest(prior),APPS14_PINS['inventory']['sha256'])
  functions=lambda b:{n.name:ast.get_source_segment(b.decode(),n)for n in ast.parse(b).body if isinstance(n,ast.FunctionDef)}
  old,new=functions(prior),functions(raw);self.assertEqual(set(new)-set(old),{'_owned_paths'});self.assertEqual({n for n in old if old[n]!=new[n]},{'scan'})
  self.assertEqual(I.PHASES,self.old().PHASES)
  for n in('_collect_encoded','collect','_collect_diagnostic_encoded','_collect_diagnostic','publish','_publish_diagnostic','validate','relative','encoded'):
   self.assertEqual(old[n],new[n],n)
 def test_5000_ordered_result_error_and_partial_owner_state_parity(self):
  class String(str):pass
  values=['a','a/','a/b','x/y/z','a//b','/a','a/./b','a/../b','a\n','a\0','x'*513,'','/','.','..','./','../','a\x85b','a\u2028b','å/字','a\\b','a/%f','a\ud800b',None,1,String('a')];rng=random.Random(150022);old=self.old()
  def serial(paths,owners,name):
   files=[]
   for value in paths:
    item,directory=old.relative(value)
    if not directory:old.need(item not in owners,'duplicate regular file ownership');owners[item]=name;files.append(item)
   return files
  for _ in range(5000):
   paths=[rng.choice(values)for _ in range(rng.randrange(10))];owners={n:'prior'for n in rng.sample(['a','a/b','x/y/z'],rng.randrange(4))};snapshot=list(paths)
   self.assertEqual(self.outcome(serial,paths,owners),self.outcome(I._owned_paths,paths,owners));self.assertEqual(paths,snapshot)
 def test_canonical_batch_preserves_order_and_owner_map_without_perpath_relative(self):
  paths=['usr/','usr/å/字','a\\literal','name with space','%literal','a/b/'];owners={'prior':'held'};expected=self.outcome(self.serial,paths,owners)
  with patch.object(I,'relative',side_effect=AssertionError('valid batch must not call perpath validator')):actual=self.outcome(I._owned_paths,paths,owners)
  self.assertEqual(actual,expected)
 def test_invalid_duplicate_and_foreign_ownership_keep_exact_ordered_fallback(self):
  for paths,owners in [(['first','first'],{}),(['first','prior'],{'prior':'old'}),(['first','bad//path','later'],{}),(['dir/','bad/../path'],{}),(['first','\0'],{})]:
   seen=[];original=I.relative
   def track(value):seen.append(value);return original(value)
   with patch.object(I,'relative',side_effect=track):got=self.outcome(I._owned_paths,paths,owners)
   self.assertEqual(got,self.outcome(self.serial,paths,owners));self.assertEqual(seen,paths[:len(seen)]);self.assertTrue(seen)
 def test_record_local_ownership_never_reuses_prior_call_state(self):
  paths=['a','b'];first={};self.assertEqual(I._owned_paths(paths,first,'one'),paths);second={};self.assertEqual(I._owned_paths(paths,second,'two'),paths);self.assertEqual(first,{'a':'one','b':'one'});self.assertEqual(second,{'a':'two','b':'two'})
  with self.assertRaisesRegex(ValueError,'duplicate regular'):I._owned_paths(paths,first,'three')
 def test_actual_twofresh_scans_all_raw_reads_and_same_complete_publication(self):
  with tempfile.TemporaryDirectory()as td:
   db=Path(td)/'db';fixture(db,4,32);out=Path(td)/'inventory.json';old=self.old();old.publish(db,out,C,lambda row:A.package(row,R));expected=out.read_bytes();out.unlink();scans=[];reads=[];scan=I.scan;read=C.read_member
   def track(*a):scans.append(a[-1]);return scan(*a)
   def member(*a,**kw):reads.append(a[1]);return read(*a,**kw)
   with patch.object(I,'scan',side_effect=track),patch.object(C,'read_member',side_effect=member):I.publish_diagnostic(db,out,C,lambda row:A.package(row,R))
   self.assertEqual(out.read_bytes(),expected);self.assertEqual(len(scans),2);self.assertEqual(scans[0],scans[1]);value=json.loads(expected);self.assertEqual(len(reads),2*len(value['observation']['inputs']));self.assertEqual(I.validate(value,lambda row:A.package(row,R)),I.QUALIFICATION);self.assertEqual(json.loads(out.with_name(out.name+'.stage.json').read_bytes())['phase'],'DONE')
 def test_physical_between_scan_mutation_and_real_lock_still_refuse(self):
  with tempfile.TemporaryDirectory()as td:
   db=Path(td)/'db';fixture(db,2,2);scan=I.scan;calls=[]
   def changed(*a):
    value=scan(*a);calls.append(1)
    if len(calls)==1:
     files=next((db/'local').glob('fixture-*/files'));files.write_bytes(files.read_bytes().replace(b'/f000',b'/fresh'))
    return value
   with patch.object(I,'scan',side_effect=changed),self.assertRaisesRegex(ValueError,'between two complete'):I.collect(db,C,lambda row:A.package(row,R))
   self.assertEqual(len(calls),2);(db/'db.lck').touch()
   with self.assertRaisesRegex(ValueError,'db.lck'):I.collect(db,C,lambda row:A.package(row,R))
 def test_expired_observation_and_output_bound_fail_without_weakening_clocks(self):
  with tempfile.TemporaryDirectory()as td:
   db=Path(td)/'db';fixture(db,2,2)
   with self.assertRaisesRegex(ValueError,'observation deadline'):I.scan(db,C,lambda row:A.package(row,R),time.monotonic()-1)
   out=Path(td)/'never.json'
   with patch.object(I,'MAX_INSTALLED_JSON',1),self.assertRaisesRegex(ValueError,'input byte bound'):I.publish(db,out,C,lambda row:A.package(row,R))
   self.assertFalse(out.exists())

if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
