# SPDX-License-Identifier: MIT
"""Optional stage DATA, full default equivalence and interruption/refusal controls."""
import argparse,ast,hashlib,importlib.util,json,os,shutil,stat,subprocess,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--repository-source',type=Path,required=True);options,rest=p.parse_known_args();SOURCE=options.repository_source.absolute()
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
A=load('_stage_apps10',HERE/'apps.py');I=load('_stage_inventory10',HERE/'inventory.py');C,R,_=A.helpers(SOURCE)
INV={'actual': None, 'app_edits': [["    if args.command=='inventory':return inventory_reader().publish(args.dbpath,args.output,c,lambda row:package(row,r))", "    if args.command=='inventory':\n        reader=inventory_reader();publish=reader.publish_diagnostic if getattr(args,'diagnostic_stage',False) else reader.publish\n        return publish(args.dbpath,args.output,c,lambda row:package(row,r))"], ["    inventory.add_argument('--dbpath',type=Path,required=True);inventory.add_argument('--output',type=Path,required=True)", "    inventory.add_argument('--dbpath',type=Path,required=True);inventory.add_argument('--output',type=Path,required=True)\n    inventory.add_argument('--diagnostic-stage',action='store_true',help='explicit fresh0600 sibling stage JSON with finite phases/timing only; never acceptance')"]], 'collect_edits': [['def collect(dbpath,c,normalize):', 'def _collect_diagnostic(dbpath,c,normalize,stage):'], ['    first=scan(dbpath,c,normalize,deadline);second=scan(dbpath,c,normalize,deadline)', "    stage('SCAN_FIRST');first=scan(dbpath,c,normalize,deadline)\n    stage('SCAN_SECOND');second=scan(dbpath,c,normalize,deadline)\n    stage('COMPARE_READS')"], ['    rows,inputs,_=second;raw_sha=digest(encoded(inputs))', "    rows,inputs,_=second;stage('ENCODE_INPUTS');raw_sha=digest(encoded(inputs))\n    stage('ENCODE_ROWS')"], ['    need(len(encoded(result))<=MAX_INSTALLED_JSON', "    stage('ENCODE_RESULT_BOUND')\n    need(len(encoded(result))<=MAX_INSTALLED_JSON"]], 'parent_apps': {'bytes': 22543, 'sha256': '8b575e25226463834a45b3f679ee4ddf5ef124976b008494a4944c0252cdf1f5'}, 'parent_functions': {'collect': {'bytes': 931, 'sha256': '6bb2c677c51df2330fd2578268aec8dc2b118aadd07eb2d616ee9195d1918a25'}, 'digest': {'bytes': 54, 'sha256': '9fb90e75a3fa51c6705ac79119ed84196af7ea53a216e638aad327d6af01244a'}, 'encoded': {'bytes': 101, 'sha256': 'a69d679eaeddc0770ab81fa57e83ed717ff6c4688b6c508780bb21c833e74a07'}, 'identity': {'bytes': 129, 'sha256': '77d35faa23f8d785b233735dcd485f0f7fc4eae9557bd2d69ed047ed339a9e53'}, 'need': {'bytes': 61, 'sha256': 'ef0f37716b901d5aa8237c6375c20d869794f31dee8387fa2cd0cb5f62108294'}, 'publish': {'bytes': 2140, 'sha256': '3bf80623647b8a889584f2d1546f275f2c5656a35184904c7edc4d3939ad6344'}, 'relative': {'bytes': 368, 'sha256': 'c3eb05c02eb907874024a5de57110f845c4be9a2cb1ead7b0d797cdb7605c503'}, 'scan': {'bytes': 5430, 'sha256': '2b24cef5d55996cbae64faab671ae45dae462ab3356c53483f8bdb0baf4b87a5'}, 'sections': {'bytes': 999, 'sha256': 'b15f7dd78b3b81a1ee282c3d226a4c865b0ff28839a8b7c11c4d00c3e75d8561'}, 'validate': {'bytes': 2350, 'sha256': '91fd48d2b7212efe070bf2b253e7af261f96e6f56e8ca2a28997b3c1a62ad642'}}, 'parent_inventory': {'bytes': 13270, 'sha256': '8bb0e7374882d4b74f50cadf5a1d3d1524627e10714b53848b8b27eb6da30837'}, 'publish_edits': [['def publish(dbpath,output,c,normalize):', 'def _publish_diagnostic(dbpath,output,c,normalize,stage):'], ['        value=collect(dbpath,c,normalize);raw=encoded(value)', "        value=_collect_diagnostic(dbpath,c,normalize,stage);stage('ENCODE_PUBLICATION');raw=encoded(value)\n        stage('REOPEN_OUTPUT_PARENT')"], ['        fd=os.open(output.name,', "        stage('OPEN_OUTPUT')\n        fd=os.open(output.name,"], ["                with os.fdopen(os.dup(fd),'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())", "                with os.fdopen(os.dup(fd),'wb') as stream:\n                    stage('WRITE_OUTPUT');stream.write(raw);stream.flush()\n                    stage('FSYNC_OUTPUT');os.fsync(stream.fileno())\n                stage('VERIFY_OUTPUT')"], ['                os.fsync(parent)', "                stage('FSYNC_PARENT');os.fsync(parent)"]]}

# Full finite Apps11 CPU delta; before helpers remain exact qualified Apps10.
APPS11_EDITS={'apps': [('def package(row,r):', '\ndef package(row,r):'), ("            if key=='files':need(all(part not in ('','.','..') for part in item.split('/')),'unsafe payload path')", "            if key=='files':\n                parts=item.split('/')\n                need(''not in parts and'.'not in parts and'..'not in parts,'unsafe payload path')")], 'inventory': [('MAX_INSTALLED_JSON=16*1024**2', "MAX_INSTALLED_JSON=16*1024**2\n_RECORD_CONTROL=re.compile(r'[\\x00-\\x08\\x0b-\\x1f\\x7f]')\n_PATH_CONTROL=re.compile(r'[\\x00-\\x1f\\x7f]')\n_SECTION=re.compile(r'%[A-Z][A-Z0-9_]*%')"), ("re.search(r'[\\x00-\\x08\\x0b-\\x1f\\x7f]',text)is None", '_RECORD_CONTROL.search(text)is None'), ("elif re.fullmatch('%[A-Z][A-Z0-9_]*%',line):", "elif line.startswith('%')and _SECTION.fullmatch(line):"), ("re.search(r'[\\x00-\\x1f\\x7f]',value)is None", '_PATH_CONTROL.search(value)is None'), ("    need(all(part not in ('','.','..') for part in name.split('/')),'noncanonical ALPM ownership path')", "    parts=name.split('/')\n    need(''not in parts and'.'not in parts and'..'not in parts,'noncanonical ALPM ownership path')"), ("            for path in owners:\n                parent=path.rpartition('/')[0]\n                while parent:\n                    need(parent not in owners,'regular file/ancestor ownership conflict')\n                    parent=parent.rpartition('/')[0]\n                need('.' not in owners,'regular file/ancestor ownership conflict')", "            # owners is complete and immutable here; memoize only already\n            # checked prefixes in THIS scan, never observations across scans.\n            checked_ancestors=set()\n            for path in owners:\n                parent=path.rpartition('/')[0]\n                while parent and parent not in checked_ancestors:\n                    need(parent not in owners,'regular file/ancestor ownership conflict')\n                    checked_ancestors.add(parent);parent=parent.rpartition('/')[0]\n            need('.' not in owners,'regular file/ancestor ownership conflict')")]}
APPS10_PINS={'apps': {'bytes': 22826, 'sha256': 'de9118c7ea98d0ea0263a0615b1ad1e4ed3402c9ea6f1dcbf43d4e75258975dc'}, 'inventory': {'bytes': 20286, 'sha256': '0f9dae65da1411548e5083ebdc14cc0d7f5f342ea0940dbcc2fd560e80b59888'}}
def before11(raw,kind):
 text=raw.decode()
 for old,new in reversed(APPS11_EDITS[kind]):
  assert text.count(new)==1;text=text.replace(new,old,1)
 result=text.encode();assert dict(bytes=len(result),sha256=hashlib.sha256(result).hexdigest())==APPS10_PINS[kind],'whole exact Apps10 CPU predecessor inverse';return result

parent=types.ModuleType('_exact_parent9_inventory');parent.__file__=str(HERE/'inventory.py');raw=before11((HERE/'inventory.py').read_bytes(),'inventory').split(b'\n# BEGIN_APPS10_OPTIONAL_STAGE_DIAGNOSTIC\n')[0];assert I.digest(raw)==INV['parent_inventory']['sha256'];exec(compile(raw,parent.__file__,'exec'),parent.__dict__)
def fixture(db,count=4):
 local=db/'local';local.mkdir(parents=True);(local/'ALPM_DB_VERSION').write_bytes(b'9\n')
 for n in range(count):
  name='fixture-'+str(n).zfill(3);q=local/(name+'-1-1');q.mkdir();(q/'desc').write_text('%NAME%\n'+name+'\n\n%VERSION%\n1-1\n\n%ARCH%\naarch64\n\n');(q/'files').write_text('%FILES%\n'+''.join('usr/share/'+name+'/file'+str(i)+'\n'for i in range(64))+'\n')
def normalize(row):return A.package(row,R)
def state(output):return json.loads(output.with_name(output.name+'.stage.json').read_bytes())
class Controls(unittest.TestCase):
 def test_all_original_functions_default_cli_operands_and_diagnostic_derivative_inverse(self):
  functions=lambda text:{n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)};now=functions((HERE/'inventory.py').read_text())
  prior=functions(before11((HERE/'inventory.py').read_bytes(),'inventory').decode())
  self.assertEqual({n for n in prior if now[n]!=prior[n]},{'scan','relative','sections'})
  for n,w in INV['parent_functions'].items():self.assertEqual(dict(bytes=len(prior[n].encode()),sha256=I.digest(prior[n].encode())),w,n)
  for n in prior:
   if n not in {'scan','relative','sections'}:self.assertEqual(now[n],prior[n])
  for name,edits in(('_collect_diagnostic',INV['collect_edits']),('_publish_diagnostic',INV['publish_edits'])):
   text=now[name]
   for a,b in reversed(edits):self.assertEqual(text.count(b),1);text=text.replace(b,a,1)
   self.assertEqual(text,now['collect'if name=='_collect_diagnostic'else'publish'])
  text=before11((HERE/'apps.py').read_bytes(),'apps').decode()
  for a,b in reversed(INV['app_edits']):self.assertEqual(text.count(b),1);text=text.replace(b,a,1)
  self.assertEqual(dict(bytes=len(text.encode()),sha256=I.digest(text.encode())),INV['parent_apps'])
 def test_whole606_default_and_optin_exact_output_result_twofresh_scans(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);db=root/'db';fixture(db,606);out=root/'inventory.json';old=parent.publish(db,out,C,normalize);expected=out.read_bytes();out.unlink();new=I.publish(db,out,C,normalize);self.assertEqual(old,new);self.assertEqual(out.read_bytes(),expected);self.assertFalse(out.with_name(out.name+'.stage.json').exists());out.unlink();calls=[];scan=I.scan
   def record(*args):calls.append(args[-1]);return scan(*args)
   with patch.object(I,'scan',side_effect=record):observed=I.publish_diagnostic(db,out,C,normalize)
   self.assertEqual(observed,old);self.assertEqual(out.read_bytes(),expected);self.assertEqual(len(calls),2);self.assertEqual(calls[0],calls[1]);v=state(out);self.assertEqual((v['status'],v['phase'],v['sequence']),('DONE','DONE',14));self.assertEqual(set(v),{'schema','status','phase','sequence','elapsed_seconds','authority'});self.assertLess(len(out.with_name(out.name+'.stage.json').read_bytes()),1024);self.assertEqual(out.with_name(out.name+'.stage.json').stat().st_mode&0o777,0o600)
 def test_actual_isolated_cli_default_and_optin_without_stdout_schema_change(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);db=root/'db';fixture(db);out=root/'inventory.json';base=[sys.executable,'-I','-B',str(HERE/'apps.py'),'--repository-source',str(SOURCE),'inventory','--dbpath',str(db),'--output',str(out)];a=subprocess.run(base,capture_output=True,timeout=15);self.assertEqual(a.returncode,0,a.stderr);raw=out.read_bytes();out.unlink();b=subprocess.run([*base,'--diagnostic-stage'],capture_output=True,timeout=15);self.assertEqual(b.returncode,0,b.stderr);self.assertEqual(a.stdout,b.stdout);self.assertEqual(a.stderr,b.stderr);self.assertEqual(out.read_bytes(),raw);self.assertEqual(state(out)['phase'],'DONE')
 def test_real_first_second_scan_mutation_and_original_deadline_refuse(self):
  for fail in('mutation','deadline'):
   with self.subTest(fail=fail),tempfile.TemporaryDirectory()as td:
    root=Path(td);db=root/'db';fixture(db);out=root/'inventory.json';scan=I.scan;calls=[]
    def controlled(*args):
     if fail=='deadline':return scan(*args[:-1],0)
     value=scan(*args);calls.append(1)
     if len(calls)==1:(db/'local/fixture-000-1-1/files').write_bytes(b'%FILES%\nusr/changed\n\n')
     return value
    with patch.object(I,'scan',side_effect=controlled),self.assertRaises(ValueError):I.publish_diagnostic(db,out,C,normalize)
    v=state(out);self.assertEqual(v['status'],'FAILED');self.assertEqual(v['phase'],'COMPARE_READS'if fail=='mutation'else'SCAN_FIRST');self.assertFalse(out.exists())
 def test_original_failed_fsync_removes_output_preserves_failed_phase_and_error(self):
  for failing_call,phase in((1,'FSYNC_OUTPUT'),(2,'FSYNC_PARENT')):
   with self.subTest(phase=phase),tempfile.TemporaryDirectory()as td:
    root=Path(td);db=root/'db';fixture(db);out=root/'inventory.json';error=OSError('CONTROL_ONLY_FSYNC');calls=[];original=I.os.fsync
    def fsync(fd):
     calls.append(1)
     if len(calls)==failing_call:raise error
     return original(fd)
    with patch.object(I.os,'fsync',side_effect=fsync),self.assertRaises(OSError)as caught:I.publish_diagnostic(db,out,C,normalize)
    self.assertIs(caught.exception,error);self.assertFalse(out.exists());v=state(out);self.assertEqual((v['status'],v['phase'],v['error_type']),('FAILED',phase,'OSError'))
 def test_keyboard_interrupt_preserves_last_phase_and_closes_descriptors(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);db=root/'db';fixture(db);out=root/'inventory.json';scan=I.scan;calls=[];before=set(os.listdir('/proc/self/fd'))
   def interrupted(*args):
    calls.append(1)
    if len(calls)==2:raise KeyboardInterrupt()
    return scan(*args)
   with patch.object(I,'scan',side_effect=interrupted),self.assertRaises(KeyboardInterrupt):I.publish_diagnostic(db,out,C,normalize)
   self.assertEqual(set(os.listdir('/proc/self/fd')),before);self.assertFalse(out.exists());v=state(out);self.assertEqual((v['status'],v['phase'],v['error_type']),('FAILED','SCAN_SECOND','KeyboardInterrupt'))
 def test_owned_child_sigterm_and_timeout_leave_inflight_phase_no_output(self):
  for action in('terminate','timeout'):
   with self.subTest(action=action),tempfile.TemporaryDirectory()as td:
    root=Path(td);db=root/'db';fixture(db);out=root/'inventory.json';script=root/'child.py';script.write_text('import importlib.util,sys,time\nfrom pathlib import Path\ndef load(n,p):\n s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m\nA=load("A",Path(sys.argv[1])/"apps.py");I=load("I",Path(sys.argv[1])/"inventory.py");C,R,_=A.helpers(Path(sys.argv[2]));old=I._Stage.__call__\ndef checkpoint(self,phase):\n old(self,phase)\n if phase=="SCAN_SECOND":\n  while True:time.sleep(1)\nI._Stage.__call__=checkpoint\nI.publish_diagnostic(Path(sys.argv[3]),Path(sys.argv[4]),C,lambda row:A.package(row,R))\n');child=subprocess.Popen([sys.executable,'-I','-B',str(script),str(HERE),str(SOURCE),str(db),str(out)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
     until=time.monotonic()+8
     while time.monotonic()<until:
      try:
       if state(out)['phase']=='SCAN_SECOND':break
      except (FileNotFoundError,json.JSONDecodeError):pass
      self.assertIsNone(child.poll());time.sleep(.01)
     else:self.fail('owned child checkpoint not reached')
     if action=='terminate':child.terminate();child.communicate(timeout=5)
     else:
      with self.assertRaises(subprocess.TimeoutExpired):child.communicate(timeout=.02)
      child.kill();child.communicate(timeout=5)
     self.assertFalse(out.exists());v=state(out);self.assertEqual((v['status'],v['phase']),('RUNNING','SCAN_SECOND'));self.assertIsNotNone(child.returncode)
    finally:
     if child.poll()is None:child.kill()
     child.communicate(timeout=5)
 def test_stage_existing_link_ancestry_alias_parent_mode_and_foreign_edit_refuse(self):
  for kind in('existing','symlink','hardlink','alias','writable-parent','foreign-edit'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory()as td:
    root=Path(td);db=root/'db';fixture(db);out=root/'inventory.json';stage=out.with_name(out.name+'.stage.json')
    if kind in('existing','hardlink'):stage.write_bytes(b'foreign')
    if kind=='symlink':stage.symlink_to(root/'absent')
    if kind=='hardlink':os.link(stage,root/'external')
    if kind=='alias':alias=root/'alias';alias.symlink_to(root,target_is_directory=True);out=alias/'inventory.json'
    if kind=='writable-parent':root.chmod(0o777)
    if kind=='foreign-edit':
     call=I._Stage.__call__
     def edited(self,phase):
      call(self,phase)
      if phase=='SCAN_FIRST':stage.write_bytes(b'foreign')
     context=patch.object(I._Stage,'__call__',edited)
    else:context=__import__('contextlib').nullcontext()
    with context,self.assertRaises((ValueError,OSError)):I.publish_diagnostic(db,out,C,normalize)
    self.assertFalse(out.exists())
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
