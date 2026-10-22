# SPDX-License-Identifier: MIT
"""Finite local source/custody checks; no Git, network, or actor execution."""
import hashlib,json,os,re,stat
from pathlib import Path
RECIPE='2e58341f6fa25de5167fd8a59566b3dd7f066fe3'
PAIR=None
PAIR_REF=None
RUN=None
NAME='cachy-asahi-apps'
VERSION='0.1.0-14'
ROLES={'runtime':'cachy-asahi-repository-runtime','apps':'cachy-asahi-apps','client':'cachy-asahi-repository-client-v2'}
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def need(ok,why):
 if not ok:raise ValueError(why)
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def read(p,cap=16*1024**2):
 p=Path(p).absolute();need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary exact input ancestry');s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=cap,'ordinary bounded singlelink input');raw=p.read_bytes();t=p.lstat();need(len(raw)==s.st_size and all(getattr(s,k)==getattr(t,k)for k in FIELDS),'stable whole input read');return raw
def decode(raw):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate JSON key');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def obj(p):return decode(read(p))
def member(n):need(type(n)is str and n and not n.startswith('/')and all(p not in('','.','..','.git')for p in n.split('/')),'contained ordinary carrier role');return n
def table(root):
 root=Path(root).absolute();out={}
 for b,ds,fs in os.walk(root):
  if Path(b)==root:ds[:]=[n for n in ds if n!='.git'];fs=[n for n in fs if n!='.git']
  for n in ds:need(not(Path(b)/n).is_symlink(),'ordinary source directory')
  for n in fs:out[(Path(b)/n).relative_to(root).as_posix()]=pin(read(Path(b)/n,128*1024**2))
 return out
def closed(root,rows):need(table(root)==rows,'whole exact closed input/source map');return rows

def index_check(index,files,recipe_map,acceptance):
 need(type(PAIR)is str and re.fullmatch('[a-f0-9]{40}',PAIR)and PAIR_REF=='codex/apps14-pair-native-v1'and type(RUN)is int and RUN>0,'genuine source-bound Apps14 pair authority required')
 need(index['status']=='EXACT_ACCEPTED_APPS14_PAIR_INPUT_DATA_ONLY'and index['actual']is None,'Apps14 input DATA only')
 need(index['source']==PAIR and index['ref']==PAIR_REF and index['run']==RUN and index['recipe_source']==RECIPE,'exact Apps14 native pair/recipe source and run')
 need(index['GUI']==index['installed_current606']==index['hardware']=='NOT_RUN','no pair acceptance transfer')
 recipe_prefix=member(index['recipe_prefix']);need(recipe_prefix=='recipe-source','exact public whole42 recipe namespace')
 need({n.removeprefix(recipe_prefix+'/'):w for n,w in files.items()if n.startswith(recipe_prefix+'/')}==recipe_map,'all42 original public recipe leaves')
 archives=index['archives'];need(type(archives)is list and len(archives)==2 and len({r['path']for r in archives})==2,'two distinct original Apps14 build roles')
 pins=[]
 for row in archives:
  path=member(row['path']);w={k:row[k]for k in('bytes','sha256')};need(path.endswith('/cachy-asahi-apps-0.1.0-14-any.pkg.tar.xz')and type(w['bytes'])is int and 0<w['bytes']<=16*1024**2 and re.fullmatch('[a-f0-9]{64}',w['sha256'])and files[path]==w,'exact accepted Apps14 any archive body');pins.append(w)
 need(pins[0]==pins[1],'complete byte-identical Apps14 native pair')
 need(acceptance['source']==PAIR and acceptance['ref']==PAIR_REF and acceptance['run']==RUN and acceptance['status']=='ROOT_ACCEPTED_APPS14_NATIVE_BUILD_PAIRS_AND_FINITE_INSTALLED_LIFECYCLE','genuine matching Root Apps14 finite acceptance required')
 # Root selects the explicit archive-pin field from its original decision. Never
 # infer acceptance from a successful CI result or a historical Apps7 receipt.
 authority=acceptance
 for key in index['acceptance_archive_pointer']:
  need(type(key)in(str,int),'typed Root archive-pin pointer');authority=authority[key]
 need(type(authority)is dict and all(authority[k]==pins[0][k]for k in('bytes','sha256')),'original Root decision authorizes this exact native archive')
 need(files[member(index['acceptance'])]==pin(enc(acceptance)),'canonical original Root decision bytes')
 for role in('LICENSE','NOTICE.md'):
  need(role in files,'public source/license closure required')
 return dict(name=NAME,version=VERSION,archive=Path(archives[0]['path']).name,size=pins[0]['bytes'],sha256=pins[0]['sha256'])

PARENT='a0c8eb9ccb2994cf2f7156a6e66bfc9715b9e464'
# Source-owned host/synthetic controls only. No GUI or native acceptance.
if __name__=='__main__':
 import base64,contextlib,importlib.util,io,json,os,subprocess,sys,tempfile,types,unittest,zipfile
 from pathlib import Path
 from unittest.mock import patch
 D=Path(__file__).resolve().parent
 def load(n,p):
  spec=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
 P=load('_current_products_source_control',D/'factory/current_products.py');S=load('_stage_source_control',D/'factory/apps14_diagnostic.py');I=load('_qualified_stage_writer',D.parent/'apps14-inputs/recipe-source/packages/tools/cachy-asahi-apps14/inventory.py')
 UID=types.SimpleNamespace(getuid=lambda:23001,geteuid=lambda:23001,sysconf=os.sysconf)
 def stage(target,done=False):
  parent=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY)
  try:
   value=I._Stage(parent,target.name+'.stage.json')
   try:
    for name in I.PHASES[1:]if done else('SCAN_FIRST','SCAN_SECOND'):value(name)
   finally:value.close()
  finally:os.close(parent)
 class Controls(unittest.TestCase):
  def test_actual_current_run_completed_refusal_preserves35_and_original_gate(self):
   with tempfile.TemporaryDirectory(dir=D)as td:
    home=Path(td);calls=[];raw=b'{"status":"REFUSED"}\n'
    def actor(argv,**kw):calls.append((argv,kw));return subprocess.CompletedProcess(argv,1,raw,b'')
    with patch.object(P,'os',UID),patch.object(P,'_apps14_runtime',return_value=types.SimpleNamespace(observe=lambda:{})),patch.object(P.subprocess,'run',side_effect=actor),contextlib.redirect_stderr(io.StringIO())as capture,self.assertRaisesRegex(ValueError,'actual bounded installed Apps14 command'):P.run(home,home,{'PATH':'/usr/bin:/bin'})
    self.assertEqual(calls[0][0][-1],'--diagnostic-stage');self.assertEqual(calls[0][1]['timeout'],35);lines=capture.getvalue().splitlines();data=json.loads(lines[0].split(' ',1)[1]);self.assertEqual(base64.b64decode(data['stdout']['base64']),raw);self.assertEqual(data['reason'],'COMPLETED_COMMAND_GATE_REFUSAL');self.assertEqual(data['stage']['status'],'ABSENT');self.assertFalse(data['acceptance_authority'])
  def test_actual_owned_child_timeout_partialstreams_phase_and_retirement(self):
   real=subprocess.run
   with tempfile.TemporaryDirectory(dir=D)as td:
    home=Path(td);target=home/'apps14-current606-inventory.json';argv=['/usr/bin/cachy-asahi-apps','inventory','--dbpath','/var/lib/pacman','--output',str(target),'--diagnostic-stage']
    code="import importlib.util,os,sys,time;from pathlib import Path;p=Path(sys.argv[1]);s=importlib.util.spec_from_file_location('stage',sys.argv[2]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);v=m._Stage(fd,p.name+'.stage.json');v('SCAN_FIRST');v('SCAN_SECOND');print('owned stdout',flush=True);print('owned stderr',file=sys.stderr,flush=True);time.sleep(3)"
    def actor(actual,**kw):
     self.assertEqual(actual,argv);self.assertEqual(kw['timeout'],35)
     # Explicit inert argv translator: real owned Python child,0.2s HOST control.
     # Production35/30 are untouched; no native fit or Apps CLI result is inferred.
     return real([sys.executable,'-I','-B','-c',code,str(target),str(Path(I.__file__))],capture_output=True,timeout=.2)
    with patch.object(P,'os',UID),patch.object(P,'_apps14_runtime',return_value=types.SimpleNamespace(observe=lambda:{})),patch.object(P.subprocess,'run',side_effect=actor),contextlib.redirect_stderr(io.StringIO())as capture,self.assertRaises(subprocess.TimeoutExpired):P.run(home,home,{})
    lines=capture.getvalue().splitlines();data=json.loads(lines[0].split(' ',1)[1]);self.assertIsNone(data['returncode']);self.assertTrue(data['partial_streams']);self.assertEqual(base64.b64decode(data['stdout']['base64']),b'owned stdout\n');self.assertEqual(base64.b64decode(data['stderr']['base64']),b'owned stderr\n');self.assertEqual(data['stage']['document']['phase'],'SCAN_SECOND');self.assertTrue(data['stage']['retired']);self.assertFalse(target.with_name(target.name+'.stage.json').exists());self.assertFalse(target.exists());self.assertTrue(lines[-1].startswith('CURRENT606_APPS14_STAGE_FAILURE_DATA '))
  def test_success_reaches_original_after_identity_only_withDONE_retired(self):
   class ReachedOriginalAfterIdentity(Exception):pass
   with tempfile.TemporaryDirectory(dir=D)as td:
    home=Path(td);calls=[]
    def observe():
     calls.append(1)
     if len(calls)==2:raise ReachedOriginalAfterIdentity()
     return {}
    def actor(argv,**kw):stage(Path(argv[-2]),True);return subprocess.CompletedProcess(argv,0,b'{}',b'')
    with patch.object(P,'os',UID),patch.object(P,'_apps14_runtime',return_value=types.SimpleNamespace(observe=observe)),patch.object(P.subprocess,'run',side_effect=actor),patch.object(P,'_apps14_command_failure',side_effect=AssertionError('no failure on success')),self.assertRaises(ReachedOriginalAfterIdentity):P.run(home,home,{})
    self.assertEqual(len(calls),2);self.assertFalse((home/'apps14-current606-inventory.json.stage.json').exists())
  def test_stage_ordinary_fresh_identity_paths_and_foreign_content_refusals(self):
   with tempfile.TemporaryDirectory(dir=D)as td:
    home=Path(td);target=home/'output';parent=S.directory(home)
    try:
     stage(target,True);p=home/'output.stage.json';raw=p.read_bytes();p.write_bytes(raw.replace(b'DONE',b'EVIL'))
     value=S.observe_and_retire(parent,target);self.assertEqual(value['status'],'UNREADABLE_OR_FOREIGN_STAGE_PRESERVED');self.assertTrue(p.exists());p.unlink()
     other=home/'outside';other.write_bytes(b'foreign');p.symlink_to(other);value=S.observe_and_retire(parent,target);self.assertFalse(value['retired']);self.assertEqual(other.read_bytes(),b'foreign');p.unlink()
     for value in [dict(schema=1,status='DONE',phase='SCAN_FIRST',sequence=1,elapsed_seconds=1,authority='DIAGNOSTIC_ONLY_NOT_ACCEPTANCE'),dict(schema=1,status='RUNNING',phase='SCAN_FIRST',sequence=1,elapsed_seconds=float('nan'),authority='DIAGNOSTIC_ONLY_NOT_ACCEPTANCE')]:
      with self.assertRaises(ValueError):S.validate(value)
    finally:os.close(parent)
  def test_large_partial_stream_fullhash_bound_and_final_stage_tail(self):
   stage_value=dict(status='ABSENT',document=None,retired=True,acceptance_authority=False)
   with contextlib.redirect_stderr(io.StringIO())as capture:data=P._apps14_command_failure(types.SimpleNamespace(returncode=None,stdout=b'x'*65537,stderr=b'y'*65537),35,['/usr/bin/cachy-asahi-apps'],{},stage_value,True)
   raw=capture.getvalue().encode();self.assertLess(len(raw),192*1024+2048);self.assertTrue(data['stdout']['truncated']);self.assertEqual(data['stdout']['sha256'],P.digest(b'x'*65537));self.assertIn(b'CURRENT606_APPS14_STAGE_FAILURE_DATA',raw[-16384:])
  def test_exact_stage_DATA_survives_original512MiB_transport(self):
   T=load('_same_actor_transport',D/'transport.py');self.assertEqual(T.MAX,512*1024**2);self.assertIn('gui/guest.log',T.ROLES)
   with tempfile.TemporaryDirectory(dir=D)as td:
    root=Path(td);public=root/'public';(public/'gui').mkdir(parents=True);raw=b'CURRENT606_APPS14_STAGE_FAILURE_DATA {"acceptance_authority":false,"stage":{"phase":"SCAN_SECOND"}}\n';(public/'gui/guest.log').write_bytes(raw);(public/'retention.json').write_bytes(T.enc(dict(status='FAIL_OR_INCOMPLETE',case='minimal-generic4k',files={'gui/guest.log':T.pin(raw)},total_bytes=len(raw))))
    # Explicit synthetic transport DATA only, never a selected actual/source pair.
    proof=dict(source='0'*40,run=1,attempt=1,case='minimal-generic4k',job_token='0'*16);v=T.pack(public,root/'transport',proof);self.assertEqual(v['status'],'PACKED_PUBLIC_EVIDENCE_DATA_ONLY');self.assertFalse(v['actual_authority'])
    with zipfile.ZipFile(root/'transport/evidence.zip')as z:self.assertIsNone(z.testzip());self.assertEqual(z.read('gui/guest.log'),raw)
    diagnostic=T.enc(T.enc if False else json.loads((root/'transport/failure-data.json').read_bytes()));self.assertIn(b'SCAN_SECOND',base64.b64decode(json.loads(diagnostic)['roles']['gui/guest.log']['base64']))
 unittest.main(verbosity=2)
