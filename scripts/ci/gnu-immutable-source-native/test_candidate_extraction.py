# SPDX-License-Identifier: MIT
"""Actual helper controls; synthetic package/ALPM DATA, real owned child signals."""
import argparse,copy,ctypes,hashlib,json,os,signal,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,default=HERE.parents[2]if HERE.name=='gnu-immutable-source-native'else None);args,remaining=parser.parse_known_args();sys.argv=[sys.argv[0],*remaining]
if args.source is None:raise ValueError('development controls require explicit --source')
SOURCE=args.source.resolve();LANE=SOURCE/'runtime/runtime-vm/scripts/ci/glibc-gnu-provider-interruption'
TEMP_PARENT=HERE.parent if HERE.parent.name=='gnu-candidate-extraction-interruption-development-20261026'else None

def source_module(name,path,pin=None,inject=None):
 raw=path.read_bytes()
 if pin is not None:assert hashlib.sha256(raw).hexdigest()==pin,'exact byte-held source fixture'
 module=types.ModuleType(name);namespace=vars(module);namespace['__file__']=str(path);namespace.update(inject or {})
 if inject and 'C'in inject and b'import common as C\n'in raw:
  assert raw.count(b'import common as C\n')==1;raw=raw.replace(b'import common as C\n',b'',1)
 saved=sys.path[:]
 try:exec(compile(raw,str(path),'exec'),namespace)
 finally:sys.path[:]=saved
 return module

C=source_module('_SYNTHETIC_source_common',LANE/'common.py','ac2e38d80b0c0a283b9865fb88e6000f7c10202194298a6a3ed31b5679574d8b')
R=source_module('_source_exact_REMOVE_checkpoint',LANE/'interruption.py','daf605b234ece080706a29f597f006da95b80113baeeb57c3e7f46c102c6d8bf',dict(C=C))
L=source_module('_source_exact_lifecycle_functions',LANE/'container.py','22ce53335b8ec9a8d3200679855c7922c62cd3da4cefab15556660b1ab39192e',dict(C=C))
# The candidate module deliberately imports no common/R module; the worker injects them.
M=source_module('_actual_emitted_candidate_extraction',HERE/'candidate_extraction.py',inject=dict(C=C,R=R))

def row(raw,mode=0o644,uid=0,gid=0):return dict(type='file',mode=mode,uid=uid,gid=gid,bytes=len(raw),sha256=C.sha(raw))
def directory():return dict(type='directory',mode=0o755,uid=0,gid=0)
def prepared():return dict(prepared_add={C.NAME:C.VERSION},prepared_remove={'glibc':'SYNTHETIC_HELD'},dependencies='PASS_ALPM_PREPARE',commit_started=True,observer_root='INTACT_OUTER_HELD574',hooks='DISABLED',scriptlets='DISABLED_EXPLICIT_HELD_POST_UPGRADE_LATER')

class Setter:
 def __call__(self,handle,callback,context):self.callback=callback;return 0
class CallbackAlpm:
 def __init__(self):self.handle=ctypes.c_void_p(1);self.lib=types.SimpleNamespace(alpm_option_set_progresscb=Setter())
 def ok(self,value,label):C.need(value==0,label)

class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='SYNTHETIC-candidate-controls-',dir=TEMP_PARENT);self.work=Path(self.tmp.name);self.root=self.work/'pristine/root';self.root.parent.mkdir(mode=0o700);self.root.mkdir(mode=0o755)
  self.lane=types.SimpleNamespace(WORK=self.work,OUT=self.work,INPUTS=self.work,FIXTURE=L.FIXTURE,USER=L.USER,CONFIGS=L.CONFIGS,unchanged=L.unchanged);(self.root/L.FIXTURE).mkdir(parents=True)
 def tearDown(self):self.tmp.cleanup()
 def put(self,name,raw=b'SYNTHETIC',mode=0o644):
  p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(mode);return p
 def synthetic_lock(self,root):
  # ONLY root-only lock UID classification differs from production. Signals,
  # actual lock inode/mode, READY/ack, pipe framing, kill/reap and absence are real.
  p=root/R.LOCK;s=p.lstat();C.need(s.st_nlink==1 and s.st_size==0 and s.st_mode&0o777==0,'SYNTHETIC unprivileged empty lock');return R.identity(s)
 def witnesses(self):
  old=dict(nodes={},data={});new=dict(nodes={'usr/a':row(b'CANDIDATE_FIRST',uid=os.getuid(),gid=os.getgid()),'usr/z':row(b'CANDIDATE_LAST',uid=os.getuid(),gid=os.getgid())},data={'usr/a':b'CANDIDATE_FIRST','usr/z':b'CANDIDATE_LAST'})
  return dict(nodes={}),old,new

 def test_real_ADD_callback_READY_ack_SIGSTOP_SIGKILL_reap_and_group_absence(self):
  before,old,new=self.witnesses();point=M.choose(before,old,new)
  def transaction(api,root,archive,remove,add,log,progress):
   self.assertEqual((remove,add),('glibc',C.NAME));self.put(R.LOCK,b'',0);self.put('usr/a',new['data']['usr/a']);a=CallbackAlpm();progress.bind(a);progress.prepared=prepared();progress.armed=True
   a.lib.alpm_option_set_progresscb.callback(None,0,C.NAME.encode(),100,1,1)
   raise AssertionError('stopped callback must never return')
  self.lane.transaction=transaction;report={};index={'archives':{'a':{'path':'SYNTHETIC_NEVER_OPENED'}}}
  with patch.object(R,'lock_identity',self.synthetic_lock):
   actual=M.stop_and_kill({},self.lane,self.root,index,point,'pristine',report)
   self.assertEqual(actual['event'],0);self.assertEqual(actual['package'],C.NAME);self.assertEqual(actual['percent'],100)
   self.assertEqual(report['observed_stop'],'KERNEL_CLD_STOPPED_SIGSTOP_WITH_UNREAPED_OWNED_LEADER');self.assertEqual(report['writer']['exit_code'],-signal.SIGKILL);self.assertTrue(report['writer']['group_absence_verified']);self.assertEqual(report['writer']['pid'],report['writer']['pgid'])
   self.assertEqual(R.clear_owned_lock(self.root,actual['lock'],report['writer'])['status'],'PASS_EXACT_OWNED_STALE_LOCK_REMOVED_AFTER_GROUP_ABSENCE')
  self.assertFalse((self.root/R.LOCK).exists())

 def test_callback_rejects_wrong_event_package_and_complete_candidate(self):
  for event,package,complete in((4,C.NAME.encode(),False),(0,b'glibc',False),(0,C.NAME.encode(),True)):
   before,old,new=self.witnesses();point=M.choose(before,old,new)
   def transaction(api,root,archive,remove,add,log,progress):
    self.put(R.LOCK,b'',0);self.put('usr/a',new['data']['usr/a'])
    if complete:self.put('usr/z',new['data']['usr/z'])
    a=CallbackAlpm();progress.bind(a);progress.prepared=prepared();progress.armed=True;a.lib.alpm_option_set_progresscb.callback(None,event,package,80,1,1)
   self.lane.transaction=transaction;report={}
   with patch.object(R,'lock_identity',self.synthetic_lock),self.assertRaises(ValueError):M.stop_and_kill({},self.lane,self.root,{'archives':{'a':{'path':'SYNTHETIC'}}},point,'pristine',report)
   self.assertTrue(report['writer']['group_absence_verified']);self.assertNotIn('observed_stop',report);(self.root/R.LOCK).unlink()
   for name in('usr/a','usr/z'):
    if (self.root/name).exists():(self.root/name).unlink()

 def test_partial_and_checkpoint_protocol_foreign_lock_refusals(self):
  before,old,new=self.witnesses();point=M.choose(before,old,new);self.put('usr/a',new['data']['usr/a']);self.put(R.LOCK,b'',0)
  with patch.object(R,'lock_identity',self.synthetic_lock):
   value=dict(type='CHECKPOINT',pid=123,pgid=123,phase=M.PHASE,event=0,package=C.NAME,percent=100,howmany=1,current=1,point=point,lock=R.lock_identity(self.root),prepared=prepared());M.validate_checkpoint(value,123,self.root,point)
   for key,bad in(('event',4),('event',True),('package','glibc'),('percent',True),('percent',101),('pid',True),('howmany',True),('phase','REMOVE'),('lock',[0]*9)):
    v=copy.deepcopy(value);v[key]=bad
    with self.subTest(key=key,bad=bad),self.assertRaises(ValueError):M.validate_checkpoint(v,123,self.root,point)
   for mutate in(lambda v:v.update(extra=True),lambda v:v['prepared'].update(dependencies='BYPASSED'),lambda v:v['prepared'].update(prepared_remove={}),lambda v:v['prepared'].update(commit_started=False)):
    v=copy.deepcopy(value);mutate(v)
    with self.assertRaises(ValueError):M.validate_checkpoint(v,123,self.root,point)
   foreign=list(value['lock']);foreign[1]+=1
   with self.assertRaises(ValueError):R.clear_owned_lock(self.root,foreign,dict(group_absence_verified=True,exit_code=-9))
   self.assertTrue((self.root/R.LOCK).exists())
  self.put('usr/z',new['data']['usr/z'])
  with self.assertRaises(ValueError):M.partial(self.root,point)

 def classification(self):
  # Complete synthetic representation of 573 unrelated packages, not native DB DATA.
  base={'glibc':'SYNTHETIC_HELD',**{'fixture%03d'%i:'1'for i in range(573)}};nodes={R.LOCAL:directory(),R.LOCAL+'/ALPM_DB_VERSION':row(b'9\n'),self.lane.USER:directory(),self.lane.USER+'/keep':row(b'USER')}
  for name in base:
   prefix=R.LOCAL+'/'+name+'-'+base[name];nodes[prefix]=directory();nodes[prefix+'/desc']=row(('SYNTHETIC_DESC_'+name).encode());nodes[prefix+'/files']=row(('SYNTHETIC_FILES_'+name).encode())
  old=dict(nodes={'usr/old':row(b'OLD'),'etc/gai.conf':row(b'USER_GAI'),'etc/locale.gen':row(b'USER_LOCALE')},data={});new=dict(nodes={'usr/new':row(b'NEW'),'usr/pending':row(b'PENDING'),'etc/gai.conf':row(b'DEFAULT')},data={'.MTREE':b'SYNTHETIC_MTREE'})
  nodes.update(old['nodes']);before=dict(nodes=nodes);interrupted=copy.deepcopy(before);prefix=R.LOCAL+'/glibc-'+base['glibc'];interrupted['nodes']={n:r for n,r in interrupted['nodes'].items()if n!=prefix and not n.startswith(prefix+'/')};candidate=R.LOCAL+'/'+C.NAME+'-'+C.VERSION;interrupted['nodes'][candidate]=directory();interrupted['nodes'][candidate+'/mtree']=row(new['data']['.MTREE']);interrupted['nodes']['usr/new']=new['nodes']['usr/new'];interrupted['nodes'][R.LOCK]=row(b'',0)
  return before,interrupted,base,new,old,candidate

 def test_complete_synthetic573_DB_partial_classification_and_refusals(self):
  before,current,base,new,old,candidate=self.classification();moves,fragment,preserved=M.classify(self.lane,before,current,base,new,old);self.assertEqual(fragment,candidate);self.assertIn(candidate+'/mtree',moves);self.assertTrue(preserved['unrelated_preserved']);self.assertEqual(len(base)-1,573)
  changes=(lambda n:n.update({candidate+'/desc':row(b'COMMITTED')}),lambda n:n.update({candidate+'/install':row(b'FORBIDDEN')}),lambda n:n[candidate].update(uid=1),lambda n:n[R.LOCAL+'/fixture001-1/desc'].update(sha256='f'*64),lambda n:n[self.lane.USER+'/keep'].update(sha256='f'*64),lambda n:n['usr/new'].update(sha256='f'*64),lambda n:n.update({R.LOCAL+'/glibc-SYNTHETIC_HELD':directory()}))
  for change in changes:
   bad=copy.deepcopy(current);change(bad['nodes'])
   with self.assertRaises(ValueError):M.classify(self.lane,before,bad,base,new,old)

 def test_quarantine_exact_moves_closed_retirement_and_unknown_drift_refusal(self):
  self.put('usr/new',b'CANDIDATE');candidate=R.LOCAL+'/'+C.NAME+'-'+C.VERSION;self.put(candidate+'/mtree',b'MTREE');moves={n:M.node(self.root/n)[0]for n in('usr/new',candidate+'/mtree')};q,receipt=M.quarantine(self.lane,self.root,moves,candidate)
  self.assertEqual(receipt['automatic_rollback'],'NOT_CLAIMED');self.assertFalse((self.root/'usr/new').exists());self.assertFalse((self.root/candidate).exists());self.assertEqual((q/'usr/new').read_bytes(),b'CANDIDATE')
  (q/'foreign').write_bytes(b'FOREIGN')
  with self.assertRaises(ValueError):M.retire_quarantine(q,moves)
  self.assertEqual((q/'usr/new').read_bytes(),b'CANDIDATE');(q/'foreign').unlink();(q/'usr/new').write_bytes(b'CORRUPTED')
  with self.assertRaises(ValueError):M.retire_quarantine(q,moves)
  (q/'usr/new').write_bytes(b'CANDIDATE');M.retire_quarantine(q,moves);self.assertFalse(q.exists())
  self.put('usr/late',b'LATE');moves={'usr/late':M.node(self.root/'usr/late')[0]};self.put('usr/late',b'FOREIGN');(self.root/candidate).mkdir()
  with self.assertRaises(ValueError):M.quarantine(self.lane,self.root,moves,candidate)
  self.assertEqual((self.root/'usr/late').read_bytes(),b'FOREIGN')

 def test_explicit_configuration_restore_and_fail_closed_defaults(self):
  default=b'DEFAULT\n';wanted=b'CAPTURED USER CHANGES\n';name='etc/gai.conf';self.put(name,default,0o640);old=dict(nodes={name:M.node(self.root/name)[0]});captured={name:(dict(old['nodes'][name],bytes=len(wanted),sha256=C.sha(wanted)),wanted)}
  r=M.restore_configs(self.lane,self.root,captured,old);self.assertEqual((self.root/name).read_bytes(),wanted);self.assertEqual(r['ALPM_active_configuration_preservation'],'NOT_CLAIMED');self.assertEqual(r['operations'][0]['operation'],'RESTORE_CAPTURED_OWNED_CLONE_CONFIGURATION')
  self.put(name,b'FOREIGN',0o640)
  with self.assertRaises(ValueError):M.restore_configs(self.lane,self.root,captured,old)
  self.assertEqual((self.root/name).read_bytes(),b'FOREIGN');self.put(name,default,0o640);self.put('etc/gai.conf.pacnew',b'FOREIGN')
  with self.assertRaises(ValueError):M.restore_configs(self.lane,self.root,{},old)
  self.assertEqual((self.root/'etc/gai.conf.pacnew').read_bytes(),b'FOREIGN')

 def test_declared_package_hardlink_group_quarantine_and_retirement(self):
  # Genuine filesystem links, synthetic archive-owned group; configurations stay
  # singlelink-only. No package input or target root is used by this control.
  self.put('usr/first-link',b'GROUP_BYTES');os.link(self.root/'usr/first-link',self.root/'usr/second-link');candidate=R.LOCAL+'/'+C.NAME+'-'+C.VERSION;(self.root/candidate).mkdir(parents=True)
  names=('usr/first-link','usr/second-link');group=C.sha(('\n'.join(names)+'\n').encode());moves={n:dict(row(b'GROUP_BYTES',uid=os.getuid(),gid=os.getgid()),hardlink_group=group)for n in names}
  q,receipt=M.quarantine(self.lane,self.root,moves,candidate);self.assertEqual((q/names[0]).stat().st_ino,(q/names[1]).stat().st_ino);self.assertEqual((q/names[0]).stat().st_nlink,2);M.retire_quarantine(q,moves);self.assertFalse(q.exists())
  self.put(names[0],b'GROUP_BYTES');os.link(self.root/names[0],self.root/names[1]);os.link(self.root/names[0],self.root/'usr/foreign-alias');(self.root/candidate).mkdir()
  with self.assertRaises(ValueError):M.quarantine(self.lane,self.root,moves,candidate)
  self.assertTrue(all((self.root/n).read_bytes()==b'GROUP_BYTES'for n in(*names,'usr/foreign-alias')))

 def test_owned_clone_only_and_symlink_configuration_refusal(self):
  M.owned(self.lane,self.root,'pristine');self.root.chmod(0o700)
  with self.assertRaises(ValueError):M.owned(self.lane,self.root,'pristine')
  self.root.chmod(0o755)
  with self.assertRaises(ValueError):M.owned(self.lane,self.root,'modified')
  self.put('etc/real',b'UNCHANGED');(self.root/'etc/gai.conf').symlink_to('real');old=dict(nodes={'etc/gai.conf':row(b'UNCHANGED',uid=os.getuid(),gid=os.getgid())})
  with self.assertRaises(ValueError):M.restore_configs(self.lane,self.root,{'etc/gai.conf':(old['nodes']['etc/gai.conf'],b'NEW')},old)
  self.assertEqual((self.root/'etc/real').read_bytes(),b'UNCHANGED')
  (self.root/'etc/gai.conf').unlink();self.put('etc/gai.conf',b'DEFAULT');os.link(self.root/'etc/gai.conf',self.root/'etc/foreign-link');old=dict(nodes={'etc/gai.conf':M.node(self.root/'etc/gai.conf')[0]})
  with self.assertRaises(ValueError):M.restore_configs(self.lane,self.root,{'etc/gai.conf':(old['nodes']['etc/gai.conf'],b'NEW')},old)
  self.assertEqual((self.root/'etc/foreign-link').read_bytes(),b'DEFAULT')

 def fake_recovery(self,inventory=None,add=None,remove=None,prepare_code=0,commit_code=0):
  base={'glibc':'SYNTHETIC_HELD',**{'fixture%03d'%i:'1'for i in range(573)}};expected={k:v for k,v in base.items()if k!='glibc'};calls=[]
  class Alpm:
   def __init__(a,*args,**kwargs):a.handle=ctypes.c_void_p(1);a.started=False;calls.append(('construct',args,kwargs))
   def inventory(a):calls.append(('inventory',));return expected if inventory is None else inventory
   def ok(a,code,label):C.need(code==0,label)
   def alpm_trans_init(a,handle,flags):calls.append(('init',flags));return 0
   def alpm_pkg_load(a,handle,archive,full,siglevel,loaded):calls.append(('load',archive,full,siglevel));ctypes.cast(loaded,ctypes.POINTER(ctypes.c_void_p))[0]=ctypes.c_void_p(2);return 0
   def alpm_add_pkg(a,handle,package):calls.append(('add',));return 0
   def alpm_trans_prepare(a,*args):calls.append(('prepare',));return prepare_code
   def alpm_trans_get_add(a,handle):return {'glibc':base['glibc']}if add is None else add
   def alpm_trans_get_remove(a,handle):return {}if remove is None else remove
   def packages(a,value):return value
   def alpm_trans_commit(a,*args):calls.append(('commit',));return commit_code
   def close(a):calls.append(('close',a.started))
  api={'roots':types.SimpleNamespace(Alpm=Alpm,installer=types.SimpleNamespace(Ptr=ctypes.c_void_p))};lane=types.SimpleNamespace(WORK=self.work,database=lambda *a:[dict(name=k,version=v)for k,v in expected.items()],inventory=L.inventory,limits=lambda api,seconds:dict(SYNTHETIC_DEADLINE=seconds))
  return api,lane,base,expected,calls

 def test_actual_held_add_ordinary_flags_prepare_sets_commit_and_close(self):
  api,lane,base,expected,calls=self.fake_recovery();result=M.held_add(api,lane,self.root,self.work/'SYNTHETIC_PINNED_HELD',base,self.work/'SYNTHETIC_LOG');self.assertEqual(len(expected),573);self.assertEqual(result['flags'],(1<<7)|(1<<10));self.assertEqual(result['prepared_remove'],{});self.assertEqual(result['prepared_add'],{'glibc':base['glibc']})
  self.assertEqual([c[0]for c in calls],['construct','inventory','init','load','add','prepare','commit','close']);self.assertEqual(calls[2][1],(1<<7)|(1<<10));self.assertEqual(calls[3][2:],(1,0));self.assertEqual(calls[-1],('close',True));self.assertEqual(calls[0][2]['limits'],dict(SYNTHETIC_DEADLINE=120))
  # The fake has no remove/overwrite/nodeps API: actual function cannot use one.

 def test_held_add_wrong_inventory_sets_prepare_commit_refuse_and_always_close(self):
  for options in(dict(inventory={}),dict(add={'glibc':'WRONG'}),dict(remove={'other':'1'}),dict(prepare_code=-1),dict(commit_code=-1)):
   api,lane,base,expected,calls=self.fake_recovery(**options)
   with self.assertRaises(ValueError):M.held_add(api,lane,self.root,self.work/'SYNTHETIC_HELD',base,self.work/'SYNTHETIC_LOG')
   self.assertEqual(calls[-1][0],'close')
   if options.get('commit_code')!=-1:self.assertNotIn('commit',[c[0]for c in calls])
  api,lane,base,expected,calls=self.fake_recovery();lane.database=lambda *a:[]
  with self.assertRaises(ValueError):M.held_add(api,lane,self.root,self.work/'SYNTHETIC_HELD',base,self.work/'SYNTHETIC_LOG')
  self.assertEqual(calls,[])

if __name__=='__main__':unittest.main(verbosity=2)
