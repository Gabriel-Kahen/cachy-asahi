"""Private source-only controls; no ALPM/native/source-entry actor is run."""
import ast,copy,hashlib,importlib.util,json,os,signal,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
import argparse
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[3]);args,remaining=p.parse_known_args();sys.argv=[sys.argv[0],*remaining]
D=Path(__file__).resolve().parent;ROOT=args.source.resolve();sys.path.insert(0,str(D));import interruption_case as I
spec=importlib.util.spec_from_file_location('fixed_case',ROOT/'scripts/ci/gnu-immutable-source-native/fixed_case.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
POLICY=dict(source=json.loads((D/'interruption-profile.json').read_bytes())['before'])
def tree():
 values={p.relative_to(ROOT).as_posix():p.read_bytes()for p in(ROOT/'runtime').rglob('*')if p.is_file()};assert{n:I.pin(b)for n,b in values.items()}=={n:w for n,w in POLICY['source'].items()if n.startswith('runtime/')};return{n[8:]:b for n,b in values.items()}
BASE=tree()
def load_checkpoint():
 raw=BASE[I.CHECKPOINT];m=types.ModuleType('_private_exact_remove_control');m.__file__='<SOURCE_PRIVATE_REMOVE_CONTROL>'
 def need(ok,why):
  if not ok:raise ValueError(why)
 m.C=types.SimpleNamespace(need=need,NAME='SYNTHETIC_PRIVATE_PROVIDER',VERSION='1',CACHES=set(),sha=lambda b:hashlib.sha256(b).hexdigest(),read=lambda p,cap:Path(p).read_bytes())
 assert raw.count(b'import common as C\n')==1;exec(compile(raw.replace(b'import common as C\n',b'',1),m.__file__,'exec'),vars(m));return m
class Controls(unittest.TestCase):
 def test_normal_both_and_selected_outputs_exact_and_whole_interruption_inverse(self):
  self.assertEqual(I.render(BASE,'both',F,operation='normal'),F.render(BASE,'both'))
  for case in I.CASES:
   normal,unused=F.render(BASE,case);self.assertEqual(I.render(BASE,case,F,operation='normal'),F.render(BASE,case));after,ledger=I.render(BASE,case,F);back=I.inverse(after,ledger);back['runtime-source.json']=normal['runtime-source.json'];self.assertEqual(back,normal);self.assertEqual(set(after),set(BASE));self.assertEqual(len(after),667)
   self.assertEqual(json.loads(after['runtime-source.json'])['files'],{n:I.pin(b)for n,b in after.items()if n!='runtime-source.json'})
   self.assertEqual(after[I.CHECKPOINT],BASE[I.CHECKPOINT]);self.assertEqual(after['immutable/runtime_policy.py'],normal['immutable/runtime_policy.py']);self.assertEqual(after['immutable/bootstrap_loader.py'],normal['immutable/bootstrap_loader.py']);self.assertEqual(after['immutable/service.py'],normal['immutable/service.py'])
   for name in ledger:compile(after[name],name,'exec')
  for case,op in(('both','remove-interruption'),('foreign','remove-interruption'),('pristine','foreign')):
   with self.assertRaises(ValueError):I.render(BASE,case,F,op)
 def test_actual_generated16k_lifecycle_binding_function_bodies_and_clocks(self):
  for case in I.CASES:
   after,_=I.render(BASE,case,F);text=after['immutable/worker.py'].decode();tree=ast.parse(text);wanted={'REMOVE_OPERANDS','REMOVE_PROFILE','REMOVE_CHECKPOINT'};nodes=[n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id in wanted for t in n.targets)or isinstance(n,ast.FunctionDef)and n.name=='remove_interruption_lifecycle'];space=dict(ast=ast,P=I);exec(compile(ast.Module(body=nodes,type_ignores=[]),'<EXACT_RENDERED_REMOVE_LIFECYCLE>','exec'),space)
   raw=BASE[I.NATIVE].decode();rules=[("sys.path.insert(0,str(Path(__file__).resolve().parent))","sys.path.insert(0,'/runner')"),("results[0]['page_size']==4096","results[0]['page_size']==16384"),("Path('/.dockerenv').is_file()","os.sysconf('SC_PAGE_SIZE')==16384 and 'caa_debian_maintained_installed16k=1' in Path('/proc/cmdline').read_text().split()"),("'actual generic4K runtime result'","'actual generic16K runtime result'"),("report['proc_preflight']['status']=='PASS_READONLY_PROC_PREFLIGHT' and report['proc_preflight']['cleanup']=='PASS_OWNED_EMPTY_PROBE_REMOVED'","report['proc_preflight']['status']=='PASS_PID1_READONLY_PROC_PREFLIGHT' and report['proc_preflight']['cleanup']=='PASS_PID1_OWNED_PROBE_REMOVED'")]
   for a,b in rules:self.assertEqual(raw.count(a),1);raw=raw.replace(a,b,1)
   changed=space['remove_interruption_lifecycle'](raw);a,b=I.functions(raw.encode()),I.functions(changed.encode());self.assertEqual({n for n in a if a[n]!=b[n]},{'transaction','run_case','main'});self.assertEqual(a['config_handoff'],b['config_handoff']);self.assertEqual(a['validate_runtime'],b['validate_runtime']);self.assertIn('==16384',b['validate_runtime']);self.assertIn('GNU_SELECTED_INTERRUPTION',b['run_case']);self.assertEqual(b['run_case'].count('config_handoff('),3)
   with self.assertRaises(ValueError):space['remove_interruption_lifecycle'](raw.replace('def transaction(', 'def foreign_transaction(',1))
 def test_real_owned_stop_kill_and_fd_lock_retirement_private_fixture(self):
  m=load_checkpoint()
  with tempfile.TemporaryDirectory(prefix='gnu-remove-private-')as td:
   root=Path(td);(root/'usr').mkdir();(root/'usr/removed').write_bytes(b'old');(root/'usr/remaining').write_bytes(b'held');(root/'var/lib/pacman').mkdir(parents=True);lock=root/m.LOCK;point=dict(removed='usr/removed',remaining='usr/remaining',remaining_sha256=hashlib.sha256(b'held').hexdigest());report={}
   class Setter:
    def __call__(self,handle,callback,data):self.callback=callback;return 0
   setter=Setter();alpm=types.SimpleNamespace(lib=types.SimpleNamespace(alpm_option_set_progresscb=setter),handle=None,ok=lambda code,label:m.C.need(code==0,label))
   def transaction(api,where,archive,remove,add,log,progress):
    self.assertEqual((where,remove,add),(root,'glibc',m.C.NAME));lock.write_bytes(b'');lock.chmod(0);progress.bind(alpm);progress.prepared=dict(prepared_add={m.C.NAME:m.C.VERSION},prepared_remove={'glibc':'old'},dependencies='PASS_ALPM_PREPARE',commit_started=True,observer_root='INTACT_OUTER_HELD574',hooks='DISABLED',scriptlets='DISABLED_EXPLICIT_HELD_POST_UPGRADE_LATER');progress.armed=True;(root/point['removed']).unlink();setter.callback(None,4,b'glibc',10,1,1);raise AssertionError('stopped callback must not return')
   lane=types.SimpleNamespace(transaction=transaction,INPUTS=root,OUT=root)
   # UID1000 host fixture cannot assert root ownership; only this private control
   # substitutes that one root-only lock classification. Product body stays exact.
   identity=lambda where:m.identity((where/m.LOCK).lstat())
   with patch.object(m,'lock_identity',side_effect=identity):
    checkpoint=m.stop_and_kill({},lane,root,dict(archives={'a':dict(path='synthetic')}),point,'pristine',report);self.assertEqual(report['writer']['exit_code'],-signal.SIGKILL);self.assertTrue(report['writer']['group_absence_verified']);self.assertEqual(report['observed_stop'],'KERNEL_CLD_STOPPED_SIGSTOP_WITH_UNREAPED_OWNED_LEADER');self.assertFalse((root/point['removed']).exists())
    with self.assertRaises(ValueError):m.clear_owned_lock(root,checkpoint['lock'],dict(group_absence_verified=False,exit_code=-9))
    held=lock.with_name('original-lock');lock.rename(held);lock.write_bytes(b'');lock.chmod(0)
    with self.assertRaises(ValueError):m.clear_owned_lock(root,checkpoint['lock'],report['writer'])
    lock.unlink();held.rename(lock)
    with self.assertRaises(ValueError):m.clear_owned_lock(root,checkpoint['lock'],report['writer']) # rename changes ctime, even same inode/bytes
    fresh=identity(root);self.assertEqual(m.clear_owned_lock(root,fresh,report['writer'])['status'],'PASS_EXACT_OWNED_STALE_LOCK_REMOVED_AFTER_GROUP_ABSENCE');self.assertFalse(lock.exists())
   with self.assertRaises(ProcessLookupError):os.kill(report['writer']['pid'],0)
 def test_original_lock_and_checkpoint_foreign_shapes_refuse(self):
  m=load_checkpoint()
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);(root/'var/lib/pacman').mkdir(parents=True);lock=root/m.LOCK;lock.write_bytes(b'');lock.chmod(0)
   with self.assertRaises(ValueError):m.lock_identity(root) # unprivileged host cannot satisfy original root:root
   lock.chmod(0o600);lock.write_bytes(b'foreign')
   with self.assertRaises(ValueError):m.lock_identity(root)
   for row in({},dict(type='CHECKPOINT'),dict(type='CHECKPOINT',extra=True)):
    with self.assertRaises(ValueError):m.validate_checkpoint(row,17,root,{})
 def test_checkpoint_source_and_all_three_modified_handoffs_remain_exact(self):
  after,ledger=I.render(BASE,'modified',F);worker=after['immutable/worker.py'];self.assertIn(b"'provider_config_handoff','rollback_config_prepare','rollback_config_handoff'",worker);self.assertIn(b'PASS_EXPLICIT_CLONE_CONFIG_HANDOFF',worker);self.assertIn(b'actual REMOVE callback/stop/kill/absence required',worker);self.assertEqual(after[I.INTERRUPTED],BASE[I.INTERRUPTED]);self.assertEqual(after[I.NATIVE],BASE[I.NATIVE]);self.assertEqual(after[I.CHECKPOINT],BASE[I.CHECKPOINT]);self.assertIn(b'==10',after['immutable/native_controller.py']);self.assertIn(b"retired['leases'] == 6",after['immutable/owner.py']);self.assertIn(b"('modified',)*5",after['immutable/leases.py']);self.assertNotIn(b'OLD_INTERRUPTION_ACCEPTED',worker)
if __name__=='__main__':unittest.main(verbosity=2)
