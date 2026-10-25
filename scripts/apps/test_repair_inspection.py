# SPDX-License-Identifier: MIT
"""Readonly source controls: real temporary files/flock, explicit auth/namespace models.

No actual signing, libalpm, namespace or full574/native acceptance is inferred.
"""
import copy,fcntl,hashlib,importlib.util,json,os,sys,tempfile,time,types,unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
BASE=Path(os.environ.get('APPS_REPAIR_SOURCE',ROOT))
def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
R=load('repair_inspection_control',HERE/'repair_inspection.py');T=load('repair_backend_control',BASE/'scripts/apps/transaction.py');M=load('repair_closure_control',BASE/'scripts/apps/full574_closure.py')
NS=types.SimpleNamespace
class Inspect(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='readonly-repair-unit-');self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name);self.workspace=self.base/'copy';self.workspace.mkdir(mode=0o700);self.root=self.workspace/'root';self.root.mkdir();self.events=[]
  self.stack=__import__('contextlib').ExitStack();self.addCleanup(self.stack.close)
  self.stack.enter_context(patch.object(R,'backend',return_value=T));self.stack.enter_context(patch.object(T,'commit',side_effect=AssertionError('commit forbidden')));self.stack.enter_context(patch.object(T.F,'Alpm',side_effect=AssertionError('ALPM handle forbidden')));self.stack.enter_context(patch.object(T.SUP.subprocess,'Popen',side_effect=AssertionError('all actors forbidden')))
 def nodes(self):
  return T.F.observe(self.root,limits=T.limits(),hardlinks='generic-development-internal')['nodes']
 def fixture(self):
  for n in ('usr/share','home/user','etc/pacman.d','var/lib/pacman/local/base-1'):(self.root/n).mkdir(parents=True,exist_ok=True)
  for n in ('home/user/note','etc/pacman.d/public','var/lib/pacman/local/base-1/desc'):(self.root/n).write_bytes(b'preserved source user trust db')
  self.seed=self.nodes();self.name='cachy-asahi-apps';self.leaf='usr/share/selected';target=self.root/self.leaf;target.write_bytes(b'expected source-bound selected file');nodes=self.nodes();self.payloads={self.name:{n:nodes[n] for n in ('usr','usr/share',self.leaf)}}
  self.inventory=dict(packages=[dict(name=r['name'],version=r['version']) for r in json.loads((BASE/'scripts/ci/maintained-desktop574-inputs.json').read_bytes())['packages']]+[dict(name=self.name,version=M.VERSIONS[self.name])])
  metadata=dict(name=self.name,version=M.VERSIONS[self.name],arch='any',depend=[],provides=[],conflict=[],replaces=[],files=[self.leaf]);before=dict(metadata,source='caller-installed-inventory',metadata_sha256=M.digest(metadata));after=dict(metadata,source='signed-release',metadata_sha256=M.digest(metadata),release_archive_sha256='b'*64)
  plan=dict(operation='reinstall',requested_packages=[self.name],reinstalls=[dict(before=before,after=after)],additions=[],upgrades=[],removals=[],dependencies=[],conflicts=[],unchanged_selected=[],before_inventory_sha256='d'*64,after_inventory_sha256='d'*64,repair_policy='EXPLICIT_SELECTED_SAME_VERSION_AND_METADATA_ONLY_NO_DEPENDENCY_EXPANSION')
  self.inventory['packages'][-1]=metadata
  plan['before_inventory_sha256']=plan['after_inventory_sha256']=T.sha(T.encoded(sorted(self.inventory['packages'],key=lambda row:row['name'])))
  self.fresh=dict(plan=plan,synthetic=True,binding={'unit_model':'NOT_CRYPTO_EVIDENCE'},helper_pins={});self.planfile=self.base/'plan.json';self.planfile.write_bytes(T.encoded(self.fresh));self.bundle=self.base/'release';(self.bundle/'repo').mkdir(parents=True);(self.bundle/'repo/pkg.tar').write_bytes(b'explicit inert archive model')
  self.context=dict(base={},spec={'policy':{'protected_packages':[]}},available={self.name:metadata},release=dict(packages=[dict(name=self.name,version=M.VERSIONS[self.name],sha256='b'*64,filename='pkg.tar')],files={'repo/pkg.tar':T.sha((self.bundle/'repo/pkg.tar').read_bytes())}))
  self.args=NS(operation='reinstall',workspace=str(self.workspace),plan=str(self.planfile),plan_sha256=T.sha(self.planfile.read_bytes()))
  self.closure=object.__new__(M.Adapter);self.closure.payloads=self.payloads;self.closure.policy=dict(candidates={self.name:dict(archive_sha256='b'*64)},source_capabilities={});self.closure.binding=dict(unit_model='NOT_NATIVE_LEASE_EVIDENCE');self.closure.comparator=None;self.closure.source_check=lambda:(dict(nodes=self.seed),{});self.closure.owner=lambda owner:self.events.append('owner')
  def observe(root,budget):
   self.events.append('measure');M.reinstall_nodes(self.seed,self.nodes(),self.payloads,self.closure.repair_names,self.closure.repair_installed);return dict(nodes=self.nodes())
  def capture(root,value):
   self.closure.baseline={};self.closure.baseline_caps={};self.closure.repair_damage=M.reinstall_nodes(self.seed,value['nodes'],self.payloads,self.closure.repair_names,self.closure.repair_installed)
  self.closure.observe=observe;self.closure.capture=capture;self.closure.archive=lambda *a:self.events.append('archive')
  self.owner=dict(source_tree_sha256=T.sha(T.encoded(self.seed)));self.stack.enter_context(patch.object(T,'root_guard',return_value=(self.workspace,self.root,self.owner)));self.stack.enter_context(patch.object(T,'limits',side_effect=lambda args=None:T.F.Limits(deadline=time.monotonic()+30)))
  self.stack.enter_context(patch.object(T,'closure_for',return_value=self.closure));self.stack.enter_context(patch.object(M,'unchanged',return_value=dict(status='INERT_AUXILIARY_MODEL_NOT_NATIVE')));self.stack.enter_context(patch.object(M.aux,'checkpoint',return_value={}));self.stack.enter_context(patch.object(M,'capability_map',return_value={}))
  @contextmanager
  def lock(workspace):
   p=workspace/'unit-lock';fd=os.open(p,os.O_RDWR|os.O_CREAT,0o600)
   try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.events.append('locked');yield
   finally:fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)
  self.stack.enter_context(patch.object(T,'locked',lock))
  @contextmanager
  def auth(args,c,r):self.events.append('authenticated-context');yield self.context
  def execute(args):self.events.append('authenticated-replan');return copy.deepcopy(self.fresh)
  app=NS(inventory_reader=lambda:NS(collect=lambda *a:copy.deepcopy(self.inventory)),encoded=T.encoded,indexed=lambda rows,r:{p['name']:dict(p) for p in rows},package=lambda p,r:{k:v for k,v in p.items() if k in ('name','version','arch','depend','provides','conflict','replaces','files')},execute=execute,authenticated=auth)
  c=T.B.client;r=NS(archive_members=lambda p:{'.PKGINFO':'.PKGINFO'},run=lambda argv:b'pkgname = explicit-inert-unit-model\n')
  self.stack.enter_context(patch.object(T,'app_source',return_value=(app,c,r)));self.stack.enter_context(patch.object(T,'snapshot_inputs',side_effect=lambda args,work,c:NS(**vars(args),release=str(self.bundle))));self.stack.enter_context(patch.object(T.I,'archive_payload',side_effect=lambda *a:copy.deepcopy(self.payloads[self.name])))
  target.write_bytes(b'actual damaged temp-file bytes');return target
 def test_live_host_refuses_before_auth_measure_or_alpm(self):
  args=NS(operation='reinstall')
  with patch.object(T.os,'getuid',return_value=1000),patch.object(T,'app_source',side_effect=AssertionError('auth reached')):result=R.inspect_reinstall(args)
  self.assertEqual(result['status'],'FAIL');self.assertFalse(result['commit_started']);self.assertFalse(result['packages_committed'])
 def test_explicit_reinstall_only(self):
  with patch.object(T,'root_guard',side_effect=AssertionError('root touched')):result=R.inspect_reinstall(NS(operation='install'))
  self.assertEqual(result['status'],'FAIL');self.assertIn('reinstall',result['error'])
 def test_actual_temp_damage_and_missing_pins_auth_precede_measurement(self):
  target=self.fixture()
  for missing in (False,True):
   if missing:target.unlink();self.closure.__dict__.pop('repair_names',None)
   self.events.clear();before=self.nodes();result=R.inspect_reinstall(self.args);self.assertEqual(result['status'],'INSPECTED_AUTHENTICATED_OWNED_FULL574_REINSTALL',result)
   self.assertEqual(result['before'],T.pins(dict(nodes=before),self.inventory));self.assertEqual(result['damage'],{self.leaf:before.get(self.leaf)});self.assertEqual(before,self.nodes());self.assertFalse(result['repair_authority']);self.assertFalse(result['packages_committed']);self.assertEqual(result['transaction'],'NOT_RUN');self.assertLess(self.events.index('authenticated-replan'),self.events.index('measure'));self.assertLess(self.events.index('authenticated-context'),self.events.index('measure'));self.assertEqual(list(self.workspace.glob('apps-repair-inspect-*')),[])
 def test_stale_plan_and_auth_failure_refuse_before_measure(self):
  self.fixture();self.args.plan_sha256='0'*64;result=R.inspect_reinstall(self.args);self.assertEqual(result['status'],'FAIL');self.assertNotIn('measure',self.events)
  self.args.plan_sha256=T.sha(self.planfile.read_bytes())
  with patch.object(T,'snapshot_inputs',side_effect=ValueError('signature authentication refused')):result=R.inspect_reinstall(self.args)
  self.assertEqual(result['status'],'FAIL');self.assertNotIn('measure',self.events)
 def test_foreign_lock_and_pending_marker_are_not_deleted(self):
  self.fixture()
  for p in (self.root/T.DB/'db.lck',self.workspace/'apps-pending.json'):
   p.write_bytes(b'foreign exact bytes');result=R.inspect_reinstall(self.args);self.assertEqual(result['status'],'FAIL');self.assertEqual(p.read_bytes(),b'foreign exact bytes');self.assertNotIn('measure',self.events);p.unlink()
 def test_unselected_user_trust_db_and_type_damage_refuse(self):
  target=self.fixture()
  for n in ('home/user/note','etc/pacman.d/public','var/lib/pacman/local/base-1/desc'):
   p=self.root/n;original=p.read_bytes();p.write_bytes(b'unselected drift');result=R.inspect_reinstall(self.args);self.assertEqual(result['status'],'FAIL');p.write_bytes(original);self.closure.__dict__.pop('repair_names',None)
  target.unlink();target.symlink_to('elsewhere');self.assertEqual(R.inspect_reinstall(self.args)['status'],'FAIL')
 def test_real_workspace_flock_exclusion(self):
  self.fixture();fd=os.open(self.workspace/'unit-lock',os.O_RDWR|os.O_CREAT,0o600)
  try:
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);result=R.inspect_reinstall(self.args);self.assertEqual(result['status'],'FAIL');self.assertEqual(result['error_type'],'BlockingIOError');self.assertNotIn('measure',self.events)
  finally:os.close(fd)
 def test_source_contains_no_alpm_or_mutation_entrypoint(self):
  text=(HERE/'repair_inspection.py').read_text();self.assertNotIn('T.commit(',text);self.assertNotIn('T.apply(',text);self.assertNotIn('T.B.transaction(',text);self.assertNotIn('unlink(',text);self.assertNotIn('write_bytes(',text[text.index('def inspect_reinstall'):]);self.assertIn('closure.authorize_reinstall(',text);self.assertIn('app.execute(copied)',text);self.assertIn('app.authenticated(copied,c,r)',text)
class Supervision(unittest.TestCase):
 def argv(self,workspace):
  result=['inspect-reinstall']
  for name in ('workspace','ownership-sha256','apps-source','apps-provenance-sha256','repository-source','full574-policy','full574-policy-sha256','full574-lease','full574-lease-sha256','release','release-sha256','catalog','catalog-sha256','catalog-signature','keyring','signer','plan','plan-sha256'):result+=['--'+name,str(workspace)]
  return result+['--applications','apps']
 def worker(self):return dict(status='INSPECTED_AUTHENTICATED_OWNED_FULL574_REINSTALL',commit_started=False,packages_committed=False,transaction='NOT_RUN')
 def run_main(self,root,row):
  import io
  capture=io.StringIO()
  with patch.object(R,'backend',return_value=T),patch.object(T,'root_guard',return_value=(root,root,{})),patch.object(T,'execution_seconds',return_value=600),patch.object(T.SUP,'run',return_value=row) as supervisor,patch('sys.stdout',capture):code=R.main(self.argv(root))
  return code,json.loads(capture.getvalue()),supervisor.call_args
 def test_exact600_worker_argv_output_and_reap_gates(self):
  with tempfile.TemporaryDirectory() as td:
   row=dict(returncode=0,termination=None,direct_child_reaped=True,group_kill_sent=True,stdout=T.encoded(self.worker()),stderr=b'');code,result,call=self.run_main(Path(td),row)
   self.assertEqual(code,0);self.assertEqual(call.kwargs['timeout'],600);self.assertEqual(call.kwargs['output_limit'],512*1024);self.assertEqual(call.kwargs['cwd'],td);self.assertEqual(call.args[0][-1],'--worker');self.assertEqual(call.args[0].count('--worker'),1);self.assertEqual(call.args[0][1:3],['-I','-B']);self.assertEqual(result['worker']['seconds'],600)
 def test_timeout_or_unreaped_or_wrong_status_cannot_export_positive(self):
  original=dict(returncode=0,termination=None,direct_child_reaped=True,group_kill_sent=True,stdout=T.encoded(self.worker()),stderr=b'')
  with tempfile.TemporaryDirectory() as td:
   for change in (dict(termination='timeout'),dict(direct_child_reaped=False),dict(group_kill_sent=False),dict(returncode=1),dict(stdout=T.encoded(dict(self.worker(),transaction='COMMITTED')))):
    code,result,_=self.run_main(Path(td),dict(original,**change));self.assertEqual(code,1);self.assertEqual(result['status'],'FAIL');self.assertNotIn('before',result)
 def test_owner_guard_precedes_spawn(self):
  import io
  with tempfile.TemporaryDirectory() as td,patch.object(R,'backend',return_value=T),patch.object(T,'root_guard',side_effect=ValueError('owner refused')),patch.object(T.SUP,'run',side_effect=AssertionError('spawn before guard')),patch('sys.stdout',io.StringIO()):self.assertEqual(R.main(self.argv(Path(td))),1)
 def test_real_short_owned_child_timeout_group_signal_and_reap(self):
  # Explicitly authorized small real subprocess; no crypto, ALPM or namespace.
  import signal
  with tempfile.TemporaryDirectory() as td:
   row=T.SUP.run([sys.executable,'-I','-c','import os,time;print(os.getpid(),flush=True);time.sleep(10)'],env={'PATH':'/usr/bin:/bin'},cwd=td,timeout=.15,grace=.05,output_limit=4096)
   self.assertEqual(row['termination'],'timeout');self.assertTrue(row['direct_child_reaped']);self.assertTrue(row['group_kill_sent']);pid=int(row['stdout']);self.assertLess(row['returncode'],0)
   with self.assertRaises(ProcessLookupError):os.killpg(pid,0)
if __name__=='__main__':unittest.main(verbosity=2)
