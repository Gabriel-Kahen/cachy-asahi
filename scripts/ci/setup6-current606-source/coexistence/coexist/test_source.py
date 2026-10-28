"""Focused portable coexistence source controls; no native/installed acceptance."""
import copy,hashlib,json,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import guard as G,latest_plan as P,integration as I,latest_graph_scope as GRAPH,latest_restoration as R,transaction_adapter as T,coexist_inputs as INPUTS
class Controls(unittest.TestCase):
 def base(self):return dict(line.split()for line in(G.ROOT/'copyworker/scripts/ci/current606-doctor2-copy/expected606.lock').read_text().splitlines())
 def test_published636_whole_608_ancestry_and_null_actual(self):
  fact=G.verify();self.assertEqual(fact['parent_files'],636);self.assertEqual(fact['original_files'],608);self.assertIsNone(fact['actual']);p=json.loads((G.HERE/'parent636.json').read_bytes());self.assertEqual(p['publication']['source'],'a8eb556eed8813762b2ad50598741a2e3d51a022');self.assertEqual(fact['bounds']['consumer'],1800+fact['bounds']['component'])
 def test_fourteen_one_package_steps_full604_and_final_original606(self):
  base=self.base();steps=P.transitions(base);self.assertEqual(len(steps),14);self.assertEqual(steps[-1]['after'],base);self.assertEqual(1+2*len(steps),29);self.assertEqual(sum(s['real_setup']for s in steps),4)
  for step in steps:
   name=step['name'];self.assertEqual({k:v for k,v in step['before'].items()if k!=name},{k:v for k,v in step['after'].items()if k!=name});self.assertEqual(step['after']['cachy-asahi-repository-runtime'],'0.1.0-1')
   if step['real_setup']:self.assertEqual((step['after']['cachy-asahi-apps'],step['after']['cachy-asahi-setup']),('0.1.0-7','0.1.0-6'))
  drift=dict(base);drift['cachy-asahi-apps']='0.1.0-7'
  with self.assertRaises(ValueError):P.transitions(drift)
 def test_whole_signed_primitive_two_exact_roles_and_noexec_security_held(self):
  raw=(G.HERE/'held/alpm_step.py').read_bytes();wanted=G.pin(raw)
  for role,name,old,new in P.PRODUCTS:
   text=T.derive(raw,wanted,role);self.assertIn('NAME='+repr(name),text)
   for token in('deny_exec()','alpm_trans_prepare','alpm_trans_commit','REVKEYSIG','NO_PUBKEY','exact other605 versions held'):self.assertIn(token,text)
   compile(text,'<native-source-only>','exec')
  with self.assertRaises(ValueError):T.derive(raw,wanted,'foreign')
  with self.assertRaises(ValueError):T.derive(raw+b'\n',wanted,'apps')
 def test_selected_graph_protects_other_selected_tool_and_all604(self):
  paths={'apps':dict(files=['usr/bin/cachy-asahi-apps'],directories=[]),'setup':dict(files=['usr/bin/cachy-asahi-setup'],directories=[])};raw=(G.HERE/'held/package_graph.py').read_bytes();scope=GRAPH.bind(raw,paths,'apps');before=dict(scope='COMPLETE_PACKAGE_PAYLOAD_RAW_DB_KNOWN_ANCESTRY_PLUS_ETC_HOME_ROOT_NOT_WHOLE_ROOT',packages=[{'name':'protected','version':'1'}],nodes={n:dict(kind='file',sha256='a'*64)for n in('usr/bin/cachy-asahi-apps','usr/bin/cachy-asahi-setup','etc/pacman.conf')},hardlinks=[]);after=copy.deepcopy(before);after['nodes']['usr/bin/cachy-asahi-apps']['sha256']='b'*64;GRAPH.protected(scope,before,after,None)
  for path in('usr/bin/cachy-asahi-setup','etc/pacman.conf'):
   drift=copy.deepcopy(after);drift['nodes'][path]['sha256']='b'*64
   with self.assertRaises(ValueError):GRAPH.protected(scope,before,drift,None)
  paths['apps']['files'].append('etc/pacman.conf')
  with self.assertRaises(ValueError):GRAPH.paths(paths)
 def test_same_original_owner_caps_cleanup_runner_and_unchanged_real240(self):
  anchor=G.anchor();P0,A,X,C=anchor.source_context(G.ROOT);old=A.owner(P0.ROOT);text=I.owner_program(old)
  for a,b in reversed(I.OWNER_EDITS):text=text.replace(b,a,1)
  self.assertEqual(text,old);self.assertNotIn('--privileged',I.owner_program(old));self.assertIn('active.process.wait(timeout=9000)',I.owner_program(old));self.assertIn('signal.setitimer(signal.ITIMER_REAL,13800)',I.owner_program(old))
  with tempfile.TemporaryDirectory()as tmp:
   runner,_=X.emit_runner(P0.ROOT,Path(tmp)/'runner');ledger=I.stage_runner(G,P0,runner);self.assertEqual(ledger['expected_graphs'],29);self.assertEqual(G.files(runner/'setup240'),G.files(G.ROOT/'setup240'));self.assertEqual((runner/'real606/apps_entry.py').read_bytes(),(G.HERE/'apps_entry.py').read_bytes())
 def test_real_public_apps7_packet_full_inspector_no_actor_or_new_signing(self):
  anchor=G.anchor();C,_,I0=anchor.builds.apis();packet=Path(__file__).resolve().parents[3]/'apps7-renewed-test-carrier-root-20261019/source/payload'
  if not packet.is_dir():
   import os
   packet=Path(os.environ['APPS7_PAIR_PACKET'])/'payload'
  with anchor.builds.aliases({'contract':C}):value=I0.legacy().inspect(packet)
  self.assertEqual(value['cachy-asahi-apps']['version'],'0.1.0-7');self.assertEqual(G.pin(value['cachy-asahi-apps']['path'].read_bytes()),dict(bytes=23212,sha256='23fc2fe5707606b0f3bd8c6322b9e7ae0c47a6ff1024cd239f4486679638be39'));self.assertEqual(value['cachy-asahi-repository-runtime']['version'],'0.1.0-1')
 def test_nonce_projection_and_exact_new_workflow_transport_policy(self):
  anchor=G.anchor();context=anchor.source_context(G.ROOT);obj=I.Integration(G,anchor,context,Path('/inert-apps'),Path('/inert-setup'))
  with tempfile.TemporaryDirectory()as tmp:
   out=Path(tmp);obj.prepare_nonce(out);self.assertEqual((out/'plan/bridge-selection.json').read_bytes(),(out/'setup6-selection.json').read_bytes());value=json.loads((out/'setup6-selection.json').read_bytes());self.assertEqual(value['nonce'],obj.nonce);self.assertTrue(all(value[k]is None for k in('actual_source','actual_ref','actual_run')))
  policy=json.loads((G.HERE/'transport-policy.json').read_bytes());self.assertEqual(policy['workflow_name'],'native-arm-current606-setup6-apps7-coexistence');self.assertEqual(policy['nonce_path'],'plan/bridge-selection.json');workflow=(G.ROOT/'.github/workflows/native-arm-build.yml').read_text();self.assertIn('expanded604-code/coexist/transport-policy.json',workflow);self.assertIn('13860s',workflow)
 def test_full_prepare_caller_routes_both_exact_domains_and_shared_nonce(self):
  anchor=G.anchor();context=anchor.source_context(G.ROOT);P0,A,X,C=context;obj=I.Integration(G,anchor,context,Path('/inert-apps'),Path('/inert-setup'));obj.nonce='a'*32
  with tempfile.TemporaryDirectory()as tmp:
   out=Path(tmp);tools=out/'tools606';runner=out/'runner'
   def old_prepare(*args):tools.mkdir();X.emit_runner(P0.ROOT,runner);return tools,runner
   def pair(old,new):return{k:dict(path='/runner/inputs/archives/'+k,signature=dict(path='/runner/inputs/archives/'+k+'.sig'))for k in(old,new)}
   def setup(**kw):
    target=kw['output'];target.mkdir();(target/'lifecycle-plan.json').write_bytes(C.encoded(dict(**pair('original1','new2'),original606_manifest={})) );return target
   def apps(*args):
    args[4].mkdir();return pair('original6','new7')
   with patch.object(X,'prepare',side_effect=old_prepare),patch.object(anchor.builds,'doctor',side_effect=setup),patch.object(INPUTS,'make',side_effect=apps):actual=obj.prepare(P0.ROOT,out/'producer',out,None,out/'ready',C)
   self.assertEqual(actual,(tools,runner));plan=json.loads((tools/'setup6/native-plan.json').read_bytes());self.assertEqual(set(plan['products']),{'apps','setup'});self.assertEqual(plan['nonce'],obj.nonce)
   for role,products in plan['products'].items():
    self.assertEqual(set(products),{'original','new'})
    for product in products.values():self.assertTrue(product['path'].startswith('/tools606/'+('apps7'if role=='apps'else'setup6')+'/archives/'))
 def test_typed_full_joint_receipt_missing_caps_graph_or_other_tool_refuses(self):
  from validate import validate
  anchor=G.anchor();_,_,_,C=anchor.source_context(G.ROOT);SC=C.load('_coexist_whole_setup240_gate',G.ROOT/'setup240/scripts/ci/setup6-real-modules/contract.py');real=json.loads((G.HERE/'controls/original581-real-modules.json').read_bytes());SC.validate_real(real);base=self.base();steps=P.transitions(base);events=[]
  retired=dict(returncode=0,termination=None,direct_child_reaped=True,group_retired=True)
  for step in steps:
   apps=None
   if step['after'].get('cachy-asahi-apps')=='0.1.0-7':
    control=dict(status='PASS_INSTALLED_CONTROLS',mode='apps',tests=15,failures=0,errors=0,skipped=0,installed_source=True,report_bytes=10,report_sha256='a'*64);home=dict(CLI=2,inventory_count=len(step['after']),inventory_versions_sha256=hashlib.sha256(P.inventory_bytes(step['after'])).hexdigest(),installed_controls=control,user_config_preserved=True);apps=dict(status='PASS_ACTUAL_NATIVE_APPS7_BOTH_HOMES',homes={k:copy.deepcopy(home)for k in('fresh','existing')},zero_capabilities=True,NNP=1,CapBnd='00000000000000db',applied='NOT_APPLIED')
   events.append(dict(phase=step['phase'],acted_role=step['role'],version=step['version'],count=len(step['after']),other604_physical_preservation=dict(status='PROTECTED_KNOWN606_GRAPH_HELD',whole_root=False),private_registries_preserved=True,fixture_graph_unchanged=True,process=dict(retired),transaction=dict(status='COMMITTED_NATIVE_APPS7_SETUP6_REQUIRES_FULL_READBACK',before_count=len(step['before']),after_count=len(step['after']),signature='REQUIRED_TEST_ONLY',hooks='DISABLED',scriptlets='DISABLED'),real_modules=copy.deepcopy(real)if step['real_setup']else None,Apps7=apps,Apps7_process=dict(retired)if apps else None))
  phases=['baseline-original606',*(e['phase']for e in events for _ in range(2))];value=dict(status='PASS_NATIVE_FULL606_APPS7_SETUP6_COEXISTENCE_REQUIRES_REPLAY',nonce='a'*32,base_count=606,counts=[606,*[len(x['after'])for x in steps]],other604_physical_preservation=True,real_modules_suites=4,selected_inode_restoration='NOT_CLAIMED',events=events,graphs=[dict(sequence=i,phase=phase,state='COMPLETE',nodes=1,bytes_read=1,graph_sha256='a'*64,started=i*2,seconds=1)for i,phase in enumerate(phases)],ldconfig=[dict(phase=p)for p in['baseline-original606',*[s['phase']for s in steps]]],Apps7_coexistence='ACTUAL_INSTALLED_CLI_AND15_CONTROLS_BOTH_HOMES_REQUIRES_REPLAY',notification_delivery='NOT_RUN',notification_scope='PRIVATE_NOTIFY_SEND_RECORDER_ONLY',audio='NOT_RUN',GUI='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED',performance='NOT_CLAIMED')
  # Synthetic timing/process DATA around one authentic old581 fixture receipt;
  # never emitted as a new606 positive or used by a native acceptance reader.
  validate(value,'a'*32,SC.validate_real,base)
  for mutate in(lambda v:v['events'][0]['Apps7'].update(NNP=0),lambda v:v['graphs'].pop(),lambda v:v['events'][0]['Apps7']['homes']['existing'].update(inventory_versions_sha256='0'*64),lambda v:v['events'][1]['real_modules']['cases'].pop('fish-request-forward'),lambda v:v['events'][0]['transaction'].update(hooks='ENABLED'),lambda v:v.update(other604_physical_preservation=False)):
   drift=copy.deepcopy(value);mutate(drift)
   with self.assertRaises(ValueError):validate(drift,'a'*32,SC.validate_real,base)
 def test_actual_isolated_entry_help_and_full_source_route_only(self):
  for name in('run.py','prepare.py','step_entry.py','ordinary_entry.py','apps_entry.py'):
   r=subprocess.run([sys.executable,'-I','-B',str(G.HERE/name),'--help'],capture_output=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr)
  r=subprocess.run([sys.executable,'-I','-B',str(G.HERE/'run.py'),'--source-preflight'],capture_output=True,timeout=30);self.assertEqual(r.returncode,0,r.stderr);self.assertIsNone(json.loads(r.stdout)['actual'])
if __name__=='__main__':unittest.main(verbosity=2)
