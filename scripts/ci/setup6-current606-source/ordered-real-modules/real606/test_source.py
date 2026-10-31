"""Focused source/adapter controls only; never native Docker/GPG/module execution."""
import copy,hashlib,json,os,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import guard as G,latest_plan as P,integration as I,latest_graph_scope as GRAPH,latest_restoration as R,transaction_adapter as T
class Controls(unittest.TestCase):
 def test_whole_original608_and_closed_source(self):
  fact=G.verify();self.assertEqual(fact['original_files'],608);self.assertIsNone(fact['actual']);self.assertEqual(fact['bounds']['owner'],9600)
 def test_real_source_only_normal_runner_closure_and_whole240(self):
  anchor=G.anchor();P0,A,X,C=anchor.source_context(G.ROOT)
  with tempfile.TemporaryDirectory()as temp:
   runner,old=X.emit_runner(P0.ROOT,Path(temp)/'runner');before=(runner/'tools606.py').read_bytes();ledger=I.stage_runner(G,P0,runner);self.assertEqual(ledger['expected_graphs'],15);self.assertEqual(ledger['expected_real_suites'],4);self.assertEqual(G.files(runner/'setup240'),G.files(G.ROOT/'setup240'))
   text=(runner/'tools606.py').read_text()
   for a,b in reversed(I.NATIVE_EDITS):text=text.replace(b,a)
   self.assertEqual(text.encode(),before)
   for relative in('copyworker/held-copy/scripts/update/supervision.py','copyworker/held-copy/scripts/install/local_transaction.py','copyworker/held-copy/scripts/update/full_root.py','setup240/scripts/ci/setup6-real-modules/installed.py','setup240/scripts/ci/setup6-real-modules/real_recovery.py'):self.assertTrue((runner/relative).is_file())
 def test_whole_owner_and_validator_inverses_keep_caps_and_cleanup(self):
  anchor=G.anchor();P0,A,X,C=anchor.source_context(G.ROOT);old=A.owner(P0.ROOT);text=I.owner_program(old)
  for a,b in reversed(I.OWNER_EDITS):text=text.replace(b,a,1)
  self.assertEqual(text,old);actual=I.owner_program(old);self.assertIn('active.process.wait(timeout=4800)',actual);self.assertIn('signal.setitimer(signal.ITIMER_REAL,9600)',actual);self.assertEqual(actual.count('cap-add='),old.count('cap-add='));self.assertNotIn('--privileged',actual);I.bridge_program((P0.HERE/'bridge606.py').read_text())
 def test_complete_original_signed_transaction_inverse(self):
  raw=(G.HERE/'held/alpm_step.py').read_bytes();pin=G.pin(raw);text=T.derive(raw,pin)
  for a,b in reversed(T.EDITS):text=text.replace(b,a,1)
  self.assertEqual(text.encode(),raw)
  for token in('deny_exec()','alpm_trans_prepare','alpm_trans_commit','--no-auto-key-retrieve','REVKEYSIG','NO_PUBKEY') :self.assertIn(token,text)
 def test_exact_all_other605_versions_and_source_bounded_phases(self):
  base=dict(line.split()for line in(G.ROOT/'copyworker/scripts/ci/current606-doctor2-copy/expected606.lock').read_text().splitlines());steps=P.transitions(base);self.assertEqual([r['phase']for r in steps],[n for n,_ in P.PHASES]);self.assertEqual(len(steps),7);self.assertEqual(steps[-1]['after'],base);self.assertEqual(sum(r['version']=='0.1.0-6'for r in steps),4)
  changed=dict(base);changed['cachy-asahi-apps']='0.1.0-7'
  with self.assertRaises(ValueError):P.transitions(changed)
 def test_full_graph_selected_scope_refuses_foreign_paths_and_mutation(self):
  paths={'setup':dict(files=['usr/bin/cachy-asahi-setup','usr/bin/cachy-asahi-repository'],directories=[])};scope=GRAPH.bind((G.HERE/'held/package_graph.py').read_bytes(),paths,'setup');selected='usr/bin/cachy-asahi-setup';protected='etc/pacman.conf';before=dict(scope='COMPLETE_PACKAGE_PAYLOAD_RAW_DB_KNOWN_ANCESTRY_PLUS_ETC_HOME_ROOT_NOT_WHOLE_ROOT',packages=[{'name':'other','version':'1'}],nodes={n:dict(kind='file',sha256='a'*64)for n in(selected,protected)},hardlinks=[]);after=copy.deepcopy(before);after['nodes'][selected]['sha256']='b'*64;self.assertEqual(GRAPH.protected(scope,before,after,None)['status'],'PROTECTED_KNOWN606_GRAPH_HELD')
  after['nodes'][protected]['sha256']='c'*64
  with self.assertRaises(ValueError):GRAPH.protected(scope,before,after,None)
  paths['setup']['files'].append('etc/pacman.conf')
  with self.assertRaises(ValueError):GRAPH.paths(paths)
 def test_full_raw_desc_only_actual_restoring_install_date_can_change(self):
  before=b'%NAME%\ncachy-asahi-setup\n\n%INSTALLDATE%\n100\n\n%VERSION%\n0.1.0-5\n\n';after=before.replace(b'100',b'200');clock=dict(authority='SOURCE_OWNED_TRANSACTION_WALLCLOCK_NOT_ROOT_OBSERVATION',start_seconds=199,end_seconds=201,monotonic_seconds=.1);R.desc(before,after,clock)
  with self.assertRaises(ValueError):R.desc(before,after.replace(b'0.1.0-5',b'0.1.0-6'),clock)
  with self.assertRaises(ValueError):R.desc(before,after,dict(clock,start_seconds=201))
 def test_whole_sign_function_with_original_module_closure_and_inert_gpg(self):
  anchor=G.anchor();_,_,_,C=anchor.source_context(G.ROOT);module=C.scoped_load('_full606_original_signer',G.ROOT/'held606/held604/scripts/ci/expanded600-installer-vm/materializer.py',{'contract':C});calls=[]
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);home=root/'home';home.mkdir(mode=0o700);archive=root/'inert';archive.write_bytes(b'SOURCE_ONLY_NO_PACKAGE');fingerprint='A'*40
   with patch.object(module.subprocess,'check_output',return_value='fpr:::::::::'+fingerprint+':\n'),patch.object(module.subprocess,'run',side_effect=lambda argv,**kw:(calls.append((argv,kw))or types.SimpleNamespace(returncode=0))):module.sign(home,[archive],fingerprint)
  self.assertEqual(len(calls),2);self.assertIn('--detach-sign',calls[0][0]);self.assertEqual(calls[0][1]['timeout'],30);self.assertEqual(calls[1][0][0],'gpgconf')
 def test_complete_prepare_and_export_callers_with_inert_producer_boundaries(self):
  anchor=G.anchor();context=anchor.source_context(G.ROOT);P0,A,X,C=context;obj=I.Integration(G,anchor,context,Path('/inert-runtime'),Path('/inert-setup'));obj.nonce='a'*32
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);tools=root/'tools606';runner=root/'runner';calls=[]
   def old_prepare(*args):
    out=args[2];obj.prepare_nonce(out);plan=out/'plan';plan.mkdir(mode=0o700);[(plan/n).write_text('{}\n')for n in('original-payload.json','original587-manifest.json','target604-manifest.json','initial14-payload.json','predecessor-payload.json','plan.json','expected587.lock','expected604.lock','selection.json')];tools.mkdir();X.emit_runner(P0.ROOT,runner);return tools,runner
   def candidate(**kw):
    calls.append(kw);out=kw['output'];out.mkdir();products={k:dict(path='/runner/inputs/archives/'+k,signature=dict(path='/runner/inputs/archives/'+k+'.sig'))for k in('original1','new2')};(out/'lifecycle-plan.json').write_bytes(C.encoded(dict(**products,original606_manifest={})));return out
   with patch.object(X,'prepare',side_effect=old_prepare),patch.object(anchor.builds,'doctor',side_effect=candidate):actual=obj.prepare(P0.ROOT,root/'producer',root,None,root/'ready',C)
   self.assertEqual(actual,(tools,runner));self.assertEqual(calls[0]['root'],G.ROOT);plan=json.loads((tools/'setup6/native-plan.json').read_bytes());self.assertEqual(plan['nonce'],obj.nonce)
   for value in plan['products'].values():self.assertTrue(value['path'].startswith('/tools606/setup6/archives/'));self.assertTrue(value['signature']['path'].startswith('/tools606/setup6/archives/'))
   container=root/'container';container.mkdir()
   for name in('setup6-progress.json','setup6-error.json','setup6-graph-timing.json','setup6-full606.json'):(container/name).write_text('{}')
   exported=obj.export_names(root)
   for name in('container/setup6-progress.json','container/setup6-error.json','container/setup6-graph-timing.json','container/setup6-full606.json','tools606/setup6/native-plan.json','tools606/setup6-runner-derivation.json'):self.assertIn(name,exported)
   report=dict(status='FAIL');obj.prepare_export(root,report);self.assertEqual(report['tools606_scope']['other603_physical_preservation'],'UNKNOWN');self.assertEqual(report['native_acceptance'],'REQUIRES_FULL_REPLAY_AND_ROOT_DECISION')
 def test_full_original_real240_gate_and_finite_receipt_shape_refusals(self):
  from validate import validate
  anchor=G.anchor();_,_,_,C=anchor.source_context(G.ROOT);SC=C.load('_real240_unchanged_gate',G.ROOT/'setup240/scripts/ci/setup6-real-modules/contract.py');real=json.loads((G.HERE/'controls/original581-real-modules.json').read_bytes());SC.validate_real(real)
  events=[]
  for phase,version in P.PHASES:events.append(dict(phase=phase,version=version,count=605 if version is None else 606,other605_physical_preservation=dict(status='PROTECTED_KNOWN606_GRAPH_HELD',whole_root=False),private_registries_preserved=True,fixture_graph_unchanged=True,process=dict(returncode=0,termination=None,direct_child_reaped=True,group_retired=True),transaction=dict(status='COMMITTED_NATIVE_SETUP6_REQUIRES_FULL_READBACK',signature='REQUIRED_TEST_ONLY',hooks='DISABLED',scriptlets='DISABLED'),real_modules=copy.deepcopy(real)if version=='0.1.0-6'else None))
  phases=['baseline5',*(phase for phase,_ in P.PHASES for _ in range(2))];graphs=[dict(sequence=i,phase=phase,state='COMPLETE',nodes=1,bytes_read=1,graph_sha256='a'*64,started=i*2,seconds=1)for i,phase in enumerate(phases)]
  # Deliberately synthetic timing/process DATA around an authentic old581 receipt;
  # this controls only the pure shape gate and creates no new606 evidence.
  value=dict(status='PASS_NATIVE_FULL606_SETUP6_REAL_MODULES_REQUIRES_REPLAY',nonce='a'*32,base_count=606,counts=[606,606,606,606,606,605,606,606],other605_physical_preservation=True,real_modules_suites=4,selected_inode_restoration='NOT_CLAIMED',events=events,graphs=graphs,ldconfig=[dict(phase=p)for p in['baseline5',*[n for n,_ in P.PHASES]]],Apps7_coexistence='NOT_RUN_BASELINE_APPS6',notification_delivery='NOT_RUN',notification_scope='PRIVATE_NOTIFY_SEND_RECORDER_ONLY',audio='NOT_RUN',GUI='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED',performance='NOT_CLAIMED');validate(value,'a'*32,SC.validate_real)
  for mutate in(lambda v:v['events'][0]['real_modules']['cases'].pop('fish-request-forward'),lambda v:v['graphs'].pop(),lambda v:v['events'][0]['real_modules']['security'].update(CapBnd='00000000800400db'),lambda v:v.update(notification_delivery='PASS'),lambda v:v['events'][0]['process'].update(group_retired=False)):
   changed=copy.deepcopy(value);mutate(changed)
   with self.assertRaises(ValueError):validate(changed,'a'*32,SC.validate_real)
 def test_complete_original606_typed_validator_on_authentic_old_data(self):
  anchor=G.anchor();context=anchor.source_context(G.ROOT);obj=I.Integration(G,anchor,context,Path('/inert-runtime'),Path('/inert-setup'));value=json.loads((G.HERE/'controls/original606-tools.json').read_bytes());context[2].validate(value)
  for event in value['events']:event['other603_physical_preservation']=event.pop('all604_preserved');event['selected_setup_domain']='EXACT_TYPED_ALPM_REQUIRES_FULL_SETUP5_RESTORATION'
  obj.validate(value);broken=copy.deepcopy(value);broken['events'][0]['observations'][0]['products'][context[0].ROLES[0]]['controls']=26
  with self.assertRaises(ValueError):obj.validate(broken)
 def test_actual_isolated_new_entries_and_source_preflight(self):
  for entry in('run.py','prepare.py','step_entry.py','ordinary_entry.py'):
   row=subprocess.run([sys.executable,'-I','-B',str(G.HERE/entry),'--help'],capture_output=True,timeout=10);self.assertEqual(row.returncode,0,row.stderr)
  row=subprocess.run([sys.executable,'-I','-B',str(G.HERE/'run.py'),'--source-preflight'],capture_output=True,timeout=30);self.assertEqual(row.returncode,0,row.stderr);self.assertIsNone(json.loads(row.stdout)['actual'])
if __name__=='__main__':unittest.main(verbosity=2)
