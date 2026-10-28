"""Inert fixture routing controls; --actual-packet tests genuine held archive data."""
import argparse,copy,json,os,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
F=C.load('held_payload_tests',C.HERE/'held_payloads.py');ROOT=C.HERE.parents[2]
class Controls(unittest.TestCase):
 def test_private_function_facade_does_not_mutate_original_globals(self):
  ns={};exec("def current():return {'original':1}\ndef original(self):self.payloads=current()",ns)
  original=ns['original'];clone=F.clone(original,dict(current=lambda:{'held':2}));a=types.SimpleNamespace();clone(a)
  self.assertEqual(a.payloads,{'held':2});self.assertIs(clone.__code__,original.__code__);b=types.SimpleNamespace();original(b);self.assertEqual(b.payloads,{'original':1})
 def test_supervisor_routes_only_exact_owned_child_without_resource_change(self):
  calls=[];T=types.SimpleNamespace(SUP=types.SimpleNamespace(run=lambda argv,**kw:calls.append((argv,kw))))
  original=T.SUP;F.supervisor(T,Path('/source/scripts/apps/transaction.py'),['/source/fixture.py']);argv=['python','-I','-B','/source/scripts/apps/transaction.py','apply','--worker'];options=dict(timeout=600,output_limit=1024**2,env={'original':'retained'},cwd='/work')
  T.SUP.run(argv,**options);self.assertEqual(calls[0],(['python','-I','-B','/source/fixture.py','apply','--worker'],options));self.assertIsNot(T.SUP,original)
  T.SUP.run(['python','-I','-B','/other.py'],**options);self.assertEqual(calls[1][0][-1],'/other.py');self.assertEqual(argv[3],'/source/scripts/apps/transaction.py')
 def test_backend_and_selected_routes_are_explicit_and_floor_source_unchanged(self):
  text=(C.HERE/'lifecycle.py').read_text();selected=(C.HERE/'selected_fixture.py').read_text();cancel=(C.HERE/'cancel.py').read_text();install=(C.HERE/'install_dependency.py').read_text()
  self.assertEqual(text.count("str(C.HERE/'selected_fixture.py'),'--staged-source',str(RULES)"),2);self.assertIn('F.calls(H,C)',text)
  self.assertLess(selected.index('stage.validate(C,a.staged_source)'),selected.index("a.staged_source/'scripts/orphans/selected.py'"));self.assertIn('selected.main(rest)',selected)
  self.assertLess(cancel.index('.configure(selected.T,C,a.staged_source)'),cancel.index('value=selected.apply('));self.assertIn('.configure(T,C,Path(\'/source\'))',install)
  self.assertNotIn('O.floor=',text+selected+cancel+install);self.assertNotIn('__file__=',selected)
 def test_emit_keeps_new_files_and_independent_concurrency(self):
  text=(C.HERE/'prepare.py').read_text();wf=(ROOT/'.github/workflows/native-arm-orphans-full574-cleanup.yml').read_text()
  for name in ('held_payloads.py','fixture_backend.py','selected_fixture.py','test_held_payloads.py'):self.assertIn(repr(name),text)
  self.assertIn('group: native-arm-orphans-full574-cleanup-${{ inputs.trial }}',wf);self.assertIn('cancel-in-progress: false',wf);self.assertIn('3550s',wf);self.assertIn('--actual-packet',wf)
 def test_materialize_and_bind_and_retention_derive_exact_original_seams(self):
  M=C.load('held_mode_derivation_test',C.HERE/'modes.py');raw=(ROOT/'scripts/ci/apps-full574-native/job.py').read_text()
  for mode in M.TRIALS:
   parts=M.derived(raw,mode);self.assertIn('return HELD.publish(C,args.source,output/\'inputs\',packet,payload,origins)',parts['materialize']);self.assertIn("module=C.adapter(root,output/'inputs')",parts['bind']);self.assertIn("'held-payloads.json'",parts['retain']);self.assertLess(parts['run'].index('packet=materialize('),parts['run'].index("row=reserve(report,args.output,'export')"))


def actual_control(packet_root):
 """Actual archive bytes, no source execution/build/ALPM or574 acceptance."""
 C.source(ROOT);packet,payload,origins=C.inputs(ROOT,packet_root)
 with tempfile.TemporaryDirectory(prefix='orphans-held-control-') as name:
  temp=Path(name);inputs=temp/'inputs';inputs.mkdir();(inputs/'archives').mkdir()
  (inputs/'native-index.json').write_bytes(C.checked(packet_root,C.policy()['packet_index']))
  for row in packet['packages'].values():(inputs/'archives'/Path(row['files']['a']['path']).name).write_bytes(C.checked(packet_root,row['files']['a']))
  F.publish(C,ROOT,inputs,packet,payload,origins);proof=F.read(C,ROOT,inputs)
  old=C.load('held_actual_original_closure',ROOT/'scripts/apps/full574_closure.py');facade=F.facade(C,ROOT,old,inputs)
  original=old.current_payloads();held=facade.current_payloads();C.need(original['cachy-asahi-orphans']!=held['cachy-asahi-orphans'],'actual Orphans2 source must differ from held Orphans1 archive')
  for n in C.VERSIONS:
   if n!='cachy-asahi-orphans':C.need(original[n]==held[n],'unexpected other current/held package difference')
  # Exercise original complete Adapter candidate-binding logic with real held
  # nodes. Only its final large-source scan is replaced by a recorded boundary;
  # this is not a modeled574 tree or native/source-preservation acceptance.
  seed=temp/'seed';seed.mkdir();token='a'*32;caps={'CONTROL_ONLY_FILE_NOT_A_574_TREE':'00'*20};common=dict(schema_version=1,purpose=old.PURPOSE,execution_budget=dict(old.EXECUTION_BUDGET),**{n:'b'*64 for n in ('snapshot_sha256','extraction_receipt_sha256','source_tree_sha256','source_packages_sha256','source_closure_sha256')},source_capabilities_sha256=old.digest(caps))
  policy=dict(common,baseline_lock_sha256=old.LOCK_SHA256,source_capabilities=caps,candidates={n:dict(version=C.VERSIONS[n],archive_sha256=r['archive']['sha256'],payload_sha256=r['payload_sha256']) for n,r in proof['held_candidates'].items()});lease=dict(common,token=token,source=str(seed),source_identity=[seed.stat().st_dev,seed.stat().st_ino]);args=types.SimpleNamespace()
  for key,value in (('policy',policy),('lease',lease)):
   path=temp/(key+'.json');path.write_bytes(C.encoded(value));path.chmod(0o600);setattr(args,'full574_'+key,str(path));setattr(args,'full574_'+key+'_sha256',C.sha(path.read_bytes()))
  T=C.load('held_actual_original_backend',ROOT/'scripts/apps/transaction.py');budget=T.F.Limits(deadline=time.monotonic()+30);seen=[]
  with patch.dict(os.environ,{'CACHY_ASAHI_APPS_TRANSACTION':token}),patch.object(old.Adapter,'source_check',lambda self:seen.append('FINAL_SOURCE_SCAN_NOT_RUN_IN_CONTROL')):
   try:old.Adapter(args,T,budget)
   except ValueError as error:C.need('candidate-binding' in str(error),'old source model must reject the real held policy at candidate-binding')
   else:raise ValueError('old Orphans2 model unexpectedly accepted held Orphans1 policy')
   C.need(not seen,'old model crossed the original candidate gate')
   actual=facade.connect(args,T,budget);C.need(actual.payloads==held and len(seen)==1,'all four held nodes must pass original complete candidate bindings')
   C.need(facade.Adapter.__init__.__code__ is old.Adapter.__init__.__code__ and facade.connect.__code__ is old.connect.__code__ and old.current_payloads()==original,'unchanged original constructor/connect code and globals required')
   # Independently inconsistent metadata/bytes must still fail, with no fallback
   # to current source, unchecked proof, omitted fourth package or zero digest.
   bad=copy.deepcopy(policy);bad['candidates']['cachy-asahi-orphans']['payload_sha256']=old.digest(original['cachy-asahi-orphans']);path=Path(args.full574_policy);path.write_bytes(C.encoded(bad));args.full574_policy_sha256=C.sha(path.read_bytes())
   try:facade.connect(args,T,budget)
   except ValueError as error:C.need('candidate-binding' in str(error),'contradictory policy must still reject at original gate')
   else:raise ValueError('contradictory current-source policy accepted')
  proof_path=inputs/F.PROOF;good=proof_path.read_bytes();bad=copy.deepcopy(proof);bad['held_candidates']['cachy-asahi-orphans']['payload_sha256']=old.digest(original['cachy-asahi-orphans']);proof_path.write_bytes(C.encoded(bad))
  try:F.read(C,ROOT,inputs)
  except ValueError:pass
  else:raise ValueError('unchecked current-source proof accepted')
  proof_path.write_bytes(good)
  # The real transaction module's exact closure-loader boundary also routes to
  # a separately loaded held facade, without replacing any shared module globals.
  args.full574_policy_sha256=C.sha(C.encoded(policy));Path(args.full574_policy).write_bytes(C.encoded(policy))
  F.configure(T,C,ROOT,inputs);loaded=T.load('held_actual_configured_closure',ROOT/'scripts/apps/full574_closure.py')
  C.need(loaded.current_payloads()==held,'actual transaction loader must resolve all four held payloads')
  with patch.dict(os.environ,{'CACHY_ASAHI_APPS_TRANSACTION':token}),patch.object(loaded.Adapter,'source_check',lambda self:None):
   C.need(loaded.connect(args,T,budget).payloads==held,'configured transaction closure must pass original candidate bindings')
  archive=inputs/'archives'/Path(packet['packages']['cachy-asahi-orphans']['files']['a']['path']).name
  alias=inputs/'archive-alias';os.link(archive,alias)
  try:
   try:F.read(C,ROOT,inputs)
   except ValueError:pass
   else:raise ValueError('held archive hardlink alias accepted')
  finally:alias.unlink()
  renamed=inputs/'original-archive';archive.rename(renamed);archive.symlink_to(renamed)
  try:
   try:F.read(C,ROOT,inputs)
   except ValueError:pass
   else:raise ValueError('held archive symlink accepted')
  finally:archive.unlink();renamed.rename(archive)
  archive.write_bytes(archive.read_bytes()+b'drift')
  try:F.read(C,ROOT,inputs)
  except ValueError:pass
  else:raise ValueError('changed held archive accepted')
  return dict(status='PASS_ACTUAL_HELD_FOUR_ARCHIVE_ADAPTER_CONTROL_NOT_NATIVE',held_versions=C.VERSIONS,rules=proof['readonly_rules'],candidates=proof['held_candidates'],original_globals='UNCHANGED',original_constructor_and_connect_code='IDENTICAL',source_scan='NOT_RUN_EXPLICIT_CONTROL_BOUNDARY',ALPM='NOT_RUN',native='NOT_RUN',hardware='NOT_RUN')
if __name__=='__main__':
 p=argparse.ArgumentParser(add_help=False);p.add_argument('--actual-packet',type=Path);a,rest=p.parse_known_args()
 if a.actual_packet:
  with patch('subprocess.Popen',side_effect=AssertionError('actors forbidden in archive control')):print(C.encoded(actual_control(a.actual_packet.absolute())).decode(),end='')
 else:unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
