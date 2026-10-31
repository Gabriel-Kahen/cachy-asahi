"""New maintained DATA-reader models only; no factory/source/native execution."""
import ast,copy,hashlib,io,json,tempfile,types,unittest,zipfile
from pathlib import Path
D=Path(__file__).resolve().parent;PROPOSED=D

def run_controls():
 path=PROPOSED/'reader_data.py';R=types.ModuleType('_maintained_reader_controls');R.__file__=str(path);exec(compile(path.read_bytes(),str(path),'exec'),vars(R));C=R.checkpoint_contract()
 def identity():return dict(source='a'*40,ref='codex/synthetic-maintained-reader',run=7,attempt=1)
 def metadata():
  expected=identity();repo=dict(id=1414857795,full_name='Gabriel-Kahen/cachy-asahi',private=False);run=dict(id=7,head_sha=expected['source'],head_branch=expected['ref'],run_attempt=1,workflow_id=381664314,status='completed',conclusion='failure',event='workflow_dispatch',path='.github/workflows/native-arm-build.yml',name='native-arm-core622-current-desktop',repository=repo,head_repository=dict(repo));steps=[dict(name='Close completed prerequisite metadata before the Core installer',number=2,status='completed',conclusion='success'),dict(name='Upload completed prerequisite metadata checkpoint',number=3,status='completed',conclusion='success')];jobs=dict(total_count=1,jobs=[dict(id=8,run_id=7,head_sha=expected['source'],run_attempt=1,status='completed',name='native',labels=['ubuntu-24.04-arm'],steps=steps)]);wr=dict(id=7,head_sha=expected['source'],head_branch=expected['ref'],repository_id=1414857795,head_repository_id=1414857795);core=dict(id=11,name='core7-real-systemd-7-1',size_in_bytes=10,digest='sha256:'+'b'*64,expired=False,workflow_run=wr);checkpoint=dict(id=12,name='core622-maintained-prerequisite-metadata-7-1',size_in_bytes=10,digest='sha256:'+'c'*64,expired=False,workflow_run=copy.deepcopy(wr));return expected,run,jobs,core,checkpoint
 def checkpoint():
  expected=identity();nonce=hashlib.sha256(('current607-core622:'+expected['source']+':7').encode()).hexdigest()[:32];roles={n:dict(bytes=1,sha256='b'*64)for n in C.ROLES};roles['fdk-evidence/result.txt']=R.pin(b'FDK_PAIR=PASS\nEXIT=0\n');report=dict(status='SOURCE_REPORTED_PAIR_METADATA_VALIDATED',distinct_recorded_environments=True,original_comparison='CONTENTS_PKGINFO_AND_BYTES_EQUAL',original_validation_errors=0,package_count=1,raw_package_payload='NOT_CARRIED',independent_actor_replay=False);value=dict(schema=2,version=C.VERSION,baseline_source=C.BASELINE,status='COMPLETED_MAINTAINED_PREREQUISITE_METADATA_CHECKPOINT_DATA_ONLY',identity=expected,nonce=nonce,job_clock_available=False,job_clock=None,native_phase_clock_available=False,workflow_job_timeout_minutes=350,installer_timeout_seconds=15600,installer_kill_grace_seconds=60,installer_step_timeout_minutes=270,source_roles=roles,source_metadata_bytes=sum(v['bytes']for v in roles.values()),source_role_count=31,original_native_runner_arch=None,source_reports={n:dict(report)for n in(*C.NAMES,'fdk')},stage='BEFORE_EXPENSIVE_CORE_INSTALLER',installer='NOT_ENTERED_BY_CHECKPOINT',original_metadata_bodies='NOT_CARRIED_HASHES_AND_FINITE_PROJECTION_ONLY',package_payloads='NOT_CARRIED',private_roots='NOT_READ',logs='NOT_READ',normal90_acceptance=False,functional_acceptance=False,native_acceptance=False,hardware='NOT_RUN',release='NOT_ADMITTED',acceptance=False);return value
 def zipper(entries):
  stream=io.BytesIO()
  with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_STORED)as archive:
   for name,raw in entries:
    info=zipfile.ZipInfo(name);info.external_attr=0o100644<<16;archive.writestr(info,raw)
  return stream.getvalue()
 def body(value):
  raw=R.encoded(value);export=dict(schema=2,version=C.VERSION,status='CLOSED_COMPLETED_MAINTAINED_PREREQUISITE_METADATA_CHECKPOINT_DATA_ONLY',identity=value['identity'],nonce=value['nonce'],files={'checkpoint.json':R.pin(raw)},bytes=len(raw),acceptance=False);return zipper([('checkpoint.json',raw),('export.json',R.encoded(export))])
 def frame(expected,nonce):
  resources={name:None for name in R.TELEMETRY_RESOURCES};return dict(schema=1,status='BOUNDED_SOURCE_PHASE_RESOURCE_DATA_ONLY',identity=expected,nonce=nonce,sequence=1,kind='INTERVAL',elapsed_ms=0,phase='AWAITING_INSTALLER_PHASE',installer_identity=None,pump_identity=dict(pid=12,start_ticks=None),resource_scope='HOST_MEMINFO_PUMP_ONLY_INSTALLER_ID_ASSERTED',resources=resources,unavailable_fields=sorted(resources),acceptance=False)
 def receipts():
  expected=identity();nonce=hashlib.sha256(('current607-core622:'+expected['source']+':7').encode()).hexdigest()[:32];writer=R.pin(b'synthetic export writer');f=frame(expected,nonce);telemetry=dict(schema=1,status='BOUNDED_STDOUT_PUMP_TELEMETRY_DATA_ONLY',identity=expected,nonce=nonce,cadence_seconds=60,interval_cap=262,phase_marker_cap=32,frame_cap=1024,total_frame_cap=294,interval_samples=1,phase_markers=0,emitted_frames=1,dropped_frames=0,rejected_markers=0,last_phase=f['phase'],installer_identity=None,pump_identity=f['pump_identity'],recent=[f],acceptance=False);raws={}
  for role in('phase.stdout','phase.stderr'):
   value=dict(schema=2 if role=='phase.stdout'else 1,status='BOUNDED_PRIVATE_STREAM_METADATA_DATA_ONLY',identity=expected,nonce=nonce,role=role,source_export=writer,intent=R.pin(b'same private intent'),observer_deadline=15660.0,observed_bytes=2*1024**2,observed_sha256='d'*64,eof=True,retained=dict(bytes=1024**2,sha256='e'*64),complete=False,window='PREFIX',errors=[],acceptance=False)
   if role=='phase.stdout':value['telemetry']=telemetry
   raws['runner-telemetry/'+role+'.json']=R.encoded(value)
  files={n:R.pin(raw)for n,raw in raws.items()};export=dict(files=files,bytes=sum(v['bytes']for v in files.values()),runner_telemetry=dict(schema=1,status='OPTIONAL_SANITIZED_RUNNER_METADATA_DATA_ONLY',roles=dict(files),acceptance=False));source_files={'export622.py':writer,**{'synthetic-role-%02d'%i:R.pin(b'')for i in range(65)}};return expected,raws,export,source_files
 def change_receipt(raws,export,name,change):
  value=R.obj(raws[name]);change(value);raws[name]=R.encoded(value);export['files'][name]=R.pin(raws[name]);export['runner_telemetry']['roles'][name]=export['files'][name];export['bytes']=sum(v['bytes']for v in export['files'].values())
 class Focused(unittest.TestCase):
  def test_maintained_module_has_no_frozen_dependencies_or_actor_functions(self):
   text=path.read_text();self.assertNotIn('artifacts/development',text);self.assertNotIn('/home/',text);self.assertNotIn('04a943',text);tree=ast.parse(text);names={n.name for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))};self.assertTrue(names.isdisjoint({'telemetry_proc','telemetry_resources','telemetry_write','telemetry_process_identity','PhaseResourceTelemetry','resilience_pump','resilience_delegate'}));self.assertEqual(R.BASELINE_SOURCE,'ad09020a776c93fad3c2625c836a99cbde0c83b9')
  def test_exact_two_artifact_view_preserves_original_core_row(self):
   expected,run,jobs,core,row=metadata();listing=dict(total_count=2,artifacts=[core,row]);result=R.checkpoint_metadata(expected,run,jobs,listing);self.assertIs(result['artifact'],row);self.assertFalse(result['acceptance']);self.assertEqual(result['body_GET_authority'],'NONE');view=R.core_artifact_view(expected,run,jobs,listing);self.assertIs(view['artifacts'][0],core);self.assertEqual(view['total_count'],1);self.assertEqual(len(listing['artifacts']),2)
  def test_core_only_failure_checkpoint_only_and_success_gate(self):
   expected,run,jobs,core,row=metadata();self.assertIs(R.core_artifact_view(expected,run,jobs,dict(total_count=1,artifacts=[core]))['artifacts'][0],core)
   with self.assertRaises(ValueError):R.core_artifact_view(expected,run,jobs,dict(total_count=1,artifacts=[row]))
   run['conclusion']='success'
   with self.assertRaises(ValueError):R.core_artifact_view(expected,run,jobs,dict(total_count=1,artifacts=[core]))
  def test_metadata_wrong_source_duplicate_unknown_size_status_and_types(self):
   for kind in('source','duplicate','unknown','size','progress','attempt'):
    expected,run,jobs,core,row=metadata();listing=dict(total_count=2,artifacts=[core,row])
    if kind=='source':row['workflow_run']['head_sha']='0'*40
    elif kind=='duplicate':listing['artifacts']=[row,dict(row)]
    elif kind=='unknown':row['name']='unrelated-private'
    elif kind=='size':row['size_in_bytes']=16*1024**2+1
    elif kind=='progress':jobs['jobs'][0]['steps'][0]['status']='in_progress'
    else:run['run_attempt']=True
    with self.subTest(kind=kind),self.assertRaises(ValueError):R.checkpoint_metadata(expected,run,jobs,listing)
  def test_checkpoint_closed_zip_canonical31roles_and_unavailable_clocks(self):
   expected,run,jobs,core,row=metadata();value=checkpoint();raw=body(value);row.update(size_in_bytes=len(raw),digest='sha256:'+R.pin(raw)['sha256']);result=R.checkpoint_data(raw,expected,row);self.assertFalse(result['acceptance']);self.assertFalse(result['native_acceptance']);self.assertEqual(result['source_metadata_roles'],31);self.assertEqual(result['body_GET_authority'],'NONE');self.assertEqual(result['installer_acceptance'],'NOT_ESTABLISHED');self.assertFalse(value['job_clock_available']);self.assertIsNone(value['job_clock']);self.assertFalse(value['native_phase_clock_available'])
  def test_checkpoint_refuses_frozen_clock_schema_credit_fdk_and_cause_fields(self):
   for kind in('clock','schema','native','fdk','private'):
    expected,run,jobs,core,row=metadata();value=checkpoint()
    if kind=='clock':value['job_clock_available']=True;value['job_clock']=R.pin(b'pretendclock')
    elif kind=='schema':value['schema']=1
    elif kind=='native':value['native_acceptance']=True
    elif kind=='fdk':value['source_roles']['fdk-evidence/result.txt']=R.pin(b'FAIL\n')
    else:value['cause']='OOM'
    raw=body(value);row.update(size_in_bytes=len(raw),digest='sha256:'+R.pin(raw)['sha256'])
    with self.subTest(kind=kind),self.assertRaises(ValueError):R.checkpoint_data(raw,expected,row)
  def test_checkpoint_zip_crc_names_sizes_digest_refusal(self):
   expected,run,jobs,core,row=metadata();raw=body(checkpoint());broken=bytearray(raw);at=broken.index(b'COMPLETED_MAINTAINED_PREREQUISITE');broken[at]^=1;broken=bytes(broken);row.update(size_in_bytes=len(broken),digest='sha256:'+R.pin(broken)['sha256'])
   with self.assertRaises((ValueError,zipfile.BadZipFile)):R.checkpoint_data(broken,expected,row)
   raw=zipper([('checkpoint.json',b'{}'),('export.json',b'{}'),('private',b'secret')]);row.update(size_in_bytes=len(raw),digest='sha256:'+R.pin(raw)['sha256'])
   with self.assertRaises(ValueError):R.checkpoint_data(raw,expected,row)
   row['digest']='sha256:'+'0'*64
   with self.assertRaises(ValueError):R.checkpoint_data(raw,expected,row)
  def test_two_telemetry_receipts_are_only_validated_closure_roles(self):
   expected,raws,export,source_files=receipts();roles=R.validate_runner_telemetry(raws,export,expected,source_files);self.assertEqual(roles,R.RUNNER_TELEMETRY_ROLES);self.assertIs(type(roles),frozenset);self.assertNotIn('runner-telemetry/phase.stdout',roles);self.assertEqual(R.validate_runner_telemetry({},dict(files={},bytes=0),expected,source_files),frozenset())
  def test_telemetry_source_writer_nonce_intent_deadline_and_private_role_refusal(self):
   name='runner-telemetry/phase.stdout.json'
   for kind in('source','writer','nonce','intent','deadline','private'):
    expected,raws,export,source_files=receipts()
    if kind=='source':change_receipt(raws,export,name,lambda v:v['identity'].update(source='0'*40))
    elif kind=='writer':change_receipt(raws,export,name,lambda v:v.update(source_export=R.pin(b'other writer')))
    elif kind=='nonce':change_receipt(raws,export,name,lambda v:v.update(nonce='0'*32))
    elif kind=='intent':change_receipt(raws,export,name,lambda v:v.update(intent=R.pin(b'other private intent')))
    elif kind=='deadline':change_receipt(raws,export,name,lambda v:v.update(observer_deadline=15661.0))
    else:raws['runner-telemetry/private']=b'secret';export['files']['runner-telemetry/private']=R.pin(b'secret');export['bytes']+=6
    with self.subTest(kind=kind),self.assertRaises(ValueError):R.validate_runner_telemetry(raws,export,expected,source_files)
  def test_telemetry_scalar_summary_and_unverified_resource_scope(self):
   name='runner-telemetry/phase.stdout.json'
   for kind in('boolean','scope','count','none','freefield'):
    expected,raws,export,source_files=receipts()
    def mutate(v):
     if kind=='boolean':v['telemetry']['recent'][0]['resources']['pump_threads']=True
     elif kind=='scope':v['telemetry']['recent'][0]['resource_scope']='VERIFIED_INSTALLER_RSS'
     elif kind=='count':v['telemetry']['interval_samples']=263
     elif kind=='none':v['telemetry']=None
     else:v['private_path']='/tmp/private'
    change_receipt(raws,export,name,mutate)
    with self.subTest(kind=kind),self.assertRaises(ValueError):R.validate_runner_telemetry(raws,export,expected,source_files)
  def test_protocol_frame_numeric_only_explicit_no_acceptance(self):
   expected=identity();nonce=hashlib.sha256(('current607-core622:'+expected['source']+':7').encode()).hexdigest()[:32];value=frame(expected,nonce);raw=R.TELEMETRY_PREFIX+R.telemetry_encoded(value)+b'\n';result=R.telemetry_frame(raw,expected);self.assertFalse(result['acceptance']);self.assertFalse(result['native_acceptance']);self.assertEqual(result['cause'],'NOT_INFERRED');self.assertIn('NOT_VERIFIED',result['installer_identity'])
   value['resources']['private_path']='/secret';raw=R.TELEMETRY_PREFIX+R.telemetry_encoded(value)+b'\n'
   with self.assertRaises(ValueError):R.telemetry_frame(raw,expected)
  def test_adjacent_contract_pin_before_exec_and_null_selection_refusal(self):
   with tempfile.TemporaryDirectory(prefix='maintained-reader-',dir=D)as td:
    old=R.__file__;R.__file__=str(Path(td)/'reader_data.py');target=Path(td)/'checkpoint_contract.py';target.write_text("raise AssertionError('UNTRUSTED_MUST_NOT_EXECUTE')\n")
    try:
     with self.assertRaises(ValueError):R.checkpoint_contract()
    finally:R.__file__=old
   with self.assertRaises(ValueError):R.expected_identity(dict(source=None,ref=None,run=None,attempt=1))
 stream=io.StringIO();result=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Focused));return dict(status='PASS'if result.wasSuccessful()else'FAIL',tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),details=stream.getvalue(),factory_emission='NOT_RUN',construct_reader='NOT_RUN',Source_prefix='NOT_RUN',old_suites='NOT_RUN',native='NOT_RUN',GET='NOT_RUN',Git='NOT_RUN',actual=None,acceptance=False)

if __name__=='__main__':
 result=run_controls();print(json.dumps(result,sort_keys=True));raise SystemExit(result['status']!='PASS')
