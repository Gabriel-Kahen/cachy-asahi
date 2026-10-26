# SPDX-License-Identifier: MIT
"""Installed Doctor CLI in the ordinary copy; unavailable queries stay unavailable."""
import hashlib,importlib.machinery,importlib.util,io,json,os,stat,subprocess,sys,unittest
from pathlib import Path
CONTEXT=Path('/var/tmp/caa-doctor2-fixture');PROGRAM=Path('/usr/bin/cachy-asahi-doctor')
CONTROL_SELECTION={'test_doctor.py': {'Diagnostics': ['test_all_queries_fixed_read_only_local_bounded_and_no_session_ids_retained', 'test_confirmed_absence_differs_from_query_failure', 'test_deadline_exhaustion_marks_unknown_without_further_queries', 'test_failed_inactive_and_missing_services_are_observed_not_healthy', 'test_known_dt_identity_is_observation_with_real_page_size', 'test_malformed_unexpected_or_duplicate_package_rows_are_unknown', 'test_missing_tools_never_launch_commands_or_infer_absence', 'test_no_local_user_bus_skips_user_queries', 'test_unexpected_service_output_is_never_retained', 'test_unknown_missing_or_ambiguous_model_stays_unknown'], 'QueryControls': ['test_output_overflow_is_unknown_and_query_group_retired', 'test_timeout_is_unknown_and_query_group_retired'], 'Reports': ['test_json_stdout_has_same_explicit_unknown_coverage', 'test_private_complete_atomic_no_overwrite_publication', 'test_stdout_is_default_and_report_errors_have_nonzero_exit', 'test_symlink_destination_and_parent_refused']}, 'test_audio.py': {'Audio': ['test_audio_obeys_original_aggregate_deadline', 'test_fixed_audio_argv_and_no_bus_dependency', 'test_malformed_extra_nonfinite_error_and_private_output_not_reported', 'test_muted_zero_and_plain_volume_are_actionable_observations', 'test_no_socket_or_wpctl_launches_no_audio_client', 'test_real_private_socket_owner_mode_and_ordinary_ancestry', 'test_socket_changed_before_or_after_client_is_unknown', 'test_socket_replacement_is_observable']}}
CONTROL_NOT_RUN={'test_audio.py': {'RealIPC': ['test_actual_local_socket_scalar_and_natural_child_retirement', 'test_real_child_overflow_is_unknown_without_private_output', 'test_stalled_local_server_deadline_kills_and_reaps_client']}}
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def call(argv,seconds=20,expected=0):
 value=subprocess.run(argv,stdin=0,capture_output=True,timeout=seconds)
 need(value.returncode==expected and len(value.stdout)+len(value.stderr)<=128*1024,'actual installed readonly command failed')
 return value

def report(value,role):
 need(type(value)is dict and value.get('schema_version')==1 and value.get('tool')=='cachy-asahi-doctor'and value.get('scope')=='local observations only'and value.get('version')==('0.1.0'if role=='doctor1'else'0.2.0'),'exact installed Doctor report/version/scope')
 rows=value.get('checks');need(type(rows)is list and len(rows)<128 and all(type(r)is dict for r in rows),'bounded actual Doctor report')
 keys=[r.get('check')for r in rows];need(len(set(keys))==len(keys),'unique observed diagnostic rows')
 platform=next(r for r in rows if r['check']=='platform');need(platform['value']==dict(architecture='aarch64',kernel=os.uname().release,page_size_bytes=os.sysconf('SC_PAGE_SIZE')),'actual generic native platform fields')
 for row in rows:
  if row['check'].startswith('package/'):
   need(row['state']in('unavailable','unknown')and row['value']['presence']=='unknown'and row['value']['version']is None,'unavailable copied-root package query grants no absence or installed-query authority')
  if row['check'].startswith(('user/','system/')):need(row['state']in('unavailable','unknown'),'offline copied-root service query grants no health authority')
 audio=[r for r in rows if r['check']=='audio/default-output']
 need(not audio if role=='doctor1'else len(audio)==1 and audio[0]['state']=='unavailable'and audio[0]['value']is None,'honest unavailable audio; no live PipeWire')
 return value

def installed_controls():
 # Whole original Doctor16/Audio8 bodies; original RealIPC3 cannot run here; replace only their module operand with
 # the actual installed program, already proved byte-equal to accepted source.
 raw=PROGRAM.read_bytes();need(raw==(CONTEXT/'doctor/cachy-asahi-doctor').read_bytes(),'installed Doctor2 source bytes')
 loader=importlib.machinery.SourceFileLoader('_installed_doctor2',str(PROGRAM));spec=importlib.util.spec_from_loader(loader.name,loader);actual=importlib.util.module_from_spec(spec);loader.exec_module(actual)
 suite=unittest.TestSuite()
 for filename,key,classes in(('test_doctor.py','doctor',('Diagnostics','QueryControls','Reports')),('test_audio.py','D',('Audio',))):
  p=CONTEXT/'doctor'/filename;spec=importlib.util.spec_from_file_location('_installed_'+key,p);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);setattr(module,key,actual)
  for cls in classes:
   case=getattr(module,cls);need(unittest.defaultTestLoader.getTestCaseNames(case)==CONTROL_SELECTION[filename][cls],'exact selected original installed control method identities');suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(case))
  for cls,methods in CONTROL_NOT_RUN.get(filename,{}).items():need(unittest.defaultTestLoader.getTestCaseNames(getattr(module,cls))==methods,'whole original unavailable RealIPC method identities held')
 stream=io.StringIO();result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite);raw=stream.getvalue().encode()
 need(result.wasSuccessful()and result.testsRun==24 and not result.skipped and 0<len(raw)<=65536,'all24 original compatible Doctor private controls')
 return dict(status='PASS_INSTALLED_CONTROLS',mode='doctor',tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),report_bytes=len(raw),report_sha256=pin(raw)['sha256'],installed_source=True,selection=CONTROL_SELECTION,not_run=dict(RealIPC=dict(tests=3,reason='NOT_RUN_COPIED_ROOT_NO_DEV_NULL',methods=CONTROL_NOT_RUN['test_audio.py']['RealIPC'])))

def main():
 need(len(sys.argv)==3 and os.getuid()==os.geteuid()>0 and os.uname().machine=='aarch64','ordinary native copied-root Doctor fixture')
 work=Path(sys.argv[1]);role=sys.argv[2];need(role in('doctor1','doctor2')and work.is_relative_to(CONTEXT/'outputs'),'fixed source fixture/output')
 need(not Path('/dev/null').exists()and not Path('/dev/null').is_symlink(),'ordinary copy has no fabricated device/EOF or query availability')
 call([str(PROGRAM),'--help'],15)
 raw=call(['/usr/bin/pacman','-Q'],15).stdout;rows=raw.decode().splitlines();inventory=dict(r.split()for r in rows);wanted=dict(r.split()for r in(CONTEXT/'expected606.lock').read_text().splitlines());wanted['cachy-asahi-doctor']='0.1.0-1'if role=='doctor1'else'0.2.0-1'
 need(len(rows)==len(inventory)==606 and inventory==wanted,'source-owned fixed pacman-Q complete606; separate from Doctor unavailable queries')
 digest=hashlib.sha256(''.join(n+' '+v+'\n'for n,v in sorted(inventory.items())).encode()).hexdigest()
 path=work/'doctor.json';value=call([str(PROGRAM),'--json','--output',str(path)],25);observed=report(json.loads(value.stdout),role);published=path.read_bytes();identity=path.lstat();need(json.loads(published)==observed and stat.S_ISREG(identity.st_mode)and identity.st_nlink==1 and stat.S_IMODE(identity.st_mode)==0o600 and identity.st_uid==os.geteuid(),'actual private report publication')
 call([str(PROGRAM),'--output',str(path)],25,2);need(path.lstat()==identity and path.read_bytes()==published,'report no-overwrite complete identity/content')
 outside=work/'outside';outside.write_bytes(b'private fixture sentinel\n');outside.chmod(0o600);before=outside.lstat();alias=work/'report-alias';alias.symlink_to('outside')
 try:call([str(PROGRAM),'--output',str(alias)],25,2);need(outside.lstat()==before and outside.read_bytes()==b'private fixture sentinel\n','symlink refusal preserves outside sentinel')
 finally:alias.unlink()
 control=installed_controls()if role=='doctor2'else None
 print(json.dumps(dict(status='PASS_ACTUAL_INSTALLED_DOCTOR_OFFLINE',recipe_role=role,CLI=4,inventory_count=606,inventory_sha256=pin(raw)['sha256'],inventory_versions_sha256=digest,inventory_authority='SOURCE_OWNED_FIXED_PACMAN_Q_NOT_DOCTOR_QUERY',query_scope='COPIED_ROOT_UNAVAILABLE_NOT_HEALTH_PROOF',doctor=observed,private_report=dict(**pin(published),mode='0600',no_overwrite='PASS',symlink_refusal='PASS'),installed_controls=24 if control else 0,controls=control,applied='NOT_APPLIED'),sort_keys=True))
if __name__=='__main__':main()
