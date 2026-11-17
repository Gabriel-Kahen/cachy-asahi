#!/usr/bin/env -S python3 -I -B
"""Root-only once entry using the established external owned-process supervisor."""
import argparse,datetime,hashlib,importlib.util,json,os,resource,subprocess,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent

def module(n,p):
 sp=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m

def run(path,sha):
 I=module('Root_metadata_issuer',HERE/'Root-issue.DRAFT.py');v,R,f,T,runtime=I.parameters(path,sha);issued=T/'issued'
 record=I.read(issued/'Root-entry-command.ACTUAL.json');ap=issued/'Root-outer-authority.ACTUAL.json';R.check_ref(record['authority']);I.need(record['authority']['path']==str(ap),'exact issued authority path')
 c=I.read(ap);R.require_issued(c,f);I.need(c['nonce']==v['nonce'] and c['Main']==v['Main'] and c['runtime_profile']['path']==str(runtime) and record['runtime']==runtime.stem.split('-')[-1],'exact fresh Root operation/Main/runtime joins')
 I.need(record['argv']==I.entry_argv(c,ap,record['authority']['sha256']) and record['entry']=='UNENTERED' and record['once']is True and record['retry']is False and record['external_seconds']==485 and record['cleanup_seconds']==90,'exact reviewed entry vector; no arbitrary command or retry')
 I.need(not(T/'actor-output').exists() and not(issued/'Root-once-entry-intent.ACTUAL.json').exists(),'once fresh output/intent')
 mem=int(next(s.split()[1]for s in Path('/proc/meminfo').read_text().splitlines()if s.startswith('MemAvailable:')))*1024;I.need(mem>=3221225472,'fresh3GiB actor+controller+reserve minimum')
 I.put(issued/'Root-once-entry-intent.ACTUAL.json',dict(issuer='Root',argv=record['argv'],authority=record['authority'],runtime=record['runtime'],once=True,retry=False,external_seconds=485,retirement_seconds=90,MemAvailable=mem,issued_utc=datetime.datetime.now(datetime.timezone.utc).isoformat()))
 helper=HERE/'capsule/owned_process.py';I.need(I.pin(helper)==dict(bytes=25140,sha256='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'),'unchanged external owned-process helper');O=module('Root_metadata_external_owned',helper);O.prepare()
 def limits():
  resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(536870912,536870912));resource.setrlimit(resource.RLIMIT_AS,(4294967296,4294967296))
 env=dict(os.environ,LC_ALL='C.UTF-8',TZ='UTC',PYTHONDONTWRITEBYTECODE='1')
 for key in list(env):
  if key.startswith('GIT_TRACE')or key in('GIT_CURL_VERBOSE','GH_DEBUG'):env.pop(key)
 with(issued/'Root-entry.stdout').open('xb')as stdout,(issued/'Root-entry.stderr').open('xb')as stderr:
  child=subprocess.Popen(record['argv'],cwd=str(HERE),env=env,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True,preexec_fn=limits)
  ret=O.supervise(child,cap=485,retirement=90,grace=1,streams=())
 ret['output_bytes']=len(ret.pop('output'));I.put(issued/'Root-external-retirement.ACTUAL.json',ret)
 closure=dict(issuer='Root',runtime=record['runtime'],status='HOLD',external=ret,Root_acceptance=None,Perl_baseline_qualification=None,Perl_preservation=None,M2=None,release=None)
 try:
  I.need(ret['passed']is True and ret['reaped']is True and ret['ownership']=='REAPED' and ret['group_census']=='EMPTY_TWICE' and not ret['timeout'] and not ret['signals'] and ret['error']is None,'natural/reaped external parent and EMPTY_TWICE')
  report_path=T/'actor-output/records/Root-outer-result.json';report=R.decode(R.read(report_path,16384))
  I.need(report['status']=='COMPLETE_PUBLIC_LDCACHE_RECOVERY_ONLY' and report['nonce']==v['nonce'] and report['policy_exit_code']==0 and report['original_inputs_unchanged']is report['owned_container_absent']is report['owned_children_reaped']is report['close_only']is True and not report['forced_owned_cleanup'] and not report['cleanup_errors'] and not report['signals'] and not report.get('error'),'complete finite metadata + original input invariance + owned closure')
  I.need(report['artifact_descriptors']is not None and report['live_child_guard_samples']>0,'whole observer artifacts and periodic live reserve guard')
  small=R.decode(R.read(T/'actor-output/decoder-output/scan/observation.DATA.json',16384));I.need(R.validate_observation(small,c,f)==report['observation_summary'],'same bounded producer/parent summary')
  actual_artifacts,total=R.retain_artifact_descriptors(T/'actor-output/decoder-output/scan',small,time.monotonic()+120)
  I.need(actual_artifacts==report['artifact_descriptors'] and total==report['artifact_bytes'] and total<=1610612736+4*1024**2,'independent exact opaque artifact hashes, modes, membership and aggregate cap')
  end=time.monotonic()+8;scope=Path(c['controller_scope']['path'])
  while scope.exists() and time.monotonic()<end:time.sleep(.025)
  I.need(not scope.exists(),'controller scope collected');time.sleep(.025);I.need(not scope.exists(),'controller scope collected twice')
  def census(extra):
   argv=[f['docker_cli']['path'],'--host='+f['docker_endpoint'],'container','ls','-a','--no-trunc',*extra,'--format','{{.ID}}']
   cli_env=dict(PATH='/usr/bin:/bin',HOME='/home/gabe',XDG_RUNTIME_DIR='/run/user/1000',DOCKER_CONFIG=str(T/'actor-output/empty-docker-config'),LC_ALL='C',TZ='UTC')
   child=subprocess.Popen(argv,env=cli_env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,preexec_fn=limits);row=O.supervise(child,cap=8,retirement=1,grace=.2,max_output=4096);output=row.pop('output')
   I.need(row['passed']is True and row['reaped']is True and row['group_census']=='EMPTY_TWICE' and not row['timeout'] and not row['signals'] and row['error']is None and output.strip()==b'','independent exact owned-CID absence')
   return dict(argv=argv,retirement=row)
  filters=[]
  for key,value in R.labels(c,record['authority']['sha256']).items():filters+=['--filter','label='+key+'='+value]
  absences=[census(filters),census(['--filter','name=^/'+R.name(c)+'$'])]
  cid=I.read(T/'actor-output/records/created-cid.json')['cid'];absences.append(census(['--filter','id='+cid]))
  original_inputs={}
  intent=I.read(T/'actor-output/records/once-intent.json')['inputs']
  for role in('input_raw','input_prepared'):
   actual,identity=R.whole(f[role]['path'],4*1024**3,time.monotonic()+60);I.need(actual=={k:f[role][k]for k in('bytes','sha256')}and list(identity)==intent[role]['identity'],'independent whole original input/stat unchanged')
   original_inputs[role]=dict(**actual,identity=identity,unchanged=True)
  closure.update(status='COMPLETE_PUBLIC_LDCACHE_RECOVERY_AND_CLEANUP_ONLY',policy_exit_code=report['policy_exit_code'],observation_summary=report['observation_summary'],artifact_descriptors=report['artifact_descriptors'],artifact_bytes=report['artifact_bytes'],scope_collected_twice=True,owned_absence_independently_verified=absences,original_inputs=original_inputs,canonical_custody='SAME_FD_PIDFD_REAL_NB_CLOSE_ONLY',outer_report=dict(path=str(report_path),**I.pin(report_path)))
 except BaseException as error:closure['error']=dict(category=type(error).__name__,message=str(error)[:700])
 I.need(len(R.encoded(closure))<=16384,'bounded parent summary and opaque descriptors')
 closure['observed_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();I.put(T/'Root-terminal-closure.ACTUAL.json',closure)
 print(json.dumps(closure,sort_keys=True));return 0 if closure['status']=='COMPLETE_PUBLIC_LDCACHE_RECOVERY_AND_CLEANUP_ONLY'else 2

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parameters',type=Path,required=True);p.add_argument('--parameters-sha256',required=True);a=p.parse_args()
 if not(sys.flags.isolated and sys.dont_write_bytecode and __debug__ and os.getuid()==os.geteuid()==1000):raise ValueError('isolated ordinary Root entry')
 return run(a.parameters,a.parameters_sha256)
if __name__=='__main__':raise SystemExit(main())
