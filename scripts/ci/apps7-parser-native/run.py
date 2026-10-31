#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One cap0 native consumer of the original owned574 image; no package mutations."""
import argparse,fcntl,json,os,platform,re,signal,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

def argv(source,image,name,token):
 p=C.policy();return ['/usr/bin/docker','run','--name',name,'--pull=never','--platform=linux/arm64','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--pids-limit='+str(p['pids']),'--memory='+str(p['memory_bytes']),'--cpus='+str(p['cpus']),'--user',str(os.getuid())+':'+str(os.getgid()),'--label='+C.LABEL+'='+token,'--env=CACHY_ASAHI_APPS_PARSER_NATIVE=1','--mount','type=bind,src='+str(source/C.LANE)+',dst=/inputs,readonly','--entrypoint=/usr/bin/python3',image,'-I','-B','/inputs/worker.py']
def _execute(source,base,out,token):
 C.verify_source(source);p=C.policy();C.need(platform.system()=='Linux'and platform.machine()=='aarch64'and os.getuid()==os.geteuid()>0 and not any(k.startswith('DOCKER_')for k in os.environ),'ordinary nativeARM host')
 for path in(source,base,out):C.safe(path)
 C.need(not out.exists()and not out.is_relative_to(source)and not source.is_relative_to(out)and not out.is_relative_to(base)and not base.is_relative_to(out)and re.fullmatch('[a-f0-9]{32}',token),'fresh owned consumer scope')
 original=C.obj(C.read(base/'report.json'));image=C.read(base/'image-id').decode().strip();C.need(original['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION'and original['image']==image and re.fullmatch('sha256:[a-f0-9]{64}',image)and C.digest(base/'installed-packages.lock')==p['dataset_lock_sha256'],'exact original574 image/lock')
 def capture(args):
  r=subprocess.run(['/usr/bin/docker',*args],capture_output=True,timeout=20);C.need(r.returncode==0 and len(r.stdout)+len(r.stderr)<=1024**2,'bounded native daemon observation');return r.stdout.decode().strip()
 C.need(capture(['context','show'])=='default'and json.loads(capture(['context','inspect','default']))[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock'and capture(['info','--format','{{.Architecture}}'])in('aarch64','arm64')and capture(['image','inspect','--format','{{.Os}}/{{.Architecture}}',image])=='linux/arm64','local nativeARM daemon/image')
 out.mkdir(mode=0o700);fd=os.open(out/'consumer.lock',os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_CLOEXEC,0o600);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);name='cachy-asahi-product-'+os.urandom(16).hex();C.save(out/'owner.json',dict(schema_version=1,token=token,image=image,label=C.LABEL,containers=[name]))
 report=dict(status='INCOMPLETE',dataset_lock_sha256=p['dataset_lock_sha256'],base_image_sha256=image.split(':')[1],source_digest=C.digest(source/C.LANE/'source-manifest.json'));runner=C.load('_pinned_benchmark_group_owner',source/'scripts/ci/glibc-owned-runtime/runner.py')
 try:
  row,stdout,stderr,error=runner.run_command(argv(source,image,name,token),out,dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',TZ='UTC'),p['owner_seconds'],p['report_bytes']);(out/'worker.stdout').write_bytes(stdout);(out/'worker.stderr').write_bytes(stderr);report['command']=row;C.need(error is None and row['exit_code']==0 and row['group_absence_verified']is True,'natural worker completion/group absence');measurement=C.metrics(C.obj(stdout));(out/'measurement.json').write_bytes(C.encoded(measurement));report.update(status='COMPLETED_PARSER_EXPERIMENT_NOT_GAIN_ACCEPTANCE',measurement=C.pin(C.encoded(measurement)))
 except BaseException as e:report.update(error_kind=type(e).__name__)
 finally:C.save(out/'report.json',report);os.close(fd)
 return int(report['status']!='COMPLETED_PARSER_EXPERIMENT_NOT_GAIN_ACCEPTANCE')
def execute(source,base,out,token):
 C.verify_source(source);p=C.policy()
 def stop(*_):raise TimeoutError('finite native owner deadline/cancellation')
 previous={s:signal.signal(s,stop)for s in(signal.SIGALRM,signal.SIGINT,signal.SIGTERM)};signal.setitimer(signal.ITIMER_REAL,p['owner_seconds'])
 try:return _execute(source,base,out,token)
 finally:
  signal.setitimer(signal.ITIMER_REAL,0)
  for s,h in previous.items():signal.signal(s,h)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--base-dir',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--consumer-token',required=True);a=p.parse_args();raise SystemExit(execute(a.source.absolute(),a.base_dir.absolute(),a.output.absolute(),a.consumer_token))
