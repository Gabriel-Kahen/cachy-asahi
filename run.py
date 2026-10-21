# SPDX-License-Identifier: MIT
"""Native diagnostic triplet only; no package build, install or profile promotion."""
import argparse,hashlib,importlib.util,json,os,platform,re,shutil,signal,stat,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import profiles as P
pin=lambda raw:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def need(ok,why):
 if not ok:raise ValueError(why)
def enc(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def save(path,raw):
 with Path(path).open('xb')as stream:stream.write(raw)
def command(argv,seconds,out,name):
 started=time.monotonic();timed_out=False
 try:r=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=seconds,env=dict(os.environ));code=r.returncode;stdout=r.stdout;stderr=r.stderr
 except subprocess.TimeoutExpired as error:timed_out=True;code=None;stdout=error.stdout or b'';stderr=error.stderr or b''
 need(len(stdout)+len(stderr)<=8*1024**2,'bounded diagnostic command');save(out/(name+'.stdout'),stdout);save(out/(name+'.stderr'),stderr);return dict(argv=argv,exit_code=code,timed_out=timed_out,limit_seconds=seconds,elapsed_seconds=time.monotonic()-started,stdout=pin(stdout),stderr=pin(stderr)),stdout


def arguments(name,image,out,kind,profile):
 args=['docker','run','--name',name,'--label','org.cachy-asahi.userns-probe='+name,'--pull=never','--platform','linux/arm64','--user','1001:1001','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--pids-limit','64','--memory','512m','--cpus','1','--network','none','--tmpfs','/tmp:rw,nosuid,nodev,exec,size=16m','--tmpfs','/var/tmp:rw,nosuid,nodev,exec,size=2g,mode=1777','--tmpfs','/run:rw,nosuid,nodev,noexec,size=16m,mode=0700,uid=1001,gid=1001','--mount','type=bind,src='+str(out)+',dst=/out']
 if kind!='default':args+=['--security-opt','seccomp='+str(profile)]
 return args+[image]
def retire(name,image,out):
 r=subprocess.run(['docker','container','inspect',name],capture_output=True,timeout=5)
 if r.returncode:
  need(b'No such'in r.stderr,'owned inspect absence is explicit');return dict(status='ABSENT_BEFORE_RETIRE',name=name)
 v=json.loads(r.stdout);need(len(v)==1 and v[0]['Name']=='/'+name and v[0]['Image']==image and(v[0]['Config'].get('Labels')or{}).get('org.cachy-asahi.userns-probe')==name,'same owned exact diagnostic actor');before=v[0];r=subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=5);need(r.returncode==0,'owned diagnostic removal');after=subprocess.run(['docker','container','inspect',name],capture_output=True,timeout=5);need(after.returncode!=0 and b'No such'in after.stderr,'exact owned actor absence');return dict(status='OWNED_REMOVED_AND_ABSENT',name=name,inspect=before,remove=dict(exit_code=r.returncode,stdout=pin(r.stdout),stderr=pin(r.stderr)))
def source():
 raw=(HERE/'source-manifest.json').read_bytes();v=json.loads(raw);need(len(v['files'])>0,'whole diagnostic source manifest');actual={p.relative_to(HERE).as_posix():pin(p.read_bytes())for p in HERE.rglob('*')if p.is_file()and'.git'not in p.parts and p.name!='source-manifest.json'};need(actual==v['files'],'whole exact diagnostic source, no unreferenced role');return v

def main():
 a=argparse.ArgumentParser();a.add_argument('--output',type=Path,required=True);args=a.parse_args();out=args.output.absolute();need(not out.exists()and out.parent.is_dir(),'fresh outside-source diagnostic output');need(not out.is_relative_to(HERE)and not HERE.is_relative_to(out),'separate diagnostic output');out.mkdir(mode=0o700);started=time.monotonic();manifest=source();identity=dict(source=os.environ['GITHUB_SHA'],workflow_source=os.environ['GITHUB_WORKFLOW_SHA'],run=int(os.environ['GITHUB_RUN_ID']),attempt=int(os.environ['GITHUB_RUN_ATTEMPT']));need(re.fullmatch('[a-f0-9]{40}',identity['source'])and identity['source']==identity['workflow_source']and identity['run']>0 and identity['attempt']==1,'exact reviewed first-attempt source/run/workflow');need(platform.machine()in('aarch64','arm64')and os.sysconf('SC_PAGESIZE')==4096 and os.getuid()==1001 and os.getgid()==1001,'same actual nativeARM4K ordinary1001 identity');version,raw=command(['docker','version','--format','{{json .Server}}'],10,out,'docker-version');need(version['exit_code']==0,'fresh actual Engine version');server=json.loads(raw);need(server['Version']=='28.0.4','exact Moby28.0.4 profile version, drift remains unqualified');info,security=command(['docker','info','--format','{"architecture":{{json .Architecture}},"os":{{json .OSType}},"security":{{json .SecurityOptions}}}'],10,out,'docker-security');need(info['exit_code']==0,'actual Docker security options');docker_info=json.loads(security);need(docker_info['architecture']in('aarch64','arm64')and docker_info['os']=='linux','native ARM Docker daemon');host={}
 for name,path in dict(status='/proc/self/status',lsm='/sys/kernel/security/lsm',apparmor='/proc/sys/kernel/apparmor_restrict_unprivileged_userns',userns='/proc/sys/kernel/unprivileged_userns_clone',max_userns='/proc/sys/user/max_user_namespaces').items():
  try:raw=Path(path).read_bytes();need(len(raw)<=1024**2,'bounded host diagnostic')
  except OSError as error:raw=('UNREADABLE errno='+str(error.errno)+'\n').encode()
  save(out/('host-'+name+'.txt'),raw);host[name]=pin(raw)
 context=out/'context';context.mkdir();(context/'root/usr').mkdir(parents=True);(context/'root/proc').mkdir();(context/'root/out').mkdir();(context/'root/usr/marker').write_text('owned chroot root\n');compiler=[]
 for src,target in(('probe.c','held-probe'),('diagnostics.c','diagnostics')):
  argv=['/usr/bin/cc','-std=gnu11','-static','-O2','-Wall','-Wextra','-Werror','-I',str(HERE),'-o',str(context/'root'/target),str(HERE/src)];row,raw=command(argv,30,out,'compile-'+target);need(row['exit_code']==0,'native static diagnostic compiler');binary=(context/'root'/target).read_bytes();need(binary[:4]==b'\x7fELF'and binary[18:20]==b'\xb7\x00','actual native AARCH64 static binary');row['binary']=pin(binary);compiler.append(row)
 (context/'Dockerfile').write_text('FROM scratch\nCOPY root/ /\nUSER 1001:1001\nENTRYPOINT ["/diagnostics"]\n');tag='caa-userns-probe:'+os.urandom(8).hex();build,raw=command(['docker','build','--network=none','--pull=false','--tag',tag,str(context)],60,out,'image-build');need(build['exit_code']==0,'scratch-only image build');inspection,raw=command(['docker','image','inspect',tag],10,out,'image-inspect');need(inspection['exit_code']==0,'owned static image inspect');image=json.loads(raw)[0];need(image['Architecture']=='arm64'and image['Os']=='linux'and image['Config']['User']=='1001:1001','exact native private static image');image_id=image['Id'];base=json.loads((HERE/'moby-default.json').read_bytes());results=[]
 spec=importlib.util.spec_from_file_location('_held_original58_receipt',HERE/'probe_receipt.py');validator=importlib.util.module_from_spec(spec);spec.loader.exec_module(validator)
 try:
  for kind in('default','user-only','user-and-chroot'):
   cell=out/kind;cell.mkdir(mode=0o700);profile=out/(kind+'-seccomp.json');save(profile,enc(P.selected(base,kind)));name='caa-userns-'+os.urandom(8).hex();argv=arguments(name,image_id,cell,kind,profile);result=dict(configuration=kind,identity=identity,original_probe={n:manifest['files'][n]for n in('probe.c','caa-owned-userns.h','probe_receipt.py')},profile=pin(profile.read_bytes()),command=argv,mechanism_pass=False,acceptance=False)
   try:
    row,stdout=command(argv,20,out,kind);result['process']=row;stderr=(out/(kind+'.stderr')).read_bytes()
    if row['exit_code']==0 and not stderr:
     result['original58']=validator.parse(stdout,'native-preflight');result['mechanism_pass']=True
   except Exception as error:result['error']=dict(type=type(error).__name__,message=str(error))
   finally:result['retirement']=retire(name,image_id,out)
   result['diagnostics']={p.name:pin(p.read_bytes())for p in cell.iterdir()if p.is_file()};save(out/(kind+'-result.json'),enc(result));results.append(result)
 finally:
  row,raw=command(['docker','image','rm',tag],30,out,'owned-image-retire');need(row['exit_code']==0,'remove own diagnostic image tag only')
 result=dict(schema=1,status='COMPLETE_NATIVE_THREE_PROFILE_DIAGNOSTIC_ONLY',identity=identity,source=manifest,native=dict(machine=platform.machine(),page_size=os.sysconf('SC_PAGESIZE'),uid=os.getuid(),gid=os.getgid(),kernel=platform.release(),docker_server=server,docker_info=docker_info),host=host,compiler=compiler,image=image,configurations=results,elapsed_seconds=time.monotonic()-started,package_build='NOT_RUN',systemd_assertions='NOT_RUN_ORIGINAL58_MECHANISM_ONLY',profile_promotion='NOT_GRANTED',hardware='NOT_RUN',acceptance=False);save(out/'result.json',enc(result));print(enc(result).decode(),end='')
def interrupted(*_):raise KeyboardInterrupt('bounded diagnostic interrupted')
if __name__=='__main__':
 signal.signal(signal.SIGTERM,interrupted);main()
