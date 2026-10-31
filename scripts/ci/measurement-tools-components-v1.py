#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite measurement CI fixture and explicitly scoped source/private tests."""
import argparse,ast,contextlib,hashlib,importlib.util,json,os,shlex,shutil,stat,subprocess,sys,unittest
from pathlib import Path
PROFILE='manifests/measurement-tools-source-20261028.json'
PROFILE_SHA='24692e6754b466c9172343c80883733fe14b240b18d15b87b109aed397c14ec0'
RECIPE='packages/tools/cachy-asahi-measurement-tools'
def need(ok,why):
 if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def fixture(root,work):
 body=(root/PROFILE).read_bytes();need(sha(body)==PROFILE_SHA,'exact measurement profile');profile=json.loads(body);rows=profile['files'];need(len(rows)==24,'exact finite24 source rows');out=work/'source';out.mkdir();names=set()
 for row in [*rows,dict(path=PROFILE,bytes=len(body),sha256=PROFILE_SHA,mode='0644')]:
  name=row['path'];p=Path(name);need(name not in names and not p.is_absolute()and all(x not in('','..','.')for x in p.parts),'finite unique relative source path');names.add(name);source=root/p;st=source.lstat();need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and not source.is_symlink(),'ordinary fixture input');raw=source.read_bytes();need(len(raw)==row['bytes']and sha(raw)==row['sha256']and stat.S_IMODE(st.st_mode)==int(row['mode'],8),'whole fixture byte/mode pin');target=out/p;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(int(row['mode'],8))
 return out
def static(root):
 adapter=load('measurement_adapter',root/'scripts/checks/check_measurement_tools_v1.py');original=root/'scripts/checks/measurement_tools_package_checks_original_v1.py';need(sha(original.read_bytes())==adapter.ORIGINAL_SHA256,'adapter original checker pin');checks=load('measurement_original_checks',original);report=checks.recipe(root/RECIPE/'PKGBUILD');need(not report['errors'],str(report['errors']));need(report['metadata']['depends']==['python>=3.12'],'supported package Python minimum');print(json.dumps(dict(status='PASS_RETAINED_STATIC_ADAPTER_RECIPE_API',fresh_scope='recipe API only; no makepkg, archive inspection or workloads',makepkg_printsrcinfo='NOT_RUN_HERE_RETAINED_HOST_RECEIPT_ONLY',archive_static='NOT_RUN_HERE_RETAINED_HOST_RECEIPT_ONLY',native='NOT_RUN'),sort_keys=True))
@contextlib.contextmanager
def discovered_source_fixture(tests,root,work):
 """Bind every discovered measurement source control; never filter or skip one."""
 def cases(tests):
  for test in tests:
   if isinstance(test,unittest.TestSuite):yield from cases(test)
   else:yield test
 target=(root/'scripts/release/test_measurement_tools_source_delivery_v1.py').resolve();selected=[];modules=set()
 for test in cases(tests):
  module=sys.modules.get(type(test).__module__)
  if module is not None and getattr(module,'__file__',None)and Path(module.__file__).resolve()==target:
   selected.append(test);modules.add(module)
 if not selected:
  yield
  return
 need(len(selected)==4 and len(modules)==1,'all four discovered measurement source controls required');module=next(iter(modules));previous=module.ROOT;need(previous is None,'discovered source fixture was already configured');module.ROOT=fixture(root,work)
 try:yield
 finally:module.ROOT=previous
def suite(root,kind,work):
 relative='scripts/release/test_measurement_tools_source_delivery_v1.py'if kind=='source'else RECIPE+'/test_package.py';module=load('measurement_'+kind,root/relative)
 if kind=='source':module.ROOT=root;expected=4
 else:module.RECIPE=root/RECIPE;module.EVIDENCE=work/'package-evidence';expected=8
 tests=unittest.defaultTestLoader.loadTestsFromModule(module);need(tests.countTestCases()==expected,'exact focused count');result=unittest.TextTestRunner(verbosity=2,failfast=True).run(tests);need(result.wasSuccessful()and not result.skipped and result.testsRun==expected,'focused tests failed/skipped/incomplete')
def package(root,work):
 need(shutil.which('bwrap')is not None,'BLOCKED_REQUIRED_SANDBOX: bwrap unavailable; no fallback');selected=Path(sys.executable).resolve();need(selected!=Path('/usr/bin/python3').resolve(),'BLOCKED_SELECTED_INTERPRETER: setup-python isolated prefix required for private launcher bridge');bridge=work/'python-driver';bridge.write_text('#!/bin/sh\nexec '+shlex.quote(str(selected))+' "$@"\n');bridge.chmod(0o755)
 # The fixed installed shebang and workload path select this interpreter only
 # inside a private mount namespace. No host symlink or security policy changes.
 box=['bwrap','--die-with-parent','--ro-bind','/','/','--bind',str(work),str(work),'--ro-bind',str(bridge),'/usr/bin/python3','--dev','/dev','--tmpfs','/sys','--unshare-net','--unshare-pid','--proc','/proc','--']
 check=subprocess.run([*box,'/usr/bin/true'],capture_output=True,timeout=20)
 if check.returncode:
  sys.stderr.buffer.write(check.stderr[:8192]);raise ValueError('BLOCKED_REQUIRED_SANDBOX: private PID/proc/dev/empty-sys/network prerequisite refused; eight controls NOT_RUN; no sudo/unconfined/skip fallback')
 command=[*box,str(selected),'-I','-B','-Werror::ResourceWarning',str(Path(__file__).resolve()),'package-inner','--root',str(root),'--work',str(work)];result=subprocess.run(command,timeout=180);need(result.returncode==0,'eight private package controls failed; no fallback')
# CI-only supported disposable guest. Original package()/Source25 stay unchanged.
GUEST_IMAGE_URL='https://chuangtzu.ftp.acc.umu.se/images/cloud/trixie/20261026-2643/debian-13-generic-amd64-20261026-2643.qcow2'
GUEST_IMAGE_BYTES=438894592
GUEST_IMAGE_SHA512='5bd891c6e62d01639f52a5587b72a4607421e445732214be787dba6043cf9797a6ff90bed982aada6a6c7e619f1f956d961c4fad76757171abd607920aac098a'
def guest_config(helper_sha,python_mm):
 need(len(helper_sha)==64 and all(c in '0123456789abcdef' for c in helper_sha),'helper digest')
 need(python_mm in ('3.12','3.14'),'guest Python matrix')
 # No host mount, SSH/key, host capability, policy or sysctl adjustment. The
 # root bootstrap installs dependencies in this disposable guest only.
 script='''set -eu
package_started=0
bootstrap_log=/run/measurement-bootstrap.log
bootstrap_stage=prepare
finish() {
 rc=$?
 trap - EXIT
 if ! tail -c 524289 -- "$bootstrap_log" > /dev/ttyS0; then
  printf '\\nMEASUREMENT_BOOTSTRAP_LOG_EXPORT=FAILED\\n' > /dev/ttyS0 || :
 fi
 printf '\\nMEASUREMENT_BOOTSTRAP_STAGE=%s exit=%d\\n' "$bootstrap_stage" "$rc" > /dev/ttyS0
 printf '\\nMEASUREMENT_GUEST_RESULT={"exit":%d,"package_started":%d,"helper_sha256":"HELPER_SHA","python":"PYTHON_MM","profile_sha256":"PROFILE_PIN"}\\n' "$rc" "$package_started" > /dev/ttyS0
 /sbin/poweroff
 exit "$rc"
}
trap finish EXIT
bootstrap_umask=$(umask)
umask 077
exec > "$bootstrap_log" 2>&1
umask "$bootstrap_umask"
export DEBIAN_FRONTEND=noninteractive
bootstrap_stage=apt-update
apt-get update -qq
bootstrap_stage=apt-install
apt-get install --yes --quiet --no-install-recommends bubblewrap python3 libssl3t64 libexpat1 libzstd1 libffi8 liblzma5 libbz2-1.0 libsqlite3-0 libreadline8t64 libncursesw6 libuuid1
bootstrap_stage=source-setup
install -d /mnt/measureci /opt/measurement
mount -o ro /dev/disk/by-label/MEASURECI /mnt/measureci
cd /mnt/measureci
sha256sum -c SHA256SUMS
python3 -I -B -c 'import tarfile; t=tarfile.open("python.tar"); t.extractall("/opt/measurement", filter="data"); t.close()'
cp helper.py /opt/measurement/helper.py
cp -a source /opt/measurement/source
printf '%s  %s\\n' HELPER_SHA /opt/measurement/helper.py | sha256sum -c -
bootstrap_stage=python-probe
env LD_LIBRARY_PATH=/opt/measurement/python/lib /opt/measurement/python/bin/python3 -I -B -c 'import sys,ssl,hashlib,zlib,bz2,lzma,ctypes,sqlite3; assert sys.version_info[:2] == tuple(map(int,"PYTHON_MM".split(".")))'
bootstrap_stage=package8
package_started=1
runuser -u measurement -- env LD_LIBRARY_PATH=/opt/measurement/python/lib /opt/measurement/python/bin/python3 -I -B -Werror::ResourceWarning /opt/measurement/helper.py package --root /opt/measurement/source --work /home/measurement/package-ci
'''.replace('HELPER_SHA',helper_sha).replace('PYTHON_MM',python_mm).replace('PROFILE_PIN',PROFILE_SHA)
 return {'users':[{'name':'measurement','lock_passwd':True,'shell':'/bin/bash'}],
         'ssh_pwauth':False,'disable_root':True,'package_update':False,
         'runcmd':[['/bin/bash','-ec',script]]}
def guest_verdict(raw,helper_sha,python_mm):
 records=[]
 for line in raw.decode('utf-8','replace').splitlines():
  if line.startswith('MEASUREMENT_GUEST_RESULT='):
   records.append(json.loads(line.split('=',1)[1]))
 need(len(records)==1,'exact one guest terminal receipt required')
 expected=dict(exit=0,package_started=1,helper_sha256=helper_sha,python=python_mm,profile_sha256=PROFILE_SHA)
 need(records[0]==expected and type(records[0].get('exit'))is int and type(records[0].get('package_started'))is int,'guest bootstrap/package result differs; no incomplete promotion')
 need(b'Ran 8 tests in 'in raw and b'\nOK'in raw.replace(b'\r\n',b'\n'),'original eight-control runner completion required')
 return records[0]
def guest_diagnostics(raw):
 import re
 lines=[]
 for line in raw.decode('utf-8','replace').splitlines():
  if re.search(r'authorization|cookie|password|secret|(?:gh|github)_token|api[_-]?key|access[_-]?token|token\s*[:=]|private.key',line,re.I):
   lines.append('[sensitive field omitted]');continue
  lines.append(re.sub(r'https?://[^\s]+','[URL omitted]',line))
 # Anchor the bounded diagnostic window at the terminal receipt; later
 # shutdown chatter must not discard the bootstrap failure or receipt.
 terminal=[i for i,line in enumerate(lines)if line.startswith('MEASUREMENT_GUEST_RESULT=')]
 if terminal:lines=lines[:terminal[-1]+1]
 return '\n'.join(lines)[-16384:]
GUEST_OWNER_SHA256='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
_guest_unresolved=None
def guest_supervisor(owner,cancel):
 """CI-only v1 copy: exactly two cooperative checks in protected source points."""
 import copy
 raw=Path(owner.__file__).read_bytes();need(sha(raw)==GUEST_OWNER_SHA256,'exact cancellation-owner source pin')
 tree=ast.parse(raw);source=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='supervise');derived=copy.deepcopy(source)
 protected=[n for n in derived.body if isinstance(n,ast.Try)];need(len(protected)==1,'one reviewed protected owner try')
 protected=protected[0];loops=[n for n in protected.body if isinstance(n,ast.While)];need(len(loops)==1,'one reviewed active owner loop')
 check=ast.parse("if _measurement_guest_cancel_v1[0]: raise KeyboardInterrupt('guest cancellation signal '+str(_measurement_guest_cancel_v1[0]))").body[0]
 protected.body.insert(0,copy.deepcopy(check));loops[0].body.insert(0,copy.deepcopy(check))
 verify=copy.deepcopy(derived);t=next(n for n in verify.body if isinstance(n,ast.Try));w=next(n for n in t.body if isinstance(n,ast.While));need(ast.dump(t.body.pop(0))==ast.dump(check)and ast.dump(w.body.pop(0))==ast.dump(check),'exact two cancellation checks')
 need(ast.dump(verify,include_attributes=False)==ast.dump(source,include_attributes=False),'all original owner operations held')
 namespace=dict(owner.__dict__);need('_measurement_guest_cancel_v1'not in namespace,'fresh CI cancellation binding');namespace['_measurement_guest_cancel_v1']=cancel
 module=ast.fix_missing_locations(ast.Module(body=[derived],type_ignores=[]));exec(compile(module,str(owner.__file__)+'::guest-term-v1','exec'),namespace)
 return namespace['supervise']
def guest_failure(error,ownership='NOT_STARTED'):
 return dict(passed=False,exit=None,reaped=False,ownership=ownership,timeout=False,signals=[],output=b'',output_complete=False,group_census='UNKNOWN'if ownership=='UNKNOWN'else'NOT_OBSERVED',error=type(error).__name__+': '+str(error)[:300],seconds=None)
@contextlib.contextmanager
def guest_custody(owner,argv,work):
 """One owner through retirement/export. SIGTERM/SIGINT handlers never raise."""
 import signal
 global _guest_unresolved
 stops={signal.SIGTERM,signal.SIGINT};previous={};mask=None;child=None;transferred=False;cancel=[0];phase='prepare';result=None
 def stopped(signum,frame):
  if not cancel[0]:cancel[0]=signum
 try:
  need(_guest_unresolved is None,'prior guest wait remains unresolved; no further launch')
  supervise=guest_supervisor(owner,cancel)
  owner.prepare()
  previous={sig:signal.getsignal(sig)for sig in stops}
  mask=signal.pthread_sigmask(signal.SIG_BLOCK,stops)
  need(not(mask&stops),'cancellation signals must be unblocked before guest launch')
  phase='handler-install'
  for sig in stops:signal.signal(sig,stopped)
  phase='handler-unmask'
  signal.pthread_sigmask(signal.SIG_SETMASK,mask)  # Child inherits the original unblocked mask.
  if cancel[0]:raise KeyboardInterrupt('guest cancellation before launch')
  phase='launch'
  child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
  phase='supervise';transferred=True
  result=supervise(child,cap=180,retirement=.5,grace=.1)
 except BaseException as error:
  if child is not None and not transferred:
   # Only this branch still owns a fresh child never given to supervise().
   # A shorter failure retirement cannot renew the normal 180s run budget.
   try:result=owner.supervise(child,cap=.6,retirement=.5,grace=.1)
   except BaseException as cleanup:result=guest_failure(cleanup,'UNKNOWN')
   result['passed']=False;result['wrapper_error']=type(error).__name__+': '+str(error)[:300]
   result['error']=result.get('error')or result['wrapper_error']
  else:result=guest_failure(error,'UNKNOWN'if transferred else'NOT_STARTED')
 finally:
  # No handler restoration, caller logging or export precedes bounded custody.
  if child is not None and not result.get('reaped'):
   child._child_created=False  # Never let Popen's destructor turn ECHILD into zero.
   _guest_unresolved=(child,result)
   for pipe in (child.stdout,child.stderr):
    if pipe is not None:
     try:pipe.close()
     except OSError:pass  # No reads, numeric probes, signals or wait retries.
  try:
   before_export=signal.pthread_sigmask(signal.SIG_BLOCK,stops)
   if mask is None:mask=before_export
   pending=signal.sigpending()&stops
   if not cancel[0]and pending:cancel[0]=min(pending)
  except BaseException as error:
   result['passed']=False;result['signal_block_error']=type(error).__name__+': '+str(error)[:300]
  result.update(cancel_signal=cancel[0]or None,custody_phase=phase,supervisor_variant='CI_GUEST_TERM_V1_TWO_PROTECTED_CHECKS')
  if cancel[0]:
   result['passed']=False;result['error']=result.get('error')or 'guest cancellation signal '+str(cancel[0])
 body_error=None
 try:yield result
 except BaseException as error:body_error=error;raise
 finally:
  # Still blocked through caller serial/supervision/error export. Restore every
  # saved handler even after a partial install; never touch the child here.
  failures=[]
  for sig,handler in previous.items():
   try:signal.signal(sig,handler)
   except BaseException as error:failures.append(type(error).__name__+': '+str(error)[:300])
  if not failures and mask is not None:
   try:signal.pthread_sigmask(signal.SIG_SETMASK,mask)
   except BaseException as error:failures.append(type(error).__name__+': '+str(error)[:300])
  if failures:
   blocked=None
   try:signal.pthread_sigmask(signal.SIG_BLOCK,stops);blocked=True
   except BaseException:pass
   try:
    restoration=dict(status='FAIL',errors=failures,child_reaped=result['reaped'],ownership=result['ownership'],signals_left_blocked=blocked)
    (work/'guest-handler-restore-error.json').write_text(json.dumps(restoration,sort_keys=True)+'\n')
    print(guest_diagnostics(json.dumps(dict(guest_signal_restoration=restoration),sort_keys=True).encode()),flush=True)
   except BaseException:
    if body_error is None:raise
   if body_error is None:raise ValueError('guest signal restoration failed after custody/export')

def guest(root,work):
 import tarfile,urllib.request
 need(os.geteuid()!=0,'ordinary host guest owner required')
 need(all(shutil.which(x)for x in ('qemu-system-x86_64','qemu-img','cloud-localds','genisoimage')),'explicit disposable VM tools required')
 selected=Path(sys.executable).resolve();prefix=Path(sys.base_prefix).resolve();need(selected.is_relative_to(prefix)and selected!=Path('/usr/bin/python3').resolve(),'separate selected Python prefix required')
 need(','not in str(work),'QEMU work path must not contain option separator')
 python_mm='.'.join(map(str,sys.version_info[:2]));need(python_mm in ('3.12','3.14'),'exact guest Python matrix')
 image=work/'debian.qcow2';h=hashlib.sha512();count=0
 with urllib.request.urlopen(GUEST_IMAGE_URL,timeout=20)as response,image.open('xb')as target:
  need(response.url==GUEST_IMAGE_URL,'exact official image origin; no redirect')
  while True:
   chunk=response.read(1024**2)
   if not chunk:break
   count+=len(chunk);need(count<=1024**3,'guest image byte bound');target.write(chunk);h.update(chunk)
 need(count==GUEST_IMAGE_BYTES and h.hexdigest()==GUEST_IMAGE_SHA512,'official dated guest image size/SHA512 differs')
 inputs=work/'guest-inputs';inputs.mkdir();shutil.copytree(root,inputs/'source');helper=(Path(__file__).resolve()).read_bytes();helper_sha=sha(helper);(inputs/'helper.py').write_bytes(helper)
 total=0
 with tarfile.open(inputs/'python.tar','w',format=tarfile.PAX_FORMAT)as archive:
  for path in [prefix,*sorted(prefix.rglob('*'))]:
   st=path.lstat();need(stat.S_ISREG(st.st_mode)or stat.S_ISDIR(st.st_mode)or stat.S_ISLNK(st.st_mode),'ordinary selected Python prefix')
   if path.is_symlink():need(path.resolve(strict=True).is_relative_to(prefix),'Python symlink must remain inside selected prefix')
   total+=st.st_size if stat.S_ISREG(st.st_mode)else 0;need(total<=1024**3,'selected interpreter prefix byte bound')
   archive.add(path,arcname='python'+('/'+str(path.relative_to(prefix))if path!=prefix else''),recursive=False)
 (inputs/'SHA256SUMS').write_text(''.join(sha((inputs/name).read_bytes())+'  '+name+'\n'for name in ('python.tar','helper.py')))
 subprocess.run(['genisoimage','-quiet','-R','-V','MEASURECI','-o',str(work/'inputs.iso'),str(inputs)],check=True,timeout=20)
 (work/'user-data').write_text('#cloud-config\n'+json.dumps(guest_config(helper_sha,python_mm))+'\n')
 (work/'meta-data').write_text(json.dumps({'instance-id':'measurement-'+helper_sha[:12]+'-'+python_mm,'local-hostname':'measurement-ci'})+'\n')
 subprocess.run(['cloud-localds',str(work/'seed.iso'),str(work/'user-data'),str(work/'meta-data')],check=True,timeout=20)
 subprocess.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(image),str(work/'run.qcow2')],check=True,timeout=20)
 subprocess.run(['qemu-img','resize',str(work/'run.qcow2'),'8G'],check=True,timeout=20)
 argv=['qemu-system-x86_64','-accel','tcg,thread=multi','-cpu','max','-smp','2','-m','2048','-display','none','-serial','stdio','-monitor','none','-no-reboot','-drive','file='+str(work/'run.qcow2')+',if=virtio,format=qcow2','-drive','file='+str(work/'seed.iso')+',media=cdrom,readonly=on','-drive','file='+str(work/'inputs.iso')+',media=cdrom,readonly=on','-nic','user,model=virtio-net-pci']
 owner=load('measurement_guest_owner',root/RECIPE/'owned_process.py')
 with guest_custody(owner,argv,work)as result:
  (work/'guest-serial.log').write_bytes(result['output'])
  record={k:v for k,v in result.items()if k!='output'}
  (work/'guest-supervision.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
  print(guest_diagnostics(json.dumps(dict(guest_supervision=record),sort_keys=True).encode()),flush=True)
  print('Bounded guest diagnostic tail; full raw serial retained privately in work directory:')
  print(guest_diagnostics(result['output']),flush=True)
  need(result['passed']and result['exit']==0 and result['reaped']and result['error']is None and result['output_complete']and not result['timeout']and not result['signals']and result['ownership']=='REAPED'and result['group_census']=='EMPTY_TWICE','guest must exit naturally with complete owned supervision; preserve raw failure')
  receipt=guest_verdict(result['output'],helper_sha,python_mm)
 (work/'guest-result.json').write_text(json.dumps(dict(status='PASS_GUEST_PACKAGE8_ONLY',receipt=receipt,image_sha512=GUEST_IMAGE_SHA512,image_bytes=count,scope='x86_64 disposable Debian guest; original private package8 only; no ARM/ALPM/M2/performance acceptance'),sort_keys=True,indent=2)+'\n')
 print(json.dumps(dict(status='PASS_GUEST_PACKAGE8_ONLY',python=python_mm,tests=8,skipped=0,profile_sha256=PROFILE_SHA,native='NOT_RUN',M2='NOT_RUN',performance='NOT_MEASURED'),sort_keys=True))

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=['inspect','source','package','package-inner','guest']);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--work',type=Path,required=True);args=parser.parse_args();need(sys.version_info>=(3,12),'Python>=3.12 required');root=args.root.resolve(strict=True);work=args.work.absolute()
 if args.mode=='package-inner':
  need(os.geteuid()!=0 and Path('/proc/self').is_dir()and Path('/dev/null').exists()and not any(Path('/sys').iterdir()),'private ordinary-user proc/dev/empty-sys prerequisite');print(json.dumps(dict(driver=sys.version,installed_launcher_python=sys.executable,scope='PRIVATE_FIXTURE_ONLY_NO_HOST_SENSOR_OR_SESSION_CENSUS_NO_NATIVE_OR_PERFORMANCE'),sort_keys=True));suite(root,'package',work);return
 need(not work.exists(),'fresh private work required');work.mkdir(mode=0o700,parents=True);root=fixture(root,work);static(root)
 for rel,count in [('scripts/release/test_measurement_tools_source_delivery_v1.py',4),(RECIPE+'/test_package.py',8)]:
  node=ast.parse((root/rel).read_bytes());need(sum(isinstance(x,ast.FunctionDef)and x.name.startswith('test_')for x in ast.walk(node))==count,'static focused suite count')
 if args.mode=='source':suite(root,'source',work)
 elif args.mode=='package':package(root,work)
 elif args.mode=='guest':guest(root,work)
 else:print(json.dumps(dict(status='PASS_FINITE25_FIXTURE_AND_STATIC_WIRING_ONLY',source_controls='RETAINED_NOT_RERUN',package_controls='RETAINED_NOT_RERUN',package_bwrap_actors=0),sort_keys=True))
if __name__=='__main__':main()
