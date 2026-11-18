#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Root-admitted hosted llhttp reference bootstrap/pair; never an actor on import."""
import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import types

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('llhttp-reference_contract',HERE/'contract.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C)
LABEL='org.cachy-asahi.llhttp-minimal-builder.nonce'


def natural(row,zero=True):
    C.need(row['reaped']is True and row['ownership']=='REAPED'and row['group_census']=='EMPTY_TWICE'and row['output_complete']is True and not row['signals']and not row['timeout']and row['error']is None and type(row['exit'])is int and 0<=row['exit']<=255 and row['passed']is(row['exit']==0)and(not zero or row['exit']==0),'natural owned command retirement required')


class Commands:
    def __init__(self,O,out,end,cleanup_end,state):
        self.O,self.out,self.end,self.cleanup_end,self.state=O,out,end,cleanup_end,state
        self.rows=[];self.lock=threading.RLock();O.prepare()

    def __call__(self,argv,seconds=60,check=True,env=None):
        with self.lock:
            C.need(not self.state.pending or self.state.cleaning,'cancelled before command')
            remaining=(self.cleanup_end if self.state.cleaning else self.end)-time.monotonic()
            C.need(remaining>1 and len(self.rows)<512,'finite whole operation/command count')
            C.need(type(seconds)in(int,float)and math.isfinite(seconds)and seconds>1,'finite prelaunch command deadline')
            cap=min(seconds,remaining);label=f'{len(self.rows):03d}';child=None;row=fallback=first=None;secondary=[]
            def limits():
                resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3))
                resource.setrlimit(resource.RLIMIT_CPU,(math.ceil(cap)+5,math.ceil(cap)+5))
                resource.setrlimit(resource.RLIMIT_FSIZE,(16*1024**2,16*1024**2))
                resource.setrlimit(resource.RLIMIT_CORE,(0,0))
            try:
                with (self.out/(label+'.stdout')).open('xb')as stdout,(self.out/(label+'.stderr')).open('xb')as stderr:
                    os.fchmod(stdout.fileno(),0o600);os.fchmod(stderr.fileno(),0o600)
                    clean={'PATH':'/usr/bin:/bin','HOME':str(self.out),'LC_ALL':'C.UTF-8','TZ':'UTC'}
                    if env:clean.update(env)
                    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,env=clean,start_new_session=True,preexec_fn=limits)
                    row=self.O.supervise(child,cap=cap,retirement=.5,grace=.1,streams=(),max_output=0,log_fd=None)
            except BaseException as error:first=error
            finally:
                if child is not None and child.returncode is None and child._child_created:
                    try:fallback=self.O.supervise(child,cap=1.5,retirement=.5,grace=.1,streams=(),max_output=0,log_fd=None)
                    except BaseException as error:
                        if first is None:first=error
                        else:secondary.append(dict(type=type(error).__name__,message=str(error)[:500]))
            stdout=(self.out/(label+'.stdout')).read_bytes()if(self.out/(label+'.stdout')).exists()else b'';stderr=(self.out/(label+'.stderr')).read_bytes()if(self.out/(label+'.stderr')).exists()else b''
            C.need(len(stdout)<=16*1024**2 and len(stderr)<=16*1024**2,'complete finite stdout/stderr')
            if row is not None:row=dict(row);row.pop('output',None)
            if fallback is not None:fallback=dict(fallback);fallback.pop('output',None)
            record=dict(argv=list(argv),retirement=row,fallback_retirement=fallback,secondary_errors=secondary,stdout=C.pin(stdout),stderr=C.pin(stderr))
            if first is not None:record['failure']=dict(type=type(first).__name__,message=str(first)[:500])
            self.rows.append(record);(self.out/(label+'.json')).write_text(json.dumps(record,indent=2)+'\n')
            if first is not None:raise first
            natural(row,check);return subprocess.CompletedProcess(argv,row['exit'],stdout,stderr)


def resource_observation(profile,parent):
    C.need(os.getuid()==os.geteuid()>0 and platform.system()=='Linux'and platform.machine()in('aarch64','arm64'),'ordinary genuine native ARM Linux host required')
    C.need(all(shutil.which(n,path='/usr/bin:/bin')for n in('python3','docker','gpg','zstd')),'existing reviewed host Python/Docker/GPG/zstd tools required; no host installs')
    available=int(next(line.split()[1]for line in Path('/proc/meminfo').read_text().splitlines()if line.startswith('MemAvailable:')))*1024
    disk=shutil.disk_usage(parent).free
    C.need(available>=profile['resources']['minimum_available_bytes']and disk>=profile['resources']['minimum_disk_bytes'],'fresh whole-host memory/disk minimum')
    return dict(machine=platform.machine(),page_size=os.sysconf('SC_PAGE_SIZE'),uid=os.getuid(),gid=os.getgid(),MemAvailable=available,filesystem_available=disk,runner_image={n:os.environ.get(n)for n in('ImageOS','ImageVersion','RUNNER_OS','RUNNER_ARCH')})


def container_identity(row,name,image,labels,kind,out):
    C.need(row['Name']=='/'+name and row['Image']==image and row['Config']['Labels']==labels,'same exact owned container name/image/labels')
    h=row['HostConfig'];C.need(h['ReadonlyRootfs']is True and h['NetworkMode']=='none'and h['CapDrop']==['ALL']and not h.get('CapAdd')and not h['Privileged']and not h['Devices']and not h.get('DeviceRequests')and h.get('Init')in(False,None)and h.get('PidMode','')=='','ordinary cap0 NNP offline reference builder')
    C.need(h['SecurityOpt']in(['no-new-privileges'],['no-new-privileges=true']),'exact inherited NNP')
    if kind=='build':
        C.need(row['Config']['User']==str(os.getuid())+':'+str(os.getgid())and row['Config']['Entrypoint']==['/bin/bash']and row['Config']['Cmd']==['/builder-entry.sh'],'fixed ordinary normal makepkg entry')
        C.need(h['Memory']==h['MemorySwap']==4*1024**3 and h['NanoCpus']==4*10**9 and h['PidsLimit']==512 and h['Tmpfs']=={'/tmp':'rw,nosuid,nodev,exec,size=4g'},'explicit selected build resource bounds')
        expected={('bind',str(out/'inputs'),'/inputs',False),('bind',str(out/'artifacts'),'/out',True),('bind',str(HERE/'runtime/scripts/build/container-entry-v2.sh'),'/builder-entry.sh',False),('bind',str(out/'expected-packages.lock'),'/expected-packages.lock',False)}
    else:
        C.need(row['Config']['Entrypoint']==['/bin/cat']and row['Config']['Cmd']==['/builder-packages.lock'],'fixed inventory reader only')
        C.need(h['Memory']==h['MemorySwap']==512*1024**2 and h['NanoCpus']==10**9 and h['PidsLimit']==32,'finite inventory reader resources');expected=set()
    C.need(len(row['Mounts'])==len(expected)and {(m['Type'],m['Source'],m['Destination'],m['RW'])for m in row['Mounts']}==expected,'exact fixed input/output mounts')


ARCHIVE = 'https://pkgmirror.sametimetomorrow.net/aarch64/packages/'
PRIMARY = 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/'
RECOVERED_PATHS = {
    'flex-2.6.10-1-aarch64.pkg.tar.xz': 'f/flex/',
    'libffi-3.8.0-1-aarch64.pkg.tar.xz': 'l/libffi/',
    'linux-aarch64-7.3.4-3-aarch64.pkg.tar.xz': 'l/linux-aarch64/',
    'tpm2-tss-4.2.1-2-aarch64.pkg.tar.xz': 't/tpm2-tss/',
}


def recover_original_packages(native, evidence):
    """Resolve four original package URLs without altering the frozen acquisition/audit."""
    original = native.fetch
    archive_lane = threading.Lock()

    def fetch(item, cache):
        try:
            return original(item, cache)
        except native.AcquisitionError as error:
            name = item['filename']
            path = RECOVERED_PATHS.get(name)
            if (path is None or item['url'] != PRIMARY + name or error.filename != name
                    or error.category != 'HTTP failure' or error.http_status != 404):
                raise
        archived = ARCHIVE + path + name
        with archive_lane:
            evidence[name] = dict(primary=item['url'], primary_http_status=404, url=archived,
                                  expected_bytes=item['size'], expected_sha256=item['sha256'], status='ATTEMPTED')
            target = original(dict(item, url=archived), cache)
            evidence[name]['status'] = 'PASS_PINNED_BODY'
            return target

    native.fetch = fetch


def prepare_offline_pacman_conf(context):
    """Expose the exact generated public config to the in-image unprivileged builder."""
    path = C.ordinary(context / 'pacman.conf')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        before = os.fstat(stream.fileno())
        C.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
               and stat.S_IMODE(before.st_mode) in (0o600, 0o644) and before.st_size == 116,
               'owned generated offline pacman.conf')
        C.need(C.pin(stream.read(117)) == {'bytes': 116, 'sha256': '14d304eeb83baf1379279356c232580fd095c2d508b41c74677347801a0bafe7'},
               'exact reviewed offline pacman.conf bytes before Docker COPY')
        os.fchmod(stream.fileno(), 0o644)
        after = os.fstat(stream.fileno())
        C.need(os.path.samestat(before, after) and os.path.samestat(after, path.lstat())
               and stat.S_IMODE(after.st_mode) == 0o644,
               'exact offline pacman.conf mode before Docker COPY')


def bootstrap_adapter(native,runner,out,nonce,scopes,B):
    """Only existing signed bootstrap, with explicit ownership projections."""
    tag='cachy-llhttp-minimal-builder-bootstrap:'+nonce
    def call(argv,log=None,timeout=1800):
        actual=list(argv)
        if actual[:2]==['docker','build']:
            C.need(actual[2:7]==['--network=none','--pull=false','--platform=linux/arm64','--iidfile',str(out/'image-id')]and actual[-1]==str(out/'context'),'fixed unchanged scratch bootstrap command')
            prepare_offline_pacman_conf(out / 'context')
            actual=actual[:-1]+['--quiet','--tag',tag,'--label',LABEL+'='+nonce,actual[-1]]
        if actual[:2]==['docker','run']:
            image=actual[-2];C.need(actual[-3:]==['--entrypoint=/bin/cat',image,'/builder-packages.lock'],'fixed bootstrap inventory reader')
            name='cachy-llhttp-minimal-builder-'+nonce+'-inventory';image_row=json.loads(runner(['/usr/bin/docker','image','inspect',image],60).stdout)[0]
            labels=image_row['Config'].get('Labels')or{};C.need(labels.get(LABEL)==nonce,'owned freshly labelled bootstrap image')
            scope=new_scope(B,runner,name,image,labels,'inventory',out);C.need(scope.listing(time.monotonic()+8)is None,'fresh inventory-reader identity');scope.submitted=True;scopes.append(scope)
            actual=actual[:2]+['--name',name,'--cpus=1','--memory=512m','--memory-swap=512m','--pids-limit=32']+actual[2:]
        if actual[0]=='docker':actual[0]='/usr/bin/docker'
        result=runner(actual,timeout)
        if log is not None:Path(log).write_bytes(result.stdout+result.stderr)
        return result.stdout.decode().strip()
    def audit_run(argv,**kwargs):
        C.need(kwargs==dict(text=True,capture_output=True,timeout=60),'fixed original GPG verification seam')
        result=runner(argv,60,check=False);return subprocess.CompletedProcess(argv,result.returncode,result.stdout.decode(),result.stderr.decode())
    native.run=call;native.subprocess=types.SimpleNamespace(run=audit_run,SubprocessError=subprocess.SubprocessError)
    return tag


def new_scope(B,runner,name,image,labels,kind,out):
    class Scope(B.OwnedContainer):
        def call(self,argv,deadline):
            if argv[1:3]==['container','rm']and '--force'in argv:self.forced_cleanup=True
            actual=['/usr/bin/docker',*argv[1:]];return runner(actual,max(1.1,min(8,deadline-time.monotonic())),check=False)
        def validate(self,row):container_identity(row,self.name,self.image,self.labels,kind,out)
    value=Scope(name,out/(name+'.cid'),image,labels,HERE,out);value.forced_cleanup=False;return value


def retain(out):
    """Finite existing evidence encoder input; omit cache/context/keyring homes."""
    evidence=out/'evidence.incomplete';total=0
    selected=[]
    for name in('report.json','cleanup.json','comparison.json','pair.json'):
        if (out/name).is_file():selected.append((out/name,name))
    for name in('bootstrap.json','acquisition.json','signatures.json','package-audit.json','rootfs-inventory.json','rootfs-hooks.json','cache-checksums.json','packages.lock','inputs.lock.json','bootstrap.log'):
        if (out/'bootstrap'/name).is_file():selected.append((out/'bootstrap'/name,'bootstrap/'+name))
    for folder in('build-1','build-2','commands'):
        if (out/folder).is_dir():
            for path in sorted((out/folder).rglob('*')):
                C.need(not path.is_symlink(),'ordinary full evidence only')
                if path.is_file():selected.append((path,str(path.relative_to(out))))
    sizes={name:source.stat().st_size for source,name in selected};C.need(sum(sizes.values())<=15*1024**2,'complete public evidence exceeds inherited finite encoder budget')
    evidence.mkdir(mode=0o700);pins={}
    for source,name in selected:
        raw=C.read(source,16*1024**2,empty=True);total+=len(raw);C.need(len(raw)==sizes[name],'retained DATA changed during copy')
        path=evidence/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o600);pins[name]=C.pin(raw)
    (evidence/'evidence-manifest.json').write_text(json.dumps(pins,indent=2,sort_keys=True)+'\n');C.need(sum(p.stat().st_size for p in evidence.rglob('*')if p.is_file())<=16*1024**2,'whole inherited encoder budget')
    evidence.rename(out/'evidence');return dict(files=len(selected),bytes=total)


def execute(root,output,map_sha,admission,runtime):
    profile=C.load(HERE/'profile.json');C.verify_source(root,map_sha);nonce=C.admitted(admission,runtime,map_sha,os.environ,profile)
    output=C.ordinary(output);observed=resource_observation(profile,output.parent);C.need(not output.exists()and root not in output.parents,'new disjoint native operation output')
    os.umask(0o077);output.mkdir(mode=0o700);(output/'consumed.json').write_text(json.dumps(dict(nonce=nonce,source=admission['source'],admission=C.pin(json.dumps(admission,sort_keys=True).encode())))+'\n')
    for n in('commands','bootstrap','cache'):(output/n).mkdir(mode=0o700)
    O=C.module(HERE/'runtime/owned_process.py','llhttp-reference_owned');B=C.module(HERE/'runtime/reference_controller.py','llhttp-reference_container');state=B.Cancellation();state.__enter__()
    started=time.monotonic();end=started+profile['resources']['pair_seconds'];cleanup_end=end+profile['resources']['cleanup_seconds'];runner=Commands(O,output/'commands',end,cleanup_end,state)
    scopes=[];tag=None;rootfs_import=None;report=dict(status='HOLD',natural_outcome=None,cleanup=None,actual_host=observed,source=admission['source'],source_map_sha256=map_sha,canonical_admission=C.pin(json.dumps(admission,sort_keys=True).encode()),canonical_runtime=C.pin(json.dumps(runtime,sort_keys=True).encode()),ref=admission['ref'],run=os.environ['GITHUB_RUN_ID'],attempt=1,job=os.environ.get('GITHUB_JOB'),nonce=nonce,image=None,Root_acceptance=None,hardware='NOT RUN',release='NOT ADMITTED')
    def deadline(signum,frame):raise TimeoutError('whole admitted llhttp reference operation deadline')
    previous=signal.signal(signal.SIGALRM,deadline);signal.setitimer(signal.ITIMER_REAL,profile['resources']['pair_seconds'])
    try:
        C.need(profile['inputs_sha256']=='629ef92976d17f13443897b0711a54ecb3e404eea4d0d997447407d76a9baf16','exact independent206 public input profile before ordinary complete audit')
        native=C.module(HERE/'runtime/scripts/ci/native_arm.py','llhttp-reference_native');C.audit_adapter(native,C.read(HERE/'runtime/scripts/ci/native_arm.py'));tag=bootstrap_adapter(native,runner,output/'bootstrap',nonce,scopes,B)
        inputs=C.load(HERE/'runtime/scripts/ci/inputs.lock.json');shutil.copyfile(HERE/'runtime/scripts/ci/inputs.lock.json',output/'bootstrap/inputs.lock.json')
        C.seed_minimal_public_signatures(output/'cache',inputs,profile)
        recovery={};report['acquisition_recovery']=recovery;recover_original_packages(native,recovery)
        native.audit(inputs, output/'cache', output/'bootstrap')
        report['signed_rootfs'] = dict(status='PROVISIONING_PENDING')
        shared = C.module(HERE/'rootfs_bootstrap_core.py', 'minimal206_signed_rootfs_core')
        rootfs_import = shared.SignedRootfsBootstrap(native, runner, output/'bootstrap', nonce,
                                                       operation='minimal206')
        # The original offline Dockerfile RUN is the first real shell gate.
        image = native.build(inputs, output/'cache', output/'bootstrap', {})
        C.need(rootfs_import.submitted and re.fullmatch(r'sha256:[0-9a-f]{64}', rootfs_import.image or ''),
               'exact imported rootfs used for ordinary offline provisioning')
        report['signed_rootfs'] = dict(status='PROVISIONING_AND_INVENTORY_PASSED',
                                     import_image_id=rootfs_import.image)
        C.need((output/'bootstrap/packages.lock').read_bytes()==C.read(HERE/'expected206.lock'),'genuine exact freshly provisioned206 BUILD_ONLY inventory')
        image_row=json.loads(runner(['/usr/bin/docker','image','inspect',image],60).stdout)[0];C.need(image_row['Id']==image and image_row['Config']['Labels'].get(LABEL)==nonce,'exact owned bootstrap image')
        report['image']=image;report['packages_lock']=C.pin((output/'bootstrap/packages.lock').read_bytes())
        bootstrap=C.load(output/'bootstrap/bootstrap.json');bootstrap['legacy_command']=bootstrap['command'];bootstrap['command']=next(r['argv']for r in runner.rows if r['argv'][:2]==['/usr/bin/docker','build']);(output/'bootstrap/bootstrap.json').write_text(json.dumps(bootstrap,indent=2)+'\n')
        builds,compare=C.plans(HERE,output,image)
        for attempt,argv in enumerate(builds,1):
            name='cachy-llhttp-minimal-builder-'+nonce+'-'+str(attempt);labels=dict(image_row['Config']['Labels']);labels[LABEL]=nonce
            scope=new_scope(B,runner,name,image,labels,'build',output/('build-'+str(attempt)));C.need(scope.listing(time.monotonic()+8)is None,'fresh separate build identity');scope.submitted=True;scopes.append(scope)
            runner(argv,360,env={'CACHY_LLHTTP_MINIMAL_BUILDER_NONCE':nonce,'CACHY_LLHTTP_MINIMAL_BUILDER_ATTEMPT':str(attempt)})
            C.need(scope.listing(time.monotonic()+8)is None,'ordinary completed --rm build container absent')
        result=runner(compare,120);(output/'comparison.json').write_bytes(result.stdout)
        finisher=C.module(HERE/'finish_pair.py','llhttp-reference_finisher');pair=finisher.finish(output/'build-1',output/'build-2',output/'comparison.json',image);(output/'pair.json').write_text(json.dumps(pair,indent=2)+'\n')
        C.verify_source(root,map_sha)
        report.update(natural_outcome='PASS_CURRENT_LLHTTP_MINIMAL206_BUILD_ONLY_NATIVE_PAIR_AND_CHECKS',status='PAIR_PASSED_PENDING_CLEANUP',pair=pair)
    except BaseException as error:
        report.update(natural_outcome='HOLD',failure=dict(type=type(error).__name__,message=str(error)[:1000]))
    finally:
        state.cleaning=True;runner.cleanup_end=min(runner.cleanup_end,time.monotonic()+profile['resources']['cleanup_seconds']);signal.setitimer(signal.ITIMER_REAL,profile['resources']['cleanup_seconds']);cleanup=dict(containers=[],image=None,errors=[])
        for scope in reversed(scopes):
            record={}
            try:scope.cleanup(record)
            except BaseException as error:record.setdefault('cleanup_errors',[]).append(dict(type=type(error).__name__,message=str(error)[:500]))
            cleanup['containers'].append(dict(name=scope.name,forced=scope.forced_cleanup,**record))
        if tag is not None:
            try:
                listing=['/usr/bin/docker','image','ls','--all','--no-trunc','--quiet','--filter','label='+LABEL+'='+nonce]
                ids=runner(listing,8).stdout.decode().splitlines();C.need(len(ids)<=1,'one exact fresh owned image only')
                if ids:
                    image=ids[0];rows=json.loads(runner(['/usr/bin/docker','image','inspect',image],8).stdout)
                    C.need(re.fullmatch('sha256:[0-9a-f]{64}',image)and len(rows)==1 and rows[0]['Id']==image and rows[0]['Config']['Labels'].get(LABEL)==nonce and rows[0].get('RepoTags')in([tag],[])and not rows[0].get('RepoDigests'),'same exclusively owned bootstrap image before removal')
                    runner(['/usr/bin/docker','image','rm',image],30)
                C.need(not runner(listing,8).stdout.strip(),'owned nonce-labelled image absent')
                cleanup['image']=dict(image_id=ids[0]if ids else None,owned_image_absence_verified=True,cache_removed=False,build_cache_state='UNCLAIMED')
            except BaseException as error:cleanup['errors'].append(dict(step='owned-image',type=type(error).__name__,message=str(error)[:500]))
        if rootfs_import is not None:
            if report['signed_rootfs']['status'] == 'PROVISIONING_PENDING':
                report['signed_rootfs'] = dict(status='PROVISIONING_NOT_CONFIRMED',
                                             import_submitted=rootfs_import.submitted,
                                             import_image_id=rootfs_import.image)
            if cleanup['image'] and cleanup['image']['owned_image_absence_verified']:
                try:
                    cleanup['signed_rootfs_image'] = rootfs_import.cleanup()
                except BaseException as error:
                    cleanup['errors'].append(dict(step='signed-rootfs-image', type=type(error).__name__,
                                                  message=str(error)[:500]))
            else:
                cleanup['signed_rootfs_image'] = dict(status='HOLD_DERIVED_IMAGE_NOT_CLOSED')
        clean=not cleanup['errors']and all(r.get('owned_container_absence_verified')and not r.get('cleanup_errors')and not r['forced']for r in cleanup['containers'])
        report['cleanup']=cleanup;report['commands']=runner.rows
        if clean and not state.pending and report['natural_outcome']=='PASS_CURRENT_LLHTTP_MINIMAL206_BUILD_ONLY_NATIVE_PAIR_AND_CHECKS':report['status']='PASS_CURRENT_LLHTTP_MINIMAL206_BUILD_ONLY_NATIVE_PAIR_ONLY'
        elif not clean or state.pending:report['status']='HOLD_CLEANUP_OR_CANCELLED'
        else:report['status']='HOLD'
        (output/'cleanup.json').write_text(json.dumps(cleanup,indent=2)+'\n');(output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        try:retain(output)
        except BaseException as error:
            report.update(status='HOLD_RETENTION',retention_failure=dict(type=type(error).__name__,message=str(error)[:500]));(output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous);state.__exit__()
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--source-map-sha256',required=True);p.add_argument('--admission-sha256',required=True);p.add_argument('--runtime-sha256',required=True);a=p.parse_args()
    C.need(sys.flags.isolated and __debug__,'isolated nonoptimized Source entry required')
    admission_raw=os.environ.pop('ROOT_LLHTTP_MINIMAL206_BUILD_ONLY_ADMISSION_JSON','').encode();runtime_raw=os.environ.pop('ROOT_LLHTTP_MINIMAL206_BUILD_ONLY_RUNTIME_JSON','').encode()
    C.need(0<len(admission_raw)<=16384 and 0<len(runtime_raw)<=16384 and C.pin(admission_raw)['sha256']==a.admission_sha256 and C.pin(runtime_raw)['sha256']==a.runtime_sha256,'exact externally reviewed Root admission/runtime bytes')
    report=execute(C.ordinary(a.root),a.output,a.source_map_sha256,json.loads(admission_raw),json.loads(runtime_raw));print(json.dumps(dict(status=report['status'],Root_acceptance=None),sort_keys=True));return 0 if report['status']=='PASS_CURRENT_LLHTTP_MINIMAL206_BUILD_ONLY_NATIVE_PAIR_ONLY'else 1


if __name__=='__main__':raise SystemExit(main())
