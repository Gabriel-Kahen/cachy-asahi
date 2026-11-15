#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Future Root-admitted hosted phases. Authoring never invokes this entry."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
spec=importlib.util.spec_from_file_location('hosted_llvm23_common',HERE/'common.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']


class Commands:
    def __init__(self,work,deadline,scope='bootstrap'):
        self.work=work;self.deadline=deadline;self.scope=scope;self.rows=[];self.cancelled=[False];self.cleaning=False;self.on_tick=None
        self.owned=c.load('hosted_exact_owned',ROOT/'helpers/owned_child.py')
        (work/scope/'operations').mkdir(parents=True,mode=0o700,exist_ok=True)
    def save(self):(self.work/self.scope/'operations.json').write_bytes(c.encode(self.rows))
    def __call__(self,argv,log=None,timeout=60,**kwargs):
        c.need(self.cleaning or not self.cancelled[0],'Root cancellation before command')
        cap=min(timeout,self.deadline-time.monotonic());c.need(0<cap<=14400,'finite owned phase deadline')
        argv=list(map(str,argv));prefix=self.scope+'/operations/'+f'{len(self.rows):03d}'
        row=dict(argv=argv,stdout=prefix+'.stdout',stderr=prefix+'.stderr',stdout_pin=None,stderr_pin=None,lifecycle={},returncode=None)
        def tick():
            c.need(self.cleaning or not self.cancelled[0],'Root cancellation after owned witness')
            if self.on_tick is not None and not self.cleaning:self.on_tick()
        # Native audit uses only capture/text/check and occasional stdout=PIPE.
        c.need(set(kwargs)<= {'capture_output','text','encoding','errors','check','stdout','stderr','env','stdin'},'fixed original callback subset')
        try:
            with (self.work/row['stdout']).open('xb') as out,(self.work/row['stderr']).open('xb') as err:
                result=self.owned.run(argv,timeout=cap,cwd=self.work,env=dict(PATH='/usr/bin:/bin',HOME=str(self.work/'home'),LC_ALL='C',TZ='UTC',RUNNER_TEMP=os.environ['RUNNER_TEMP'],GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_NO_REPLACE_OBJECTS='1',GIT_OPTIONAL_LOCKS='0',GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0'),stdout=out,stderr=err,lifecycle=row['lifecycle'],stdout_limit=16*1024**2,stderr_limit=16*1024**2,on_tick=tick)
            stdout=c.read(self.work/row['stdout'],16*1024**2);stderr=c.read(self.work/row['stderr'],16*1024**2)
            row.update(returncode=result.returncode,stdout_pin=c.pin(stdout),stderr_pin=c.pin(stderr))
            c.need(_natural(row['lifecycle']) and row['lifecycle']['exit']==result.returncode,'natural direct command retirement required')
            if log is not None:Path(log).write_bytes(stdout+stderr)
            if kwargs.get('text') or kwargs.get('encoding'):stdout=stdout.decode(kwargs.get('encoding') or 'utf8');stderr=stderr.decode(kwargs.get('encoding') or 'utf8')
            done=subprocess.CompletedProcess(argv,result.returncode,stdout,stderr)
            if kwargs.get('check') and result.returncode:raise subprocess.CalledProcessError(result.returncode,argv,stdout,stderr)
            return done
        finally:self.rows.append(row);self.save()


def _natural(row):return row.get('natural_exit') is True and row.get('forced_cleanup') is False and row.get('group_absent') is True and row.get('retirement')=='REAPED' and row.get('ownership_lost') is False and row.get('leader_held_until_group_inspection') is True and row.get('exit_observed_via_waitpid') is True


def storage_record(path):
    path=c.path(path);v=os.statvfs(path);s=path.stat()
    row=dict(path=str(path),canonical=True,accessible=True,device=s.st_dev,available_bytes=v.f_bavail*v.f_frsize,total_inodes=v.f_files,available_inodes=v.f_favail)
    c.need(row['available_bytes']>=8*1024**3 and 120000<=row['available_inodes']<=row['total_inodes'],'actual fixed-pool input/bootstrap storage reserve')
    return row


def daemon(command):
    sock=Path('/var/run/docker.sock');before=sock.stat()
    info=command(DOCKER+['info','--format','{{json .}}'],timeout=30);version=command(DOCKER+['version','--format','{{json .}}'],timeout=30)
    c.need(info.returncode==version.returncode==0,'actual native local daemon metadata')
    data=c.decode(info.stdout);storage=Path(data['DockerRootDir']);ordinary=c.path(storage)
    canonical=storage.is_absolute() and '..' not in storage.parts and not any(p.is_symlink() for p in (storage,*storage.parents))
    v=os.statvfs(ordinary);s=ordinary.stat();after=sock.stat()
    identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid)
    host=dict(system=platform.system(),machine=platform.machine(),uid=os.getuid(),gid=os.getgid(),groups=os.getgroups(),MemAvailable_bytes=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))*1024)
    socket=dict(path=str(sock),uid=before.st_uid,socket=stat.S_ISSOCK(before.st_mode),stable=identity(before)==identity(after))
    fs=dict(path=str(storage),canonical=canonical,accessible=True,device=s.st_dev,available_bytes=v.f_bavail*v.f_frsize,total_inodes=v.f_files,available_inodes=v.f_favail)
    # Each actual device must independently retain this bootstrap reserve;
    # duplicate paths/devices share one observation, never double-count free space.
    temp=Path(os.environ['RUNNER_TEMP']);paths=(temp,temp/'llvm23-hosted',temp/'alarm-cache',temp/'pgo-hosted-retained')
    fs['work_filesystems']=[storage_record(path) for path in paths]
    return c.daemon_data(data,c.decode(version.stdout),host,socket,fs)


def base_binding(args):
    c.verify_source(ROOT,args.map_sha256)
    binding=c.context(args.source_sha,args.map_sha256,args.approval_sha256,os.environ)
    raw=c.read(Path(os.environ['RUNNER_TEMP'])/'llvm23-root-admission.json')
    c.need(c.pin(raw)['sha256']==args.approval_sha256,'external Root admission digest')
    a=c.decode(raw);policy=c.decode(c.read(ROOT/'policy.json'))
    c.need(a['status']=='ROOT_ADMITTED_SINGLE_NATIVE_LLVM23_ATTEMPT' and a['operation']==c.OPERATION and a['source']==binding['source'] and a['ref']==binding['ref'] and a['source_map_sha256']==args.map_sha256,'new exact Root Source/ref/operation admission')
    c.need(a['resources']==policy and a['source_reviewed'] is a['holds_preserved'] is True and a['authority'],'Root resource/source qualification missing')
    return binding


def proof(args,work):
    b=base_binding(args);c.need(not work.exists(),'fresh one-shot Source proof work')
    c.need(work.parent.stat().st_uid==1001 and not work.parent.stat().st_mode&0o022 and not work.is_relative_to(ROOT) and not ROOT.is_relative_to(work),'owned disjoint private runner-temp parent')
    initial_storage=storage_record(work.parent)
    work.mkdir(mode=0o700);(work/'home').mkdir(mode=0o700)
    command=Commands(work,time.monotonic()+150,scope='proof')
    git=['/usr/bin/git','--no-replace-objects','--git-dir='+str(ROOT/'.git'),'--work-tree='+str(ROOT),'-c','protocol.allow=never','-c','core.fsmonitor=false']
    result=command(git+['rev-parse','--verify','HEAD'],timeout=30);c.need(result.returncode==0 and result.stdout.decode().strip()==b['source'],'actual published Git HEAD')
    raw=command(git+['ls-tree','-rz','--full-tree',b['source']],timeout=60);c.need(raw.returncode==0,'actual complete published tree')
    manifest=c.decode(c.read(ROOT/'source-map.json'));found={}
    for item in raw.stdout.split(b'\0'):
        if not item:continue
        meta,name=item.split(b'\t',1);mode,kind,digest=meta.decode().split();name=name.decode()
        body=c.read(ROOT/name,64*1024**2);want=hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()
        c.need(kind=='blob' and digest==want and mode==('100755' if (ROOT/name).stat().st_mode&0o111 else '100644'),'actual Git blob/mode join')
        found[name]=dict(**c.pin(body),mode=int(mode[-3:],8),blob=digest)
    c.need(set(found)==set(manifest['files'])|{'source-map.json'},'exact published membership')
    record=dict(schema=1,status='PASS_EXACT_HOSTED_SOURCE_READBACK',binding=b,files=found,actors=command.rows,storage_before_inputs=initial_storage)
    (work/'source-readback.json').write_bytes(c.encode(record));return record


def metadata(args,work):
    # Existing Actions token, bounded read-only job metadata; no new credential.
    import urllib.request
    b=base_binding(args);prior=c.decode(c.read(work/'source-readback.json'));c.need(prior['binding']==b,'prior exact Source readback before token use')
    token=os.environ.get('GH_TOKEN','');c.need(token,'existing Actions metadata token required')
    url='https://api.github.com/repos/Gabriel-Kahen/cachy-asahi/actions/runs/'+b['run']+'/jobs?filter=latest&per_page=10'
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*a,**k):return None
    request=urllib.request.Request(url,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json'})
    with urllib.request.build_opener(NoRedirect).open(request,timeout=30) as response:raw=response.read(1024**2+1)
    value=c.decode(raw);jobs=value['jobs'];c.need(value['total_count']==len(jobs)==1 and jobs[0]['name']=='llvm23-native-v1' and jobs[0]['run_id']==int(b['run']) and jobs[0]['head_sha']==b['source'],'actual unique same-run/source hosted job')
    b['job']=str(jobs[0]['id']);c.need(b['job'].isdecimal() and int(b['job'])>0,'actual numeric job ID')
    (work/'binding.json').write_bytes(c.encode(b));(work/'job-metadata.json').write_bytes(raw)


def inputs(args,work):
    b=base_binding(args);proof=c.decode(c.read(work/'source-readback.json'));c.need(proof['binding']==b,'Source proof before retained DATA transport')
    original=ROOT/'original';prior_path=sys.path.copy();prior_modules=sys.modules.copy();prior_run=subprocess.run
    try:
        sys.modules.pop('common',None);sys.path[:0]=[str(original/'native')]
        transport=c.load('held_original_retained_transport',original/'native/retained_transport.py')
        pgo=c.load('held_original_transport_ownership',original/'bootstrap/scripts/ci/zlib-pgo-native-hosted/owner.py')
        subprocess.run=pgo.owned_subprocess_run
        profile=c.read(original/'bootstrap/scripts/ci/setup6-retained-helpers/carrier-profile.json',2*1024**2)
        result=transport.deliver(original,Path(os.environ['RUNNER_TEMP'])/'pgo-hosted-retained',work/'retained-transport',profile,'4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c')
        c.need(result['status']=='PASS_EXACT_RETAINED_GIT_DATA_ONLY','exact held retained DATA transport')
        (work/'input-transport.json').write_bytes(c.encode(result))
    finally:
        subprocess.run=prior_run;sys.path[:]=prior_path
        for name,module in list(sys.modules.items()):
            file=getattr(module,'__file__',None)
            if name.startswith('held_original_') or file and Path(file).is_relative_to(original):
                if name in prior_modules:sys.modules[name]=prior_modules[name]
                else:sys.modules.pop(name,None)
        if 'common' in prior_modules:sys.modules['common']=prior_modules['common']
        else:sys.modules.pop('common',None)



def run_native(args,work):
    b=base_binding(args);binding=c.decode(c.read(work/'binding.json'))
    c.need(all(binding[k]==v for k,v in b.items()) and args.execute,'same-Source actual job and separate Root execute operand required')
    policy=c.decode(c.read(ROOT/'policy.json'))
    command=Commands(work,time.monotonic()+policy['native_seconds']);image=None
    previous={s:signal.getsignal(s) for s in (signal.SIGTERM,signal.SIGINT)}
    auth=c.decode(c.read(ROOT/'evidence/authentication.json'))['source_signatures']['llvm']
    c.need(auth['signature_mathematics']=='PASS' and auth['archive']['sha256']=='ebe9be46fe8756d58c5b198ffad0fa2a766257add81a4dc52179bfacc7888ee6','retained upstream LLVM signature/provenance join required before actors')
    report=dict(schema=1,status='FAIL',binding=binding,mode='ROOTFUL_CONTAINER_NO_BWRAP_V1',native_acceptance=False,cleanup={})
    def cancel(_number,_frame):command.cancelled[0]=True
    try:
        for s in previous:signal.signal(s,cancel)
        observed=daemon(command);(work/'daemon.json').write_bytes(c.encode(observed))
        # Independent reserve checks apply before bootstrap/source acquisition and actors.
        available=int(next(s.split()[1] for s in Path('/proc/meminfo').read_text().splitlines() if s.startswith('MemAvailable:')))*1024
        c.need(available>=12*1024**3,'8 GiB workload plus 4 GiB host memory reserve')
        for path in (work,Path(observed['info']['DockerRootDir'])):
            v=os.statvfs(path);c.need(v.f_bavail*v.f_frsize>=64*1024**3 and v.f_favail>=600000,'64 GiB/600k inode workload reserve')
        source=c.load('llvm23_source_intake',ROOT/'hosted/material.py').acquire(ROOT,work,command)
        bootstrap=c.load('llvm23_signed349',ROOT/'hosted/bootstrap.py')
        original=bootstrap._docker_argv
        def docker_argv(argv,owner):
            result=original(argv,owner)
            if result[:3]==DOCKER+['build']:
                path=Path(result[-1])/'Dockerfile';before=path.read_bytes()
                suffix=b'\nUSER root\nRUN mkdir -p /opt/cachy-asahi && ln -s /work/dest/opt/cachy-asahi/llvm23-source-reference /opt/cachy-asahi/llvm23-source-reference\nUSER alarm\nWORKDIR /tmp\n'
                c.need(before.endswith(b'USER alarm\nWORKDIR /tmp\n') and b'/opt/cachy-asahi' not in before,'exact private-prefix-only bootstrap filesystem delta')
                path.write_bytes(before+suffix)
                (work/'bootstrap/private-prefix-delta.json').write_bytes(c.encode(dict(before=c.pin(before),after=c.pin(before+suffix),append=suffix.decode(),package_additions=[])))
            return result
        bootstrap._docker_argv=docker_argv
        try:prepared=bootstrap.run(ROOT,work,binding,min(command.deadline,time.monotonic()+4500),command)
        finally:bootstrap._docker_argv=original
        image=prepared['image'];report['bootstrap']=prepared
        c.need(c.read(work/'bootstrap/packages.lock')==c.read(ROOT/'expected349.lock'),'actual signed349 unchanged')
        producer=c.load('llvm23_actual_producer',ROOT/'hosted/producer.py')
        report['build']=producer.run(ROOT,work,binding,image,source,command)
        c.need(report['build']['status']=='COMPLETED_EXPORTED_RETIRED','LLVM build/package/export incomplete')
        report['status']='LLVM23_BUILD_EXPORTED_RETIRED_PENDING_INDEPENDENT_READER'
    except BaseException as error:report['error']=type(error).__name__+': '+str(error)[:2048]
    finally:
        command.cleaning=True;command.on_tick=None;command.deadline=time.monotonic()+300
        errors=[]
        try:
            home=work/'bootstrap/gpg'
            if home.is_dir():
                command(['gpgconf','--homedir',str(home),'--kill','gpg-agent'],timeout=30,check=True)
                c.need(not any(home.glob('S.gpg-agent*')),'owned bootstrap GPG sockets remain')
            report['cleanup']['gpg_agent_absent']=True
        except BaseException as error:errors.append(str(error))
        if image is None:
            iid=work/'bootstrap/image-id'
            if iid.is_file():image=c.read(iid).decode().strip()
        try:
            token=hashlib.sha256((binding['source']+':'+binding['ref']+':'+binding['run']).encode()).hexdigest()[:24]
            probe='llvm23-bootstrap-inventory-'+token
            result=command(DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+probe+'$'],timeout=30,check=True)
            if result.stdout.strip():
                c.need(result.stdout.decode().strip()==probe,'only exact bootstrap inventory actor')
                item=c.decode(command(DOCKER+['container','inspect',probe],timeout=30,check=True).stdout)[0]
                c.need(item['Config']['Labels']['cachy-asahi.hosted-llvm23']==token and item['Config']['Labels']['cachy-asahi.hosted-llvm23.source']==binding['source'],'exact owned inventory actor only')
                command(DOCKER+['rm','-f',probe],timeout=30,check=True)
                report['status']='FAIL';report['error']='bootstrap inventory actor needed forced retirement'
            absent=command(DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+probe+'$'],timeout=30,check=True)
            c.need(not absent.stdout.strip(),'bootstrap inventory absence unknown')
            report['cleanup']['bootstrap_probe_absent']=True
        except BaseException as error:errors.append(str(error))
        try:
            if image:
                owner=bootstrap.image_owner(binding)
                data=c.decode(command(DOCKER+['image','inspect',image],timeout=30,check=True).stdout)[0]
                c.need(data['Id']==image and data['Config']['Labels']['cachy-asahi.hosted-llvm23']==owner['token'] and data['Config']['Labels']['cachy-asahi.hosted-llvm23.source']==binding['source'] and data.get('RepoTags')==[owner['tag']],'exact owned image retirement only')
                command(DOCKER+['image','rm',image],timeout=60,check=True)
                absent=command(DOCKER+['image','inspect',image],timeout=30)
                c.need(absent.returncode==1 and absent.stderr.decode().strip()=='Error response from daemon: No such image: '+image,'owned image absence not proven')
                report['cleanup']['image_absent']=True
        except BaseException as error:errors.append(str(error))
        report['cleanup']['errors']=errors
        if errors or not report['cleanup'].get('image_absent') or command.cancelled[0]:report['status']='FAIL'
        (work/'hosted.json').write_bytes(c.encode(report))
        for s,handler in previous.items():signal.signal(s,handler)
    return 0 if report['status']=='LLVM23_BUILD_EXPORTED_RETIRED_PENDING_INDEPENDENT_READER' else 2


if __name__=='__main__':
    c.need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized entry required')
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=('proof','metadata','inputs','native'))
    for key in ('source-sha','map-sha256','approval-sha256'):parser.add_argument('--'+key,required=True)
    parser.add_argument('--execute',action='store_true');args=parser.parse_args();work=Path(os.environ['RUNNER_TEMP'])/'llvm23-hosted'
    if args.phase=='proof':proof(args,work)
    elif args.phase=='metadata':metadata(args,work)
    elif args.phase=='inputs':inputs(args,work)
    else:raise SystemExit(run_native(args,work))
