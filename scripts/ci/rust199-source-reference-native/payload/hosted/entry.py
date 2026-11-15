#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Prospective Root-prepared LOCAL_READONLY route; no acquisition or image build."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parent.parent
OPERATION='rust199-source-reference-native-v1'
DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']


def need(value,why):
    if not value:raise ValueError(why)


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def read(path,cap=4*1024**2):
    need(path.is_absolute() and all(not p.is_symlink() for p in (path,*path.parents)),'ordinary absolute Source/Root input')
    with path.open('rb') as f:
        before=os.fstat(f.fileno());need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=cap,'finite ordinary input')
        raw=f.read(cap+1);after=os.fstat(f.fileno())
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_mtime_ns,s.st_ctime_ns)
    need(len(raw)==before.st_size and identity(before)==identity(after)==identity(path.lstat()),'input changed or exceeded cap');return raw


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def source_gate(root,map_sha):
    need(re.fullmatch('[0-9a-f]{64}',map_sha or ''),'external Source map pin')
    raw=read(root/'source-map.json');need(hashlib.sha256(raw).hexdigest()==map_sha and stat.S_IMODE((root/'source-map.json').stat().st_mode)==0o644,'whole external Source map bytes/mode differ')
    m=json.loads(raw);need(m['schema']==1 and m['operation']==OPERATION and m['actual']==dict.fromkeys(('source','ref','run','job','approval','artifact','image')),'unexecuted exact Source DATA map')
    files={};directories=set();total=0
    for here,dirs,names in os.walk(root,followlinks=False):
        if Path(here)==root:
            if (root/'.git').exists():need((root/'.git').is_dir() and not (root/'.git').is_symlink(),'ordinary actual Source Git directory')
            dirs[:]=[n for n in dirs if n!='.git']
        for d in dirs:
            need(not (Path(here)/d).is_symlink(),'no Source directory aliases');directories.add(str((Path(here)/d).relative_to(root)))
        for name in names:
            p=Path(here)/name;n=p.relative_to(root).as_posix()
            need(n=='source-map.json' or n in m['files'],'unmapped Source member: '+n)
            if n=='source-map.json':continue
            body=read(p,64*1024**2);mode=stat.S_IMODE(p.stat().st_mode);total+=len(body)
            files[n]=dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),mode=mode)
    wanted={str(p) for name in m['files'] for p in Path(name).parents if str(p)!='.'}
    need(files==m['files'] and directories==wanted and len(files)<384 and total<=96*1024**2,'complete bounded Source bytes/modes/membership')
    return m


def natural(row):return row.get('natural_exit') is True and row.get('forced_cleanup') is False and row.get('group_absent') is True and row.get('retirement')=='REAPED' and row.get('ownership_lost') is False and row.get('leader_held_until_group_inspection') is True and row.get('exit_observed_via_waitpid') is True


class Commands:
    def __init__(self,work,seconds):
        self.work=work;self.deadline=time.monotonic()+seconds;self.cleaning=False;self.cancelled=[False];self.on_tick=None;self.rows=[]
        self.owned=load('rust_owned_child',ROOT/'helpers/owned_child.py');(work/'operations').mkdir(mode=0o700)
    def __call__(self,argv,timeout=60,check=True):
        need(self.cleaning or not self.cancelled[0],'cancelled owned command')
        cap=min(timeout,self.deadline-time.monotonic());need(0<cap<=16200,'finite owned command deadline')
        row=dict(argv=list(map(str,argv)),lifecycle={},returncode=None);index=len(self.rows);self.rows.append(row)
        def tick():
            need(self.cleaning or not self.cancelled[0],'Root cancellation')
            if self.on_tick is not None and not self.cleaning:self.on_tick()
        try:
            out=self.work/'operations'/f'{index:03}.stdout';err=self.work/'operations'/f'{index:03}.stderr'
            with out.open('xb') as stdout,err.open('xb') as stderr:
                result=self.owned.run(row['argv'],timeout=cap,cwd=self.work,env=dict(PATH='/usr/bin:/bin',HOME=str(self.work/'home'),LC_ALL='C',TZ='UTC',GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_NO_REPLACE_OBJECTS='1',GIT_OPTIONAL_LOCKS='0',GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0'),stdout=stdout,stderr=stderr,lifecycle=row['lifecycle'],stdout_limit=32*1024**2,stderr_limit=32*1024**2,on_tick=tick)
            stdout=read(out,32*1024**2);stderr=read(err,32*1024**2);row.update(returncode=result.returncode,stdout=dict(bytes=len(stdout),sha256=hashlib.sha256(stdout).hexdigest()),stderr=dict(bytes=len(stderr),sha256=hashlib.sha256(stderr).hexdigest()))
            need(natural(row['lifecycle']) and row['lifecycle']['exit']==result.returncode,'owned natural child retirement required')
            done=subprocess.CompletedProcess(argv,result.returncode,stdout,stderr)
            if check and result.returncode:raise subprocess.CalledProcessError(result.returncode,argv,stdout,stderr)
            return done
        finally:(self.work/'operations.json').write_bytes(encode(self.rows))


def storage(path,disk,inodes):
    need(path.is_absolute() and path.is_dir() and not any(p.is_symlink() for p in (path,*path.parents)),'actual ordinary storage path')
    v=os.statvfs(path);need(v.f_bavail*v.f_frsize>=disk and v.f_favail>=inodes,'fresh disk/inode reserve')
    return dict(path=str(path),device=path.stat().st_dev,available_bytes=v.f_bavail*v.f_frsize,available_inodes=v.f_favail)


def fresh_host(work,a,command):
    need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()==1001,'actual nonroot native ARM runner')
    mem=int(next(s.split()[1] for s in Path('/proc/meminfo').read_text().splitlines() if s.startswith('MemAvailable:')))*1024
    need(mem>=a['resources']['minimum_host_memory_bytes'],'fresh 12 GiB memory available')
    sock=Path('/var/run/docker.sock');before=sock.stat();need(stat.S_ISSOCK(before.st_mode) and before.st_uid==0,'actual root-owned daemon socket')
    info=json.loads(command(DOCKER+['info','--format','{{json .}}'],timeout=30).stdout);version=json.loads(command(DOCKER+['version','--format','{{json .}}'],timeout=30).stdout)
    need((before.st_dev,before.st_ino)==(sock.stat().st_dev,sock.stat().st_ino) and info['OSType']=='linux' and info['Architecture'] in ('aarch64','arm64') and info['CgroupVersion']=='2' and not any('rootless' in s for s in info.get('SecurityOptions',[])),'stable local native rootful cgroupv2 daemon')
    records=[storage(p,a['resources']['minimum_host_disk_bytes'],a['resources']['minimum_host_available_inodes']) for p in (work,Path(info['DockerRootDir']))]
    image=json.loads(command(DOCKER+['image','inspect',a['image']['id']],timeout=30).stdout)[0]
    need(image['Id']==a['image']['id'] and image['Architecture']=='arm64' and image['Os']=='linux' and not image['Config'].get('Volumes'),'actual prequalified immutable image already present; no pull/build route')
    result=dict(info=info,version=version,MemAvailable_bytes=mem,storage=records,image=image)
    (work/'daemon.json').write_bytes(encode(result));return result


def readback(a,command):
    git=['/usr/bin/git','--no-replace-objects','--git-dir='+str(ROOT/'.git'),'--work-tree='+str(ROOT),'-c','protocol.allow=never','-c','core.fsmonitor=false']
    need(command(git+['rev-parse','--verify','HEAD']).stdout.decode().strip()==a['source']['sha'],'actual checked out Source HEAD')
    rows=command(git+['ls-tree','-rz','--full-tree',a['source']['sha']]).stdout;found={}
    for item in rows.split(b'\0'):
        if not item:continue
        meta,name=item.split(b'\t',1);mode,kind,digest=meta.decode().split();name=name.decode();body=read(ROOT/name,64*1024**2)
        need(kind=='blob' and digest==hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest() and mode==('100755' if (ROOT/name).stat().st_mode&0o111 else '100644'),'actual Git blob/mode differs')
        found[name]=dict(mode=mode,blob=digest)
    need(set(found)==set(json.loads(read(ROOT/'source-map.json'))['files'])|{'source-map.json'},'exact published Source Git membership')
    return dict(schema=1,status='PASS_PUBLISHED_SOURCE_DATA_READBACK',source=a['source'],files=found)


def actual_job(a):
    import urllib.request
    need(os.environ.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi' and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==a['source']['sha'] and os.environ.get('GITHUB_REF')==a['source']['ref'] and os.environ.get('GITHUB_RUN_ID')==a['source']['run'] and os.environ.get('RUST199_OPERATION')==OPERATION,'exact actual same-repository Source/ref/run/operation')
    token=os.environ.get('GH_TOKEN','');need(token,'existing same-job Actions read token')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):return None
    url='https://api.github.com/repos/Gabriel-Kahen/cachy-asahi/actions/runs/'+a['source']['run']+'/jobs?filter=latest&per_page=10'
    request=urllib.request.Request(url,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json'})
    with urllib.request.build_opener(NoRedirect).open(request,timeout=30) as response:raw=response.read(1024**2+1)
    need(len(raw)<=1024**2,'bounded actual job metadata');data=json.loads(raw)
    need(data['total_count']==len(data['jobs'])==1,'one actual native job')
    job=data['jobs'][0];need(str(job['id'])==a['source']['job'] and job['name']=='rust199-native-v1' and str(job['run_id'])==a['source']['run'] and job['head_sha']==a['source']['sha'],'actual exact job ID/Source binding')
    return raw


def run(args):
    source_gate(ROOT,args.map_sha256)
    gate=load('rust_external_admission',ROOT/'admission.py');raw=read(args.admission)
    need(hashlib.sha256(raw).hexdigest()==args.admission_sha256,'external whole Root admission SHA')
    a=gate.decode(raw);need(raw==encode(a),'canonical exact Root admission bytes')
    a=gate.validate(a,check_files=True)  # BEFORE network, daemon, material acquisition or actor.
    need(a['source']['map_sha256']==args.map_sha256 and a['source']['approval']==args.approval_sha256,'independent Root approval/map selectors')
    need(args.execute,'explicit prospective native execution operand')
    work=Path(os.environ['RUNNER_TEMP'])/'rust199-hosted'
    need(not work.exists() and work.parent.stat().st_uid==1001 and not work.parent.stat().st_mode&0o022 and not work.is_relative_to(ROOT) and not ROOT.is_relative_to(work),'fresh private disjoint owned runner-temp')
    storage(work.parent,a['resources']['minimum_host_disk_bytes'],a['resources']['minimum_host_available_inodes'])
    work.mkdir(mode=0o700);(work/'home').mkdir(mode=0o700);command=Commands(work,a['resources']['native_seconds'])
    report=dict(schema=1,status='FAIL',source=a['source'],native_acceptance=False,holds_preserved=True)
    handlers={s:signal.getsignal(s) for s in (signal.SIGINT,signal.SIGTERM)}
    def cancel(_s,_f):command.cancelled[0]=True
    try:
        for s in handlers:signal.signal(s,cancel)
        (work/'source-readback.json').write_bytes(encode(readback(a,command)))
        (work/'job-metadata.json').write_bytes(actual_job(a))
        fresh_host(work,a,command)
        report['producer']=load('rust_native_producer',ROOT/'hosted/producer.py').run(ROOT,work,a,command)
        if report['producer']['status']=='COMPLETED_EXPORTED_RETIRED':report['status']='RUST199_BUILD_EXPORTED_RETIRED_PENDING_INDEPENDENT_READER'
    except BaseException as error:report['error']=type(error).__name__+': '+str(error)[:2048]
    finally:
        for s,h in handlers.items():signal.signal(s,h)
        (work/'hosted.json').write_bytes(encode(report))
    return 0 if report['status']=='RUST199_BUILD_EXPORTED_RETIRED_PENDING_INDEPENDENT_READER' else 2


if __name__=='__main__':
    need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized entry')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--admission',type=Path,required=True)
    for n in ('admission-sha256','approval-sha256','map-sha256'):p.add_argument('--'+n,required=True)
    p.add_argument('--execute',action='store_true');raise SystemExit(run(p.parse_args()))
