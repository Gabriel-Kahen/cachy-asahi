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
spec=importlib.util.spec_from_file_location('hosted_perl_common',HERE/'common.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']


class Commands:
    def __init__(self,work,deadline,scope='bootstrap'):
        self.work=work;self.deadline=deadline;self.scope=scope;self.rows=[];self.cancelled=[False];self.cleaning=False
        self.owned=c.load('hosted_exact_owned',ROOT/'perl/helpers/owned_child.py')
        (work/scope/'operations').mkdir(parents=True,mode=0o700,exist_ok=True)
    def save(self):(self.work/self.scope/'operations.json').write_bytes(c.encode(self.rows))
    def __call__(self,argv,log=None,timeout=60,**kwargs):
        c.need(self.cleaning or not self.cancelled[0],'Root cancellation before command')
        cap=min(timeout,self.deadline-time.monotonic());c.need(0<cap<=3600,'finite owned phase deadline')
        argv=list(map(str,argv));prefix=self.scope+'/operations/'+f'{len(self.rows):03d}'
        row=dict(argv=argv,stdout=prefix+'.stdout',stderr=prefix+'.stderr',stdout_pin=None,stderr_pin=None,lifecycle={},returncode=None)
        def tick():c.need(self.cleaning or not self.cancelled[0],'Root cancellation after owned witness')
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
    temp=Path(os.environ['RUNNER_TEMP']);paths=(temp,temp/'perl-hosted',temp/'alarm-cache',temp/'pgo-hosted-retained')
    fs['work_filesystems']=[storage_record(path) for path in paths]
    return c.daemon_data(data,c.decode(version.stdout),host,socket,fs)


def base_binding(args):
    c.verify_source(ROOT,args.map_sha256)
    return c.context(args.source_sha,args.map_sha256,args.approval_sha256,os.environ)


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
    value=c.decode(raw);jobs=value['jobs'];c.need(value['total_count']==len(jobs)==1 and jobs[0]['name']=='perl5423-native-v2' and jobs[0]['run_id']==int(b['run']) and jobs[0]['head_sha']==b['source'],'actual unique same-run/source hosted job')
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
    b=base_binding(args);binding=c.decode(c.read(work/'binding.json'));c.need(all(binding[k]==v for k,v in b.items()),'actual same-Source job binding')
    c.need(args.execute,'Root actual-role authorization required')
    oldenv=dict(os.environ);previous={s:signal.getsignal(s) for s in (signal.SIGINT,signal.SIGTERM)}
    command=Commands(work,time.monotonic()+4500);record=dict(schema=1,status='FAIL',binding=binding,source_readback_sha256=c.pin(c.read(work/'source-readback.json'))['sha256'],daemon_identity_sha256=None,bootstrap={},pair_exit=None,cleanup=dict(image=None,image_removed=False,image_absent=False,probe_absent=False,gpg_agent_absent=False,error=None))
    image=None
    def requested(number,frame):command.cancelled[0]=True
    try:
        for s in previous:signal.signal(s,requested)
        observed=daemon(command);(work/'daemon.json').write_bytes(c.encode(observed));record['daemon_identity_sha256']=c.pin(c.encode(observed))['sha256']
        bootstrap=c.load('hosted_signed349',HERE/'bootstrap.py');prepared=bootstrap.run(ROOT,work,binding,command.deadline,command);image=prepared['image']
        signatures=c.read(work/'bootstrap/signatures.json');lock=c.read(work/'bootstrap/packages.lock');c.need(lock==c.read(ROOT/'original/native/expected349.lock'),'actual signed349 lock')
        a=c.decode(c.read(ROOT/'perl/admission.TEMPLATE.json'));q=c.decode(c.read(ROOT/'perl/qualification.TEMPLATE.json'))
        a.update(source=dict(sha=binding['source'],ref=binding['ref'].removeprefix('refs/heads/')),run=binding['run'],job=binding['job'],approval=binding['approval'],image=image,source_map_sha256=c.COMPONENT_MAP,input_signature_audit_sha256=c.pin(signatures)['sha256'])
        q.update(status='ROOT_ADMITTED_CONTAINER_PRECONDITIONS',source=binding['source'],run=binding['run'],job=binding['job'],image=image,source_readback_sha256=record['source_readback_sha256'],native_daemon_identity_sha256=record['daemon_identity_sha256'],input_signature_audit_sha256=a['input_signature_audit_sha256'])
        ar,qr=c.encode(a),c.encode(q);a['qualification_sha256']=c.pin(qr)['sha256'];ar=c.encode(a)
        ap,qp=work/'adapter-admission.json',work/'adapter-qualification.json';ap.write_bytes(ar);qp.write_bytes(qr)
        record['bootstrap']=dict(image=image,expected349_sha256=c.pin(lock)['sha256'],acquisition_sha256=c.pin(c.read(work/'bootstrap/acquisition.json'))['sha256'],signatures_sha256=c.pin(signatures)['sha256'],operations_sha256=None)
        producer=c.load('held_perl_v2_producer',ROOT/'perl/producer.py')
        values=argparse.Namespace(admission=str(ap),qualification=str(qp),admission_sha256=c.pin(ar)['sha256'],qualification_sha256=c.pin(qr)['sha256'],output=str(work/'pair'),nested_namespace_diagnostic=None)
        record['pair_exit']=producer.run(values);c.need(record['pair_exit']==0,'ordinary Perl native pair failed')
        record['status']='PAIR_COMPLETED'
    except BaseException as error:record['error']=type(error).__name__+': '+str(error)[:2048]
    finally:
        command.deadline=time.monotonic()+240;command.cleaning=True
        errors=[]
        try:
            keyhome=work/'bootstrap/gpg'
            if keyhome.is_dir():
                stopped=command(['gpgconf','--homedir',str(keyhome),'--kill','gpg-agent'],timeout=30)
                c.need(stopped.returncode==0 and all(not p.exists() and not p.is_symlink() for p in [keyhome/('S.gpg-agent'+suffix) for suffix in ('','.browser','.extra','.ssh')]),'owned bootstrap host GPG agent retirement')
            record['cleanup']['gpg_agent_absent']=True
        except BaseException as error:errors.append('GPG: '+str(error)[:1024])
        token=hashlib.sha256((binding['source']+':'+binding['ref']+':'+binding['run']).encode()).hexdigest()[:24]
        try:
            if image is None:
                iid=work/'bootstrap/image-id'
                try:
                    if iid.is_file():image=c.read(iid).decode().strip()
                except (OSError,ValueError):pass
                if image is None:
                    found=command(DOCKER+['image','ls','--no-trunc','-q','--filter','label=cachy-asahi.hosted-perl='+token])
                    ids=found.stdout.decode().splitlines();c.need(found.returncode==0 and len(ids)<=1,'unambiguous deterministic owned image recovery')
                    if ids:image=ids[0]
            if image:c.need(__import__('re').fullmatch('sha256:[0-9a-f]{64}',image),'exact owned image ID')
        except BaseException as error:errors.append('image recovery: '+str(error)[:1024]);image=None
        try:
            probe='perl-bootstrap-inventory-'+token
            probe_query=DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+probe+'$']
            listed=command(probe_query);c.need(listed.returncode==0,'owned inventory probe list')
            if listed.stdout.strip():
                c.need(listed.stdout.decode().strip()==probe,'only exact named inventory probe')
                observed=command(DOCKER+['container','inspect',probe]);item=c.decode(observed.stdout)[0]
                c.need(observed.returncode==0 and image and item['Image']==image and item['Config']['Labels']['cachy-asahi.hosted-perl']==token and item['Config']['Labels']['cachy-asahi.hosted-perl.source']==binding['source'],'only owned inventory container may retire')
                retired=command(DOCKER+['rm','-f',probe]);listed=command(probe_query)
                c.need(retired.returncode==0 and listed.returncode==0 and not listed.stdout.strip(),'inventory container absence')
                record['status']='FAIL';record['error']='inventory probe required forced retirement'
            record['cleanup']['probe_absent']=True
        except BaseException as error:errors.append('inventory: '+str(error)[:1024])
        try:
            if image:
                inspected=command(DOCKER+['image','inspect',image]);data=c.decode(inspected.stdout)[0]
                c.need(inspected.returncode==0 and data['Id']==image and data['Config']['Labels']['cachy-asahi.hosted-perl']==token and data['Config']['Labels']['cachy-asahi.hosted-perl.source']==binding['source'] and data.get('RepoTags')==['perl-native-base:'+token],'only exact owned Source image without foreign aliases may retire')
                removed=command(DOCKER+['image','rm',image]);absent=command(DOCKER+['image','inspect',image])
                c.need(removed.returncode==0 and absent.returncode==1 and absent.stderr.decode().strip()=='Error response from daemon: No such image: '+image,'owned image retirement and absence')
                record['cleanup'].update(image=image,image_removed=True,image_absent=True)
        except BaseException as error:errors.append('image: '+str(error)[:1024])
        if errors:record['cleanup']['error']='; '.join(errors);record['status']='FAIL'
        if record['status']!='PAIR_COMPLETED':record['daemon_build_retirement']='UNPROVEN_ON_FAILED_OR_FORCED_BUILD;_ROOT_HOLD_REQUIRED'
        if not record['cleanup']['image_absent']:record['status']='FAIL'
        if command.cancelled[0]:record['status']='FAIL';record['error']='Root cancellation requested'
        if record['bootstrap']:record['bootstrap']['operations_sha256']=c.pin(c.read(work/'bootstrap/operations.json'))['sha256']
        (work/'hosted.json').write_bytes(c.encode(record))
        for s,handler in previous.items():signal.signal(s,handler)
        os.environ.clear();os.environ.update(oldenv)
    return 0 if record['status']=='PAIR_COMPLETED' else 2


if __name__=='__main__':
    c.need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized hosted entry')
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=('proof','metadata','inputs','native'))
    for key in ('source-sha','map-sha256','approval-sha256'):parser.add_argument('--'+key,required=True)
    parser.add_argument('--execute',action='store_true');args=parser.parse_args();work=Path(os.environ['RUNNER_TEMP'])/'perl-hosted'
    if args.phase=='proof':proof(args,work)
    elif args.phase=='metadata':metadata(args,work)
    elif args.phase=='inputs':inputs(args,work)
    else:raise SystemExit(run_native(args,work))
