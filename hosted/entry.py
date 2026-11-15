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
spec=importlib.util.spec_from_file_location('hosted_perl_baseline_common',HERE/'common.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']


class Commands:
    def __init__(self,work,deadline,scope='bootstrap'):
        self.work=work;self.deadline=deadline;self.scope=scope;self.rows=[];self.cancelled=[False];self.cleaning=False
        self.owned=c.load('hosted_exact_owned',ROOT/'original/bootstrap/scripts/ci/zlib-pgo-native-hosted/owned_child.py')
        (work/scope/'operations').mkdir(parents=True,mode=0o700,exist_ok=True)
    def save(self):(self.work/self.scope/'operations.json').write_bytes(c.encode(self.rows))
    def __call__(self,argv,log=None,timeout=60,limit=16*1024**2,**kwargs):
        c.need(self.cleaning or not self.cancelled[0],'Root cancellation before command')
        cap=min(timeout,self.deadline-time.monotonic());c.need(0<cap<=3600,'finite owned phase deadline')
        c.need(type(limit) is int and 0<limit<=32*1024**2,'finite original channel bound')
        argv=list(map(str,argv));prefix=self.scope+'/operations/'+f'{len(self.rows):03d}'
        row=dict(argv=argv,stdout=prefix+'.stdout',stderr=prefix+'.stderr',stdout_pin=None,stderr_pin=None,lifecycle={},returncode=None)
        def tick():c.need(self.cleaning or not self.cancelled[0],'Root cancellation after owned witness')
        # Native audit uses only capture/text/check and occasional stdout=PIPE.
        c.need(set(kwargs)<= {'capture_output','text','encoding','errors','check','stdout','stderr','env','stdin'},'fixed original callback subset')
        try:
            with (self.work/row['stdout']).open('xb') as out,(self.work/row['stderr']).open('xb') as err:
                result=self.owned.run(argv,timeout=cap,cwd=self.work,env=dict(PATH='/usr/bin:/bin',HOME=str(self.work/'home'),LC_ALL='C',TZ='UTC',RUNNER_TEMP=os.environ['RUNNER_TEMP'],GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_NO_REPLACE_OBJECTS='1',GIT_OPTIONAL_LOCKS='0',GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0'),stdout=out,stderr=err,lifecycle=row['lifecycle'],stdout_limit=limit,stderr_limit=limit,on_tick=tick)
            stdout=c.read(self.work/row['stdout'],limit);stderr=c.read(self.work/row['stderr'],limit)
            row.update(returncode=result.returncode,stdout_pin=c.pin(stdout),stderr_pin=c.pin(stderr))
            c.need(_natural(row['lifecycle']) and row['lifecycle']['exit']==result.returncode,'natural direct command retirement required')
            if log is not None:Path(log).write_bytes(stdout+stderr)
            if kwargs.get('text') or kwargs.get('encoding'):stdout=stdout.decode(kwargs.get('encoding') or 'utf8');stderr=stderr.decode(kwargs.get('encoding') or 'utf8')
            done=subprocess.CompletedProcess(argv,result.returncode,stdout,stderr)
            if kwargs.get('check') and result.returncode:raise subprocess.CalledProcessError(result.returncode,argv,stdout,stderr)
            return done
        finally:self.rows.append(row);self.save()


def _natural(row):return row.get('natural_exit') is True and row.get('forced_cleanup') is False and row.get('group_absent') is True and row.get('retirement')=='REAPED' and row.get('ownership_lost') is False and row.get('leader_held_until_group_inspection') is True and row.get('exit_observed_via_waitpid') is True and 'cleanup_error' not in row and type(row.get('exit')) is int


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
    temp=Path(os.environ['RUNNER_TEMP']);paths=(temp,temp/'perl-baseline-observation',temp/'alarm-cache',temp/'pgo-hosted-retained')
    fs['work_filesystems']=[storage_record(path) for path in paths]
    return c.daemon_data(data,c.decode(version.stdout),host,socket,fs)


def base_binding(args):
    c.verify_source(ROOT,args.map_sha256)
    b=c.context(args.source_sha,args.map_sha256,args.approval_sha256,os.environ)
    raw=c.read(Path(os.environ['RUNNER_TEMP'])/'perl-baseline-root-admission.json')
    c.need(c.pin(raw)['sha256']==args.approval_sha256,'exact external Root observation admission')
    a=c.decode(raw);contract=c.decode(c.read(ROOT/'contract.json'));policy=c.decode(c.read(ROOT/'policy.json'))
    c.need(a['status']=='ROOT_ADMITTED_SINGLE_PERL_BASELINE_OBSERVATION_ATTEMPT' and a['authority']=='Root' and a['operation']==c.OPERATION and a['source']==b['source'] and a['ref']==b['ref'] and a['source_map_sha256']==args.map_sha256,'separate concrete Root observation Source/ref/map authority')
    c.need(a['observer_policy_sha256']==contract['observer_policy_sha256']==c.pin(c.read(ROOT/'observer-policy.json'))['sha256'] and a['resources']==policy and all(a[k] is True for k in ('fixed_path_capture_policy_reviewed','readonly_cap0_observer_domain_reviewed','holds_preserved')),'Root fixed-path/schema/cap0 read-only capture review required')
    return b


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
    value=c.decode(raw);jobs=value['jobs'];c.need(value['total_count']==len(jobs)==1 and jobs[0]['name']=='perl5423-baseline-observation-native-v1' and jobs[0]['run_id']==int(b['run']) and jobs[0]['head_sha']==b['source'],'actual unique same-run/source hosted job')
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


def owner(binding):
    token=hashlib.sha256((binding['source']+':'+binding['ref']+':'+binding['run']).encode()).hexdigest()[:24]
    return dict(token=token,name='perl-baseline-observer-'+token,tag='perl-baseline-native-base:'+token,
                label='cachy-asahi.perl-baseline-observer')


def observer_argv(root,image,binding,policy_sha):
    own=owner(binding)
    observed={key:binding[key] for key in ('source','ref','run','job')}
    observed.update(image=image,token=own['token'],policy_sha256=policy_sha)
    argv=DOCKER+['create','--pull=never','--name',own['name'],'--label',own['label']+'='+own['token'],
        '--label',own['label']+'.source='+binding['source'],'--network=none','--read-only','--user=0:0',
        '--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=512m',
        '--memory-swap=512m','--pids-limit=64','--mount',f'type=bind,src={root},dst=/inputs,readonly',
        '--entrypoint=/usr/bin/python3',image,'-I','-B','/inputs/hosted/observer.py',
        '--binding-json',c.encode(observed).decode()]
    return argv,observed


def inspect_observer(actual,root,image,binding,base_labels):
    own=owner(binding);host=actual['HostConfig'];config=actual['Config']
    c.need(actual['Name']=='/'+own['name'] and actual['Image']==image and config['User']=='0:0','actual exact Root0 observer identity')
    c.need((config.get('Labels') or {})==dict(base_labels,**{own['label']:own['token'],own['label']+'.source':binding['source']}),'exact image plus owned observer labels')
    c.need(host['ReadonlyRootfs'] is True and host['NetworkMode']=='none' and host['CapDrop']==['ALL'] and not host.get('CapAdd') and host['Memory']==host['MemorySwap']==536870912 and host['NanoCpus']==2000000000 and host['PidsLimit']==64 and host['SecurityOpt']==['no-new-privileges'] and host['Privileged'] is False and not host.get('Devices') and not host.get('DeviceRequests') and not host.get('VolumesFrom'),'actual separate bounded read-only cap0 observer domain')
    c.need(type(actual['Mounts']) is list and len(actual['Mounts'])==1,'one exact observer bind only')
    mount=actual['Mounts'][0]
    c.need(mount['Type']=='bind' and mount['Source']==str(root) and mount['Destination']=='/inputs' and mount['RW'] is False and not host.get('Tmpfs'),'only Source read-only bind; no writable host mounts or tmpfs')
    return own


def retire_observer(root,work,binding,image,base_labels,command,domain):
    own=owner(binding)
    if domain['create_intent']:
        listed=command(DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+own['name']+'$'],check=True)
        if listed.stdout.strip():
            actual=c.decode(command(DOCKER+['inspect',own['name']],check=True).stdout)[0]
            inspect_observer(actual,root,image,binding,base_labels)
            if actual['State']['Running']:
                command(DOCKER+['stop','--time=5',own['name']],check=True)
                domain['forced_stop']=True
            command(DOCKER+['rm',own['name']],check=True)
        absent=command(DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+own['name']+'$'],check=True)
        c.need(not absent.stdout.strip(),'owned observer absence unknown')
        domain['container_absent']=True
    (work/'observer-domain.json').write_bytes(c.encode(domain))


def observe_image(root,work,binding,image,policy_sha,command,domain):
    actual_image=c.decode(command(DOCKER+['image','inspect',image],check=True).stdout)[0]
    c.need(actual_image['Id']==image and actual_image['Architecture']=='arm64' and actual_image['Os']=='linux' and not actual_image.get('Config',{}).get('Volumes') and not actual_image.get('Config',{}).get('Healthcheck'),'actual immutable native baseline image')
    labels=actual_image['Config'].get('Labels') or {};own=owner(binding)
    domain['image_labels']=labels
    listed=command(DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+own['name']+'$'],check=True)
    c.need(not listed.stdout.strip(),'fresh observer namespace')
    argv,observed=observer_argv(root,image,binding,policy_sha)
    domain['create_intent']=True;(work/'observer-domain.json').write_bytes(c.encode(domain))
    (work/'observation-binding.json').write_bytes(c.encode(observed))
    command(argv,timeout=30,check=True)
    actual=c.decode(command(DOCKER+['inspect',own['name']],check=True).stdout)[0]
    inspect_observer(actual,root,image,binding,labels);domain['before']=actual
    result=command(DOCKER+['start','--attach',own['name']],timeout=60,limit=32*1024**2,check=True)
    data=c.decode(result.stdout,32*1024**2);observer=c.load('perl_baseline_passive_data',root/'hosted/observer.py')
    observer.validate(data);c.need(data['binding']==observed,'actual Source/image/token observation binding differs')
    (work/'observation.json').write_bytes(result.stdout)
    finished=c.decode(command(DOCKER+['inspect',own['name']],check=True).stdout)[0]
    inspect_observer(finished,root,image,binding,labels);domain['after']=finished
    c.need(finished['State']['Status']=='exited' and finished['State']['ExitCode']==0 and not finished['State']['OOMKilled'],'natural observer exit required')
    domain['natural_exit']=True
    return dict(observation=c.pin(result.stdout),binding=observed)


def retire_image(work,binding,image,command):
    own=owner(binding);label='cachy-asahi.hosted-perl-baseline'
    ids=set();inventory_recovered=False
    for selected in ('reference='+own['tag'],'label='+label+'='+own['token']):
        raw=command(DOCKER+['image','ls','--no-trunc','-q','--filter',selected],check=True).stdout.decode()
        ids.update(raw.splitlines())
    if image:ids.add(image)
    c.need(len(ids)<=1,'ambiguous owned bootstrap image identity')
    for selected in ids:
        c.need(__import__('re').fullmatch('sha256:[0-9a-f]{64}',selected),'exact immutable owned bootstrap image id')
        data=c.decode(command(DOCKER+['image','inspect',selected],check=True).stdout)[0]
        c.need(data['Id']==selected and data['Config']['Labels'][label]==own['token'] and data['Config']['Labels'][label+'.source']==binding['source'] and data.get('RepoTags')==[own['tag']],'only exact Source-owned bootstrap image may retire')
        probe='perl-baseline-bootstrap-inventory-'+own['token']
        listed=command(DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+probe+'$'],check=True)
        if listed.stdout.strip():
            item=c.decode(command(DOCKER+['inspect',probe],check=True).stdout)[0]
            c.need(item['Image']==selected and item['Name']=='/'+probe and item['Config']['Labels'][label]==own['token'] and item['Config']['Labels'][label+'.source']==binding['source'],'only exact owned bootstrap inventory container may retire')
            if item['State']['Running']:command(DOCKER+['stop','--time=5',probe],check=True)
            command(DOCKER+['rm',probe],check=True);inventory_recovered=True
            absent=command(DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+probe+'$'],check=True)
            c.need(not absent.stdout.strip(),'owned bootstrap inventory container absence unknown')
        command(DOCKER+['image','rm',selected],check=True)
        absent=command(DOCKER+['image','inspect',selected]);c.need(absent.returncode==1,'owned image absence unknown')
    for selected in ('reference='+own['tag'],'label='+label+'='+own['token']):
        absent=command(DOCKER+['image','ls','--no-trunc','-q','--filter',selected],check=True)
        c.need(not absent.stdout.strip(),'owned bootstrap image namespace remains')
    return dict(image_absent=True,owned_image_ids=sorted(ids),bootstrap_inventory_recovered=inventory_recovered)


def run_native(args,work):
    b=base_binding(args);binding=c.decode(c.read(work/'binding.json'))
    c.need(all(binding[k]==v for k,v in b.items()) and args.execute,'same separately Root-admitted Source/job only')
    command=Commands(work,time.monotonic()+5100);previous={sig:signal.getsignal(sig) for sig in (signal.SIGTERM,signal.SIGINT)}
    report=dict(schema=1,status='FAIL',binding=binding,bootstrap=None,observation=None,cleanup={},qualification='NOT_ISSUED_FOR_LATER_MUTATION')
    domain=dict(schema=1,create_intent=False,container_absent=False,natural_exit=False,forced_stop=False)
    image=None
    def cancel(_signal,_frame):command.cancelled[0]=True
    try:
        for sig in previous:signal.signal(sig,cancel)
        (work/'daemon.json').write_bytes(c.encode(daemon(command)))
        bootstrap=c.load('perl_baseline_signed349',ROOT/'hosted/bootstrap.py')
        report['bootstrap']=bootstrap.run(ROOT,work,binding,min(command.deadline,time.monotonic()+4500),command)
        image=report['bootstrap']['image']
        c.need(c.read(work/'bootstrap/packages.lock')==c.read(ROOT/'expected349.lock'),'actual complete signed349 baseline inventory')
        contract=c.decode(c.read(ROOT/'contract.json'))
        report['observation']=observe_image(ROOT,work,binding,image,contract['observer_policy_sha256'],command,domain)
        report['status']='BASELINE_OBSERVATION_PRODUCED_PENDING_ROOT_REVIEW'
    except BaseException as error:report['error']=type(error).__name__+': '+str(error)[:2048]
    finally:
        command.cleaning=True;command.deadline=time.monotonic()+240;errors=[]
        try:
            if domain['create_intent']:retire_observer(ROOT,work,binding,image,domain['image_labels'],command,domain)
        except BaseException as error:errors.append('observer: '+str(error))
        try:
            home=work/'bootstrap/gpg'
            if home.is_dir():
                command(['gpgconf','--homedir',str(home),'--kill','gpg-agent'],timeout=30,check=True)
                c.need(not any(home.glob('S.gpg-agent*')),'owned bootstrap GPG sockets remain')
            report['cleanup']['gpg_agent_absent']=True
        except BaseException as error:errors.append('gpg: '+str(error))
        try:report['cleanup'].update(retire_image(work,binding,image,command))
        except BaseException as error:errors.append('image: '+str(error))
        report['cleanup'].update(errors=errors,observer_container_absent=domain['container_absent'])
        if errors or command.cancelled[0] or not domain['natural_exit'] or domain['forced_stop'] or not domain['container_absent'] or not report['cleanup'].get('image_absent') or report['cleanup'].get('bootstrap_inventory_recovered'):report['status']='FAIL'
        (work/'observer-domain.json').write_bytes(c.encode(domain));(work/'hosted.json').write_bytes(c.encode(report))
        for sig,handler in previous.items():signal.signal(sig,handler)
    return 0 if report['status']=='BASELINE_OBSERVATION_PRODUCED_PENDING_ROOT_REVIEW' else 2


if __name__=='__main__':
    c.need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized hosted observation entry')
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=('proof','metadata','inputs','native'))
    for key in ('source-sha','map-sha256','approval-sha256'):parser.add_argument('--'+key,required=True)
    parser.add_argument('--execute',action='store_true');args=parser.parse_args();work=Path(os.environ['RUNNER_TEMP'])/'perl-baseline-observation'
    if args.phase=='proof':proof(args,work)
    elif args.phase=='metadata':metadata(args,work)
    elif args.phase=='inputs':inputs(args,work)
    else:raise SystemExit(run_native(args,work))
