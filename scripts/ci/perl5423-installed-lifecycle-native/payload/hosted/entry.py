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
import shutil
import signal
import stat
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
spec=importlib.util.spec_from_file_location('hosted_perl_lifecycle_common',HERE/'common.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']


class Commands:
    def __init__(self,work,deadline,scope='bootstrap'):
        self.work=work;self.deadline=deadline;self.scope=scope;self.rows=[];self.cancelled=[False];self.cleaning=False
        self.owned=c.load('hosted_exact_owned',ROOT/'lifecycle-code/helpers/owned_child.py')
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
    temp=Path(os.environ['RUNNER_TEMP']);paths=(temp,temp/'perl-lifecycle-hosted',temp/'alarm-cache',temp/'pgo-hosted-retained')
    fs['work_filesystems']=[storage_record(path) for path in paths]
    return c.daemon_data(data,c.decode(version.stdout),host,socket,fs)


def base_binding(args):
    c.verify_source(ROOT,args.map_sha256)
    b=c.context(args.source_sha,args.map_sha256,args.approval_sha256,os.environ)
    raw=c.read(Path(os.environ['RUNNER_TEMP'])/'perl-lifecycle-root-admission.json')
    c.need(c.pin(raw)['sha256']==args.approval_sha256,'exact external Root lifecycle admission')
    a=c.decode(raw);contract=c.decode(c.read(ROOT/'contract.json'));policy=c.decode(c.read(ROOT/'policy.json'))
    c.need(a['status']=='ROOT_ADMITTED_SINGLE_PERL_INSTALLED_LIFECYCLE_ATTEMPT' and a['authority'] and a['operation']==c.OPERATION and a['source']==b['source'] and a['ref']==b['ref'] and a['source_map_sha256']==args.map_sha256,'concrete new Root Source/ref/operation authority')
    c.need(a['input_review_sha256']==contract['input_review_sha256'] and a['resources']==policy and all(a[k] is True for k in ('separate_root_RW_lifecycle_domain_reviewed','baseline_effective_ALPM_config_hooks_reviewed','public_trust_and_source_bindings_reviewed','holds_preserved')),'Root RW lifecycle/baseline/public-trust prerequisites missing')
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
    value=c.decode(raw);jobs=value['jobs'];c.need(value['total_count']==len(jobs)==1 and jobs[0]['name']=='perl5423-installed-lifecycle-native-v1' and jobs[0]['run_id']==int(b['run']) and jobs[0]['head_sha']==b['source'],'actual unique same-run/source hosted job')
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



def qualify_image(root,work,binding,image,review,command):
    """Observe a fresh signed349 image under a separate cap0/RO metadata domain."""
    module=c.load('perl_lifecycle_image_data',root/'hosted/image_probe.py')
    token=hashlib.sha256((binding['source']+':'+binding['run']+':'+binding['job']).encode()).hexdigest()[:24]
    name='perl-lifecycle-image-'+token
    report=dict(name=name,image=image,status='FAIL',create_intent=False,removed=False)
    def save():(work/'image-qualification.json').write_bytes(c.encode(report))
    save()
    try:
        actual_image=c.decode(command(DOCKER+['image','inspect',image],check=True).stdout)[0]
        c.need(actual_image['Id']==image and actual_image['Architecture']=='arm64' and actual_image['Os']=='linux' and not actual_image.get('Config',{}).get('Volumes') and not actual_image.get('Config',{}).get('Healthcheck'),'actual immutable native baseline image metadata')
        base_labels=actual_image['Config'].get('Labels') or {}
        listed=command(DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+name+'$'],check=True)
        c.need(not listed.stdout.strip(),'fresh exact metadata namespace')
        report['create_intent']=True;save()
        argv=DOCKER+['create','--name',name,'--label','cachy-asahi.lifecycle-metadata='+token,'--label','cachy-asahi.lifecycle-metadata.source='+binding['source'],'--network=none','--read-only','--user=0:0','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=1','--memory=256m','--memory-swap=256m','--pids-limit=32','--mount',f'type=bind,src={root},dst=/inputs,readonly','--entrypoint=/usr/bin/python3',image,'-I','-B','/inputs/hosted/image_probe.py']
        command(argv,timeout=30,check=True)
        observed=c.decode(command(DOCKER+['inspect',name],check=True).stdout)[0]
        host=observed['HostConfig'];config=observed['Config']
        c.need(observed['Image']==image and config['User']=='0:0' and host['ReadonlyRootfs'] and host['NetworkMode']=='none' and host['CapDrop']==['ALL'] and not host.get('CapAdd') and host['Memory']==host['MemorySwap']==268435456 and host['NanoCpus']==1000000000 and host['PidsLimit']==32 and host['SecurityOpt']==['no-new-privileges'] and not host['Privileged'],'actual cap0 RO metadata create domain')
        c.need((config.get('Labels') or {})==dict(base_labels,**{'cachy-asahi.lifecycle-metadata':token,'cachy-asahi.lifecycle-metadata.source':binding['source']}),'metadata container labels must join exact image labels plus owned probe labels')
        data=c.decode(command(DOCKER+['start','--attach',name],timeout=60,check=True).stdout,16*1024**2)
        report['metadata']=data;report['comparison']=module.compare(data,review['image_expectations'])
        after=c.decode(command(DOCKER+['inspect',name],check=True).stdout)[0]
        c.need(after['State']['Status']=='exited' and after['State']['ExitCode']==0 and not after['State']['OOMKilled'],'natural metadata completion')
        report['base_labels']=base_labels;report['status']='OBSERVED_FRESH_SIGNED349_IMAGE_MATCHES_ROOT_REVIEW_DATA'
    finally:
        if report['create_intent']:
            listed=command(DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+name+'$'],check=True)
            if listed.stdout.strip():
                item=c.decode(command(DOCKER+['inspect',name],check=True).stdout)[0]
                c.need(item['Image']==image and item['Config']['Labels']['cachy-asahi.lifecycle-metadata']==token and item['Config']['Labels']['cachy-asahi.lifecycle-metadata.source']==binding['source'],'only exact owned metadata container may retire')
                if item['State']['Running']:
                    command(DOCKER+['stop','--time=5',name],check=True);report['status']='FAIL'
                command(DOCKER+['rm',name],check=True)
            absent=command(DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+name+'$'],check=True)
            c.need(not absent.stdout.strip(),'metadata container absence unknown');report['removed']=True
        save()
    c.need(report['status']=='OBSERVED_FRESH_SIGNED349_IMAGE_MATCHES_ROOT_REVIEW_DATA' and report['removed'],'image observation incomplete')
    return report


def run_native(args,work):
    b=base_binding(args);binding=c.decode(c.read(work/'binding.json'))
    c.need(all(binding[k]==v for k,v in b.items()) and args.execute,'same new Root admitted actual Source/job only')
    root_review=c.decode(c.read(ROOT/'input-review.json',4*1024**2),4*1024**2);contract=c.decode(c.read(ROOT/'contract.json'))
    c.need(c.pin(c.read(ROOT/'input-review.json',4*1024**2))['sha256']==contract['input_review_sha256'] and root_review['status']=='ROOT_REVIEWED_PREREQUISITES_FOR_SINGLE_NATIVE_LIFECYCLE','actual Root baseline/source/trust review before actors')
    command=Commands(work,time.monotonic()+5460);previous={s:signal.getsignal(s) for s in (signal.SIGTERM,signal.SIGINT)};image=None
    report=dict(schema=1,status='FAIL',binding=binding,input_review_sha256=contract['input_review_sha256'],actual_signing=False,cleanup={})
    def cancel(_signal,_frame):command.cancelled[0]=True
    try:
        for sig in previous:signal.signal(sig,cancel)
        # Source sealing happened only after concrete reviewed baseline/signature/public-trust inputs.
        capsule=c.load('perl_lifecycle_capsule_data',ROOT/'hosted/capsule.py').materialize(ROOT,work)
        report['capsule_source_map_sha256']=contract['capsule']['source_map_sha256']
        daemon_record=daemon(command);(work/'daemon.json').write_bytes(c.encode(daemon_record))
        cache=Path(os.environ['RUNNER_TEMP'])/'alarm-cache'
        seeded={}
        for name,pin in [('perl-5.42.3-1-aarch64.pkg.tar.xz',dict(bytes=16017184,sha256='f0e47c42ec91985898af2ce7355ef4eead50457108706add1f8c1650bca19b8f')),('perl-5.42.3-1-aarch64.pkg.tar.xz.sig',dict(bytes=566,sha256='f40e70ac18f61c8b706c7642bac2cfef7b4fcb9d96bd30da3fc41c48a6667dca'))]:
            source=c.read(capsule/name,64*1024**2);c.need(c.pin(source)==pin,'exact reviewed retained baseline bytes before cache seed')
            target=cache/name
            if target.exists():c.need(c.pin(c.read(target,64*1024**2))==pin,'existing baseline cache differs')
            else:
                with target.open('xb') as output:output.write(source)
                target.chmod((capsule/name).stat().st_mode & 0o777)
            seeded[name]=pin
        (work/'baseline-cache-seed.json').write_bytes(c.encode(dict(status='EXACT_ALREADY_REVIEWED_BASELINE_DATA_ONLY',files=seeded,network_requests=0)))
        bootstrap=c.load('perl_lifecycle_signed349',ROOT/'hosted/bootstrap.py')
        report['bootstrap']=bootstrap.run(ROOT,work,binding,min(command.deadline,time.monotonic()+4500),command)
        image=report['bootstrap']['image']
        c.need(c.read(work/'bootstrap/packages.lock')==c.read(ROOT/'expected349.lock'),'actual complete signed349 provider required')
        qualified=qualify_image(ROOT,work,binding,image,root_review,command)
        # Root external lifecycle-domain review is already required by base_binding;
        # only the actual fresh image and observation-dependent operands are filled here.
        q=c.decode(c.read(ROOT/'lifecycle-code/qualification.TEMPLATE.json'))
        trust=root_review['trust_review']
        q.update(source_map_sha256=contract['capsule']['source_map_sha256'],image=image,base_labels=qualified['base_labels'],native='aarch64',page_bytes=4096,runtime_domain='SEPARATE_ROOT_WRITABLE_NATIVE_ARM4K_ALPM_V1',test_fingerprint=trust['test_fingerprint'],baseline_fingerprint=trust['baseline_fingerprint'],signing_credentials='EXCLUDED; fresh Root TEST signing performed outside actors',status='ROOT_ADMITTED_FOR_FINITE_COMPONENT_TRIAL')
        qr=c.encode(q);(work/'inner-qualification.json').write_bytes(qr)
        a=c.decode(c.read(ROOT/'lifecycle-code/admission.TEMPLATE.json'));run=binding['run']+'-'+binding['job']
        a.update(run=run,source_map_sha256=contract['capsule']['source_map_sha256'],image=image,base_labels=qualified['base_labels'],container='cachy-perl-lifecycle-'+run,inputs=str(capsule),test_fingerprint=trust['test_fingerprint'],baseline_fingerprint=trust['baseline_fingerprint'],root_qualification_sha256=c.pin(qr)['sha256'])
        ar=c.encode(a);(work/'inner-admission.json').write_bytes(ar)
        producer=c.load('held_pinned_installed_lifecycle',capsule/'producer.py')
        report['lifecycle']=producer.execute(argparse.Namespace(admission=str(work/'inner-admission.json'),admission_sha256=c.pin(ar)['sha256'],qualification=str(work/'inner-qualification.json'),qualification_sha256=c.pin(qr)['sha256'],source_map_sha256=contract['capsule']['source_map_sha256'],output=str(work/'installed')))
        c.need(report['lifecycle']['status']=='PASS_PRODUCED_PERL_INSTALLED_LIFECYCLE_DATA_REQUIRES_INDEPENDENT_ROOT_REVIEW','installed lifecycle incomplete')
        report['status']='LIFECYCLE_PRODUCED_PENDING_INDEPENDENT_ROOT_REVIEW'
    except BaseException as error:report['error']=type(error).__name__+': '+str(error)[:2048]
    finally:
        command.cleaning=True;command.deadline=time.monotonic()+240;errors=[]
        try:
            home=work/'bootstrap/gpg'
            if home.is_dir():
                command(['gpgconf','--homedir',str(home),'--kill','gpg-agent'],timeout=30,check=True);c.need(not any(home.glob('S.gpg-agent*')),'owned bootstrap GPG sockets remain')
            report['cleanup']['gpg_agent_absent']=True
        except BaseException as error:errors.append(str(error))
        if image is None and (work/'bootstrap/image-id').is_file():image=c.read(work/'bootstrap/image-id').decode().strip()
        try:
            if image:
                token=hashlib.sha256((binding['source']+':'+binding['ref']+':'+binding['run']).encode()).hexdigest()[:24]
                probe='perl-lifecycle-bootstrap-inventory-'+token
                listed=command(DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+probe+'$'],check=True)
                if listed.stdout.strip():
                    item=c.decode(command(DOCKER+['inspect',probe],check=True).stdout)[0]
                    c.need(item['Image']==image and item['Config']['Labels']['cachy-asahi.hosted-perl-lifecycle']==token and item['Config']['Labels']['cachy-asahi.hosted-perl-lifecycle.source']==binding['source'],'exact owned bootstrap inventory actor only')
                    command(DOCKER+['rm','-f',probe],check=True);report['status']='FAIL'
                data=c.decode(command(DOCKER+['image','inspect',image],check=True).stdout)[0]
                c.need(data['Id']==image and data['Config']['Labels']['cachy-asahi.hosted-perl-lifecycle']==token and data['Config']['Labels']['cachy-asahi.hosted-perl-lifecycle.source']==binding['source'] and data.get('RepoTags')==['perl-lifecycle-native-base:'+token],'exact owned bootstrap image retirement only')
                command(DOCKER+['image','rm',image],check=True)
                absent=command(DOCKER+['image','inspect',image]);c.need(absent.returncode==1,'owned image absence unknown');report['cleanup']['image_absent']=True
        except BaseException as error:errors.append(str(error))
        report['cleanup']['errors']=errors
        if errors or command.cancelled[0] or not report['cleanup'].get('image_absent'):report['status']='FAIL'
        (work/'hosted.json').write_bytes(c.encode(report))
        for sig,handler in previous.items():signal.signal(sig,handler)
    return 0 if report['status']=='LIFECYCLE_PRODUCED_PENDING_INDEPENDENT_ROOT_REVIEW' else 2


if __name__=='__main__':
    c.need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized hosted lifecycle entry')
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=('proof','metadata','inputs','native'))
    for key in ('source-sha','map-sha256','approval-sha256'):parser.add_argument('--'+key,required=True)
    parser.add_argument('--execute',action='store_true');args=parser.parse_args();work=Path(os.environ['RUNNER_TEMP'])/'perl-lifecycle-hosted'
    if args.phase=='proof':proof(args,work)
    elif args.phase=='metadata':metadata(args,work)
    elif args.phase=='inputs':inputs(args,work)
    else:raise SystemExit(run_native(args,work))
