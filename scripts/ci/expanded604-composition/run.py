#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Manual signed604 composition of accepted archives; no target-hardware admission."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import contract as C

HERE=Path(__file__).resolve().parent
CARRIERS=('legacy_source','eight_source','seven_source','management_source','setup_source','welcome_source')
PRODUCER_PATHS=('code','preparation_source','product','updater','desktop','updater_v2_source','native','fdk','cache','setup4_pair')
PUBLIC_CAP=64*1024**2  # Separate604 bound; original600's16MiB export remains unchanged.


def save(path,value):path.write_bytes(C.encoded(value))


def require_verifier_absence(producer_root):
    home=producer_root/'private/expanded604-verifier'
    C.need(not (home.exists() or home.is_symlink()),'public verifier agent absence uncertain; preserve604 cache and original producer')


def capture(argv):
    result=subprocess.run(argv,capture_output=True,text=True,timeout=30)
    C.need(len(result.stdout)+len(result.stderr)<=1024**2,'bounded daemon observation required')
    result.check_returncode();return result.stdout.strip()


def verify(args):
    policy=C.policy();C.verify_source(args.code)
    C.need(C.revision(args.code)==args.code_revision,'exact immutable implementation source required')
    summary=C.inputs(args,policy)
    C.need(type(summary) is dict and type(summary.get('retention')) is list,'verified finite public input closure required')
    return policy,summary


def prepare_plan(ready,target,out,source,legacy,policy,audios):
    profile=C.load('_expanded604_profile',source/'scripts/ci/full-composition-installer-vm/profile.py')
    original,original_ref,before=profile.manifest(ready)
    selected,target_ref,after=C.target_manifest(target)
    C.need((before,after)==C.locks(),'exact587/604 closed manifests required')
    incoming=[r for r in selected['packages'] if before.get(r['name'])!=r['version']]
    C.need(len(incoming)==19 and len(after.keys()-before.keys())==17,'exact19 changed or added archives required')
    checks=C.load('_expanded604_checks',source/'scripts/checks/package_checks.py')
    rows=[]
    for row in incoming:
        inspected=checks.package(target/row['archive'])
        if row['name'] in C.AUDIO:
            expected=audios[row['name']]['inspected']
            C.need(all(inspected[k]==expected[k] for k in ('sha256','members','metadata','elf','errors')),
                'target audio differs from exact original inspected audio contract')
        else:C.need(not inspected['errors'],'target project archive inspection rejected')
        C.need(inspected['sha256']==row['sha256'],'target archive byte identity differs')
        rows.append(dict(row,metadata=inspected['metadata']['.PKGINFO'],
            payload={p:n for p,n in inspected['members'].items() if n['type']!='5' and p not in {'.PKGINFO','.BUILDINFO','.MTREE'}}))
    C.need(C.selected(before,{r['name']:r['version'] for r in rows})==after,'finite selected incoming closure differs')
    before_payload=profile.payload(ready,original['packages'],source)
    after_payload=profile.payload(target,selected['packages'],source)
    C.need(before_payload['packages']==before and after_payload['packages']==after,'full archive payload merge differs')
    root=out/'plan';root.mkdir()
    save(root/'original-payload.json',before_payload)
    shutil.copyfile(ready/'manifest.json',root/'original587-manifest.json')
    shutil.copyfile(target/'manifest.json',root/'target604-manifest.json')
    names={r['name'] for r in original['projects']}|{'htmlq','pacman-contrib','archlinux-contrib','pyalpm'}
    C.need(len(names)==14,'exact14 bootstrap inputs required')
    save(root/'initial14-payload.json',[dict(name=n,version=before[n],payload={p:before_payload['nodes'][p]
        for p in before_payload['ownership'][n] if before_payload['nodes'][p]['type']!='directory'}) for n in sorted(names)])
    predecessor={}
    for name in C.UPGRADES:
        row=next(r for r in original['packages'] if r['name']==name)
        inspected=checks.package(ready/row['archive']);C.need(not inspected['errors'],'predecessor archive rejected')
        predecessor[name]={p:n for p,n in inspected['members'].items() if n['type']!='5' and p not in {'.PKGINFO','.BUILDINFO','.MTREE'}}
    save(root/'predecessor-payload.json',predecessor)
    plan=dict(schema_version=1,baseline_sha256=C.BEFORE,target_sha256=C.AFTER,
        original_manifest=original_ref,target_manifest=target_ref,before=before,after=after,incoming=rows,
        test_signer=original['preparation']['signer_roles']['ephemeral_TEST'],combined=policy['combined'])
    save(root/'plan.json',plan)
    for name,value in (('expected587.lock',before),('expected604.lock',after)):(root/name).write_bytes(C.inventory_bytes(value))
    save(root/'selection.json',dict(baseline_sha256=C.BEFORE,target_sha256=C.AFTER,
        incoming=[{k:r[k] for k in ('name','version','archive','sha256','size','signature_sha256','signer')} for r in rows],
        payload_merge=dict(status='PASS_NO_OVERLAPS',packages=604,nodes=len(after_payload['nodes']),
            shared_profile='UNCHANGED_BOUNDED_ARCHIVE_API',shared587_limits='UNCHANGED')))
    return root,plan


def export(out,report,args,summary):
    public=out/'public';public.mkdir(exist_ok=True);refs={};spent=0
    def copy(path,name,required=False):
        nonlocal spent
        if not path.exists():
            C.need(not required,'missing required retention: '+name);return
        C.safe(path);info=path.lstat()
        C.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=32*1024**2,'bounded ordinary public retention required')
        spent+=info.st_size;C.need(spent<=PUBLIC_CAP,'separate604 public64MiB cap exceeded')
        dest=public/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,dest)
        refs[name]=dict(bytes=dest.stat().st_size,sha256=C.sha(dest))
    names=['lifecycle.log','producer.json','producer-cleanup.json','containers.json','producer-owner.json','input-summary.json',
        'container/lifecycle.json','container/combined-shell.json','plan/plan.json','plan/selection.json',
        'plan/original587-manifest.json','plan/target604-manifest.json','plan/expected587.lock','plan/expected604.lock']
    phases=('baseline587','install604','same-version604','remove-to587-upgraded','remove-to587','restore604','final587-upgraded','final587')
    names += ['container/'+prefix+phase+suffix for phase in phases for prefix,suffix in [('ld-','.json'),('aux-','.bin')]]
    for name in names:copy(out/name,name)
    retention=summary['retention'];C.need(len(retention)<=1024,'finite retained input file count exceeded')
    input_api=C.scoped_load('_expanded604_public_retention',HERE/'inputs.py',aliases={'contract':C})
    seen=set()
    for row in retention:
        C.need(set(row)=={'root','ref'} and row['root'] in CARRIERS,'only public bound input carriers retained')
        name='inputs/'+row['root']+'/'+row['ref']['path'];C.need(name not in seen,'duplicate retained input reference');seen.add(name)
        copy(input_api.source_ref(getattr(args,row['root']),row['ref']),name,True)
    report['public_files']=refs;report['retention']=dict(files=len(refs),bytes=spent,cap=PUBLIC_CAP,
        native_pairs='ORIGINAL_ACCEPTED_BOTH_ARCHIVES_NO_REBUILD',scope='PUBLIC_BOUND_INPUTS_AND_CLOSED_LIFECYCLE_RECORDS')
    save(public/'report.json',report)


def parser():
    value=argparse.ArgumentParser(description=__doc__)
    for name in (*PRODUCER_PATHS,*CARRIERS,'audio_inputs','output'):
        value.add_argument('--'+name.replace('_','-'),type=Path,required=True)
    value.add_argument('--code-revision',required=True);value.add_argument('--check-inputs',action='store_true');return value


def main(argv=None):
    args=parser().parse_args(argv)
    for name,value in vars(args).items():
        if isinstance(value,Path):setattr(args,name,C.safe(value.absolute()))
    policy,summary=verify(args)  # No output, secrets, Docker or producer module before all input gates.
    if args.check_inputs:
        print(json.dumps(dict(status='PASS_PASSIVE_BOUND604_INPUTS',native='NOT_RUN')));return 0
    C.need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and
        not any(k.startswith('DOCKER_') for k in os.environ),'ordinary native ARM host required')
    C.need(capture(['docker','context','show'])=='default' and
        json.loads(capture(['docker','context','inspect','default']))[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock' and
        capture(['docker','info','--format','{{.Architecture}}']) in ('aarch64','arm64'),'local native ARM Docker required')
    out=args.output;C.need(out.parent==Path('/tmp') and not out.exists(),'fresh owned /tmp output required')
    out.mkdir(mode=0o700);(out/'home').mkdir(mode=0o700)
    save(out/'input-summary.json',dict(summary=summary['summary'],retention=summary['retention']))
    env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',TZ='UTC',HOME=str(out/'home'))
    producer=C.load('_expanded604_producer',args.code/'scripts/ci/full-composition-installer-vm/producer.py')
    common=C.load('_expanded604_logged',args.code/'scripts/virtual/common.py')
    owner=C.scoped_load('_expanded604_owned',args.code/'scripts/ci/expanded-development-composition/owned.py',aliases={'contract':C})
    materializer=C.scoped_load('_expanded604_materializer',HERE/'materializer.py',aliases={'contract':C})
    producerout=Path('/tmp')/('expanded604-producer-'+os.urandom(16).hex())
    save(out/'producer-owner.json',dict(path=str(producerout)))
    report=dict(status='FAIL',scope='NATIVE_OFFLINE604_COMPOSITION_ONLY',hardware='NOT_RUN',installer='NOT_RUN',
        services='NOT_RUN',audio_execution='NOT_RUN',notification_delivery='NOT_RUN',release='NOT_ADMITTED',commands=[],cleanup=[])
    owned=None;active=None;error=None
    def interrupted(*_):raise TimeoutError('expanded604 cancelled or deadline')
    prior={s:signal.signal(s,interrupted) for s in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM)}
    signal.setitimer(signal.ITIMER_REAL,6600)  # Original600 owner deadline retained; no added build actors.
    try:
        producerargs=argparse.Namespace(**{n:getattr(args,n) for n in PRODUCER_PATHS},code_revision=args.code_revision,output=producerout)
        ready=producer.prepare(producerargs)
        image=(producerout/'private/desktop574/image-id').read_text().strip()
        C.need(re.fullmatch('sha256:[0-9a-f]{64}',image) and
            capture(['docker','image','inspect','--format','{{.Os}}/{{.Architecture}}',image])=='linux/arm64','exact native574 builder required')
        owned=owner.Containers(out/'containers.json',image)
        target=materializer.prepare(ready,producerout,args.eight_source,args.seven_source,args.audio_inputs,
            args.legacy_source,out/'ready604',policy,args.management_source,args.setup_source,args.welcome_source,args.code)
        planroot,plan=prepare_plan(ready,target,out,args.code,args.legacy_source,policy,summary['audios'])
        resultdir=out/'container';resultdir.mkdir()
        name='cachy-asahi-expanded604-'+os.urandom(16).hex()
        command=['docker','run','--name',name,'--pull=never','--platform=linux/arm64','--network=none','--cap-drop=ALL',
            '--security-opt=no-new-privileges','--pids-limit=512','--memory=8g','--cpus=4','--user=0:0',
            '--tmpfs=/tmp:rw,nosuid,nodev,exec,size=2g','--env=CACHY_ASAHI_EXPANDED604='+owned.token]
        command+=['--cap-add='+c for c in ('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETUID','SETGID')]
        for source,dest,readonly in ((ready,'/original',True),(target,'/target',True),(planroot,'/plan',True),
            (HERE,'/runner',True),(args.code,'/code',True),(args.legacy_source,'/combined',True),(resultdir,'/out',False)):
            command+=['--mount','type=bind,src='+str(source)+',dst='+dest+(',readonly' if readonly else '')]
        command=owned.launch(command+['--entrypoint=/usr/bin/python3',image,'-I','-B','/runner/lifecycle.py'])
        report['commands'].append(dict(argv=command,log='lifecycle.log'))
        active=common.LoggedProcess(command,out/'lifecycle.log',env=env,limit=16*1024**2)
        active.process.wait(timeout=1800);active.finish();C.need(active.process.returncode==0,'native604 lifecycle failed')
        life=C.read(resultdir/'lifecycle.json',4*1024**2);C.validate_result(life)
        C.validate_combined(C.read(C.checked(resultdir,life['combined_shell'],1024**2)))
        C.need(len(owned.rows)==1,'exactly one lifecycle consumer; accepted pairs are never rebuilt')
        report.update(status='PASS_NATIVE_EXPANDED604_COMPOSITION',lifecycle=life,original587='PRESERVED_AND_RESTORED',
            accepted_archives='REUSED_WITHOUT_REBUILD',builder_provenance='ORIGINAL574_DISTINCT_FROM604_DEPLOYMENT')
    except BaseException as caught:error=caught;report.update(error_type=type(caught).__name__,error=str(caught)[:2048])
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        if active:
            try:
                if active.process.poll() is None:
                    os.killpg(active.process.pid,signal.SIGKILL);active.process.wait(timeout=10)
                active.finish()
            except BaseException as caught:error=error or caught
        absence=True
        if owned:
            try:owned.cleanup();report['cleanup'].append(dict(resource='owned-consumer',status='PASS'))
            except BaseException as caught:
                absence=False;error=error or caught;report['cleanup'].append(dict(resource='owned-consumer',status='FAIL',error=str(caught)[:512]))
        try:require_verifier_absence(producerout)
        except BaseException as caught:
            absence=False;error=error or caught
            report['cleanup'].append(dict(resource='expanded604-public-verifier',status='FAIL_AGENT_ABSENCE_UNCERTAIN',
                preserved=['owned604-public-cache','original-producer'],error=str(caught)[:512]))
        target=out/'ready604'
        if absence and (target.exists() or target.is_symlink()):
            try:
                C.safe(target);C.need(target.is_dir(),'owned604 cache directory required')
                for path in target.rglob('*'):
                    C.need(not path.is_symlink(),'owned604 public cache symlink refused')
                    if path.is_dir():path.chmod(0o700)
                shutil.rmtree(target);C.need(not target.exists(),'owned604 public cache remains')
                report['cleanup'].append(dict(resource='owned604-public-cache',status='PASS'))
            except BaseException as caught:error=error or caught;report['cleanup'].append(dict(resource='owned604-public-cache',status='FAIL',error=str(caught)[:512]))
        if absence and (producerout/'producer-owner.json').is_file():
            try:producer.cleanup(producerout);report['cleanup'].append(dict(resource='original-producer',status='PASS'))
            except BaseException as caught:error=error or caught;report['cleanup'].append(dict(resource='original-producer',status='FAIL',error=str(caught)[:512]))
        for name in ('producer.json','producer-cleanup.json'):
            path=producerout/'public'/name
            if path.is_file() and not path.is_symlink() and path.stat().st_size<=1024**2:shutil.copyfile(path,out/name)
        if error is not None:report['status']='FAIL'
        try:export(out,report,args,summary)
        except BaseException as caught:
            error=error or caught;report.update(status='FAIL',export_error=str(caught)[:512]);(out/'public').mkdir(exist_ok=True);save(out/'public/report.json',report)
        if owned:owned.close()
        for sig,handler in prior.items():signal.signal(sig,handler)
    return int(error is not None)


if __name__=='__main__':raise SystemExit(main())
