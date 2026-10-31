#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Manual native600 composition; no installer, services or target-hardware admission."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import contract as C
import inputs
import bang
from owned import Containers,capture

HERE=Path(__file__).resolve().parent


def save(path,value):path.write_bytes(C.encoded(value))


def revision(path):return subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True,timeout=15).strip()


def check(args):
    policy=C.policy();C.source(args.code);C.verify_self(args.code)
    C.need(revision(args.code)==args.code_revision and revision(args.script_source)==policy['script_source'] and
           revision(args.bang_source)==policy['bang_source'] and revision(args.combined_source)==policy['combined']['source'],
           'held immutable source revisions differ')
    bundle=args.script_source
    index=C.read(C.checked(bundle,policy['script_index']))
    rows=inputs.retained(bundle,index,args.code)
    bang.recipe(args.bang_source,policy,inputs.tools(args.code)[0])
    inputs.combined(args.combined_source,policy)
    return policy,bundle,rows


def export(out,report):
    public=out/'public';public.mkdir(exist_ok=True)
    names=['lifecycle.log','producer.json','producer-cleanup.json','plan/original587-manifest.json','bang-comparison.json','plan/expected587.lock','plan/expected600.lock','plan/selection.json',
           'containers.json','container/lifecycle.json','container/combined-shell.json']
    phases=['baseline587','install600','same-version600','remove-to587-bang2','remove-to587',
            'restore600','final587-bang2','final587']
    names += ['container/'+prefix+phase+suffix for phase in phases for prefix,suffix in [('ld-','.json'),('aux-','.bin')]]
    for side in ('a','b'):
        base=C.UPGRADE+'-'+side
        names += [base+'/'+n for n in ('provenance.json','validation.json','build.log','expected-packages.lock')]
        names += [base+'/artifacts/'+n for n in ('environment.txt','packages.lock','config.sha256','makepkg.conf','pacman.conf','generated.SRCINFO')]
        artifacts=out/base/'artifacts'
        if artifacts.is_dir():
            names += [str(p.relative_to(out)) for p in artifacts.glob(C.UPGRADE+'-'+C.NEW+'-any.pkg.tar.*') if not p.name.endswith('.sig')]
    total=0;refs={}
    for name in names:
        path=out/name
        if not path.exists():continue
        C.safe(path);C.need(path.is_file() and path.stat().st_size<=16*1024**2,'bounded public ordinary file required')
        total+=path.stat().st_size;C.need(total<=16*1024**2,'public export total bound')
        dest=public/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,dest)
        refs[name]=dict(bytes=dest.stat().st_size,sha256=C.sha(dest))
    report['public_files']=refs;save(public/'report.json',report)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('code','preparation-source','product','updater','desktop','updater-v2-source','native','fdk','cache','setup4-pair',
                 'script-source','bang-source','combined-source','audio-inputs','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--code-revision',required=True);parser.add_argument('--check-inputs',action='store_true')
    args=parser.parse_args()
    for name,value in vars(args).items():
        if isinstance(value,Path):setattr(args,name,C.safe(value.absolute()))
    policy,bundle,retained=check(args)
    if args.check_inputs:
        print(json.dumps(dict(status='PASS_PASSIVE_BOUND_INPUTS',retained=len(retained),native='NOT_RUN')));return 0
    C.need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and
           not any(k.startswith('DOCKER_') for k in os.environ),'ordinary native ARM host required')
    C.need(capture(['docker','context','show'])=='default' and
           json.loads(capture(['docker','context','inspect','default']))[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock' and
           capture(['docker','info','--format','{{.Architecture}}']) in ('aarch64','arm64'),'local native ARM Docker required')
    out=args.output;C.need(out.parent==Path('/tmp') and not out.exists(),'fresh owned /tmp output required')
    out.mkdir(mode=0o700);(out/'home').mkdir(mode=0o700)
    env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',TZ='UTC',HOME=str(out/'home'))
    producer=C.load('expanded_initial_producer',args.code/'scripts/ci/full-composition-installer-vm/producer.py')
    profile=C.load('expanded_profile',args.code/'scripts/ci/full-composition-installer-vm/profile.py')
    api=C.load('expanded_sign_api',args.code/'scripts/ci/full-development-composition/run.py')
    common=C.load('expanded_logged',args.code/'scripts/virtual/common.py')
    producerout=Path('/tmp')/('expanded600-producer-'+os.urandom(16).hex())
    save(out/'producer-owner.json',dict(path=str(producerout)))
    report=dict(status='FAIL',scope='GENERIC_OFFLINE600_COMPOSITION_ONLY',hardware='NOT_RUN',installer='NOT_RUN',
                services='NOT_RUN',audio_execution='NOT_RUN',notification_delivery='NOT_RUN',release='NOT_ADMITTED',
                input_source=policy['script_source'],script_index=policy['script_index'],bang_source=policy['bang_source'],
                combined_source=policy['combined']['source'],commands=[],cleanup=[])
    owned=None;active=None;error=None;verifier=None

    def execute(argv,log,seconds):
        nonlocal active
        if argv[:2]==['docker','run']:argv=owned.launch(argv)
        report['commands'].append(dict(argv=argv,log=str(log.relative_to(out))))
        active=common.LoggedProcess(argv,log,env=env,limit=16*1024**2)
        try:
            active.process.wait(timeout=seconds);active.finish()
            C.need(active.process.returncode==0,'native command failed: '+log.name)
        finally:
            if active.process.poll() is None:
                try:os.killpg(active.process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                active.process.wait(timeout=10)
            active.finish();active=None

    def interrupted(*_):raise TimeoutError('expanded600 cancelled or deadline')
    prior={s:signal.signal(s,interrupted) for s in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM)}
    signal.setitimer(signal.ITIMER_REAL,6600)
    try:
        producerargs=argparse.Namespace(**vars(args));producerargs.output=producerout
        ready=producer.prepare(producerargs)
        original,_,before=profile.manifest(ready)
        image=(producerout/'private/desktop574/image-id').read_text().strip()
        C.need(re.fullmatch('sha256:[0-9a-f]{64}',image) and
               capture(['docker','image','inspect','--format','{{.Os}}/{{.Architecture}}',image])=='linux/arm64','exact native574 image required')
        owned=Containers(out/'containers.json',image)
        base=C.lock((ready/'builder-packages.lock').read_bytes(),574)
        epoch=C.read(args.desktop/'scripts/ci/maintained-desktop574-inputs.json')['source_date_epoch']
        successor=bang.build(args.bang_source,args.code,out,base,image,ready/'builder-packages.lock',epoch,policy,execute)
        report['bang_pair']=dict(status=successor['pair_status'],archive=successor['archive_ref'])
        addons=out/'addons'
        plan,sign=inputs.plan(ready,bundle,args.audio_inputs,args.code,successor,args.combined_source,policy,addons)
        signer=api.sign(addons,out,sign);plan['test_signer']=signer
        upstream=original['preparation']['signer_roles']['upstream_ALARM']
        for row in plan['incoming']:
            sig=addons/(row['archive']+'.sig');row.update(signature_size=sig.stat().st_size,signature_sha256=C.sha(sig),
                                                          signer=upstream if row['signer_role']=='ALARM' else signer)
        keys=[ready/r['path'] for r in original['keyrings']]+[addons/'TEST-public.asc']
        verifier=producer.PublicVerifier(out/'public-verifier',keys)
        for row in original['packages']:verifier(ready/row['archive'],ready/row['signature'],row['signer'])
        for row in plan['incoming']:verifier(addons/row['archive'],addons/(row['archive']+'.sig'),row['signer'])
        verifier.close();verifier=None
        planroot=out/'plan';planroot.mkdir()
        shutil.copyfile(ready/'manifest.json',planroot/'original587-manifest.json')
        before_payload=profile.payload(ready,original['packages'],args.code)
        expanded=[dict(r,archive=str(ready/r['archive'])) for r in original['packages'] if r['name']!=C.UPGRADE]
        expanded += [dict(r,archive=str(addons/r['archive'])) for r in plan['incoming']]
        after_payload=profile.payload(Path('/'),expanded,args.code)
        C.need(after_payload['packages']==plan['after'],'closed full600 payload merge differs')
        initial_names={r['name'] for r in original['projects']}|{'htmlq','pacman-contrib','archlinux-contrib','pyalpm'}
        initial_rows=[]
        for name in sorted(initial_names):
            nodes={p:before_payload['nodes'][p] for p in before_payload['ownership'][name]
                   if before_payload['nodes'][p]['type']!='directory'}
            initial_rows.append(dict(name=name,version=before[name],payload=nodes))
        save(planroot/'initial14-payload.json',initial_rows)
        save(planroot/'original-payload.json',before_payload)
        checks,_=inputs.tools(args.code)
        old=next(r for r in original['packages'] if r['name']==C.UPGRADE)
        oldreport=checks.package(ready/old['archive'])
        save(planroot/'bang1-payload.json',{p:n for p,n in oldreport['members'].items() if n['type']!='5' and p not in inputs.META})
        save(planroot/'plan.json',plan)
        (planroot/'expected587.lock').write_bytes(C.inventory_bytes(plan['before']))
        (planroot/'expected600.lock').write_bytes(C.inventory_bytes(plan['after']))
        save(planroot/'selection.json',dict(baseline_sha256=C.BASE_SHA,expanded_sha256=C.sha(planroot/'expected600.lock'),
            incoming=[{k:r[k] for k in ('name','version','sha256','size','signature_sha256','signer')} for r in plan['incoming']],
            payload_merge=dict(status='PASS_NO_OVERLAPS',nodes=len(after_payload['nodes']),packages=600)))
        resultdir=out/'container';resultdir.mkdir()
        name='cachy-asahi-expanded600-'+os.urandom(16).hex()
        argv=['docker','run','--name',name,'--pull=never','--platform=linux/arm64','--network=none','--cap-drop=ALL',
              '--security-opt=no-new-privileges','--pids-limit=512','--memory=8g','--cpus=4','--user=0:0',
              '--tmpfs=/tmp:rw,nosuid,nodev,exec,size=2g','--env=CACHY_ASAHI_EXPANDED600='+owned.token]
        argv += ['--cap-add='+c for c in ('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETUID','SETGID')]
        for source,dest,readonly in ((ready,'/original',True),(addons,'/addons',True),(planroot,'/plan',True),
            (HERE,'/runner',True),(args.code,'/code',True),(args.combined_source,'/combined',True),(resultdir,'/out',False)):
            argv += ['--mount','type=bind,src='+str(source)+',dst='+dest+(',readonly' if readonly else '')]
        execute(argv+['--entrypoint=/usr/bin/python3',image,'-I','-B','/runner/lifecycle.py'],out/'lifecycle.log',1800)
        life=C.read(resultdir/'lifecycle.json',4*1024**2);C.validate_result(life)
        receipt=C.checked(resultdir,life['combined_shell'],1024**2);C.validate_combined(C.read(receipt))
        C.need(len(owned.rows)==3,'two builders and one installed consumer required')
        report.update(status='PASS_NATIVE_EXPANDED600_COMPOSITION',lifecycle=life,original587='PRESERVED_AND_RESTORED')
    except BaseException as caught:error=caught;report.update(error_type=type(caught).__name__,error=str(caught)[:2048])
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        absence=True
        if owned:
            try:owned.cleanup();report['cleanup'].append(dict(resource='owned-containers',status='PASS'))
            except BaseException as caught:absence=False;error=error or caught;report['cleanup'].append(dict(resource='containers',status='FAIL',error=str(caught)[:512]))
        if verifier:
            try:verifier.close()
            except BaseException as caught:
                error=error or caught;report['cleanup'].append(dict(resource='public-verifier',status='FAIL',error=str(caught)[:512]))
        signing=out/'test-signing'
        if signing.exists():
            try:
                subprocess.run(['gpgconf','--homedir',str(signing),'--kill','all'],check=True,capture_output=True,timeout=15)
                shutil.rmtree(signing);report['cleanup'].append(dict(resource='expanded-test-secret',status='PASS'))
            except BaseException as caught:
                error=error or caught;report['cleanup'].append(dict(resource='expanded-test-secret',status='FAIL',error=str(caught)[:512]))
        if absence and (producerout/'producer-owner.json').is_file():
            try:producer.cleanup(producerout);report['cleanup'].append(dict(resource='initial-producer',status='PASS'))
            except BaseException as caught:error=error or caught;report['cleanup'].append(dict(resource='initial-producer',status='FAIL',error=str(caught)[:512]))
        for name in ('producer.json','producer-cleanup.json'):
            source=producerout/'public'/name
            if source.is_file() and not source.is_symlink() and source.stat().st_size<=1024**2:
                shutil.copyfile(source,out/name)
        if error is not None:report['status']='FAIL'
        try:export(out,report)
        except BaseException as caught:
            error=error or caught;report.update(status='FAIL',export_error=str(caught)[:512]);(out/'public').mkdir(exist_ok=True);save(out/'public/report.json',report)
        if owned:owned.close()
        for sig,handler in prior.items():signal.signal(sig,handler)
    return int(error is not None)


if __name__=='__main__':raise SystemExit(main())
