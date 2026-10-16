#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fresh owned original producer -> private full26 generic VM -> ordered teardown."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
import adapter as A

HERE=Path(__file__).resolve().parent
LABEL='org.cachy-asahi.installer-full26.producer'


def save(path,value):path.write_bytes(A.encoded(value))
def read(path):return json.loads(A.read(path))
def sha(path):return A.digest(A.read(path,256*1024**2))['sha256']


def policy(workspace):
    value=read(HERE/'policy.json')
    A.need(value['schema_version']==1 and value['status']=='ROOT_BOUND_ORIGINAL_PRODUCER_AND_FULL26',
           'UNBOUND full26 source; no secrets or actors permitted')
    row=value['producer']
    A.need(type(row) is dict and set(row)=={'ref','inputs_sha256','recipes_sha256','integration_sha256'} and
           re.fullmatch('[0-9a-f]{40}',row['ref']) and
           all(re.fullmatch('[0-9a-f]{64}',row[k]) for k in row if k!='ref'), 'exact original producer source/locks')
    A.need(row['inputs_sha256']=='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f' and
           row['recipes_sha256']=='a5fb287b4dda2a90bf61d4fa8cbbc5d666dad8bb450a70544d00545b091f36e3',
           'unchanged original341/four-package producer inputs required')
    for name,expected in read(HERE/'source-manifest.json')['files'].items():
        A.need(A.digest(A.read(workspace/name))==expected,'full26 source closure changed: '+name)
    return value


def revision(root):
    row=subprocess.run(['git','-C',str(root),'rev-parse','HEAD'],capture_output=True,text=True,timeout=10)
    A.need(row.returncode==0 and re.fullmatch('[0-9a-f]{40}',row.stdout.strip()), 'exact checkout revision')
    return row.stdout.strip()


def proof(workspace,output):
    selected=policy(workspace)  # Before Git/GITHUB_OUTPUT/mkdir/secrets/actors.
    source=os.environ['SOURCE_SHA']
    A.need(source==os.environ['WORKFLOW_SHA']==os.environ['GITHUB_SHA']==revision(workspace) and
           os.environ['RUNNER_ARCH']=='ARM64' and os.environ['RUNNER_OS']=='Linux', 'exact source/workflow/native runner')
    identity=':'.join((os.environ['GITHUB_RUN_ID'],os.environ['GITHUB_RUN_ATTEMPT'],source))
    row=dict(status='SOURCE_ONLY_ROOT_BOUND_FULL26',source_sha=source,run_id=os.environ['GITHUB_RUN_ID'],
             attempt=os.environ['GITHUB_RUN_ATTEMPT'],token=hashlib.sha256(('installer-full26:'+identity).encode()).hexdigest()[:32],
             producer=selected['producer'],native_P0='UNCHANGED_FAILED',hardware='NOT_RUN')
    save(output,row)
    with open(os.environ['GITHUB_OUTPUT'],'a') as stream:stream.write('producer_ref='+selected['producer']['ref']+'\n')
    return row


@contextmanager
def modules(directory,names):
    previous={n:sys.modules.get(n) for n in names};prior=list(sys.path)
    try:
        for name in names:sys.modules.pop(name,None)
        sys.path.insert(0,str(directory));yield
    finally:
        sys.path[:]=prior
        for name,value in previous.items():
            if value is None:sys.modules.pop(name,None)
            else:sys.modules[name]=value


def vm_retired(output):
    try:
        value=read(output/'owner-public/result.json')
        return (value['private_workspace_cleanup']=='PASS' and value['guest']['owned_group_retirement']=='PASS' and
                value['guest']['cleanup_uncertain'] is False and all(r['status']=='PASS' for r in value['cleanup']))
    except (OSError,ValueError,KeyError):return False


def tooling_packet(source,engine,output):
    """Copy the exact retained 21-package tooling closure; never fetch URLs."""
    A.need(isinstance(source,Path) and source.is_absolute() and source.is_dir() and
           not any(p.is_symlink() for p in (source,*source.parents)) and
           not output.exists() and not output.is_symlink(),'ordinary immutable tooling packet/fresh cache')
    lock_path=engine/'scripts/virtual/tooling.lock.json';lock=read(lock_path)
    A.need(lock['schema_version']==1 and lock['base_package_count']==341 and
           len(lock['packages'])==21 and lock['expected_package_count']==362,'exact21 original tooling lock')
    rows=lock['keyring_files']+[v for r in lock['packages'] for v in
        (r,dict(filename=r['filename']+'.sig',size=r['signature_size'],sha256=r['signature_sha256']))]
    files={r['filename']:dict(bytes=r['size'],sha256=r['sha256']) for r in rows}
    A.need(len(rows)==len(files)==45 and all(Path(n).name==n for n in files),'flat45 tooling closure')
    expected=dict(schema_version=1,purpose='installer-full26-generic-vm-tooling-inputs',
                  tooling_lock_sha256=sha(lock_path),files=files)
    A.need(read(source/'index.json')==expected and
           {p.name for p in source.iterdir()}=={'index.json',*files},'closed exact tooling index')
    # Validate the complete borrowed packet before materializing any cache.
    for name,row in files.items():
        A.need(A.digest(A.read(source/name))==row,'retained tooling byte/hash differs: '+name)
    output.mkdir(mode=0o700)
    for name,row in files.items():
        raw=A.read(source/name);A.need(A.digest(raw)==row,'tooling input changed during copy')
        (output/name).write_bytes(raw)
    receipt=dict(status='EXACT_RETAINED_TOOLING_INPUTS',files=files,
                 index=A.digest(A.read(source/'index.json')),tooling_lock_sha256=sha(lock_path),
                 count=45,bytes=sum(r['bytes'] for r in files.values()),network='NOT_USED')
    save(output.parent/'tooling-inputs.json',receipt)
    return receipt


def producer_safe(controller,integration_started,vm_started,vm):
    if vm_started and (not integration_started or not vm_retired(vm)):return False
    if controller is None:return not integration_started
    if not integration_started:
        # The pinned constructor only snapshots source and creates directories.
        # Do not infer retirement after a run or any acquired consumer image.
        return (not vm_started and controller.installed is None and controller.installed_owned is None and
                controller.report.get('stages')=={})
    return controller.report.get('owned_image_cleanup',{}).get('status')=='PASS'


def consume(controller,engine,cache,output,implementation):
    A.need(controller.report['stages']['lifecycle']['status']=='PASS' and re.fullmatch('sha256:[0-9a-f]{64}',controller.installed),
           'fresh successful installed original-four lifecycle required')
    output.mkdir(mode=0o700);inputs=output/'inputs';inputs.mkdir(mode=0o700)
    raw=controller.work/'lifecycle-raw';source=engine/'scripts/virtual'
    paths={'base_inputs_lock':controller.native_out/'inputs.lock.json','base_lock':controller.native_out/'packages.lock',
        'installed_lock':raw/'installed-packages.lock','lifecycle_receipt':raw/'lifecycle/result.json',
        'installed_image_receipt':raw/'installed-image.json','committed_config':raw/'committed-config.json',
        'committed_verification':raw/'committed-image/result.json','commit_receipt':raw/'commit-receipt.json',
        'tooling_lock':source/'tooling.lock.json','tooling_audit':source/'tooling-audit.json'}
    def copy(origin,name):
        raw=A.read(origin,256*1024**2);target=inputs/name;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw);A.need(sha(target)==A.digest(raw)['sha256'],'immutable VM input copy changed');return dict(path=name,sha256=sha(target))
    files={alias:copy(p,'metadata/'+alias+p.suffix) for alias,p in paths.items()}
    rows=read(paths['committed_verification'])['baseline']
    A.need(rows==controller.rows['baseline'],'verified original-four archive rows differ')
    for row in rows:copy(controller.archives/row['archive'],row['archive'])
    lock=read(paths['tooling_lock']);blobs=lock['keyring_files']+[r for row in lock['packages'] for r in
        (row,dict(filename=row['filename']+'.sig',sha256=row['signature_sha256'],size=row['signature_size']))]
    A.need(len(blobs)==45,'exact21-package tooling/key/signature closure')
    for row in blobs:
        A.need(Path(row['filename']).name==row['filename'],'flat tooling input')
        origin=cache/row['filename'];A.need(origin.stat().st_size==row['size'] and sha(origin)==row['sha256'],'tooling byte join')
        copy(origin,'tooling-cache/'+row['filename'])
    with modules(source,('common','audit_tooling','image_decode_report','controller')):
        import controller as owner
        import common
        for name,row in common.TRANSACTION_FILES.items():
            ref=copy(engine/name,name);A.need(ref['sha256']==row['sha256'] and (inputs/name).stat().st_size==row['bytes'],'full26 fixture join')
        contract=dict(schema_version=1,execution='native-aarch64-controller-qemu-tcg-guest',installed_image_id=controller.installed,
            source_commit=implementation,baseline_source_commit=controller.commit,run_id=os.environ['GITHUB_RUN_ID'],
            run_attempt=os.environ['GITHUB_RUN_ATTEMPT'],core_sha256=owner.CORE,audit_tooling_sha256=owner.AUDITOR_PIN,
            controller_sha256=sha(source/'controller.py'),baseline=rows,files=files,cache_dir='tooling-cache',purpose=A.PURPOSE,
            transaction_fixture=dict(source_commit=implementation,sources=common.TRANSACTION_FILES,tool_profile=common.TRANSACTION_PROFILE),
            transaction_launcher=common.TRANSACTION_LAUNCHER)
        path=inputs/'controller-contract.json';save(path,contract)
        passed=owner.main(['--contract',str(path),'--contract-sha256',sha(path),'--output',str(output/'owner-public')])
    value=read(output/'owner-public/result.json')
    A.need(passed and value['status']==A.PASS and vm_retired(output),'full26 owner or retirement failed')
    controller.report['virtual']=dict(status=A.PASS,scope='GENERIC_ARM_FULL26_ORIGINAL_METHODS_SOFTWARE_ONLY',native_P0='UNCHANGED_FAILED',hardware='NOT_RUN')


def producer_tag(token):
    A.need(re.fullmatch('[0-9a-f]{32}',token) is not None,'exact producer lease token')
    return 'cachy-asahi-full26-producer:'+token


def cleanup_image(native,output,token,safe):
    path=output/'native/image-id'
    if not path.exists():
        attempted=(output/'producer-build.json').exists()
        return dict(status='RETAINED_CREATION_UNKNOWN' if attempted else 'NOT_CREATED',absence_verified=not attempted)
    image=path.read_text().strip();ledger=read(output/'producer-owner.json')
    A.need(safe and ledger['token']==token and image not in ledger['before_images'],'consumers must retire before new producer cleanup')
    tag=producer_tag(token)
    A.need(re.fullmatch('sha256:[0-9a-f]{64}',image) is not None and ledger.get('tag')==tag and
           ledger.get('tag_absent_before') is True,'exact freshly owned producer tag/image lease')
    rows=json.loads(native.run(['docker','image','inspect',image],timeout=30))
    A.need(len(rows)==1 and rows[0]['Id']==image and rows[0]['Config']['Labels'].get(LABEL)==token and
           rows[0].get('RepoTags')==[tag],'foreign/borrowed producer or tag preserved')
    # Child image removal may prune untagged parents. The run-private tag keeps
    # this producer alive until consumers retire; final removal must not prune.
    native.run(['docker','image','rm','--no-prune',tag],timeout=60)
    remaining=native.run(['docker','image','ls','-a','--no-trunc','-q'],timeout=30).splitlines()
    tagged=native.run(['docker','image','ls','-a','--no-trunc','--quiet','--filter','reference='+tag],timeout=30).splitlines()
    A.need(image not in remaining and not tagged and set(ledger['before_images'])<=set(remaining),'producer/tag absence/borrowed images preserved')
    return dict(status='PASS',image=image,tag=tag,absence_verified=True,tag_absence_verified=True,
                borrowed_images_preserved=True,parent_pruning=False)


def run(args):
    selected=policy(args.workspace);binding=selected['producer'];source=read(args.proof)
    A.need(source['producer']==binding and source['source_sha']==revision(args.workspace) and revision(args.producer)==binding['ref'], 'Root source/producer binding')
    identity=':'.join((os.environ['GITHUB_RUN_ID'],os.environ['GITHUB_RUN_ATTEMPT'],source['source_sha']))
    A.need(source['status']=='SOURCE_ONLY_ROOT_BOUND_FULL26' and source['run_id']==os.environ['GITHUB_RUN_ID'] and
           source['attempt']==os.environ['GITHUB_RUN_ATTEMPT'] and
           source['token']==hashlib.sha256(('installer-full26:'+identity).encode()).hexdigest()[:32] and
           source['source_sha']==os.environ['SOURCE_SHA']==os.environ['WORKFLOW_SHA']==os.environ['GITHUB_SHA'],
           'same actual source/workflow/run/attempt lease')
    for flag,name in (('inputs','inputs.lock.json'),('recipes','recipes.lock.json'),('integration','integration.lock.json')):
        A.need(sha(args.producer/'scripts/ci'/name)==binding[flag+'_sha256'],'exact original producer lock')
    A.need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and
           args.output.is_absolute() and args.output.parent==Path(os.environ['RUNNER_TEMP']).resolve() and
           not args.output.exists() and not args.output.is_symlink() and
           not any(p.is_symlink() for p in args.output.parents),'ordinary native caller/fresh owned runner output')
    args.output.mkdir(mode=0o700);output=args.output;lease=os.open(output/'producer.lease',os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_CLOEXEC,0o600)
    fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
    save(output/'source-proof.json',source)
    result=dict(status='FAIL',scope='GENERIC_ARM_FULL26_ORIGINAL_METHODS_SOFTWARE_ONLY',native_P0='UNCHANGED_FAILED',hardware='NOT_RUN',
                source_sha=source['source_sha'],producer_ref=binding['ref'],VM='NOT_STARTED',producer_cleanup='NOT_STARTED')
    engine=output/'engine';A.prepare(args.workspace,engine);vm=output/'vm';started=False;integration_started=False;controller=None
    def interrupted(*_):raise InterruptedError('full26 owner cancelled')
    prior={sig:signal.signal(sig,interrupted) for sig in (signal.SIGTERM,signal.SIGINT)}
    names=('native_arm','integration','integration_export','lifecycle_inventory','repository_projection','desktop_projection','commit_image','package_checks')
    with modules(args.producer/'scripts/ci',names):
        import native_arm as native
        import integration
        original_run=native.run;original_remove=integration.remove_derivative
        try:
            inputs=read(args.producer/'scripts/ci/inputs.lock.json')
            lock=integration.preflight(args.producer,args.producer/'scripts/ci/integration.lock.json',binding['integration_sha256'],binding['recipes_sha256'],inputs['source_date_epoch'])
            tooling=output/'tooling-cache'
            tooling_packet(args.tooling_inputs,engine,tooling)  # Before any native/Docker producer actor.
            probe=output/'probe';probe.mkdir();native.probe(probe)
            before=set(native.run(['docker','image','ls','-a','--no-trunc','-q'],timeout=30).splitlines())
            tag=producer_tag(source['token'])
            tagged=native.run(['docker','image','ls','-a','--no-trunc','--quiet','--filter','reference='+tag],timeout=30).splitlines()
            A.need(not tagged,'producer lease tag already exists; borrowed tag preserved')
            save(output/'producer-owner.json',dict(schema_version=1,token=source['token'],before_images=sorted(before),
                                                  label=LABEL,tag=tag,tag_absent_before=True))
            def owned_command(argv,*pos,**kw):
                if argv[:2]==['docker','build']:
                    A.need(argv.count('--iidfile')==1 and '--tag' not in argv and '-t' not in argv,'original owned producer build anchor')
                    argv=[*argv[:2],'--label',LABEL+'='+source['token'],'--tag',tag,*argv[2:]]
                    save(output/'producer-build.json',dict(argv=argv,token=source['token'],tag=tag,scope='fresh original341+4 producer only'))
                return original_run(argv,*pos,**kw)
            native.run=owned_command
            code=native.main(['build','--inputs-sha256',binding['inputs_sha256'],'--recipes-sha256',binding['recipes_sha256'],
                             '--cache',str(args.cache),'--output',str(output/'native')])
            A.need(code==0,'fresh original native pair producer failed')
            image=(output/'native/image-id').read_text().strip();A.need(image not in before,'fresh token-labeled image required')
            controller=integration.Controller(image,output/'native',output/'integration',lock,binding['ref'],package_only=True)
            def retained_derivative(owned,base):
                if started and not vm_retired(vm):return dict(status='FAIL',absence_verified=False,cleanup_uncertain=True,reason='RETAINED_FULL26_VM_RETIREMENT_UNKNOWN')
                return original_remove(owned,base)
            integration.remove_derivative=retained_derivative
            def consumer(current):
                nonlocal started
                started=True;result['VM']='STARTED';save(output/'result.json',result)
                consume(current,engine,tooling,vm,source['source_sha'])
            integration_started=True
            A.need(controller.run(consumers=consumer),'producer integration/full26 consumer failed')
            result.update(status='PASS',VM=A.PASS)
        except BaseException as error:result.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:512])
        finally:
            pending=[]
            for sig in prior:signal.signal(sig,lambda n,f:pending.append(n))
            native.run=original_run;integration.remove_derivative=original_remove
            safe=producer_safe(controller,integration_started,started,vm)
            try:
                result['producer_cleanup']=cleanup_image(native,output,source['token'],safe)
            except BaseException as error:result.update(status='FAIL',producer_cleanup=dict(status='RETAINED_OR_FAILED',error=str(error)[:256]))
            if pending:result.update(status='FAIL',cleanup_signals=pending)
            save(output/'result.json',result);os.close(lease)
            for sig,handler in prior.items():signal.signal(sig,handler)
    return result


def retain(source,output):
    A.need(not output.exists(),'fresh closed public evidence directory');output.mkdir(mode=0o700)
    selected=['source-proof.json','result.json','producer-owner.json','producer-build.json','engine/adapter.json','native/result.json','native/bootstrap.json','tooling-inputs.json',
              'integration/result.json','vm/owner-public/result.json','vm/owner-public/guest-events.json']
    selected += ['vm/owner-public/'+n+'-container.log' for n in ('tooling','verify','prepare','runtime')]
    adapter=source/'engine/adapter.json';pinned_sources=set()
    if adapter.exists():
        for name,row in read(adapter)['files'].items():
            A.need(name in {*('scripts/virtual/'+n for n in A.VIRTUAL),'scripts/install/local_transaction.py',
                           'scripts/install/test_local_transaction.py','scripts/port/kernel-native-job/runtime.py'}, 'finite engine export source')
            A.need(A.digest(A.read(source/'engine'/name))==row['after'],'actual private engine after-hash')
            selected.append('engine/'+name);pinned_sources.add('engine/'+name)
    contract=source/'vm/inputs/controller-contract.json'
    if contract.exists():
        value=read(contract);selected.append('vm/inputs/controller-contract.json')
        aliases={'base_inputs_lock','base_lock','installed_lock','lifecycle_receipt','installed_image_receipt',
                 'committed_config','committed_verification','commit_receipt','tooling_lock','tooling_audit'}
        A.need(set(value['files'])==aliases and len(value['baseline'])==4,'exact public input receipt export')
        for row in value['files'].values():
            name=row['path'];A.need(name.startswith('metadata/') and len(Path(name).parts)==2 and '..' not in Path(name).parts,'closed metadata path')
            A.need(sha(source/'vm/inputs'/name)==row['sha256'],'actual metadata input join');selected.append('vm/inputs/'+name)
        for row in value['baseline']:
            name=row['archive'];A.need(name.startswith('baseline/') and len(Path(name).parts)==2 and '..' not in Path(name).parts,'closed original archive path')
            A.need(sha(source/'vm/inputs'/name)==row['sha256'],'actual original archive join');selected.append('vm/inputs/'+name)
    result=dict(status='CLOSED_BOUNDED_FULL26_EVIDENCE',files={},errors=[],hardware='NOT_RUN',native_P0='UNCHANGED_FAILED')
    total=0
    for name in selected:
        origin=source/name
        if not origin.exists():continue
        try:
            raw=A.read(origin,8*1024**2);total+=len(raw)
            # Immutable source contains assertions/filter code spelling PRIVATE
            # KEY. It is not runtime key material. Still reject actual armor
            # delimiters in source, and retain the strict runtime/log filter.
            private=(re.search(rb'-----BEGIN (?:PGP PRIVATE KEY BLOCK|(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----',raw)
                     if name in pinned_sources else b'PRIVATE KEY' in raw)
            A.need(total<=64*1024**2 and not private,'closed public bound/privacy')
            target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);result['files'][name]=A.digest(raw)
        except (OSError,ValueError) as error:result['errors'].append(name+': '+str(error)[:128])
    need_result=read(source/'result.json')
    if need_result['status']=='PASS':
        try:
            required={'source-proof.json','producer-owner.json','producer-build.json','engine/adapter.json',
                      'native/result.json','native/bootstrap.json','tooling-inputs.json','integration/result.json','vm/owner-public/result.json',
                      'vm/owner-public/guest-events.json','vm/inputs/controller-contract.json'}
            A.need(required<=set(result['files']) and vm_retired(source/'vm') and
                   need_result['producer_cleanup']['status']=='PASS' and
                   need_result['producer_cleanup']['absence_verified'] is True,'complete actual owner/source/cleanup export')
            events=read_list(source/'vm/owner-public/guest-events.json')
            rows=[v for v in events if v.get('event')=='transaction_result']
            A.need(len(rows)==1,'one actual full26 matrix record')
            row=rows[0];order=[(c,n) for c,names in A.selection().items() for n in names]
            A.need(row['status']==A.PASS and row['tests']==26 and row['failures']==row['errors']==row['skips']==0 and
                   row['class_cleanups_returned'] is True and row['cancelled'] is False and
                   [(v['cls'],v['method']) for v in row['duties']]==order and
                   all(v['status']=='PASS' for v in row['duties']) and len(row['methods'])==17 and
                   sum(len(v['calls']) for v in row['methods'])==22,'complete original26 duties/22 calls')
        except (OSError,ValueError,KeyError,TypeError) as error:result['errors'].append('completion: '+str(error)[:128])
    if need_result['status']!='PASS' or result['errors']:result['status']='FAIL_OR_INCOMPLETE_FULL26_EVIDENCE'
    save(output/'retention.json',result);return result


def read_list(path):
    value=json.loads(A.read(path));A.need(type(value) is list and len(value)<=1000 and all(type(v)is dict for v in value),'bounded closed public event list');return value


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=('proof','run','retain'))
    for name in ('workspace','proof','producer','cache','output','source','tooling-inputs'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    try:
        value=proof(args.workspace,args.proof) if args.phase=='proof' else run(args) if args.phase=='run' else retain(args.source,args.output)
        print(json.dumps(value,sort_keys=True));return int(value['status'] not in ('SOURCE_ONLY_ROOT_BOUND_FULL26','PASS','CLOSED_BOUNDED_FULL26_EVIDENCE'))
    except (OSError,ValueError,KeyError) as error:
        print(json.dumps(dict(status='REFUSED_OR_FAILED_FULL26',error=str(error)[:256])));return 1


if __name__=='__main__':raise SystemExit(main())
