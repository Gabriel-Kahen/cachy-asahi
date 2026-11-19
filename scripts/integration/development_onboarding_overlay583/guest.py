# SPDX-License-Identifier: MIT
"""Run the installed onboarding exercise within an admitted Overlay583 target."""
from base64 import b64decode, b64encode
from hashlib import file_digest, sha256
from pathlib import Path
import json
import os
import re
import resource
import shutil
import stat
import subprocess
from tempfile import TemporaryDirectory, TemporaryFile
import time
from types import ModuleType

UID = GID = 29085
EXAMPLE = 'examples/development/hello.c'
GREETING = 'Hello from cachy-asahi'
EDIT = 'Hello from my installed terminal'
OUTPUT_CAP = 256 * 1024
LABELS = ('shell','git-version','cc-version','nano-version','source-clone','prepare','edit','rebuild',
          'verify','baseline-elf','rebuild-elf','inventory-unchanged')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return sha256(raw).hexdigest()


def inventory_capture(owner, argv, env, cap, workspace):
    def limit_output_file():
        _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        limit = OUTPUT_CAP if hard == resource.RLIM_INFINITY else min(hard, OUTPUT_CAP)
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

    with TemporaryFile(dir=workspace) as stderr:
        child=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=stderr,
                               preexec_fn=limit_output_file,start_new_session=True)
        result=owner.supervise(child,cap=cap,retirement=1,max_output=OUTPUT_CAP)
        stderr.seek(0)
        diagnostic=stderr.read(OUTPUT_CAP+1)
        require(len(result['output'])+len(diagnostic)<=OUTPUT_CAP,'bounded inventory command streams')
        return result, diagnostic


def executable_pins(target, expected):
    for name,row in expected.items():
        path=target/name
        info=path.lstat()
        require(info.st_uid==info.st_gid==0,'root-owned installed tool '+name)
        if 'link' in row:
            require(stat.S_ISLNK(info.st_mode) and os.readlink(path)==row['link'],'exact installed tool alias '+name)
        else:
            require(path.resolve()==path and stat.S_ISREG(info.st_mode) and
                    info.st_size==row['bytes'] and stat.S_IMODE(info.st_mode)==row['mode'],'exact installed tool shape '+name)
            with path.open('rb') as file:
                require(file_digest(file,'sha256').hexdigest()==row['sha256'],'exact installed tool bytes '+name)


def evidence_tool(program):
    loaded=ModuleType('installed_onboarding_evidence')
    loaded.__file__='/caa-onboarding-reviewed/examples/development/onboarding.py'
    exec(compile(program,loaded.__file__,'exec'),vars(loaded))
    return loaded


def joined_reports(work, program, materials):
    evidence=work/'evidence'
    rebuilt=[path for path in evidence.iterdir() if path.name.startswith('rebuild-')]
    require(len(rebuilt)==1 and len(list(evidence.iterdir()))==2,'exact baseline and rebuild directory')
    tool=evidence_tool(program)
    baseline, before=tool.success_evidence(evidence/'baseline','baseline')
    edited, after=tool.success_evidence(rebuilt[0],'rebuild')
    expected=materials['fixture_commit']
    for row in (baseline,edited):
        require(row['source_revision']==row['checkout_head']==expected and row['architecture']=='aarch64' and
                row['page_size']==16384 and row['effective_uid']==UID,'exact ordinary installed ARM16K and source identity')
    require(baseline['source_repository']==edited['source_repository'] and
            baseline['source_sha256']==materials['example_sha256'] and edited['source_sha256']==materials['edit_sha256'] and
            edited['run']['stdout']==EDIT+'\n' and baseline['binary_sha256']!=edited['binary_sha256'],
            'exact edited source, binary and output retained')
    return (rebuilt[0],dict(baseline_report_sha256=before,rebuild_report_sha256=after,source_revision=expected),
            dict(baseline=baseline['binary_sha256'],rebuilt=edited['binary_sha256']))


def retain_evidence(work):
    root=work/'evidence'
    def bounded(path):
        info=path.lstat()
        require(path.resolve()==path and stat.S_ISREG(info.st_mode) and 0<info.st_size<=192*1024,
                'bounded retained build evidence')
        return b64encode(path.read_bytes()).decode('ascii')
    return {directory.name:{name:bounded(directory/name) for name in ('report.json','hello.c','hello')}
            for directory in root.iterdir()}


def verify_evidence(receipt, selected):
    evidence=receipt['build_evidence']
    require(type(evidence) is dict and len(evidence)==2 and 'baseline' in evidence and
            all(key=='baseline' or re.fullmatch(r'rebuild-[A-Za-z0-9_]+',key) for key in evidence),
            'exact demo evidence directories')
    with TemporaryDirectory(prefix='onboarding-offline-review-') as temporary:
        root=Path(temporary)
        for label,rows in evidence.items():
            require(set(rows)=={'report.json','hello.c','hello'},'exact saved evidence files')
            out=root/'evidence'/label
            out.mkdir(parents=True)
            for name,value in rows.items():
                require(type(value) is str and len(value)<=256*1024,'bounded saved build body')
                body=b64decode(value,validate=True)
                if name=='hello':
                    require(body[:6]==b'\x7fELF\x02\x01' and int.from_bytes(body[18:20],'little')==183,
                            'retained AArch64 ELF executable')
                (out/name).write_bytes(body)
        _,verified,binaries=joined_reports(root,b64decode(selected['program'],validate=True),selected)
    require(verified==receipt['verified'] and binaries==receipt['binaries'],'exact saved build readback evidence')


def validate(receipt, selected, lock, nonce):
    require(receipt['kind']=='OVERLAY583_INSTALLED_DEVELOPMENT_ONBOARDING_R2' and receipt['nonce']==nonce and
            receipt['fixture_commit']==selected['fixture_commit'] and receipt['upstream_commit']==selected['upstream_commit'] and
            receipt['initial_lock']==lock and receipt['installed_tools']==selected['tool_versions'] and
            receipt['scope']=='SCRIPTED_EDIT_INSTALLED_ARM16K_ONLY','exact installed onboarding receipt')
    rows=receipt['commands']
    require([row['label'] for row in rows]==list(LABELS)[:len(rows)],'closed onboarding command roster')
    if receipt['status']=='PASS':
        require(len(rows)==len(LABELS) and receipt['final_lock']==lock and receipt['workspace_removed'] is True and
                receipt['origin_namespace_absent'] is True and receipt['effective_uid']==UID and
                receipt['verified']['source_revision']==receipt['fixture_commit'] and
                receipt['readback_executed_binary'] is False and receipt['hardware'] is None,
                'complete exact removed ordinary-user workspace and retained result')
        diagnostic=rows[-1]['inventory_stderr']
        require(set(diagnostic)=={'bytes','sha256'} and type(diagnostic['bytes']) is int and
                0<=diagnostic['bytes']<=OUTPUT_CAP-lock['bytes'] and
                re.fullmatch(r'[a-f0-9]{64}',diagnostic['sha256']),
                'separate bounded inventory stderr receipt')
        for row in rows:
            proc=row['process']
            require(proc['exit']==0 and proc['reaped'] is proc['output_complete'] is True and
                    proc['ownership']=='REAPED' and proc['group_census']=='EMPTY_TWICE' and
                    proc['timeout'] is False and proc['signals']==[] and proc['error'] is None,
                    'exact owned subprocess retirement')
        verify_evidence(receipt,selected)
    else:
        require(receipt['status']=='HOLD' and receipt['hardware'] is None,'explicit incomplete onboarding receipt')
    return receipt


def exercise(trial, plan, lock, env, deadline, selected):
    nonce=plan['nonce']
    target=trial.TARGET
    workspace=Path('/var/tmp')/('caa-development-onboarding-'+nonce)
    host=target/workspace.relative_to('/')
    receipt=dict(kind='OVERLAY583_INSTALLED_DEVELOPMENT_ONBOARDING_R2',status='HOLD',nonce=nonce,
                 fixture_commit=selected['fixture_commit'],upstream_commit=selected['upstream_commit'],
                 scope='SCRIPTED_EDIT_INSTALLED_ARM16K_ONLY',initial_lock=trial.pin(lock),final_lock=None,
                 installed_tools=selected['tool_versions'],commands=[],hardware=None,workspace_removed=False,
                 origin_namespace_absent=False)
    owned=False
    root_mode=None
    try:
        require(os.geteuid()==0 and os.uname().machine=='aarch64' and os.sysconf('SC_PAGE_SIZE')==16384,
                'admitted ARM16K guest root')
        require(trial.canonical_lock(lock,583).items() >= selected['tool_versions'].items(),'exact selected compiler/tool lock')
        executable_pins(target, selected['tools'])
        node=target.stat()
        require(node.st_uid==node.st_gid==0 and target.resolve()==target,'exact installed target root')
        mode=stat.S_IMODE(node.st_mode)
        if not mode&0o001:
            target.chmod(mode|0o001)
            root_mode=mode
        require(host.parent.is_dir() and host.parent.resolve()==host.parent and not os.path.lexists(host),'fresh guest-only workspace')
        host.mkdir(mode=0o755)
        owned=True
        host.chmod(0o755)
        home=host/'home'
        home.mkdir(mode=0o700)
        os.chown(home,UID,GID)
        bundle=b64decode(selected['bundle'],validate=True)
        program=b64decode(selected['program'],validate=True)
        require(digest(bundle)==selected['bundle_sha256'] and digest(program)==selected['program_sha256'],'exact embedded fixture source')
        driver='driver/examples/development/onboarding.py'
        (host/driver).parent.mkdir(mode=0o755,parents=True)
        for directory in ((host/'driver'),(host/'driver/examples'),(host/'driver/examples/development')):
            directory.chmod(0o755)
        for name,body in (('source.bundle',bundle),(driver,program)):
            path=host/name
            path.write_bytes(body)
            path.chmod(0o444)
        owner=ModuleType('installed_onboarding_owned_process')
        exec(compile(selected['owned_process'],'held-owned-process.py','exec'),vars(owner))
        owner.prepare()
        end=min(deadline,time.monotonic()+240)
        guest_home=workspace/'home'
        origin=guest_home/'origin'
        work=guest_home/'exercise'
        env=dict(PATH='/usr/bin:/bin',HOME=str(guest_home),TMPDIR=str(guest_home),LC_ALL='C.UTF-8',TZ='UTC',
                 GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_ALLOW_PROTOCOL='file')
        chroot=['/usr/bin/chroot',f'--userspec={UID}:{GID}',f'--groups={GID}',str(target)]
        py=['/usr/bin/python3','-I','-B',str(workspace/driver)]

        def run(label,argv):
            require(label==LABELS[len(receipt['commands'])],'exact next onboarding role')
            cap=min(60,end-time.monotonic())
            require(cap>1,'bounded onboarding clock exhausted')
            extra={}
            if label=='inventory-unchanged':
                observed, diagnostic=inventory_capture(owner,list(map(str,argv)),env,cap,host)
                extra['inventory_stderr']=trial.pin(diagnostic)
            else:
                child=subprocess.Popen([*chroot,*map(str,argv)],env=env,stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
                observed=owner.supervise(child,cap=cap,retirement=1,max_output=OUTPUT_CAP)
            output=observed.pop('output')
            receipt['commands'].append(dict(label=label,process=observed,output_sha256=digest(output),**extra))
            require(observed['passed'] is True and observed['exit']==0 and observed['group_census']=='EMPTY_TWICE',
                    'owned onboarding role failed: '+label)
            return output

        with trial.ExitStack() as mounts:
            trial.target_api_mounts(target,env,mounts)
            actual=run('shell',['/usr/bin/bash','--noprofile','--norc','-c','printf "%s\n" "$EUID"'])
            require(actual==f'{UID}\n'.encode(),'ordinary installed shell uid')
            receipt['effective_uid']=UID
            for label,tool in (('git-version','git'),('cc-version','cc'),('nano-version','nano')):
                require(run(label,['/usr/bin/'+tool,'--version']),'installed tool version report')
            run('source-clone',['/usr/bin/git','-c','protocol.allow=never','-c','protocol.file.allow=always',
                               'clone','--no-local','--branch','onboarding',workspace/'source.bundle',origin])
            run('prepare',[*py,'prepare',work,'--source',origin,'--revision',selected['fixture_commit']])
            edit_script=('from pathlib import Path; import sys; p=Path(sys.argv[1]); old=p.read_bytes(); '
                         'assert old.count(sys.argv[2].encode())==1; p.write_bytes(old.replace(sys.argv[2].encode(),sys.argv[3].encode()))')
            run('edit',['/usr/bin/python3','-I','-B','-c',edit_script,work/'checkout'/EXAMPLE,GREETING,EDIT])
            run('rebuild',[*py,'rebuild',work,'--expect',EDIT])
            rebuilt, verified, binaries=joined_reports(home/'exercise',program,selected)
            relative=work/'evidence'/rebuilt.name
            check=json.loads(run('verify',[*py,'verify',relative]))
            require(check==dict(status='PASS',scope='retained-build-evidence',**verified),'actual independent verify invocation agrees')
            for label,directory in (('baseline-elf',work/'evidence/baseline'),('rebuild-elf',relative)):
                output=run(label,['/usr/bin/readelf','-h',directory/'hello'])
                require(any(line.split()==[b'Machine:',b'AArch64'] for line in output.splitlines()),'exact AArch64 ELF')
            query=next(argv for role,argv,_ in plan['operations'] if role=='query')
            actual=trial.sorted_rows(run('inventory-unchanged',query))
            require(actual==lock,'retained exact 583 installed inventory after onboarding')
            receipt.update(status='PASS',verified=verified,binaries=binaries,final_lock=trial.pin(actual),
                           build_evidence=retain_evidence(home/'exercise'),readback_executed_binary=False)
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        receipt.update(status='HOLD',failure=type(error).__name__)
    finally:
        try:
            if owned:
                shutil.rmtree(host)
            receipt['workspace_removed']=receipt['origin_namespace_absent']=not os.path.lexists(host)
        finally:
            if root_mode is not None:
                target.chmod(root_mode)
    return validate(receipt,selected,trial.pin(lock),nonce)
