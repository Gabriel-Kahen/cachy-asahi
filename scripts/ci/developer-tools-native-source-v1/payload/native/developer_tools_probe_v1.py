# SPDX-License-Identifier: MIT
"""Fixed installed/relocated developer journeys and passive raw-log checks.

Import creates no actor. Only the caller's retained owned Commands runner may
launch commands. Existing packaged runners own and retire their child groups.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

NAME='cachy-asahi-developer-tools'
VERSION='0.1.0-1'
ROLES=('workflow','build-systems','debugger','python')
STEPS=('help','version','verify',*ROLES)
RUNNERS=dict(workflow='developer_workflow.py',**{'build-systems':'developer_build_systems.py'},debugger='developer_debugger.py',python='python_development.py')
LOG=re.compile(r'[0-9]{3}-[A-Za-z0-9._+-]{1,96}\.log')

def need(ok,why):
    if not ok:raise ValueError(why)
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def data_pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path,cap=1024**2):
    path=Path(path);need(path==path.resolve() and not any(q.is_symlink()for q in(path,*path.parents)),'ordinary fixed journey operand')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded single-link journey operand')
        with os.fdopen(os.dup(fd),'rb')as stream:body=stream.read(cap+1)
        identity=lambda q:(q.st_dev,q.st_ino,q.st_mode,q.st_nlink,q.st_size,q.st_mtime_ns,q.st_ctime_ns)
        need(len(body)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'whole stable journey operand');return body
    finally:os.close(fd)

def requests(cli,home,policy):
    home=Path(home)
    rows=[('help',['--help']),('version',['--version']),('verify',['verify'])]
    for role in ROLES:
        args=[role,'--output',str(home/role),'--command-timeout','20','--total-timeout','90']
        args+=['--python','/usr/bin/python3','--uv',policy['journey_policy']['uv']]if role=='python'else['--tool-path','/usr/bin:/bin']
        rows.append((role,args))
    return rows

def validate_cli(cli,policy):
    cli=Path(cli);need(cli.name==NAME and cli.parent.name=='bin'and cli.parent.parent.name=='usr','fixed installed or complete moved prefix')
    prefix=cli.parents[2];expected=policy['recipe']['payload_files']
    need(len(expected)==34,'exact34 installed payload leaves')
    for name,row in expected.items():
        p=prefix/name
        need(data_pin(read(p))=={k:row[k]for k in('bytes','sha256')}and stat.S_IMODE(p.stat().st_mode)==row['mode'],'exact installed/moved runtime bytes and modes')
    runtime=prefix/'usr/lib'/NAME/'0.1.0'
    need({p.relative_to(prefix).as_posix()for p in runtime.rglob('*')if p.is_file()}=={n for n in expected if n.startswith('usr/lib/')},'no extra runtime files')
    return dict(files=34,payload=expected)

def supervision(row,logs):
    need(type(row)is dict and row.get('success')is True and type(row.get('argv'))is list and 0<len(row['argv'])<=128,'original bounded successful command row')
    name=row.get('log');need(type(name)is str and LOG.fullmatch(name) and name in logs and data_pin(logs[name])==row.get('log_pin'),'original raw nested command output pin')
    state=row.get('supervision');code=state.get('exit')if type(state)is dict else None;expected=row.get('expected');need(type(code)is int and (code>0 if expected=='nonzero'else type(expected)is int and code==expected),'actual nested exit must match expected outcome');need(type(state)is dict and state.get('reaped')is True and state.get('ownership')=='REAPED'and state.get('group_census')=='EMPTY_TWICE'and state.get('output_complete')is True and state.get('error')is None and state.get('timeout')is False and state.get('signals')==[],'owned nested process retirement and complete output required')
    return logs[name]

def validate_debugger_output(raw, source, line, expected, version):
    text = raw.decode('utf-8', errors='replace')
    location = re.escape(str(source)) + ':' + str(line)
    # Count and order assertions: an exit-0 GDB invocation alone is insufficient.
    patterns = [r'(?m)^Breakpoint 1, workflow_step \(seed=10\) at ' + location + r'\r?$',
                r'(?m)^DEBUGGER_LOCAL:' + str(expected) + r'\r?$',
                r'(?m)^#0\s+workflow_step \(seed=10\) at ' + location + r'\r?$',
                r'(?m)^#1\s+(?:0x[0-9a-f]+ in )?main \(\) at ' + re.escape(str(source)) + r':\d+\r?$',
                r'(?m)^Debugger version ' + version + ': ' + str(expected) + r'\r?$',
                r'(?m)^\[Inferior \d+ \(process \d+\) exited normally\]\r?$',
                r'(?m)^DEBUGGER_EXIT:0\r?$', r'(?m)^DEBUGGER_DONE\r?$']
    end = 0
    for pattern in patterns:
        matches = list(re.finditer(pattern, text))
        if len(matches) != 1 or matches[0].start() < end:
            raise ValueError('missing, duplicate or out-of-order debugger observation: ' + pattern)
        end = matches[0].end()
    return dict(source_breakpoint=dict(path=str(source), line=line), known_local=expected,
                stack=['workflow_step(seed=10)', 'main()'], continued=True, normal_exit=0)

def validate_journey(role,value,logs,policy):
    need(role in ROLES and type(value)is dict and value.get('architecture')=='aarch64'and type(value.get('page_size'))is int and value['page_size']>0 and type(value.get('uid'))is int and value['uid']!=0,'actual nonroot native ARM journey report')
    need(value.get('physical_M2')=='NOT_RUN'and value.get('performance')=='NOT_MEASURED'and value.get('release')=='NOT_ADMITTED'and 'error'not in value,'no target/performance/release inference or persisted journey error')
    payload=policy['recipe']['payload_files'];prefix='usr/lib/'+NAME+'/0.1.0/';sources=value.get('sources',{})
    for key,name in [('runner','scripts/workflows/'+RUNNERS[role]),('owned_process','scripts/virtual/owned_process.py')]:
        need(sources.get(key)=={k:payload[prefix+name][k]for k in('bytes','sha256')},'same original packaged runner/helper bytes')
    helper='helper'if role in('build-systems','debugger')else'workflow'
    if role!='workflow':need(sources.get(helper)=={k:payload[prefix+'scripts/workflows/developer_workflow.py'][k]for k in('bytes','sha256')},'same packaged Commands implementation')
    commands=value.get('commands');need(type(commands)is list and 0<len(commands)<=200,'finite original journey commands')
    actual={};seen=set()
    for row in commands:
        need(row['log']not in seen,'unique nested command raw log');seen.add(row['log']);actual[row['step']]=supervision(row,logs)
    need(set(logs)==seen,'complete exact nested log namespace')
    if role=='workflow':
        need(value.get('status')=='PASS_LOCAL_DEVELOPER_COMPONENT'and not value.get('missing_required'),'real Git/editor/compiler/venv workflow required')
        need(all(value.get('tools',{}).get(n,{}).get('workflow')=='EXECUTED'for n in('git','cc','c++','vim','python3')),'required tools must execute real workflows')
        need(all(n in actual for n in('git-init','git-add','git-commit','git-revision','git-local-clone','git-checkout')),'real local Git journey required')
        need(re.fullmatch(rb'[0-9a-f]{40}\n',actual['git-revision'])is not None,'actual local Git revision')
        projects=value.get('project_workflows');need(type(projects)is dict and set(projects)=={'make','ninja'},'both fixed incremental project backends reported')
        for name,p in projects.items():
            need(p.get('status')in('PASS_REAL_PROJECT_WORKFLOW','MISSING_OPTIONAL'),'failed optional backend cannot become NOT_RUN')
            if p['status']=='MISSING_OPTIONAL':need(p.get('workflow')=='NOT_RUN','missing optional backend explicitly NOT_RUN')
    elif role=='build-systems':
        need(value.get('status')in('PASS_AVAILABLE_LOCAL_WORKFLOWS','NOT_RUN_NO_BUILD_SYSTEM'),'available backend outcomes only')
        projects=value.get('project_workflows');need(type(projects)is dict and set(projects)=={'cmake','meson'},'every build-system backend explicitly reported')
        needs=dict(cmake=('cmake','ctest','ninja','cc','c++'),meson=('meson','ninja','cc','c++'))
        for backend,p in projects.items():
            if p.get('status')=='NOT_RUN':
                missing=p.get('missing');need(type(missing)is list and missing and set(missing)<=(set(needs[backend]))and all(value['tools'][n].get('status')=='MISSING'for n in missing),'only genuinely absent required backend tools permit NOT_RUN')
                continue
            need(p.get('status')=='PASS_REAL_PROJECT_WORKFLOW'and p.get('unchanged')=='NO_OBJECT_LIBRARY_BINARY_WRITES'and p.get('compile_failure')=='REAL_NONZERO_STALE_EXECUTION_REFUSED'and p.get('test_failure')=='REAL_NONZERO_EXECUTION_REVOKED'and p.get('installed')=='PASS_PRIVATE_PREFIX_RUNTIME','real build/test/incremental/private-install lifecycle required')
            records=p.get('records',[]);outcomes={r.get('step'):r.get('outcome')for r in records}
            need(outcomes.get('unchanged-check')=='NO_PRODUCT_WRITES'and outcomes.get('changed-check')=='CPP_OBJECT_AND_LIBRARY_CHANGED_C_OBJECT_UNTOUCHED'and outcomes.get('installed-runtime')=='BUILD_SOURCE_WITHHELD_LIBRARY_REQUIRED_AND_RESTORED','actual incremental objects and withheld-source relocated runtime')
            need(sum(r.get('outcome')=='REFUSED_BEFORE_LAUNCH'and r.get('attempted_launches')==0 for r in records)==3,'all three stale execution controls before launch')
            for tail in('configure','broken-build','broken-test','test-recovery-test','install'):
                need(backend+'-'+tail in actual,'every real backend configure/build/test/install output retained')
    elif role=='debugger':
        need(value.get('status')=='PASS_LOCAL_DEBUGGER_COMPONENT'and set(value.get('projects',{}))=={'c','cpp'},'both real native GDB projects')
        for language,p in value['projects'].items():
            need(p.get('status')=='PASS_REAL_GDB_WORKFLOW'and p.get('compile_failure')=='REAL_NONZERO_STALE_DEBUGGER_REFUSED'and p.get('recovery')=='PASS_REBUILT'and p.get('initial')!=p.get('edited'),'edited and recovered debugger lifecycle')
            records=p.get('records',[])
            need(sum(r.get('outcome')=='STALE_DEBUGGER_REFUSED'and r.get('attempted_launches')==0 for r in records)==3,'three stale-debugger controls before launch')
            for step in('initial-debug','edited-debug','recovery-debug'):
                raw=actual.get(language+'-'+step,b'')
                matches=[r for r in records if r.get('step')==step and r.get('outcome')=='PASS_SOURCE_LOCAL_STACK_CONTINUE_EXIT'];need(len(matches)==1,'sole original GDB business observation')
                observed=matches[0]['observed'];location=observed['source_breakpoint'];source=Path(location['path']);need(source.name=='hello.'+language and source.parent.name==language+'-project'and source.parent.parent.name=='debugger','fixed original debugger source fixture path')
                checked=validate_debugger_output(raw,source,location['line'],17 if step=='initial-debug'else 21,'one'if step=='initial-debug'else'two');need(checked==observed,'all ordered debugger source/local/stack/continue/normal-exit observations must match raw output')
            for row in commands:
                if row['step']in{language+'-'+s for s in('initial-debug','edited-debug','recovery-debug')}:
                    argv=row['argv'];need('-nx'in argv and '-nh'in argv and '--batch'in argv and 'set auto-load off'in argv and 'set debuginfod enabled off'in argv,'GDB fixed no-startup/no-download argv')
    else:
        need(value.get('status')=='PASS_LOCAL_PYTHON_WORKFLOW'and value.get('uv',{}).get('path')==policy['journey_policy']['uv']and value['uv'].get('file')=={k:policy['journey_policy']['uv_pin'][k]for k in('bytes','sha256')}and value['uv'].get('inputs')=='BUILT_IN_UV_BACKEND_NO_EXTERNAL_CACHE','actual frozen uv fixture journey, not presence/version credit')
        p=value.get('project',{});need(p.get('status')=='PASS_LOCAL_PYTHON_WORKFLOW'and p.get('unchanged')=='NO_BUILD_OR_INSTALL_LAUNCH'and p.get('edit')=='CHANGED_SOURCE_WHEEL_INSTALLED_MODULE_AND_CLI_OUTPUT'and p.get('failure_recovery')=='REAL_BUILD_AND_UNIT_FAILURES_RECOVERED','real Python wheel/install/CLI/edit/failure/recovery')
        for row in commands:
            if row['argv'][0]==policy['journey_policy']['uv'] and row['step']!='uv-version':
                need('--offline'in row['argv'] and ('--no-index'in row['argv']or 'venv'in row['argv']),'actual uv offline/no-index argv')
    return dict(status=value['status'],backends={n:p['status']for n,p in value.get('project_workflows',{}).items()})

def probe(cli,home,label,policy,command,progress):
    cli,home=Path(cli),Path(home);installed=validate_cli(cli,policy);records=[];journeys={};exports=[]
    scope=Path(policy['invocation']['store'])/'journey'/'developer-tools-alpm-v1'
    progress.update(status='FAIL',label=label,journey_logs=exports,journeys=journeys)
    def capture(key):
        body=read(home/key/'result.json');value=json.loads(body);logs={r['log']:read(home/key/r['log'])for r in value.get('commands',[])};copied={}
        for index,(name,data)in enumerate(sorted({'result.json':body,**logs}.items())):
            leaf='800-'+label+'-'+key+'-'+('%03d'%index)+'.log';target=scope/leaf
            with target.open('xb')as stream:stream.write(data)
            target.chmod(0o644);row=dict(log=leaf,log_pin=data_pin(data));exports.append(row);copied[name]=row
        journeys[key]=dict(summary=None,files=copied)
        return value,logs
    for number,(key,args)in enumerate(requests(cli,home,policy)):
        argv=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(home),'PATH=/usr/bin:/bin','PYTHONDONTWRITEBYTECODE=1',str(cli),*args]
        # Missing optional backend outcomes are package exit2 and remain explicit;
        # workflow/debugger/Python inputs are supplied by the exact354/tool closure.
        expected=0
        try:raw=command(key,argv,expected,cwd=home)
        except BaseException:
            if key in ROLES and (home/key/'result.json').is_file():
                try:capture(key)
                except (OSError,ValueError,KeyError):pass
            raise
        need(type(raw)is bytes and len(raw)<=1024**2,'bounded original CLI stdout')
        if key=='version':need(raw==(NAME+' 0.1.0\n').encode(),'actual installed/relocated version')
        elif key=='help':need(all(word in raw for word in(b'workflow',b'build-systems',b'debugger',b'python',b'verify')),'all fixed CLI commands visible')
        elif key=='verify':need(json.loads(raw).get('status')=='PASS_PACKAGED_RUNTIME'and json.loads(raw).get('files')==28,'exact packaged runtime verify')
        else:
            value,logs=capture(key)
            summary=validate_journey(key,value,logs,policy)
            need(json.loads(raw).get('status')==value['status'],'launcher summary joins actual original report')
            journeys[key]['summary']=summary
        records.append(dict(step=key,argv=argv,expected=expected,stdout=data_pin(raw)))
    need(validate_cli(cli,policy)==installed,'packaged source and fixtures unchanged after real journeys')
    result=dict(status='PASS_DEVELOPER_TOOLS_FIXED_INSTALLED_JOURNEYS',version=VERSION,label=label,scope=label,cli=str(cli),home=str(home),installed=installed,commands=records,journeys=journeys,journey_logs=exports,physical_M2='NOT_RUN',performance='NOT_MEASURED',release='NOT_ADMITTED')
    progress.update(result);return result
