# SPDX-License-Identifier: MIT
"""Fixed future Root-plan delivery. No actor runs on import.

Hosted Linux/CPython/stdlib and Root's workflow/vars are trusted. Immutable Git
checkouts and selected file pins are ordinary custody, not a Python sandbox.
"""
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import sys
import time

REPOSITORY='Gabriel-Kahen/cachy-asahi'
REF='refs/heads/codex/project-private-libraries-cli-registered-v1'
WORKFLOW='.github/workflows/native-arm-runner-observation.yml'
CLI='scripts/ci/private-library-cli/'
SOURCE_ROWS_PATH='manifests/reviewed/project-private-libraries-cli-source-rows.json'
PEER_PATH='manifests/reviewed/project-private-libraries-cli-source-peer.json'
PLAN_LIMIT=128*1024
PLAN_ENV='ROOT_REGISTERED_PRIVATE_LIBRARY_CLI_PLAN_B64'
PIN_ENV='ROOT_REGISTERED_PRIVATE_LIBRARY_CLI_PLAN_SHA256'
PLAN_KEYS=frozenset(('schema_version','purpose','repository','ref','code_commit','source_commit','data_commit',
    'bootstrap','job','source_rows','peer_receipt','metadata','tools'))
INPUT_KEYS=frozenset(('contract_sha256','materialization_plan_sha256','jbigkit_inputs_sha256','libtiff_inputs_sha256'))
INPUT_PATHS={'contract_sha256':'manifests/reviewed/project-private-libraries.json',
    'materialization_plan_sha256':'scripts/ci/development/project_library_sources/materialization-plan.json',
    'jbigkit_inputs_sha256':'manifests/reviewed/project-jbigkit-inputs.json',
    'libtiff_inputs_sha256':'manifests/reviewed/project-libtiff-inputs.json'}
HEADERS=('CACHY_OLD_FOUR_SCHEMA','CACHY_OLD_FOUR_SOURCE_EPOCH')
SEEDS=('CACHY_OLD_FOUR_JBIGKIT_01','CACHY_OLD_FOUR_JBIGKIT_02','CACHY_OLD_FOUR_JBIGKIT_SIG_01',
    *('CACHY_OLD_FOUR_LIBTIFF_'+str(n).zfill(2)for n in range(1,16)),'CACHY_OLD_FOUR_LIBTIFF_SIG_01')
BODIES=('boundary','parent_bridge','entry','operations','owned_build','baseline_bridge','evidence','consumer_adapter',
    'bootstrap','job','producer_supervisor','publication')


def need(value,reason):
    if not value:raise ValueError(reason)


def exact(value,keys):need(type(value)is dict and set(value)==set(keys),'ROOT_CLOSED_FIELDS')


def pin(value,width=64):
    need(type(value)is str and re.fullmatch('[0-9a-f]{'+str(width)+'}',value) and value!='0'*width,'ROOT_FULL_PIN')
    return value


def relative(value):
    need(type(value)is str and 0<len(value)<=512 and '\\'not in value,'ROOT_RELATIVE_PATH')
    path=PurePosixPath(value)
    need(not path.is_absolute() and '..'not in path.parts and path.as_posix()==value and value!='.' and
        '.git'not in path.parts and '__pycache__'not in path.parts and not value.endswith(('.pyc','.pyo')),'ROOT_RELATIVE_PATH')
    return value


def decode(raw,limit=PLAN_LIMIT):
    need(type(raw)is bytes and 0<len(raw)<=limit,'ROOT_JSON_CAP')
    def pairs(rows):
        value={}
        for key,item in rows:
            need(key not in value,'ROOT_DUPLICATE_KEY');value[key]=item
        return value
    def constant(_):raise ValueError('ROOT_NONFINITE_JSON')
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)


def descriptor(row,limit,*,allow_empty=False):
    exact(row,('path','sha256','bytes'));relative(row['path']);pin(row['sha256'])
    need(type(row['bytes'])is int and (0 if allow_empty else 1)<=row['bytes']<=limit,'ROOT_BODY_CAP')


def validate_plan(raw,expected,environment):
    pin(expected);need(hashlib.sha256(raw).hexdigest()==expected,'ROOT_PLAN_PIN')
    value=decode(raw);exact(value,PLAN_KEYS)
    need(type(value['schema_version'])is int and value['schema_version']==1 and
        value['purpose']=='project-private-libraries-cli-root-plan' and value['repository']==REPOSITORY and value['ref']==REF,
        'ROOT_PLAN_SCHEMA')
    for key in ('code_commit','source_commit','data_commit'):pin(value[key],40)
    need(len({value[key]for key in ('code_commit','source_commit','data_commit')})==3,'ROOT_DISTINCT_COMMITS')
    descriptor(value['bootstrap'],PLAN_LIMIT);descriptor(value['job'],PLAN_LIMIT)
    descriptor(value['source_rows'],8*1024**2);descriptor(value['peer_receipt'],PLAN_LIMIT)
    need(value['bootstrap']['path']==CLI+'bootstrap.py' and value['job']['path']==CLI+'job.py','ROOT_FIXED_ENTRY_BODIES')
    exact(value['metadata'],INPUT_KEYS)
    for checksum in value['metadata'].values():pin(checksum)
    exact(value['tools'],('git','interpreter','docker','gpgv'))
    for name,row in value['tools'].items():
        exact(row,('path','sha256'));pin(row['sha256'])
        if name=='interpreter':need(re.fullmatch('/usr/bin/python3(?:[.][0-9]+)?',row['path']),'ROOT_INTERPRETER_PATH')
        else:need(row['path']=='/usr/bin/'+name,'ROOT_FIXED_TOOL_PATH')
    need(environment.get('GITHUB_REPOSITORY')==REPOSITORY and environment.get('GITHUB_REF')==REF and
        environment.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and
        environment.get('GITHUB_SHA')==environment.get('GITHUB_WORKFLOW_SHA')==value['source_commit'] and
        environment.get('GITHUB_WORKFLOW_REF')==REPOSITORY+'/'+WORKFLOW+'@'+REF,'ROOT_EXECUTION_IDENTITY')
    for key in ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT'):
        need(type(environment.get(key))is str and re.fullmatch('[1-9][0-9]{0,19}',environment[key]),'ROOT_RUN_IDENTITY')
    return value


def plan_from_environment(environment):
    encoded=environment.pop(PLAN_ENV,None);expected=environment.pop(PIN_ENV,None)
    need(type(encoded)is str and encoded.isascii() and 0<len(encoded)<=4*((PLAN_LIMIT+2)//3),'ROOT_PLAN_BASE64_CAP')
    raw=base64.b64decode(encoded,validate=True)
    need(base64.b64encode(raw).decode('ascii')==encoded,'ROOT_CANONICAL_BASE64')
    return raw,expected


def detach_seeds(environment):
    values={name:environment.pop(name)for name in tuple(environment)if name.startswith('CACHY_OLD_FOUR_')}
    need(set(values)==set((*HEADERS,*SEEDS)),'ROOT_CLOSED_SEED_ENVIRONMENT')
    need(len(SEEDS)==19 and all(type(v)is str and 0<len(v)<=65536 and v.isascii() for v in values.values()),'ROOT_NINETEEN_SEEDS_REQUIRED')
    need(values[HEADERS[0]]=='1' and values[HEADERS[1]]=='1791748800','ROOT_SEED_HEADERS')
    return values


def live(entry):
    need(type(entry)in(int,float)and math.isfinite(entry) and 0<entry<=time.monotonic()<entry+10800,'ROOT_ORIGINAL_DEADLINE')
    return entry+10800-time.monotonic()


def identity(info):
    return [getattr(info,key)for key in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')]


def read_regular(path,limit,entry):
    live(entry);path=Path(path)
    need(path.is_absolute() and '..'not in path.parts and all(not p.is_symlink()for p in(path,*path.parents)),'ROOT_UNALIASED_PATH')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);first=None
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=limit,'ROOT_REGULAR_BODY_CAP')
        chunks=[];count=0
        while True:
            live(entry);block=os.read(fd,min(65536,limit+1-count))
            if not block:break
            chunks.append(block);count+=len(block);need(count<=limit,'ROOT_REGULAR_BODY_CAP')
        need(count==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'ROOT_BODY_CHANGED')
        live(entry);return b''.join(chunks),identity(before)
    except BaseException as error:first=error;raise
    finally:
        try:os.close(fd)
        except BaseException as error:
            if first is None:raise
            first.add_note('ROOT_BODY_CLOSE_UNCERTAIN:'+type(error).__name__)


def observed_tools(plan,entry):
    values={}
    for name,row in plan['tools'].items():
        raw,node=read_regular(row['path'],128*1024**2,entry)
        need(len(raw)>0 and hashlib.sha256(raw).hexdigest()==row['sha256'] and node[4]==0 and stat.S_IMODE(node[2])==0o755,'ROOT_TOOL_BYTES')
        values[name]={**row,'identity':node}
    need(values['interpreter']['path']==str(Path(sys.executable).resolve()),'ROOT_RUNNING_INTERPRETER')
    need(platform.system()=='Linux' and platform.machine()in('aarch64','arm64'),'ROOT_HOSTED_NATIVE_ARM_REQUIRED')
    return values


def git_command(tool,args,root,entry,*,capture=False):
    """Fixed bootstrap delivery commands only; no source-selected command string."""
    live(entry)
    current,_=read_regular(tool['path'],128*1024**2,entry)
    need(hashlib.sha256(current).hexdigest()==tool['sha256'],'ROOT_GIT_TOOL_DRIFT')
    environment={'PATH':'/usr/bin:/bin','HOME':str(root),'TMPDIR':str(root),'LC_ALL':'C',
        'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0'}
    argv=[tool['path'],'-c','core.hooksPath=/dev/null','-c','protocol.file.allow=never','-c','protocol.ext.allow=never',*args]
    remaining=min(entry+10800-120,entry+10080)-time.monotonic()
    need(remaining>0,'ROOT_DELIVERY_WORK_CUTOFF')
    result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,env=environment,cwd=root,timeout=min(120,remaining),check=False)
    need(result.returncode==0,'ROOT_GIT_DELIVERY_FAILED');live(entry)
    if capture:
        need(type(result.stdout)is bytes and len(result.stdout)<=41,'ROOT_GIT_HEAD_CAP');return result.stdout
    return None


def checkout(tool,commit,destination,private_root,entry):
    pin(commit,40);need(not destination.exists(),'ROOT_FRESH_CHECKOUT')
    # No hooks, templates, filters from user configuration, submodule recursion,
    # credentials or arbitrary remote URLs. Keep .git for the original producer.
    git_command(tool,['init','--quiet','--template=',str(destination)],private_root,entry)
    git_command(tool,['-C',str(destination),'remote','add','origin','https://github.com/'+REPOSITORY+'.git'],private_root,entry)
    git_command(tool,['-C',str(destination),'-c','fetch.fsckObjects=true','fetch','--quiet','--depth=1','--no-tags','origin',commit],private_root,entry)
    git_command(tool,['-C',str(destination),'checkout','--quiet','--detach',commit],private_root,entry)
    head=git_command(tool,['-C',str(destination),'rev-parse','--verify','HEAD^{commit}'],private_root,entry,capture=True)
    need(head==(commit+'\n').encode('ascii'),'ROOT_CHECKOUT_HEAD')


def checked_body(root,row,entry,*,allow_empty=False):
    descriptor(row,8*1024**2,allow_empty=allow_empty);raw,node=read_regular(root/row['path'],row['bytes'],entry)
    need(len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'],'ROOT_SELECTED_BODY_PIN')
    return raw,node


def authenticate_sources(plan,source,data,entry):
    raw,_=checked_body(data,plan['source_rows'],entry);rows=decode(raw,8*1024**2)
    exact(rows,('schema_version','purpose','files'))
    need(type(rows['schema_version'])is int and rows['schema_version']==1 and rows['purpose']=='project-private-libraries-cli-source-rows'and
        type(rows['files'])is dict and 12<=len(rows['files'])<=512,'ROOT_SOURCE_ROWS_SCHEMA')
    files=rows['files'];need({CLI+name+'.py'for name in BODIES}|{WORKFLOW}<=set(files),'ROOT_TWELVE_BODIES_AND_WORKFLOW')
    total=0
    for name,row in files.items():
        relative(name);exact(row,('sha256','bytes','mode'));descriptor({'path':name,'sha256':row['sha256'],'bytes':row['bytes']},8*1024**2,allow_empty=True)
        need(type(row['mode'])is int and row['mode']in(0o644,0o755),'ROOT_SOURCE_MODE')
        body,node=checked_body(source,{'path':name,'sha256':row['sha256'],'bytes':row['bytes']},entry,allow_empty=True)
        need(stat.S_IMODE(node[2])==row['mode'],'ROOT_SOURCE_MODE');total+=len(body)
        need(total<=64*1024**2,'ROOT_SOURCE_TOTAL_CAP')
    for key in ('bootstrap','job'):
        expected=plan[key];need(files[expected['path']]['sha256']==expected['sha256'] and files[expected['path']]['bytes']==expected['bytes'],
            'ROOT_CODE_SOURCE_BODY_JOIN')
    need(all(name in files and files[name]['sha256']==plan['metadata'][key]for key,name in INPUT_PATHS.items()),
        'ROOT_METADATA_SOURCE_JOIN')
    peer_raw,_=checked_body(data,plan['peer_receipt'],entry);peer=decode(peer_raw)
    exact(peer,('schema_version','purpose','source_rows_sha256','review_status','native_admission'))
    need(type(peer['schema_version'])is int and peer['schema_version']==1 and
        peer['purpose']=='project-private-libraries-cli-source-peer'and peer['source_rows_sha256']==plan['source_rows']['sha256']and
        peer['review_status']=='REVIEWED_SOURCE_ONLY'and peer['native_admission']is False,'ROOT_SOURCE_PEER_JOIN')
    return rows,peer


def prepare(plan_raw,expected_plan_sha256,*,earliest_entry,environment=None):
    """Return Root job context; all future actor paths are fixed above."""
    environment=os.environ if environment is None else environment
    live(earliest_entry);plan=validate_plan(plan_raw,expected_plan_sha256,environment)
    seeds=detach_seeds(environment)  # Before the first Git child or producer actor.
    tools=observed_tools(plan,earliest_entry)
    temporary=Path(environment.get('RUNNER_TEMP',''))
    need(temporary.is_absolute()and temporary.is_dir()and not temporary.is_symlink(),'ROOT_RUNNER_TEMP')
    private=temporary/('cachy-private-libraries-cli-'+environment['GITHUB_RUN_ID']+'-'+environment['GITHUB_RUN_ATTEMPT'])
    need(not private.exists()and not private.is_symlink(),'ROOT_FRESH_PRIVATE_JOB')
    private.mkdir(mode=0o700);need(stat.S_IMODE(private.stat().st_mode)==0o700,'ROOT_PRIVATE_JOB_MODE')
    source,data=private/'source',private/'data'
    checkout(tools['git'],plan['source_commit'],source,private,earliest_entry)
    checkout(tools['git'],plan['data_commit'],data,private,earliest_entry)
    rows,peer=authenticate_sources(plan,source,data,earliest_entry)
    live(earliest_entry)
    return {'plan':plan,'plan_sha256':hashlib.sha256(plan_raw).hexdigest(),'environment':dict(environment),'earliest_entry':earliest_entry,'source_root':source,
        'data_root':data,'private_root':private,'source_rows':rows,'peer_receipt':peer,'seed_environment':seeds,'tools':tools}


def main(plan_raw,expected_plan_sha256,*,earliest_entry):
    context=prepare(plan_raw,expected_plan_sha256,earliest_entry=earliest_entry)
    body=context['source_root']/CLI/'job.py'
    # The literal manifest and external Root plan authenticated this fixed body.
    spec=importlib.util.spec_from_file_location('project_private_libraries_cli_job',body)
    module=importlib.util.module_from_spec(spec);module.__cached__=None;sys.modules[spec.name]=module
    # -B does not forbid reading a preexisting cache in the full Git checkout.
    # Retain ordinary spec metadata, but execute only the authenticated bytes.
    raw,_=checked_body(context['source_root'],context['plan']['job'],earliest_entry)
    exec(compile(raw,str(body),'exec'),module.__dict__)
    live(earliest_entry);return module.run(context)
