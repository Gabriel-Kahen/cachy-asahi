# SPDX-License-Identifier: MIT
"""Bind the complete workflow capsule; source metadata grants no native acceptance."""
import argparse,hashlib,json,os,platform,re,stat,subprocess,sys
from pathlib import Path
BINDINGS={'apps16_archive': {'bytes': 29664, 'sha256': '319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af'}, 'apps16_pair_source': '950b0699a6e3f7a56758d4d17a5d30dabc7b6e11', 'caps': {'backend_seconds': 600, 'caller_seconds': 610, 'cleanup_seconds': 650, 'interruption_seconds': 600, 'job_minutes': 142, 'lifecycle_seconds': 4320, 'owner_seconds': 4870, 'producer_seconds': 2300, 'public_bytes': 201326592, 'reap_seconds': 5}, 'frozen574_source': 'ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad', 'operation': 'recover-apps16-reinstall', 'operation_profile_sha256': '2adc59b48dc461ea801ad6d163c19811e38ec9d8b7f3da587507d9f28906b13f', 'packet_index': {'bytes': 82492, 'path': 'index.json', 'sha256': '6995af00a982ec4545dff26bcb26f25f1868a8267d46031aa060ed0575443fb5'}, 'packet_source': '54352850a57a7e34e75c3a021fa20525eee59bf6', 'retained_public_source': '04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd', 'source_input': 'c14a8362e2cf9cda84c0b5c1a181658a8c9111a6'}
WORKFLOWS=('.github/workflows/native-arm-apps16-reinstall-interruption.yml','.github/workflows/native-arm-build.yml')
CAP=192*1024**2

def need(ok,why):
    if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def decode(raw):
    def pairs(rows):
        out={}
        for k,v in rows:need(k not in out,'duplicate capsule key');out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite capsule JSON'))
def canonical(value):
    raw=os.fspath(value);need(os.path.isabs(raw)and raw==os.path.normpath(raw)and not raw.startswith('//'),'absolute normalized capsule path')
    p=Path(raw);need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary capsule ancestry');return p
def identity(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(path,cap=16*1024**2):
    path=canonical(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded singlelink capsule input');parts=[];size=0
        while chunk:=os.read(fd,65536):parts.append(chunk);size+=len(chunk);need(size<=a.st_size,'capsule input grew')
        need(size==a.st_size and identity(a)==identity(os.fstat(fd))==identity(path.lstat()),'capsule FD/path changed');return b''.join(parts)
    finally:os.close(fd)
def tree(root,cap=16*1024**2):
    root=canonical(root);need(root.is_dir(),'capsule directory');out={};dirs=set()
    for path in sorted(root.rglob('*')):
        s=path.lstat();name=path.relative_to(root).as_posix()
        if stat.S_ISDIR(s.st_mode):need(not path.is_symlink(),'directory alias');dirs.add(name)
        else:out[name]=pin(read(path,cap))
    need(dirs=={q.as_posix()for name in out for q in Path(name).parents if str(q)!='.'},'closed capsule namespace');return out

def verify(root,capsule_sha,operation_profile_sha,source_sha,operation):
    root=canonical(root)
    need(operation==BINDINGS['operation']and operation_profile_sha==BINDINGS['operation_profile_sha256'],'one independently pinned operation')
    need(type(source_sha)is str and re.fullmatch('[a-f0-9]{40}',source_sha),'exact future published source SHA')
    need(type(capsule_sha)is str and re.fullmatch('[a-f0-9]{64}',capsule_sha),'explicit independent capsule SHA256')
    raw=read(root/'capsule.json');need(pin(raw)['sha256']==capsule_sha,'capsule manifest hash')
    value=decode(raw);need(value['schema_version']==1 and value['status']=='SOURCE_ONLY_NATIVE_ARM_OPERATION_CAPSULE'and value['bindings']==BINDINGS and value['actual']is None and value['Root_acceptance']is None,'source-only exact native capsule')
    op_raw=read(root/'operation/profile.json');need(pin(op_raw)['sha256']==operation_profile_sha,'immutable original operation profile')
    op=decode(op_raw);source=tree(root/'repair-source');owned=tree(root/'operation')
    need(len(source)==245 and source==op['source_files'],'complete unchanged c14/public245')
    need(owned==dict(op['operation_files'],**{'profile.json':pin(op_raw)})and len(owned)==10,'complete separately pinned recovery operation10')
    expected={'repair-source/'+n:w for n,w in source.items()}|{'operation/'+n:w for n,w in owned.items()}
    need(set(value['files'])==set(expected)|set(WORKFLOWS)|{'workflow-support/bootstrap.py'},'exact complete recovery capsule258 nonself members')
    for name,w in value['files'].items():need(pin(read(root/name))==w,'capsule member drift: '+name)
    need(all(value['files'][n]==w for n,w in expected.items()),'capsule map joins source and independently pinned operation')
    need(read(root/WORKFLOWS[0])==read(root/WORKFLOWS[1]),'registered alias exact workflow bytes')
    return value

def write(path,raw,mode):
    path=canonical(path);need(path.parent.is_dir()and not os.path.lexists(path),'fresh capsule receipt')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
    with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno());os.fchmod(stream.fileno(),mode)

def activate(root,capsule_sha,operation_profile_sha,source_sha,operation,receipt):
    value=verify(root,capsule_sha,operation_profile_sha,source_sha,operation);env=os.environ
    receipt=canonical(receipt);need(not receipt.is_relative_to(canonical(root)),'activation receipt outside source capsule')
    need(canonical(root)==canonical(env['GITHUB_WORKSPACE'])and env['GITHUB_REPOSITORY']=='Gabriel-Kahen/cachy-asahi'and env['GITHUB_EVENT_NAME']=='workflow_dispatch','explicit repository/workflow activation')
    need(env['GITHUB_SHA']==env['GITHUB_WORKFLOW_SHA']==source_sha and env['RUNNER_ARCH']=='ARM64'and env['RUNNER_OS']=='Linux'and platform.machine()=='aarch64'and platform.system()=='Linux'and os.getuid()==os.geteuid()>0,'genuine ordinary native ARM source/workflow environment')
    path=env['GITHUB_WORKFLOW_REF'].split('@',1)[0].removeprefix('Gabriel-Kahen/cachy-asahi/')
    need(path in WORKFLOWS,'one declared native workflow/registered alias')
    result=subprocess.run(['/usr/bin/git','-C',str(root),'rev-parse','HEAD'],text=True,capture_output=True,timeout=10)
    need(result.returncode==0 and result.stdout.strip()==source_sha and not result.stderr,'actual capsule checkout/source identity')
    run,attempt=env['GITHUB_RUN_ID'],env['GITHUB_RUN_ATTEMPT'];need(re.fullmatch('[1-9][0-9]{0,19}',run)and re.fullmatch('[1-9][0-9]{0,19}',attempt),'actual run identity')
    row=dict(status='SOURCE_CAPSULE_ACTIVATION_ONLY_NOT_NATIVE_ACCEPTANCE',operation=operation,capsule_sha256=capsule_sha,operation_profile_sha256=operation_profile_sha,source_input=BINDINGS['source_input'],identity=dict(source=source_sha,run=int(run),attempt=int(attempt)),workflow_path=path,bindings=value['bindings'],native_acceptance=False,Root_acceptance=None)
    write(receipt,enc(row),0o600);return row

def retain(root,capsule_sha,operation_profile_sha,source_sha,operation,receipt,public,cache_receipt=None):
    verify(root,capsule_sha,operation_profile_sha,source_sha,operation)
    receipt=canonical(receipt);held=receipt.lstat();need(held.st_uid==os.getuid()and stat.S_IMODE(held.st_mode)==0o600,'owned private original activation receipt')
    raw=read(receipt);row=decode(raw);env=os.environ
    need(row['status']=='SOURCE_CAPSULE_ACTIVATION_ONLY_NOT_NATIVE_ACCEPTANCE'and row['operation']==operation and row['capsule_sha256']==capsule_sha and row['operation_profile_sha256']==operation_profile_sha and row['native_acceptance']is False and row['Root_acceptance']is None,'original activation source binding')
    need(row['identity']==dict(source=source_sha,run=int(env['GITHUB_RUN_ID']),attempt=int(env['GITHUB_RUN_ATTEMPT'])),'same original run/attempt activation')
    public=canonical(public);need(not public.is_relative_to(canonical(root))and not canonical(root).is_relative_to(public),'public evidence disjoint from source capsule')
    before=tree(public,64*1024**2);old=read(public/'retention.json');need(pin(old)==before['retention.json'],'original retention bytes')
    extras={'operation-capsule-activation.json':raw}
    if cache_receipt is not None and os.path.lexists(cache_receipt):extras['producer-retained-cache.json']=read(cache_receipt)
    need(not any(os.path.lexists(public/name)for name in(*extras,'operation-capsule-retention.json')),'fresh capsule evidence roles')
    files=dict(before,**{n:pin(b)for n,b in extras.items()});proof=dict(status='DATA_ONLY_CAPSULE_BINDING_ORIGINAL_RETENTION_UNCHANGED',identity=row['identity'],operation=operation,capsule_sha256=capsule_sha,operation_profile_sha256=operation_profile_sha,original_retention=pin(old),original_status=decode(old).get('status'),files=files,native_acceptance=False,Root_acceptance=None)
    proof_raw=enc(proof);need(sum(p['bytes']for p in files.values())+len(proof_raw)<=CAP,'unchanged complete192MiB public evidence cap')
    need(tree(public,64*1024**2)==before and read(receipt)==raw,'late original retention/activation drift')
    for name,data in extras.items():write(public/name,data,0o644)
    write(public/'operation-capsule-retention.json',proof_raw,0o644)
    need(read(public/'retention.json')==old,'original retention never rewritten');return proof

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('verify','activate','retain'))
    for name in('root','capsule-sha256','operation-profile-sha256','source-sha','operation'):p.add_argument('--'+name,required=True)
    for name in('receipt','public','cache-receipt'):p.add_argument('--'+name,type=Path)
    a=p.parse_args();args=(Path(a.root),a.capsule_sha256,a.operation_profile_sha256,a.source_sha,a.operation)
    if a.mode=='verify':value=verify(*args);result=dict(status='SOURCE_ONLY_COMPLETE_CAPSULE_VERIFIED',files=len(value['files'])+1,actual=None)
    elif a.mode=='activate':need(a.receipt is not None,'activation receipt required');result=activate(*args,a.receipt)
    else:need(a.receipt is not None and a.public is not None,'original activation and public evidence required');result=retain(*args,a.receipt,a.public,a.cache_receipt)
    print(enc({k:v for k,v in result.items()if k!='files'}).decode(),end='')

if __name__=='__main__':main()
