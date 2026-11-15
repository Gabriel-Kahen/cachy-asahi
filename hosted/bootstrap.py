# SPDX-License-Identifier: MIT
"""Future one-image signed349 bootstrap using held leaves; import runs no role."""
from contextlib import contextmanager
import hashlib
import importlib.util
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
ORIGINAL_MAP='0c37bef7218caa6cb0f0e6d1b22ed5053b10a228f53e15076f5803d2fcf86b3e'
EXPECTED349='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'
DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']
LABEL='cachy-asahi.hosted-llvm23'
_ACTIVE=False


def need(value,why):
    if not value:raise ValueError(why)


def tick(deadline):
    need(type(deadline) in (int,float) and math.isfinite(deadline) and time.monotonic()<deadline,
         'finite original bootstrap deadline exhausted')


@contextmanager
def seed_commands(pgo,command):
    """Inject cancellation only after the held wrapper selects its blob bound."""
    primitive=pgo.owned_child();previous_primitive=primitive.run;previous_run=subprocess.run
    def checked(argv,**kwargs):
        need(not command.cancelled[0],'Root cancellation before retained DATA child')
        prior_tick=kwargs.get('on_tick')
        def on_tick():
            if prior_tick is not None:prior_tick()
            need(not command.cancelled[0],'Root cancellation after retained child ownership witness')
        return previous_primitive(argv,**dict(kwargs,on_tick=on_tick))
    try:
        primitive.run=checked;subprocess.run=pgo.owned_subprocess_run
        yield
    finally:primitive.run=previous_primitive;subprocess.run=previous_run


def image_owner(binding):
    need(type(binding['source']) is str and re.fullmatch('[0-9a-f]{40}',binding['source']) and
         type(binding['ref']) is str and binding['ref'] and type(binding['run']) is str and
         re.fullmatch('[1-9][0-9]{0,19}',binding['run']),'actual Source/ref/run image owner')
    token=hashlib.sha256((binding['source']+':'+binding['ref']+':'+binding['run']).encode()).hexdigest()[:24]
    return dict(token=token,tag='llvm23-native-base:'+token,source=binding['source'])


def combined_inputs(original,profile,expected):
    """Pure union; original signed rootfs/keyring policy is not rewritten."""
    additions=profile['additions']['rows'];packages=original['packages']
    need(len(packages)==248 and len(additions)==8,'exact original248 plus fixed8 package rows')
    combined=dict(original,packages=[*packages,*additions])
    names=[row['name'] for row in combined['packages']]
    files=[row['filename'] for row in combined['packages']]
    need(len(set(names))==256 and len(set(files))==256,'disjoint package names/archive leaves')
    versions={row['name'][0]:row['version'][0] for row in original['rootfs_packages']}
    versions.update({row['name']:row['version'] for row in combined['packages']})
    lock=''.join(name+' '+version+'\n' for name,version in sorted(versions.items())).encode()
    need(len(versions)==349 and lock==expected and hashlib.sha256(lock).hexdigest()==EXPECTED349,
         'complete exact349 inventory derivation')
    return combined


def cache_only(row,cache,deadline,checked_leaf):
    tick(deadline);path=checked_leaf(cache,row);tick(deadline);return path


@contextmanager
def held_modules(root,common):
    """Scope original absolute-import names and restore every overwritten alias."""
    need(threading.current_thread() is threading.main_thread(),'bootstrap imports require main thread')
    original=root/'original';before_path=sys.path.copy();before_modules=sys.modules.copy()
    try:
        for name in ('common','package_checks','legacy_prefill'):sys.modules.pop(name,None)
        old=common.load('_perl_bootstrap_original_common',original/'native/common.py')
        old.verify_source(original,ORIGINAL_MAP)
        sys.modules['common']=old
        sys.path[:0]=[str(original/'native'),str(original/'bootstrap/scripts/ci/setup6-retained-helpers')]
        yield SimpleNamespace(common=old,
            native=common.load('_perl_bootstrap_original_native',original/'bootstrap/scripts/ci/native_arm.py'),
            seed=common.load('_perl_bootstrap_retained_prepare',original/'bootstrap/scripts/ci/setup6-retained-helpers/prepare.py'),
            provision=common.load('_perl_bootstrap_provision',original/'native/provision.py'),
            cache=common.load('_perl_bootstrap_cache_leaf',original/'native/owner.py'),
            fetch=common.load('_perl_bootstrap_fetch',original/'native/bootstrap_inputs.py'),
            pgo=common.load('_perl_bootstrap_git_supervision',original/'bootstrap/scripts/ci/zlib-pgo-native-hosted/owner.py'))
    finally:
        sys.path[:]=before_path
        for name,module in list(sys.modules.items()):
            file=getattr(module,'__file__',None)
            if name.startswith('_perl_bootstrap_') or file and Path(file).is_relative_to(original):
                if name in before_modules:sys.modules[name]=before_modules[name]
                else:sys.modules.pop(name,None)
        for name in ('common','package_checks','legacy_prefill'):
            if name in before_modules:sys.modules[name]=before_modules[name]
            else:sys.modules.pop(name,None)


def seed_additions(profile,carrier,cache,out,deadline,provision,common):
    """Reuse checked_file and atomic no-replace publication for sixteen DATA leaves."""
    before=provision.cache_inventory(cache,deadline);rows=[]
    for row in profile['additions']['rows']:
        rows.extend((row,dict(filename=row['filename']+'.sig',size=row['signature_size'],sha256=row['signature_sha256'])))
    need(len(rows)==16 and len({row['filename'] for row in rows})==16,'exact fixed8 archive/signature pairs')
    report=dict(status='FAIL_FIXED_EIGHT_CACHE',files={},prior_cache_metadata=before)
    target=out/'fixed-eight-cache.json';target.write_bytes(common.encode(report))
    try:
        for row in rows:
            tick(deadline);name=row['filename']
            need(type(name) is str and re.fullmatch('[A-Za-z0-9._+@:~-]{1,255}',name) and name not in ('.','..'),'literal retained package filename')
            source=carrier/'packages'/name;destination=cache/name
            if os.path.lexists(destination):
                provision.checked_file(source,row,deadline)
                result=provision.checked_file(destination,row,deadline)
                state='EXACT_EXISTING_FILE_PRESERVED'
            else:
                fd,temporary=tempfile.mkstemp(prefix='.perl-fixed8-',suffix='.partial',dir=cache);partial=Path(temporary)
                try:
                    with os.fdopen(fd,'wb') as stream:
                        result=provision.checked_file(source,row,deadline,stream)
                        stream.flush();os.fsync(stream.fileno())
                    need(provision.checked_file(partial,row,deadline)==result,'copied exact retained DATA differs')
                    os.link(partial,destination)
                finally:partial.unlink(missing_ok=True)
                state='EXACT_DATA_ATOMIC_NO_REPLACE_COPY'
            report['files'][name]=dict(status=state,**result);target.write_bytes(common.encode(report))
        after=provision.cache_inventory(cache,deadline)
        need(all(after.get(name)==value for name,value in before.items()) and
             set(after)==set(before)|{row['filename'] for row in rows},'prior cache inode metadata must remain unchanged')
        report['status']='PASS_FIXED_EIGHT_CACHE_DATA_ONLY';report['after_cache_metadata']=after
        return report
    finally:target.write_bytes(common.encode(report))


def _docker_argv(argv,owner):
    command=list(map(str,argv))
    if command[0]=='docker':command=DOCKER+command[1:]
    if command[:len(DOCKER)+1]==DOCKER+['build']:
        command[len(DOCKER)+1:len(DOCKER)+1]=['--no-cache','--tag',owner['tag'],
            '--label',LABEL+'='+owner['token'],'--label',LABEL+'.source='+owner['source']]
    if command[:len(DOCKER)+1]==DOCKER+['run']:
        need(command[3:]==['--rm','--pull=never','--network=none','--cap-drop=ALL',
             '--security-opt=no-new-privileges','--read-only','--entrypoint=/bin/cat',command[-2],'/builder-packages.lock'] and
             re.fullmatch('sha256:[0-9a-f]{64}',command[-2]),'only fixed held inventory metadata run allowed')
        command[3:3]=['--name','llvm23-bootstrap-inventory-'+owner['token'],
            '--label',LABEL+'='+owner['token'],'--label',LABEL+'.source='+owner['source'],
            '--cpus=1','--memory=128m','--memory-swap=128m','--pids-limit=32']
    return command


def bootstrap_directory(work):
    out=work/'bootstrap'
    if not os.path.lexists(out):out.mkdir(mode=0o700)
    info=out.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode) in (0o700,0o755),
         'ordinary owned private bootstrap evidence directory')
    need({path.name for path in out.iterdir()}<={'operations','operations.json'},'fresh bootstrap except caller-owned operation receipts')
    for path in out.iterdir():
        info=path.lstat()
        need(info.st_uid==os.getuid() and not stat.S_IMODE(info.st_mode)&0o022,'owned protected existing operation evidence')
        if path.name=='operations.json':
            need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=2*1024**2,'ordinary bounded operation index')
        else:
            need(stat.S_ISDIR(info.st_mode),'ordinary operation directory')
            count=0
            for leaf in path.iterdir():
                count+=1;info=leaf.lstat()
                need(count<=1200 and re.fullmatch('[0-9]{3}\\.(stdout|stderr)',leaf.name) and
                     stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and
                     not stat.S_IMODE(info.st_mode)&0o022 and info.st_size<=16*1024**2,'bounded caller-owned raw operation stream')
    return out


@contextmanager
def native_commands(native,command,deadline,owner):
    """GPG and native CLI use the caller's actual owned CompletedProcess callback."""
    global _ACTIVE
    need(threading.current_thread() is threading.main_thread() and not _ACTIVE,'exclusive main-thread bootstrap command scope')
    tick(deadline);_ACTIVE=True;previous=(native.run,subprocess.run);builds=[]
    def invoke(argv,log=None,timeout=60,**kwargs):
        need(threading.current_thread() is threading.main_thread(),'actor callback from unexpected worker thread')
        tick(deadline)
        need(type(timeout) in (int,float) and math.isfinite(timeout) and timeout>0,'finite requested command timeout')
        timeout=min(timeout,3600,deadline-time.monotonic());need(timeout>0,'remaining command deadline')
        argv=_docker_argv(argv,owner)
        if argv[:3]==DOCKER+['build']:
            need(not builds,'exactly one original signed349 image build');builds.append(argv)
        result=command(argv,log=log,timeout=timeout,**kwargs)
        need(type(result.returncode) is int,'actual CompletedProcess exit required');tick(deadline)
        return result
    def native_run(argv,log=None,timeout=1800):
        result=invoke(argv,log=log,timeout=timeout,capture_output=log is None,text=True,check=False)
        need(result.returncode==0,'held native command failed: '+str(result.returncode))
        if log is None:
            need(type(result.stdout) is str,'held native capture requires text stdout')
            return result.stdout.strip()
    native.run=native_run;subprocess.run=invoke
    try:yield invoke,builds
    finally:
        native.run,subprocess.run=previous;_ACTIVE=False


def run(root,work,binding,deadline,command):
    """Future role only. Root owns admission, input transport and final image cleanup."""
    need(threading.current_thread() is threading.main_thread(),'bootstrap caller must be main thread')
    tick(deadline);root=Path(root);work=Path(work)
    spec=importlib.util.spec_from_file_location('_perl_hosted_bootstrap_common',HERE/'common.py')
    common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
    common.verify_source(root,binding['source_map_sha256'])
    temp=Path(os.environ['RUNNER_TEMP'])
    need(root.is_absolute() and root==root.resolve() and HERE==root/'hosted' and work==temp/'llvm23-hosted' and
         work.is_dir() and work.stat().st_uid==os.getuid() and stat.S_IMODE(work.stat().st_mode)==0o700 and
         os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1001,'owned fixed hosted bootstrap paths/user')
    cache=temp/'alarm-cache';carrier=temp/'pgo-hosted-retained';out=work/'bootstrap'
    need(not any(path.is_symlink() for node in (root,work,cache,carrier) for path in (node,*node.parents)), 'ordinary source/work/cache/carrier ancestry')
    need(cache.is_dir() and cache.stat().st_uid==1001 and stat.S_IMODE(cache.stat().st_mode)==0o700 and
         carrier.is_dir() and (carrier/'.git').is_dir() and not (carrier/'.git').is_symlink(), 'existing private cache and exact delivered carrier required')
    out=bootstrap_directory(work);owner=image_owner(binding)
    with held_modules(root,common) as held:
        profile,original,expected=held.common.input_contract(root/'original')
        combined=combined_inputs(original,profile,expected)
        (out/'inputs.lock.json').write_bytes(common.encode(combined))
        with seed_commands(held.pgo,command):
            receipt=held.seed.prepare(carrier,cache,'native248',root/'original/bootstrap/scripts/ci/inputs.lock.json',
                                      min(deadline,time.monotonic()+2250),carrier/'.git')
        need(not command.cancelled[0],'Root cancellation after retained DATA preparation')
        tick(deadline);(out/'input-data-preparation.json').write_bytes(common.encode(receipt))
        seed_additions(profile,carrier,cache,out,deadline,held.provision,common)
        previous_fetch=held.native.fetch
        def cache_fetch(row,selected):
            return cache_only(row,selected,deadline,held.cache.cache_file)
        held.native.fetch=held.fetch.bind_fetch(original,profile['additions']['rows'],cache,cache_fetch,previous_fetch)
        try:
            with native_commands(held.native,command,deadline,owner) as (invoke,builds):
                need(held.native.audit(combined,cache,out)==256,'complete original256 signed package audit required')
                for selected in ('reference='+owner['tag'],'label='+LABEL+'='+owner['token']):
                    result=invoke(DOCKER+['image','ls','--no-trunc','-q','--filter',selected],capture_output=True,text=True,check=False)
                    need(result.returncode==0 and result.stdout in ('',b'') and result.stderr in ('',b''),'fresh owned bootstrap image namespace required')
                image=held.native.build(combined,cache,out,{})
                need(len(builds)==1 and type(image) is str and re.fullmatch('sha256:[0-9a-f]{64}',image),'one actual immutable signed349 image required')
                result=invoke(DOCKER+['image','inspect',image],capture_output=True,text=True,check=False)
                need(result.returncode==0,'actual immutable image inspection required')
                rows=common.decode(result.stdout.encode() if type(result.stdout) is str else result.stdout)
                need(type(rows) is list and len(rows)==1,'one actual image inspection')
                actual=rows[0];labels=actual['Config']['Labels']
                need(actual['Id']==image and actual['Architecture']=='arm64' and actual['Os']=='linux' and
                     labels.get(LABEL)==owner['token'] and labels.get(LABEL+'.source')==binding['source'] and
                     owner['tag'] in actual.get('RepoTags',[]),'exact Root-owned native image labels/tag')
                (out/'image-inspect.json').write_bytes(common.encode(actual))
                need(common.read(out/'packages.lock',1024**2)==expected,'actual complete349 installed inventory required')
        finally:held.native.fetch=previous_fetch
    result=dict(image=image,tag=owner['tag'],token=owner['token'],inventory='llvm23-bootstrap-inventory-'+owner['token'],expected349_sha256=EXPECTED349)
    for name,key in [('inputs.lock.json','inputs_sha256'),('acquisition.json','acquisition_sha256'),
                     ('signatures.json','signatures_sha256'),('image-inspect.json','image_inspect_sha256'),
                     ('input-data-preparation.json','preparation_sha256'),('fixed-eight-cache.json','cache_additions_sha256')]:
        result[key]=common.pin(common.read(out/name,8*1024**2))['sha256']
    (out/'proof.json').write_bytes(common.encode(dict(status='PASS_FRESH_SIGNED349_BOOTSTRAP',binding=binding,**result)))
    return result
