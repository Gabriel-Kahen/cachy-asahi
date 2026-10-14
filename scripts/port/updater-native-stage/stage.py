#!/usr/bin/env python3
"""One finite private updater trial; public output contains guarded JSON only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import sys
import tempfile
import time
import types

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PACKAGE = 'packages/tools/cachy-asahi-update/'
READY_SHA = '56c55879b340ddb85b2deafc0eb2465a77450edb8ac2fcda96592c13322c23d4'
BUDGET = {'total_seconds':6900, 'raw_retention_seconds':7100, 'materialize_seconds':910,
          'freeze_seconds':120, 'native_seconds':5400, 'projection_seconds':60,
          'export_seconds':60, 'cleanup_seconds':180, 'private_bytes':8*1024**3,
          'private_members':200000, 'source_bytes':32*1024**2,
          'minimum_output_free_bytes':10*1024**3, 'minimum_docker_free_bytes':10*1024**3,
          'shared_growth_bytes':16*1024**3, 'filesystem_growth_bytes':8*1024**3,
          'remaining_reserve_bytes':2*1024**3}
ENDPOINT = 'unix:///run/docker.sock'


def need(value, code):
    if not value: raise ValueError(code)


def digest(data): return hashlib.sha256(data).hexdigest()


def regular(path, limit=4*1024**2):
    path=Path(path)
    need(not any(p.is_symlink() for p in (path,*path.parents)), 'symlink-input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=limit, 'bounded-input')
        with os.fdopen(fd,'rb',closefd=False) as stream: data=stream.read(limit+1)
        after=os.fstat(fd)
        need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
             and len(data)==before.st_size, 'input-race')
        return data
    finally: os.close(fd)


def unique(rows):
    value={}
    for k,v in rows:
        need(k not in value,'duplicate-key');value[k]=v
    return value


def load(path): return json.loads(regular(path),object_pairs_hook=unique)


def save(path,value):
    fd,name=tempfile.mkstemp(prefix='.receipt-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(value,stream,sort_keys=True,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally: Path(name).unlink(missing_ok=True)


def module(path, expected=None):
    """Execute verified source bytes directly; never consume .pyc caches."""
    raw=regular(path,32*1024**2)
    if expected: need(digest(raw)==expected,'module-pin')
    name='updater_stage_'+path.stem.replace('-','_')
    result=types.ModuleType(name);result.__file__=str(path);sys.modules[name]=result
    exec(compile(raw,str(path),'exec'),result.__dict__)
    return result


def ordinary():
    need(os.getuid()==os.geteuid()>0 and os.getgid()==os.getegid()>0,'ordinary-user-required')


def host():
    ordinary();need(platform.system()=='Linux' and platform.machine() in ('aarch64','arm64'),'native-host-required')
    with Path('/proc/sys/kernel/random/boot_id').open('rb') as stream:raw=stream.read(129)
    need(len(raw)<=128,'host-boot-id-bound');boot=raw.decode().strip()
    need(re.fullmatch('[0-9a-f-]{36}',boot),'host-boot-id')
    sock=Path('/run/docker.sock').lstat();need(stat.S_ISSOCK(sock.st_mode),'local-daemon-socket')
    return {'system':'Linux','machine':platform.machine(),'release':platform.release(),
            'boot_id_sha256':digest(boot.encode()),'uid':os.getuid(),'gid':os.getgid(),
            'docker_socket_identity':{'device':sock.st_dev,'inode':sock.st_ino}}


def tools():
    result={}
    for name in ('python','docker','git','gpg','gpgconf'):
        raw=sys.executable if name=='python' else shutil.which(name,path='/usr/bin:/bin')
        need(raw,'host-tool-missing');path=Path(raw).resolve(strict=True)
        result[name]={'path':str(path),'sha256':digest(regular(path,256*1024**2))}
    return result


def tool_check(value):
    need(type(value) is dict and set(value)=={'python','docker','git','gpg','gpgconf'},'host-tool-set')
    for row in value.values():
        need(type(row) is dict and set(row)=={'path','sha256'} and Path(row['path']).is_absolute(), 'host-tool-record')
        need(digest(regular(Path(row['path']),256*1024**2))==row['sha256'],'host-tool-drift')


def stage_files(root):
    prefix='scripts/port/updater-native-stage/'
    return sorted(p.relative_to(root).as_posix() for p in (root/prefix).rglob('*')
                  if p.is_file() and '__pycache__' not in p.parts and p.name not in ('stage.lock.json','source.lock.json'))


def freeze(root,commit,ready,output,bootstrap_source_sha=None,bootstrap_stage_sha=None):
    """Data-only freeze on the selected native host after the sources are committed."""
    need(ready==READY_SHA,'reviewed-checkpoint-required')
    need(re.fullmatch('[0-9a-f]{64}',bootstrap_stage_sha or '') and
         digest(regular(HERE/'stage.py'))==bootstrap_stage_sha,'bootstrap-stage-pin')
    need(re.fullmatch('[0-9a-f]{64}',bootstrap_source_sha or ''),'bootstrap-source-pin')
    source=module(HERE/'source.py',bootstrap_source_sha)
    contract={'schema_version':1,'scope':'finite private native updater trial','budget':BUDGET,
              'host':host(),'docker_endpoint':ENDPOINT,'tools':tools(),
              'source':source.collect(root,commit,stage_files(root),ready)}
    need(output.is_absolute() and output.is_relative_to('/tmp') and not output.exists()
         and output.parent.resolve(strict=True)==output.parent,'fresh-controller-path')
    save(output,contract)
    return digest(regular(output))


def authenticate(root,controller,expected):
    raw=regular(controller)
    need(re.fullmatch('[0-9a-f]{64}',expected or '') and digest(raw)==expected,'controller-pin')
    value=json.loads(raw,object_pairs_hook=unique)
    need(type(value) is dict and set(value)=={'schema_version','scope','budget','host','docker_endpoint','tools','source'}
         and value['schema_version']==1 and value['budget']==BUDGET and value['docker_endpoint']==ENDPOINT
         and value['source']['ready_sha256']==READY_SHA,'controller-schema')
    need(value['host']==host(),'host-binding');tool_check(value['tools'])
    rows=value['source']['files'];prefix='scripts/port/updater-native-stage/'
    need(digest(regular(HERE/'stage.py'))==rows[prefix+'stage.py']['sha256'],'controller-self-pin')
    source=module(HERE/'source.py',rows[prefix+'source.py']['sha256'])
    source.verify(root,value['source'])
    return value,source


def snapshot(root,target,contract):
    target.mkdir(mode=0o700)
    for name,row in contract['files'].items():
        data=regular(root/name,32*1024**2);need(digest(data)==row['sha256'],'source-copy-drift')
        dest=target/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data);dest.chmod(row['file_mode'])
    verify_snapshot(target,contract)


def verify_snapshot(target,contract):
    found=set()
    for p in target.rglob('*'):
        need(not p.is_symlink(),'snapshot-link')
        if p.is_dir(): continue
        name=p.relative_to(target).as_posix();need(name in contract['files'],'snapshot-extra')
        row=contract['files'][name];data=regular(p,32*1024**2)
        need(digest(data)==row['sha256'] and stat.S_IMODE(p.stat().st_mode)==row['file_mode'],'snapshot-byte-mode')
        found.add(name)
    need(found==set(contract['files']),'snapshot-missing')


GPG_SOCKETS=frozenset({'S.gpg-agent','S.gpg-agent.browser','S.gpg-agent.extra',
                       'S.gpg-agent.ssh','S.dirmngr','S.keyboxd'})
_DIRECTORY_LEAF_ISSUER=object()
DIRECTORY_LEAF_FIELDS=frozenset({'availability','check','scope','component'})
DIRECTORY_LEAF_COMBINATIONS=frozenset(
    [('OPEN_FD_IDENTITY',scope,component) for scope in ('ROOT','DESCENDANT')
     for component in ('DEVICE','INODE','MODE')] +
    [('ROOT_PATH_MISSING','ROOT','NONE'),('LINKED_CHILD_PATH_MISSING','DESCENDANT','NONE')] +
    [('PATH_IDENTITY',scope,component) for scope in ('ROOT','DESCENDANT')
     for component in ('DEVICE','INODE','OWNER','MODE')] +
    [('PATH_NOT_DIRECTORY',scope,'TYPE') for scope in ('ROOT','DESCENDANT')] +
    [('CHILD_OPEN_REAPPEARED','DESCENDANT','NONE')])


def directory_leaf_unknown():
    return {'availability':'NOT_OBSERVED','check':'UNKNOWN','scope':'UNKNOWN','component':'UNKNOWN'}


def directory_leaf_projection(row):
    """One closed pathless group; it never participates in acceptance."""
    need(type(row) is dict and set(row)==DIRECTORY_LEAF_FIELDS and
         all(type(value) is str for value in row.values()),'directory-leaf-fields')
    if row['availability']=='NOT_OBSERVED':
        need(row==directory_leaf_unknown(),'directory-leaf-unknown')
    else:
        need(row['availability']=='OBSERVED' and (row['check'],row['scope'],row['component'])
             in DIRECTORY_LEAF_COMBINATIONS,'directory-leaf-enum')
    need(len(json.dumps(row,sort_keys=True,separators=(',',':')).encode())<=256,'directory-leaf-bound')
    return dict(row)


def _directory_leaf_issued(error):
    """Read only the source-issued plain capsule, never exception properties/text."""
    try:
        if type(error) is not ValueError:return None
        values=object.__getattribute__(error,'__dict__')
        if type(values) is not dict:return None
        issued=dict.get(values,'_directory_leaf_issued')
        if type(issued) is not tuple or len(issued)!=4 or type(_DIRECTORY_LEAF_ISSUER) is not object or \
           issued[0] is not _DIRECTORY_LEAF_ISSUER or not all(type(v) is str for v in issued[1:]):return None
        directory_leaf_projection({'availability':'OBSERVED','check':issued[1],
                                   'scope':issued[2],'component':issued[3]})
        return issued
    except BaseException:return None


def _directory_leaf_fact(issued):
    if type(issued) is tuple and len(issued)==4 and type(_DIRECTORY_LEAF_ISSUER) is object and \
       issued[0] is _DIRECTORY_LEAF_ISSUER and all(type(v) is str for v in issued[1:]):
        return directory_leaf_projection({'availability':'OBSERVED','check':issued[1],
                                          'scope':issued[2],'component':issued[3]})
    return directory_leaf_unknown()


def disk_check(root,expected_identity=None):
    """Observe owned files through directory FDs; only vanished entries are skipped."""
    root=Path(root)
    need(root.is_absolute() and root.is_relative_to('/tmp') and root!=Path('/tmp')
         and '..' not in root.parts,'private-root-path')
    count=size=0;chain=[]
    identity=lambda info:(info.st_dev,info.st_ino,info.st_uid,stat.S_IMODE(info.st_mode))
    def refuse(check,depth,component):
        error=ValueError('private-directory-identity')
        try:
            selected=component() if callable(component) else component
            scope='ROOT' if depth==0 else 'DESCENDANT'
            directory_leaf_projection({'availability':'OBSERVED','check':check,'scope':scope,'component':selected})
            object.__getattribute__(error,'__dict__')['_directory_leaf_issued']=(
                _DIRECTORY_LEAF_ISSUER,check,scope,selected)
        except BaseException:pass
        raise error
    def mismatch(actual,before):
        return next(name for name,a,b in zip(('DEVICE','INODE','OWNER','MODE'),identity(actual),identity(before)) if a!=b)
    def directory(info):
        need(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid(),'private-directory-owner')
        need(info.st_mode & 0o500==0o500 and not info.st_mode & 0o7022,'private-directory-permission')
    def mount_check():
        with Path('/proc/self/mountinfo').open('rb') as stream:data=stream.read(4*1024**2+1)
        need(len(data)<=4*1024**2 and len(data.splitlines())<=8192,'private-mount-bound')
        for line in data.splitlines():
            fields=line.split();need(len(fields)>=6,'private-mount-format')
            name=re.sub(rb'\\([0-7]{3})',lambda m:bytes([int(m[1],8)]),fields[4])
            need(not Path(os.fsdecode(name)).is_relative_to(root),'private-nested-mount')
    def validate(parent,name,fd,before,depth):
        opened=os.fstat(fd);directory(opened)
        if not identity(opened)==identity(before):
            refuse('OPEN_FD_IDENTITY',depth,lambda:mismatch(opened,before))
        try:current=os.stat(name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:
            if not (depth>0 and opened.st_nlink==0):
                refuse('ROOT_PATH_MISSING' if depth==0 else 'LINKED_CHILD_PATH_MISSING',depth,'NONE')
            return False
        matched=identity(current)==identity(before)
        if not (matched and stat.S_ISDIR(current.st_mode)):
            refuse('PATH_IDENTITY' if not matched else 'PATH_NOT_DIRECTORY',depth,
                   (lambda:mismatch(current,before)) if not matched else 'TYPE')
        return True
    def walk(parent,name,fd,before,prefix,depth):
        nonlocal count,size
        need(depth<=128,'private-depth-budget')
        if not validate(parent,name,fd,before,depth):return
        locks={};seen=set()
        try:
            with os.scandir(fd) as entries:
                for entry in entries:
                    seen.add(entry.name);count+=1;need(count<=BUDGET['private_members'],'private-member-budget')
                    try:info=os.stat(entry.name,dir_fd=fd,follow_symlinks=False)
                    except FileNotFoundError:
                        validate(parent,name,fd,before,depth);continue
                    need(info.st_uid==os.getuid(),'private-foreign-owner')
                    need(info.st_dev==before.st_dev,'private-nested-mount')
                    relative=prefix+(entry.name,)
                    if stat.S_ISDIR(info.st_mode):
                        directory(info)
                        try:child=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                        except FileNotFoundError:
                            validate(parent,name,fd,before,depth)
                            try:os.stat(entry.name,dir_fd=fd,follow_symlinks=False)
                            except FileNotFoundError:continue
                            refuse('CHILD_OPEN_REAPPEARED',depth+1,'NONE')
                        try:walk(fd,entry.name,child,info,relative,depth+1)
                        finally:os.close(child)
                    elif stat.S_ISREG(info.st_mode):
                        gpg=relative[:2]==('native','gpg')
                        need(info.st_nlink==1 or gpg and info.st_nlink==2 and
                             (entry.name.startswith('.#lk') or entry.name.endswith('.lock')),'private-hardlink')
                        need(info.st_mode & 0o400 and not info.st_mode & 0o7022,'private-file-permission')
                        if info.st_nlink==2:
                            key=(info.st_dev,info.st_ino)
                            if key not in locks:
                                need(len(locks)<64,'private-gpg-lock-bound')
                                try:held=os.open(entry.name,os.O_PATH|os.O_NOFOLLOW,dir_fd=fd)
                                except FileNotFoundError:
                                    validate(parent,name,fd,before,depth);continue
                                locks[key]=held
                                need(identity(os.fstat(held))==identity(info),'private-file-identity')
                        size+=info.st_size;need(size<=BUDGET['private_bytes'],'private-disk-budget')
                    else:
                        need(stat.S_ISSOCK(info.st_mode) and relative[:2]==('native','gpg')
                             and len(relative)==3 and entry.name in GPG_SOCKETS,'private-file-type')
            validate(parent,name,fd,before,depth)
            # Dotlock peers may appear/disappear during the first enumeration.
            # Reobserve only the held inode, without trusting an outside peer.
            for attempt in range(3):
                if not locks:break
                observed={key:set() for key in locks};enumerated=0
                with os.scandir(fd) as entries:
                    for entry in entries:
                        enumerated+=1;need(enumerated<=BUDGET['private_members'],'private-member-budget')
                        if entry.name not in seen:
                            seen.add(entry.name);count+=1;need(count<=BUDGET['private_members'],'private-member-budget')
                            new=True
                        else:new=False
                        try:info=os.stat(entry.name,dir_fd=fd,follow_symlinks=False)
                        except FileNotFoundError:continue
                        need(info.st_uid==os.getuid(),'private-foreign-owner')
                        need(info.st_dev==before.st_dev,'private-nested-mount')
                        key=(info.st_dev,info.st_ino)
                        if stat.S_ISDIR(info.st_mode):
                            directory(info)
                            if new:
                                try:child=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                                except FileNotFoundError:continue
                                try:walk(fd,entry.name,child,info,prefix+(entry.name,),depth+1)
                                finally:os.close(child)
                        elif stat.S_ISREG(info.st_mode):
                            need(info.st_mode & 0o400 and not info.st_mode & 0o7022,'private-file-permission')
                            if info.st_nlink>1:
                                need(info.st_nlink==2 and (entry.name.startswith('.#lk') or entry.name.endswith('.lock')),
                                     'private-hardlink')
                                if key not in locks:
                                    need(len(locks)<64,'private-gpg-lock-bound')
                                    try:held=os.open(entry.name,os.O_PATH|os.O_NOFOLLOW,dir_fd=fd)
                                    except FileNotFoundError:continue
                                    locks[key]=held
                                    need(identity(os.fstat(held))==identity(info),'private-file-identity')
                            if key in locks:
                                need(entry.name.startswith('.#lk') or entry.name.endswith('.lock'),'private-hardlink')
                                observed.setdefault(key,set()).add(entry.name)
                            if new:size+=info.st_size;need(size<=BUDGET['private_bytes'],'private-disk-budget')
                        else:
                            need(stat.S_ISSOCK(info.st_mode) and prefix==('native','gpg')
                                 and entry.name in GPG_SOCKETS,'private-file-type')
                validate(parent,name,fd,before,depth)
                pending=False
                for key,held in locks.items():
                    current=os.fstat(held)
                    need(current.st_uid==os.getuid() and current.st_nlink<=2,'private-hardlink')
                    if current.st_nlink>len(observed[key]):pending=True
                if not pending:break
            else:raise ValueError('private-hardlink')
        finally:
            for held in locks.values():os.close(held)
    try:
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);chain.append((None,None,parent,os.fstat(parent)))
        for name in root.parts[1:]:
            before=os.stat(name,dir_fd=parent,follow_symlinks=False)
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            chain.append((parent,name,child,before));need(identity(os.fstat(child))==identity(before),'private-root-identity')
            parent=child
        before=chain[-1][3];directory(before)
        need(stat.S_IMODE(before.st_mode)==0o700,'private-root-permission')
        if expected_identity is not None:
            need(type(expected_identity) in (list,tuple) and len(expected_identity)==2
                 and all(type(v) is int and v>=0 for v in expected_identity)
                 and tuple(expected_identity)==(before.st_dev,before.st_ino),'private-root-identity')
        mount_check();walk(*chain[-1],(),0);mount_check()
        for parent,name,fd,before in chain[1:]:
            current=os.stat(name,dir_fd=parent,follow_symlinks=False)
            need(identity(current)==identity(before) and stat.S_ISDIR(current.st_mode),'private-root-identity')
        return {'members':count,'bytes':size}
    finally:
        for _,_,fd,_ in reversed(chain):os.close(fd)


def environment(private,contract,broker_ready=True):
    value={'PATH':str(private/'bin')+':/usr/bin:/bin','HOME':str(private/'home'),
            'LC_ALL':'C.UTF-8','TZ':'UTC','PYTHONDONTWRITEBYTECODE':'1','PYTHONNOUSERSITE':'1',
            'DOCKER_HOST':ENDPOINT,'DOCKER_CONFIG':str(private/'docker-config')}
    if broker_ready:
        value.update(CACHY_ASAHI_BROKER_CONTROLLER=str(private/'broker-controller.json'),
                     CACHY_ASAHI_BROKER_CONTROLLER_SHA256=digest(regular(private/'broker-controller.json')))
    return value


def scoped_gpg_home(private):
    home=private/'native/gpg'
    for path in (private,private/'native',home):
        if not path.exists() and not path.is_symlink():return None
        info=path.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and not path.is_symlink()
             and path.resolve(strict=True)==path,'scoped-gpg-home')
    need(home.is_relative_to(private) and stat.S_IMODE(home.stat().st_mode)==0o700,'scoped-gpg-home')
    return home


def ownership_save(output,owner):
    save(output/'ownership.json',owner)


def launches_verified(owner):
    rows=owner['launch_intents'];children=owner['children']
    need(type(rows) is list and len(rows)<=16,'process-intent-count')
    linked=[]
    for row in rows:
        need(type(row) is dict and set(row)=={'phase','status','child_index'} and
             type(row['phase']) is str and re.fullmatch('[a-z-]{1,40}',row['phase']) and
             row['status'] in ('REGISTERED','ABSENT'),'ambiguous-process-launch')
        index=row['child_index']
        if index is None:need(row['status']=='ABSENT','ambiguous-process-launch')
        else:
            need(type(index) is int and 0<=index<len(children) and index not in linked,'process-intent-index')
            linked.append(index)
            if row['status']=='ABSENT':need(children[index]['complete'],'process-absence-mismatch')
    need(set(linked)==set(range(len(children))),'unlinked-process-record')


def tracked_process(owner,output,runner,phase,argv,stdout,stderr,deadline,env,cwd,on_tick=None):
    intent={'phase':phase,'status':'INTENT','child_index':None};item={}
    need(len(owner['launch_intents'])<16,'process-intent-count')
    owner['launch_intents'].append(intent);ownership_save(output,owner)
    def spawned(identity):
        need(len(owner['children'])<16,'stage-process-count')
        intent.update(status='REGISTERED',child_index=len(owner['children']))
        owner['children'].append(dict(identity,complete=False));ownership_save(output,owner)
    try:
        item=runner(argv,stdout,stderr,deadline,env,cwd,on_tick=on_tick,on_spawn=spawned)
        return item
    except BaseException as error:
        item=getattr(error,'receipt',{})
        raise
    finally:
        if intent['child_index'] is not None:
            owner['children'][intent['child_index']]['complete']=item.get('group_absent',False)
        if item.get('group_absent',False):intent['status']='ABSENT'
        ownership_save(output,owner)


def install_signals(previous,handler):
    mask=signal.pthread_sigmask(signal.SIG_BLOCK,set(previous))
    try:
        for number in previous:signal.signal(number,handler)
        signal.pthread_sigmask(signal.SIG_SETMASK,mask)
        return mask
    except BaseException:
        try:
            for number,old in previous.items():
                for _ in range(2):
                    try:signal.signal(number,old);break
                    except BaseException:pass
        finally:
            for _ in range(2):
                try:signal.pthread_sigmask(signal.SIG_SETMASK,mask);break
                except BaseException:pass
        raise


def finish_signals(previous,cancelled,commit,mask):
    """Drain pending cancellation and restore caller state on every failure."""
    failed=False
    try:
        try:
            signal.pthread_sigmask(signal.SIG_BLOCK,set(previous))
            for _ in range(8):
                pending=signal.sigpending() & set(previous)
                if pending:
                    cancelled.extend(s for s in pending if s not in cancelled)
                    signal.sigtimedwait(set(previous),0)
                    continue
                if cancelled:commit(False)
                if not (signal.sigpending() & set(previous)):break
            else:raise ValueError('pending-signal-bound')
        except BaseException:failed=True
        if failed:
            if not cancelled:cancelled.append(0)
            commit(True)
    finally:
        try:
            for number,handler in previous.items():
                for _ in range(2):
                    try:signal.signal(number,handler);break
                    except BaseException:failed=True
        finally:
            for _ in range(2):
                try:signal.pthread_sigmask(signal.SIG_SETMASK,mask);break
                except BaseException:failed=True
    if failed:
        if not cancelled:cancelled.append(0)
        commit(True)


PROCESS_PHASES=frozenset({'native-daemon','materialize','freeze','native-pair','public-projection',
                          'public-guard','public-bundle','gpg-cleanup','recovery-gpg'})
RUNTIME_REASONS=frozenset({'invalid-deadline','timeout','invalid-command','unsafe-log',
                           'nonprivate-log-parent','subreaper-unavailable','signal-state-restore',
                           'spawn-failed','registration-failed','log-write','log-limit','tick-failed',
                           'process-failed','runtime-failed','group-cleanup','cancelled'})
IO_TICK_CODES=frozenset({'missing-path','permission-denied','io-error','validation-error','unexpected-error'})
TICK_CODES={
    'private-scan':IO_TICK_CODES | frozenset({'private-root-path','private-directory-owner',
        'private-directory-permission','private-mount-bound','private-mount-format','private-nested-mount',
        'private-directory-identity','private-depth-budget','private-member-budget','private-foreign-owner',
        'private-hardlink','private-file-permission','private-disk-budget','private-file-type',
        'private-root-identity','private-root-permission','private-gpg-lock-bound','private-file-identity'}),
    'socket-identity':IO_TICK_CODES | {'daemon-socket-changed'},
    'daemon-storage':IO_TICK_CODES | {'docker-storage-budget'},
    'cancellation':frozenset({'cancelled'}),
}
DIAGNOSTIC_FIELDS=frozenset({'failed_phase','runtime_reason','runtime_returncode','tick_operation','tick_reason',
                           'directory_leaf'})


def diagnostic_projection(value):
    """Finite metadata only; unknown keys/values never become public diagnostics."""
    fields=set(value) & DIAGNOSTIC_FIELDS
    if not fields:return {}
    required={'failed_phase','runtime_reason','runtime_returncode'}
    need(fields-{'directory_leaf'} in (required,required|{'tick_operation','tick_reason'}),'diagnostic-field-set')
    need(type(value['failed_phase']) is str and value['failed_phase'] in PROCESS_PHASES
         and type(value['runtime_reason']) is str and value['runtime_reason'] in RUNTIME_REASONS,'diagnostic-enum')
    code=value['runtime_returncode']
    need(code is None or type(code) is int and -64<=code<=255,'diagnostic-returncode')
    if 'tick_operation' in fields:
        op=value['tick_operation'];reason=value['tick_reason']
        need(value['runtime_reason']=='tick-failed' and type(op) is str and op in TICK_CODES
             and type(reason) is str and reason in TICK_CODES[op],'diagnostic-tick-enum')
    result={name:value[name] for name in fields}
    if 'directory_leaf' in fields:
        need(value['runtime_reason']=='tick-failed' and value.get('tick_operation')=='private-scan'
             and value.get('tick_reason')=='private-directory-identity','directory-leaf-context')
        result['directory_leaf']=directory_leaf_projection(value['directory_leaf'])
    return result


def failure_diagnostics(receipt,phase,item,runtime,tick=None):
    """Only the authenticated runtime's typed process receipt can seed fields."""
    try:
        if 'failed_phase' in receipt:return
        if type(item) is not runtime.Receipt or not {'kind','schema_version','status','reason_code','returncode'}<=set(item) or type(item.get('kind')) is not str or item['kind']!='process-lifecycle' or \
           type(item.get('schema_version')) is not int or item['schema_version']!=1 or \
           type(item.get('status')) is not str or item['status'] not in ('FAIL','CANCELLED'):return
        value={'failed_phase':phase,'runtime_reason':item.get('reason_code'),
               'runtime_returncode':item.get('returncode')}
        if type(tick) is dict and tick and value['runtime_reason']=='tick-failed':
            value.update(tick_operation=dict.get(tick,'operation'),tick_reason=dict.get(tick,'reason'))
            if value['tick_operation']=='private-scan' and value['tick_reason']=='private-directory-identity':
                value['directory_leaf']=_directory_leaf_fact(dict.get(tick,'_directory_leaf_issued'))
        receipt.update(diagnostic_projection(value))
    except BaseException:return


def tick_observation(operation,action,failed):
    try:return action()
    except Exception as error:
        try:
            if type(failed) is dict and not failed:
                if isinstance(error,PermissionError):reason='permission-denied'
                elif isinstance(error,FileNotFoundError):reason='missing-path'
                elif isinstance(error,OSError):reason='io-error'
                elif type(error) is ValueError:
                    args=object.__getattribute__(error,'args')
                    text=args[0] if type(args) is tuple and len(args)==1 and type(args[0]) is str else None
                    reason=text if text in TICK_CODES[operation] else 'validation-error'
                else:reason='unexpected-error'
                value={'operation':operation,'reason':reason}
                if operation=='private-scan' and reason=='private-directory-identity':
                    try:value['_directory_leaf_issued']=_directory_leaf_issued(error)
                    except BaseException:pass
                dict.update(failed,value)
        except BaseException:pass
        raise


CLEANUP_REASONS=frozenset({'process-ownership-unverified','process-group-unverified',
    'cleanup-validation-or-daemon-failure','client-launch-ambiguous','client-group-ambiguous',
    'container-cleanup-unverified','image-cleanup-ambiguous','image-id-missing','image-id-invalid','image-id-drift',
    'image-owner-unverified','image-daemon-query-failed','image-remains','cleanup-cancelled','docker-cleanup-unverified',
    'gpg-home-unverified','gpg-process-unverified','private-removal-unverified','private-removal-blocked',
    'retention-budget-exceeded','storage-observation-unverified'})
CLEANUP_FIELDS=frozenset({'process_cleanup_status','docker_cleanup_status','gpg_cleanup_status',
                         'private_cleanup_status','daemon_disposal_status','cleanup_reasons'})


def cleanup_projection(value):
    fields=set(value) & CLEANUP_FIELDS
    if not fields:return {}
    need(fields==CLEANUP_FIELDS,'cleanup-field-set')
    for name in CLEANUP_FIELDS-{'daemon_disposal_status','cleanup_reasons'}:
        need(type(value[name]) is str and value[name] in ('PASS','FAIL','NOT RUN'),'cleanup-status-enum')
    need(type(value['daemon_disposal_status']) is str and value['daemon_disposal_status']=='NOT ATTESTED','cleanup-disposal-enum')
    reasons=value['cleanup_reasons']
    need(type(reasons) is list and len(reasons)<=len(CLEANUP_REASONS) and
         all(type(v) is str and v in CLEANUP_REASONS for v in reasons) and
         reasons==sorted(set(reasons)),'cleanup-reason-enum')
    return {name:value[name] for name in fields}


def storage_projection(value):
    need(type(value) is dict and set(value)=={'mode','latched','reason','filesystems'},'storage-public-schema')
    need(type(value['mode']) is str and value['mode'] in ('shared','separate') and
         type(value['latched']) is bool and type(value['reason']) is str and
         value['reason'] in ('none','growth-limit','reserve-floor','observation-failed','baseline-floor') and
         value['latched']==(value['reason']!='none'),'storage-public-enum')
    rows=value['filesystems'];roles=['shared'] if value['mode']=='shared' else ['private','daemon']
    need(type(rows) is list and len(rows)==len(roles),'storage-public-count')
    fields={'role','baseline_free_bytes','current_free_bytes','peak_growth_bytes',
            'growth_limit_bytes','reserve_bytes','device'}
    for row,role in zip(rows,roles):
        need(type(row) is dict and set(row)==fields and type(row['role']) is str and row['role']==role,
             'storage-public-row')
        need(all(type(row[k]) is int and 0<=row[k]<=2**63-1 for k in fields-{'role'}),'storage-public-scalar')
        need(row['growth_limit_bytes']==BUDGET['shared_growth_bytes' if role=='shared' else 'filesystem_growth_bytes']
             and row['reserve_bytes']==BUDGET['remaining_reserve_bytes'] and
             max(0,row['baseline_free_bytes']-row['current_free_bytes'])<=row['peak_growth_bytes']<=row['baseline_free_bytes'],
             'storage-public-bound')
    if len(rows)==2:need(rows[0]['device']!=rows[1]['device'],'storage-public-devices')
    witness={'none':all(row['baseline_free_bytes']>=row['growth_limit_bytes']+row['reserve_bytes'] and
                       row['peak_growth_bytes']<=row['growth_limit_bytes'] and row['current_free_bytes']>=row['reserve_bytes']
                       for row in rows),
             'baseline-floor':any(row['baseline_free_bytes']<row['growth_limit_bytes']+row['reserve_bytes'] for row in rows),
             'growth-limit':any(row['peak_growth_bytes']>row['growth_limit_bytes'] for row in rows),
             'reserve-floor':any(row['peak_growth_bytes']>max(0,row['baseline_free_bytes']-row['reserve_bytes']) for row in rows),
             'observation-failed':True}
    need(witness[value['reason']],'storage-public-latch')
    return value


def public_summary(receipt):
    """Fixed scalar/hash/typed lifecycle fields; no host paths, argv or raw logs."""
    allowed=('schema_version','status','phase','controller_sha256','ready_sha256','source_commit',
             'candidate_sha256','native_compilation','publication','hardware','elapsed_seconds',
             'failure_class','private_data_removed','raw_retention_within_budget','cleanup_status',
             'cancelled','public_bundle_sha256')
    result={k:receipt[k] for k in allowed if k in receipt}
    result.update(diagnostic_projection(receipt));result.update(cleanup_projection(receipt))
    if 'storage' in receipt:result['storage']=storage_projection(receipt['storage'])
    return result


def process_identity(pid):
    raw=Path(f'/proc/{pid}/stat').read_text()
    fields=raw[raw.rfind(')')+2:].split()
    uid=re.search(r'^Uid:\s+(\d+)',Path(f'/proc/{pid}/status').read_text(),re.M)
    need(uid and int(uid[1])==os.getuid(),'process-owner')
    return {'pid':pid,'start_ticks':int(fields[19])}


def stop_record(record,deadline):
    """Recovery refuses a reused PID or a live group whose leader is ambiguous."""
    need(set(record)=={'pid','group','start_ticks','complete'} and all(type(record[k]) is int and record[k]>1
         for k in ('pid','group','start_ticks')) and record['pid']==record['group'],'process-record')
    need(type(record['complete']) is bool,'process-record')
    if record['complete']:return {'status':'PASS','group_absent':True,'absence_already_attested':True}
    def exists():
        try:os.killpg(record['group'],0);return True
        except ProcessLookupError:return False
    if not exists():return {'status':'PASS','group_absent':True}
    try:current=process_identity(record['pid'])
    except FileNotFoundError:return {'status':'FAIL','reason_code':'ambiguous-group-leader'}
    if current!={'pid':record['pid'],'start_ticks':record['start_ticks']}:
        return {'status':'FAIL','reason_code':'reused-process-id'}
    os.killpg(record['group'],signal.SIGTERM);grace=min(deadline,time.monotonic()+10)
    while exists() and time.monotonic()<grace:time.sleep(.05)
    if exists():
        try:need(process_identity(record['pid'])==current,'reused-process-id')
        except FileNotFoundError:return {'status':'FAIL','reason_code':'ambiguous-group-leader'}
        os.killpg(record['group'],signal.SIGKILL)
        while exists() and time.monotonic()<min(deadline,grace+3):time.sleep(.05)
    return {'status':'FAIL' if exists() else 'PASS','group_absent':not exists()}


def revoke_terminal(output,prefix='terminal'):
    current=output/(prefix+'-public')
    if current.exists():
        need(not current.is_symlink() and current.resolve(strict=True)==current
             and current.stat().st_uid==os.getuid(),'terminal-output-identity')
        for name in ('terminal.json','export-manifest.json'):
            path=current/name
            if path.exists() or path.is_symlink():regular(path);path.unlink()


def publish_terminal(output,receipt,guard,revision,prefix='terminal'):
    staged=output/(prefix+'-input')
    current=output/(prefix+'-public')
    try:
        staged.mkdir(mode=0o700,exist_ok=True)
        save(staged/'terminal.json',public_summary(receipt))
        next_output=output/(prefix+'-guard-'+str(revision))
        need(guard.export_evidence(staged,next_output)['evidence_export']=='PASS','terminal-guard-failed')
        current.mkdir(mode=0o700,exist_ok=True)
        # A consumer reads only after exit; commit the manifest after its receipt.
        os.replace(next_output/'terminal.json',current/'terminal.json')
        os.replace(next_output/'export-manifest.json',current/'export-manifest.json')
        next_output.rmdir()
    except BaseException:
        # Failed replacement must never leave an older terminal PASS public.
        revoke_terminal(output,prefix)
        raise


def owned_cleanup(owner,output,private,contract,runtime,broker,runner,deadline,env,receipt,cancelled,recovery=False):
    """Attempt each authenticated scope; ambiguity still prevents raw removal."""
    receipt.update(process_cleanup_status='NOT RUN',docker_cleanup_status='NOT RUN',gpg_cleanup_status='NOT RUN',
                   private_cleanup_status='NOT RUN',daemon_disposal_status='NOT ATTESTED',cleanup_reasons=[])
    reasons=set()
    def failed(error,reason,phase=None):
        reasons.add(reason)
        if type(error).__name__ in ('RuntimeCancelled','KeyboardInterrupt','BuildCancelled','SourceCancelled'):
            if not cancelled:cancelled.append(0)
        if phase:failure_diagnostics(receipt,phase,getattr(error,'receipt',None),runtime)
    try:
        launches_verified(owner)
        receipt['process_cleanup']=[stop_record(row,deadline) for row in reversed(owner['children'])]
        receipt['process_cleanup_status']='PASS' if all(row['status']=='PASS' for row in receipt['process_cleanup']) else 'FAIL'
        if receipt['process_cleanup_status']=='FAIL':reasons.add('process-group-unverified')
    except BaseException as error:
        receipt['process_cleanup_status']='FAIL';failed(error,'process-ownership-unverified')
    try:
        docker=broker.cleanup(private,owner['nonce'],contract['tools']['docker']['path'],ENDPOINT,deadline)
        receipt['docker_cleanup']=docker;receipt['docker_cleanup_status']='PASS' if docker.get('status')=='PASS' else 'FAIL'
        if receipt['docker_cleanup_status']=='FAIL':
            codes=docker.get('failures',[])
            admitted=[v for v in codes if type(v) is str and v in CLEANUP_REASONS] if type(codes) is list else []
            reasons.update(admitted or ['docker-cleanup-unverified'])
    except BaseException as error:
        receipt['docker_cleanup_status']='FAIL';failed(error,'docker-cleanup-unverified')
    phase='recovery-gpg' if recovery else 'gpg-cleanup'
    try:
        home=scoped_gpg_home(private)
    except BaseException as error:
        receipt['gpg_cleanup_status']='FAIL';failed(error,'gpg-home-unverified')
    else:
        try:
            if home is not None:
                suffix='-'+os.urandom(4).hex() if recovery else ''
                item=tracked_process(owner,output,runner,phase,
                    [contract['tools']['gpgconf']['path'],'--homedir',str(home),'--kill','all'],
                    private/'logs'/(phase+suffix+'.stdout'),private/'logs'/(phase+suffix+'.stderr'),
                    min(deadline,time.monotonic()+15),env,private)
                failure_diagnostics(receipt,phase,item,runtime)
                need(item['status']=='PASS' and item.get('group_absent') is True,'gpg-cleanup-failed')
            receipt['gpg_cleanup_status']='PASS'
        except BaseException as error:
            receipt['gpg_cleanup_status']='FAIL';failed(error,'gpg-process-unverified',phase)
    if receipt['process_cleanup_status']=='PASS':
        try:
            launches_verified(owner)
            need(all(row['complete'] for row in owner['children']),'owned-process-cleanup-unverified')
        except BaseException as error:
            receipt['process_cleanup_status']='FAIL';failed(error,'process-group-unverified')
    if all(receipt[k]=='PASS' for k in ('process_cleanup_status','docker_cleanup_status','gpg_cleanup_status')):
        try:
            removed=runtime.owned_remove(output,'private',owner['nonce'],deadline)
            receipt['private_cleanup']=removed;receipt['private_data_removed']=removed.get('removed',False)
            if removed['status']=='CANCELLED' and not cancelled:cancelled.append(0)
            receipt['private_cleanup_status']='PASS' if removed['status']=='PASS' and receipt['private_data_removed'] else 'FAIL'
            if receipt['private_cleanup_status']=='FAIL':reasons.add('private-removal-unverified')
        except BaseException as error:
            receipt['private_cleanup_status']='FAIL';failed(error,'private-removal-unverified')
    else:reasons.add('private-removal-blocked')
    receipt['cleanup_reasons']=sorted(reasons)
    receipt['cleanup_status']='PASS' if receipt['private_cleanup_status']=='PASS' else 'FAIL'
    owner.update(cleanup_verified=receipt['cleanup_status']=='PASS',private_removed=receipt['private_data_removed'])
    ownership_save(output,owner)
    return receipt['cleanup_status']=='PASS'


def pipeline(root,controller,controller_sha,output,runner=None):
    contract,source=authenticate(root,controller,controller_sha)
    rows=contract['source']['files'];prefix='scripts/port/updater-native-stage/'
    runtime=module(HERE/'runtime.py',rows[prefix+'runtime.py']['sha256'])
    broker=module(HERE/'broker.py',rows[prefix+'broker.py']['sha256'])
    run_process=runner or runtime.run_process
    need(output.is_absolute() and output.is_relative_to('/tmp') and output.parent.resolve(strict=True)==output.parent
         and not output.exists() and not output.is_symlink(),'fresh-stage-output')
    need(shutil.disk_usage(output.parent).free>=BUDGET['minimum_output_free_bytes'],'output-free-disk')
    output.mkdir(mode=0o700);start=time.monotonic();deadline=start+BUDGET['total_seconds']
    nonce=os.urandom(16).hex();private=None;env=None;failure=None;cancelled=[];broker_contract=None
    guard=module(root/'scripts/ci/integration_export.py',rows['scripts/ci/integration_export.py']['sha256'])
    receipt={'schema_version':1,'status':'RUNNING','phase':'private-registration','controller_sha256':controller_sha,
             'ready_sha256':READY_SHA,'source_commit':contract['source']['source_commit'],
             'native_compilation':'NOT RUN','publication':'NOT ACCEPTED','hardware':'NOT RUN',
             'private_data_removed':False,'cleanup_status':'NOT RUN','raw_retention_within_budget':False,'processes':{}}
    info=output.stat()
    owner={'schema_version':1,'controller_sha256':controller_sha,'source_commit':receipt['source_commit'],
           'host':contract['host'],'nonce':nonce,'uid':os.getuid(),
           'output_identity':{'device':info.st_dev,'inode':info.st_ino},'stage':process_identity(os.getpid()),
           'started_monotonic':start,'private_record':None,'children':[],
           'cleanup_verified':False,'private_removed':False,'launch_intents':[]}
    ownership_save(output,owner)
    signals={signal.SIGTERM,signal.SIGINT}
    if signal.getitimer(signal.ITIMER_REAL)[0] or callable(signal.getsignal(signal.SIGALRM)):signals.add(signal.SIGALRM)
    previous={s:signal.getsignal(s) for s in signals}
    def defer(signum,_frame):
        if signum not in cancelled:cancelled.append(signum)
    original_mask=install_signals(previous,defer)
    def final_cancel(failed):
        receipt['cancelled']=True
        receipt['status']='FAIL' if failed or receipt['status']=='FAIL' or receipt['cleanup_status']!='PASS' else 'CANCELLED'
        try:save(output/'result.json',receipt)
        finally:publish_terminal(output,receipt,guard,2,prefix='terminal')
    try:
        save(output/'result.json',receipt)
        try:
            private=output/'private'
            runtime.owned_create(output,'private',nonce)
            owner['private_record']=runtime.owned_record(output,'private',nonce);ownership_save(output,owner)
            for name in ('home','logs','bin'): (private/name).mkdir(mode=0o700)
            copied=private/'source';snapshot(root,copied,contract['source'])
            alias=private/'bin/docker'
            broker_raw=regular(copied/(prefix+'broker.py'))
            need(broker_raw.startswith(b'#!/usr/bin/env python3\n'),'broker-entrypoint')
            alias.write_bytes(('#!'+contract['tools']['python']['path']+'\n').encode()+broker_raw.split(b'\n',1)[1]);alias.chmod(0o755)
            env=environment(private,contract,broker_ready=False)
            broker_contract=None
            python=contract['tools']['python']['path'];package=copied/PACKAGE
            materialized=private/'materialized';candidate=private/'candidate';native=private/'native'
            storage=None;last_tick=0
            def command(phase,argv,seconds,absolute_end=None):
                receipt['phase']=phase;save(output/'result.json',receipt)
                need(not cancelled,'stage-cancelled');verify_snapshot(copied,contract['source']);tool_check(contract['tools'])
                tick_failure={}
                def tick():
                    nonlocal last_tick
                    def uncancelled():need(not cancelled,'cancelled')
                    tick_observation('cancellation',uncancelled,tick_failure)
                    now=time.monotonic()
                    if now-last_tick>=1:
                        last_tick=now
                        tick_observation('private-scan',lambda:disk_check(private,owner['private_record']['child']),tick_failure)
                        def socket_check():
                            sock=Path('/run/docker.sock').lstat()
                            need({'device':sock.st_dev,'inode':sock.st_ino}==contract['host']['docker_socket_identity'],
                                 'daemon-socket-changed')
                        tick_observation('socket-identity',socket_check,tick_failure)
                        if broker_contract is not None:
                            def storage_tick():
                                try:return broker.storage_check(broker_contract)
                                except ValueError as error:
                                    if type(error) is broker.BrokerError and error.code=='docker-storage-budget':
                                        raise ValueError('docker-storage-budget') from None
                                    raise
                            tick_observation('daemon-storage',storage_tick,tick_failure)
                endpoint = min(deadline, time.monotonic()+seconds) if absolute_end is None else absolute_end
                need(type(endpoint) in (int,float) and endpoint <= deadline and time.monotonic() < endpoint,
                     'stage-phase-deadline')
                try:
                    item=tracked_process(owner,output,run_process,phase,argv,
                                         private/'logs'/f'{phase}.stdout',private/'logs'/f'{phase}.stderr',
                                         endpoint,env,copied,tick)
                    receipt['processes'][phase]=item;failure_diagnostics(receipt,phase,item,runtime,tick_failure)
                except BaseException as error:
                    item=getattr(error,'receipt',{'status':'FAIL','reason_code':'stage-process-failed'})
                    receipt['processes'][phase]=item;failure_diagnostics(receipt,phase,item,runtime,tick_failure)
                    raise
                need(item['status']=='PASS','stage-process-failed')
            command('native-daemon',[contract['tools']['docker']['path'],'--host',ENDPOINT,'info','--format','{{json .}}'],30)
            daemon=load(private/'logs/native-daemon.stdout')
            need(daemon.get('Architecture') in ('aarch64','arm64'),'native-daemon-required')
            storage=Path(daemon['DockerRootDir']);need(storage.is_absolute() and storage.resolve(strict=True)==storage,
                                                    'daemon-storage-directory')
            broker_contract={'schema_version':1,'nonce':nonce,'root':str(private),
                             'real_docker':contract['tools']['docker']['path'],
                             'real_docker_sha256':contract['tools']['docker']['sha256'],
                             'docker_endpoint':ENDPOINT,'deadline_monotonic':deadline,
                             'docker_socket_identity':contract['host']['docker_socket_identity'],
                             'storage_policy':broker.storage_policy(private,storage)}
            save(private/'broker-controller.json',broker_contract)
            broker_contract.update(_path=str(private/'broker-controller.json'),
                                   _sha256=digest(regular(private/'broker-controller.json')))
            broker.storage_initialize(broker_contract)
            env=environment(private,contract)
            lock_sha=digest(regular(package/'runner-inputs.lock.json'))
            # The unchanged built-in worker inherits our owned session. Its CLI
            # applies the original resource limits; no separate-session supervisor.
            materialized.mkdir(mode=0o700)
            save(materialized/'materializer-result.json',{'schema_version':1,'scope':'private source materialization',
                 'status':'RUNNING','phase':'launch-data-worker','runner_inputs_sha256':lock_sha})
            command('materialize',[python,'-I','-B',str(package/'materialize-inputs.py'),'--child','--output',str(materialized),
                                  '--pins-sha256',lock_sha],BUDGET['materialize_seconds'])
            need(load(materialized/'materializer-result.json')['status']=='PASS','materialization-not-passed')
            source_archive=materialized/'private-sanitized/cachy-update-e2b1b7144be71cf392809f48d1440f8da1d9c81a-sanitized.tar.gz'
            vendor=materialized/'private-cache/cachy-update-vendor.tar.gz'
            command('freeze',[python,'-I','-B',str(package/'updater-native.py'),'freeze','--source',str(source_archive),
                              '--vendor',str(vendor),'--output',str(candidate)],BUDGET['freeze_seconds'])
            candidate_sha=digest(regular(candidate/'candidate.json'));receipt['candidate_sha256']=candidate_sha
            native_end = min(deadline,time.monotonic()+BUDGET['native_seconds'])
            def seed_check():
                need(not cancelled,'stage-cancelled')
                need(time.monotonic() < native_end,'stage-native-deadline')
            seed_holder = {}
            seed_helper = module(copied/(prefix+'current_cache.py'),rows[prefix+'current_cache.py']['sha256'])
            receipt['phase'] = 'native-cache-seed'
            try:
                receipt['cache_seed'] = seed_helper.seed(copied,private,contract['source'],native_end,
                    seed_check,seed_holder,module,regular,verify_snapshot)
            except BaseException:
                if seed_holder.get('observation',{}).get('cancelled') is True and not cancelled:
                    cancelled.append(0)  # Existing unknown-number cancellation marker.
                raise
            save(output/'result.json',receipt)
            command('native-pair',[python,'-I','-B',str(package/'updater-native.py'),'build','--candidate',str(candidate/'candidate.json'),
                                   '--candidate-sha256',candidate_sha,'--cache',str(private/'archives'),'--output',str(native)],BUDGET['native_seconds'],absolute_end=native_end)
            need(load(native/'result.json')['native_pair']=='PASS','native-pair-not-passed')
            source.verify(root,contract['source']);verify_snapshot(copied,contract['source'])
            receipt['native_compilation']='PASS PRIVATE NATIVE PAIR'
        except BaseException as error:
            failure=error;receipt['failure_class']=type(error).__name__
            if owner['private_record'] is None and getattr(error,'receipt',{}).get('registered'):
                owner['private_record']=runtime.owned_record(output,'private',nonce);ownership_save(output,owner)
            if type(error).__name__ in ('RuntimeCancelled','KeyboardInterrupt','BuildCancelled','SourceCancelled'):
                if not cancelled:cancelled.append(0)
            if cancelled:receipt['status']='CANCELLED'
            else:receipt['status']='FAIL'
        finally:
            # Project, guard and bundle in bounded owned processes while the
            # authenticated source snapshot remains available for all helpers.
            try:
                if private is not None and private.is_dir():
                    copied=private/'source'
                    empty=private/'empty-raw';empty.mkdir(mode=0o700)
                    raw=private/'native' if (private/'native').is_dir() else empty
                    materialized=private/'materialized' if (private/'materialized').is_dir() else None
                    public_env=env or {'PATH':'/usr/bin:/bin','HOME':str(private/'home'),'LC_ALL':'C.UTF-8'}
                    for operation,input_path,output_path,module_name,phase in (
                        ('project',raw,output/'projected',PACKAGE+'public-evidence.py','public-projection'),
                        ('guard',output/'projected',output/'guarded','scripts/ci/integration_export.py','public-guard'),
                        ('bundle',output/'guarded',output/'public-evidence.tar.gz','scripts/ci/log_evidence.py','public-bundle')):
                        receipt['phase']=phase;save(output/'result.json',receipt)
                        verify_snapshot(copied,contract['source']);tool_check(contract['tools'])
                        argv=[contract['tools']['python']['path'],'-I','-B',str(copied/(prefix+'public_worker.py')),
                              '--operation',operation,'--module',str(copied/module_name),
                              '--module-sha256',rows[module_name]['sha256'],'--stage-output',str(output),
                              '--input',str(input_path),'--output',str(output_path)]
                        if operation=='project' and materialized is not None:argv+=['--materialized',str(materialized)]
                        item=tracked_process(owner,output,run_process,phase,argv,
                                             private/'logs'/f'{phase}.stdout',private/'logs'/f'{phase}.stderr',
                                             min(deadline,time.monotonic()+BUDGET['projection_seconds' if operation=='project' else 'export_seconds']),
                                             public_env,copied)
                        receipt['processes'][phase]=item;failure_diagnostics(receipt,phase,item,runtime)
                        need(item['status']=='PASS','public-process-failed')
                        status=load(private/'logs'/f'{phase}.stdout')
                        need(status=={'status':'PASS','operation':operation},'public-worker-receipt')
                    need(load(output/'projected/projection.json')['projection']=='PASS','public-projection-failed')
                    need(load(output/'guarded/export-manifest.json')['evidence_export']=='PASS','credential-guard-failed')
                    receipt['public_bundle_sha256']=digest(regular(output/'public-evidence.tar.gz',8*1024**2))
                    receipt['public_projection']='PASS';receipt['credential_guard']='PASS'
            except BaseException as error:
                if type(error).__name__ in ('RuntimeCancelled','KeyboardInterrupt','BuildCancelled','SourceCancelled') and not cancelled:cancelled.append(0)
                failure_diagnostics(receipt,receipt['phase'],getattr(error,'receipt',None),runtime)
                failure=failure or error;receipt.update(status='FAIL',public_projection='FAIL',failure_class=type(error).__name__)
            receipt['phase']='owned-cleanup';save(output/'result.json',receipt)
            cleanup_deadline=min(start+BUDGET['raw_retention_seconds'],time.monotonic()+BUDGET['cleanup_seconds'])
            storage_error=False
            if private is not None:
                if broker_contract is not None:
                    try:receipt['storage']=storage_projection(broker.storage_projection(broker_contract))
                    except BaseException:
                        storage_error=True;failure=failure or ValueError('storage-observation-unverified');receipt['status']='FAIL'
                cleaned=owned_cleanup(owner,output,private,contract,runtime,broker,run_process,cleanup_deadline,
                                      env or environment(private,contract,broker_ready=False),receipt,cancelled)
                if storage_error:
                    receipt['cleanup_reasons']=sorted(set(receipt['cleanup_reasons'])|{'storage-observation-unverified'})
                if not cleaned:
                    failure=failure or ValueError('owned-cleanup-unverified');receipt['status']='FAIL'
                    receipt.setdefault('failure_class',type(failure).__name__)
            receipt['raw_retention_within_budget']=time.monotonic()-start<=BUDGET['raw_retention_seconds']
            if not receipt['raw_retention_within_budget'] and 'cleanup_reasons' in receipt:
                receipt['cleanup_reasons']=sorted(set(receipt['cleanup_reasons'])|{'retention-budget-exceeded'})
            receipt['cleanup_status']='PASS' if receipt['private_data_removed'] and receipt.get('docker_cleanup',{}).get('status')=='PASS' else 'FAIL'
            owner.update(cleanup_verified=receipt['cleanup_status']=='PASS',private_removed=receipt['private_data_removed'])
            ownership_save(output,owner)
            if failure is None and receipt['cleanup_status']=='PASS' and receipt['raw_retention_within_budget']:receipt['status']='PASS'
            elif receipt['status']=='RUNNING':receipt['status']='FAIL'
            receipt['cancelled']=bool(cancelled)
            if cancelled and receipt['cleanup_status']=='PASS':receipt['status']='CANCELLED'
            receipt.update(phase='finalized',elapsed_seconds=int(time.monotonic()-start));save(output/'result.json',receipt)
            def cancel_status():
                receipt['cancelled']=bool(cancelled)
                if cancelled and receipt['cleanup_status']=='PASS':receipt['status']='CANCELLED'
            # Cancellation is monotonic: after the first terminal commit, repeat
            # once if a save/export boundary observed a newly deferred signal.
            for revision in range(2):
                cancel_status();before=(receipt['status'],receipt['cancelled'])
                try:publish_terminal(output,receipt,guard,revision)
                except BaseException as error:receipt.update(status='FAIL',failure_class=type(error).__name__)
                cancel_status();save(output/'result.json',receipt);cancel_status()
                if before==(receipt['status'],receipt['cancelled']):break
    except BaseException as error:
        receipt.update(status='FAIL',failure_class=type(error).__name__)
        revoke_terminal(output,prefix='terminal')
        raise
    finally:
        finish_signals(previous,cancelled,final_cancel,original_mask)
    return receipt


def recover(root,controller,controller_sha,output,owner_sha):
    """Always-step recovery: explicit external ownership pin, no active/reused PID grant."""
    contract,_source=authenticate(root,controller,controller_sha)
    need(output.is_absolute() and output.is_relative_to('/tmp') and output.resolve(strict=True)==output
         and output.stat().st_uid==os.getuid() and stat.S_IMODE(output.stat().st_mode)==0o700,'recovery-output')
    raw=regular(output/'ownership.json');need(re.fullmatch('[0-9a-f]{64}',owner_sha or '')
                                            and digest(raw)==owner_sha,'ownership-pin')
    owner=json.loads(raw,object_pairs_hook=unique);info=output.stat()
    fields={'schema_version','controller_sha256','source_commit','host','nonce','uid','output_identity',
            'stage','started_monotonic','private_record','children','cleanup_verified','private_removed',
            'launch_intents'}
    need(type(owner) is dict and set(owner)==fields and owner['schema_version']==1 and
         owner['controller_sha256']==controller_sha and owner['source_commit']==contract['source']['source_commit']
         and owner['host']==contract['host'] and type(owner['uid']) is int and owner['uid']==os.getuid()
         and owner['output_identity']=={'device':info.st_dev,'inode':info.st_ino}
         and re.fullmatch('[0-9a-f]{32}',owner['nonce']) and type(owner['children']) is list
         and len(owner['children'])<=16 and type(owner['cleanup_verified']) is bool
         and type(owner['private_removed']) is bool,'ownership-schema')
    need(type(owner['stage']) is dict and set(owner['stage'])=={'pid','start_ticks'}
         and all(type(v) is int and v>1 for v in owner['stage'].values()),'stage-process-record')
    try:original=process_identity(owner['stage']['pid'])
    except FileNotFoundError:original=None
    need(original!=owner['stage'],'original-stage-still-active')
    prefix='scripts/port/updater-native-stage/';rows=contract['source']['files']
    runtime=module(HERE/'runtime.py',rows[prefix+'runtime.py']['sha256'])
    broker=module(HERE/'broker.py',rows[prefix+'broker.py']['sha256'])
    guard=module(root/'scripts/ci/integration_export.py',rows['scripts/ci/integration_export.py']['sha256'])
    private=output/'private';deadline=time.monotonic()+BUDGET['cleanup_seconds'];cancelled=[]
    signals={signal.SIGTERM,signal.SIGINT}
    if signal.getitimer(signal.ITIMER_REAL)[0] or callable(signal.getsignal(signal.SIGALRM)):signals.add(signal.SIGALRM)
    previous={s:signal.getsignal(s) for s in signals}
    def defer(signum,_frame):
        if signum not in cancelled:cancelled.append(signum)
    original_mask=install_signals(previous,defer)
    receipt={'schema_version':1,'status':'FAIL','phase':'recovery','controller_sha256':controller_sha,
             'ready_sha256':READY_SHA,'source_commit':owner['source_commit'],'native_compilation':'NOT ATTESTED BY RECOVERY',
             'publication':'NOT ACCEPTED','hardware':'NOT RUN','private_data_removed':False,'cleanup_status':'FAIL'}
    def final_cancel(failed):
        receipt['cancelled']=True
        receipt['status']='FAIL' if failed or receipt['status']=='FAIL' or receipt['cleanup_status']!='PASS' else 'CANCELLED'
        try:save(output/'recovery-result.json',receipt)
        finally:publish_terminal(output,receipt,guard,2,prefix='recovery-terminal')
    try:
        save(output/'recovery-result.json',receipt)
        try:
            if not private.exists():
                need(owner['cleanup_verified'] and owner['private_removed'],'missing-raw-cleanup-unverified')
                receipt.update(status='PASS',private_data_removed=True,cleanup_status='PASS')
            else:
                runtime.owned_adopt(output,'private',owner['nonce'],owner['private_record'])
                broker_path=private/'broker-controller.json';storage_error=False
                if broker_path.exists() or broker_path.is_symlink():
                    try:
                        c=broker.load_controller(str(broker_path),digest(regular(broker_path)),allow_expired=True)
                        receipt['storage']=storage_projection(broker.storage_projection(c))
                    except BaseException:storage_error=True
                env=environment(private,contract,broker_ready=False)
                cleaned=owned_cleanup(owner,output,private,contract,runtime,broker,runtime.run_process,deadline,
                                      env,receipt,cancelled,recovery=True)
                if storage_error:
                    receipt['cleanup_reasons']=sorted(set(receipt['cleanup_reasons'])|{'storage-observation-unverified'})
                need(cleaned and not storage_error,'owned-cleanup-unverified')
                receipt['status']='PASS'
            elapsed=time.monotonic()-owner['started_monotonic']
            receipt['raw_retention_within_budget']=0<=elapsed<=BUDGET['raw_retention_seconds']
            if not receipt['raw_retention_within_budget'] and 'cleanup_reasons' in receipt:
                receipt['cleanup_reasons']=sorted(set(receipt['cleanup_reasons'])|{'retention-budget-exceeded'})
            need(receipt['raw_retention_within_budget'],'raw-retention-budget-exceeded')
        except BaseException as error:
            if type(error).__name__=='RuntimeCancelled' and not cancelled:cancelled.append(0)
            failure_diagnostics(receipt,'recovery-gpg',getattr(error,'receipt',None),runtime)
            receipt.update(status='FAIL',failure_class=type(error).__name__)
        finally:
            receipt['cancelled']=bool(cancelled)
            if cancelled and receipt['cleanup_status']=='PASS':receipt['status']='CANCELLED'
            receipt['phase']='finalized';save(output/'recovery-result.json',receipt)
            for revision in range(2):
                if cancelled and receipt['cleanup_status']=='PASS':receipt['status']='CANCELLED';receipt['cancelled']=True
                before=(receipt['status'],receipt['cancelled'])
                try:publish_terminal(output,receipt,guard,revision,prefix='recovery-terminal')
                except BaseException as error:receipt.update(status='FAIL',failure_class=type(error).__name__)
                if cancelled and receipt['cleanup_status']=='PASS':receipt['status']='CANCELLED';receipt['cancelled']=True
                save(output/'recovery-result.json',receipt)
                if cancelled and receipt['cleanup_status']=='PASS':receipt['status']='CANCELLED';receipt['cancelled']=True
                if before==(receipt['status'],receipt['cancelled']):break
    except BaseException as error:
        receipt.update(status='FAIL',failure_class=type(error).__name__)
        revoke_terminal(output,prefix='recovery-terminal')
        raise
    finally:
        finish_signals(previous,cancelled,final_cancel,original_mask)
    return receipt


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('freeze','run','cleanup'))
    parser.add_argument('--root',type=Path,default=ROOT)
    parser.add_argument('--source-commit');parser.add_argument('--ready-sha256',default=READY_SHA)
    parser.add_argument('--bootstrap-source-sha256');parser.add_argument('--bootstrap-stage-sha256')
    parser.add_argument('--controller',type=Path);parser.add_argument('--controller-sha256')
    parser.add_argument('--ownership-sha256')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        if args.mode=='freeze':
            checksum=freeze(args.root,args.source_commit,args.ready_sha256,args.output,
                            args.bootstrap_source_sha256,args.bootstrap_stage_sha256)
            print(json.dumps({'source_freeze':'PASS','controller_sha256':checksum,'native_compilation':'NOT RUN'}))
        elif args.mode=='run':
            result=pipeline(args.root,args.controller,args.controller_sha256,args.output)
            print(json.dumps(public_summary(result),sort_keys=True));sys.exit(0 if result['status']=='PASS' else 1)
        else:
            result=recover(args.root,args.controller,args.controller_sha256,args.output,args.ownership_sha256)
            print(json.dumps(public_summary(result),sort_keys=True));sys.exit(0 if result['status']=='PASS' else 1)
    except BaseException as error:
        print(json.dumps({'status':'FAIL','failure_class':type(error).__name__}));sys.exit(1)
