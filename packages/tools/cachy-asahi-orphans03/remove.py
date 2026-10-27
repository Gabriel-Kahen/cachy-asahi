#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite exact leaf removal. No hooks, scripts, recursion, package fetch or shell."""
import argparse,ctypes as C,errno,hashlib,importlib.machinery,importlib.util,json,os,re,signal,stat,time,threading
from pathlib import Path

HERE=Path(__file__).resolve().parent
CORE=HERE/'cachy-asahi-orphans'
if not CORE.is_file():CORE=HERE/'readonly.py'
loader=importlib.machinery.SourceFileLoader('orphans_readonly',str(CORE))
spec=importlib.util.spec_from_loader(loader.name,loader);O=importlib.util.module_from_spec(spec);loader.exec_module(O)
need=O.need
FLAGS=(1<<7)|(1<<10)  # NOHOOKS|NOSCRIPTLET: retain deps, versions, conflicts and lock.
MAX_FILES=32768;MAX_SELECTED_FILES=4096;MAX_RECEIPT=65536
BLOCKED=('usr/share/libalpm','usr/share/systemd','usr/share/dbus-1','usr/share/polkit-1',
         'usr/share/alsa','usr/share/pipewire','usr/share/wireplumber','usr/bin/speakersafetyd','usr/bin/asahi-audio')
HELPERS=('usr/bin/ldconfig','usr/sbin/ldconfig','sbin/ldconfig')


def same_snapshot(current,saved,*,locked=False,removed=()):
    """Only lock/package-removal changes to directory size/times are permitted."""
    actual=dict(current['nodes']);expected=dict(saved['nodes'])
    if locked:need('db.lck' in actual,'owned lock missing from snapshot');actual.pop('db.lck')
    for path in list(expected):
        if any(path=='local/'+n+'-'+v or path.startswith('local/'+n+'-'+v+'/') for n,v in removed):expected.pop(path)
    for path in ('.','local') if removed else ('.',):
        a=dict(actual[path]);b=dict(expected[path])
        if path=='local' and b['links']>1:b['links']-=len(removed)
        for key in ('bytes','mtime_ns','ctime_ns'):a.pop(key);b.pop(key)
        need(a==b,'database directory replaced or permissions changed');actual[path]=a;expected[path]=b
    need(actual==expected,'installed database is stale or changed')


def read_plan(path,pin,names):
    need(type(pin) is str and re.fullmatch('[0-9a-f]{64}',pin),'exact reviewed plan SHA256 required')
    need(type(names) is list and 0<len(names)<=O.MAX_PACKAGES and len(names)==len(set(names)) and all(type(n) is str and O.NAME.fullmatch(n) for n in names),'nonempty unique exact selections required')
    saved,record=O.json_file(path)
    need(record['sha256']==pin,'reviewed plan bytes differ')
    need(saved.get('operation')=='EXPLICIT_ORPHAN_REMOVAL_PLAN' and type(saved.get('selected')) is dict and set(saved['selected'])==set(names),'exact selected plan required')
    need(O.plan(Path(saved['assessment']),names)==saved,'reviewed plan is stale or changed')
    assessment,identity=O.json_file(Path(saved['assessment']))
    need(identity==saved['assessment_identity'],'assessment replaced or changed')
    return saved,record,assessment


def recheck_inputs(path,record,saved):
    value,again=O.json_file(path);need(again==record and value==saved,'plan replaced or changed')
    _,again=O.json_file(Path(saved['assessment']));need(again==saved['assessment_identity'],'assessment replaced or changed')


class OwnedLock:
    def __init__(self,db):
        self.db=db
        # ALPM creates mode000 locks: ownership is the bounded single-link inode
        # observed immediately after our successful transaction initialization.
        with O.directory(db) as (fd,_):info=os.stat('db.lck',dir_fd=fd,follow_symlinks=False)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==os.geteuid() and info.st_size<=64,'ordinary owned ALPM lock required')
        self.record=O.identity(info)
        self.check()
    def check(self):
        with O.directory(self.db) as (fd,_):info=os.stat('db.lck',dir_fd=fd,follow_symlinks=False)
        need(stat.S_ISREG(info.st_mode),'ALPM lock is no longer regular');record=O.identity(info)
        need(record==self.record,'ALPM lock replaced or changed; never clear it')


class File(C.Structure):_fields_=[('name',C.c_char_p),('size',C.c_long),('mode',C.c_uint)]
class Files(C.Structure):_fields_=[('count',C.c_size_t),('files',C.POINTER(File))]


class Transaction(O.Installed):
    """Only the fixed public ALPM16 removal/prepare/commit ABI is exposed."""
    def __init__(self,root,db):
        super().__init__(root,db);self.started=False;self.lock=None;self.db=db
        p=C.c_void_p
        declarations={'alpm_trans_init':([p,C.c_int],C.c_int),'alpm_trans_prepare':([p,C.POINTER(p)],C.c_int),'alpm_trans_commit':([p,C.POINTER(p)],C.c_int),
          'alpm_trans_release':([p],C.c_int),'alpm_remove_pkg':([p,p],C.c_int),'alpm_trans_get_add':([p],p),'alpm_trans_get_remove':([p],p),
          'alpm_db_get_pkg':([p,C.c_char_p],p),'alpm_pkg_has_scriptlet':([p],C.c_int),'alpm_pkg_get_backup':([p],p),
          'alpm_pkg_get_files':([p],C.POINTER(Files)),'alpm_errno':([p],C.c_int),'alpm_strerror':([C.c_int],C.c_char_p)}
        for name,(args,result) in declarations.items():getattr(self.lib,name).argtypes=args;getattr(self.lib,name).restype=result
    def ok(self,code,label):
        if code:raise O.Refused(label+': '+self.lib.alpm_strerror(self.lib.alpm_errno(self.handle)).decode())
    def begin(self):
        previous=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGTERM,signal.SIGINT})
        try:
            self.ok(self.lib.alpm_trans_init(self.handle,FLAGS),'transaction lock');self.started=True;self.lock=OwnedLock(self.db)
        finally:signal.pthread_sigmask(signal.SIG_SETMASK,previous)
    def packages(self,head):
        result={}
        for pointer in O.nodes(head,O.MAX_PACKAGES):
            name=self.name(pointer);need(name not in result,'duplicate transaction package');result[name]=self.lib.alpm_pkg_get_version(pointer).decode()
        return result
    def inventory(self):return self.packages(self.lib.alpm_db_get_pkgcache(self.lib.alpm_get_localdb(self.handle)))
    def pointer(self,name,version):
        pointer=self.lib.alpm_db_get_pkg(self.lib.alpm_get_localdb(self.handle),name.encode())
        need(pointer and self.lib.alpm_pkg_get_version(pointer).decode()==version,'exact removal identity changed');return pointer
    def files(self,name,version):
        pointer=self.pointer(name,version);head=self.lib.alpm_pkg_get_files(pointer);need(head and head.contents.count<=MAX_FILES,'bounded installed file list required')
        return [head.contents.files[i].name.decode('utf8') for i in range(head.contents.count)]
    def declarative(self,name,version):
        p=self.pointer(name,version);need(self.lib.alpm_pkg_has_scriptlet(p)==0 and not self.lib.alpm_pkg_get_backup(p),'selected scriptlet or backup semantics unsupported')
    def remove(self,name,version):self.ok(self.lib.alpm_remove_pkg(self.handle,self.pointer(name,version)),'exact remove')
    def prepare(self):
        details=C.c_void_p();code=self.lib.alpm_trans_prepare(self.handle,C.byref(details))
        # Error detail allocations belong to this finite process. Never interpret
        # an errno-dependent union as another type; process exit reclaims them.
        self.ok(code,'ALPM prepare')
        return self.packages(self.lib.alpm_trans_get_add(self.handle)),self.packages(self.lib.alpm_trans_get_remove(self.handle))
    def commit(self):
        details=C.c_void_p();self.ok(self.lib.alpm_trans_commit(self.handle,C.byref(details)),'ALPM commit')
    def cleanup(self,result):
        errors=[]
        if self.started:
            try:
                need(self.lock is not None,'lock identity not established; retain uncertain lock');self.lock.check()
                self.ok(self.lib.alpm_trans_release(self.handle),'ALPM transaction release');self.started=False;result['transaction_released']=True
            except BaseException as error:
                errors.append(str(error)[:300]);result['handle_abandoned']=True
                # alpm_release also releases transactions: do not let it unlink
                # a replaced/uncertain lock. Process exit reclaims the handle.
                result['cleanup_errors']=errors;return
        if self.handle:
            try:self.ok(self.lib.alpm_release(self.handle),'ALPM handle release');result['handle_released']=True;self.handle=None
            except BaseException as error:errors.append(str(error)[:300])
        result['cleanup_errors']=errors


def ordinary_path(text):
    need(type(text) is str and 0<len(text)<=512 and not text.startswith('/') and '\x00' not in text,'ordinary relative ownership path required')
    path=Path(text.rstrip('/'));need(path.as_posix()==text.rstrip('/') and all(p not in ('.','..') for p in path.parts),'ambiguous ownership path refused');return path


def payload_node(root,path,bounds):
    with O.directory(root/path.parent) as (fd,_):
        info=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
        need(info.st_uid in (0,os.geteuid()) and not info.st_mode&0o6000,'unsafe payload ownership or setid mode')
        if stat.S_ISDIR(info.st_mode):return dict(kind='directory',**O.identity(info))
        record,_=O.read(fd,path.name,bounds,128*1024**2);return dict(kind='file',**record)


def payload_guard(api,root,before,selected,*,allow_ldconfig=False):
    for helper in HELPERS:
        # lexists catches broken aliases too. No optional helper execution.
        with O.directory(root) as (fd,_):
            need(allow_ldconfig or not os.path.lexists(root/helper),'target ldconfig helper/alias unsupported')
    files={};others=set();bounds=O.limits();count=0
    for name,version in before.items():
        paths=api.files(name,version);count+=len(paths);need(count<=MAX_FILES,'installed ownership bound')
        if name in selected:api.declarative(name,version);files[name]=paths
        else:others.update(str(ordinary_path(p)) for p in paths)
    chosen={};directories={}
    for paths in files.values():
        for raw in paths:
            path=ordinary_path(raw);text=str(path)
            # Selected leaves may only own ordinary declarative userspace files.
            need(text in ('usr','usr/bin','usr/share') or text.startswith(('usr/bin/','usr/share/')),'selected platform/config/library path unsupported')
            need(not any(text==p or text.startswith(p+'/') for p in BLOCKED) and path.suffix!='.hook' and path.name not in {'speakersafetyd.service','asahi-audio.service'},'selected protected integration path')
            node=payload_node(root,path,bounds)
            if node['kind']=='directory':directories[text]=node
            else:need(text not in others and text not in chosen,'selected payload overlaps other ownership');chosen[text]=node
            need(len(chosen)+len(directories)<=MAX_SELECTED_FILES,'selected payload bound')
    # A shared directory may be removed by rmdir if all its payload disappears.
    # Require an actually present, unselected child outside the selection.
    retained=set()
    for text in others-set(chosen)-set(directories):
        if os.path.lexists(root/text):retained.update(str(p) for p in Path(text).parents)
    shared={text:node for text,node in directories.items() if text in others}
    need(set(shared)<=retained,'selected removal could remove an unselected-owned empty directory')
    # Every other owner is protected against removal through file aliasing;
    # selected regular files are single-link and all ancestors are no-follow.
    return chosen,shared


def initial_result():
    return dict(schema_version=1,status='REFUSED',phase='preflight',commit_started=False,packages_committed=False,
                transaction_released=False,handle_released=False,handle_abandoned=False,cleanup_errors=[],
                lock_state='NOT_OBSERVED',hardware='NOT_RUN',rollback='NOT_ATTEMPTED',scope='FINITE_DECLARATIVE_ORPHAN_REMOVAL')


def execute(args,save,*,factory=Transaction):
    result=initial_result();api=None
    try:
        saved,record,assessment=read_plan(args.plan,args.plan_sha256,args.select)
        root,db=Path(assessment['root']),Path(assessment['dbpath']);selected={n:saved['selected'][n]['version'] for n in saved['selected']}
        need(root!=Path('/'),'successor removes only from explicit offline roots')
        with O.directory(root) as (fd,_):
            info=os.fstat(fd);need(info.st_uid==os.geteuid() and not info.st_mode&0o022,'private caller-owned offline target required')
        binding=dict(selected=selected,root=str(root),dbpath=str(db),plan_identity=record,assessment_identity=saved['assessment_identity'])
        need(len(O.encoded(binding))+2*len(O.encoded(selected))<MAX_RECEIPT-16384,'selection exceeds finite result reporting bound')
        result.update(binding)
        save(result);api=factory(root,db);api.begin();result['phase']='locked-revalidation';save(result)
        current,lost=O.inspect(root,db,assessment['extra_protected'],list(selected),owned_lock=api.lock)
        same_snapshot(current['database'],assessment['database'],locked=True)
        need({k:v for k,v in current.items() if k!='database'}=={k:v for k,v in assessment.items() if k!='database'},'dependency/protection facts changed')
        need(not lost and not current['broken_dependencies'] and all(current['packages'][n]['candidate'] for n in selected),'protected/needed or inconsistent selection')
        before={n:r['version'] for n,r in current['packages'].items()};need(api.inventory()==before,'transaction cache differs from fresh installed facts')
        chosen,directories=payload_guard(api,root,before,selected)
        result.update(before_inventory_sha256=O.digest(O.encoded(before)),before_count=len(before),phase='prepare');save(result)
        for name,version in selected.items():api.remove(name,version)
        additions,removals=api.prepare();result.update(prepared_add=additions,prepared_remove=removals)
        need(additions=={} and removals==selected,'ALPM prepared a different selection')
        api.lock.check();recheck_inputs(args.plan,record,saved)
        snapshot,_=O.database_snapshot(db,owned_lock=api.lock);same_snapshot(snapshot,current['database'])
        # Payload cannot drift while preparing, even though ALPM locks only DB.
        for path,node in chosen.items():need(payload_node(root,Path(path),O.limits())==node,'selected payload replaced or changed')
        result.update(phase='commit',commit_started=True,packages_committed='UNKNOWN');save(result)
        api.commit();result['packages_committed']=True;result['phase']='postcommit';save(result)
        api.lock.check();after,_=O.inspect(root,db,assessment['extra_protected'],owned_lock=api.lock)
        need({n:r['version'] for n,r in after['packages'].items()}=={n:v for n,v in before.items() if n not in selected},'postcommit installed package set differs')
        same_snapshot(after['database'],assessment['database'],locked=True,removed=tuple(selected.items()))
        for path in chosen:need(not os.path.lexists(root/path),'selected payload remains after commit')
        for path,before_dir in directories.items():
            after_dir=payload_node(root,Path(path),O.limits())
            need(all(after_dir[k]==before_dir[k] for k in ('kind','dev','ino','mode','uid','gid')),'unselected-owned shared directory removed or replaced')
        result.update(after_inventory_sha256=O.digest(O.encoded({n:r['version'] for n,r in after['packages'].items()})),after_count=len(after['packages']),status='APPLIED',phase='complete')
    except BaseException as error:
        result.update(status='FAILED' if result['commit_started'] else 'REFUSED',error_type=type(error).__name__,reason=str(error)[:500])
    finally:
        if api is not None:api.cleanup(result)
        try:
            if 'dbpath' in result:
                O.unlocked(Path(result['dbpath']));result['lock_state']='ABSENT'
        except BaseException:result['lock_state']='PRESENT_OR_UNCERTAIN'
        if result['cleanup_errors'] or result['lock_state']=='PRESENT_OR_UNCERTAIN':result['status']='FAILED'
        if result['commit_started'] and result['status']!='APPLIED':result['recovery']='OUTCOME_UNCERTAIN_REVIEW_TARGET_AND_LOCK_DO_NOT_RETRY_OR_AUTO_UNLOCK'
        save(result)
    return result


class Receipt:
    """New single-link private output. Hold fd; never overwrite a replacement."""
    def __init__(self,path):
        self.path=O.absolute(path);self.fd=None
        with O.directory(self.path.parent) as (fd,_):
            info=os.fstat(fd);need(info.st_uid==os.geteuid() and not info.st_mode&0o022,'private caller-owned result parent required')
            self.parent=(info.st_dev,info.st_ino)
            self.fd=os.open(self.path.name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd);os.fsync(fd)
        self.node=os.fstat(self.fd)
    def check(self):
        with O.directory(self.path.parent) as (fd,_):
            parent=os.fstat(fd);need((parent.st_dev,parent.st_ino)==self.parent and parent.st_uid==os.geteuid() and not parent.st_mode&0o022,'result parent replaced or unsafe')
            info=os.stat(self.path.name,dir_fd=fd,follow_symlinks=False)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and (info.st_dev,info.st_ino)==(self.node.st_dev,self.node.st_ino) and stat.S_IMODE(info.st_mode)==0o600 and info.st_uid==os.geteuid(),'result replaced or unsafe')
    def save(self,value):
        self.check();raw=O.encoded(value);need(len(raw)<=MAX_RECEIPT,'result size bound');os.lseek(self.fd,0,os.SEEK_SET)
        while raw:written=os.write(self.fd,raw);need(written>0,'result write failed');raw=raw[written:]
        os.ftruncate(self.fd,os.lseek(self.fd,0,os.SEEK_CUR));os.fsync(self.fd);self.check()
    def read(self):
        self.check();os.lseek(self.fd,0,os.SEEK_SET);return json.loads(os.read(self.fd,MAX_RECEIPT+1))
    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None


def supervise(args,receipt,*,work=execute):
    """One reaper: reserve the child through the last signal, then waitpid."""
    need(threading.current_thread() is threading.main_thread() and threading.active_count()==1,'single main-thread child owner required')
    need(signal.getsignal(signal.SIGCHLD)==signal.SIG_DFL,'default owned-child reaping disposition required')
    need(hasattr(os,'waitid') and hasattr(os,'WNOWAIT'),'WNOWAIT child ownership required')
    signal.signal(signal.SIGCHLD,signal.SIG_DFL)  # Clear inherited SA_NOCLDWAIT.
    receipt.save(initial_result());parent=os.getpid()
    requested=[];old={};pid=None;owned=False;wait_status=None;termination=None;fault=None;old_mask=None
    cancellation={signal.SIGTERM,signal.SIGINT,signal.SIGALRM}
    def request(signum,frame):requested.append(signum)
    def observe():
        nonlocal owned,fault
        if not owned:return None
        try:
            row=os.waitid(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
            if row is not None:need(row.si_pid==pid and row.si_code in (os.CLD_EXITED,os.CLD_KILLED,os.CLD_DUMPED),'unexpected child observation')
            return row
        except BaseException as error:
            owned=False;fault=type(error).__name__+': '+str(error)[:300];return None
    def send(signum):
        nonlocal owned,fault
        observe()
        if not owned:return False
        try:os.kill(pid,signum);return True
        except BaseException as error:
            owned=False;fault=type(error).__name__+': '+str(error)[:300];return False
    try:
        for signum in cancellation:old[signum]=signal.signal(signum,request)
        old_mask=signal.pthread_sigmask(signal.SIG_BLOCK,cancellation)
        pid=os.fork()
        if pid==0:
            try:
                libc=C.CDLL(None,use_errno=True);libc.prctl.argtypes=[C.c_int,C.c_ulong,C.c_ulong,C.c_ulong,C.c_ulong];libc.prctl.restype=C.c_int
                need(libc.prctl(1,signal.SIGKILL,0,0,0)==0 and os.getppid()==parent,'parent-death guard failed')
                def cancel(signum,frame):raise InterruptedError('removal worker interrupted')
                for signum in cancellation:signal.signal(signum,cancel)
                signal.pthread_sigmask(signal.SIG_SETMASK,old_mask)
                value=work(args,receipt.save);os._exit(0 if value['status']=='APPLIED' else 1)
            except BaseException:os._exit(2)
        owned=True
        # Pending cancellation is delivered only after the PID has an owner.
        signal.pthread_sigmask(signal.SIG_SETMASK,old_mask);old_mask=None
        until=time.monotonic()+args.timeout_seconds;kill_at=None
        while owned:
            if observe() is not None:break
            if not owned:break
            now=time.monotonic()
            if termination is None and (requested or now>=until):
                termination='CANCELLED' if requested else 'TIMEOUT'
                if not send(signal.SIGTERM):break
                kill_at=now+2
            elif kill_at is not None and now>=kill_at:
                send(signal.SIGKILL);break
            time.sleep(0.02)
    except BaseException as error:
        termination='SUPERVISOR_ERROR';fault=type(error).__name__+': '+str(error)[:300]
    finally:
        # Every numeric signal is preceded by a successful WNOWAIT observation.
        # No wait/poll has released the PID yet. Lost ownership is permanent.
        row=observe()
        if owned and row is None:send(signal.SIGKILL)
        cleanup_until=time.monotonic()+2
        while owned:
            row=observe()
            if not owned:break
            if row is not None:
                try:
                    child,status=os.waitpid(pid,os.WNOHANG)
                    need(child==pid,'terminal child final reap not observed')
                    wait_status=status;owned=False
                except OSError as error:
                    fault=type(error).__name__+': '+str(error)[:300];termination='SUPERVISOR_ERROR'
                    if isinstance(error,ChildProcessError) or error.errno==errno.ECHILD:owned=False
                    elif time.monotonic()<cleanup_until:continue  # Reobserve; no later signals.
                except BaseException as error:
                    owned=False;fault=type(error).__name__+': '+str(error)[:300];termination='SUPERVISOR_ERROR'
                break
            if time.monotonic()>=cleanup_until:break
            time.sleep(0.02)
        if old_mask is not None:signal.pthread_sigmask(signal.SIG_SETMASK,old_mask)
        for signum,handler in old.items():signal.signal(signum,handler)
    try:result=receipt.read()
    except (ValueError,OSError):result=dict(initial_result(),commit_started='UNKNOWN',packages_committed='UNKNOWN',reason='incomplete worker receipt')
    code=os.waitstatus_to_exitcode(wait_status) if wait_status is not None else None
    result['worker']=dict(reaped=wait_status is not None,exitcode=code,termination=termination,ownership='REAPED' if wait_status is not None else 'UNKNOWN')
    if fault:result['worker']['error']=fault
    if wait_status is None:
        result.update(status='FAILED',last_durable_commit_started=result.get('commit_started'),last_durable_packages_committed=result.get('packages_committed'),commit_started='UNKNOWN',packages_committed='UNKNOWN')
    elif termination or code!=0 or result.get('status')!='APPLIED':
        result['status']='FAILED' if result.get('commit_started') else 'REFUSED'
        if result.get('phase')=='commit' and result.get('packages_committed') is not True:result['packages_committed']='UNKNOWN'
    if result['status']!='APPLIED':result['recovery']='REVIEW_RECEIPT_TARGET_AND_LOCK_NO_AUTOMATIC_RETRY_OR_UNLOCK'
    receipt.save(result);return result


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('plan',type=Path);p.add_argument('--plan-sha256',required=True)
    p.add_argument('--select',action='append',required=True);p.add_argument('--result',type=Path,required=True);p.add_argument('--timeout-seconds',type=int,default=60)
    a=p.parse_args(argv);receipt=None;delegated=False
    try:
        need(1<=a.timeout_seconds<=120,'timeout must be between 1 and 120 seconds')
        # Refuse result inside target before creating it; report input identity
        # is also checked again by the worker and immediately before commit.
        _,_,assessment=read_plan(a.plan,a.plan_sha256,a.select)
        need(Path(assessment['root'])!=Path('/'),'successor removes only from explicit offline roots')
        need(not O.absolute(a.result).is_relative_to(Path(assessment['root'])),'result must be outside target root')
        receipt=Receipt(a.result);delegated=True;result=supervise(a,receipt)
        print(json.dumps(result,sort_keys=True));return 0 if result['status']=='APPLIED' else 1
    except (O.Refused,OSError,ValueError,TypeError,KeyError,RecursionError) as error:
        result=initial_result()
        if delegated:
            result.update(status='FAILED',commit_started='UNKNOWN',packages_committed='UNKNOWN',recovery='REVIEW_TARGET_AND_LAST_DURABLE_RECEIPT_NO_RETRY_OR_UNLOCK')
            try:
                last=receipt.read()
                if last.get('commit_started') is True or last.get('packages_committed') is True:result.update(last,status='FAILED')
            except (O.Refused,OSError,ValueError):pass
        result.update(reason=str(error)[:500],error_type=type(error).__name__)
        print(json.dumps(result,sort_keys=True));return 1
    finally:
        if receipt is not None:receipt.close()


if __name__=='__main__':raise SystemExit(main())
