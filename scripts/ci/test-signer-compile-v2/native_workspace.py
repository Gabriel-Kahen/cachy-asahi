# SPDX-License-Identifier: MIT
"""Deferred fixed workspace allocation; Root supplies all authority and runtime."""
import math
from pathlib import Path
import re
import stat

class Refused(ValueError):pass
def need(value,code):
    if not value:raise Refused(code)
def identity(row):
    return tuple(getattr(row,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink'))

class NativeWorkspaceFactory:
    """Borrow Root ancestry; own allocations until successful Workspace transfer.

    close() closes only helper-owned FDs once. Directory effects are retained for
    Root artifact custody; neither close nor failure deletes any named object.
    """
    def __init__(self,workspace_class=None,*,expected_workspace_class=None,
                 provision=None,expected_provision=None,admission=None,expected_admission=None,
                 ancestry=None,expected_ancestry=None,io=None,expected_io=None,clock=None,
                 cancel=None,cancel_types=(KeyboardInterrupt,)):
        need(type(admission) is object and admission is expected_admission and
             type(ancestry) is object and ancestry is expected_ancestry,'Root-workspace-factory-admission')
        need(callable(workspace_class) and workspace_class is expected_workspace_class and
             type(provision) is dict and provision is expected_provision and io is not None and io is expected_io
             and callable(clock) and callable(cancel),'Root-closed-workspace-bindings')
        need(set(provision)=={'base_fd','base_path','base_identity','job_name','child_uid','child_gid','ancestors'},
             'closed-workspace-provision')
        base=provision['base_path'];name=provision['job_name']
        need(type(base) is str and Path(base).is_absolute() and str(Path(base))==base and '..' not in Path(base).parts
             and len(base)<=1024 and all(32<=ord(c)<127 for c in base),'Root-base-path')
        need(type(name) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,79}',name),'Root-job-leaf')
        need(all(type(provision[k]) is int and 0<provision[k]<2**31 for k in ('child_uid','child_gid')),'Root-child-credentials')
        rows=provision['ancestors']
        need(type(rows) is tuple and 1<=len(rows)<=32,'Root-borrowed-ancestry')
        self.borrowed={};paths=[]
        for item in rows:
            need(type(item) is dict and set(item)=={'fd','path','identity'} and type(item['fd']) is int and item['fd']>=0
                 and item['fd'] not in self.borrowed and type(item['path']) is str
                 and Path(item['path']).is_absolute() and str(Path(item['path']))==item['path']
                 and '..' not in Path(item['path']).parts,'Root-ancestry-row')
            value=item['identity']
            need(type(value) is tuple and len(value)==6 and all(type(n) is int and n>=0 for n in value)
                 and stat.S_ISDIR(value[2]) and value[5]>=1,'Root-ancestry-identity')
            self.borrowed[item['fd']]=dict(path=item['path'],identity=value);paths.append(item['path'])
        need(paths[0]=='/' and paths[-1]==base and all(str(Path(paths[i]).parent)==paths[i-1] for i in range(1,len(paths))),
             'Root-complete-ancestry')
        fd=provision['base_fd'];value=provision['base_identity']
        need(type(fd) is int and fd>=0 and fd in self.borrowed and self.borrowed[fd]==dict(path=base,identity=value) and
             value[3:5]==(0,0) and stat.S_IMODE(value[2])==0o755,'Root-protected-child-traversable-base')
        need(type(cancel_types) is tuple and cancel_types and all(isinstance(t,type) and issubclass(t,BaseException) for t in cancel_types),
             'Root-cancel-types')
        self.cls,self.provision,self.io,self.clock,self.cancel=workspace_class,dict(provision),io,clock,cancel
        self.admission,self.ancestry,self.cancel_types=admission,ancestry,cancel_types
        self.owned={};self.effects=[];self.started=self.transferred=self.closed=False
        self.first=None;self.cancelled=self.uncertain=False;self.last=None;self.work_end=self.cleanup_end=None;self.close_result=None

    def _remember(self,error):
        if self.first is None:self.first=error
        self.cancelled|=isinstance(error,self.cancel_types)

    def _live(self,end,cleanup=False):
        now=self.clock()
        need(type(now) in (int,float) and math.isfinite(now) and (self.last is None or now>=self.last),'factory-clock')
        self.last=now
        if not cleanup:self.cancel()
        need(now<end,'factory-original-deadline')

    def _borrowed_guard(self):
        for fd,item in self.borrowed.items():
            need(identity(self.io.fstat(fd))==item['identity']==identity(self.io.stat(item['path'],follow_symlinks=False)),
                 'borrowed-held-named-drift')

    def _guard_fd(self,fd):
        item=self.owned[fd];need(item['identity'] is not None,'unbound-owned-FD')
        need(identity(self.io.fstat(fd))==item['identity']==identity(self.io.stat(item['name'],dir_fd=item['parent'],follow_symlinks=False)),
             'owned-held-named-drift')

    def _guard(self):
        self._live(self.work_end);self._borrowed_guard()
        for fd,item in self.owned.items():
            if not item['transferred']:self._guard_fd(fd)
        self._live(self.work_end)

    def _refresh_parent(self,fd):
        item=self.borrowed[fd] if fd in self.borrowed else self.owned[fd]
        actual=identity(self.io.fstat(fd))
        need(actual[:5]==item['identity'][:5] and actual[5]>=1,'own-mkdir-parent-anchor')
        named=self.io.stat(item['path'],follow_symlinks=False) if fd in self.borrowed else self.io.stat(item['name'],dir_fd=item['parent'],follow_symlinks=False)
        need(identity(named)==actual,'own-mkdir-parent-binding');item['identity']=actual
        if fd in self.owned:self.effects[item['effect']]['identity']=actual

    def _create(self,parent,parent_path,name,mode,owner):
        self._guard();path=str(Path(parent_path)/name)
        effect=dict(path=path,parent_fd=parent,name=name,identity=None,creation='STARTED')
        self.effects.append(effect);index=len(self.effects)-1
        try:self.io.mkdir(name,0o700,dir_fd=parent)
        except FileExistsError:effect['creation']='NOT_CREATED';raise
        except BaseException:effect['creation']='UNKNOWN';self.uncertain=True;raise
        effect['creation']='CREATED';self._live(self.work_end)
        expected=identity(self.io.stat(name,dir_fd=parent,follow_symlinks=False));effect['identity']=expected
        need(stat.S_ISDIR(expected[2]) and expected[3:5]==(0,0) and expected[5]>=1,'fresh-Root-directory')
        self._refresh_parent(parent);self._live(self.work_end)
        try:fd=self.io.open(name,self.io.O_RDONLY|self.io.O_DIRECTORY|self.io.O_NOFOLLOW|self.io.O_NONBLOCK,dir_fd=parent)
        except BaseException:self.uncertain=True;raise
        unique=type(fd) is int and fd>=0 and fd not in self.borrowed and fd not in self.owned
        if not unique:self.uncertain=True
        need(unique,'new-owned-FD')
        self.owned[fd]=dict(path=path,name=name,parent=parent,identity=None,effect=index,transferred=False,close_attempted=False,close_completed=False)
        actual=identity(self.io.fstat(fd));self.owned[fd]['identity']=actual
        need(actual==expected,'fresh-open-identity');self._guard_fd(fd);self._live(self.work_end)
        self.io.fchmod(fd,mode)
        after=identity(self.io.fstat(fd))
        need(after[:2]==actual[:2] and stat.S_ISDIR(after[2]) and stat.S_IMODE(after[2])==mode
             and after[3:]==actual[3:],'owned-fchmod-result')
        self.owned[fd]['identity']=after;effect['identity']=after;self._guard_fd(fd);self._live(self.work_end)
        if owner!=(0,0):
            self.io.fchown(fd,*owner);after_owner=identity(self.io.fstat(fd))
            need(after_owner[:3]==after[:3] and after_owner[3:5]==owner and after_owner[5]==after[5],'owned-fchown-result')
            self.owned[fd]['identity']=after_owner;effect['identity']=after_owner;self._guard_fd(fd);self._live(self.work_end)
        return fd,path

    def __call__(self,work_end,cleanup_end):
        need(not self.started and not self.closed,'factory-once')
        need(all(type(n) in (int,float) and math.isfinite(n) for n in (work_end,cleanup_end)) and work_end<cleanup_end,
             'factory-original-frame')
        self.started=True;self.work_end,self.cleanup_end=work_end,cleanup_end
        try:
            self._guard();need(self.io.getuid()==self.io.geteuid()==self.io.getgid()==self.io.getegid()==0,'actual-Root-parent')
            p=self.provision
            job,job_path=self._create(p['base_fd'],p['base_path'],p['job_name'],0o755,(0,0))
            inputs,input_path=self._create(job,job_path,'inputs',0o755,(0,0))
            outputs,output_path=self._create(job,job_path,'outputs',0o700,(p['child_uid'],p['child_gid']))
            self._guard()
            workspace=self.cls(admission=self.admission,expected_admission=self.admission,
                ancestry=self.ancestry,expected_ancestry=self.ancestry,input_fd=inputs,input_path=input_path,
                output_fd=outputs,output_path=output_path,child_uid=p['child_uid'],child_gid=p['child_gid'],
                work_end=work_end,cleanup_end=cleanup_end,cancel=self.cancel,cancel_types=self.cancel_types,
                os_api=self.io,clock=self.clock)
            self._guard()
            self.owned[inputs]['transferred']=self.owned[outputs]['transferred']=True
            self.transferred=True;return workspace
        except BaseException as error:
            self._remember(error);self.close();raise

    def close(self):
        need(not self.closed,'factory-close-once');self.closed=True
        if self.started:
            for fd,item in reversed(tuple(self.owned.items())):
                if item['transferred']:continue
                item['close_attempted']=True
                try:
                    self._live(self.cleanup_end,cleanup=True);self._borrowed_guard();self._guard_fd(fd)
                    self.io.close(fd);item['close_completed']=True;self._live(self.cleanup_end,cleanup=True)
                except BaseException as error:self.uncertain=True;self._remember(error)
        self.uncertain|=any(e['creation'] in ('STARTED','UNKNOWN') or e['creation']=='CREATED' and e['identity'] is None for e in self.effects)
        self.close_result=dict(status='PASS_HELPER_FDS_RETIRED_DIRECTORIES_RETAINED' if self.first is None and not self.cancelled and not self.uncertain else 'FAIL',
            first_cause=None if self.first is None else type(self.first).__name__,cancelled=self.cancelled,uncertain=self.uncertain,
            owned_FDs_retired=all(item['close_completed'] for item in self.owned.values() if not item['transferred']),
            transferred=self.transferred,retained_directory_effects=[dict(e) for e in self.effects],
            directory_absence_claimed=False,borrowed_FDs_closed=False,
            workspace_FDs_closed_by_helper=False if self.transferred else None)
        return self.close_result
