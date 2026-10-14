# SPDX-License-Identifier: MIT
"""Root-admitted worker session successor; import performs no actor operation.

Root selects this Source, the worker and its native admission independently.
Private stdout is never streamed. No syscall hard-preemption is claimed.
"""
import json
import hashlib
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import time

RETAINED = []
PREFIX = 'org.cachy-asahi.pair.'


def need(ok, code):
    if not ok: raise ValueError(code)


def decode(raw):
    need(type(raw) is bytes and len(raw) <= 1024**2, 'guardian-private-bound')
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'guardian-duplicate-json'); value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'guardian-nonfinite-json'))


def root_identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid)


def read_journal(root_fd,budget,uid):
    slot={'fd':None,'resource':'owned-resource-journal'};RETAINED.append(slot);first=None;data=bytearray()
    try:
        budget.call(lambda:slot.update(fd=os.open('resources.jsonl',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=root_fd)))
        before=budget.call(lambda:os.fstat(slot['fd']))
        need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_uid==uid and
             stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=32*1024**2,'guardian-journal-file')
        while len(data)<before.st_size:
            raw=budget.call(lambda:os.pread(slot['fd'],min(65536,before.st_size-len(data)),len(data)))
            need(raw,'guardian-journal-short');data.extend(raw)
        after=budget.call(lambda:os.fstat(slot['fd']))
        need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'guardian-journal-drift')
        need(data.endswith(b'\n'),'guardian-journal-truncated')
        rows=data.splitlines();need(0<len(rows)<=65536 and all(len(row)<=256*1024 for row in rows),'guardian-journal-frames')
        result=budget.call(lambda:decode(bytes(rows[-1])))
    except BaseException as error:first=error
    if slot['fd']is not None:
        try:
            def closed():os.close(slot['fd']);slot['closed']=True
            budget.call(closed);slot['fd']=None
        except BaseException as error:first=first or error
    if first is not None:slot['uncertainty']=first;raise first
    RETAINED.remove(slot);return result



class Budget:
    def __init__(self, authority, start, J):
        need(type(start) in (int,float) and type(J) in (int,float) and
             math.isfinite(start) and math.isfinite(J) and start>0 and J==start+7200,
             'guardian-original-clock')
        self.authority=authority; self.start=start; self.J=J; self.E=J-360
        self.end=J-180; self.first=None; self.last=None; self.stopped=False

    def fail(self, error):
        if self.first is None:
            self.first=error
            try:observed=time.monotonic()
            except BaseException:observed=self.last if self.last is not None else self.start
            if type(observed)not in(int,float)or not math.isfinite(observed)or observed<self.start:
                observed=self.last if self.last is not None else self.start
            try:old=getattr(error,'first_failure_at',None)
            except BaseException:old=None
            if type(old) in (int,float) and math.isfinite(old) and 0<old<=observed:
                observed=min(observed,old)
            self.end=min(self.end,observed+180)
            try:error.first_failure_at=observed
            except BaseException:pass
            try:self.authority.record_failure(error,cleanup=observed>=self.E)
            except BaseException as secondary:
                try:error.add_note('Root first-cause recording uncertainty: '+type(secondary).__name__)
                except BaseException:pass
        return self.first

    def check(self, end=None):
        need(not self.stopped,'guardian-stopped')
        try:
            now=time.monotonic(); ceiling=self.end if end is None else min(end,self.J)
            need(type(now) in (int,float) and math.isfinite(now) and self.start<=now<ceiling and
                 (self.last is None or now>=self.last),'guardian-original-cutoff')
            self.last=now;self.authority.check(cleanup=now>=self.E or self.first is not None)
        except BaseException as error:
            self.stopped=True;self.fail(error);raise

    def call(self, action, end=None):
        self.check(end)
        try: value=action()
        except BaseException as error: self.fail(error); raise
        self.check(end);return value


class Physical:
    """Finite proc observation, retained FDs on failed postguards, pidfd signals."""
    def __init__(self,budget):
        self.budget=budget;self.members={};self.proven=set();self.close_attempted=set()
        self.pid=None;self.birth=None;self.reaped=False;self.receipt=None

    def row(self,pid):
        b=self.budget;slot={'fd':None,'path':f'/proc/{pid}/stat'};RETAINED.append(slot)
        first=None;raw=None
        try:
            def opened():
                try:slot['fd']=os.open(slot['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
                except FileNotFoundError:slot['missing']=True
            b.call(opened)
            if slot.get('missing'):
                RETAINED.remove(slot);return None
            raw=b.call(lambda:os.read(slot['fd'],4097));need(len(raw)<=4096,'guardian-proc-stat-bound')
        except BaseException as error:first=error
        if slot['fd'] is not None:
            try:b.call(lambda:os.close(slot['fd']));slot['fd']=None
            except BaseException as error:first=first or error
        if first is not None:
            slot['uncertainty']=first;raise first
        RETAINED.remove(slot)
        end=raw.rfind(b')');need(end>0,'guardian-proc-stat-shape')
        fields=raw[end+2:].split();need(len(fields)>=20,'guardian-proc-stat-shape')
        need(int(raw.split(b' ',1)[0])==pid,'guardian-proc-pid')
        return {'pid':pid,'group':int(fields[2]),'session':int(fields[3]),'start':int(fields[19])}

    def scan(self):
        names=self.budget.call(lambda:os.listdir('/proc'))
        pids=[int(n)for n in names if n.isascii()and n.isdigit()]
        need(len(pids)<=32768,'guardian-proc-members-bound');found=[]
        for pid in pids:
            row=self.row(pid)
            if row is None:continue
            if row['session']==self.pid:found.append(row)
        return found

    def bind(self,proc,tool):
        self.pid=proc.pid;row=self.row(proc.pid)
        need(row is not None and row['group']==row['session']==proc.pid,'guardian-new-session-required')
        self.birth=row
        self.budget.call(lambda:self.members.__setitem__(proc.pid,(row,os.pidfd_open(proc.pid,0))))
        need(self.row(proc.pid)==row,'guardian-start-drift')
        self.proven.add(proc.pid)
        executable=self.budget.call(lambda:os.stat(f'/proc/{proc.pid}/exe'))
        need((executable.st_dev,executable.st_ino)==tuple(tool.held_identity[:2]),'guardian-worker-executable')
        self.executable={'device':executable.st_dev,'inode':executable.st_ino,'sha256':tool.sha256}

    def retire(self,proc):
        # Keep the direct child unreaped until all session-member identities
        # have been enumerated. No killpg, numeric signal or poll fallback.
        if self.receipt is not None:return self.receipt
        for row in ([]if self.reaped else self.scan()):
            pid=row['pid']
            if pid not in self.members:
                self.budget.call(lambda:self.members.__setitem__(pid,(row,os.pidfd_open(pid,0))))
                need(self.row(pid)==row,'guardian-member-start-drift')
                self.proven.add(pid)
            else:need(self.members[pid][0]==row,'guardian-member-reuse')
        for number in (signal.SIGTERM,signal.SIGKILL):
            for pid,(row,fd) in tuple(self.members.items()):
                if pid not in self.proven or pid in self.close_attempted:continue
                try:self.budget.call(lambda fd=fd:signal.pidfd_send_signal(fd,number,None,0))
                except ProcessLookupError:pass
        if not self.reaped:
            def waited():
                value=proc.wait(timeout=max(0,min(2,self.budget.end-time.monotonic())));self.reaped=True
                if value!=0:self.budget.fail(ValueError('guardian-worker-exit'))
                return value
            self.budget.call(waited)
        need(self.scan()==[],'guardian-session-absence-unproved')
        need(self.row(self.pid)is None,'guardian-direct-proc-absence-unproved')
        for pid,(row,fd) in tuple(self.members.items()):
            need(pid not in self.close_attempted,'guardian-pidfd-close-uncertain')
            def closed(pid=pid,fd=fd):self.close_attempted.add(pid);os.close(fd)
            self.budget.call(closed);del self.members[pid]
        self.receipt={'pid':self.pid,'start':self.birth['start'],'session':self.birth['session'],
                'pidfd_used':True,'direct_reaped':True,'direct_proc_absent':True,'session_absent':True,
                'executable':getattr(self,'executable',None)}
        return self.receipt


def inspect_cleanup(handoff,spec,budget,docker_call):
    value=spec['value'];result=handoff['result']
    def docker(args):
        raw=budget.call(lambda:docker_call(tuple(args),budget.end))
        need(type(raw)is bytes and len(raw)<=1024**2,'guardian-docker-bound');return raw
    daemon=decode(docker(('info','--format','{{json .}}')))
    need(daemon.get('ID')==value['daemon_id'] and daemon.get('OSType')=='linux' and
         daemon.get('Architecture')in('arm64','aarch64'),'guardian-daemon-drift')
    root_fd=next(fd for path,fd,expected in spec['held_roots']if path==value['work_root'])
    journal=read_journal(root_fd,budget,value['uid'])
    need(journal['schema']==1 and journal['purpose']=='native-two-recipe-build-pair-owner' and
         journal['daemon_id']==value['daemon_id']and journal['nonce']==value['nonce']and
         journal['source_sha256']==spec['owner_source_sha256']and
         journal['context_sha256']==result['image']['context_sha256']and journal['cleanup_errors']==[],
         'guardian-journal-binding')
    containers=journal['containers'];images=journal['images']
    need(type(containers)is list and len(containers)==7 and {r['role']for r in containers}==
         {'provision','topmem-1','topmem-2','fish-1','fish-2','zsh-1','zsh-2'},'guardian-all-container-roles')
    need(type(images)is list and len(images)==2 and {r['role']for r in images}=={'rootfs','compiler'},'guardian-all-image-roles')
    for row in containers:
        need(all(row[k]is True for k in('attempted','confirmed','waited','removed'))and row['exit_code']==0,
             'guardian-container-journal-retirement')
        if row['role']!='provision':need(row['id']==result['builds'][row['role']]['container_id'],'guardian-build-cid-binding')
    full_ids=[row['id']for row in containers];need(len(set(full_ids))==7,'guardian-distinct-full-cids')
    for cid in full_ids:
        need(re.fullmatch('[0-9a-f]{64}',cid),'guardian-full-cid')
        need(not docker(('container','ls','--all','--no-trunc','--quiet','--filter','id='+cid)).strip(),
             'guardian-container-remains')
    image_ids=[row['id']for row in images]
    need(len(set(image_ids))==2 and all(re.fullmatch('sha256:[0-9a-f]{64}',i)for i in image_ids)and
         all(all(row[k]is True for k in('attempted','confirmed','removed'))for row in images)and
         next(row['id']for row in images if row['role']=='compiler')==result['image']['id'],'guardian-full-image')
    all_images=docker(('image','ls','--all','--no-trunc','--quiet')).decode('ascii').splitlines()
    need(len(all_images)<=4096 and not set(image_ids)&set(all_images),'guardian-image-remains')
    for kind in ('container','image'):
        need(not docker((kind,'ls','--all','--no-trunc','--quiet','--filter',
                         'label='+PREFIX+'nonce='+value['nonce'])).strip(),'guardian-nonce-resource-remains')
    roots=[]
    for path,fd,expected in spec['held_roots']:
        held=budget.call(lambda fd=fd:os.fstat(fd));named=budget.call(lambda path=path:os.lstat(path))
        need(root_identity(held)==root_identity(named)==tuple(expected)and stat.S_ISDIR(held.st_mode) and
             held.st_uid==value['uid'] and held.st_gid==value['gid'] and
             stat.S_IMODE(held.st_mode)in(0o700,0o755),'guardian-retained-root-drift')
        roots.append({'path':path,'identity':list(expected),'status':'ROOT_RETAINED_EVIDENCE'})
    need({row['path']for row in roots}=={value['work_root'],spec['pins']['integration']['native']['checker_root']},
         'guardian-root-closure')
    return {'daemon_id':value['daemon_id'],'full_container_ids_absent':full_ids,
            'full_image_ids_absent':image_ids,'nonce_resources_absent':True,'roots':roots}


def validate_handoff(raw,spec,contract):
    handoff=decode(raw)
    need(handoff['schema']==1 and handoff['status']=='PRIVATE_ROOT_CONTAINMENT_REQUIRED' and
         handoff['publication_allowed']is False,'guardian-private-status')
    value=spec['value'];J=value['workflow_end'];start=value['original_entry']
    need((handoff['original_start'],handoff['original_E'],handoff['original_J'],handoff['publication_end'])==
         (start,J-360,J,J),'guardian-worker-original-clock')
    need(handoff['packet_sha256']==spec['packet_sha']and handoff['driver_sha256']==spec['driver_sha'],
         'guardian-worker-source-binding')
    need(handoff['native_binding']==spec['native_binding']and handoff['native_selection']==spec['native_selection'],
         'guardian-native-binding')
    need(handoff['helper_cleanup']['publication_allowed']is False,'guardian-mapping-retirement-required')
    need(handoff['result']['native_build']=='PRIVATE_CHECKED','guardian-private-native-status')
    candidate=dict(handoff['result']);candidate['native_build']='PASS'
    contract.validate_result(candidate,spec['expected_job'])
    records=handoff['process_records'];need(type(records)is list and 0<len(records)<=8192,'guardian-child-record-bound')
    for row in records:
        need(row['kind']in('docker','gpg')and row['code']==0 and row['scope']=='direct-child-only' and
             row['identity']['pidfd_used']is True and type(row['identity']['pid'])is int and row['identity']['pid']>0 and
             row['identity']['tool_sha256']==value['tools'][row['kind']], 'guardian-cli-retirement-source-binding')
    return handoff


def launch(spec,*,process_owner,python_tool,contract,authority,observer,docker_call,environment,publish):
    """Run Root-selected worker; store checked candidate privately after absence.

    Root passes already authenticated Authority/observer, held root FDs and
    pinned interpreter. These capabilities are not constructed or granted here.
    Retained work/checker roots contain artifacts; this does not delete them.
    publish is Parent's private-store callback. Parent retires its own Source,
    observer and tools and restores controls before its separate public write.
    """
    value=spec['value'];b=Budget(authority,value['original_entry'],value['workflow_end'])
    proc=selector=pipe=None;physical=Physical(b);output=bytearray();slot={};RETAINED.append(slot)
    try:
        b.check(b.E)
        need(b.call(lambda:(authority.start,authority.E,authority.J,authority.execution_granted),b.E)==
             (b.start,b.E,b.J,True),'guardian-Root-admission-binding')
        need(type(environment)is dict,'guardian-explicit-environment')
        expected_env={'GITHUB_REPOSITORY':'Gabriel-Kahen/cachy-asahi','GITHUB_SHA':value['source_commit'],
                      'GITHUB_WORKFLOW_SHA':value['workflow_commit'],'GITHUB_RUN_ID':value['run_id'],
                      'GITHUB_RUN_ATTEMPT':value['run_attempt']}
        need(all(environment.get(k)==v for k,v in expected_env.items()),'guardian-current-job-environment')
        worker_env=expected_env|{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TZ':'UTC','HOME':spec['cwd']}
        b.call(lambda:observer.capture('source'),b.E)
        need(type(python_tool)is process_owner.VerifiedTool,'guardian-held-interpreter')
        b.call(lambda:python_tool.verify(b.E),b.E);b.call(process_owner.single_threaded,b.E)
        parent_path,parent_fd,parent_id=spec['work_parent_node']
        need(os.path.dirname(value['work_root'])==parent_path,'guardian-work-parent-binding')
        parent=b.call(lambda:os.fstat(parent_fd),b.E);parent_named=b.call(lambda:os.lstat(parent_path),b.E)
        need(root_identity(parent)==root_identity(parent_named)==tuple(parent_id)and stat.S_ISDIR(parent.st_mode)and
             parent.st_uid==value['uid']and stat.S_IMODE(parent.st_mode)==0o700,'guardian-work-parent-custody')
        def absent():
            try:os.stat(os.path.basename(value['work_root']),dir_fd=parent_fd,follow_symlinks=False)
            except FileNotFoundError:return True
            return False
        need(b.call(absent,b.E),'guardian-work-root-not-fresh')
        # Worker must create its reviewed Docker/GPG children. Their selected
        # owners install NoFork independently; no inherited worker filter may
        # prohibit their legitimate fork/initial setsid. Root explicitly admits
        # the selected worker/native Source's bounded child/session assumption.
        need(spec['trusted_worker_children_stay_owned']is True,'guardian-worker-source-policy')
        worker_path,worker_fd,worker_identity=spec['worker_node']
        need(worker_path==spec['worker_path'] and type(worker_fd)is int and worker_fd>=0 and
             worker_fd!=python_tool.fd and re.fullmatch('[0-9a-f]{64}',spec['worker_sha']), 'guardian-held-worker-source')
        def ident(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        held=b.call(lambda:os.fstat(worker_fd),b.E);named=b.call(lambda:os.lstat(worker_path),b.E)
        need(ident(held)==ident(named)==tuple(worker_identity) and stat.S_ISREG(held.st_mode)and
             held.st_nlink==1,'guardian-worker-source-drift')
        need(0<held.st_size<=1024**2,'guardian-worker-source-bound')
        worker_raw=bytearray()
        while len(worker_raw)<held.st_size:
            chunk=b.call(lambda:os.pread(worker_fd,min(65536,held.st_size-len(worker_raw)),len(worker_raw)),b.E)
            need(chunk,'guardian-worker-short');worker_raw.extend(chunk)
        need(b.call(lambda:hashlib.sha256(worker_raw).hexdigest(),b.E)==spec['worker_sha'],'guardian-worker-pin')
        need(ident(b.call(lambda:os.fstat(worker_fd),b.E))==tuple(worker_identity),'guardian-worker-source-drift')
        argv=[python_tool.path,'-I','-B','/proc/self/fd/'+str(worker_fd),'--packet',spec['packet_path'],
              '--packet-sha',spec['packet_sha'],'--driver',spec['driver_path'],'--driver-sha',spec['driver_sha'],
              '--original-entry',str(value['original_entry']),'--original-J',str(value['workflow_end'])]
        with process_owner.masked() as previous:
            b.check(b.E)
            proc=subprocess.Popen(argv,executable='/proc/self/fd/'+str(python_tool.fd),env=worker_env,cwd=spec['cwd'],
                 stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,close_fds=True,
                 pass_fds=(python_tool.fd,worker_fd),shell=False,start_new_session=True,
                 preexec_fn=lambda:signal.pthread_sigmask(signal.SIG_SETMASK,previous))
            slot['process']=proc;pipe=proc.stdout;slot['pipe']=pipe;slot['physical']=physical;physical.bind(proc,python_tool)
        b.call(lambda:os.set_blocking(pipe.fileno(),False));selector=b.call(selectors.DefaultSelector);slot['selector']=selector
        b.call(lambda:selector.register(pipe,selectors.EVENT_READ));eof=False
        while not eof:
            events=b.call(lambda:selector.select(min(.1,max(0,b.end-time.monotonic()))))
            for key,event in events:
                raw=b.call(lambda:os.read(pipe.fileno(),65536))
                if not raw:eof=True;break
                output.extend(raw);need(len(output)<=1024**2,'guardian-private-output-cap')
        b.check()
        # Reap/nonzero classification precedes subsequent close/JSON faults.
        retired=physical.retire(proc)
        if b.first is not None:raise b.first
        need(proc.returncode==0,'guardian-worker-exit')
        handoff=validate_handoff(bytes(output),spec,contract)
        for pid in {row['identity']['pid']for row in handoff['process_records']}:
            need(pid!=proc.pid and physical.row(pid)is None,'guardian-reported-cli-proc-absence')
        b.call(lambda:slot.update(work_fd=os.open(os.path.basename(value['work_root']),os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY|os.O_CLOEXEC,dir_fd=parent_fd)))
        work=b.call(lambda:os.fstat(slot['work_fd']));work_named=b.call(lambda:os.stat(os.path.basename(value['work_root']),dir_fd=parent_fd,follow_symlinks=False))
        need(root_identity(work)==root_identity(work_named)and stat.S_ISDIR(work.st_mode)and work.st_uid==value['uid']and
             work.st_gid==value['gid']and stat.S_IMODE(work.st_mode)==0o700,'guardian-work-root-custody')
        cleanup_spec=dict(spec);cleanup_spec['held_roots']=[*spec['held_roots'],(value['work_root'],slot['work_fd'],root_identity(work))]
        cleanup=inspect_cleanup(handoff,cleanup_spec,b,docker_call)
        b.call(lambda:os.close(slot['work_fd']));slot.pop('work_fd')
        b.call(selector.close);slot.pop('selector');b.call(pipe.close);slot.pop('pipe')
        b.call(lambda:observer.capture('cleanup'))
        public_pair=dict(handoff['result']);public_pair['native_build']='PASS'
        result={'schema':1,'status':'PRIVATE_ROOT_PUBLICATION_PENDING','publication_allowed':False,
                'pair_result':public_pair,'worker_retirement':retired,'root_cleanup':cleanup,
                'reported_cli_processes_absent':sorted({row['identity']['pid']for row in handoff['process_records']}),
                'original_start':b.start,'original_E':b.E,'original_J':b.J}
        b.call(lambda:publish(result),b.J);RETAINED.remove(slot);return result
    except BaseException as error:
        b.fail(error)
        if proc is not None:
            try:physical.retire(proc)
            except BaseException as cleanup_error:b.first.add_note('guardian retirement uncertainty: '+type(cleanup_error).__name__)
        slot['private_stdout']=bytes(output);slot['budget']=b
        try:b.first.retained_pair_guardian=slot
        except BaseException:pass
        raise b.first
