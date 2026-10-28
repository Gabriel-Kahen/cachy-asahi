#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only, explicitly selected debugfs adapter; source/model stage only."""
from contextlib import ExitStack, contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time
import types

CORE_SHA = '3a71ba896700f72130e35a56845516bd9c42de0b1b0fd782b79829b37ac262a7'
TOOL_CONTRACT_SHA = '4f53cd7be7a9f23c526007bd846b4c09b040be364504959dbf4273b5591d3ef6'
IMAGE_SHA = '76f95dae6180bc4a45ffdeaccec26681d75b2207b90062064fcd2a845adbf9db'
IMAGE_SIZE = 3680501760
MIB = 1024**2
META, STDERR, FILE, TOTAL, NODES = 8*MIB, 64*1024, 512*MIB, 8*1024**3, 500000
KINDS = {'regular':'file','directory':'directory','symlink':'symlink',
         'character special':'char-device','block special':'block-device','FIFO':'fifo','socket':'socket'}


def need(value, reason):
    if not value: raise ValueError(reason)


def uint(value, maximum=2**32-1, minimum=0):
    return type(value) is int and minimum<=value<=maximum


FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')


def identity(info):return [getattr(info,k) for k in FIELDS]


@contextmanager
def held_regular(value, budget, expected=None):
    """Validate an O_PATH nofollow inode before obtaining any readable file FD."""
    value=Path(value);need(value.is_absolute() and '..' not in value.parts and len(str(value))<=4096 and len(value.parts)<=65,'input-path')
    with ExitStack() as stack:
        budget.check();parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);stack.callback(os.close,parent);ancestors=[]
        for name in value.parts[1:-1]:
            budget.check();fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);stack.callback(os.close,fd)
            ancestors.append((parent,name,os.fstat(fd)));parent=fd
        budget.check();binding=os.open(value.name,os.O_PATH|os.O_NOFOLLOW,dir_fd=parent);stack.callback(os.close,binding);before=os.fstat(binding)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1,'ordinary-input-before-read')
        if expected is not None:need(identity(before)==expected,'input-identity-before-read')
        budget.check();fd=os.open('/proc/self/fd/'+str(binding),os.O_RDONLY|os.O_NONBLOCK);stack.callback(os.close,fd)
        need(identity(os.fstat(fd))==identity(before),'input-readable-binding')
        yield fd,before
        budget.check();need(identity(before)==identity(os.fstat(fd))==identity(os.fstat(binding))==identity(os.stat(value.name,dir_fd=parent,follow_symlinks=False)),'input-final-drift')
        for p,n,old in ancestors:
            budget.check();now=os.stat(n,dir_fd=p,follow_symlinks=False)
            need((old.st_dev,old.st_ino,old.st_mode)==(now.st_dev,now.st_ino,now.st_mode),'input-ancestor-drift')


def read_reference(core, ref, maximum, budget):
    core.reference(ref,maximum)
    with held_regular(ref['path'],budget,ref['identity']) as (fd,_):
        data=bytearray()
        while True:
            budget.check();b=os.read(fd,min(MIB,ref['size']-len(data)+1));budget.check()
            if not b:break
            data.extend(b);need(len(data)<=ref['size'],'reference-size')
        need(len(data)==ref['size'] and hashlib.sha256(data).hexdigest()==ref['sha256'],'reference-digest')
        return bytes(data)


def load_core(source, deadline=None):
    """Execute only exact held source bytes, without import/PYC fallback."""
    deadline=time.monotonic()+1200 if deadline is None else deadline
    need(type(deadline) in (int,float) and math.isfinite(deadline) and time.monotonic()<deadline<=time.monotonic()+1200,'source-deadline')
    def check():need(time.monotonic()<deadline,'source-deadline')
    source=Path(source);need(source.is_absolute(),'core-path')
    with held_regular(source,types.SimpleNamespace(check=check)) as (fd,before):
        need(stat.S_IMODE(before.st_mode)==0o644 and before.st_size<=MIB,'core-type');data=bytearray()
        while len(data)<=MIB:
            check();b=os.read(fd,65536);check()
            if not b:break
            data.extend(b)
        need(len(data)==before.st_size and hashlib.sha256(data).hexdigest()==CORE_SHA,'core-source')
    module=types.ModuleType('held_payload_correspondence');module.__file__=str(source)
    code=compile(bytes(data),str(source),'exec');check();exec(code,module.__dict__);check();return module



class WorkLedger:
    """One source-bound archive/image budget; callers retain custody across retries."""
    def __init__(self, source, deadline):
        self.source=Path(source);self.pin=CORE_SHA;self._source=self.source;self._pin=self.pin
        self.core=load_core(self.source,deadline);self.budget=self.core.Budget(deadline)
        self._budget=self.budget;self._core=self.core;self.end=deadline;self._end=deadline
        self.calls=0;self._high=(0,0,0,0);self._owner=None;self._invalid=False;self._used={}
    def record(self):
        values=(self.budget.decoded,self.budget.nodes,self.budget.tree_bytes,self.calls)
        valid=(not self._invalid and self.budget is self._budget and self.core is self._core
               and type(self.budget) is self.core.Budget and self.budget.end==self.end==self._end
               and self.source==self._source and self.pin==self._pin==CORE_SHA
               and all(type(n) is int and n>=old for n,old in zip(values,self._high)))
        self._invalid=not valid
        need(valid,'ledger-custody')
        self._high=values
        need(values[0]+values[2]<=TOTAL and values[1]<=NODES,'image-content-total')
        need(values[3]<=3*NODES+2,'call-bound')
    def check(self, owner=None):
        self.record();self.budget.check()
        need(self._owner is owner,'ledger-lease')
    def bind(self, source, deadline):
        self.check()
        need(Path(source)==self.source and deadline==self.end and type(deadline) in (int,float)
             and self.pin==CORE_SHA,'ledger-binding')
    def acquire(self, owner):
        need(owner is not None,'ledger-owner');self.check()
        need(id(owner) not in self._used and len(self._used)<NODES,'ledger-retired-or-lease-bound')
        self._used[id(owner)]=owner;self._owner=owner
    def release(self, owner):
        need(self._owner is owner,'ledger-lease');self._owner=None;self.record()
    def claim_call(self, owner):
        self.check(owner);need(self.calls<3*NODES+2,'call-bound');self.calls+=1;self.record()
    def charge(self, size, owner):
        self.record();need(self._owner is owner and owner is not None,'ledger-lease');need(uint(size,MIB),'ledger-charge')
        self.budget.tree_bytes+=size;self.record();self.budget.check()
    def archive_nodes(self, ref, expected):
        owner=object();self.acquire(owner)
        try:return self.core.archive_nodes(ref,expected,self.budget)
        finally:dispose((lambda:self.release(owner),))


def dispose(actions):
    """Finish bounded owned cleanup, then deliver cancellation; retain first cause."""
    primary=sys.exc_info()[1];failure=None;old=None
    try:
        old=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM,signal.SIGALRM})
    except BaseException as exc:failure=exc
    for action in actions:
        try:action()
        except BaseException as exc:
            if failure is None:failure=exc
    if old is not None:
        try:signal.pthread_sigmask(signal.SIG_SETMASK,old)
        except BaseException as exc:
            if failure is None:failure=exc
    if failure is not None:
        if primary is not None:primary.add_note('owned cleanup also failed: '+type(failure).__name__)
        else:raise failure


def dispose_process(process, end):
    failure=None
    def attempt(action):
        nonlocal failure
        try:return True,action()
        except BaseException as exc:
            if failure is None:failure=exc
            return False,None
    ok,status=attempt(process.poll)
    if not ok or status is None:
        attempt(lambda:os.killpg(process.pid,signal.SIGTERM))
        waited,_=attempt(lambda:process.wait(timeout=max(.001,min(1,end-time.monotonic()))))
        if not waited:
            attempt(lambda:os.killpg(process.pid,signal.SIGKILL))
            attempt(lambda:process.wait(timeout=max(.001,end-time.monotonic())))
    if failure is not None:raise failure


def request(kind, inode):
    need(kind in ('ls','stat','cat') and uint(inode,minimum=1),'request')
    return ('ls -p ' if kind=='ls' else kind+' ')+'<'+str(inode)+'>'


def text(raw, maximum=META):
    need(type(raw) is bytes and len(raw)<=maximum,'metadata-bound')
    s=raw.decode('utf-8');need(not re.search(r'[\x00-\x08\x0b-\x1f\x7f]',s),'metadata-control');return s


def listing(raw):
    out={}
    for line in text(raw).splitlines():
        if not line:continue
        p=line.split('/');need(len(p)==8 and p[0]==p[7]=='' and all(re.fullmatch(r'[0-9]+',p[k]) for k in (1,2,3,4)),'listing-framing')
        inode,mode,uid,gid=int(p[1]),int(p[2],8),int(p[3]),int(p[4]);name=p[5]
        need(uint(inode,minimum=1) and uint(mode,0o177777) and uint(uid) and uint(gid),'listing-integer')
        kind=next((v for k,v in [(0o100000,'file'),(0o040000,'directory'),(0o120000,'symlink'),(0o010000,'fifo'),(0o020000,'char-device'),(0o060000,'block-device'),(0o140000,'socket')] if mode&0o170000==k),None)
        need(kind is not None and type(name) is str and 0<len(name)<=255 and not re.search(r'[\x00-\x1f\x7f/]',name),'listing-name')
        need((kind=='directory' and p[6]=='') or re.fullmatch(r'[0-9]+',p[6]),'listing-size')
        size=None if not p[6] else int(p[6]);need(size is None or uint(size,FILE),'listing-size')
        need(name not in out and len(out)<NODES,'listing-duplicate-or-bound')
        out[name]=dict(inode=inode,type=kind,mode=mode&0o7777,uid=uid,gid=gid,bytes=size)
    need('.' in out and '..' in out and all(out[n]['type']=='directory' for n in ('.','..')),'listing-dot')
    return out


def inode_stat(raw, inode):
    s=text(raw);lines=s.splitlines()
    def one(pattern):
        found=[re.fullmatch(pattern,line) for line in lines];found=[x for x in found if x]
        need(len(found)==1,'stat-field');return found[0]
    a=one(r'Inode: ([0-9]+)   Type: (regular|directory|symlink|character special|block special|FIFO|socket)    Mode:  (0[0-7]{3,4})   Flags: 0x[0-9a-fA-F]+')
    b=one(r'User:\s+([0-9]+)   Group:\s+([0-9]+)(?:\s+Project:\s+[0-9]+)?\s+Size: ([0-9]+)')
    c=one(r'Links: ([0-9]+)   Blockcount: [0-9]+')
    n=int(a[1]);mode=int(a[3],8);uid,gid,size=map(int,b.groups());links=int(c[1])
    need(n==inode and uint(n,minimum=1) and uint(mode,0o7777) and uint(uid) and uint(gid) and uint(size,FILE) and uint(links,minimum=1),'stat-identity')
    row=dict(inode=n,type=KINDS[a[2]],mode=mode,uid=uid,gid=gid,bytes=size,nlink=links)
    fast=[re.fullmatch(r'Fast link dest: "([^"\\\r\n]*)"',line) for line in lines];fast=[x[1] for x in fast if x]
    need(len(fast)<=1 and (not fast or row['type']=='symlink'),'stat-fast-link')
    need(not any(line.startswith('Fast link dest:') for line in lines) or len(fast)==1,'stat-fast-link-framing')
    if fast:
        need(0<len(fast[0].encode())==size<=4096,'stat-link-size');row['target']=fast[0]
    if row['type'] in ('char-device','block-device'):
        d=one(r'Device major/minor number: ([0-9]+):([0-9]+) \(hex [0-9a-fA-F]+:[0-9a-fA-F]+\)');row['rdev']=os.makedev(int(d[1]),int(d[2]))
    row['stat_sha256']=hashlib.sha256(raw).hexdigest();return row


def checked_process(argv, executable, pass_fds, kind, expected_size, deadline, popen=subprocess.Popen, retain_link=False, output_budget=TOTAL, *, ledger=None, owner=None):
    """Bound both pipes concurrently; hash cat stdout, never retain its contents."""
    need(type(deadline) in (int,float) and math.isfinite(deadline) and time.monotonic()+2<deadline<=time.monotonic()+1200,'process-deadline')
    need(kind in ('ls','stat','cat') and uint(expected_size,FILE) and type(retain_link) is bool and (not retain_link or kind=='cat' and 0<expected_size<=4096) and uint(output_budget,TOTAL),'process-kind-size')
    need(type(ledger) is WorkLedger and owner is not None and ledger.end==deadline,'ledger-required');ledger.check(owner)
    output_budget=min(output_budget,TOTAL-ledger.budget.decoded-ledger.budget.tree_bytes)
    end=min(deadline,time.monotonic()+20);work_end=end-2
    cap=min(expected_size if kind=='cat' else META,output_budget)
    need(kind!='cat' or cap==expected_size,'process-output-budget')
    ledger.claim_call(owner)
    output=bytearray();errors=bytearray();digest=hashlib.sha256();size=0;process=None
    blocked={signal.SIGINT,signal.SIGTERM,signal.SIGALRM};old=None
    def child_setup():
        signal.pthread_sigmask(signal.SIG_SETMASK,old)
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3))
    try:
        need(time.monotonic()<work_end,'process-deadline')
        old=signal.pthread_sigmask(signal.SIG_BLOCK,blocked)
        try:
            process=popen(argv,executable=executable,pass_fds=pass_fds,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          close_fds=True,start_new_session=True,preexec_fn=child_setup,cwd='/',env={'LC_ALL':'C','TZ':'UTC'})
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK,old)
        with selectors.DefaultSelector() as selector:
            for stream,label in ((process.stdout,'stdout'),(process.stderr,'stderr')):selector.register(stream,selectors.EVENT_READ,label)
            while selector.get_map():
                need(time.monotonic()<work_end,'process-deadline')
                for key,_ in selector.select(min(.1,max(0,work_end-time.monotonic()))):
                    b=key.fileobj.read1(MIB)
                    need(type(b) is bytes and len(b)<=MIB,'pipe-read')
                    if not b:selector.unregister(key.fileobj);continue
                    if key.data=='stderr':errors.extend(b);need(len(errors)<=STDERR,'stderr-bound')
                    else:
                        ledger.charge(len(b),owner)
                        size+=len(b);need(size<=cap,'stdout-bound');digest.update(b)
                        if kind!='cat' or retain_link:output.extend(b)
            code=process.wait(timeout=max(.001,work_end-time.monotonic()))
        need(time.monotonic()<work_end and code==0,'process-return')
        need(re.fullmatch(rb'debugfs 1\.47\.4 \([A-Za-z0-9 .-]{1,64}\)\n',bytes(errors)),'debugfs-diagnostic')
        if kind=='cat':need(size==expected_size,'cat-size')
        result=dict(data=bytes(output) if kind!='cat' else b'',bytes=size,sha256=digest.hexdigest(),returncode=code)
        if retain_link:result['link_data']=bytes(output)
        return result
    finally:
        if process is not None:
            dispose((lambda:dispose_process(process,end),
                     *(pipe.close for pipe in (process.stdout,process.stderr) if pipe is not None)))


class Tool:
    """Lifetime-pinned input handles; explicit actor selection required before any read."""
    def __init__(self, core, contract_ref, image_ref, deadline, execution_selected=False, *, ledger=None):
        need(execution_selected is True,'image-actor-not-selected')
        need(type(ledger) is WorkLedger and ledger.core is core and ledger.end==deadline,'ledger-required')
        ledger.acquire(self);self.ledger=ledger
        self.core,self.budget=core,ledger.budget;self.stack=ExitStack();self.calls=self.bytes=self.output_bytes=0;self.links=[]
        try:
            need(contract_ref['sha256']==TOOL_CONTRACT_SHA,'tool-contract')
            contract=core.decode(read_reference(core,contract_ref,META,self.budget))
            need(contract['schema_version']==2 and contract['approved'] is False and contract['actors']=='NOT RUN','tool-contract-scope')
            self.refs={};self.fds={}
            for logical,row in contract['binary_and_recursive_DT_NEEDED'].items():
                ref=row['reference'];core.reference(ref,FILE)
                if ref['path'] not in self.refs:
                    fd,_=self.stack.enter_context(held_regular(ref['path'],self.budget,ref['identity']));need(core.hashed(fd,ref['size'],self.budget)==ref['sha256'],'tool-digest')
                    self.refs[ref['path']]=ref;self.fds[ref['path']]=fd
                for link in row['links']:self.links.append(link)
            for interpreter in contract['interpreter_links']:
                for link in interpreter['ancestor_links']:
                    self.budget.check();need(os.readlink(link['path'])==link['target'],'interpreter-link')
                    self.links.append(dict(path=link['path'],target=link['target'],identity=core.identity(os.lstat(link['path']))))
            self.check_links()
            self.executable_fd=self.fds[contract['binary_and_recursive_DT_NEEDED']['/usr/bin/debugfs']['reference']['path']]
            need(image_ref['size']==IMAGE_SIZE and image_ref['sha256']==IMAGE_SHA,'image-binding');core.reference(image_ref,4*1024**3)
            self.image_ref=image_ref;self.image_fd,_=self.stack.enter_context(held_regular(image_ref['path'],self.budget,image_ref['identity']))
            need(core.hashed(self.image_fd,IMAGE_SIZE,self.budget)==IMAGE_SHA,'image-digest')
        except BaseException:
            dispose((self.stack.close,lambda:ledger.release(self)));raise
    def check_links(self):
        for link in self.links:
            self.budget.check();need(self.core.identity(os.lstat(link['path']))==link['identity'] and os.readlink(link['path'])==link['target'],'tool-link-drift')
    def check_pins(self):
        self.check_links()
        for ref in self.refs.values():
            with held_regular(ref['path'],self.budget,ref['identity']):pass
    def call(self, kind, inode, size=0, link=False):
        self.ledger.check(self)
        command=request(kind,inode);self.budget.check();self.check_pins();need(self.calls<3*NODES+2,'call-bound');self.calls+=1
        remaining=TOTAL-self.budget.tree_bytes-self.budget.decoded
        need(remaining>=0 and (kind!='cat' or uint(size,FILE) and size<=remaining),'image-content-total')
        argv=('/usr/bin/debugfs','-R',command,'/proc/self/fd/'+str(self.image_fd))
        result=checked_process(argv,'/proc/self/fd/'+str(self.executable_fd),(self.executable_fd,self.image_fd),kind,size,self.budget.end,retain_link=link,output_budget=remaining,ledger=self.ledger,owner=self)
        self.output_bytes+=result['bytes'];self.ledger.check(self)
        if kind=='cat':self.bytes+=result['bytes']
        self.check_pins();self.budget.check();return result
    def close(self):
        try:
            self.ledger.check(self);self.check_pins()
            for path,fd in self.fds.items():
                ref=self.refs[path];os.lseek(fd,0,os.SEEK_SET);need(self.core.hashed(fd,ref['size'],self.budget)==ref['sha256'],'tool-final-digest')
            os.lseek(self.image_fd,0,os.SEEK_SET);need(self.core.hashed(self.image_fd,IMAGE_SIZE,self.budget)==IMAGE_SHA,'image-final-digest')
        finally:dispose((self.stack.close,lambda:self.ledger.release(self)))
    def __enter__(self):return self
    def __exit__(self,*args):dispose((self.close,))


def observe(tool):
    """Enumerate names as data. Every command uses only a validated decimal inode."""
    rows={};directories=set();core=tool.core;budget=tool.budget
    def read_stat(inode):return inode_stat(tool.call('stat',inode)['data'],inode)
    def walk(inode,prefix,parent,depth):
        budget.check();need(depth<=64 and inode not in directories,'image-directory-cycle');directories.add(inode)
        before=read_stat(inode);need(before['type']=='directory','image-directory-type')
        raw=tool.call('ls',inode)['data'];children=listing(raw)
        need(all(children['.'][k]==before[k] for k in ('inode','type','mode','uid','gid')) and children['..']['inode']==parent and (children['.']['bytes'] is None or children['.']['bytes']==before['bytes']),'image-directory-parent')
        for name,entry in sorted(children.items()):
            if name in ('.','..'):continue
            budget.node();relative=core.path(prefix+name);need(relative not in rows,'image-duplicate-path')
            pre=read_stat(entry['inode']);need(all(pre[k]==entry[k] for k in ('inode','type','mode','uid','gid')) and (entry['bytes'] is None or pre['bytes']==entry['bytes']),'image-listing-stat')
            row={k:pre[k] for k in ('type','mode','uid','gid','inode','nlink')};row['device']=0
            if pre['type']=='directory':walk(pre['inode'],relative+'/',inode,depth+1)
            elif pre['type']=='file':
                content=tool.call('cat',pre['inode'],pre['bytes']);need(content['bytes']==pre['bytes'],'image-content-size');row.update(bytes=content['bytes'],sha256=content['sha256'])
            elif pre['type']=='symlink':
                if 'target' in pre:target=pre['target']
                else:
                    need(0<pre['bytes']<=4096,'image-symlink-size')
                    # Cat hashes regular files; symlinks need bounded target bytes as data.
                    result=tool.call('cat',pre['inode'],pre['bytes'],link=True);target=result.get('link_data')
                    need(type(target) is bytes and len(target)==pre['bytes'],'image-long-symlink-unobserved');target=target.decode('utf-8')
                need(0<len(target.encode())<=4096 and not re.search(r'[\x00-\x1f\x7f]',target),'image-link-target');row['target']=target
            elif pre['type'] in ('char-device','block-device'):row['rdev']=pre['rdev']
            need(read_stat(pre['inode'])==pre,'image-inode-drift');rows[relative]=row
        need(tool.call('ls',inode)['data']==raw and read_stat(inode)==before,'image-directory-drift')
    walk(2,'',2,0)
    budget.check();return rows


def compare_image(tool, expected, ownership):
    rows=observe(tool)
    links={}
    for nodes in expected.values():
        for name,node in nodes.items():
            tool.budget.check()
            if node.get('type')=='hardlink':links[name]=node['target'].removeprefix('./')
    for name in links:
        seen=set();target=name
        while target in links:
            tool.budget.check();need(target not in seen,'hardlink-cycle');seen.add(target);target=links[target]
    result=tool.core.compare(expected,rows,ownership,tool.budget);tool.budget.check()
    need(len(json.dumps(result,allow_nan=False).encode())<=256*MIB,'report-bound')
    tool.budget.check()
    result.update(image_reader='SOURCE proposal; actual image admission remains separate',image_issuer_authentication_accepted=False,
                  independent_key_owner_trust_accepted=False,installed_payload_verified=False,installation_accepted=False,hardware_accepted=False)
    return result


def open_selected(source, contract_ref, image_ref, deadline, execution_selected=False, *, ledger=None):
    """Caller must separately select the actor and bind the same absolute cutoff."""
    need(execution_selected is True,'image-actor-not-selected')
    need(type(ledger) is WorkLedger,'ledger-required');ledger.bind(source,deadline)
    return Tool(ledger.core,contract_ref,image_ref,deadline,execution_selected=True,ledger=ledger)


def run_selected(source, contract_ref, image_ref, expected, ownership, deadline, execution_selected=False, *, ledger=None):
    """No result leaves this entry point before final input rehash/FD disposal."""
    with open_selected(source,contract_ref,image_ref,deadline,execution_selected,ledger=ledger) as tool:
        result=compare_image(tool,expected,ownership)
    need(time.monotonic()<deadline,'final-deadline')
    result['immutable_image_final_rehash']=True
    result['image_sha256']=image_ref['sha256']
    need(time.monotonic()<deadline,'final-deadline')
    return result
