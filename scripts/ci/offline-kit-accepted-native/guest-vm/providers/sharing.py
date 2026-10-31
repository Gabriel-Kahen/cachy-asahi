#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Finite owned-VM KSM experiment. Never an installed service or host command."""
import ctypes
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import select
import signal
import stat
import sys
import time

PAGE=16384
PAGES=128
SCAN_SECONDS=60
COMMAND_SECONDS=90
CONFIG={'pages_to_scan':512,'sleep_millisecs':20}
COUNTERS=('pages_shared','pages_sharing','pages_unshared','pages_volatile','full_scans')
PROFILE='OWNED_ANONYMOUS_KSM16K_SHARING_UNMERGE_V1'
SYSFS=Path('/sys/kernel/mm/ksm')

def need(ok,why):
    if not ok:raise ValueError(why)

def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()

def number(raw):
    need(type(raw)is bytes and re.fullmatch(rb'(0|[1-9][0-9]{0,19})\n',raw)and int(raw)<2**63,'bounded kernel decimal')
    return int(raw)

def page(nonce,index):
    need(type(nonce)is str and re.fullmatch('[a-f0-9]{32}',nonce)and type(index)is int and 0<=index<PAGES,'source nonce/page index')
    # Every page is nonzero and distinct; the two separately allocated buffers
    # get identical bytes. Zero-page optimization cannot satisfy the experiment.
    block=hashlib.sha256(('ksm16k:'+nonce+':'+str(index)).encode()).digest()
    return block*(PAGE//len(block))

def expected_hash(nonce):
    digest=hashlib.sha256()
    for index in range(PAGES):digest.update(page(nonce,index))
    return digest.hexdigest()

def require_kernel_config(raw):
    need(type(raw)is bytes and len(raw)<=262144,'bounded authenticated kernel config')
    need(raw.splitlines().count(b'CONFIG_KSM=y')==1 and raw.splitlines().count(b'CONFIG_ADVISE_SYSCALLS=y')==1 and b'# CONFIG_ADVISE_SYSCALLS is not set'not in raw,'KSM sharing requires genuine CONFIG_KSM=y and CONFIG_ADVISE_SYSCALLS=y kernel')

def birth(pid):
    raw=Path('/proc',str(pid),'stat').read_bytes()
    need(len(raw)<=4096 and raw.startswith((str(pid)+' (').encode()),'owned proc stat')
    fields=raw[raw.rfind(b')')+2:].split()
    need(len(fields)>=20 and fields[19].isdigit(),'owned process start ticks')
    return int(fields[19])

def merged(pid):
    # Kernel's per-mm counter, separate from unrelated global sysfs counters.
    return number(Path('/proc',str(pid),'ksm_merging_pages').read_bytes())

def guard(selection,parent):
    need(os.getpid()!=1 and os.getppid()==parent and parent>1 and os.getpgid(0)==os.getpid(),'dedicated direct child/session only')
    need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'and os.sysconf('SC_PAGE_SIZE')==PAGE,'actual root ARM16K guest only')
    nonce=selection.get('nonce');need(type(nonce)is str and re.fullmatch('[a-f0-9]{32}',nonce),'source-owned boot nonce')
    tokens=Path('/proc/cmdline').read_text().split()
    need(tokens.count('caa_ksm2_vm='+nonce)==1 and 'init=/init-ksm2'in tokens,'same private guest boot')
    need({p.name for p in Path('/sys/class/net').iterdir()}<={'lo'}and os.uname().release==selection['kernel']['release'],'same noNIC selected kernel')
    need(Path('/workspace/selection.json').is_file()and os.statvfs('/source').f_flag&os.ST_RDONLY,'original readonly source/selection')
    return nonce

class Scalars:
    """Fixed real sysfs descriptors; compare before every write, refuse foreign edits."""
    def __init__(self):
        self.files={}
        self.directory=None
        try:self.initialize()
        except BaseException:
            self.close()
            raise

    def initialize(self):
        self.directory=os.open(SYSFS,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        self.files={};self.original={};self.owned={};self.events=[]
        self.parent=os.fstat(self.directory)
        for name in ('run',*CONFIG,*COUNTERS):
            write=name=='run'or name in CONFIG
            fd=os.open(name,(os.O_RDWR if write else os.O_RDONLY)|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.directory)
            self.files[name]=fd
            row=os.fstat(fd);buf=ctypes.create_string_buffer(512)
            need(ctypes.CDLL(None).fstatfs(fd,buf)==0 and ctypes.c_long.from_buffer(buf).value==0x62656572,'fixed real sysfs only')
            need(stat.S_ISREG(row.st_mode)and row.st_uid==0 and row.st_nlink==1,'root-owned ordinary sysfs attribute')
            if write:self.original[name]=self.read(name)
        need(self.original['run']==0,'isolated original paused run0 required')
        self.owned=dict(self.original)
        advisor=SYSFS/'advisor_mode'
        if advisor.exists():need(advisor.read_bytes()==b'[none] scan-time\n','automatic scan advisor must already be disabled')
        need(self.counters()['pages_shared']==self.counters()['pages_sharing']==0,'no preexisting shared KSM pages')

    def read(self,name):
        fd=self.files[name];before=os.fstat(fd);named=os.stat(name,dir_fd=self.directory,follow_symlinks=False)
        need((before.st_dev,before.st_ino)==(named.st_dev,named.st_ino),'held sysfs attribute identity')
        parent=SYSFS.stat();need((parent.st_dev,parent.st_ino)==(self.parent.st_dev,self.parent.st_ino),'held sysfs directory identity')
        os.lseek(fd,0,os.SEEK_SET);return number(os.read(fd,65))

    def write(self,name,value):
        need(name in self.owned and type(value)is int and value>=0,'fixed scalar write only')
        need({key:self.read(key)for key in self.owned}==self.owned,'foreign edit refused; no overwrite')
        fd=self.files[name];raw=(str(value)+'\n').encode();os.lseek(fd,0,os.SEEK_SET)
        need(os.write(fd,raw)==len(raw),'one complete scalar write')
        # Remember expected post-write even if later readback fails; restoration
        # still requires an exact current-value comparison, never a blind write.
        self.owned[name]=value
        need(self.read(name)==value,'actual scalar readback')
        self.events.append({'name':name,'value':value})

    def counters(self):return {name:self.read(name)for name in COUNTERS}

    def restore(self):
        if self.owned['run']!=self.original['run']:self.write('run',self.original['run'])
        for name in reversed(tuple(CONFIG)):
            if self.owned[name]!=self.original[name]:self.write(name,self.original[name])
        need({name:self.read(name)for name in self.original}==self.original,'exact original run0/config restored')

    def close(self):
        for fd in self.files.values():os.close(fd)
        if self.directory is not None:os.close(self.directory)

def read_line(fd,deadline):
    raw=bytearray()
    while not raw.endswith(b'\n'):
        remaining=deadline-time.monotonic();need(remaining>0,'owned child protocol deadline')
        need(select.select([fd],[],[],remaining)[0],'owned child protocol deadline')
        part=os.read(fd,4097-len(raw));need(part and len(raw)+len(part)<=4096,'bounded complete child record')
        raw.extend(part)
    need(raw.count(b'\n')==1,'one child record')
    return json.loads(raw)

def child(input_fd,output_fd,nonce,parent):
    try:
        need(os.getppid()==parent,'owned child parent')
        region=mmap.mmap(-1,PAGE*PAGES,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS,prot=mmap.PROT_READ|mmap.PROT_WRITE)
        for index in range(PAGES):region[index*PAGE:(index+1)*PAGE]=page(nonce,index)
        region.madvise(mmap.MADV_MERGEABLE)
        def report():
            value=dict(pid=os.getpid(),parent=parent,group=os.getpgid(0),birth=birth(os.getpid()),nonce=nonce,bytes=len(region),sha256=sha(region),mergeable=True)
            raw=encoded(value);need(os.write(output_fd,raw)==len(raw),'one complete child report')
        report()
        while True:
            command=os.read(input_fd,1)
            if command==b'R':report()
            elif command==b'Q':break
            else:raise ValueError('unknown/closed child protocol')
        region.madvise(mmap.MADV_UNMERGEABLE);region.close();os._exit(0)
    except BaseException:os._exit(1)

def spawn(nonce,deadline,previous):
    opened=[];parent=os.getpid()
    try:
        incoming,send=os.pipe2(os.O_CLOEXEC);opened.extend((incoming,send))
        receive,outgoing=os.pipe2(os.O_CLOEXEC);opened.extend((receive,outgoing))
        pid=os.fork()
    except BaseException:
        for fd in opened:os.close(fd)
        raise
    if pid==0:
        # Never unwind into the controller's sysfs-restoration finally block.
        try:
            os.close(send);os.close(receive)
            for row in previous:
                os.close(row['send']);os.close(row['receive'])
            child(incoming,outgoing,nonce,parent)
        finally:os._exit(1)
    os.close(incoming);os.close(outgoing)
    row=dict(pid=pid,send=send,receive=receive)
    try:row['initial']=read_line(receive,deadline)
    except BaseException:
        os.kill(pid,signal.SIGKILL);os.waitpid(pid,0);os.close(send);os.close(receive);raise
    return row

def observe_children(children,nonce,deadline,request=False):
    rows=[]
    for row in children:
        if request:need(os.write(row['send'],b'R')==1,'owned byte-readback request')
        value=read_line(row['receive'],deadline)if request else row['initial']
        need(value==dict(pid=row['pid'],parent=os.getpid(),group=os.getpgid(0),birth=birth(row['pid']),nonce=nonce,bytes=PAGE*PAGES,sha256=expected_hash(nonce),mergeable=True),'exact owned child identity/nonzero bytes preserved')
        rows.append(dict(value,ksm_merging_pages=merged(row['pid'])))
    return rows

def retire(children,deadline):
    receipts=[]
    for row in children:need(os.write(row['send'],b'Q')==1,'owned child quit request')
    for row in children:
        while True:
            pid,status=os.waitpid(row['pid'],os.WNOHANG)
            if pid:break
            need(time.monotonic()<deadline,'owned child retirement deadline');time.sleep(.01)
        need(os.waitstatus_to_exitcode(status)==0 and not Path('/proc',str(pid)).exists(),'natural owned child retirement')
        receipts.append(dict(pid=pid,birth=row['initial']['birth'],exit=0,reaped=True,proc_absent=True))
    return receipts

class SharingInterrupted(Exception):pass

def experiment(selection,parent,checkpoint=None):
    nonce=guard(selection,parent);deadline=time.monotonic()+75;children=[];scalars=None;retired=False
    previous_term=signal.getsignal(signal.SIGTERM)
    def stop(signum,frame):raise SharingInterrupted('owned sharing SIGTERM')
    signal.signal(signal.SIGTERM,stop)
    try:
        scalars=Scalars();before=scalars.counters()
        for _ in range(2):children.append(spawn(nonce,deadline,children))
        initial=observe_children(children,nonce,deadline)
        need(all(row['ksm_merging_pages']==0 for row in initial),'owned buffers initially unshared')
        for name,value in CONFIG.items():scalars.write(name,value)
        scalars.write('run',1);scan_deadline=min(deadline,time.monotonic()+SCAN_SECONDS)
        while True:
            counters=scalars.counters();counts=[merged(row['pid'])for row in children]
            if counters['pages_shared']>=PAGES and counters['pages_sharing']>=PAGES and all(n>=PAGES for n in counts):break
            need(time.monotonic()<scan_deadline,'bounded actual KSM sharing not observed');time.sleep(.1)
        shared=observe_children(children,nonce,deadline,True);sharing=scalars.counters()
        need(sharing['full_scans']>before['full_scans'],'actual complete KSM scan advanced')
        if checkpoint is not None:checkpoint(nonce,children,scalars,deadline)
        scalars.write('run',2);unmerged=observe_children(children,nonce,deadline,True);after=scalars.counters()
        need(after['pages_shared']==after['pages_sharing']==0 and all(row['ksm_merging_pages']==0 for row in unmerged),'actual run2 unmerged global and both owned mm pages')
        scalars.write('run',0);retirement=retire(children,deadline);retired=True;scalars.restore()
        result=dict(profile=PROFILE,status='PASS_OWNED_VM_SHARING_UNMERGE_RESTORATION',nonce=nonce,parent=parent,controller=dict(pid=os.getpid(),group=os.getpgid(0),birth=birth(os.getpid())),page_size=PAGE,pages_per_child=PAGES,children=[row['initial']for row in children],initial=initial,shared=shared,unmerged=unmerged,counters=dict(before=before,sharing=sharing,unmerged=after,retired=scalars.counters()),configuration=dict(original=scalars.original,selected=CONFIG,restored={name:scalars.read(name)for name in scalars.original}),writes=list(scalars.events),retirement=retirement,scan_limit=SCAN_SECONDS,command_limit=COMMAND_SECONDS,scope='GENERIC16K_OWNED_ANONYMOUS_PAGES_ONLY',hardware='NOT_RUN',performance='NOT_MEASURED',release='NOT_ADMITTED')
        try:validate(result,nonce)
        except ValueError as error:
            try:counter_failure(result,nonce,error)
            except Exception:pass
            raise
        return result
    finally:
        try:
            if not retired:
                for row in children:
                    try:os.kill(row['pid'],signal.SIGKILL)
                    except ProcessLookupError:pass
                for row in children:
                    try:os.waitpid(row['pid'],0)
                    except ChildProcessError:pass
            for row in children:
                os.close(row['send']);os.close(row['receive'])
            if scalars is not None:
                try:scalars.restore()
                finally:scalars.close()
        finally:signal.signal(signal.SIGTERM,previous_term)

def counter_failure(value,nonce,error):
    # Only already-captured bounded rows; no sysfs/process reads or authority.
    if type(error)is not ValueError or str(error)not in ('complete bounded counter readback','full_scans pinned run2 epoch reset','fresh scan progression'):return
    if type(nonce)is not str or not re.fullmatch('[a-f0-9]{32}',nonce):return
    counters=value.get('counters');phases=('before','sharing','unmerged','retired')
    if type(counters)is not dict or set(counters)!=set(phases):return
    if not all(type(row)is dict and set(row)==set(COUNTERS)and all(type(n)is int and 0<=n<2**63 for n in row.values())for row in counters.values()):return
    raw=b'KSM_COUNTER_FAILURE_DATA_V1 '+encoded(dict(purpose='KSM_COUNTER_FAILURE_DATA_V1',nonce=nonce,error=str(error),phase_order=list(phases),run2_boundary='SHARING_TO_UNMERGED',counters=counters,acceptance='NOT_GRANTED',cleanup='UNKNOWN'))
    if len(raw)<=4096:os.write(2,raw)

def command_join(value,commands):
    expected=['/usr/bin/python3','-I','-B','/source/sharing.py','--owned-parent',str(value['parent'])]
    rows=[row for row in commands if row['argv']==expected]
    need(len(rows)==1,'one exact source-owned sharing command/parent')
    row=rows[0];raw=encoded(value)
    need(row['exit_code']==0 and row['group_absence_verified']is True and type(row['time_limit'])in(int,float)and 0<row['time_limit']<=COMMAND_SECONDS and type(row['seconds'])in(int,float)and 0<=row['seconds']<=row['time_limit']+6 and row['output_limit']==128*1024,'natural original bounded sharing supervisor/group retirement')
    need(row['stdout_bytes']==len(raw)and row['stdout_sha256']==sha(raw)and row['stderr_bytes']==0 and row['stderr_sha256']==sha(b''),'complete original sharing capture joins exact receipt')
    return row

def validate(value,nonce):
    """Passive receipt predicates, additional to original complete VM proof."""
    fields={'profile','status','nonce','parent','controller','page_size','pages_per_child','children','initial','shared','unmerged','counters','configuration','writes','retirement','scan_limit','command_limit','scope','hardware','performance','release'}
    need(type(value)is dict and set(value)==fields,'closed sharing receipt schema')
    need(type(value)is dict and value['profile']==PROFILE and value['nonce']==nonce and value['status']=='PASS_OWNED_VM_SHARING_UNMERGE_RESTORATION','exact sharing receipt profile/nonce')
    need(value['page_size']==PAGE and value['pages_per_child']==PAGES and value['scan_limit']==SCAN_SECONDS and value['command_limit']==COMMAND_SECONDS,'fixed experiment bounds')
    need(value['scope']=='GENERIC16K_OWNED_ANONYMOUS_PAGES_ONLY'and value['hardware']=='NOT_RUN'and value['performance']=='NOT_MEASURED'and value['release']=='NOT_ADMITTED','finite scope only')
    controller=value['controller'];need(type(controller)is dict and set(controller)=={'pid','group','birth'},'closed controller identity');need(type(value['parent'])is int and value['parent']>1 and type(controller['pid'])is int and controller['pid']>1 and controller['pid']==controller['group']and controller['pid']!=value['parent']and type(controller['birth'])is int and controller['birth']>0,'owned controller session')
    children=value['children'];need(type(children)is list and len(children)==2 and len({row['pid']for row in children})==2,'two distinct owned anonymous mappings')
    for row in children:
        need(set(row)=={'pid','parent','group','birth','nonce','bytes','sha256','mergeable'}and type(row['pid'])is int and row['pid']>1 and row['pid']not in(controller['pid'],value['parent'])and row['parent']==row['group']==controller['pid']and type(row['birth'])is int and row['birth']>=controller['birth']and row['nonce']==nonce and row['bytes']==PAGE*PAGES and row['sha256']==expected_hash(nonce)and row['mergeable']is True,'source-owned PID/birth/nonce and full nonzero byte hash')
    for phase in ('initial','shared','unmerged'):
        rows=value[phase];need(len(rows)==2,'both children each phase')
        for original,row in zip(children,rows):
            need({k:v for k,v in row.items()if k!='ksm_merging_pages'}==original and type(row['ksm_merging_pages'])is int and (row['ksm_merging_pages']>=PAGES if phase=='shared'else row['ksm_merging_pages']==0),'fresh owned mm KSM counters/full preserved bytes')
    counters=value['counters'];need(set(counters)=={'before','sharing','unmerged','retired'},'all counter phases')
    previous=0
    for phase in ('before','sharing','unmerged','retired'):
        row=counters[phase];need(set(row)==set(COUNTERS)and all(type(n)is int and 0<=n<2**63 for n in row.values()),'complete bounded counter readback')
        need(row['full_scans']>=previous if phase in ('before','sharing') else row['full_scans']==0,'full_scans pinned run2 epoch reset');previous=row['full_scans']
        need((row['pages_shared']>=PAGES and row['pages_sharing']>=PAGES)if phase=='sharing'else row['pages_shared']==row['pages_sharing']==0,'global sharing then actual run2 unmerge')
    need(counters['sharing']['full_scans']>counters['before']['full_scans'],'fresh scan progression')
    config=value['configuration'];need(set(config)=={'original','selected','restored'}and set(config['original'])=={'run',*CONFIG}and config['original']['run']==0 and config['selected']==CONFIG and config['restored']==config['original']and all(type(n)is int and 0<=n<2**63 for n in config['original'].values()),'original run0/all changed configuration restored')
    writes=[dict(name=name,value=n)for name,n in CONFIG.items()]+[dict(name='run',value=n)for n in(1,2,0)]
    writes +=[dict(name=name,value=config['original'][name])for name in reversed(tuple(CONFIG))if CONFIG[name]!=config['original'][name]]
    need(value['writes']==writes,'exact bounded write order; no hidden run2 or foreign overwrite')
    need(value['retirement']==[dict(pid=row['pid'],birth=row['birth'],exit=0,reaped=True,proc_absent=True)for row in children],'both exact owned children naturally retired')
    return value

if __name__=='__main__':
    need(len(sys.argv)==3 and sys.argv[1]=='--owned-parent'and sys.argv[2].isdigit(),'explicit owned guest parent required')
    with Path('/workspace/selection.json').open('rb')as stream:raw=stream.read(2*1024**2+1)
    need(len(raw)<=2*1024**2,'bounded original selection')
    def pairs(rows):
        value={}
        for name,item in rows:
            need(name not in value,'duplicate selection JSON');value[name]=item
        return value
    selection=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite selection JSON'))
    sys.stdout.buffer.write(encoded(experiment(selection,int(sys.argv[2]))))
