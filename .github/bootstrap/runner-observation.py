"""Private fixed-path read-only runner observation; no actor or grant issuance."""
import time
ENTRY=time.monotonic()
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import sys

REPOSITORY='Gabriel-Kahen/cachy-asahi'
LIMIT=64*1024
SIGNALS={signal.SIGINT,signal.SIGTERM,signal.SIGALRM}


class Refused(ValueError):pass
class Interrupted(BaseException):pass


def need(value,code):
    if not value:raise Refused(code)


def check(end):
    need(type(end)in(int,float)and math.isfinite(end)and 0<time.monotonic()<end,'observation-deadline')


def identity(row):
    return (row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid,row.st_nlink,
            row.st_size,row.st_mtime_ns,row.st_ctime_ns)


def metadata(path,row):
    return {'path':str(path),'device':row.st_dev,'inode':row.st_ino,
            'mode':oct(stat.S_IMODE(row.st_mode)),'uid':row.st_uid,'gid':row.st_gid,
            'links':row.st_nlink,'bytes':row.st_size}


@contextmanager
def masked():
    previous=signal.pthread_sigmask(signal.SIG_BLOCK,SIGNALS)
    try:yield
    finally:
        cause=sys.exc_info()[1]
        try:signal.pthread_sigmask(signal.SIG_SETMASK,previous)
        except BaseException:
            if cause is None:raise


@contextmanager
def controls(end):
    need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'existing-timer')
    previous={}
    def interrupt(number,frame):raise Interrupted('observation-interrupted')
    try:
        for number in SIGNALS:
            previous[number]=signal.getsignal(number);signal.signal(number,interrupt)
        check(end);signal.setitimer(signal.ITIMER_REAL,end-time.monotonic())
        yield
    finally:
        cause=sys.exc_info()[1];fault=None
        try:signal.setitimer(signal.ITIMER_REAL,0)
        except BaseException as error:fault=error
        for number,handler in previous.items():
            try:signal.signal(number,handler)
            except BaseException as error:fault=fault or error
        if cause is None and fault is not None:raise fault


class Reader:
    def __init__(self,end):self.end=end;self.nodes=[]

    def open(self,path,flags,*,name=None,parent=None):
        check(self.end)
        with masked():
            fd=os.open(path if name is None else name,flags|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            try:
                row=os.fstat(fd);self.nodes.append((Path(path),fd,identity(row)))
            except BaseException:
                try:os.close(fd)
                except BaseException:pass
                raise
        check(self.end)
        return fd,row

    def directory(self,path,*,trusted=False):
        path=canonical(str(path));current=Path('/')
        fd,row=self.open(current,os.O_RDONLY|os.O_DIRECTORY)
        rows=[metadata(current,row)]
        for part in path.parts[1:]:
            current=current/part
            fd,row=self.open(current,os.O_RDONLY|os.O_DIRECTORY,name=part,parent=fd)
            rows.append(metadata(current,row))
        if trusted:need(all(row['uid']==0 and not int(row['mode'],8)&0o022 for row in rows),'tool-ancestor-owner-mode')
        self.verify();return fd,rows

    def verify(self):
        for path,fd,before in self.nodes:
            check(self.end)
            held=os.fstat(fd);named=os.stat(path,follow_symlinks=False)
            width=5 if stat.S_ISDIR(before[2])else 9
            need(identity(held)[:width]==identity(named)[:width]==before[:width],'identity-drift')
        check(self.end)

    def file(self,path,cap):
        need(path in {'/usr/bin/git','/usr/bin/docker','/usr/bin/python3'}or
             re.fullmatch(r'/usr/bin/python3(?:\.[0-9]{1,3}){1,2}',path),'fixed-file-path')
        need(type(cap)is int and 0<cap<=128*1024**2,'file-cap')
        parent,_=self.directory('/usr/bin',trusted=True)
        before=os.stat(Path(path).name,dir_fd=parent,follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode)and before.st_uid==0 and
             stat.S_IMODE(before.st_mode)==0o755 and before.st_nlink==1,'tool-owner-mode-type-links')
        need(0<before.st_size<=cap,'file-size-cap')
        fd,row=self.open(path,os.O_RDONLY,name=Path(path).name,parent=parent)
        need(identity(row)==identity(before),'file-open-drift')
        total=0;hasher=hashlib.sha256()
        while True:
            check(self.end);block=os.read(fd,min(65536,cap+1-total))
            if not block:break
            total+=len(block);need(total<=cap,'file-size-cap');hasher.update(block)
        need(total==before.st_size,'file-size-drift')
        self.verify()
        return {'status':'OBSERVED',**metadata(path,row),'sha256':hasher.hexdigest(),'stable_named_and_fd':True}

    def interpreter(self):
        parent,_=self.directory('/usr/bin',trusted=True)
        path='/usr/bin/python3';links=[];seen=set()
        for _ in range(9):
            check(self.end);need(path not in seen,'interpreter-cycle');seen.add(path)
            row=os.stat(Path(path).name,dir_fd=parent,follow_symlinks=False)
            if stat.S_ISREG(row.st_mode):
                target=self.file(path,64*1024**2);self.verify()
                return {'status':'OBSERVED','entry_path':'/usr/bin/python3','links':links,'target':target}
            need(len(links)<8 and stat.S_ISLNK(row.st_mode)and row.st_uid==0 and row.st_nlink==1,'interpreter-link')
            fd,held=self.open(path,os.O_PATH,name=Path(path).name,parent=parent)
            need(identity(held)==identity(row),'interpreter-link-drift')
            target=os.readlink('',dir_fd=fd)
            need(type(target)is str and len(target)<=128,'interpreter-target')
            full=target if target.startswith('/')else '/usr/bin/'+target
            need(re.fullmatch(r'/usr/bin/python3(?:\.[0-9]{1,3}){0,2}',full),'interpreter-target')
            links.append({**metadata(path,row),'target':target});path=full
        raise Refused('interpreter-depth')

    def socket(self):
        parent,_=self.directory('/run',trusted=True)
        row=os.stat('docker.sock',dir_fd=parent,follow_symlinks=False)
        need(stat.S_ISSOCK(row.st_mode)and row.st_uid==0,'docker-socket-owner-type')
        check(self.end)
        after=os.stat('docker.sock',dir_fd=parent,follow_symlinks=False)
        need(identity(row)==identity(after),'docker-socket-drift');self.verify()
        return {'status':'OBSERVED',**metadata('/run/docker.sock',row),'stat_only':True,'connected':False}

    def workspace(self,environment):
        original=canonical(environment.get('GITHUB_WORKSPACE'));temporary=canonical(environment.get('RUNNER_TEMP'))
        need(not original.is_relative_to(temporary)and not temporary.is_relative_to(original),'workspace-temp-overlap')
        _,rows=self.directory(original);_,temp=self.directory(temporary)
        parent=rows[-2]if len(rows)>1 else rows[0]
        self.verify()
        return {'status':'OBSERVED','original':str(original),'temporary':str(temporary),
                'original_ancestors':rows,'temporary_ancestors':temp,'disjoint':True,
                'fresh_sibling_parent_uid_matches_runner':parent['uid']==os.getuid(),
                'fresh_sibling_parent_not_group_other_writable':not int(parent['mode'],8)&0o022,
                'original_and_temp_uid_match_runner':rows[-1]['uid']==temp[-1]['uid']==os.getuid(),
                'sibling_created':False}

    def close(self):
        errors=[]
        for path,fd,before in reversed(self.nodes):
            try:
                row=os.fstat(fd)
                need(identity(row)[:2]==before[:2],'retirement-foreign');os.close(fd)
            except BaseException as error:errors.append(type(error).__name__)
        self.nodes.clear();return errors


def canonical(value):
    need(type(value)is str and 0<len(value)<=4096 and '\0'not in value,'canonical-path')
    path=Path(value)
    need(path.is_absolute()and str(path)==value and len(path.parts)<=64 and
         '..'not in path.parts and path!=Path('/'),'canonical-path')
    return path


def job(environment):
    need(type(environment)is dict,'job-environment')
    result={}
    for key,pattern in (('GITHUB_RUN_ID','[1-9][0-9]{0,19}'),('GITHUB_RUN_ATTEMPT','[1-9][0-9]{0,9}'),
                        ('GITHUB_SHA','[0-9a-f]{40}'),('GITHUB_WORKFLOW_SHA','[0-9a-f]{40}')):
        value=environment.get(key);need(type(value)is str and re.fullmatch(pattern,value),'job-field')
        result[key]=value
    need(environment.get('GITHUB_REPOSITORY')==REPOSITORY and result['GITHUB_SHA']==result['GITHUB_WORKFLOW_SHA'],'job-source')
    result['GITHUB_REPOSITORY']=REPOSITORY
    for key in ('ImageOS','ImageVersion'):
        value=environment.get(key)
        if value is not None:
            need(type(value)is str and re.fullmatch('[A-Za-z0-9._+-]{1,128}',value),'image-field')
            result[key]=value
    return result


def section(function):
    try:return function()
    except Refused as error:return {'status':'REFUSED','code':str(error)}
    except OSError as error:return {'status':'REFUSED','code':'os-error','errno':error.errno}


def encode(report,end):
    check(end);raw=json.dumps(report,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'
    need(len(raw)<=LIMIT,'report-byte-cap');check(end);return raw


def observe(environment,*,entry=None):
    actual=time.monotonic()
    if entry is None:entry=actual
    need(type(entry)in(int,float)and math.isfinite(entry)and 0<entry<=actual,'observation-entry')
    end=entry+60;reader=Reader(end);first=None;result=None;errors=[]
    try:
        check(end);selected=job(environment)
        machine=os.uname().machine;pagesize=os.sysconf('SC_PAGE_SIZE')
        need(type(machine)is str and re.fullmatch('[A-Za-z0-9_+-]{1,64}',machine)and
             type(pagesize)is int and 0<pagesize<=1024*1024 and pagesize&(pagesize-1)==0,'host-fields')
        result={'schema_version':1,'purpose':'read-only-hosted-arm-runner-observation',
                'scope':'Observed bytes/metadata only; no private-runner or actor guarantee.',
                'job':selected,'host':{'machine':machine,'page_size':pagesize,'uid':os.getuid(),
                                      'arm_machine':machine in {'aarch64','arm64'}},
                'tools':{name:section(lambda name=name:reader.file('/usr/bin/'+name,128*1024**2))for name in ('git','docker')},
                'interpreter':section(reader.interpreter),'docker_socket':section(reader.socket),
                'workspace':section(lambda:reader.workspace(environment)),
                'observation_allowance_seconds':60,'actors_executed':False,'clock_or_grant_issued':False}
        reader.verify();encode(result,end)
    except BaseException as error:first=error
    finally:errors=reader.close()
    if first is not None:raise first
    need(not errors,'retirement-uncertain');check(end);return result


def emit(raw,end):
    need(type(raw)is bytes and len(raw)<=LIMIT,'report-byte-cap')
    position=0
    while position<len(raw):
        check(end);count=os.write(sys.stdout.fileno(),raw[position:])
        need(type(count)is int and 0<count<=len(raw)-position,'report-short-write');position+=count
    check(end)


def main(environment,*,entry=ENTRY):
    with controls(entry+60):
        report=observe(environment,entry=entry);emit(encode(report,entry+60),entry+60)
    check(entry+60)
    complete=(all(report[key]['status']=='OBSERVED'for key in ('interpreter','docker_socket','workspace'))and
              all(item['status']=='OBSERVED'for item in report['tools'].values()))
    return 0 if complete else 1


if __name__=='__main__':
    try:code=main(dict(os.environ))
    except BaseException:code=1
    sys.exit(code)
