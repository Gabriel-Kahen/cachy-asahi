#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Separately admitted finite namespace observations; never builds a package."""
import argparse
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import resource
import secrets
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import policy as P

DOCKER = '/usr/bin/docker'
RESOURCES = dict(cpus=1, memory=512*1024**2, memory_swap=512*1024**2, pids=64,
                 tmpfs=64*1024**2, probe_seconds=20, execution_seconds=90, cleanup_seconds=35,
                 probe_stream_bytes=16*1024, controller_bytes=2*1024**2, controller_commands=24)
HELPERS = {'owned_process.py':'83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f',
           'reference_controller.py':'e7c8935f342d4b36bb6f8f24c0b48c3b8aa04be9807f62c3f8141aeaf26819fc'}
ACTUAL = dict(image_id=None, binary_qualification=None, context_qualification=None, namespace_qualification=None)
NS = ('user','mnt','net','pid')

# Passed only to the immutable-image Python interpreter, never archive code.
CONTEXT = """def context():
 import os
 from pathlib import Path
 return dict(uid=os.getuid(),gid=os.getgid(),ns={n:os.readlink('/proc/self/ns/'+n)for n in ('user','mnt','net','pid')})
"""
INNER = CONTEXT + """
import json,os,socket,sys
from pathlib import Path
request=json.loads(sys.argv[1]);current=context();work=Path(request['work'])
assert not list((work/'hidden').iterdir())
assert (work/'readonly/input').read_bytes()==b'namespace-preflight-only\\n'
try:
 with (work/'readonly/input').open('wb')as f:f.write(b'forbidden')
except OSError as e:
 assert e.errno==30
else:raise ValueError('read-only fixture was writable')
current.update(kind='NESTED_NAMESPACE_PROBE_DATA_V1',stage=request['stage'],net_interfaces=[n for _,n in socket.if_nameindex()],uid_map=Path('/proc/self/uid_map').read_text()[:4096],gid_map=Path('/proc/self/gid_map').read_text()[:4096],bwrap_parent=request.get('bwrap_parent'))
print(json.dumps(current,sort_keys=True))
"""
MAPPED = CONTEXT + """
import json,os,sys
request=json.loads(sys.argv[1]);request['bwrap_parent']=context()
os.execv('/usr/bin/unshare',['/usr/bin/unshare','--user','--map-root-user','--','/usr/bin/python3','-I','-B','-c',sys.argv[2],json.dumps(request)])
"""


def need(ok, why):
    if not ok:raise ValueError(why)


def load(path, name, expected):
    raw=P.read(path);need(P.pin(raw)['sha256']==expected,'whole existing supervision helper '+name)
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def helpers(root):
    root=Path(root)
    return load(root/'owned_process.py','namespace_probe_owned',HELPERS['owned_process.py']),load(root/'reference_controller.py','namespace_probe_container',HELPERS['reference_controller.py'])


def natural(row, zero=True):
    need(row['reaped']is True and row['ownership']=='REAPED' and not row['timeout'] and not row['signals'] and
         row['group_census']=='EMPTY_TWICE' and row['output_complete']is True and row['error']is None and
         type(row['exit'])is int and 0<=row['exit']<=255 and row['passed']is (row['exit']==0)and
         type(row['seconds'])in(int,float)and 0<=row['seconds']<row['cap_seconds'] and
         (not zero or row['passed']is True and row['exit']==0), 'natural owned command retirement required')


def supervised(O, argv, out, label, seconds, per_stream):
    # Validate before launch; fixed regular file captures, never log_fd=regular.
    need(type(seconds)in(int,float)and 1<seconds<=60 and type(per_stream)is int and 0<per_stream<=128*1024,'finite supervision/capture bounds')
    O.prepare();child=None
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE,(per_stream,per_stream))
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        resource.setrlimit(resource.RLIMIT_CPU,(math.ceil(seconds)+5,math.ceil(seconds)+5))
        resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3))
        resource.setrlimit(resource.RLIMIT_NOFILE,(128,128))
    try:
        with (out/(label+'.stdout')).open('xb')as so,(out/(label+'.stderr')).open('xb')as se:
            os.fchmod(so.fileno(),0o600);os.fchmod(se.fileno(),0o600)
            child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=so,stderr=se,start_new_session=True,
                                   env={'PATH':'/usr/bin:/bin','HOME':str(out),'LC_ALL':'C.UTF-8','TZ':'UTC'},preexec_fn=limits)
            row=O.supervise(child,cap=seconds,retirement=.5,grace=.1,streams=(),max_output=0,log_fd=None)
    finally:
        if child is not None and child.returncode is None and child._child_created:
            O.supervise(child,cap=1.5,retirement=.5,grace=.1,streams=(),max_output=0,log_fd=None)
    stdout=(out/(label+'.stdout')).read_bytes();stderr=(out/(label+'.stderr')).read_bytes()
    need(len(stdout)<=per_stream and len(stderr)<=per_stream,'complete bounded command captures')
    row=dict(row);row.pop('output',None);row['cap_seconds']=seconds
    return row,stdout,stderr


def nested_argv(work, stage):
    need(stage in ('bwrap','mapped-root'),'fixed probe stage')
    work=Path(work)
    prefix=['/usr/bin/bwrap','--unshare-net','--ro-bind','/','/','--proc','/proc','--dev','/dev',
            '--tmpfs','/tmp','--bind',str(work),str(work),'--ro-bind',str(work/'readonly'),str(work/'readonly'),
            '--chdir',str(work),'--tmpfs',str(work/'hidden')]
    request=json.dumps(dict(stage=stage,work=str(work)),sort_keys=True)
    return prefix+['/usr/bin/python3','-I','-B','-c',INNER,request] if stage=='bwrap' else prefix+['/usr/bin/python3','-I','-B','-c',MAPPED,request,INNER]


def maps(raw):
    need(type(raw)is str and len(raw)<=4096,'bounded namespace map')
    rows=[line.split()for line in raw.splitlines()]
    need(0<len(rows)<=8 and all(len(v)==3 and all(re.fullmatch('[0-9]+',n)for n in v)for v in rows),'ordinary namespace map rows')
    return [[int(n)for n in row]for row in rows]


def effects(outer, value, stage):
    need(value['kind']=='NESTED_NAMESPACE_PROBE_DATA_V1'and value['stage']==stage and value['net_interfaces']==['lo'],'exact stage and loopback-only observations')
    context_rows=[outer,value]+([value['bwrap_parent']]if stage=='mapped-root'else[])
    for row in context_rows:
        need(type(row)is dict and all(type(row[n])is int and 0<=row[n]<2**32 for n in ('uid','gid'))and
             set(row['ns'])==set(NS)and all(type(row['ns'][n])is str and len(row['ns'][n])<=64 and re.fullmatch(n+r':\[[0-9]+\]',row['ns'][n])for n in NS),'actual bounded namespace identities/links')
    need(outer['uid']>0 and outer['gid']>0,'ordinary outer identity')
    need(value['ns']['pid']==outer['ns']['pid'],'no PID namespace selected')
    need(all(value['ns'][n]!=outer['ns'][n]for n in ('user','mnt','net')),'required nested namespace links differ')
    maps(value['uid_map']);maps(value['gid_map'])
    if stage=='bwrap':need((value['uid'],value['gid'])==(outer['uid'],outer['gid'])and value['bwrap_parent']is None,'ordinary bwrap identity preserved')
    else:
        parent=value['bwrap_parent']
        need(type(parent)is dict and (parent['uid'],parent['gid'])==(outer['uid'],outer['gid'])and
             all(parent['ns'][n]!=outer['ns'][n]for n in ('user','mnt','net'))and parent['ns']['pid']==outer['ns']['pid'],'actual pre-unshare bwrap context')
        need(value['uid']==value['gid']==0 and value['ns']['user']!=parent['ns']['user']and
             all(value['ns'][n]==parent['ns'][n]for n in ('mnt','net','pid'))and
             maps(value['uid_map'])==[[0,parent['uid'],1]]and maps(value['gid_map'])==[[0,parent['gid'],1]],'exact mapped-root effect relative to bwrap parent')
    return True


def assess(outer, stage, retirement, stdout, stderr):
    answer=dict(stage=stage,outcome='UNKNOWN',retirement=retirement,stdout_b64=base64.b64encode(stdout).decode(),stderr_b64=base64.b64encode(stderr).decode(),cause='NOT_INFERRED')
    try:
        natural(retirement,False)
        if retirement['exit']!=0:
            if any(s in stderr for s in (b'Operation not permitted',b'Permission denied')):answer['outcome']='DENIED'
        else:
            value=json.loads(stdout);effects(outer,value,stage);answer.update(outcome='OBSERVED_REQUIRED_EFFECTS',observation=value)
    except (ValueError,KeyError,TypeError):pass
    return answer


def diagnostic(value):
    need(type(value)is dict and set(value)=={'kind','outer','binaries','binary_qualification',
         'context_qualification','observations','children_absent_twice'}and
         value.get('kind')=='NESTED_NAMESPACE_PREFLIGHT_DATA_V1'and
         value.get('children_absent_twice')is True and value.get('binary_qualification')is None and
         value.get('context_qualification')is None,'complete unqualified diagnostic DATA required')
    binaries=value.get('binaries')
    need(type(binaries)is dict and set(binaries)=={'python3','bwrap','unshare'},'all three actual binary observations required')
    for name,row in binaries.items():
        need(type(row)is dict and set(row)=={'path','resolved','bytes','sha256'}and
             row['path']=='/usr/bin/'+name and type(row['resolved'])is str and
             0<len(row['resolved'])<=4096 and row['resolved'].startswith('/')and
             Path(row['resolved']).anchor=='/'and str(Path(row['resolved']))==row['resolved']and '..'not in Path(row['resolved']).parts and
             not any(c in row['resolved']for c in '\n\r\0')and
             type(row['bytes'])is int and 0<row['bytes']<=64*1024**2 and
             type(row['sha256'])is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
             'finite original binary path/whole-file hash observation required')
    need(type(value.get('observations'))is list and len(value['observations'])==2 and
         all(type(r)is dict for r in value['observations'])and [r.get('stage')for r in value['observations']]==['bwrap','mapped-root'],'complete two-operation diagnostic DATA')
    return value


def actor():
    need(os.getpid()==1 and os.getuid()==os.geteuid()>0 and platform.machine()=='aarch64','ordinary native ARM container PID1 only')
    status=dict(line.split(':',1)for line in Path('/proc/self/status').read_text().splitlines()if ':'in line)
    need(all(int(status[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapBnd'))and status['NoNewPrivs'].strip()=='1','outer cap0/NNP required')
    O=load(Path('/runtime/owned_process.py'),'namespace_actor_owned',HELPERS['owned_process.py'])
    outer=dict(uid=os.getuid(),gid=os.getgid(),ns={n:os.readlink('/proc/self/ns/'+n)for n in NS})
    binaries={}
    for name in ('python3','bwrap','unshare'):
        p=(Path('/usr/bin')/name).resolve()
        with p.open('rb')as stream:raw=stream.read(64*1024**2+1)
        need(0<len(raw)<=64*1024**2,'bounded actual image binary')
        binaries[name]=dict(path='/usr/bin/'+name,resolved=str(p),**P.pin(raw))
    report=dict(kind='NESTED_NAMESPACE_PREFLIGHT_DATA_V1',outer=outer,binaries=binaries,binary_qualification=None,context_qualification=None,observations=[],children_absent_twice=False)
    with tempfile.TemporaryDirectory(prefix='namespace-preflight-',dir='/tmp')as temporary:
        work=Path(temporary);(work/'readonly').mkdir();(work/'hidden').mkdir();(work/'readonly/input').write_bytes(b'namespace-preflight-only\n');(work/'readonly/input').chmod(0o600);(work/'hidden/marker').write_bytes(b'hidden\n')
        for stage in ('bwrap','mapped-root'):
            retirement,stdout,stderr=supervised(O,nested_argv(work,stage),work,stage,20,RESOURCES['probe_stream_bytes'])
            report['observations'].append(assess(outer,stage,retirement,stdout,stderr))
    for _ in range(2):
        need(sorted(p for p in os.listdir('/proc')if p.isdecimal())==['1'],'unexpected container child remains')
        time.sleep(.02)
    report['children_absent_twice']=True
    print(json.dumps(report,sort_keys=True));return 0  # Diagnostic completion is not namespace support.


def create_argv(image, name, labels, cid, profile, runtime, uid, gid):
    return ['docker','create','--pull=never','--platform=linux/arm64','--cidfile',str(cid),'--name',name,'--init=false',
            *[v for k,val in sorted(labels.items())for v in ('--label',k+'='+val)],'--user='+str(uid)+':'+str(gid),
            '--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges',
            '--security-opt','seccomp='+str(profile),'--cpus=1','--memory=512m','--memory-swap=512m','--pids-limit=64',
            '--ipc=private','--tmpfs','/tmp:rw,nosuid,nodev,exec,size=64m','--mount','type=bind,source='+str(HERE)+',target=/probe,readonly',
            '--mount','type=bind,source='+str(runtime/'owned_process.py')+',target=/runtime/owned_process.py,readonly',
            '--entrypoint=/usr/bin/python3',image,'-I','-B','/probe/probe.py','--inside-probe']


def unique_json(raw):
    def pairs(rows):
        need(len(rows)==len(dict(rows)),'duplicate JSON key refused')
        return dict(rows)
    return json.loads(raw,object_pairs_hook=pairs)


def confinement(row, name, image, labels, runtime, uid, gid):
    need(re.fullmatch('[0-9a-f]{64}',row['Id'])and row['Name']=='/'+name and row['Image']==image and row['Config']['Labels']==labels,'exact owned container identity')
    need(row['Config']['User']==str(uid)+':'+str(gid)and row['Config']['Entrypoint']==['/usr/bin/python3']and row['Config']['Cmd']==['-I','-B','/probe/probe.py','--inside-probe'],'exact ordinary probe entry')
    h=row['HostConfig'];need(h['ReadonlyRootfs']is True and h['NetworkMode']=='none'and h['CapDrop']==['ALL']and not h['CapAdd']and h['Privileged']is False and not h['Devices']and not h.get('DeviceRequests')and h.get('Init')is False and h.get('PidMode','')==''and h.get('IpcMode')=='private'and h.get('UTSMode','')==''and not h.get('PortBindings')and not h.get('PublishAllPorts')and not h.get('Binds'),'cap0 offline readonly probe only')
    need(all(type(h[k])is int for k in ('Memory','MemorySwap','NanoCpus','PidsLimit'))and h['Memory']==h['MemorySwap']==512*1024**2 and h['NanoCpus']==1000000000 and h['PidsLimit']==64 and h['Tmpfs']=={'/tmp':'rw,nosuid,nodev,exec,size=64m'},'fixed preflight resources')
    opts=h['SecurityOpt'];need(type(opts)is list and len(opts)==2 and sum(v in ('no-new-privileges','no-new-privileges=true')for v in opts)==1,'exact NNP plus seccomp options')
    sec=[v for v in opts if v.startswith('seccomp=')];need(len(sec)==1 and unique_json(sec[0][8:])==json.loads((HERE/'nested-seccomp.json').read_bytes()),'exact loaded namespace profile, not a path/unconfined')
    expected={('bind',str(HERE),'/probe',False),('bind',str(runtime/'owned_process.py'),'/runtime/owned_process.py',False)}
    need(len(row['Mounts'])==2 and {(m['Type'],m['Source'],m['Destination'],m['RW'])for m in row['Mounts']}==expected,'only two readonly trusted-code mounts')


def run(image, profile, profile_sha256, output, runtime_root, allow=False):
    need(allow and sys.flags.isolated and __debug__,'separate explicit Root admission required before execution')
    need(type(image)is str and re.fullmatch('sha256:[0-9a-f]{64}',image),'immutable image ID required')
    raw=P.request(profile,profile_sha256,'none','native');need(raw is not None,'explicit reviewed namespace profile required')
    code_pins={n:P.pin(P.read(HERE/n))for n in ('probe.py','policy.py')}
    need(all(','not in str(p)for p in (HERE,Path(runtime_root),Path(output))),'Docker path delimiters refused')
    O,B=helpers(runtime_root);runtime=Path(runtime_root);out=Path(output)
    need(out.is_absolute()and out==out.resolve()and not out.exists()and not any(p.is_symlink()for p in (out,*out.parents)),'fresh ordinary private output')
    out.mkdir(mode=0o700);start=time.monotonic();count=0;records=[];scope=None;state=B.Cancellation();state.__enter__()
    report=dict(status='HOLD',image_id=image,namespace_qualification=None,binary_qualification=None,context_qualification=None,code_pins=code_pins,cleanup={})
    def command(argv,deadline,large=False):
        nonlocal count
        remaining=min(deadline,start+125)-time.monotonic();need(remaining>1 and count<24,'finite command/whole preflight budget')
        limit=128*1024 if large else 32*1024
        used=sum(p.stat().st_size for p in out.iterdir()if p.is_file());need(used+2*limit+(128*1024 if state.cleaning else 512*1024)<=RESOURCES['controller_bytes'],'finite complete preflight output budget')
        count+=1;need(argv[0]=='docker','fixed Docker CLI only')
        actual=[DOCKER,'--host=unix:///var/run/docker.sock',*argv[1:]]
        row,stdout,stderr=supervised(O,actual,out,f'{count:02}',min(60 if large else 8,remaining),limit)
        records.append(dict(argv=actual,retirement=row,stdout=P.pin(stdout),stderr=P.pin(stderr)))
        natural(row)
        return subprocess.CompletedProcess(argv,row['exit'],stdout,stderr)
    def cmd(argv,large=False):return command(argv,start+90,large)
    try:
        server=cmd(P.COMMAND);need(not server.stderr,'fresh Engine query stderr must be empty');observed=P.server(json.loads(server.stdout));P.retain(raw,observed,out)
        rows=json.loads(cmd(['docker','image','inspect',image]).stdout);need(len(rows)==1,'sole image inspection');parent=rows[0]
        need(parent['Id']==image and parent['Architecture']=='arm64'and parent['Os']=='linux'and not parent['Config'].get('Volumes'),'native immutable image without implicit volumes')
        need(type(parent['Config'].get('Labels')or{})is dict and len(parent['Config'].get('Labels')or{})<=61 and
             all(type(k)is type(v)is str and len(k)+len(v)<=4096 and '\n'not in k+v for k,v in (parent['Config'].get('Labels')or{}).items()),'bounded parent labels')
        name='cachy-nested-preflight-'+secrets.token_hex(12);labels=dict(parent['Config'].get('Labels')or{});labels.update({'org.cachy-asahi.namespace-probe-owner':str(os.getuid()),'org.cachy-asahi.namespace-probe-token':name,'org.cachy-asahi.namespace-probe-profile':P.PROFILE['sha256']})
        class Scope(B.OwnedContainer):
            def call(self,argv,deadline):return command(argv,deadline)
            def validate(self,row):confinement(row,self.name,self.image,self.labels,runtime,os.getuid(),os.getgid())
        scope=Scope(name,out/'container.cid',image,labels,HERE,out)
        need(scope.listing(start+90)is None,'fresh probe name already exists');scope.submitted=True
        cmd(create_argv(image,name,labels,scope.cidfile,out/'nested-seccomp.json',runtime,os.getuid(),os.getgid()))
        scope.recover(start+90)
        try:cmd(['docker','start','-a',name],True)
        finally:
            console=cmd(['docker','logs',name],True)
        terminal=scope.recover(start+90);need(not terminal['State']['Running']and terminal['State']['ExitCode']==0 and not terminal['State']['OOMKilled'],'natural completed diagnostic container required')
        data=diagnostic(unique_json(console.stdout))
        need((data['outer']['uid'],data['outer']['gid'])==(os.getuid(),os.getgid()),'actual actor identity matches fixed container user')
        for row in data['observations']:
            checked=assess(data['outer'],row['stage'],row['retirement'],base64.b64decode(row['stdout_b64'],validate=True),base64.b64decode(row['stderr_b64'],validate=True))
            need(row==checked,'complete original command bytes and observed effects join')
        need({n:P.pin(P.read(HERE/n))for n in code_pins}==code_pins,'trusted probe source changed during operation')
        report['observations'] = data
        P.verify(out,P.descriptor(observed))
        report['status'] = 'OBSERVATIONS_RETAINED_NOT_QUALIFICATION'
    except BaseException as error:report['failure']=dict(type=type(error).__name__,message=str(error)[:1000])
    finally:
        state.cleaning=True
        if scope is not None:scope.cleanup(report['cleanup'])
        if state.pending:report.update(cancelled=True,status='HOLD_CANCELLED')
        if not report['cleanup'].get('owned_container_absence_verified')or report['cleanup'].get('cleanup_errors'):report['status']='HOLD_CLEANUP_OR_NOT_ENTERED'
        report['commands']=records
        try:
            encoded=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode();need(len(encoded)<=128*1024,'bounded complete preflight report');(out/'preflight.json').write_bytes(encoded)
        finally:state.__exit__(None,None,None)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--inside-probe',action='store_true');p.add_argument('--allow-preflight',action='store_true')
    for n in ('image','profile','profile-sha256','output','runtime-root'):p.add_argument('--'+n)
    a=p.parse_args()
    if a.inside_probe:return actor()
    if any(getattr(a,n)is None for n in ('image','profile','profile_sha256','output','runtime_root')):
        p.error('execution requires explicit image/profile/hash/output/runtime-root')
    result=run(a.image,Path(a.profile),a.profile_sha256,Path(a.output),Path(a.runtime_root),a.allow_preflight)
    return 0 if result['status']=='OBSERVATIONS_RETAINED_NOT_QUALIFICATION'and all(r['outcome']=='OBSERVED_REQUIRED_EFFECTS'for r in result['observations']['observations'])else 2


if __name__=='__main__':raise SystemExit(main())
