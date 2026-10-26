# SPDX-License-Identifier: MIT
"""Fixed607 build inventory and pre-build ownership; never GUI acceptance."""
import fcntl,hashlib,json,os,re,stat,types
from pathlib import Path
TARGET=dict(bytes=12076,sha256='be35402204ba5c03d78279722afa83047c9575d2da70fb5c4064f46ed15954c5')
PHASE=dict(schema_version=1,role='runtime607',phase='ALIAS_BOUND_PRE_BUILD',build_requested=False)
STEP='''      - name: Fixed607 build boundary and early owned retirement controls before secrets
        timeout-minutes: 3
        run: python3 -I -B gui607-source/implementation/test_build_inventory.py
'''
SUFFIX=b"\n# Whole687 AND fixed607 build inventory; no actual acceptance.\ndef verify(require_known=False):\n return __import__('build_inventory_guard').verify(require_known)\n"
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def workflow(raw):
 anchor=b'      - name: Selected607 actual owner-context controls before secrets\n';need(raw.count(anchor)==1 and STEP.encode()not in raw,'one exact new build presecret command');return raw.replace(anchor,STEP.encode()+anchor,1)
def owned_read(path,cap):
 path=Path(path);need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary owned cleanup input');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded singlelink owned cleanup input');raw=os.read(fd,cap+1);need(len(raw)==a.st_size and key(a)==key(os.fstat(fd))==key(path.lstat()),'fresh whole cleanup input');return raw
 finally:os.close(fd)
def lease_retirement(original,value,terminal,lease,proof,runtime,base,current):
 """Called inside the unchanged original cleanup's acquired owner-lease scope."""
 p=value.get('resource_acquisition',{})
 if p.get('schema_version')!=2:return original(value)
 runtime=Path(runtime);base=Path(base);need(runtime.is_absolute()and runtime==runtime.resolve()and str(runtime)==proof['runtime_path']and current['original348']==proof,'exact current owner runtime/proof')
 a=os.fstat(lease);b=(runtime/'runtime.lease').lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_uid==os.getuid()and stat.S_IMODE(a.st_mode)==0o600 and (a.st_dev,a.st_ino,a.st_mode,a.st_uid,a.st_nlink)==(b.st_dev,b.st_ino,b.st_mode,b.st_uid,b.st_nlink)and not any(q.is_symlink()for q in(runtime/'runtime.lease',*runtime.parents)),'actual held owned singlelink lease FD')
 fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
 need(set(terminal)=={'schema_version','profile','mode','child_started','natural_exit','reaped','group_absent','returncode'}and type(terminal['schema_version'])is int and terminal['schema_version']==1 and all(terminal[k]is True for k in('child_started','natural_exit','reaped','group_absent'))and type(terminal['returncode'])is int and terminal['returncode']==1,'exact failed reaped actor group terminal facts')
 need(current['status']=='SOURCE_BOUND_LATEST607_GUI_NATIVE_CASE'and current['profile']==terminal['profile']==proof['profile']and current['mode']==terminal['mode']and current['case']==current['profile']+'-'+current['mode']and current['profile']in('minimal','overlay')and current['mode']in('generic4k','generic16k')and type(current['run'])is int and current['run']>0 and type(current['attempt'])is int and current['attempt']==1 and re.fullmatch('[a-f0-9]{40}',current['source'])and current['source']==proof['source_sha']==proof['workflow_sha']and str(current['run'])==proof['run_id']and str(current['attempt'])==proof['run_attempt']and current['job_token']==proof['job_token']and re.fullmatch('[a-f0-9]{16}',current['job_token']),'current exact case/source/run/job owner facts')
 report=json.loads(owned_read(base/'report.json',1024**2));ownership=report['ownership'];need(report['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION'and ownership['token']==proof['job_token']and ownership['image']==report['image']==value['base_image']and all(ownership[k]is True for k in('build_started','build_complete','probe_started','probe_complete'))and owned_read(base/'image-id',128).decode().strip()==report['image'],'original exact borrowed producer identity and current owned job')
 return original(value)
