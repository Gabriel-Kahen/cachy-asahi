# SPDX-License-Identifier: MIT
"""Exact Welcome fixture derivation and bounded rooted child entry.

The original fixture's five CLI, 8/12 compiled and root-refusal assertions stay
unchanged. Only its three input paths and stdin=0 (inherited owner /dev/null)
are routed. No /dev node creation or proc mount is necessary inside the copy.
"""
import ctypes,hashlib,os,runpy,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
CONTEXT='/var/tmp/caa-setup6-fixture'

def derive(raw):
 # Own finite entrypoint; whole-held original15 native controls are separate.
 C.need(raw==C.ordinary(Path(__file__).with_name('fixture_entry.py'),128*1024),'exact source-owned Apps entrypoint')
 return raw

def zero_caps():
 class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
 class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
 libc=ctypes.CDLL(None,use_errno=True);header=Header(0x20080522,0);data=(Data*2)()
 C.need(libc.capset(ctypes.byref(header),ctypes.byref(data))==0,'drop all capability sets')
 C.need(libc.prctl(47,4,0,0,0)==0 and libc.prctl(38,1,0,0,0)==0,'clear ambient capabilities and set NNP')

def status(fd):
 os.lseek(fd,0,os.SEEK_SET);raw=os.read(fd,65537);C.need(len(raw)<=65536,'bounded held process status')
 fields={k:v.strip()for k,v in(line.split(':',1)for line in raw.decode().splitlines()if ':'in line)}
 out={k:int(fields[k],16)for k in('CapEff','CapPrm','CapBnd','CapInh','CapAmb')};out.update(NoNewPrivs=int(fields['NoNewPrivs']),uid=os.geteuid(),gid=os.getegid());return out

def enter(root,script,work,role,kind,uid,gid,environment):
 """Run only in a separately supervised child, never in the owning process."""
 C.need(Path(root)==Path('/work/main/root')and script==CONTEXT+'/fixture_entry.py','fixed owned copy/rooted fixture')
 C.need(role in('setup5','setup6')and kind=='ordinary','finite rooted fixture role/kind')
 C.need(type(work)is str and work.startswith(CONTEXT+'/outputs/')and Path(work).as_posix()==work and '..'not in Path(work).parts,'fixed owned fixture output')
 C.need(type(uid)is int and type(gid)is int and((kind=='ordinary'and uid>0 and gid>0)or(kind=='root-guard'and uid==gid==0)),'explicit root/ordinary fixture identity')
 C.need(type(environment)is dict and set(environment)=={'HOME','PATH','LANG','LC_ALL','PYTHONDONTWRITEBYTECODE','XDG_CONFIG_HOME','XDG_CACHE_HOME','XDG_DATA_HOME','XDG_STATE_HOME','XDG_RUNTIME_DIR','TMPDIR'},'closed no-display ordinary environment')
 C.need(environment['PATH']=='/usr/bin:/bin'and environment['PYTHONDONTWRITEBYTECODE']=='1'and all(type(v)is str and '\0'not in v for v in environment.values()),'bounded fixture environment')
 # Retained proc descriptor is opened before chroot; it observes this child after
 # UID/cap changes without mounting /proc inside the supplied ordinary tree.
 proc=os.open('/proc/self/status',os.O_RDONLY|os.O_CLOEXEC)
 try:
  C.capability_profile(status(proc));fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:os.fchdir(fd);os.chroot('.');os.chdir('/')
  finally:os.close(fd)
  if kind=='ordinary':os.setgroups([]);os.setgid(gid);os.setuid(uid);zero_caps()
  C.capability_profile(status(proc),ordinary_child=kind=='ordinary')
 finally:os.close(proc)
 C.need(os.fstat(0).st_rdev==os.makedev(1,3),'owner-inherited stdin must be /dev/null')
 os.environ.clear();os.environ.update(environment)
 sys.argv=[script,*(['--root-guard']if kind=='root-guard'else[]),work,role]
 runpy.run_path(script,run_name='__main__')

def stage(target):
 C.need(Path(target)==Path('/work/main/root'),'exact copied-root fixture target')
 base=Path(__file__).resolve().parents[3]
 rows={'fixture_entry.py':Path(__file__).with_name('fixture_entry.py'),'expected606.lock':Path(__file__).with_name('expected606.lock')}
 rows.update({'setup/'+n:base/'held-setup'/n for n in('setup.py','setup5.py','test_setup.py','test_shell_modules.py','test_recovery_preview.py','recovery_preview.py')})
 values={n:C.ordinary(p,1024**2)for n,p in rows.items()}
 root=Path(target)/CONTEXT.lstrip('/');C.need(not root.exists()and not root.is_symlink()and not any(p.is_symlink()for p in(root.parent,*root.parent.parents)),'fresh ordinary fixture context')
 root.mkdir(mode=0o700)
 for name,raw in values.items():
  path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o444)
 for d in root.rglob('*'):
  if d.is_dir():d.chmod(0o755)
 (root/'outputs').mkdir(mode=0o755);(root/'homes').mkdir(mode=0o755);root.chmod(0o755)
 return dict(context=CONTEXT,files={n:C.pin(raw)for n,raw in values.items()},derived_fixture_sha256=C.pin(values['fixture_entry.py'])['sha256'],routing='ACTUAL_SIGNED_INSTALLED_SETUP6_PURE_SIX_RECOVERY_CONTROLS_REAL_SHELL_NOT_RUN')

def _failure_data(value,spec):
 """Failure-only bounded original stream DATA; never alters the original guard."""
 try:
  import base64,json
  streams={}
  for name in('stdout','stderr'):
   raw=value[name];tail=raw[-2048:];streams[name]=dict(C.pin(raw),tail_bytes=len(tail),tail_sha256=C.pin(tail)['sha256'],tail_base64=base64.b64encode(tail).decode(),omitted_bytes=len(raw)-len(tail),truncated=len(raw)>len(tail))
  record=dict(schema_version=1,status='ROOTED_FIXTURE_FAILURE_DATA_NOT_ACCEPTANCE',spec_sha256=C.pin(C.encoded(spec))['sha256'],role=spec['role'],kind=spec['kind'],uid=spec['uid'],gid=spec['gid'],outcome={k:value[k]for k in('returncode','termination','direct_child_reaped','group_kill_sent','group_retired','descendants_reaped')},streams=streams,acceptance='NOT_GRANTED')
  raw=(json.dumps(record,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode()
  C.need(len(raw)<=8192 and sum(value[k].__len__()for k in('stdout','stderr'))<=128*1024,'bounded original rooted fixture failure DATA')
  sys.stderr.write('CURRENT606_ROOTED_FIXTURE_FAILURE '+raw.decode());sys.stderr.flush()
 except Exception:pass


def run(spec,*,spec_path,timeout=70):
 """Supervise one source-owned child; the enclosing worker owns target lifetime."""
 sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'held-copy/scripts/update'))
 import supervised
 C.need(type(timeout)in(int,float)and 0<timeout<=70,'bounded remaining rooted fixture deadline')
 path=Path(spec_path);C.need(path.parent==Path('/work/fixture-plans')and not path.exists()and not path.is_symlink(),'fresh owned rooted-fixture plan')
 raw=C.encoded(spec);C.need(len(raw)<=16384,'finite rooted-fixture plan')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb')as out:out.write(raw)
 value=supervised.run([sys.executable,'-I','-B',str(Path(__file__).resolve()),'--enter',str(path)],env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'},cwd='/',timeout=timeout,output_limit=128*1024,grace=1,signal_uid=spec['uid'])
 if not(value['returncode']==0 and value['termination']is None and value['direct_child_reaped']is True and value['group_retired']is True):_failure_data(value,spec)
 C.need(value['returncode']==0 and value['termination']is None and value['direct_child_reaped']is True and value['group_retired']is True,'rooted Welcome fixture failed; retained disposal required')
 receipt=C.decode(value['stdout']);C.need(type(receipt)is dict and receipt.get('recipe_role')==spec['role'],'typed rooted fixture receipt')
 return dict(receipt=receipt,retirement={k:value[k]for k in('returncode','termination','direct_child_reaped','group_kill_sent','group_retired','descendants_reaped')},stdout=C.pin(value['stdout']),stderr=C.pin(value['stderr']))

def main():
 C.need(len(sys.argv)==3 and sys.argv[1]=='--enter','fixed private rooted fixture child entry')
 path=Path(sys.argv[2]);C.need(path.parent==Path('/work/fixture-plans'),'fixed owner plan directory')
 spec=C.decode(C.ordinary(path,16384));C.need(set(spec)=={'root','script','work','role','kind','uid','gid','environment','derived_fixture_sha256'},'closed rooted fixture spec')
 raw=C.ordinary(Path(spec['root'])/spec['script'].lstrip('/'),128*1024)
 C.need(raw==derive(raw)and C.pin(raw)['sha256']==spec['derived_fixture_sha256'],'whole actual rooted fixture source')
 enter(**{k:v for k,v in spec.items()if k!='derived_fixture_sha256'})
if __name__=='__main__':main()
