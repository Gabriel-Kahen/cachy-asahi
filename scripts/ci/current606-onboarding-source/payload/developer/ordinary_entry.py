#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real ordinary PTY/editor/C build inside the original owned native606 Docker."""
import ctypes,hashlib,importlib.util,json,os,pwd,stat,subprocess,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent/'real606')]
from native_api import C
import receipt as R

def module(path):
 spec=importlib.util.spec_from_file_location('_whole_reviewed_software_onboarding',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def security():
 fields=dict(line.split(':',1)for line in Path('/proc/self/status').read_text().splitlines()if':'in line)
 value={k:int(fields[k],16 if k.startswith('Cap')else 10)for k in('CapEff','CapPrm','CapInh','CapAmb','CapBnd','NoNewPrivs')};R.need(value==dict(CapEff=0,CapPrm=0,CapInh=0,CapAmb=0,CapBnd=0xdb,NoNewPrivs=1),'actual ordinary retained capabilities');return value

def drop(account):
 os.setgroups([]);os.setgid(account.pw_gid);os.setuid(account.pw_uid)
 class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
 class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
 libc=ctypes.CDLL(None,use_errno=True);head=Header(0x20080522,0);data=(Data*2)();R.need(libc.capset(ctypes.byref(head),ctypes.byref(data))==0 and libc.prctl(47,4,0,0,0)==0 and libc.prctl(38,1,0,0,0)==0,'whole original ordinary capability/ambient drop and NNP');return security()

def identity(path):
 a=path.lstat();R.need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_uid==os.getuid()and not path.is_symlink(),'private ordinary config');raw=path.read_bytes();key=lambda s:[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns];R.need(key(a)==key(path.lstat()),'config changed during read');return dict(identity=key(a),sha256=hashlib.sha256(raw).hexdigest(),xattrs={n:os.getxattr(path,n).hex()for n in os.listxattr(path)})

def existing(parent,output):
 parent.mkdir(mode=0o700);names={'.config/fish/config.fish':b'# original private Fish configuration\n# >>> cachy-asahi setup fish v1 >>>\n# user-owned edited block, never overwritten\n','.zshrc':b'# original private Zsh configuration\n# >>> cachy-asahi setup zsh v1 >>>\n# user-owned edited block, never overwritten\n','user-owned.conf':b'original unrelated user configuration\n'}
 for name,raw in names.items():p=parent/name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o600)
 before={n:identity(parent/n)for n in names};rows=[];env=dict(PATH='/usr/bin:/bin',HOME=str(parent),LANG='C.UTF-8',LC_ALL='C.UTF-8',TZ='UTC')
 for step,operation,apply,expected in(('preview-existing','activate',False,2),('activate-preserve-existing','activate',True,2),('remove-preserve-existing','remove',True,0)):
  argv=['/usr/bin/cachy-asahi-setup',operation,'--components','fish','zsh','--home',str(parent),'--template-root','/usr/share/cachy-asahi']+(['--apply']if apply else[]);proc=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,env=env,cwd=parent,timeout=20);R.need(len(proc.stdout)+len(proc.stderr)<=128*1024,'bounded exact config control output');(output/(step+'.stdout')).write_bytes(proc.stdout);(output/(step+'.stderr')).write_bytes(proc.stderr);reply=json.loads(proc.stdout);R.need(proc.returncode==expected and not proc.stderr and reply['operation']==operation and reply['mode']==('applied'if apply else'preview'),'actual installed config command/status');R.need({n:identity(parent/n)for n in names}==before,'existing user config full bytes/inode/owner/mode/xattrs held');rows.append(dict(step=step,argv=argv,returncode=proc.returncode,stdout_sha256=hashlib.sha256(proc.stdout).hexdigest(),stderr_sha256=hashlib.sha256(proc.stderr).hexdigest()))
 return dict(commands=rows,original_files=sorted(names),config_identity_preserved=True,before=before,after={n:identity(parent/n)for n in names})

def main():
 if sys.argv[1:]==['--help']:print('Native-only full606 installed software onboarding: verification-home fresh-private-work nonce');return
 R.need(len(sys.argv)==4,'fixed native keys/work/nonce');keys,work=map(Path,sys.argv[1:3]);nonce=sys.argv[3];C.native_scope('/',keys,'/out/setup6-native.log');R.need(work==Path('/tmp/onboarding-full606')and work.is_dir()and not any(work.iterdir())and not any(p.is_symlink()for p in(work,*work.parents)),'fresh fixed private workspace');account=pwd.getpwnam('alarm');R.need(account.pw_uid>0 and work.stat().st_uid==account.pw_uid and stat.S_IMODE(work.stat().st_mode)==0o700,'same ordinary owned workspace');observed=drop(account);os.environ.clear();os.environ.update(PATH='/usr/bin:/bin',HOME=str(work),LANG='C.UTF-8',LC_ALL='C.UTF-8',PYTHONDONTWRITEBYTECODE='1');os.chdir(work);output=work/'evidence';output.mkdir(mode=0o700)
 old=module(HERE/'held/onboarding.py');journey=old.journey(HERE/'held/hello.c',output,work/'fresh');conflicts=existing(work/'existing',output);commands=json.loads((output/'journey-commands.json').read_bytes());R.need(tuple(r['step']for r in commands)==R.STEPS,'all original journey operations present');value=dict(journey=journey,existing=conflicts,commands=commands,security=observed,uid=os.getuid(),gid=os.getgid(),nonce=nonce);(output/'ordinary-result.json').write_bytes((json.dumps(value,sort_keys=True,indent=2)+'\n').encode());print(json.dumps(value,sort_keys=True))
if __name__=='__main__':main()
