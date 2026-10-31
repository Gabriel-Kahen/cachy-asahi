# SPDX-License-Identifier: MIT
"""Marked diskless guest only; source-owned supervisor and ordinary exec paths."""
import base64,ctypes,hashlib,importlib.util,json,os,re,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import runtime as R

def main(nonce,release):
 R.need(re.fullmatch('[a-f0-9]{32}',nonce) and os.getuid()==os.geteuid()==0 and os.getpid()!=1 and os.uname().machine=='aarch64' and os.uname().release==release and os.sysconf('SC_PAGE_SIZE')==16384 and 'armexperiments16k=1' in Path('/proc/cmdline').read_text().split(),'marked actual generic16K bootstrap only')
 receipt=json.loads(Path('/arm-inputs.json').read_bytes());R.need(len(receipt['files'])==30,'finite exact retained selection')
 def read(name):
  path=Path('/experiments')/name;R.need(name in {n.removeprefix('experiments/') for n in receipt['files']} and not path.is_symlink(),'fixed original selected leaf');raw=path.read_bytes();R.need(R.pin(raw)==receipt['files']['experiments/'+name],'retained input changed');return raw
 for name in receipt['files']:read(name.removeprefix('experiments/'))
 libc=ctypes.CDLL(None,use_errno=True);R.need(libc.prctl(38,1,0,0,0)==0,'no-new-privileges required')
 for bit in range(64):
  if libc.prctl(24,bit,0,0,0)!=0:R.need(ctypes.get_errno()==22,'drop capability bounding set')
 R.need(libc.prctl(47,4,0,0,0)==0,'clear ambient caps');work=Path('/tmp/arm16k');work.mkdir(mode=0o700);os.chown(work,23001,23001);os.setgroups([]);os.setgid(23001);os.setuid(23001)
 status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line);R.need(os.getuid()==os.geteuid()==os.getgid()==23001 and os.getgroups()==[] and all(int(status[k].strip(),16)==0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')) and status['NoNewPrivs'].strip()=='1','ordinary zero-cap/NNP guest identity')
 spec=importlib.util.spec_from_file_location('owned_supervisor','/arm/runner.py');supervisor=importlib.util.module_from_spec(spec);spec.loader.exec_module(supervisor);started=time.monotonic()
 def invoke(argv,data):
  R.need(time.monotonic()-started<840 and len(data)<=1024**2,'bounded runtime trial/input');path=work/'stdin.bin';path.write_bytes(data)
  fixed=R.fixed_argv(argv)
  row,out,err,error=supervisor.run_command(fixed,work,R.ENV,30,2*1024**2);R.need(error is None and row['group_absence_verified'],'original supervised command/retirement');row['stderr_bytes']=len(err);return row['exit_code'],out,row
 result=R.suite(receipt,read,invoke)
 for name in receipt['files']:read(name.removeprefix('experiments/'))
 result.update(page_size=16384,kernel=release,uid=23001,groups=[],caps='ALL_ZERO',no_new_privs=1,original_inputs_preserved=True)
 encoded=json.dumps(result,sort_keys=True,separators=(',',':')).encode();R.need(len(encoded)<=512*1024,'bounded correctness receipt');print('ARM_EXPERIMENTS16K '+nonce+' '+base64.b64encode(encoded).decode(),flush=True)
if __name__=='__main__':main(*sys.argv[1:])
