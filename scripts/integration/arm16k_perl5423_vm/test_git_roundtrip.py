#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Export only this committed source family to fresh temp DATA; run fenced Source check."""
import hashlib,io,os,subprocess,sys,tarfile,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
CHECK=r'''
import importlib.util,sys
from pathlib import Path
p=Path(sys.argv[1])
def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):raise RuntimeError('source roundtrip fence: '+event)
sys.addaudithook(fence)
s=importlib.util.spec_from_file_location('committed_perl_source',p/'adapter.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
m.source(sys.argv[2])
print('PASS_COMMITTED_GIT_SOURCE_ROUNDTRIP_DATA_ONLY')
'''


def main():
 if not(sys.flags.isolated and sys.dont_write_bytecode and __debug__):raise ValueError('isolated Python source regression')
 root=Path(subprocess.run(['/usr/bin/git','-C',str(HERE),'rev-parse','--show-toplevel'],check=True,stdout=subprocess.PIPE,timeout=10).stdout.decode().strip());prefix=HERE.relative_to(root).as_posix()
 raw=subprocess.run(['/usr/bin/git','-C',str(root),'-c','tar.umask=0022','archive','--format=tar','HEAD','--',prefix],check=True,stdout=subprocess.PIPE,timeout=10).stdout
 if len(raw)>4*1024**2:raise ValueError('finite committed source export')
 with tempfile.TemporaryDirectory(prefix='perl5423-git-roundtrip-')as tmp:
  out=Path(tmp)
  with tarfile.open(fileobj=io.BytesIO(raw),mode='r:')as archive:
   for member in archive:
    path=out/member.name
    if member.isdir():path.mkdir(parents=True,exist_ok=True);continue
    if not(member.isfile()and member.name.startswith(prefix+'/')and '..'not in Path(member.name).parts and member.mode in(0o644,0o755)):raise ValueError('ordinary Git source leaves/modes only')
    path.parent.mkdir(parents=True,exist_ok=True);body=archive.extractfile(member).read()
    with path.open('xb')as stream:stream.write(body)
    path.chmod(member.mode)
  source=out/prefix;digest=hashlib.sha256((source/'source.lock.json').read_bytes()).hexdigest()
  subprocess.run([sys.executable,'-I','-B','-c',CHECK,str(source),digest],check=True,timeout=15)
if __name__=='__main__':main()
