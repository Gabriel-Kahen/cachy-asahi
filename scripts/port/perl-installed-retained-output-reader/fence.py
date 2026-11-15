# SPDX-License-Identifier: MIT
"""Exact fixed passive-code and Source-capsule output domain, no artifact execution."""
import importlib.util,os,sys
from pathlib import Path

class Fence:
 def __init__(self,reads,code,writes,dirs):
  self.reads=set(map(str,reads));self.code=code;self.writes=writes;self.dirs=set(map(str,dirs));self.enabled=False;self.denied=[];self.original_spec=importlib.util.spec_from_file_location;self.imports=set(sys.modules)
 def refuse(self,why):self.denied.append(why);raise PermissionError('retained-output passive fence: '+why)
 def path(self,value):
  if isinstance(value,int):
   s=os.fstat(value)
   for name in self.reads|set(self.writes):
    try:t=os.stat(name,follow_symlinks=False)
    except FileNotFoundError:continue
    if(s.st_dev,s.st_ino)==(t.st_dev,t.st_ino):return name
   return self.refuse('undeclared descriptor')
  p=Path(os.fsdecode(value))
  if not p.is_absolute()or p!=p.resolve()or any(q.is_symlink()for q in(p,*p.parents)):return self.refuse('noncanonical operand')
  return str(p)
 def check(self,event,args):
  if not self.enabled:return
  if event=='open':
   name=self.path(args[0]);flags=args[2]
   if flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
    if name not in self.writes or flags&os.O_APPEND:return self.refuse('write outside exact capsule/result domain')
   elif name not in self.reads|set(self.writes):return self.refuse('undeclared read')
  elif event=='os.mkdir':
   if self.path(args[0])not in self.dirs or args[1]!=0o700:return self.refuse('undeclared private directory')
  elif event=='os.chmod':
   name=self.path(args[0])
   if name not in self.writes or args[1]!=self.writes[name]:return self.refuse('undeclared protected mode')
  elif event in('os.scandir','os.listdir'):
   if self.path(args[0])not in self.dirs:return self.refuse('undeclared directory listing')
  elif event=='compile':
   raw,name=args
   if name not in self.code or(raw.encode()if isinstance(raw,str)else raw)!=self.code[name]:return self.refuse('undeclared code bytes')
  elif event=='exec':
   if args[0].co_filename not in self.code:return self.refuse('artifact or undeclared code')
  elif event=='import':
   if args[0]not in self.imports:return self.refuse('unreviewed dynamic import')
  elif event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn'))or event in('os.system','pty.spawn','os.remove','os.unlink','os.rename','os.rmdir','os.symlink','os.link','os.chown','os.chdir','os.fchdir','os.chroot','os.putenv','os.unsetenv','os.kill','os.killpg','resource.setrlimit'):return self.refuse(event)
 def spec(self,name,path,*args,**kwargs):
  path=str(Path(path))
  if path not in self.code or Path(path).read_bytes()!=self.code[path]:return self.refuse('only whole-pinned passive modules may import')
  body=self.code[path]
  class Loader:
   def create_module(self,spec):return None
   def exec_module(self,module):
    module.__file__=path
    exec(compile(body,path,'exec'),module.__dict__)
  spec=importlib.util.spec_from_loader(name,Loader(),origin=path);spec.has_location=True;return spec
 def __enter__(self):
  self.enabled=True;importlib.util.spec_from_file_location=self.spec;sys.addaudithook(self.check);return self
 def __exit__(self,*args):self.enabled=False;importlib.util.spec_from_file_location=self.original_spec
