#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Outer observations only: exact original checker argv/main/limits/PTY cleanup."""
import ast,hashlib,importlib.util,json,os,re,signal,stat,sys
from pathlib import Path
CHECKER='f79eb322f34617d43ae13deaaac057f431e8e81f11a23e8a79876158c37dff00'
CASES=('noninteractive','editing','preexisting-function','preexisting-widget','preexisting-private','coexist')
PHASES=('setup-ready','reset-prompt','snapshot-created','snapshot-done')

def need(v,w):
 if not v:raise ValueError(w)
def encoded(v):return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def source(checker):
 checker=Path(checker).absolute();need(not any(p.is_symlink() for p in (checker,*checker.parents)),'ordinary exact checker source');s=checker.stat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==12038,'original checker size/type');raw=checker.read_bytes();need(hashlib.sha256(raw).hexdigest()==CHECKER,'exact original checker hash before import or actors');return checker,raw

def phases(raw):
 tree=ast.parse(raw);interactive=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='interactive');calls=sorted((n for n in ast.walk(interactive) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='terminal' and n.func.attr=='wait'),key=lambda n:n.lineno);need(len(calls)==4,'four exact source-owned readiness callsites');return {n.lineno:label for n,label in zip(calls,PHASES)}

class Observer:
 def __init__(self,module,checker,raw,work):self.module=module;self.checker=checker;self.lines=phases(raw);self.work=work;self.states={};self.failures=[]
 def install(self):
  T=self.module.Terminal;self.original=(T.__init__,T.send,T.wait);observer=self
  def init(terminal,zsh,home):
   value=observer.original[0](terminal,zsh,home);observer.states[id(terminal)]=dict(home=Path(home),snapshots_requested=0,wait_calls=0);return value
  def send(terminal,raw):
   value=observer.original[1](terminal,raw)
   if raw.endswith(b'\x18\x04'):observer.states[id(terminal)]['snapshots_requested']+=1
   return value
  def wait(terminal,predicate):
   state=observer.states[id(terminal)];state['wait_calls']+=1;frame=sys._getframe(1);phase=observer.lines.get(frame.f_lineno) if frame.f_globals is observer.module.__dict__ and frame.f_code.co_filename==str(observer.checker) else None;del frame
   try:return observer.original[2](terminal,predicate)
   except ValueError as error:
    match=re.fullmatch(r'PTY readiness deadline/exit; status=(None|-?[0-9]{1,10})',str(error))
    if match and len(observer.failures)<6:observer.failures.append(dict(home=state['home'],phase=phase or 'UNMAPPED_SOURCE_CALLSITE',snapshots_requested=state['snapshots_requested'],wait_calls=state['wait_calls'],process_status=None if match[1]=='None' else int(match[1])))
    raise
  T.__init__,T.send,T.wait=init,send,wait
 def restore(self):self.module.Terminal.__init__,self.module.Terminal.send,self.module.Terminal.wait=self.original
 def project(self):
  # Called only after original main/finally has closed its PTYs. No buffers/paths.
  rows=[]
  for failure in self.failures:
   home=failure['home'];need(home.parent==self.work and home.name in CASES and not any(p.is_symlink() for p in (home,*home.parents)),'original fixed owned case root');s=home.stat();need(s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700,'original private fixture case')
   row={k:v for k,v in failure.items() if k!='home'};need(0<=row['snapshots_requested']<=16 and 0<row['wait_calls']<=128,'finite source-owned counters');row['case']=home.name;number=row['snapshots_requested'];row.update(snapshot_exists=(home/('snapshot-'+str(number))).is_file() if number else False,snapshot_done_exists=(home/('snapshot-'+str(number)+'.done')).is_file() if number else False,prompt_sequence=None)
   try:
    p=home/'prompt-sequence';s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1 and s.st_size<=16,'bounded original prompt counter');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:raw=f.read(17)
    need(re.fullmatch(rb'[0-9]{1,4}\n?',raw) is not None,'typed original prompt counter');row['prompt_sequence']=int(raw)
   except (OSError,ValueError):row['prompt_counter_status']='UNAVAILABLE_OR_PARTIAL'
   rows.append(row)
  return dict(status='OUTER_ZSH_READINESS_DIAGNOSTIC_ONLY',acceptance_authority=False,checker_sha256=CHECKER,projection_after_original_main_return_or_unwind=True,cleanup_authority=False,failures=rows)

def run(checker,argv):
 program=str(checker);checker,raw=source(checker);spec=importlib.util.spec_from_file_location('_exact_original_substring_checker',checker);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return execute(module,checker,raw,argv,program=program)

def execute(module,checker,raw,argv,*,program=None):
 # Reuse the exact original SIGTERM handler definition/registration, not a new policy.
 body=ast.parse(raw).body[-1];need(isinstance(body,ast.If) and len(body.body)==3,'original script entry shape');entry=ast.Module(body=body.body[:-1],type_ignores=[]);before_signal=signal.getsignal(signal.SIGTERM);before_argv=sys.argv[:];observer=None
 try:
  exec(compile(entry,str(checker),'exec'),module.__dict__);sys.argv=[program if program is not None else str(checker),*argv]
  # Parse only the original work operand; original main still validates all argv.
  parser=module.argparse.ArgumentParser(add_help=False);parser.add_argument('--work',type=Path);args,_=parser.parse_known_args(argv)
  if args.work is not None:observer=Observer(module,checker,raw,args.work.absolute());observer.install()
  return module.main()
 finally:
  sys.argv=before_argv;signal.signal(signal.SIGTERM,before_signal)
  if observer is not None:
   observer.restore()
   if observer.failures:
    try:
     value=observer.project();data=encoded(value);need(len(data)<=8192,'bounded outer readiness facts');path=observer.work/'outer-readiness.json';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
     with os.fdopen(fd,'wb') as f:f.write(data)
    except (OSError,ValueError):data=encoded(dict(status='OUTER_ZSH_READINESS_FACTS_UNAVAILABLE',acceptance_authority=False))
    print('ZSH_SUBSTRING_READINESS '+data.decode(),end='',flush=True)
if __name__=='__main__':
 need(len(sys.argv)>=2,'explicit original checker required');raise SystemExit(run(sys.argv[1],sys.argv[2:]))
