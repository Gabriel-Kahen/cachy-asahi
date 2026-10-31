#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Current CI only: authenticated ZLE queued reset; historical checker stays held."""
import ast,hashlib,importlib.util,json,os,signal,stat,sys,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('_original_zsh_readiness',HERE/'zsh-substring-readiness-wrapper.py');W=importlib.util.module_from_spec(s);s.loader.exec_module(W)
DERIVED='98e37086de5c32fee32e9774dcd55c6e1ca4cb966f976f12b0c310dfe988c2a9'

def derive(raw):
 W.need(len(raw)==12038 and hashlib.sha256(raw).hexdigest()==W.CHECKER,'exact original checker before reset derivation')
 text=raw.decode()
 for old,new in [('bindkey -e\n',"bindkey -e\nbindkey '^G' send-break\n"),("terminal.send(b'\\x03')","terminal.send(b'\\x07')")]:
  W.need(text.count(old)==1,'single exact reset adapter anchor');text=text.replace(old,new)
 changed=text.encode();W.need(hashlib.sha256(changed).hexdigest()==DERIVED and len(changed)==12062,'exact declared derived checker')
 funcs=lambda d:{n.name:ast.dump(n,include_attributes=False) for n in ast.parse(d).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
 before,after=funcs(raw),funcs(changed);W.need([n for n in before if before[n]!=after[n]]==['interactive'],'only fixture interactive reset changes')
 return changed

def module(raw,filename):
 m=types.ModuleType('_explicit_zsh_queued_reset_checker');m.__file__=filename;exec(compile(raw,filename,'exec'),m.__dict__);return m

def identity():
 return dict(status='CURRENT_CI_EXPLICIT_ZLE_RESET_DERIVATIVE',original_checker_sha256=W.CHECKER,derived_checker_sha256=DERIVED,original_checker_bytes=12038,derived_checker_bytes=12062,reset='TTY_VINTR_CTRL_C_TO_QUEUED_ZLE_SEND_BREAK_CTRL_G',fixture_binding="bindkey '^G' send-break",readiness_predicates='UNCHANGED',deadlines='UNCHANGED_5_SECONDS',behavioral_cases='UNCHANGED_FIVE_OR_OPTIONAL_COEXIST',historical_checker='BYTE_HELD',acceptance_authority=False,cleanup_authority=False)

def execute(m,filename,raw,argv):
 body=ast.parse(raw).body[-1];W.need(isinstance(body,ast.If) and len(body.body)==3,'original script entry shape');entry=ast.Module(body=body.body[:-1],type_ignores=[]);before_signal=signal.getsignal(signal.SIGTERM);before_argv=sys.argv[:];observer=None
 try:
  exec(compile(entry,filename,'exec'),m.__dict__);sys.argv=[filename,*argv]
  parser=m.argparse.ArgumentParser(add_help=False);parser.add_argument('--work',type=Path);args,_=parser.parse_known_args(argv)
  if args.work is not None:observer=W.Observer(m,Path(filename),raw,args.work.absolute());observer.install()
  return m.main()
 finally:
  sys.argv=before_argv;signal.signal(signal.SIGTERM,before_signal)
  if observer is not None:
   observer.restore();work=observer.work
   W.need(work.is_dir() and not any(p.is_symlink() for p in (work,*work.parents)) and work.stat().st_uid==os.getuid() and stat.S_IMODE(work.stat().st_mode)==0o700,'original owned private fixture workspace')
   def save(name,value):
    data=W.encoded(value);W.need(len(data)<=8192,'bounded adapter facts');fd=os.open(work/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(data)
    return data
   facts=identity();save('reset-adapter.json',facts);print('ZSH_SUBSTRING_RESET_ADAPTER '+W.encoded(facts).decode(),end='',flush=True)
   if observer.failures:
    value=observer.project();value.update(checker_sha256=DERIVED,original_checker_sha256=W.CHECKER,execution='EXPLICIT_DERIVED_RESET_NOT_BYTE_EXACT_ORIGINAL');data=save('outer-readiness.json',value);print('ZSH_SUBSTRING_READINESS '+data.decode(),end='',flush=True)

def run(checker,argv):
 checker,original=W.source(checker);raw=derive(original);filename=str(HERE/'zsh-substring-zle-reset-adapter.py')+'::derived-checker';return execute(module(raw,filename),filename,raw,argv)
if __name__=='__main__':
 W.need(len(sys.argv)>=2,'explicit historical checker required');raise SystemExit(run(sys.argv[1],sys.argv[2:]))
