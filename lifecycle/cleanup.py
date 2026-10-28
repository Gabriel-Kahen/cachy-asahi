#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Complete original owned HOME/config retirement with current VM custody."""
import os,sys,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import entry
def cleanup_failure_diagnostic(error,proof):
 """Bounded exception DATA only; never read paths or grant cleanup authority."""
 import base64,json,os,re
 def path(value):
  if value is None:return dict(status='ABSENT',exact=True,base64=None)
  if type(value)not in(str,bytes):return dict(status='UNSUPPORTED_PATH_TYPE',exact=False,base64=None)
  if len(value)>4096:return dict(status='OVERSIZE_PATH_NOT_EXPORTED',exact=False,units=len(value),base64=None)
  try:raw=os.fsencode(value)
  except UnicodeError:return dict(status='UNENCODABLE_PATH_NOT_EXPORTED',exact=False,base64=None)
  if len(raw)>4096:return dict(status='OVERSIZE_PATH_NOT_EXPORTED',exact=False,bytes=len(raw),base64=None)
  return dict(status='EXACT_OS_PATH_BYTES',exact=True,bytes=len(raw),base64=base64.b64encode(raw).decode('ascii'))
 filename=path(getattr(error,'filename',None));filename2=path(getattr(error,'filename2',None))
 args=getattr(error,'args',());small=type(args)is tuple and len(args)<=16 and all(type(x)in(str,bytes,int,float,type(None))and(not isinstance(x,(str,bytes))or len(x)<=8192)for x in args)
 message=None;message_status='NOT_RENDERED_UNBOUNDED_OR_COMPLEX_ARGS';message_truncated=False
 if small and all(p['status']!='OVERSIZE_PATH_NOT_EXPORTED'for p in(filename,filename2)):
  try:
   text=str(error);message=text[:1024];message_truncated=len(text)>1024;message_status='TRUNCATED'if message_truncated else'COMPLETE'
  except Exception:message_status='RENDER_FAILED'
 wrapper={k:proof.get(k)for k in('source','ref','run','attempt','case')}if type(proof)is dict else{}
 bound=type(wrapper.get('source'))is str and re.fullmatch('[0-9a-f]{40}',wrapper['source'])is not None and type(wrapper.get('ref'))is str and len(wrapper['ref'])<=256 and type(wrapper.get('run'))is int and 0<wrapper['run']<2**63 and type(wrapper.get('attempt'))is int and wrapper['attempt']==1 and wrapper.get('case')in('normal','precommit-exit86','postcommit-exit87')
 if not bound:wrapper={}
 frames=[];tb=error.__traceback__;walked=0
 while tb is not None and walked<64:
  code=tb.tb_frame.f_code;frames.append(dict(file=path(code.co_filename),function=code.co_name[:128],line=tb.tb_lineno));frames=frames[-8:];tb=tb.tb_next;walked+=1
 number=getattr(error,'errno',None);number=number if type(number)is int and -(2**31)<=number<2**31 else None
 value=dict(status='CLEANUP_FAILURE_DIAGNOSTIC_NOT_CLEANUP_AUTHORITY',operation_boundary='ORIGINAL_PARENT4K_CLEANUP_REFUSED',wrapper=wrapper,proof_binding_complete=bool(bound),error_type=type(error).__name__[:128],error_module=type(error).__module__[:128],message=message,message_status=message_status,message_truncated=message_truncated,errno=number,filename=filename,filename2=filename2,traceback=frames,traceback_frames_walked=walked,traceback_tail_omitted=tb is not None,traceback_head_omitted=max(0,walked-len(frames)),cleanup_authority='NOT_GRANTED',Root_acceptance=None)
 if len(json.dumps(value,sort_keys=True,ensure_ascii=True,allow_nan=False).encode())>64*1024:
  return dict(status='CLEANUP_FAILURE_DIAGNOSTIC_UNAVAILABLE_OVER_BOUND',error_type=type(error).__name__[:128],cleanup_authority='NOT_GRANTED',Root_acceptance=None)
 return value

held=Path(os.environ['LATEST607_HELD_SOURCE']);module,proxy=entry.parent(held)
raw=entry.Q.read(entry.C.ROOT/'parent4k/cleanup.py')
text,_=entry.selected.derive(raw,[("result.update(error_type=type(e).__name__,reason='ORIGINAL_RETIREMENT_GUARD_REFUSED_NO_CLEANUP_AUTHORITY')","result.update(error_type=type(e).__name__,reason='ORIGINAL_RETIREMENT_GUARD_REFUSED_NO_CLEANUP_AUTHORITY',failure_diagnostic=cleanup_failure_diagnostic(e,proof))"),("'cachy-asahi-updater604-recovery4k-'","'cachy-asahi-updater607-normal-lifecycle-'"),("result['source']==C.HELD","result['source']==proof['source'] and result['held_library_source']==C.HELD")])
scope=types.ModuleType('__main__');scope.cleanup_failure_diagnostic=cleanup_failure_diagnostic;scope.__file__=str(entry.C.ROOT/'parent4k/cleanup.py');prior=sys.modules.get('case');sys.modules['case']=proxy
try:exec(compile(text,scope.__file__,'exec'),vars(scope))
finally:
 if prior is None:sys.modules.pop('case',None)
 else:sys.modules['case']=prior
