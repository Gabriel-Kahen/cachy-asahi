#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite measurement CI fixture and explicitly scoped source/private tests."""
import argparse,ast,contextlib,hashlib,importlib.util,json,os,shlex,shutil,stat,subprocess,sys,unittest
from pathlib import Path
PROFILE='manifests/measurement-tools-source-20261028.json'
PROFILE_SHA='24692e6754b466c9172343c80883733fe14b240b18d15b87b109aed397c14ec0'
RECIPE='packages/tools/cachy-asahi-measurement-tools'
def need(ok,why):
 if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def fixture(root,work):
 body=(root/PROFILE).read_bytes();need(sha(body)==PROFILE_SHA,'exact measurement profile');profile=json.loads(body);rows=profile['files'];need(len(rows)==24,'exact finite24 source rows');out=work/'source';out.mkdir();names=set()
 for row in [*rows,dict(path=PROFILE,bytes=len(body),sha256=PROFILE_SHA,mode='0644')]:
  name=row['path'];p=Path(name);need(name not in names and not p.is_absolute()and all(x not in('','..','.')for x in p.parts),'finite unique relative source path');names.add(name);source=root/p;st=source.lstat();need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and not source.is_symlink(),'ordinary fixture input');raw=source.read_bytes();need(len(raw)==row['bytes']and sha(raw)==row['sha256']and stat.S_IMODE(st.st_mode)==int(row['mode'],8),'whole fixture byte/mode pin');target=out/p;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(int(row['mode'],8))
 return out
def static(root):
 adapter=load('measurement_adapter',root/'scripts/checks/check_measurement_tools_v1.py');original=root/'scripts/checks/measurement_tools_package_checks_original_v1.py';need(sha(original.read_bytes())==adapter.ORIGINAL_SHA256,'adapter original checker pin');checks=load('measurement_original_checks',original);report=checks.recipe(root/RECIPE/'PKGBUILD');need(not report['errors'],str(report['errors']));need(report['metadata']['depends']==['python>=3.12'],'supported package Python minimum');print(json.dumps(dict(status='PASS_RETAINED_STATIC_ADAPTER_RECIPE_API',fresh_scope='recipe API only; no makepkg, archive inspection or workloads',makepkg_printsrcinfo='NOT_RUN_HERE_RETAINED_HOST_RECEIPT_ONLY',archive_static='NOT_RUN_HERE_RETAINED_HOST_RECEIPT_ONLY',native='NOT_RUN'),sort_keys=True))
@contextlib.contextmanager
def discovered_source_fixture(tests,root,work):
 """Bind every discovered measurement source control; never filter or skip one."""
 def cases(tests):
  for test in tests:
   if isinstance(test,unittest.TestSuite):yield from cases(test)
   else:yield test
 target=(root/'scripts/release/test_measurement_tools_source_delivery_v1.py').resolve();selected=[];modules=set()
 for test in cases(tests):
  module=sys.modules.get(type(test).__module__)
  if module is not None and getattr(module,'__file__',None)and Path(module.__file__).resolve()==target:
   selected.append(test);modules.add(module)
 if not selected:
  yield
  return
 need(len(selected)==4 and len(modules)==1,'all four discovered measurement source controls required');module=next(iter(modules));previous=module.ROOT;need(previous is None,'discovered source fixture was already configured');module.ROOT=fixture(root,work)
 try:yield
 finally:module.ROOT=previous
# CI-only runner diagnostics V1. No result/retirement authority.
import collections,resource,select,signal,threading,time
PROGRESS_DIR=Path('/run/measurement-progress-v1')
PROGRESS_FIFO=PROGRESS_DIR/'events'
PROGRESS_LINE=1024
PROGRESS_OUTPUT=65536
PROGRESS_INPUT=262144
PROGRESS_KINDS={'runner-start','runner-finish','class-start','class-finish','test-start','test-finish','step-start','step-finish','child-start','child-finish','heartbeat','relay-heartbeat','relay-limit'}
PROGRESS_STEPS={'idle','module-load','discovery','test-runner','result-guard','package-driver','class-setup','class-teardown','sandbox-preflight','package-inner','recipe-stage','cli-state','cli-prepare-plan','cli-run','cli-compare','cli-capture','cli-summarize','cli-version','cli-help','other'}
PROGRESS_STATUS={'active','returned','raised','timeout','success','failure','error','skip','unknown','wait-returned','limit'}
PROGRESS_TESTS=('test_01_original_source_and_exact_payload','test_02_relocated_isolated_cli','test_03_complete_host_journeys','test_04_missing_duplicate_and_mixed_plan_trials','test_05_state_and_source_drift_refused','test_06_raw_and_capture_tamper_refused','test_07_mismatched_baseline_invalid_budgets_and_flag','test_08_freshness_move_and_private_removal')
_progress=None

def progress_integer(value,low=0,high=2**63-1):
 return type(value)is int and low<=value<=high

def progress_wire(value):
 """Closed DATA only: no argv, environment, paths, exception text or counters-as-zero."""
 need(type(value)is dict and set(value)<={'v','role','kind','seq','test','step','status','ms','code','child','cpu_us','maxrss_kib','main_alive','children','dropped','age_ms'},'progress fields')
 need(value.get('v')==1 and type(value.get('v'))is int and value.get('role')in('outer','inner','relay')and value.get('kind')in PROGRESS_KINDS,'progress identity')
 for key in ('seq','ms','cpu_us','maxrss_kib','dropped','age_ms'):
  if key in value:need(value[key]is None or progress_integer(value[key]),'progress integer')
 if 'test'in value:need(progress_integer(value['test'],0,8),'progress test')
 if 'step'in value:need(value['step']in PROGRESS_STEPS,'progress step')
 if 'status'in value:need(value['status']in PROGRESS_STATUS,'progress status')
 if 'code'in value:need(value['code']is None or progress_integer(value['code'],-2**31,2**31-1),'progress code')
 if 'main_alive'in value:need(value['main_alive']is None or type(value['main_alive'])is bool,'progress main liveness')
 if 'child'in value:need(progress_integer(value['child'],1,1000000),'progress child ordinal')
 if 'children'in value:
  need(type(value['children'])is list and len(value['children'])<=4,'progress child count')
  for child in value['children']:
   need(type(child)is dict and set(child)=={'id','pid','handle','state','rss_pages','user_ticks','system_ticks','start_ticks'},'progress child fields')
   need(progress_integer(child['id'],1,1000000)and progress_integer(child['pid'],1,2**31-1),'progress child identity')
   need(child['handle']in('fd-bound','procfd-bound','exit-ready','unknown')and child['state']in('R','S','D','Z','T','t','X','x','K','W','P','I','?'),'progress child state')
   for key in ('rss_pages','user_ticks','system_ticks','start_ticks'):need(child[key]is None or progress_integer(child[key]),'progress child resource')
 raw=json.dumps(value,separators=(',',':'),sort_keys=True,ensure_ascii=True,allow_nan=False).encode()+b'\n'
 need(len(raw)<=PROGRESS_LINE,'progress line cap');return raw

def progress_decode(raw):
 need(type(raw)is bytes and 0<len(raw)<=PROGRESS_LINE and raw.endswith(b'\n'),'progress frame')
 def pairs(rows):
  out={}
  for key,value in rows:need(key not in out,'duplicate progress field');out[key]=value
  return out
 value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite progress value'));progress_wire(value);return value

def progress_stat(raw,pid):
 """Parse only an already-held proc directory's stat; never enumerate PIDs."""
 need(type(raw)is bytes and 0<len(raw)<=4096,'bounded child stat');end=raw.rfind(b')');start=raw.find(b'(')
 need(0<start<end and int(raw[:start].strip())==pid,'same child PID data');fields=raw[end+1:].split();need(len(fields)>=22,'complete child stat')
 def number(index):
  text=fields[index];need(text.isdigit()and len(text)<=19,'bounded child counter');value=int(text);need(progress_integer(value),'child counter');return value
 state=fields[0].decode('ascii');need(state in('R','S','D','Z','T','t','X','x','K','W','P','I'),'child state')
 return dict(parent=number(1),state=state,user_ticks=number(11),system_ticks=number(12),start_ticks=number(19),rss_pages=number(21))

class ProgressChild:
 """Diagnostic FD capabilities only. No signals, waits, group census or PID retries."""
 def __init__(self,ordinal,pid):
  self.ordinal=ordinal;self.pid=pid;self.pidfd=None;self.procfd=None;self.start=None;self.handle='unknown'
 def close(self,handle='unknown'):
  for name in('pidfd','procfd'):
   fd=getattr(self,name);setattr(self,name,None)
   if fd is not None:
    try:os.close(fd)
    except OSError:pass
  self.handle=handle
 def read(self):
  fd=os.open('stat',os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.procfd)
  try:
   raw=os.read(fd,4097);need(len(raw)<=4096,'child stat byte cap');return progress_stat(raw,self.pid)
  finally:os.close(fd)
 @classmethod
 def capture(cls,ordinal,child):
  cap=cls(ordinal,child.pid)
  # Called synchronously immediately after successful Popen construction, before
  # handing the object to its caller. With default SIGCHLD the fresh child is
  # unreaped here. Unsupported/ambiguous observation simply stays UNKNOWN.
  try:
   need(progress_integer(child.pid,1,2**31-1)and child.returncode is None and signal.getsignal(signal.SIGCHLD)==signal.SIG_DFL,'fresh ordinary Popen child')
   cap.procfd=os.open('/proc/'+str(child.pid),os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
   pidfd_open=getattr(os,'pidfd_open',None)
   if callable(pidfd_open):cap.pidfd=pidfd_open(child.pid,0)
   need(cap.procfd>=3 and(cap.pidfd is None or cap.pidfd>=3),'diagnostic handles never replace standard descriptors')
   data=cap.read();need(data['parent']==os.getpid(),'direct child data');cap.start=data['start_ticks'];cap.handle='fd-bound'if cap.pidfd is not None else'procfd-bound'
  except Exception:cap.close()
  return cap
 def snapshot(self):
  data=dict(id=self.ordinal,pid=self.pid,handle=self.handle,state='?',rss_pages=None,user_ticks=None,system_ticks=None,start_ticks=None)
  if self.handle not in('fd-bound','procfd-bound'):return data
  try:
   if self.pidfd is not None:
    poll=select.poll();poll.register(self.pidfd,select.POLLIN|select.POLLHUP|select.POLLERR)
    if poll.poll(0):self.close('exit-ready');data['handle']='exit-ready';return data
   stat_data=self.read();need(stat_data['start_ticks']==self.start,'same retained child identity')
   data.update({key:stat_data[key]for key in('state','rss_pages','user_ticks','system_ticks','start_ticks')})
  except Exception:self.close();data['handle']='unknown'
  return data

def progress_channel():
 """Guest-only root-created write channel; no arbitrary caller path or FD authority."""
 if os.environ.get('MEASUREMENT_RUNNER_DIAGNOSTICS')!='1':return False
 try:
  parent=PROGRESS_DIR.lstat();fifo=PROGRESS_FIFO.lstat()
  valid=(stat.S_ISDIR(parent.st_mode)and stat.S_IMODE(parent.st_mode)==0o755 and
         stat.S_ISFIFO(fifo.st_mode)and fifo.st_gid==os.getgid()and fifo.st_nlink==1 and stat.S_IMODE(fifo.st_mode)==0o620)
  if not valid:return False
  identity=(parent.st_dev,parent.st_ino,fifo.st_dev,fifo.st_ino,fifo.st_gid)
  if not all(progress_integer(x)for x in identity):return False
  pin=':'.join(map(str,identity));inherited=os.environ.get('MEASUREMENT_PROGRESS_PIN_V1')
  if parent.st_uid==fifo.st_uid==0:return pin if inherited in(None,pin)else False
  # Root's UID may be unmapped inside bwrap. The outer context verified root
  # ownership and binds this same fixed, protected inode through inherited DATA.
  return pin if parent.st_uid==fifo.st_uid and inherited==pin else False
 except OSError:return False

class RunnerProgress:
 def __init__(self,role):
  self.role=role;self.started=time.monotonic();self.seq=0;self.step='idle';self.test=0;self.child_seq=0;self.children={};self.queue=collections.deque();self.queued=0;self.dropped=0;self.fd=None;self.lock=threading.RLock();self.stop=threading.Event();self.thread=None
 def flush(self):
  try:
   if self.fd is None:self.fd=os.open(PROGRESS_FIFO,os.O_WRONLY|os.O_NONBLOCK|os.O_CLOEXEC|os.O_NOFOLLOW)
   while self.queue:
    raw=self.queue[0];need(os.write(self.fd,raw)==len(raw),'atomic progress write');self.queue.popleft();self.queued-=len(raw)
  except BlockingIOError:pass
  except Exception:
   if self.fd is not None:
    try:os.close(self.fd)
    except OSError:pass
    self.fd=None
 def emit(self,kind,status='active',**fields):
  try:
   with self.lock:
    self.seq+=1;value=dict(v=1,role=self.role,kind=kind,seq=self.seq,test=self.test,step=self.step,status=status,ms=max(0,int((time.monotonic()-self.started)*1000)),dropped=self.dropped);value.update(fields);raw=progress_wire(value)
    if self.queue:self.flush()
    if self.queued+len(raw)>8192:self.dropped+=1;return
    self.queue.append(raw);self.queued+=len(raw);self.flush()
  except Exception:pass
 def attach(self,child):
  try:
   with self.lock:
    if len(self.children)>=4:return
    self.child_seq+=1;cap=ProgressChild.capture(self.child_seq,child);self.children[id(child)]=cap;self.emit('child-start',child=cap.ordinal)
  except Exception:pass
 def detach(self,child):
  try:
   with self.lock:
    cap=self.children.pop(id(child),None)
    if cap is not None:cap.close();self.emit('child-finish','wait-returned',child=cap.ordinal)
  except Exception:pass
 def sample(self):
  try:
   with self.lock:
    cpu=rss=alive=None
    try:cpu=int(time.process_time()*1000000);need(progress_integer(cpu),'self CPU data')
    except Exception:cpu=None
    try:rss=int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss);need(progress_integer(rss),'self RSS data')
    except Exception:rss=None
    try:alive=threading.main_thread().is_alive()
    except Exception:pass
    self.emit('heartbeat',cpu_us=cpu,maxrss_kib=rss,main_alive=alive,children=[cap.snapshot()for cap in self.children.values()])
  except Exception:pass
 def loop(self):
  while not self.stop.wait(2):self.sample()
 def finish(self):
  self.stop.set()
  with self.lock:
   for cap in self.children.values():cap.close()
   self.children.clear();self.flush()
   if self.fd is not None:
    try:os.close(self.fd)
    except OSError:pass
    self.fd=None

def progress_step(command):
 try:
  if type(command)not in(list,tuple)or not all(type(x)is str for x in command):return'other'
  if 'package-inner'in command:return'package-inner'
  if 'package-stage'in command:return'recipe-stage'
  if command and command[-1]=='/usr/bin/true':return'sandbox-preflight'
  index=next((i for i,x in enumerate(command)if x.endswith('/bin/cachy-asahi-measurement-tools')),None)
  if index is None:return'other'
  args=command[index+1:]
  if '--version'in args:return'cli-version'
  if '--help'in args:return'cli-help'
  for prefix,label in((['state'],'cli-state'),(['benchmark','prepare-plan'],'cli-prepare-plan'),(['benchmark','run'],'cli-run'),(['benchmark','compare'],'cli-compare'),(['metrics','capture'],'cli-capture'),(['metrics','summarize'],'cli-summarize')):
   if args[:len(prefix)]==prefix:return label
 except Exception:pass
 return'other'

@contextlib.contextmanager
def runner_progress(role):
 global _progress
 channel=progress_channel()
 if not channel or _progress is not None:yield _progress;return
 reporter=None;original_popen=subprocess.Popen;original_run=subprocess.run;previous=_progress;previous_pin=os.environ.get('MEASUREMENT_PROGRESS_PIN_V1')
 try:
  os.environ['MEASUREMENT_PROGRESS_PIN_V1']=channel
  reporter=RunnerProgress(role)
  class ObservedPopen(original_popen):
   def __init__(child,*args,**kwargs):super().__init__(*args,**kwargs);reporter.attach(child)
   def wait(child,*args,**kwargs):
    value=super().wait(*args,**kwargs);reporter.detach(child);return value
   def poll(child,*args,**kwargs):
    value=super().poll(*args,**kwargs)
    if value is not None:reporter.detach(child)
    return value
  def observed_run(*args,**kwargs):
   with reporter.lock:before=reporter.step;reporter.step=progress_step(args[0]if args else kwargs.get('args'));reporter.emit('step-start')
   status='raised';code=None
   try:
    value=original_run(*args,**kwargs);status='returned';code=value.returncode;return value
   except subprocess.TimeoutExpired:status='timeout';raise
   finally:
    with reporter.lock:reporter.emit('step-finish',status,code=code);reporter.step=before
  _progress=reporter;subprocess.Popen=ObservedPopen;subprocess.run=observed_run;reporter.thread=threading.Thread(target=reporter.loop,daemon=True,name='measurement-progress-v1');reporter.thread.start();reporter.emit('runner-start')
 except BaseException as error:
  subprocess.Popen=original_popen;subprocess.run=original_run;_progress=previous
  if previous_pin is None:os.environ.pop('MEASUREMENT_PROGRESS_PIN_V1',None)
  else:os.environ['MEASUREMENT_PROGRESS_PIN_V1']=previous_pin
  if reporter is not None:
   try:reporter.finish()
   except Exception:pass
  reporter=None
  if not isinstance(error,Exception):raise
 outcome='raised'
 try:yield reporter;outcome='returned'
 finally:
  subprocess.Popen=original_popen;subprocess.run=original_run;_progress=previous
  if previous_pin is None:os.environ.pop('MEASUREMENT_PROGRESS_PIN_V1',None)
  else:os.environ['MEASUREMENT_PROGRESS_PIN_V1']=previous_pin
  if reporter is not None:
   try:reporter.emit('runner-finish',outcome);reporter.finish()
   except Exception:pass

@contextlib.contextmanager
def runner_stage(reporter,step):
 if reporter is None:yield;return
 with reporter.lock:before=reporter.step;reporter.step=step;reporter.emit('step-start')
 status='raised'
 try:yield;status='returned'
 finally:
  with reporter.lock:reporter.emit('step-finish',status);reporter.step=before

@contextlib.contextmanager
def runner_classes(module,reporter):
 saved=[]
 if reporter is not None:
  for name,step in(('setUpClass','class-setup'),('tearDownClass','class-teardown')):
   cls=getattr(module,'Package',None);original=cls.__dict__.get(name)if cls is not None else None
   if not isinstance(original,classmethod):continue
   def wrap(cls,original=original,step=step):
    with reporter.lock:before=reporter.step;reporter.step=step;reporter.emit('class-start')
    status='raised'
    try:value=original.__get__(None,cls)();status='returned';return value
    finally:
     with reporter.lock:reporter.emit('class-finish',status);reporter.step=before
   setattr(cls,name,classmethod(wrap));saved.append((cls,name,original))
 try:yield
 finally:
  for cls,name,original in saved:setattr(cls,name,original)

def runner_result(reporter):
 class Result(unittest.TextTestResult):
  def startTest(self,test):
   with reporter.lock:reporter.test=PROGRESS_TESTS.index(test._testMethodName)+1 if test._testMethodName in PROGRESS_TESTS else 0;self.progress_outcome='unknown';reporter.emit('test-start')
   super().startTest(test)
  def stopTest(self,test):
   super().stopTest(test)
   with reporter.lock:reporter.emit('test-finish',self.progress_outcome);reporter.test=0
  def addSuccess(self,test):super().addSuccess(test);self.progress_outcome='success'
  def addFailure(self,test,error):super().addFailure(test,error);self.progress_outcome='failure'
  def addError(self,test,error):super().addError(test,error);self.progress_outcome='error'
  def addSkip(self,test,reason):super().addSkip(test,reason);self.progress_outcome='skip'
 return Result

class ProgressRelay:
 def __init__(self,write):self.write=write;self.buffer=b'';self.discard=False;self.input=0;self.output=0;self.exhausted=False;self.valid=0
 def output_event(self,event):
  try:
   raw=b'\nMEASUREMENT_RUNNER_V1='+progress_wire(event)
   if self.exhausted:return
   if self.output+len(raw)>PROGRESS_OUTPUT-128:
    raw=b'\nMEASUREMENT_RUNNER_V1={"v":1,"role":"relay","kind":"relay-limit"}\n';self.exhausted=True
   if self.output+len(raw)<=PROGRESS_OUTPUT:self.output+=len(raw);self.write(raw)
  except Exception:pass
 def feed(self,raw):
  if type(raw)is not bytes or self.input+len(raw)>PROGRESS_INPUT:return False
  self.input+=len(raw)
  parts=raw.split(b'\n')
  for index,part in enumerate(parts):
   complete=index<len(parts)-1
   if self.discard:
    if complete:self.discard=False
    continue
   self.buffer+=part
   if len(self.buffer)+(1 if complete else 0)>PROGRESS_LINE:self.buffer=b'';self.discard=not complete;continue
   if complete:
    line=self.buffer+b'\n';self.buffer=b''
    try:
     event=progress_decode(line);need(event['role']in('outer','inner'),'runner producer role');self.valid+=1;self.output_event(event)
    except Exception:pass
  return True

def progress_serial(raw):
 fd=None
 try:
  fd=os.open('/dev/ttyS0',os.O_WRONLY|os.O_NONBLOCK|os.O_NOCTTY|os.O_CLOEXEC|os.O_NOFOLLOW);os.write(fd,raw)
 finally:
  if fd is not None:os.close(fd)

def progress_relay():
 """Guest root relay. Entire process remains inside the already-owned VM."""
 if os.geteuid()!=0:return
 fd=None
 try:
  st=PROGRESS_FIFO.lstat();need(stat.S_ISFIFO(st.st_mode)and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o620,'root-created diagnostic FIFO')
  fd=os.open(PROGRESS_FIFO,os.O_RDWR|os.O_NONBLOCK|os.O_CLOEXEC|os.O_NOFOLLOW);poll=select.poll();poll.register(fd,select.POLLIN);relay=ProgressRelay(progress_serial);start=time.monotonic();last=start;next_beat=start+2
  while time.monotonic()-start<180:
   if poll.poll(500):
    raw=os.read(fd,4096)
    if raw:
     before_valid=relay.valid
     if not relay.feed(raw):break
     if relay.valid!=before_valid:last=time.monotonic()
   elif(PROGRESS_DIR/'done').exists():break
   now=time.monotonic()
   if now>=next_beat:relay.output_event(dict(v=1,role='relay',kind='relay-heartbeat',age_ms=max(0,int((now-last)*1000))));next_beat=now+2
 except Exception:pass
 finally:
  if fd is not None:os.close(fd)

def suite(root,kind,work,progress=None):
 relative='scripts/release/test_measurement_tools_source_delivery_v1.py'if kind=='source'else RECIPE+'/test_package.py'
 with runner_stage(progress,'module-load'):module=load('measurement_'+kind,root/relative)
 if kind=='source':module.ROOT=root;expected=4
 else:module.RECIPE=root/RECIPE;module.EVIDENCE=work/'package-evidence';expected=8
 with runner_stage(progress,'discovery'):
  tests=unittest.defaultTestLoader.loadTestsFromModule(module);need(tests.countTestCases()==expected,'exact focused count')
 with runner_stage(progress,'test-runner'),runner_classes(module,progress):
  result=unittest.TextTestRunner(verbosity=2,failfast=True,**({'resultclass':runner_result(progress)}if progress is not None else{})).run(tests)
 with runner_stage(progress,'result-guard'):
  need(result.wasSuccessful()and not result.skipped and result.testsRun==expected,'focused tests failed/skipped/incomplete')
def package(root,work):
 need(shutil.which('bwrap')is not None,'BLOCKED_REQUIRED_SANDBOX: bwrap unavailable; no fallback');system_python=Path('/usr/bin/python3').resolve(strict=True);need(system_python.is_file(),'BLOCKED_SYSTEM_INTERPRETER: existing regular target required');selected=Path(sys.executable).resolve();need(selected!=system_python,'BLOCKED_SELECTED_INTERPRETER: setup-python isolated prefix required for private launcher bridge');bridge=work/'python-driver';bridge.write_text('#!/bin/sh\nexec '+shlex.quote(str(selected))+' "$@"\n');bridge.chmod(0o755)
 # The fixed installed shebang and workload path select this interpreter only
 # inside a private mount namespace. No host symlink or security policy changes.
 box=['bwrap','--die-with-parent','--ro-bind','/','/','--bind',str(work),str(work),'--ro-bind',str(bridge),str(system_python),'--dev','/dev','--tmpfs','/sys','--unshare-net','--unshare-pid','--proc','/proc','--']
 check=subprocess.run([*box,'/usr/bin/true'],capture_output=True,timeout=20)
 if check.returncode:
  sys.stderr.buffer.write(check.stderr[:8192]);raise ValueError('BLOCKED_REQUIRED_SANDBOX: private PID/proc/dev/empty-sys/network prerequisite refused; eight controls NOT_RUN; no sudo/unconfined/skip fallback')
 command=[*box,str(selected),'-I','-B','-Werror::ResourceWarning',str(Path(__file__).resolve()),'package-inner','--root',str(root),'--work',str(work)];result=subprocess.run(command,timeout=180);need(result.returncode==0,'eight private package controls failed; no fallback')
# CI-only supported disposable guest. Original package()/Source25 stay unchanged.
GUEST_IMAGE_URL='https://chuangtzu.ftp.acc.umu.se/images/cloud/trixie/20261026-2643/debian-13-generic-amd64-20261026-2643.qcow2'
GUEST_IMAGE_BYTES=438894592
GUEST_IMAGE_SHA512='5bd891c6e62d01639f52a5587b72a4607421e445732214be787dba6043cf9797a6ff90bed982aada6a6c7e619f1f956d961c4fad76757171abd607920aac098a'
def guest_config(helper_sha,python_mm):
 need(len(helper_sha)==64 and all(c in '0123456789abcdef' for c in helper_sha),'helper digest')
 need(python_mm in ('3.12','3.14'),'guest Python matrix')
 # No host mount, SSH/key, host capability, policy or sysctl adjustment. The
 # root bootstrap installs dependencies in this disposable guest only.
 script='''set -eu
package_started=0
bootstrap_log=/run/measurement-bootstrap.log
bootstrap_stage=prepare
stage() {
 bootstrap_stage=$1
 printf '\\nMEASUREMENT_BOOTSTRAP_STAGE_START=%s elapsed=%d\\n' "$bootstrap_stage" "$SECONDS" > /dev/ttyS0 || :
}
finish() {
 rc=$?
 trap - EXIT
 : > /run/measurement-progress-v1/done 2>/dev/null || :
 if ! tail -c 524289 -- "$bootstrap_log" > /dev/ttyS0; then
  printf '\\nMEASUREMENT_BOOTSTRAP_LOG_EXPORT=FAILED\\n' > /dev/ttyS0 || :
 fi
 printf '\\nMEASUREMENT_BOOTSTRAP_STAGE=%s exit=%d\\n' "$bootstrap_stage" "$rc" > /dev/ttyS0
 printf '\\nMEASUREMENT_GUEST_RESULT={"exit":%d,"package_started":%d,"helper_sha256":"HELPER_SHA","python":"PYTHON_MM","profile_sha256":"PROFILE_PIN"}\\n' "$rc" "$package_started" > /dev/ttyS0
 /sbin/poweroff
 exit "$rc"
}
trap finish EXIT
bootstrap_umask=$(umask)
umask 077
exec > "$bootstrap_log" 2>&1
umask "$bootstrap_umask"
export DEBIAN_FRONTEND=noninteractive
stage apt-update
apt-get update -qq
stage apt-install
apt-get install --yes --quiet --no-install-recommends bubblewrap python3 libssl3t64 libexpat1 libzstd1 libffi8 liblzma5 libbz2-1.0 libsqlite3-0 libreadline8t64 libncursesw6 libuuid1
stage source-setup
install -d /mnt/measureci /opt/measurement
mount -o ro /dev/disk/by-label/MEASURECI /mnt/measureci
cd /mnt/measureci
sha256sum -c SHA256SUMS
python3 -I -B -c 'import tarfile; t=tarfile.open("python.tar"); t.extractall("/opt/measurement", filter="data"); t.close()'
cp helper.py /opt/measurement/helper.py
cp -a source /opt/measurement/source
printf '%s  %s\\n' HELPER_SHA /opt/measurement/helper.py | sha256sum -c -
if install -d -m755 /run/measurement-progress-v1 && mkfifo -m620 /run/measurement-progress-v1/events && chown root:measurement /run/measurement-progress-v1/events; then
 python3 -I -B /opt/measurement/helper.py progress-relay --root /opt/measurement/source --work /run/measurement-progress-v1 &
fi
stage python-probe
env LD_LIBRARY_PATH=/opt/measurement/python/lib /opt/measurement/python/bin/python3 -I -B -c 'import sys,ssl,hashlib,zlib,bz2,lzma,ctypes,sqlite3; assert sys.version_info[:2] == tuple(map(int,"PYTHON_MM".split(".")))'
stage package8
package_started=1
runuser -u measurement -- env MEASUREMENT_RUNNER_DIAGNOSTICS=1 PATH=/opt/measurement/python/bin:/usr/local/bin:/usr/bin:/bin LD_LIBRARY_PATH=/opt/measurement/python/lib /opt/measurement/python/bin/python3 -I -B -Werror::ResourceWarning /opt/measurement/helper.py package --root /opt/measurement/source --work /home/measurement/package-ci
'''.replace('HELPER_SHA',helper_sha).replace('PYTHON_MM',python_mm).replace('PROFILE_PIN',PROFILE_SHA)
 return {'users':[{'name':'measurement','lock_passwd':True,'shell':'/bin/bash'}],
         'ssh_pwauth':False,'disable_root':True,'package_update':False,
         'runcmd':[['/bin/bash','-ec',script]]}
def guest_verdict(raw,helper_sha,python_mm):
 records=[]
 for line in raw.decode('utf-8','replace').splitlines():
  if line.startswith('MEASUREMENT_GUEST_RESULT='):
   records.append(json.loads(line.split('=',1)[1]))
 need(len(records)==1,'exact one guest terminal receipt required')
 expected=dict(exit=0,package_started=1,helper_sha256=helper_sha,python=python_mm,profile_sha256=PROFILE_SHA)
 need(records[0]==expected and type(records[0].get('exit'))is int and type(records[0].get('package_started'))is int,'guest bootstrap/package result differs; no incomplete promotion')
 need(b'Ran 8 tests in 'in raw and b'\nOK'in raw.replace(b'\r\n',b'\n'),'original eight-control runner completion required')
 return records[0]
def guest_diagnostics(raw):
 import re
 lines=[]
 for line in raw.decode('utf-8','replace').splitlines():
  if re.search(r'authorization|cookie|password|secret|(?:gh|github)_token|api[_-]?key|access[_-]?token|token\s*[:=]|private.key',line,re.I):
   lines.append('[sensitive field omitted]');continue
  lines.append(re.sub(r'https?://[^\s]+','[URL omitted]',line))
 # Anchor the bounded diagnostic window at the terminal receipt; later
 # shutdown chatter must not discard the bootstrap failure or receipt.
 terminal=[i for i,line in enumerate(lines)if line.startswith('MEASUREMENT_GUEST_RESULT=')]
 if terminal:lines=lines[:terminal[-1]+1]
 return '\n'.join(lines)[-16384:]
GUEST_OWNER_SHA256='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
_guest_unresolved=None
def guest_supervisor(owner,cancel):
 """CI-only v1 copy: exactly two cooperative checks in protected source points."""
 import copy
 raw=Path(owner.__file__).read_bytes();need(sha(raw)==GUEST_OWNER_SHA256,'exact cancellation-owner source pin')
 tree=ast.parse(raw);source=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='supervise');derived=copy.deepcopy(source)
 protected=[n for n in derived.body if isinstance(n,ast.Try)];need(len(protected)==1,'one reviewed protected owner try')
 protected=protected[0];loops=[n for n in protected.body if isinstance(n,ast.While)];need(len(loops)==1,'one reviewed active owner loop')
 check=ast.parse("if _measurement_guest_cancel_v1[0]: raise KeyboardInterrupt('guest cancellation signal '+str(_measurement_guest_cancel_v1[0]))").body[0]
 protected.body.insert(0,copy.deepcopy(check));loops[0].body.insert(0,copy.deepcopy(check))
 verify=copy.deepcopy(derived);t=next(n for n in verify.body if isinstance(n,ast.Try));w=next(n for n in t.body if isinstance(n,ast.While));need(ast.dump(t.body.pop(0))==ast.dump(check)and ast.dump(w.body.pop(0))==ast.dump(check),'exact two cancellation checks')
 need(ast.dump(verify,include_attributes=False)==ast.dump(source,include_attributes=False),'all original owner operations held')
 namespace=dict(owner.__dict__);need('_measurement_guest_cancel_v1'not in namespace,'fresh CI cancellation binding');namespace['_measurement_guest_cancel_v1']=cancel
 module=ast.fix_missing_locations(ast.Module(body=[derived],type_ignores=[]));exec(compile(module,str(owner.__file__)+'::guest-term-v1','exec'),namespace)
 return namespace['supervise']
def guest_failure(error,ownership='NOT_STARTED'):
 return dict(passed=False,exit=None,reaped=False,ownership=ownership,timeout=False,signals=[],output=b'',output_complete=False,group_census='UNKNOWN'if ownership=='UNKNOWN'else'NOT_OBSERVED',error=type(error).__name__+': '+str(error)[:300],seconds=None)
@contextlib.contextmanager
def guest_custody(owner,argv,work):
 """One owner through retirement/export. SIGTERM/SIGINT handlers never raise."""
 import signal
 global _guest_unresolved
 stops={signal.SIGTERM,signal.SIGINT};previous={};mask=None;child=None;transferred=False;cancel=[0];phase='prepare';result=None
 def stopped(signum,frame):
  if not cancel[0]:cancel[0]=signum
 try:
  need(_guest_unresolved is None,'prior guest wait remains unresolved; no further launch')
  supervise=guest_supervisor(owner,cancel)
  owner.prepare()
  previous={sig:signal.getsignal(sig)for sig in stops}
  mask=signal.pthread_sigmask(signal.SIG_BLOCK,stops)
  need(not(mask&stops),'cancellation signals must be unblocked before guest launch')
  phase='handler-install'
  for sig in stops:signal.signal(sig,stopped)
  phase='handler-unmask'
  signal.pthread_sigmask(signal.SIG_SETMASK,mask)  # Child inherits the original unblocked mask.
  if cancel[0]:raise KeyboardInterrupt('guest cancellation before launch')
  phase='launch'
  child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
  phase='supervise';transferred=True
  result=supervise(child,cap=180,retirement=.5,grace=.1)
 except BaseException as error:
  if child is not None and not transferred:
   # Only this branch still owns a fresh child never given to supervise().
   # A shorter failure retirement cannot renew the normal 180s run budget.
   try:result=owner.supervise(child,cap=.6,retirement=.5,grace=.1)
   except BaseException as cleanup:result=guest_failure(cleanup,'UNKNOWN')
   result['passed']=False;result['wrapper_error']=type(error).__name__+': '+str(error)[:300]
   result['error']=result.get('error')or result['wrapper_error']
  else:result=guest_failure(error,'UNKNOWN'if transferred else'NOT_STARTED')
 finally:
  # No handler restoration, caller logging or export precedes bounded custody.
  if child is not None and not result.get('reaped'):
   child._child_created=False  # Never let Popen's destructor turn ECHILD into zero.
   _guest_unresolved=(child,result)
   for pipe in (child.stdout,child.stderr):
    if pipe is not None:
     try:pipe.close()
     except OSError:pass  # No reads, numeric probes, signals or wait retries.
  try:
   before_export=signal.pthread_sigmask(signal.SIG_BLOCK,stops)
   if mask is None:mask=before_export
   pending=signal.sigpending()&stops
   if not cancel[0]and pending:cancel[0]=min(pending)
  except BaseException as error:
   result['passed']=False;result['signal_block_error']=type(error).__name__+': '+str(error)[:300]
  result.update(cancel_signal=cancel[0]or None,custody_phase=phase,supervisor_variant='CI_GUEST_TERM_V1_TWO_PROTECTED_CHECKS')
  if cancel[0]:
   result['passed']=False;result['error']=result.get('error')or 'guest cancellation signal '+str(cancel[0])
 body_error=None
 try:yield result
 except BaseException as error:body_error=error;raise
 finally:
  # Still blocked through caller serial/supervision/error export. Restore every
  # saved handler even after a partial install; never touch the child here.
  failures=[]
  for sig,handler in previous.items():
   try:signal.signal(sig,handler)
   except BaseException as error:failures.append(type(error).__name__+': '+str(error)[:300])
  if not failures and mask is not None:
   try:signal.pthread_sigmask(signal.SIG_SETMASK,mask)
   except BaseException as error:failures.append(type(error).__name__+': '+str(error)[:300])
  if failures:
   blocked=None
   try:signal.pthread_sigmask(signal.SIG_BLOCK,stops);blocked=True
   except BaseException:pass
   try:
    restoration=dict(status='FAIL',errors=failures,child_reaped=result['reaped'],ownership=result['ownership'],signals_left_blocked=blocked)
    (work/'guest-handler-restore-error.json').write_text(json.dumps(restoration,sort_keys=True)+'\n')
    print(guest_diagnostics(json.dumps(dict(guest_signal_restoration=restoration),sort_keys=True).encode()),flush=True)
   except BaseException:
    if body_error is None:raise
   if body_error is None:raise ValueError('guest signal restoration failed after custody/export')

def guest(root,work):
 import tarfile,urllib.request
 need(os.geteuid()!=0,'ordinary host guest owner required')
 need(all(shutil.which(x)for x in ('qemu-system-x86_64','qemu-img','cloud-localds','genisoimage')),'explicit disposable VM tools required')
 selected=Path(sys.executable).resolve();prefix=Path(sys.base_prefix).resolve();need(selected.is_relative_to(prefix)and selected!=Path('/usr/bin/python3').resolve(),'separate selected Python prefix required')
 need(','not in str(work),'QEMU work path must not contain option separator')
 python_mm='.'.join(map(str,sys.version_info[:2]));need(python_mm in ('3.12','3.14'),'exact guest Python matrix')
 image=work/'debian.qcow2';h=hashlib.sha512();count=0
 with urllib.request.urlopen(GUEST_IMAGE_URL,timeout=20)as response,image.open('xb')as target:
  need(response.url==GUEST_IMAGE_URL,'exact official image origin; no redirect')
  while True:
   chunk=response.read(1024**2)
   if not chunk:break
   count+=len(chunk);need(count<=1024**3,'guest image byte bound');target.write(chunk);h.update(chunk)
 need(count==GUEST_IMAGE_BYTES and h.hexdigest()==GUEST_IMAGE_SHA512,'official dated guest image size/SHA512 differs')
 inputs=work/'guest-inputs';inputs.mkdir();shutil.copytree(root,inputs/'source');helper=(Path(__file__).resolve()).read_bytes();helper_sha=sha(helper);(inputs/'helper.py').write_bytes(helper)
 total=0
 with tarfile.open(inputs/'python.tar','w',format=tarfile.PAX_FORMAT)as archive:
  for path in [prefix,*sorted(prefix.rglob('*'))]:
   st=path.lstat();need(stat.S_ISREG(st.st_mode)or stat.S_ISDIR(st.st_mode)or stat.S_ISLNK(st.st_mode),'ordinary selected Python prefix')
   if path.is_symlink():need(path.resolve(strict=True).is_relative_to(prefix),'Python symlink must remain inside selected prefix')
   total+=st.st_size if stat.S_ISREG(st.st_mode)else 0;need(total<=1024**3,'selected interpreter prefix byte bound')
   archive.add(path,arcname='python'+('/'+str(path.relative_to(prefix))if path!=prefix else''),recursive=False)
 (inputs/'SHA256SUMS').write_text(''.join(sha((inputs/name).read_bytes())+'  '+name+'\n'for name in ('python.tar','helper.py')))
 subprocess.run(['genisoimage','-quiet','-R','-V','MEASURECI','-o',str(work/'inputs.iso'),str(inputs)],check=True,timeout=20)
 (work/'user-data').write_text('#cloud-config\n'+json.dumps(guest_config(helper_sha,python_mm))+'\n')
 (work/'meta-data').write_text(json.dumps({'instance-id':'measurement-'+helper_sha[:12]+'-'+python_mm,'local-hostname':'measurement-ci'})+'\n')
 subprocess.run(['cloud-localds',str(work/'seed.iso'),str(work/'user-data'),str(work/'meta-data')],check=True,timeout=20)
 subprocess.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(image),str(work/'run.qcow2')],check=True,timeout=20)
 subprocess.run(['qemu-img','resize',str(work/'run.qcow2'),'8G'],check=True,timeout=20)
 argv=['qemu-system-x86_64','-accel','tcg,thread=multi','-cpu','max','-smp','2','-m','2048','-display','none','-serial','stdio','-monitor','none','-no-reboot','-drive','file='+str(work/'run.qcow2')+',if=virtio,format=qcow2','-drive','file='+str(work/'seed.iso')+',media=cdrom,readonly=on','-drive','file='+str(work/'inputs.iso')+',media=cdrom,readonly=on','-nic','user,model=virtio-net-pci']
 owner=load('measurement_guest_owner',root/RECIPE/'owned_process.py')
 with guest_custody(owner,argv,work)as result:
  (work/'guest-serial.log').write_bytes(result['output'])
  record={k:v for k,v in result.items()if k!='output'}
  (work/'guest-supervision.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
  print(guest_diagnostics(json.dumps(dict(guest_supervision=record),sort_keys=True).encode()),flush=True)
  print('Bounded guest diagnostic tail; full raw serial retained privately in work directory:')
  print(guest_diagnostics(result['output']),flush=True)
  need(result['passed']and result['exit']==0 and result['reaped']and result['error']is None and result['output_complete']and not result['timeout']and not result['signals']and result['ownership']=='REAPED'and result['group_census']=='EMPTY_TWICE','guest must exit naturally with complete owned supervision; preserve raw failure')
  receipt=guest_verdict(result['output'],helper_sha,python_mm)
 (work/'guest-result.json').write_text(json.dumps(dict(status='PASS_GUEST_PACKAGE8_ONLY',receipt=receipt,image_sha512=GUEST_IMAGE_SHA512,image_bytes=count,scope='x86_64 disposable Debian guest; original private package8 only; no ARM/ALPM/M2/performance acceptance'),sort_keys=True,indent=2)+'\n')
 print(json.dumps(dict(status='PASS_GUEST_PACKAGE8_ONLY',python=python_mm,tests=8,skipped=0,profile_sha256=PROFILE_SHA,native='NOT_RUN',M2='NOT_RUN',performance='NOT_MEASURED'),sort_keys=True))

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=['inspect','source','package','package-inner','guest','progress-relay']);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--work',type=Path,required=True);args=parser.parse_args();need(sys.version_info>=(3,12),'Python>=3.12 required');root=args.root.resolve(strict=True);work=args.work.absolute()
 if args.mode=='progress-relay':progress_relay();return
 if args.mode=='package-inner':
  need(os.geteuid()!=0 and Path('/proc/self').is_dir()and Path('/dev/null').exists()and not any(Path('/sys').iterdir()),'private ordinary-user proc/dev/empty-sys prerequisite');print(json.dumps(dict(driver=sys.version,installed_launcher_python=sys.executable,scope='PRIVATE_FIXTURE_ONLY_NO_HOST_SENSOR_OR_SESSION_CENSUS_NO_NATIVE_OR_PERFORMANCE'),sort_keys=True))
  with runner_progress('inner')as progress:suite(root,'package',work,progress)
  return
 need(not work.exists(),'fresh private work required');work.mkdir(mode=0o700,parents=True);root=fixture(root,work);static(root)
 for rel,count in [('scripts/release/test_measurement_tools_source_delivery_v1.py',4),(RECIPE+'/test_package.py',8)]:
  node=ast.parse((root/rel).read_bytes());need(sum(isinstance(x,ast.FunctionDef)and x.name.startswith('test_')for x in ast.walk(node))==count,'static focused suite count')
 if args.mode=='source':suite(root,'source',work)
 elif args.mode=='package':
  with runner_progress('outer')as progress:
   with runner_stage(progress,'package-driver'):package(root,work)
 elif args.mode=='guest':guest(root,work)
 else:print(json.dumps(dict(status='PASS_FINITE25_FIXTURE_AND_STATIC_WIRING_ONLY',source_controls='RETAINED_NOT_RERUN',package_controls='RETAINED_NOT_RERUN',package_bwrap_actors=0),sort_keys=True))
if __name__=='__main__':main()
