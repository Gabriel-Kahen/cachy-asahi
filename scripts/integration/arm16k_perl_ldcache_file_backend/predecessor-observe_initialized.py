# SPDX-License-Identifier: MIT
"""Exactly seven public recovery commands after maintained actual PIDFD/GO gates."""
import hashlib,importlib.util,json,os,re,resource,signal,stat,subprocess,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
OUT=Path('/output')
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(path):
 st=path.lstat();need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and not path.is_symlink(),'ordinary single-link output/tool')
 with path.open('rb')as f:h=hashlib.file_digest(f,'sha256').hexdigest()
 return dict(bytes=st.st_size,sha256=h)
def put(path,value):
 body=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
 with path.open('xb')as f:f.write(body)
 path.chmod(0o600)
def execute(authority_path,authority_sha):
 R=load('ldcache_recovery',HERE/'recovery.py');O=load('fixed_owned_tool_supervisor',HERE/'owned_process.py')
 request_path=Path(authority_path);need(pin(request_path)['sha256']==authority_sha,'exact Root request bound by outer authority')
 request=json.loads(request_path.read_bytes());R.require_issued(request)
 for name,expected in R.TOOLS.items():
  path=Path(name);st=path.lstat();need(st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o755 and pin(path)==expected,'actual immutable529 tool bytes/mode/owner')
 need(not(OUT/'scan').exists(),'fresh recovery artifacts');(OUT/'scan').mkdir(mode=0o700);scan=OUT/'scan'
 remaining=signal.getitimer(signal.ITIMER_REAL)[0];need(0<remaining<=180,'inherited original actor alarm remains active');deadline=time.monotonic()+remaining;frames={};receipts=[]
 for command in R.plan(request):
  remaining=deadline-time.monotonic();need(remaining>3,'shared actual actor deadline')
  budget=min(command['seconds'],remaining);O.prepare()
  def limits():
   cap=R.RAW_BYTES if command['label']=='convert'else 1048576 if command['label']=='cache-body'else 16384
   resource.setrlimit(resource.RLIMIT_FSIZE,(cap,cap));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
  child=subprocess.Popen(command['argv'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env=dict(PATH='/usr/bin:/bin',LC_ALL='C',TZ='UTC'),preexec_fn=limits)
  row=O.supervise(child,cap=budget,retirement=min(1,budget/4),grace=.1,max_output=16384)
  raw=row.pop('output')
  row['children_ru_maxrss_kib']=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
  (scan/(command['label']+'.log')).write_bytes(raw);(scan/(command['label']+'.log')).chmod(0o600)
  put(scan/(command['label']+'.retirement.json'),dict(argv=command['argv'],result=row));receipts.append(row)
  need(row['passed']is True and row['reaped']is True and row['ownership']=='REAPED'and row['group_census']=='EMPTY_TWICE'and row['exit']==0 and row['signals']==[]and not row['timeout']and row['error']is None,'natural exact tool completion; no forced success')
  if command['label']=='chain':R.chain(raw)
  elif command['label']=='convert':
   need(raw==b'','quiet exact convert');p=OUT/'observation.raw';st=p.lstat();need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_size==R.RAW_BYTES and st.st_blocks*512<=R.RAW_BYTES,'fresh exact sparse raw output geometry')
  elif command['label']=='cache-body':
   need(re.fullmatch(R.S.BANNER+b'\n',raw)is not None,'only debugfs dump banner')
  else:
   # Frozen supervisor retains all combined bytes. Normalize only the one exact
   # debugfs banner position; retain the untouched raw frame in the .log file.
   lines=raw.splitlines(keepends=True);banners=[n for n,line in enumerate(lines)if re.fullmatch(R.S.BANNER+b'\n',line)]
   need(len(banners)==1,'one exact debugfs banner');i=banners[0];frames[command['label']]=lines[i]+b''.join(lines[:i]+lines[i+1:])
 body=OUT/'cache.bin';need(pin(body)['bytes']<=1048576,'bounded public cache dump')
 result=R.decode_outputs(frames,body.read_bytes(),json.loads((HERE/'baseline-public.DATA.json').read_bytes()))
 for name in('cache.bin','observation.raw'):
  source=OUT/name;target=scan/name;need(not target.exists()and not source.is_symlink(),'only fresh owned recovery output relocation');source.rename(target)
 names={p.name for p in scan.iterdir()};expected={command['label']+suffix for command in R.plan(request)for suffix in('.log','.retirement.json')}|{'cache.bin','observation.raw'}
 need(names==expected,'exact seven-command public artifact set')
 files={name:pin(scan/name)for name in sorted(names)};need(sum(r['bytes']for r in files.values())<=R.RAW_BYTES+4*1024**2,'bounded raw plus public metadata artifact sum')
 summary=dict(kind='OBSERVED_R86_PUBLIC_LDCACHE_RECOVERY_DATA_V1',status='PUBLIC_CACHE_PARENT_DATA_NOT_LIFECYCLE_ACCEPTANCE',request=pin(request_path),Source_lock=R.SOURCE,files=files,cache_observation=result,tools_reverified=True,commands=7,all_tools_naturally_reaped=True,Root_acceptance=None,VM_acceptance=None,lifecycle_acceptance=None,M2=None,release=None)
 need(len((json.dumps(summary,sort_keys=True,indent=2)+'\n').encode())<=16384,'bounded public summary');put(scan/'observation.DATA.json',summary)
 return 0
