# SPDX-License-Identifier: MIT
"""Validate complete Meson 1.12.1 JSONL and the non-skipped chroot assertions."""
import collections,hashlib,json,math,os,stat,sys
from pathlib import Path
CAP=128*1024**2
MARKER='CAA_OWNED_USERNS_CHROOT_ASSERTIONS_COMPLETE'
WRAPPER='/tmp/work/src/systemd-8cc40e0c5e9234bf45084751ac53b1fbfe70b492/tools/test-crash-trace.sh'
EXCLUDED_SUITES=('clang-tidy','coccinelle','unused-symbols','integration-tests')
RESULTS={'OK','TIMEOUT','INTERRUPT','SKIP','FAIL','EXPECTEDFAIL','UNEXPECTEDPASS','ERROR','IGNORED'}
BAD={'FAIL','TIMEOUT','INTERRUPT','UNEXPECTEDPASS','ERROR'}
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def pairs(items):
 d={}
 for k,v in items:
  if k in d:raise ValueError('duplicate JSON field')
  d[k]=v
 return d
def invalid(_):raise ValueError('nonfinite JSON field')
def read(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode)or a.st_nlink!=1 or not 0<a.st_size<=CAP:raise ValueError('bounded ordinary complete test log')
  data=bytearray()
  while b:=os.read(fd,min(1024**2,CAP+1-len(data))):
   data.extend(b)
   if len(data)>CAP:raise ValueError('test log size bound')
  z=os.fstat(fd);identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink)
  if len(data)!=a.st_size or identity(a)!=identity(z):raise ValueError('test log changed')
  return bytes(data)
 finally:os.close(fd)
def audit(raw,intro_raw):
 if type(raw)is not bytes or not 0<len(raw)<=CAP or not raw.endswith(b'\n'):raise ValueError('complete bounded JSON lines required')
 definitions=json.loads(intro_raw,object_pairs_hook=pairs,parse_constant=invalid)
 if type(definitions)is not list or not 1<=len(definitions)<=10000:raise ValueError('complete bounded Meson introspection')
 expected={};excluded=[];definition_ids=set()
 for v in definitions:
  if type(v)is not dict or set(v)!={'cmd','env','name','workdir','timeout','suite','is_parallel','priority','protocol','depends','extra_paths'}:raise ValueError('exact signed introspection schema')
  if type(v['suite'])is not list or not v['suite']or any(type(x)is not str or not x or x.count(':')>1 or not x.partition(':')[0]for x in v['suite'])or type(v['name'])is not str:raise ValueError('typed test suite identity')
  project=v['suite'][0].partition(':')[0];suites=[x.partition(':')[2]for x in v['suite']if x.partition(':')[2]]
  name=('+'.join(suites)+' - 'if suites else'')+project+':'+v['name']
  if type(v['cmd'])is not list or not v['cmd']or any(type(x)is not str for x in v['cmd'])or not v['cmd'][0]or type(v['env'])is not dict or any(type(k)is not str or type(x)is not str for k,x in v['env'].items()):raise ValueError('typed introspection invocation')
  identity=json.dumps(v,sort_keys=True,separators=(',',':'))
  if identity in definition_ids:raise ValueError('unique complete introspection definition')
  definition_ids.add(identity)
  # Exact upstream default setup; excluded definitions remain fully validated and counted.
  if any(s.partition(':')[2]in EXCLUDED_SUITES for s in v['suite']):excluded.append(v)
  else:
   if name in expected:raise ValueError('unique introspection identity')
   expected[name]=v
 plan=expected
 rows=[];seen=set();counts=collections.Counter()
 for line in raw.splitlines():
  v=json.loads(line,object_pairs_hook=pairs,parse_constant=invalid)
  keys={'name','stdout','result','is_fail','starttime','duration','returncode','env','command'}
  if type(v)is not dict or set(v)not in(keys,keys|{'stderr'}):raise ValueError('exact signed Meson logger schema')
  if type(v['name'])is not str or not v['name']or v['name']in seen:raise ValueError('unique complete test identity')
  seen.add(v['name'])
  if v['name']not in plan or v['command']!=[WRAPPER]+plan[v['name']]['cmd']or any(v['env'].get(k)!=x for k,x in plan[v['name']]['env'].items()):raise ValueError('full planned test command/environment join')
  if v['result']not in RESULTS or type(v['is_fail'])is not bool or v['is_fail']!=(v['result']in BAD):raise ValueError('finished typed Meson result')
  if type(v['returncode'])is not int or type(v['env'])is not dict or any(type(k)is not str or type(x)is not str for k,x in v['env'].items()):raise ValueError('typed Meson process record')
  if any(type(v[k])not in(int,float)or not math.isfinite(v[k])or v[k]<0 for k in('starttime','duration')):raise ValueError('finite Meson clock')
  if type(v['command'])is not list or not v['command']or any(type(x)is not str for x in v['command'])or not v['command'][0]:raise ValueError('complete test argv')
  if any(type(v.get(k,''))is not str for k in('stdout','stderr')):raise ValueError('complete captured text')
  if v['is_fail']:raise ValueError('failed Meson test remains failed')
  counts[v['result']]+=1;rows.append(v)
  if len(rows)>10000:raise ValueError('test record bound')
 if seen!=set(plan):raise ValueError('every planned Meson test must have one complete result')
 hits=[v for v in rows if v['name']=='test - systemd:test-process-util']
 if len(hits)!=1:raise ValueError('exact process-util test record required')
 v=hits[0];command=v['command']
 if v['result']!='OK'or v['returncode']!=0 or v['is_fail']:raise ValueError('process-util skip/failure refused')
 if command!=['/tmp/work/src/systemd-8cc40e0c5e9234bf45084751ac53b1fbfe70b492/tools/test-crash-trace.sh','/tmp/work/src/build/test-process-util']:raise ValueError('exact original test wrapper and binary required')
 lines=(v['stdout']+'\n'+v.get('stderr','')).splitlines()
 # log_info() emits this fixed complete line. A substring or another test cannot supply it.
 if lines.count(MARKER)!=1 or sum((r['stdout']+'\n'+r.get('stderr','')).count(MARKER)for r in rows)!=1:raise ValueError('exact final original assertions marker required')
 return dict(schema=1,status='PASS_COMPLETE_MESON_LOG_AND_NONSKIPPED_PROCESS_ROOT_ASSERTIONS',log=pin(raw),introspection=pin(intro_raw),tests=len(rows),introspection_tests=len(definitions),default_setup=dict(name='default',wrapper=WRAPPER,excluded_suites=list(EXCLUDED_SUITES),excluded_tests=len(excluded),excluded_by_suite={s:sum(any(x.partition(':')[2]==s for x in v['suite'])for v in excluded)for s in EXCLUDED_SUITES}),results=dict(sorted(counts.items())),process_util=v,upstream_skips='REPORTED_UNCHANGED_NOT_ASSERTION_CREDIT',native_acceptance='NOT_GRANTED_BY_AUDITOR')
def save(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(raw)
  while view:view=view[os.write(fd,view):]
 finally:os.close(fd)
def main():
 if len(sys.argv)!=3:raise ValueError('complete test log and introspection operands')
 raw=read(Path(sys.argv[1]));intro=read(Path(sys.argv[2]))
 mode=os.environ.get('CACHY_ASAHI_CORE_TESTLOG_EXPORT')
 if mode is not None:
  if mode!='1'or os.environ.get('CACHY_ASAHI_CORE_CONTAINER')!='1'or os.environ.get('CORE_RECIPE')!='systemd':raise ValueError('fixed owned build export scope')
  save('/out/systemd-testlog.jsonl',raw);save('/out/systemd-intro-tests.json',intro)
 result=audit(raw,intro)
 if mode is not None:save('/out/systemd-testlog-audit.json',enc(result))
 print(enc(result).decode(),end='')
if __name__=='__main__':main()
