# SPDX-License-Identifier: MIT
"""Same-run host realtime handoff; only dedicated guest PID1 may set a clock."""
import base64,json,os,re,stat,time
from pathlib import Path
MARKER='caa_gnu_original_clock='
MIN_EPOCH_NS=1779031879*10**9
MAX_STARTUP_NS=1200*10**9
FIELDS={'schema','source_sha','ref','run_id','nonce','native_epoch_ns','native_monotonic_ns'}
def need(ok,why):
 if not ok:raise ValueError(why)
def encode(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')
def pairs(rows):
 v={}
 for k,x in rows:need(k not in v,'duplicate original-clock field');v[k]=x
 return v
def decode(raw):return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite original clock'))
def identity(v):
 need(type(v)is dict and set(v)==FIELDS and type(v['schema'])is int and v['schema']==1,'complete native clock handoff')
 need(type(v['source_sha'])is str and re.fullmatch('[a-f0-9]{40}',v['source_sha'])and type(v['ref'])is str and re.fullmatch('codex/[a-z0-9-]+',v['ref'])and type(v['run_id'])is int and 0<v['run_id']<2**63 and type(v['nonce'])is str and re.fullmatch('[a-f0-9]{32}',v['nonce']),'same-run clock selectors')
 need(type(v['native_epoch_ns'])is int and MIN_EPOCH_NS<=v['native_epoch_ns']<2**63 and type(v['native_monotonic_ns'])is int and 0<v['native_monotonic_ns']<2**63,'bounded fresh native clock sample')
 return v

def host_argv(argv,volume):
 """Called immediately before the original supervised QEMU launch, never SOURCE."""
 need(type(argv)is list and argv and argv[0]=='/usr/bin/qemu-system-aarch64'and argv.count('-append')==1 and all(type(x)is str for x in argv),'one unchanged native QEMU cmdline')
 path=Path(volume).parent.parent/'selection.json';need(path.is_absolute()and path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'same native owner selection')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);stat_identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_nlink,v.st_uid,v.st_gid,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
  need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_uid==os.geteuid()and 0<before.st_size<=65536,'ordinary bounded native selection')
  raw=bytearray()
  while len(raw)<=before.st_size:
   part=os.read(fd,min(65536,before.st_size-len(raw)+1))
   if not part:break
   raw.extend(part)
  need(len(raw)==before.st_size and stat_identity(before)==stat_identity(os.fstat(fd))==stat_identity(path.lstat()),'native selection stable FD/path through clock sample')
  selected=decode(bytes(raw))
 finally:os.close(fd)
 source=os.environ.get('SOURCE_SHA');need(source==os.environ.get('WORKFLOW_SHA')==selected['source_sha'],'native source/workflow clock identity')
 run=os.environ.get('GITHUB_RUN_ID','');need(run.isdecimal(),'native genuine run clock identity')
 v=identity(dict(schema=1,source_sha=source,ref=os.environ.get('GITHUB_REF_NAME'),run_id=int(run),nonce=selected['nonce'],native_epoch_ns=time.time_ns(),native_monotonic_ns=time.monotonic_ns()))
 token=base64.urlsafe_b64encode(encode(v)).decode('ascii');need(len(token)<=1024,'bounded native clock kernel token')
 out=list(argv);index=out.index('-append')+1;need(index<len(out)and not any(s.startswith(MARKER)for s in out[index].split()),'native clock operand cannot be preselected');out[index]+=' '+MARKER+token
 need(len(out[index].encode())<=65536,'bounded full native clock cmdline')
 return out

def guest_handoff(value,selected,cmdline=None):
 """Validate Source-selected nonce/run before setting this guest's REALTIME only."""
 need(os.getpid()==1 and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'and os.sysconf('SC_PAGE_SIZE')==16384,'dedicated real16K aarch64 root PID1 only; never host or worker clock')
 line=Path('/proc/cmdline').read_text()if cmdline is None else cmdline
 need(type(line)is str and len(line.encode())<=65536 and line.split().count('caa_gnu_immutable_runtime=1')==1,'one actual immutable guest clock purpose')
 tokens=[s[len(MARKER):]for s in line.split()if s.startswith(MARKER)];need(len(tokens)==1 and len(tokens[0])<=1024,'one same-run native clock token')
 try:raw=base64.b64decode(tokens[0],altchars=b'-_',validate=True)
 except ValueError:raise ValueError('canonical native clock base64')from None
 need(base64.urlsafe_b64encode(raw).decode()==tokens[0],'canonical native clock encoding');v=identity(decode(raw));need(encode(v)==raw,'canonical source-owned native clock record')
 need(v['source_sha']==value['actual_source']==selected['source_sha']and v['ref']==value['actual_ref']and str(v['run_id'])==str(value['actual_run'])and v['nonce']==selected['nonce']==value['broker']['nonce']==value['bootstrap']['nonce'],'clock same actual source/ref/run/fresh original nonce')
 monotonic=time.monotonic_ns();need(0<monotonic<=MAX_STARTUP_NS,'guest clock handoff before original1200-second cold-start window')
 before=time.time_ns();target=v['native_epoch_ns']+monotonic
 need(before<=target+MAX_STARTUP_NS,'guest future clock is refused, never rewound to hide expiry')
 changed=before<target
 if changed:time.clock_settime_ns(time.CLOCK_REALTIME,target)
 after=time.time_ns();need(target<=after<=target+MAX_STARTUP_NS and after>=before,'guest realtime readback and forward-only handoff')
 return dict(schema=1,status='PASS_GUEST_REALTIME_HANDOFF',source_sha=v['source_sha'],ref=v['ref'],run_id=v['run_id'],nonce=v['nonce'],native_epoch_ns=v['native_epoch_ns'],native_monotonic_ns=v['native_monotonic_ns'],guest_before_ns=before,guest_after_ns=after,guest_monotonic_ns=monotonic,clock_set=changed)

def pack_receipt(v):
 raw=encode(v);need(len(raw)<=2048,'bounded PID1 clock receipt');return base64.urlsafe_b64encode(raw).decode('ascii')
def unpack_receipt(text):
 need(type(text)is str and 0<len(text)<=4096,'explicit PID1 clock environment handoff')
 raw=base64.b64decode(text,altchars=b'-_',validate=True);need(base64.urlsafe_b64encode(raw).decode()==text and len(raw)<=2048,'canonical bounded PID1 clock receipt');v=decode(raw);need(encode(v)==raw,'canonical PID1 clock receipt');return v
