# SPDX-License-Identifier: MIT
"""Explicit current607 VM transport; parent transaction bodies stay complete."""
import ast
import hashlib
import json
from pathlib import Path
import signal,time
import kernel_data

RELEASE='7.1.13-generic16k-managed-gui'
PRED4="and os.geteuid() == 0 and Path('/.dockerenv').is_file() and os.sysconf('SC_PAGE_SIZE') == 4096"
PRED16="and os.geteuid() == 0 and os.sysconf('SC_PAGE_SIZE') == 16384 and os.uname().release == '7.1.13-generic16k-managed-gui' and 'caa_apps6_update16k=1' in Path('/proc/cmdline').read_text().split()"
COPY_COST_EDITS = [('scripts/update/aux_copy.py', [('\'# SPDX-License-Identifier: MIT\\n"""Private copied-root scalar cost DATA; no observations or authority are cached."""\\nimport ast,hashlib,json,os,resource,time\\nSTAGES=(\\\'COPY\\\',\\\'SOURCE_BEFORE\\\',\\\'CAPACITY_AND_DESTINATION_OPEN\\\',\\\'DIRECTORIES\\\',\\\'REGULAR_FILES\\\',\\\'SYMLINKS\\\',\\\'DIRECTORY_METADATA\\\',\\\'DESTINATION_OBSERVE\\\',\\\'SOURCE_AFTER\\\',\\\'FINAL_ROOT_CHECKS\\\',\\\'COMPLETE\\\')\\nEVENTS=(\\\'BEGIN\\\',\\\'POINT\\\',\\\'END\\\',\\\'FAIL\\\')\\nCOLUMNS=(\\\'monotonic_ns\\\',\\\'process_cpu_ns\\\',\\\'user_us\\\',\\\'system_us\\\',\\\'maxrss_kib\\\',\\\'rchar\\\',\\\'wchar\\\',\\\'syscr\\\',\\\'syscw\\\',\\\'read_bytes\\\',\\\'write_bytes\\\',\\\'cancelled_write_bytes\\\')\\nPREFIX=b\\\'UPDATER489_COPY_COST \\\'\\n_origin=None;_sequence=0;_bytes=0\\n\\ndef cost(stage,event):\\n """Fresh fixed-size scalar observations only; original failures always prevail."""\\n global _origin,_sequence,_bytes\\n try:\\n  if stage not in STAGES or event not in EVENTS or _sequence>=12:return\\n  started=time.monotonic_ns();usage=resource.getrusage(resource.RUSAGE_SELF);cpu=time.process_time_ns()\\n  io=[-1]*len(COLUMNS[5:])\\n  try:\\n   fd=os.open(\\\'/proc/self/io\\\',os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)\\n   try:raw=os.read(fd,1025)\\n   finally:os.close(fd)\\n   if len(raw)>1024:raise ValueError(\\\'bounded optional IO counters\\\')\\n   rows={}\\n   for line in raw.decode(\\\'ascii\\\').splitlines():\\n    key,value=line.split(\\\': \\\',1)\\n    if key in rows:raise ValueError(\\\'duplicate optional IO counter\\\')\\n    rows[key]=int(value)\\n   if set(rows)!=set(COLUMNS[5:])or any(type(v)is not int or not 0<=v<2**63 for v in rows.values()):raise ValueError(\\\'typed optional IO counters\\\')\\n   io=[rows[n]for n in COLUMNS[5:]]\\n  except Exception:pass # Missing/denied kernel accounting never suppresses scalar clocks.\\n  values=[started,cpu,int(usage.ru_utime*10**6),int(usage.ru_stime*10**6),usage.ru_maxrss,*io]\\n  if _origin is None:_origin=values[:]\\n  _sequence+=1\\n  delta=[v-b for v,b in zip(values[:5],_origin[:5])]\\n  delta+=([v-b for v,b in zip(values[5:],_origin[5:])]if all(v>=0 for v in values[5:]+_origin[5:])else[-1]*len(COLUMNS[5:]))\\n  row=[2,_sequence,STAGES.index(stage),EVENTS.index(event),*delta,time.monotonic_ns()-started]\\n  data=PREFIX+json.dumps(row,separators=(\\\',\\\',\\\':\\\')).encode(\\\'ascii\\\')+b\\\'\\\\n\\\'\\n  if len(data)>256 or _bytes+len(data)>3072:return\\n  _bytes+=len(data);os.write(2,data)\\n except BaseException:pass\\n\\n\\ndef bind(module,raw,expected):\\n """Instrument a private already-pinned whole original copier, strip-invertibly."""\\n if (len(raw),hashlib.sha256(raw).hexdigest())!=expected:raise ValueError(\\\'whole cost copier source\\\')\\n text=raw.decode();tree=ast.parse(text);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==\\\'_copy_internal\\\');original=ast.get_source_segment(text,node);changed=original\\n anchors=((\\\'SOURCE_BEFORE\\\',\\\'        before=roots.observe(source,limits=limits,hardlinks=mode)\\\'),(\\\'CAPACITY_AND_DESTINATION_OPEN\\\',\\\'        check_capacity([dict(\\\'),(\\\'DIRECTORIES\\\',\\\'        directories=sorted(\\\'),(\\\'REGULAR_FILES\\\',\\\'        copied=set()\\\'),(\\\'SYMLINKS\\\',"        for name,value in sorted(nodes.items()):\\\\n            limits.tick()\\\\n            if value[\\\'type\\\']!=\\\'symlink\\\':continue"),(\\\'DIRECTORY_METADATA\\\',\\\'        for name in reversed(directories):\\\'),(\\\'DESTINATION_OBSERVE\\\',\\\'        final_dst=roots._identity(os.fstat(dst))\\\'),(\\\'SOURCE_AFTER\\\',\\\'        after=roots.observe(source,limits=limits,hardlinks=mode)\\\'),(\\\'FINAL_ROOT_CHECKS\\\',"        _root_check(source,src,roots._identity(src_info),src_mount,limits)\\\\n        _root_check(target.parent,parent,parent_final,parent_mount,limits)"),(\\\'COMPLETE\\\',\\\'    return report\\\'))\\n for stage,anchor in anchors:\\n  if changed.count(anchor)!=1:raise ValueError(\\\'one exact copy cost seam: \\\'+stage)\\n  indent=anchor[:len(anchor)-len(anchor.lstrip())];changed=changed.replace(anchor,indent+"_updater_cost.cost("+repr(stage)+",\\\'POINT\\\')\\\\n"+anchor,1)\\n restored=\\\'\\\\n\\\'.join(line for line in changed.split(\\\'\\\\n\\\')if not line.lstrip().startswith(\\\'_updater_cost.cost(\\\'))\\n if restored!=original:raise ValueError(\\\'whole copy cost body inverse\\\')\\n # The caller supplies this very private helper namespace, not an import route.\\n module.__dict__[\\\'_updater_cost\\\']=__import__(\\\'types\\\').SimpleNamespace(cost=cost)\\n exec(compile(changed,module.__file__+\\\':scalar-cost\\\',\\\'exec\\\'),module.__dict__)\\n held=module._copy_internal\\n def copy(*args,**kwargs):\\n  cost(\\\'COPY\\\',\\\'BEGIN\\\')\\n  try:value=held(*args,**kwargs)\\n  except BaseException:\\n   cost(\\\'COPY\\\',\\\'FAIL\\\');raise\\n  cost(\\\'COPY\\\',\\\'END\\\');return value\\n copy.__wrapped__=held;copy._whole_original=original\\n module._copy_internal=copy\\n return module\\n\'', '\'# SPDX-License-Identifier: MIT\\n"""Bounded scalar copy diagnostics; no filesystem results or authority cached.\\n\\nBEGIN/POINT/END retain v2\\\'s 17 integer columns. COPY FAIL is v3: those columns,\\nthen trace_role, original_source_line, completed_groups, completed_members,\\ncompleted_bytes, parent_calls, alias_calls, statx_success, mount_fallback.\\nTrace selects the deepest recognized action frame, excluding generic need/tick.\\nCompletion means the final source-group-drift guard passed, not admission.\\n"""\\nimport ast,hashlib,json,os,resource,time\\nSTAGES=(\\\'COPY\\\',\\\'SOURCE_BEFORE\\\',\\\'CAPACITY_AND_DESTINATION_OPEN\\\',\\\'DIRECTORIES\\\',\\\'REGULAR_FILES\\\',\\\'SYMLINKS\\\',\\\'DIRECTORY_METADATA\\\',\\\'DESTINATION_OBSERVE\\\',\\\'SOURCE_AFTER\\\',\\\'FINAL_ROOT_CHECKS\\\',\\\'COMPLETE\\\')\\nEVENTS=(\\\'BEGIN\\\',\\\'POINT\\\',\\\'END\\\',\\\'FAIL\\\')\\nCOLUMNS=(\\\'monotonic_ns\\\',\\\'process_cpu_ns\\\',\\\'user_us\\\',\\\'system_us\\\',\\\'maxrss_kib\\\',\\\'rchar\\\',\\\'wchar\\\',\\\'syscr\\\',\\\'syscw\\\',\\\'read_bytes\\\',\\\'write_bytes\\\',\\\'cancelled_write_bytes\\\')\\nDIAGNOSTIC_COLUMNS=(\\\'trace_role\\\',\\\'source_line\\\',\\\'completed_groups\\\',\\\'completed_members\\\',\\\'completed_bytes\\\',\\\'parent_calls\\\',\\\'alias_calls\\\',\\\'statx_success\\\',\\\'mount_fallback\\\')\\nTRACE_ROLES=(\\\'UNKNOWN\\\',\\\'COPY_INTERNAL\\\',\\\'PARENT\\\',\\\'SOURCE_ALIAS\\\',\\\'COPY_WRITE\\\',\\\'ROOT_FILE_HASH\\\',\\\'ROOT_OBSERVE\\\',\\\'MOUNT_QUERY\\\',\\\'COPY_ROOT_CHECK\\\',\\\'ROOT_PATH\\\')\\nCOPIER=(25734,\\\'e582245bd114b0b9d83f2de4fdc81a35d2f48493ba6147879871af794476813b\\\')\\nPREFIX=b\\\'UPDATER489_COPY_COST \\\'\\n_origin=None;_sequence=0;_bytes=0\\n_stats=[0]*7;_trace=(0,0)\\n\\n\\ndef _bump(index,value=1):\\n try:\\n  if type(value)is int and value>=0:_stats[index]=min(2**63-1,_stats[index]+value)\\n except BaseException:pass\\n\\ndef parent():_bump(3)\\ndef alias():_bump(4)\\ndef complete(members,byte_count):\\n _bump(0);_bump(1,members);_bump(2,byte_count)\\ndef mount(kind):\\n """Called immediately before a successful statx/fallback result; emits nothing."""\\n if kind==\\\'statx\\\':_bump(5)\\n elif kind==\\\'fallback\\\':_bump(6)\\n\\ndef failure(error):\\n global _trace\\n try:\\n  result=(0,0);tb=error.__traceback__\\n  copier={\\\'_copy_internal\\\':1,\\\'_parent\\\':2,\\\'_source_alias\\\':3,\\\'_write\\\':4,\\\'_root_check\\\':8}\\n  roots={\\\'_file_hash\\\':5,\\\'observe\\\':6,\\\'walk\\\':6,\\\'_mount_id\\\':7,\\\'_open_root\\\':9,\\\'node\\\':9}\\n  while tb is not None:\\n   code=tb.tb_frame.f_code;file=os.path.basename(code.co_filename).split(\\\':\\\',1)[0]\\n   role=(copier.get(code.co_name,0)if file==\\\'measure_copy.py\\\'else\\n         roots.get(code.co_name,0)if file==\\\'full_root.py\\\'else\\n         7 if file==\\\'aux_copy.py\\\'and code.co_name==\\\'query\\\'else 0)\\n   if role and type(tb.tb_lineno)is int and 0<tb.tb_lineno<2**31:result=(role,tb.tb_lineno)\\n   tb=tb.tb_next\\n  _trace=result\\n except BaseException:pass\\n\\ndef cost(stage,event):\\n """Fresh fixed-size scalar observations only; original failures always prevail."""\\n global _origin,_sequence,_bytes\\n try:\\n  if stage not in STAGES or event not in EVENTS or _sequence>=12:return\\n  started=time.monotonic_ns();usage=resource.getrusage(resource.RUSAGE_SELF);cpu=time.process_time_ns()\\n  io=[-1]*len(COLUMNS[5:])\\n  try:\\n   fd=os.open(\\\'/proc/self/io\\\',os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)\\n   try:raw=os.read(fd,1025)\\n   finally:os.close(fd)\\n   if len(raw)>1024:raise ValueError(\\\'bounded optional IO counters\\\')\\n   rows={}\\n   for line in raw.decode(\\\'ascii\\\').splitlines():\\n    key,value=line.split(\\\': \\\',1)\\n    if key in rows:raise ValueError(\\\'duplicate optional IO counter\\\')\\n    rows[key]=int(value)\\n   if set(rows)!=set(COLUMNS[5:])or any(type(v)is not int or not 0<=v<2**63 for v in rows.values()):raise ValueError(\\\'typed optional IO counters\\\')\\n   io=[rows[n]for n in COLUMNS[5:]]\\n  except Exception:pass\\n  values=[started,cpu,int(usage.ru_utime*10**6),int(usage.ru_stime*10**6),usage.ru_maxrss,*io]\\n  if _origin is None:_origin=values[:]\\n  _sequence+=1\\n  delta=[v-b for v,b in zip(values[:5],_origin[:5])]\\n  delta+=([v-b for v,b in zip(values[5:],_origin[5:])]if all(v>=0 for v in values[5:]+_origin[5:])else[-1]*len(COLUMNS[5:]))\\n  diagnostic=stage==\\\'COPY\\\'and event==\\\'FAIL\\\'\\n  row=[3 if diagnostic else 2,_sequence,STAGES.index(stage),EVENTS.index(event),*delta,time.monotonic_ns()-started]\\n  if diagnostic:row.extend((*_trace,*_stats))\\n  if any(type(v)is not int or not -2**63<v<2**63 for v in row):return\\n  data=PREFIX+json.dumps(row,separators=(\\\',\\\',\\\':\\\')).encode(\\\'ascii\\\')+b\\\'\\\\n\\\'\\n  if len(data)>256 or _bytes+len(data)>3072:return\\n  _bytes+=len(data);os.write(2,data)\\n except BaseException:pass\\n\\n\\ndef _instrument(module,node,text,insertions):\\n original=ast.get_source_segment(text,node);changed=original\\n for anchor,diagnostic,after in insertions:\\n  if changed.count(anchor)!=1:raise ValueError(\\\'one exact copy diagnostic seam\\\')\\n  changed=changed.replace(anchor,anchor+\\\'\\\\n\\\'+diagnostic if after else diagnostic+\\\'\\\\n\\\'+anchor,1)\\n restored=\\\'\\\\n\\\'.join(line for line in changed.split(\\\'\\\\n\\\')if not line.lstrip().startswith(\\\'_updater_cost.\\\'))\\n if restored!=original:raise ValueError(\\\'whole copy diagnostic body inverse\\\')\\n # Compile full bodies with ORIGINAL line numbers, including unmodified guards.\\n mapping={};line=node.lineno\\n for number,value in enumerate(changed.splitlines(),1):\\n  mapping[number]=line\\n  if not value.lstrip().startswith(\\\'_updater_cost.\\\'):line+=1\\n tree=ast.parse(changed)\\n for item in ast.walk(tree):\\n  if hasattr(item,\\\'lineno\\\'):item.lineno=mapping[item.lineno]\\n  if getattr(item,\\\'end_lineno\\\',None)is not None:item.end_lineno=mapping[item.end_lineno]\\n exec(compile(tree,module.__file__,\\\'exec\\\'),module.__dict__)\\n held=getattr(module,node.name)\\n held._whole_original=original;held._cost_instrumented=changed\\n return held\\n\\ndef bind(module,raw,expected):\\n """Add diagnostics to the exact original copier; strip-invert every full body."""\\n if expected!=COPIER or (len(raw),hashlib.sha256(raw).hexdigest())!=COPIER:raise ValueError(\\\'whole cost copier source\\\')\\n text=raw.decode();tree=ast.parse(text)\\n nodes={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}\\n anchors=((\\\'SOURCE_BEFORE\\\',\\\'        before=roots.observe(source,limits=limits,hardlinks=mode)\\\'),(\\\'CAPACITY_AND_DESTINATION_OPEN\\\',\\\'        check_capacity([dict(\\\'),(\\\'DIRECTORIES\\\',\\\'        directories=sorted(\\\'),(\\\'REGULAR_FILES\\\',\\\'        copied=set()\\\'),(\\\'SYMLINKS\\\',"        for name,value in sorted(nodes.items()):\\\\n            limits.tick()\\\\n            if value[\\\'type\\\']!=\\\'symlink\\\':continue"),(\\\'DIRECTORY_METADATA\\\',\\\'        for name in reversed(directories):\\\'),(\\\'DESTINATION_OBSERVE\\\',\\\'        final_dst=roots._identity(os.fstat(dst))\\\'),(\\\'SOURCE_AFTER\\\',\\\'        after=roots.observe(source,limits=limits,hardlinks=mode)\\\'),(\\\'FINAL_ROOT_CHECKS\\\',"        _root_check(source,src,roots._identity(src_info),src_mount,limits)\\\\n        _root_check(target.parent,parent,parent_final,parent_mount,limits)"),(\\\'COMPLETE\\\',\\\'    return report\\\'))\\n additions=[]\\n for stage,anchor in anchors:\\n  indent=anchor[:len(anchor)-len(anchor.lstrip())]\\n  additions.append((anchor,indent+"_updater_cost.cost("+repr(stage)+",\\\'POINT\\\')",False))\\n additions.append(("                need(roots._identity(os.fstat(old))==identity,\\\'copy source group drift\\\')",\\n                   \\\'                _updater_cost.complete(len(members),total)\\\',True))\\n module.__dict__[\\\'_updater_cost\\\']=__import__(\\\'types\\\').SimpleNamespace(cost=cost,parent=parent,alias=alias,complete=complete)\\n held_parent=_instrument(module,nodes[\\\'_parent\\\'],text,[(\\\'    roots.installer.relative(path)\\\',\\\'    _updater_cost.parent()\\\',False)])\\n module._parent=__import__(\\\'contextlib\\\').contextmanager(held_parent)\\n _instrument(module,nodes[\\\'_source_alias\\\'],text,[(\\\'    with _parent(root,name,mount,identities,limits,nodes) as (parent,base),_descriptors() as held:\\\',\\n                                              \\\'    _updater_cost.alias()\\\',False)])\\n held=_instrument(module,nodes[\\\'_copy_internal\\\'],text,additions)\\n def copy(*args,**kwargs):\\n  global _trace\\n  _stats[:]=[0]*7;_trace=(0,0)\\n  cost(\\\'COPY\\\',\\\'BEGIN\\\')\\n  try:value=held(*args,**kwargs)\\n  except BaseException as error:\\n   failure(error);cost(\\\'COPY\\\',\\\'FAIL\\\');raise\\n  cost(\\\'COPY\\\',\\\'END\\\');return value\\n copy.__wrapped__=held;copy._whole_original=held._whole_original\\n copy._cost_instrumented=held._cost_instrumented\\n module._copy_internal=copy\\n return module\\n\''), ('        if call is None:return original(descriptor,limits)', "        if call is None:_updater_copy_cost.mount('fallback');return original(descriptor,limits)"), ('\n                call=None;return original(descriptor,limits)', "\n                call=None;_updater_copy_cost.mount('fallback');return original(descriptor,limits)"), ('\n            call=None;return original(descriptor,limits)', "\n            call=None;_updater_copy_cost.mount('fallback');return original(descriptor,limits)"), ("        if not result.mnt_id:raise ValueError('descriptor statx mount identity unavailable')", "        if not result.mnt_id:raise ValueError('descriptor statx mount identity unavailable')\n        _updater_copy_cost.mount('statx')"), ('    checked=False\n', "    empty_path=ctypes.c_char_p(b'');empty_flags=ctypes.c_int(0x1000);mount_mask=ctypes.c_uint(0x1000)\n    checked=False\n"), ("        if call(descriptor,b'',0x1000,0x1000,ctypes.byref(result))!=0:", '        if call(descriptor,empty_path,empty_flags,mount_mask,ctypes.byref(result))!=0:')])]
OWNER_EDITS=[("'audio-inputs','output')", "'audio-inputs','output','kernel-input','fresh16k-source')"), ('a=p.parse_args(argv);policy=C.policy()', 'a=p.parse_args(argv);vm.authorize(a);policy=C.policy()'), ("old.command(argv+['--entrypoint=/usr/bin/python3',image,'-I','-B','/runner.py'],public/'transaction.log',3900)", 'vm.run(a,argv,image,public,raw,old,15840)'), ('GENERIC4K_LATEST607_APPS6_TO16_COPIED_ROOT_SOFTWARE_ONLY', 'GENERIC16K_LATEST607_APPS6_TO16_COPIED_ROOT_SOFTWARE_ONLY'), ("result.update(status='PASS',composition=row)", "result.update(status='PASS',composition=row,generic16k=C.read(public/'updater16k-result.json'))"), ('failures=old.retire_outer(actor_owned,result);retired=not failures', 'failures=vm.retire_outer(old,actor_owned,result,public);retired=not failures')]

def need(ok,why):
 if not ok:raise ValueError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def transaction(function,*args):
 # Cover preparation, QEMU and export with the original enclosing15840s span.
 # A numeric QEMU-only15840 would silently widen that original transaction span.
 need(args[-1]==15840 and signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'original15840 span with no foreign timer')
 before=time.monotonic();deadline=before+15840;prior=signal.getsignal(signal.SIGALRM)
 def expired(*_):raise TimeoutError('original enclosing15840 transaction span exhausted')
 signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,15840)
 try:
  result=function(*args);need(time.monotonic()<deadline,'complete VM transport exceeded original15840 span');return result
 finally:
  signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,prior)

def derive(raw,edits):
 before=raw.decode();after=before
 for old,new in edits:
  need(after.count(old)==1,'one selected source seam '+old[:60]);after=after.replace(old,new,1)
 restored=after
 for old,new in reversed(edits):
  need(restored.count(new)==1,'one selected source inverse');restored=restored.replace(new,old,1)
 need(restored==before,'complete parent body inverse');ast.parse(after)
 return after.encode(),dict(before=pin(raw),after=pin(after.encode()),edits=edits,whole_inverse=True)

def owner(raw):
 out,proof=derive(raw,OWNER_EDITS)
 functions=lambda data:{n.name:ast.dump(n,include_attributes=False)for n in ast.parse(data).body if isinstance(n,ast.FunctionDef)}
 a,b=functions(raw),functions(out);need([n for n in a if a[n]!=b[n]]==['main'],'only outer VM dispatch changes; verifier and retirement bodies held')
 need(pin(out)==json.loads((Path(__file__).resolve().parent/'profile.json').read_bytes())['emitted_owner'],'actor owner equals constructor source emission')
 return out.decode(),proof

def candidate(api,source,target,case,descriptor):
 config,calling=api.candidate(source,target,case)
 config_raw=config.read_bytes();value=json.loads(config_raw);ledger={}
 for name,edits in (
  ('scripts/ci/full-root-upgrade-caller/container.py',[(PRED4,PRED16)]),
  ('scripts/install/local_transaction.py',[("os.uname().release == '7.2.10-1-aarch64-ARCH'", "os.uname().release == '7.1.13-generic16k-managed-gui'"),("os.sysconf('SC_PAGE_SIZE') == 4096", "os.sysconf('SC_PAGE_SIZE') == 16384")]))+tuple(COPY_COST_EDITS):
  path=target/name;raw=path.read_bytes();need(value['code_pins'][name]==pin(raw)['sha256'],'original emitted code/config join')
  out,proof=derive(raw,edits);path.write_bytes(out);value['code_pins'][name]=pin(out)['sha256'];ledger[name]=proof
 held=json.loads(json.dumps(value));held['code_pins']=json.loads(config_raw)['code_pins']
 need(held==json.loads(config_raw),'all transaction/DB/security/clock configuration outside emitted code pins held')
 config.write_bytes(enc(value))
 receipt=json.loads((target/'adapter.json').read_bytes());receipt['config_sha256']=pin(config.read_bytes())['sha256']
 receipt['explicit_generic16k']=dict(status='SOURCE_DERIVED_NOT_EXECUTED',page_size=16384,kernel=RELEASE,kernel_input=descriptor,ledger=ledger,original_config=config_raw.decode(),clocks='UNCHANGED',actual=None)
 (target/'adapter.json').write_bytes(enc(receipt))
 import custody,lifecycle_overlay
 lifecycle_overlay.apply(target,case)
 need(custody.rows(target)==custody.profile()['emitted_cases'][case],'all current16K installer/caller/config/policy emissions match constructor')
 return config,calling

def vm(api,args,extra,context,verify_dependencies):
 import common as C
 root=Path(__file__).resolve().parent;support=root/'vm'
 contract=C.load('_current607_vm_contract',support/'contract.py')
 transport=C.load('_current607_vm_transport',support/'vm.py',{'contract':contract})
 def kernel(a):
  verify_dependencies(a.fresh16k_source,'fresh16k')
  descriptor=json.loads((root/'profile.json').read_bytes())['kernel_descriptor']
  value,image,config=kernel_data.verify(a.kernel_input,descriptor)
  profile=dict(value,profile='CURRENT607_EXPLICIT_GENERIC16K_KERNEL_DATA_V1',release=RELEASE,architecture='aarch64')
  return profile,a.kernel_input/'Image',a.kernel_input/'config'
 def authorize(a):
  verify_dependencies(a.implementation,'held')
  __import__('authority').gates(extra.latest_decisions)
  api.inputs()
  return kernel(a)
 transport.kernel=kernel;transport.authorize=authorize
 transport.old_verify=lambda a:api._owner.verify_result
 transport._CURRENT607=context
 transport._KERNEL_DESCRIPTOR=json.loads((root/'profile.json').read_bytes())['kernel_descriptor']
 original_run=transport.run
 transport.run=lambda *args:transaction(original_run,*args)
 return transport

def execute(held,argv,context,verify_dependencies):
 import common as C,runtime as R,authority
 extra,rest=R.extras(argv,require_dependency=True);authority.gates(extra.latest_decisions)
 api=R.Integration(held,extra.latest_installer,extra.six_public,extra.six_record,{k:getattr(extra,k)for k in('apps16','apps16qualification','apps16current606qualification')},context['source'],extra.dependency_incoming)
 original=R.derive_owner;proof=[]
 def selected(raw):
  body,ledger=owner(original(raw).encode());proof.append(ledger);return body
 try:
  R.derive_owner=selected;active=api.owner()
 finally:R.derive_owner=original
 api._owner=active
 class Adapter:
  @staticmethod
  def prepare(source,target,case):
   descriptor=json.loads((Path(__file__).resolve().parent/'profile.json').read_bytes())['kernel_descriptor']
   return candidate(api,source,target,case,descriptor)
 active.adapter=Adapter
 active.vm=vm(api,rest,extra,context,verify_dependencies)
 need(len(proof)==1 and proof[0]['whole_inverse'],'complete parent607 owner inversion before execution')
 return active.main(rest)
