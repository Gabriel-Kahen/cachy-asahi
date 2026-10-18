# SPDX-License-Identifier: MIT
"""Finite actual-VM entry derivative; original source tree remains unchanged."""
import ast,hashlib,json,shutil
from pathlib import Path

MARKER='caa_apps574_repair16k=1'
MASK=sum(1<<n for n in (0,1,3,4,31))
ENV_BEFORE="need(mapped or Path('/.dockerenv').is_file(),'mapped namespace or explicit disposable container required')"
ENV_AFTER="need(os.sysconf('SC_PAGE_SIZE')==16384 and 'caa_apps574_repair16k=1' in Path('/proc/cmdline').read_text().split(),'explicit owned generic16K repair VM required')"

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def functions(raw):
 text=raw.decode();return {n.name:ast.dump(n,include_attributes=False) for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
def backend(raw):
 text=raw.decode();need(text.count(ENV_BEFORE)==1,'one source-bound backend environment entry predicate');out=text.replace(ENV_BEFORE,ENV_AFTER).encode();before,after=functions(raw),functions(out)
 need(set(before)==set(after) and [n for n in before if before[n]!=after[n]]==['environment_guard'],'only backend environment predicate may differ');return out

def execution(source,output,manifest):
 """An explicit derived tree, never the accepted byte-exact source tree."""
 source=Path(source);output=Path(output);need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh disjoint execution source')
 need(not source.is_relative_to(output) and not output.is_relative_to(source),'source/execution separation');rows=manifest['files'];need(type(rows)is dict and 1<=len(rows)<=256,'finite original source closure')
 checked={}
 for name,row in rows.items():
  need(type(name)is str and name and not name.startswith('/') and '\\' not in name and all(x not in ('','.','..') for x in name.split('/')),'safe original source name');p=source/name
  need(not any(q.is_symlink() for q in (p,*p.parents)) and p.is_file() and p.stat().st_nlink==1 and p.stat().st_size<=16*1024**2,'ordinary bounded original source');raw=p.read_bytes();need(pin(raw)==row,'original source pin differs: '+name);checked[name]=raw
 need('scripts/apps/transaction.py' in checked and 'scripts/apps/repair_inspection.py' in checked and 'manifests/packages.toml' in checked,'genuine backend/inspection/root marker closure required');output.mkdir(mode=0o700)
 for name,raw in checked.items():
  target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(backend(raw) if name=='scripts/apps/transaction.py' else raw)
 after={name:pin((output/name).read_bytes()) for name in checked};changed=[n for n in checked if after[n]!=rows[n]];need(changed==['scripts/apps/transaction.py'],'one explicit execution-source guard derivative')
 receipt=dict(status='DERIVED_VM_EXECUTION_SOURCE_NOT_NATIVE_SOURCE',original_manifest_sha256=pin(encoded(manifest))['sha256'],original_files=rows,execution_files=after,changed=changed,guard=dict(before=ENV_BEFORE,after=ENV_AFTER),unchanged_functions='ALL_BACKEND_FUNCTIONS_EXCEPT_ENVIRONMENT_ENTRY_PREDICATE',original_source_preserved=all(pin((source/n).read_bytes())==r for n,r in rows.items()),scope='GENERIC16K_OWNED_COPIED_ROOT_ONLY',hardware='NOT_RUN')
 (output/'execution-manifest.json').write_bytes(encoded(receipt));return receipt

BACKEND_NOTE="def _vm_backend_note(record,out,err,error):\n import base64,json\n keys={'argv','exit_code','seconds','time_limit','output_limit','group_absence_verified','stdout_bytes','stdout_sha256','stderr_bytes','stderr_sha256'}\n C.need(set(record)==keys and record['output_limit']==1024**2,'original backend receipt required')\n for side,data in (('stdout',out),('stderr',err)):\n  C.need(record[side+'_bytes']==len(data) and record[side+'_sha256']==C.sha(data),'original backend stream join')\n result=None\n try:\n  v=C.decode(out)\n  if set(v)=={'status','error_type','error','packages_committed','commit_started','recovery','rollback'} and v['status']=='FAIL' and v['packages_committed'] is False and v['commit_started'] is False and v['recovery']=='DISPOSE_OWNED_COPY_IF_COMMIT_OR_CLEANUP_UNCERTAIN' and v['rollback']=='NOT_CLAIMED' and type(v['error_type'])is str and len(v['error_type'])<=128 and type(v['error'])is str and len(v['error'])<=1024:\n   raw=v['error'].encode('utf8');result=dict(status='FAIL',error_type=v['error_type'],error=v['error'][:96],error_utf8_bytes=len(raw),error_sha256=C.sha(raw),truncated=len(v['error'])>96,commit_started=False,packages_committed=False)\n except (ValueError,KeyError,TypeError,UnicodeError):pass\n def phase_summary(data):\n  # Data-only projection of existing records; never inspect a root again.\n  stages=('source-revalidation','tree-and-aux-observation','tree-observe','complete-capability-map','capability-scan','copy-with-capability-restoration','copy-data','diagnostic-limit')\n  events=('BEGIN','END','FAIL','FURTHER_PHASE_RECORDS_OMITTED')\n  records=[];stats={};stack=[];first=None;previous=None\n  try:\n   for line in data.splitlines():\n    if not line.startswith(b'APPS574_PHASE '):continue\n    if len(line)>511 or len(records)>=96:raise ValueError('phase record bound')\n    v=json.loads(line[len(b'APPS574_PHASE '):]);base={'schema_version','seq','stage','event','monotonic_ns'}\n    if type(v)is not dict or set(v)not in (base,base|{'error_type','error_reason'}):raise ValueError('phase fields')\n    if type(v['schema_version'])is not int or v['schema_version']!=1 or type(v['seq'])is not int or v['seq']!=len(records)+1 or type(v['monotonic_ns'])is not int or not 0<=v['monotonic_ns']<2**63:raise ValueError('phase scalar')\n    stage=stages.index(v['stage']);event=events.index(v['event']);now=v['monotonic_ns']\n    if previous is not None and now<previous:raise ValueError('phase clock order')\n    if first is None:first=now\n    if stage==7 or event==3:\n     if (stage,event,v['seq'])!=(7,3,96):raise ValueError('phase limit marker')\n    else:\n     counts=stats.setdefault(stage,[0,0,0,0]);counts[event]+=1\n     if event==0:stack.append((stage,now))\n     else:\n      if not stack or stack[-1][0]!=stage:raise ValueError('phase nesting')\n      counts[3]+=now-stack.pop()[1]\n    records.append([v['seq'],stage,event,now-first]);previous=now\n   if not records:return None\n   return dict(version=1,records=len(records),first_ns=first,stages=[[s,*counts]for s,counts in sorted(stats.items())],last=records[-2:])\n  except (ValueError,TypeError,KeyError,IndexError):return dict(version=1,status='INVALID_PHASE_RECORDS')\n tail=err[-64:]\n value=dict(schema_version=1,event='prepare_copy_backend_failure',supervisor=record,result=result,stderr_tail=dict(bytes=len(tail),sha256=C.sha(tail),base64=base64.b64encode(tail).decode(),truncated=len(err)>64),supervisor_error=None if error is None else type(error).__name__,acceptance_authority=False,cleanup_authority=False)\n summary=phase_summary(err)\n if summary is not None:\n  candidate=dict(value,schema_version=2,phase_summary=summary)\n  if len(('APPS574_BACKEND_FAILURE '+json.dumps(candidate,sort_keys=True,separators=(',',':'),ensure_ascii=True)).encode())<=1900:value=candidate\n note='APPS574_BACKEND_FAILURE '+json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)\n C.need(len(note.encode())<=1900,'complete backend note must fit original2KiB tail');return note\n_vm_original_call=H.Calls.call\ndef _vm_backend_call(self,argv,*,seconds=610,expected=0):\n original=self.api;captured=[]\n def capture(*a,**kw):\n  row=original.run_command(*a,**kw);captured.append(row);return row\n self.api=types.SimpleNamespace(run_command=capture)\n try:return _vm_original_call(self,argv,seconds=seconds,expected=expected)\n except Exception as error:\n  if list(map(str,argv[:5]))==['/usr/bin/python3','-I','-B','/execution/scripts/apps/transaction.py','prepare-copy'] and len(captured)==1:\n   try:error.add_note(_vm_backend_note(*captured[0]))\n   except Exception:pass # Diagnostic loss cannot replace the original exception.\n  raise\n finally:self.api=original\nH.Calls.call=_vm_backend_call\n"

def lifecycle(raw):
 """Only container entry/command path routing differs; case bodies stay exact."""
 text=raw.decode();before=functions(raw)
 entry="sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C";need(text.count(entry)==1,'one original native contract import');text=text.replace(entry,"sys.path.insert(0,'/source/scripts/ci/apps-full574-repair-native');import contract as C")
 checks="Path(__file__).with_name('checks.py')";need(text.count(checks)==1,'one original inspection checker path');text=text.replace(checks,"SOURCE/'scripts/ci/apps-full574-repair-native/checks.py'")
 guard="Path('/.dockerenv').is_file()";replacement="(os.sysconf('SC_PAGE_SIZE')==16384 and 'caa_apps574_repair16k=1' in Path('/proc/cmdline').read_text().split())"
 need(text.count(guard)==1,'one native lifecycle environment anchor');text=text.replace(guard,replacement)
 old="str(SOURCE/'scripts/apps/repair_inspection.py')";need(text.count(old)==1,'one genuine readonly CLI path');text=text.replace(old,"'/execution/scripts/apps/repair_inspection.py'")
 anchor="if __name__=='__main__':main()";need(text.count(anchor)==1,'one native lifecycle entry dispatch')
 route="def _vm_backend(action,workspace,owner=None):\n return ['/usr/bin/python3','-I','-B','/execution/scripts/apps/transaction.py',action,*H.common(workspace,owner)]\nH.backend=_vm_backend\n"
 # The native source stays byte-exact. Route only its four readonly /seed
 # baseline/after observations through the existing authenticated full574 budget.
 for call in ("adapter.measure(Path('/seed'),T.limits())","adapter.capability_map(Path('/seed'),baseline,T.limits())","adapter.capability_map(Path('/seed'),after,T.limits(),caps)"):
  need(text.count(call)==(2 if call.startswith('adapter.measure') else 1),'exact native readonly source budget seams')
  text=text.replace(call,call.replace('T.limits()','T.limits(_vm_source_scope)'))
 route+="_vm_source_policy=INPUTS/'full574-policy.json';_vm_source_lease=INPUTS/'full574-lease.json'\n_vm_source_scope=types.SimpleNamespace(full574_policy=_vm_source_policy,full574_policy_sha256=C.sha(C.read(_vm_source_policy)),full574_lease=_vm_source_lease,full574_lease_sha256=C.sha(C.read(_vm_source_lease)))\n"
 route+=BACKEND_NOTE
 text=text.replace(anchor,route+anchor);out=text.encode();after=functions(out)
 need(set(after)==set(before)|{'_vm_backend','_vm_backend_note','_vm_backend_call'} and [n for n in before if before[n]!=after[n]]==['inspected','main'],'only exact lifecycle environment/readonly-path routing may differ');return out
