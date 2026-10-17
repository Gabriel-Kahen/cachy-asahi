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
 text=text.replace(anchor,route+anchor);out=text.encode();after=functions(out)
 need(set(after)==set(before)|{'_vm_backend'} and [n for n in before if before[n]!=after[n]]==['inspected','main'],'only exact lifecycle environment/readonly-path routing may differ');return out
