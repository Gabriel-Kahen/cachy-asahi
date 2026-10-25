# SPDX-License-Identifier: MIT
"""Future Root fresh/baseline authority is independent of historical Six inputs."""
import json,re
from pathlib import Path
import common as C
STATUSES=dict(fresh607='ROOT_ACCEPTED_SIGNED_LATEST607_FRESH_INSTALLER',baseline607='ROOT_ACCEPTED_SIGNED_LATEST607_APPS6_BASELINE')
def require_bound(policy=None):
 p=C.profile()if policy is None else policy
 C.need(type(p['authorities'])is dict and set(p['authorities'])==set(STATUSES),'closed two independent latest607 authority roles')
 C.need(all(type(p['authorities'][k])is dict for k in STATUSES),'fresh607 and Apps6-baseline607 remain UNBOUND; Six coexistence is not fresh/baseline acceptance')
 C.need(re.fullmatch('[0-9a-f]{40}',p.get('fresh_source')or'')and re.fullmatch('codex/[a-z0-9-]+',p.get('fresh_ref')or''),'genuine immutable latest607 installer publication remains UNBOUND')
 C.need(type(p.get('authority_files'))is dict and p['authority_files'] and re.fullmatch('[0-9a-f]{40}',p.get('input_sources',{}).get('latest_decisions')or''),'complete immutable decision carrier remains UNBOUND')
 return p

def decision(root,kind,ref,policy):
 C.need(kind in STATUSES and type(ref)is dict and set(ref)=={'path','bytes','sha256','source','run'},'closed Root decision reference');path=ref['path'];C.need(type(path)is str and not path.startswith('/')and all(x not in('','.','..')for x in path.split('/')),'ordinary immutable Root decision path');row=json.loads(C.checked(Path(root)/path,{k:ref[k]for k in('bytes','sha256')}));lock=policy['after']if kind=='fresh607'else policy['before']
 C.need(row.get('status')==STATUSES[kind]and row.get('source_sha')==ref['source']and type(row.get('run_id'))is int and row['run_id']==ref['run']and row['run_id']>0 and row.get('package_count')==607 and type(row['package_count'])is int and row.get('expected607_sha256')==lock['sha256'],'exact issued actual607 decision and full inventory')
 C.need(all(row.get(k)=='PASS'for k in('ordinary_parent_retired','independent_root_readback','cleanup'))and row.get('hardware')=='NOT_RUN'and row.get('release')=='NOT_ADMITTED','independent genuine full installer readback/retirement/cleanup required')
 C.need(row.get('target_kind')==kind and row.get('Apps_version')==('0.1.0-16'if kind=='fresh607'else'0.1.0-6')and row.get('other606_lock_sha256')==C.pin(''.join(n+' '+v+'\n'for n,v in sorted(C.locks()[0].items())if n!='cachy-asahi-apps').encode())['sha256'],'exact Apps target and all other606 packages held')
 if kind=='fresh607':C.need(row['source_sha']==policy['fresh_source'],'fresh607 decision must bind current exact installer publication')
 return row

def gates(root):
 p=require_bound();C.need(C.rows(root)==p['authority_files'],'whole current Root decision carrier');C.need(__import__('subprocess').check_output(['git','-C',str(C.safe(root)),'rev-parse','HEAD'],timeout=15,text=True).strip()==p['input_sources']['latest_decisions'],'immutable actual current Root decision publication');rows={k:decision(root,k,p['authorities'][k],p)for k in STATUSES};C.need(len({r['run_id']for r in rows.values()})==2,'separate genuine fresh607 and baseline607 actual runs required');return rows
