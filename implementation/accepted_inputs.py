# SPDX-License-Identifier: MIT
"""Only the exact issued Six853 decision supplies historical input authority."""
import json
from pathlib import Path
import latest_common as C
from closed_data import names

def record(root):
 root=C.safe(root);p=C.profile();rows=p['record_files'];C.need(len(rows)==22 and names(root,admin=True)==set(rows),'entire exact22 retained namespace')
 for n,w in rows.items():C.checked(root/n,w)
 index=json.loads(C.read(root/'index.json'));C.need(index['files']=={n:w for n,w in rows.items()if n!='index.json'},'complete pinned Root record index');decision=json.loads(C.checked(root/'qualification/Root-acceptance.json',p['Root_decision']));post=json.loads(C.checked(root/'qualification/Root-post-positive-pins-20261025.json',p['post']));positive=json.loads(C.checked(root/'qualification/Root-vmtest3600-positive.json',p['positive']))
 C.need((decision['source'],decision['ref'],decision['run_id'])==(p['native_source'],p['native_ref'],p['native_run'])and decision['status']=='ROOT_ACCEPTED_FINITE_NATIVE_APPS16_SIX_TOOL_SOFTWARE_COMPOSITION','exact issued Root decision, never parser success')
 C.need(decision['positive']==post['positive']==p['positive']and decision['postjoins']==p['post']and post['source']==p['native_source']and post['run']==p['native_run'],'entire decision/result/post joins')
 C.need(index['native_source']==p['native_source']and index['native_run']==p['native_run']and positive['root_acceptance']=='NOT_ISSUED'and positive['status']=='VERIFIED_FINITE_NATIVE_LATEST_SIX_SOFTWARE_COMPOSITION_PENDING_ROOT','raw pendingRoot fields preserved, separate issued decision required')
 C.need((decision['transactions'],decision['fresh_graphs'],decision['auxiliaries'],decision['whole240_suites'])==(32,65,33,4)and decision['hardware']=='NOT_RUN'and decision['release']=='NOT_ADMITTED','finite historical software input scope only')
 return decision,post

def public(record_root,root):
 decision,post=record(record_root);root=C.safe(root);rows=post['public'];C.need(len(rows)==991 and sum(w['bytes']for w in rows.values())==48072892 and names(root)==set(rows),'whole original public991 DATA namespace')
 for n,w in rows.items():C.checked(root/n,w)
 p=C.profile()
 for n,key in(('plan/target604-manifest.json','original604_manifest'),('tools606/latest/input-plan.json','input_plan'),('tools606/products.json','dns_sysctl')):C.checked(root/n,p[key])
 for row in p['incoming'].values():C.checked(root/row['path'],{k:row[k]for k in('bytes','sha256')});C.checked(root/row['signature']['path'],{k:row['signature'][k]for k in('bytes','sha256')})
 return decision,post
