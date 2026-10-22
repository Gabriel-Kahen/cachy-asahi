# SPDX-License-Identifier: MIT
"""Whole accepted568 inverse plus finite additional Apps8 source/qualification gates."""
import base64,importlib.util,json,sys,tempfile
from pathlib import Path
import lifecycle_cost_successor as original
pin,enc,rows,need=original.pin,original.enc,original.rows,original.need

def verify(root,name,want):
 root=Path(root);raw=(root/name).read_bytes();need(pin(raw)==want and not sys.flags.optimize,'whole Apps8 composition successor proof');p=json.loads(raw);before=p['before'];actual=rows(root);changed=set(p['before_bodies']);added=set(p['added'])
 need(len(before)==568 and len(actual)==len(before)+len(added)and set(actual)==set(before)|added,'entire568 ancestor/current membership')
 need({n for n in before if actual[n]!=before[n]}==changed and all(actual[n]==w for n,w in p['helpers'].items()),'exact Apps8 changed/helper source closure')
 bodies={n:base64.b64decode(p['before_bodies'][n],validate=True)if n in changed else(root/n).read_bytes()for n in before}
 need(all(pin(bodies[n])==w for n,w in before.items()),'whole original568 source inverse')
 marker='\n# BEGIN_ADDITIONAL_APPS8_COMPOSITION\n'
 for n,edits in p['edits'].items():
  text=(root/n).read_text()
  if n==p['guard']:text=text.split(marker)[0]
  for old,new in reversed(edits):need(text.count(new)==1,'one exact Apps8 operand');text=text.replace(new,old,1)
  need(text.encode()==bodies[n],'every old source body outside exact Apps8 changes')
 marker='\n# BEGIN_ADDITIONAL_APPS8_COMPOSITION\n';parts=(root/p['guard']).read_text().split(marker);footer='def verify():\n import apps8_successor\n return apps8_successor.verify(ROOT, '+repr(name)+', '+repr(want)+')\n'
 prefix=bodies[p['guard']].decode()
 for old,new in p['edits'].get(p['guard'],[]):need(prefix.count(old)==1,'one recorded guard operand');prefix=prefix.replace(old,new,1)
 need(len(parts)==2 and parts[0]==prefix and parts[1]==footer,'mandatory whole prior guard and exact Apps8 appendix')
 mf=json.loads((root/p['manifest']).read_bytes());need(mf['files']=={n:w for n,w in actual.items()if n not in{p['manifest'],*p['workflows']}},'whole new source manifest')
 restored=dict(mf,files={n:w for n,w in mf['files'].items()if n not in added})
 for n in changed-{p['manifest'],*p['workflows']}:restored['files'][n]=before[n]
 need(enc(restored)==bodies[p['manifest']],'whole ancestor manifest inverse')
 import apps8_workflow as W
 for n in p['workflows']:
  old=bodies[n]
  for stamp in(p['manifest'],'latest/implementation/latest_run.py'):
   need(old.count(before[stamp]['sha256'].encode())==1,'one source/manifest workflow checksum stamp');old=old.replace(before[stamp]['sha256'].encode(),actual[stamp]['sha256'].encode(),1)
  need(W.derive(old.decode()).encode()==(root/n).read_bytes(),'actual registered/named workflow complete finite inverse')
 need((root/p['workflows'][0]).read_bytes()==(root/p['workflows'][1]).read_bytes(),'registered and named aliases exact')
 pub=p['publication'];need(pub==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source='12d7e769a8fe32a2714c10a9096f9805f8bb7920',ref='codex/current607-layered4200-v1',files=568,git_joins=568,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and p['source_authorization']==before and p['git_authorization']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=pub['source'],ref=pub['ref'],files=before),'genuine whole568 ancestor publication/Git')
 accepted=json.loads((root/p['parent_decision']).read_bytes());need(pin((root/p['parent_decision']).read_bytes())==p['parent_decision_pin']and accepted['status']=='ROOT_ACCEPTED_FINITE_NATIVE_LATEST_FIVE_TOOL_SOFTWARE_COMPOSITION'and accepted['source']==pub['source']and accepted['run_id']==39723442009 and accepted['software_scope']['transactions']==25 and accepted['software_scope']['fresh_graphs']==51 and accepted['software_scope']['fresh_auxiliary_observations']==26 and accepted['native_clocks_seconds']==dict(component=2400,consumer=4200,owner=6600),'whole qualified finite parent software scope only')
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='current607-whole-original568-')as tmp:
   old=Path(tmp)/'source';old.mkdir()
   for n,body in bodies.items():q=old/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(body)
   need(rows(old)==before,'entire568 before old full guard')
   for q in old.rglob('*.py'):sys.modules.pop(q.stem,None)
   sys.path.insert(0,str((old/p['guard']).parent));spec=importlib.util.spec_from_file_location('_whole568_apps8_parent',old/p['guard']);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);fact=module.verify()
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 need(fact['files']==568,'whole accepted568 source gate completed')
 return dict(fact,files=len(actual),apps8_changed=len(changed),apps8_held=len(before)-len(changed),apps8_added=len(added),profile='NATIVE607_ADDITIONAL_APPS8_SAME_FIVE_PRODUCTS',product_change='APPS7_TO_APPS8_ONLY_BASELINE_FINAL_APPS6_HELD',parent_source=pub['source'],parent_run=39723442009,Apps8_full606_qualification='SEPARATE_REQUIRED_INPUT_NO_COMBINED_CREDIT',actual=None,hardware='NOT_RUN',release='NOT_ADMITTED')
