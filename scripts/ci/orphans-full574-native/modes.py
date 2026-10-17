# SPDX-License-Identifier: MIT
"""Finite independent Orphans trials over pinned original Apps owner functions."""
import ast
from pathlib import Path
TRIALS=('normal','interruption')
STATUS={n:'PASS_NATIVE574_SELECTED_ORPHAN_'+n.upper()+'_ONLY_AND_TEARDOWN' for n in TRIALS}

def replace(text,old,new):
 if text.count(old)!=1:raise ValueError('pinned owner source seam changed: '+old[:80])
 return text.replace(old,new)

def function(raw,name):
 tree=ast.parse(raw);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name]
 if len(nodes)!=1:raise ValueError('one original owner function required')
 return ast.get_source_segment(raw,nodes[0])+'\n'

def derived(raw,trial):
 if trial not in TRIALS:raise ValueError('explicit normal or interruption trial required')
 run=function(raw,'run');retain=function(raw,'retain');actor=function(raw,'actor')
 materialize=replace(function(raw,'materialize'),' return packet\n'," return HELD.publish(C,args.source,output/'inputs',packet,payload,origins)\n")
 bind=replace(function(raw,'bind'),'module=C.adapter(root)',"module=C.adapter(root,output/'inputs')")
 normal="   actor(args.source,args.output,report,command,api,'lifecycle','lifecycle.py');life=C.result(C.decode(C.read(args.output/'lifecycle-public/lifecycle.json',4*1024**2)))\n"
 interrupted="   actor(args.source,args.output,report,command,api,'interruption','lifecycle.py',('--interrupt',));interruption=C.decode(C.read(args.output/'interruption-public/interruption.json'))\n   C.need(interruption['status']=='FAIL_INTERRUPTED_OWNED_COPY_RETAINED' and interruption['worker_group_absent'] is True and interruption['packages_committed']=='UNKNOWN' and interruption['rollback']=='NOT_CLAIMED','genuine interrupted uncertainty retained')\n"
 run=replace(run,interrupted if trial=='normal' else normal,'')
 run=replace(run,"lifecycle=life,interruption=interruption",'trial=TRIAL,'+('lifecycle=life' if trial=='normal' else 'interruption=interruption'))
 run=replace(run,"report=dict(status='FAIL',token=", "report=dict(status='FAIL',trial=TRIAL,token=")
 # Only the new explicitly selected interruption trial receives the full-copy
 # 3000s actor envelope. Legacy/shared actor bodies remain on disk unchanged.
 if trial=='interruption':
  actor=replace(actor,"3000 if role=='lifecycle' else 900 if role in ('extract','interruption','source-verify') else 240", "3000 if role in ('lifecycle','interruption') else 900 if role in ('extract','source-verify') else 240")
 life="life=C.result(C.decode(C.read(args.output/'lifecycle-public/lifecycle.json',4*1024**2)))"
 interruption="interruption=C.decode(C.read(args.output/'interruption-public/interruption.json'))"
 retain=replace(retain,';'+(interruption if trial=='normal' else life),'')
 retain=replace(retain,"('native-index.json','control.json','full574-policy.json','full574-lease.json','scrub.json')","('native-index.json','control.json','full574-policy.json','full574-lease.json','scrub.json','held-payloads.json')")
 retain=replace(retain,"result=dict(status='FAIL_OR_INCOMPLETE',files={}","result=dict(status='FAIL_OR_INCOMPLETE',trial=TRIAL,files={}")
 first="  C.need(interruption['status']=='FAIL_INTERRUPTED_OWNED_COPY_RETAINED'"
 last="  snap=C.decode(C.read(args.output/'snapshot-public/snapshot.json'))"
 start=retain.index(first);end=retain.index(last,start)
 if trial=='normal':retain=retain[:start]+retain[end:]
 else:
  retain=replace(retain," and owner['lifecycle']==life",'')
  retain=retain.replace("life['source_capabilities_sha256']","C.decode(C.read(args.output/'inputs/full574-policy.json'))['source_capabilities_sha256']")
  retain=retain.replace("life['source_tree_sha256']","C.decode(C.read(args.output/'inputs/full574-policy.json'))['source_tree_sha256']")
 roles=['export','extract','signer','lifecycle' if trial=='normal' else 'interruption','source-verify','scrub','source-cleanup']
 check=("  C.need(owner['lifecycle']==life,'exact normal component owner join required')\n" if trial=='normal' else '')+"  C.need(proof_value.get('trial')==owner.get('trial')==ordered.get('trial')==TRIAL and [r['role'] for r in owner['actors']]=="+repr(roles)+" and all(r.get('exit')==0 for r in owner['actors'] if r['role']!='export'),'exact independent trial roles and natural exits required')\n"
 retain=replace(retain,"  C.need(not result['errors'],'closed evidence incomplete');result['status']=C.STATUS",check+"  C.need(not result['errors'],'closed evidence incomplete');result['status']=C.STATUS")
 tree=ast.parse(run+'\n'+retain)
 absent='interruption' if trial=='normal' else 'life'
 if any(isinstance(n,ast.Name) and n.id==absent for n in ast.walk(tree)):raise ValueError('inactive trial result remains')
 return dict(run=run,retain=retain,actor=actor,materialize=materialize,bind=bind)

def execute(H,trial,args):
 C=H.C;C.need(trial in TRIALS,'explicit independent trial required');C.source(args.source)
 if args.mode in ('run','cleanup','retain'):
  C.need(C.decode(C.read(args.proof)).get('trial')==trial,'trial differs from original source proof')
 raw=C.read(Path(H.__file__),1024**2).decode();parts=derived(raw,trial)
 H.__dict__['TRIAL']=trial;H.__dict__['HELD']=C.load('held_owner_payloads',C.HERE/'held_payloads.py');C.STATUS=STATUS[trial]
 for text in parts.values():exec(compile(text,H.__file__+':'+trial,'exec'),H.__dict__)
 value=getattr(H,args.mode)(args)
 if args.mode=='proof':
  value['trial']=trial;C.save(args.proof,value)
  with open(H.os.environ['GITHUB_OUTPUT'],'a') as f:f.write('trial='+trial+'\n')
 elif args.mode=='cleanup':
  value['trial']=trial;C.save(args.receipt,value)
 return value

def workflow(text):
 text=replace(text,'  group: native-arm-orphans-full574-cleanup\n','  group: native-arm-orphans-full574-cleanup-${{ inputs.trial }}\n')
 text=replace(text,'      manifest_sha256:\n',"      trial:\n        description: One independent selected-orphan trial; separate runs required\n        type: choice\n        required: true\n        options: [normal, interruption]\n      manifest_sha256:\n")
 text=replace(text,'      SLICE: scripts/ci/orphans-full574-native\n','      SLICE: scripts/ci/orphans-full574-native\n      TRIAL: ${{ inputs.trial }}\n')
 for mode in ('proof','check','run','cleanup','retain'):
  text=replace(text,'"$SLICE/job.py" '+mode+' --source','"$SLICE/job.py" '+mode+' --trial "$TRIAL" --source')
 text=replace(text,"-p test_lane.py -v","-p 'test*.py' -v")
 text=replace(text,'orphans-full574-cleanup-${{ github.run_id }}','orphans-full574-cleanup-${{ inputs.trial }}-${{ github.run_id }}')
 return text
