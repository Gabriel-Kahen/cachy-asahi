# SPDX-License-Identifier: MIT
"""Source-pinned readonly lifecycle frontier; no cancellation or cleanup authority."""
import ast,fcntl,hashlib,json,os,resource,stat,subprocess
from pathlib import Path
HELPER='scripts/ci/orphans-native-cancellation/cancel.py'
FUNCTIONS=('need','decode','encoded','pin','read','file_id','held_lease','inspect_actor','phase')
def helpers(root):
 raw=(Path(root)/HELPER).read_bytes();tree=ast.parse(raw);ns=dict(Path=Path,fcntl=fcntl,hashlib=hashlib,json=json,os=os,resource=resource,stat=stat,subprocess=subprocess,CAP=1024**2)
 for name in FUNCTIONS:
  nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name]
  if len(nodes)!=1:raise ValueError('one fixed readonly helper: '+name)
  exec(compile(ast.Module(body=nodes,type_ignores=[]),'source-pinned-cancel-observer','exec'),ns)
 return ns

def actor_security(C,value,args,identity):
 expected=dict(Privileged=False,ReadonlyRootfs=True,NetworkMode='none',CapDrop=['ALL'],CapAdd=['CAP_CHOWN','CAP_DAC_OVERRIDE','CAP_FOWNER','CAP_FSETID','CAP_SETFCAP'],SecurityOpt=['no-new-privileges'],Memory=4*1024**3,NanoCpus=2000000000,PidsLimit=128,Ulimits=[dict(Name='nofile',Hard=8192,Soft=8192)])
 C.need({k:value['HostConfig'][k] for k in expected}==expected and value['AppArmorProfile']=='docker-default','exact original lifecycle confinement/budgets')
 config=value['Config'];C.need(config['User']=='0:0' and config['Entrypoint']==['/usr/bin/python3'] and config['Cmd']==['-I','-B','/source/scripts/ci/apps-full574-repair-native/lifecycle.py'] and config['Env'].count('OWNER_TOKEN='+identity['consumer_token'])==1 and config['Env'].count('CACHY_APPS574_REPAIR_CASE='+args.case)==1,'exact original lifecycle command/token/case')
 expected_mounts={'/source':(str(args.source),False),'/inputs':(str(args.output/'inputs'),False),'/seed':(str(args.output/'data/original574'),False),'/work':(str(args.output/'work'),True),'/out':(str(args.output/'lifecycle-public'),True)}
 mounts={r['Destination']:(r['Source'],r['RW']) for r in value['Mounts'] if r['Type']=='bind'};C.need(mounts==expected_mounts,'exact source/input/seed readonly and working/output mounts')
 return dict(security=expected,command={k:config[k] for k in ('User','Entrypoint','Cmd')},mounts=mounts)

def frontier(args,C,S,identity,H):
 # Source/identity/aliases remain fatal; a writer's transient partial JSON is not a frontier.
 if not args.handoff.exists() or not (args.output/'owner.json').exists():return None
 try:h=H['decode'](H['read'](args.handoff,16384));owner=H['decode'](H['read'](args.output/'owner.json',4*1024**2))
 except json.JSONDecodeError:return None
 except ValueError as error:
  if str(error)=='component read drift':return None
  raise
 C.need(h['identity']==identity and h['status']=='RUNNING_NOT_CLEANUP_AUTHORITY' and h['job'] is not None,'exact original running handoff')
 job=h['job'];C.need(S.process(job['pid'])==job and job['pid']==job['pgid']==job['sid'],'actual direct job identity')
 C.need(owner['source_sha']==identity['source_sha'] and owner['case']==identity['case'] and owner['token']==identity['consumer_token'] and owner['producer_token']==identity['producer_token'],'actual owner source/case/token')
 actors=owner['actors']
 if not actors or actors[-1]['role']!='lifecycle':return None
 H['phase'](actors);name='caa-apps574-'+identity['consumer_token']+'-lifecycle';C.need(actors[-1]['name']==name,'original lifecycle name')
 value=H['inspect_actor'](name,args.component/'inspect.pending')
 if value is None:return None
 api=C.load('self_cancel_original_owner',args.source/'scripts/ci/glibc-gnu-provider-lifecycle-owner/job.py');cid=api.verify_actor(value,name,owner['image'],C.LABEL,owner['token'],actors[-1]['id'])
 security=actor_security(C,value,args,identity);state=value['State'];C.need(state['Status']=='running' and state['Running'] is True and state['Pid']>0 and not any(state[k] for k in ('Paused','Restarting','OOMKilled','Dead')) and not state['StartedAt'].startswith('0001-') and value['RestartCount']==0,'actual running original lifecycle')
 leases=dict(producer=H['held_lease'](args.base,job['pid'],True),owner=H['held_lease'](args.output/'owner.lock',job['pid']))
 C.need(S.process(job['pid'])==job,'direct job drift before observed frontier')
 return dict(status='OBSERVED_OWNED_RUNNING_LIFECYCLE_AND_DIRECT_JOB_LEASES',identity=identity,job=job,actor=dict(id=cid,name=name,image=owner['image'],label=C.LABEL,token=owner['token'],state=state,apparmor=value['AppArmorProfile'],**security),leases=leases,original_handoff=H['pin'](H['read'](args.handoff,16384)),transaction_outcome='UNKNOWN',cleanup_authority=False,acceptance_authority=False)
