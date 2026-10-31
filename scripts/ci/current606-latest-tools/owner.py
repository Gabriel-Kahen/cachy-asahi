#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reuse the complete c06 producer/owner; source-bound two-tool worker only."""
import argparse,ast,json,shutil,sys,types
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import contract as C,selection as S,runtime as R
ROOT=C.ROOT;WORKER_SOURCE=ROOT/'worker';BRIDGE_SOURCE=ROOT/'bridge'
STATUS='PASS_CURRENT606_LATEST_TOOLS_COPY_PROTOCOL_REQUIRES_RETAINED_REPLAY'

def one(raw,before,after):C.need(raw.count(before)==1,'exact joint owner seam: '+before[:80]);return raw.replace(before,after)
def source_modules():
 home=ROOT/'historical/welcome/scripts/ci/current606-welcome5-closed-owner'
 oldS=C.load('_joint_old_selection',home/'selection.py');oldC=C.load('_joint_old_contract',home/'contract.py',{'selection':oldS})
 builds=C.load('_joint_welcome_builds',home/'builds.py',{'selection':S});owner=C.load('_joint_original_owner',home/'owner.py',{'selection':oldS,'contract':oldC,'runtime':R,'builds':builds});return oldS,oldC,builds,owner

def authorize(policy):
 # Both future accepted single-composition decisions are required BEFORE any
 # native checkout, producer import, secret use, output creation or actor.
 S._joint(policy);C.need(policy.get('status')=='ROOT_BOUND_CURRENT606_LATEST_TOOLS_INPUTS'and policy.get('purpose')==S.PURPOSE,'explicit new joint source selection')
 oldS,oldC,_,_=source_modules();translated=dict(policy,status='ROOT_BOUND_CURRENT606_WELCOME5_INPUTS',purpose=oldS.PURPOSE)
 prior=sys.modules.get('selection');sys.modules['selection']=oldS
 try:oldC.authorize(translated)
 finally:
  if prior is None:sys.modules.pop('selection',None)
  else:sys.modules['selection']=prior
 return policy

def apps_api():
 home=ROOT/'historical/apps/scripts/ci/current606-apps7-closed-owner';O=C.load('_joint_apps_owner_contract',home/'contract.py');return C.load('_joint_apps_builds',home/'builds.py',{'contract':O})

def joint_context(integration,context,out):
 b=apps_api();new=out/'apps-inputs';b.apps(root=ROOT/'historical/apps',packet=integration.apps_packet,ready604=out/'ready604',output=new)
 lane=WORKER_SOURCE/'scripts/ci/current606-latest-tools-copy';sys.path[:0]=[str(lane),str(WORKER_SOURCE/'held-copy/scripts/update'),str(WORKER_SOURCE/'held-copy/scripts/apps')]
 WC=C.load('_joint_context_contract',lane/'contract.py');apis={'contract':WC}
 for n in('roles','physical','guard','lifecycle','inputs'):apis[n]=C.load('_joint_context_'+n,lane/(n+'.py'),apis)
 return apis['inputs'].compose(apps_context=new,welcome_context=context,output=out/'latest-tools-inputs')

def integration_class():
 oldS,oldC,builds,owner=source_modules();raw=(oldC.HERE/'owner.py').read_text();tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='Integration');text=ast.get_source_segment(raw,node)
 edits=[("builds.lifecycle_plan(root=self.root,context=context,target=out/'ready604',ready=ready,C=C)","builds.lifecycle_plan(root=self.root,context=context,target=out/'ready604',ready=ready,C=C)\n  context=J.joint_context(self,context,out)"),("self.root/'copyworker'","J.WORKER_SOURCE"),("shutil.copytree(self.root/'bridge',self.runner/'bridge')","shutil.copytree(J.BRIDGE_SOURCE,self.runner/'bridge')"),("shutil.copytree(self.root/'bridge',self.runner/'bridge-code')","shutil.copytree(J.BRIDGE_SOURCE,self.runner/'bridge-code')"),("report['welcome606_disposal']","report['latest606_disposal']")]
 for before,after in edits:text=one(text,before,after)
 # O keeps the exact original helper APIs and historical root. Only the
 # owner/API file location changes to this new source namespace.
 adapter=types.SimpleNamespace(**vars(oldC));adapter.HERE=HERE
 namespace=dict(vars(owner));namespace.update(O=adapter,S=S,R=R,builds=builds,J=sys.modules[__name__]);exec(compile(text,'<whole c06 Integration with five counted joint seams>','exec'),namespace)
 base=namespace['Integration']
 class Joint(base):
  def authorize(self):return authorize(self.policy)
  def complete(self,active,report):
   self.after.retire_original(active);self.phase_selection('finalizer');self.after.run('finalize',self.bridge_paths())
   handoff=C.read(self.receipts/'bridge-handoff.json');selected=self.phase_selection('copy-worker8');(self.runner/'selection.json').write_bytes(S.encoded(selected));(self.runner/'handoff.json').write_bytes(S.encoded(handoff))
   self.after.run('worker',dict(runner=self.runner,seed=self.measurement/'source606',proof=self.measurement/'private/final',work=self.measurement/'work',out=self.receipts));result=C.read(self.receipts/'result.json')
   C.need(result.get('status')=='JOINT_LATEST_COPY_COMPLETED_REQUIRES_OUTER_DISPOSAL'and result['nonce']==self.nonce and result['source_native']==S.NATIVE and result['source_run']==self.policy['current606']['run']and result['expected606_sha256']==S.LOCK and result['copy']['cleanup']=='PASS-owned-workspace-removed','complete joint worker/source/copy disposal')
   phases=['baseline','apps7','joint-latest','same-apps7','same-welcome5','remove-apps7','reinstall-apps7','remove-welcome5','reinstall-welcome5','restore-original4','restore-original6']
   C.need(result['counts']==[606,606,606,606,606,605,606,605,606,606,606]and [e['phase']for e in result['events']]==phases and result['restoration']=='EXACT_SAME_PRODUCER_ORIGINAL4_AND_ORIGINAL6_PAYLOAD_CURRENT_DB'and result['Runtime1']=='PROTECTED_NO_TRANSACTION'and result['hardware']=='NOT_RUN'and result['release']=='NOT_ADMITTED','all exact joint transitions and original6/4 restoration')
   for e in result['events']:C.need(e['other604']=='FULL_PAYLOAD_RAW_DB_INODE_HARDLINK_CAPS_PROTECTED'and e['source606']=='UNCHANGED_SEPARATE_READBACK_REQUIRED','all protected604/source606 readbacks')
   joint=result['events'][2];C.need(joint['versions']=={'apps':'0.1.0-7','welcome':'0.1.0-5'}and joint['fixtures']['apps']['homes']=={h:dict(CLI=2,inventory_count=606,installed_controls=15)for h in('fresh','existing')}and joint['fixtures']['welcome']['homes']=={h:dict(CLI=5,report=12)for h in('fresh','existing')},'both actual latest-tool suites in both homes')
   report['latest606_copy']=result;self.dispose(report)
  def prepare_export(self,out,report):
   old=dict(report)
   if old.get('status')==STATUS:old['status']='PASS_NATIVE606_DNS2_SYSCTL2_COMPOSITION'
   self.X.prepare_export(out,old);report['tools606_scope']=old['tools606_scope'];report['scope']='CURRENT606_LATEST_TOOLS_CLOSED_COPY_ONLY';report['native_acceptance']='NOT_GRANTED'
  def export_names(self,out):
   names=self.X.export_names(out)+['container/bridge-capture.json','plan/bridge-selection.json']
   for prefix in('welcome-inputs','apps-inputs','latest-tools-inputs','bridge-output','welcome-builds'):
    root=out/prefix
    if root.exists():names.extend(p.relative_to(out).as_posix()for p in sorted(root.rglob('*'))if p.is_file()and not any(p.relative_to(out).as_posix().startswith(n)for n in('welcome-inputs/sources/','latest-tools-inputs/sources/')))
   return sorted(set(names))
 return Joint,owner

def main(argv=None):
 argv=list(sys.argv[1:]if argv is None else argv)
 if argv==['--source-preflight']:print(json.dumps(C.verify(),sort_keys=True));integration_class();return 0
 if argv==['--require-selection']:authorize(C.read(HERE/'input-policy.json'));return 0
 if len(argv)==3 and argv[:2]==['--native-inputs','--apps-packet']:
  C.verify();authorize(C.read(HERE/'input-policy.json'));b=apps_api();b.public_checkout(Path(argv[2]).absolute(),C.read(ROOT/'historical/apps/scripts/ci/current606-apps7-closed-owner/input-policy.json'));return 0
 C.verify();policy=authorize(C.read(HERE/'input-policy.json'))
 C.need(argv.count('--apps-packet')==1,'one exact public192 carrier checkout');at=argv.index('--apps-packet');packet=Path(argv[at+1]).absolute();argv=argv[:at]+argv[at+2:];b=apps_api();b.public_checkout(packet,C.read(ROOT/'historical/apps/scripts/ci/current606-apps7-closed-owner/input-policy.json'))
 Joint,owner=integration_class();P,A,X,oldC=owner.source_context(ROOT/'historical/welcome');P.verify();Y=Joint(ROOT/'historical/welcome',X,oldC,policy);Y.apps_packet=packet
 raw=owner.owner_program(A.owner(P.ROOT));raw=one(raw,"'PASS_CURRENT606_WELCOME5_COPY_PROTOCOL_REQUIRES_RETAINED_REPLAY'",repr(STATUS));m=types.ModuleType('_joint_closed606_owner');m.__file__=str(P.ROOT/'held604'/P.OLD/'run.py');m.X=m.Y=Y;m.time=__import__('time');prior=sys.modules.get('contract');sys.modules['contract']=oldC
 try:exec(compile(raw,m.__file__,'exec'),m.__dict__);return m.main(argv)
 finally:
  if prior is None:sys.modules.pop('contract',None)
  else:sys.modules['contract']=prior
if __name__=='__main__':raise SystemExit(main())
