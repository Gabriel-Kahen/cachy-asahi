#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Whole-held606 owner with one counted source capture and ordered new actors."""
import argparse,copy,json,os,shutil,sys,time,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as O,selection as S,runtime as R,builds

CAPTURE_LINE=" checkpoint('baseline604',base);install('install606');install('same-version606');remove('remove604');install('reinstall606');remove('final604')"
CAPTURE_HOOK=" checkpoint('baseline604',base);install('install606');install('same-version606')\n import runpy\n bridge=runpy.run_path('/runner/bridge/scripts/ci/current606-welcome5-source-bridge/bridge.py',run_name='_closed606_capture')\n need(bridge['main'](['capture','--selection','/plan/bridge-selection.json','--code','/runner/bridge-code','--nonce',os.environ['CAA_CURRENT606_BRIDGE']])==0,'complete counted606 capture')\n remove('remove604');install('reinstall606');remove('final604')"

def one(raw,before,after):
 O.need(raw.count(before)==1,'one counted closed owner seam: '+before[:90]);return raw.replace(before,after)

def capture_program(raw):
 derived=one(raw,CAPTURE_LINE,CAPTURE_HOOK);O.need(one(derived,CAPTURE_HOOK,CAPTURE_LINE)==raw,'entire606 exercise byte-held outside capture insertion');compile(derived,'<counted606capture>','exec');return derived

def parse_mounts(argv):
 rows=[]
 for i,value in enumerate(argv):
  if value!='--mount':continue
  text=argv[i+1];parts=text.split(',');fields=dict(p.split('=',1)for p in parts if '='in p)
  O.need(set(fields)=={'type','src','dst'}and fields['type']=='bind'and set(parts)-{k+'='+v for k,v in fields.items()}<= {'readonly'},'finite actual bind arguments')
  rows.append(dict(source=fields['src'],target=fields['dst'],readonly='readonly'in parts))
 return rows

def source_context(root):
 P=O.module('_closed606_contract',root/'held606/scripts/ci/current606-native/contract.py')
 A=O.module('_closed606_adapter',root/'held606/scripts/ci/current606-native/adapter.py',{'contract':P})
 B=O.module('build_pairs',root/'held606/scripts/ci/current606-native/build_pairs.py',{'contract':P})
 X=O.module('_closed606_bridge',root/'held606/scripts/ci/current606-native/bridge606.py',{'contract':P,'adapter':A,'build_pairs':B})
 C=O.module('_closed604_contract',root/'held606/held604'/P.OLD/'contract.py')
 return P,A,X,C

def owner_program(raw):
 edits=[
 ("    policy,summary=verify(args)  # No output, secrets, Docker or producer module before all input gates.","    Y.authorize()\n    policy,summary=verify(args)  # No output, secrets, Docker or producer module before all input gates."),
 ("    signal.setitimer(signal.ITIMER_REAL,6600)","    Y.deadline=time.monotonic()+6600\n    signal.setitimer(signal.ITIMER_REAL,6600)"),
 ("'--env=CACHY_ASAHI_EXPANDED604='+owned.token]","'--env=CACHY_ASAHI_EXPANDED604='+owned.token,'--env=CAA_CURRENT606_BRIDGE='+Y.nonce]"),
 ("(tools606,'/tools606',True)","(tools606,'/tools606',True),(Y.measurement,'/measurement',False)"),
 ("        resultdir=out/'container';resultdir.mkdir()","        resultdir=out/'container';C.need(resultdir.is_dir()and not resultdir.is_symlink(),'exact precreated original output')"),
 ("        X.validate(life.get('tools606'))","        X.validate(life.get('tools606'))\n        Y.complete(active,report)"),
 ("C.need(len(owned.rows)==5,'four new distinct builders and one lifecycle consumer')","C.need(len(owned.rows)==8,'four builders, original606, finalizer, worker, disposer all retired')"),
 ("status='PASS_NATIVE606_DNS2_SYSCTL2_COMPOSITION'","status='PASS_CURRENT606_KSM2_COPY_PROTOCOL_REQUIRES_RETAINED_REPLAY'"),
 ("        try:require_verifier_absence(producerout)","        try:Y.failure(active,absence,report)\n        except BaseException as caught:\n            absence=False;error=error or caught;report['cleanup'].append(dict(resource='owned606-measurement',status='RETAINED_UNKNOWN',error=str(caught)[:512]))\n        try:require_verifier_absence(producerout)"),
 ]
 derived=raw
 for before,after in edits:derived=one(derived,before,after)
 restored=derived
 for before,after in reversed(edits):restored=one(restored,after,before)
 O.need(restored==raw,'all original606 owner bytes conserved outside nine insertions')
 O.need('active.process.wait(timeout=1800)'in derived and 'signal.setitimer(signal.ITIMER_REAL,6600)'in derived,'original consumer/owner budgets held')
 return derived

class Integration:
 def __init__(self,root,X,C,policy,packet):
  self.root,self.X,self.C,self.policy,self.packet=root,X,C,policy,packet;self.after=None;self.disposed=False;self.nonce=None;self.measurement=None;self.deadline=None
 def authorize(self):
  O.authorize(self.policy);builds.public_checkout(self.packet,self.policy);return self.policy
 def __getattr__(self,key):return getattr(self.X,key)
 def prepare(self,root,producer,out,owned,ready,C):
  tools,runner=self.X.prepare(root,producer,out,owned,ready,C)
  context=builds.ksm(root=self.root,packet=self.packet,ready604=out/'ready604',output=out/'ksm-inputs')
  O.need(len(owned.rows)==4,'four original606 independent builder actors')
  self.nonce=os.urandom(16).hex();self.measurement=out/'measurement';self.measurement.mkdir(mode=0o700)
  self.lease=R.measurement_lease(self.measurement)
  # This separate ordinary output never contains private source maps. Small
  # bridge receipts are bounded0644 so the owner can read after actor retirement.
  self.receipts=out/'bridge-output';self.receipts.mkdir(mode=0o700);self.output_lease=R.measurement_lease(self.receipts)
  self.phase_input=out/'bridge-input';self.phase_input.mkdir(mode=0o700)
  self.runner=out/'copy-runner';shutil.copytree(self.root/'copyworker',self.runner)
  shutil.copytree(context,self.runner/'inputs')
  shutil.copytree(self.root/'bridge',self.runner/'bridge');shutil.copytree(self.root/'bridge',self.runner/'bridge-code')
  (self.runner/'owner').mkdir();shutil.copyfile(O.HERE/'selection.py',self.runner/'owner/selection.py')
  # Same exact new bridge/code/API bytes are below the existing readonly runner
  # mount; no new code/input mount is added to the original six-capability actor.
  for n in('bridge','bridge-code','owner'):shutil.copytree(self.runner/n,runner/n)
  program=runner/'tools606.py';program.write_text(capture_program(program.read_text()))
  self.selected=copy.deepcopy(self.policy);self.selected.update(nonce=self.nonce,measurement=self.lease,output=self.output_lease)
  S.verify_actor(self.selected,'capture',self.nonce)
  (out/'plan/bridge-selection.json').write_bytes(S.encoded(self.selected))
  # The capture small receipt uses /out, so its lease is the original result
  # directory. Create it here rather than allowing the later mkdir to alias it.
  self.capture_output=out/'container';self.capture_output.mkdir(mode=0o700)
  self.selected['output']=R.measurement_lease(self.capture_output)
  (out/'plan/bridge-selection.json').write_bytes(S.encoded(self.selected))
  (tools/'closed-runner-derivation.json').write_bytes(S.encoded(dict(status='COUNTED_CAPTURE_ONLY_ALL_OTHER606_BYTES_HELD',source606=S.NATIVE,original_tools606=S.pin((root/'scripts/ci/current606-native/tools606.py').read_bytes()),capture_tools606=S.pin(program.read_bytes()),files={p.relative_to(runner).as_posix():S.pin(p.read_bytes())for p in sorted(runner.rglob('*'))if p.is_file()},capture_checkpoint='AFTER_SAME_VERSION606_FULL_27_28_AND_AUX',budgets=dict(original_consumer=1800,owner=6600,capture=600),native_acceptance='NOT_GRANTED')))
  for p in(self.runner,*self.runner.rglob('*'),runner,*runner.rglob('*')):
   O.need(not p.is_symlink(),'source-only runner aliases refused');p.chmod(0o755 if p.is_dir()else 0o644)
  self.after=R.AfterCapture(owned=owned,common=C.load('_closed606_logged',root/'held604/scripts/virtual/common.py'),env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',TZ='UTC',HOME=str(out/'home')),image=owned.image,nonce=self.nonce,output=out,owner_deadline=self.deadline)
  return tools,runner
 def phase_selection(self,role):
  selected=copy.deepcopy(self.selected);selected['output']=self.output_lease;selected['retirement']=self.after.retirement_context()
  if role=='finalizer':selected['capture_receipt']=O.read(self.capture_output/'bridge-capture.json',65536)
  S.verify_actor(selected,role,self.nonce)
  (self.phase_input/'selection.json').write_bytes(S.encoded(selected));return selected
 def bridge_paths(self):return dict(runner=self.runner,measurement=self.measurement,selection=self.phase_input,out=self.receipts)
 def dispose(self,report):
  self.phase_selection('dispose');self.after.run('dispose',self.bridge_paths());fact=self.after.verify_disposal(self.measurement,self.lease);self.measurement.rmdir();self.disposed=True;report['ksm606_disposal']=fact
 def complete(self,active,report):
  self.after.retire_original(active);self.phase_selection('finalizer');self.after.run('finalize',self.bridge_paths())
  handoff=O.read(self.receipts/'bridge-handoff.json',65536)
  selected=self.phase_selection('copy-worker8');(self.runner/'selection.json').write_bytes(S.encoded(selected));(self.runner/'handoff.json').write_bytes(S.encoded(handoff))
  self.after.run('worker',dict(runner=self.runner,seed=self.measurement/'source606',proof=self.measurement/'private/final',work=self.measurement/'work',out=self.receipts))
  result=O.read(self.receipts/'result.json',1024**2)
  O.need(result['status']=='COPY_PROTOCOL_COMPLETED_REQUIRES_OUTER_ORDERED_DISPOSAL'and result['nonce']==self.nonce and result['source_native']==S.NATIVE and result['source_run']==self.policy['current606']['run']and result['expected606_sha256']==S.LOCK and result['copy']['cleanup']=='PASS-owned-workspace-removed','complete copied-root lifecycle with source join and copy disposal required')
  O.need(result['counts']==[606,606,606,605,606,606]and [e['phase']for e in result['events']]==['baseline1','upgrade2','same-version2','remove2','reinstall2','restore-original1']and result['restoration']=='EXACT_ORIGINAL1_ARCHIVE_PAYLOAD_CURRENT_ALPM_DB'and result['hardware']=='NOT_RUN'and result['release']=='NOT_ADMITTED','all six Apps transitions and exact original6 restoration required')
  for e in result['events']:
   O.need(e['other605']=='FULL_PAYLOAD_RAW_DB_INODE_HARDLINK_CAPS_PROTECTED'and e['source606']=='UNCHANGED_SEPARATE_READBACK_REQUIRED','whole protected605 readback scope')
   if e['selected_version']is not None:
    v=e['fixtures'];O.need(v['zero_capabilities']is True and v['NNP']==1 and v['homes']=={k:dict(CLI=4 if e['selected_version']=='0.1.0-2'else 2,installed_controls=44 if e['selected_version']=='0.1.0-2'else 18,live_kernel_write='NOT_RUN')for k in('fresh','existing')},'actual Apps CLI and ordinary installed controls required')
  report['ksm606_copy']=result;self.dispose(report)
 def failure(self,active,absence,report):
  if self.measurement is None or self.disposed:return
  O.need(absence,'uncertain original actor absence retains source disk')
  try:untouched=R.measurement_lease(self.measurement)==self.lease
  except(ValueError,PermissionError):untouched=False
  if untouched:
   self.measurement.rmdir();return
  O.need(self.after is not None and active is not None,'unknown partial capture retained')
  if self.after.phase=='captured':self.after.retire_original(active)
  self.dispose(report)
 def prepare_export(self,out,report):
  # Preserve all old validation; a new-purpose success is translated ONLY for
  # the held source-only export validator, never an old native acceptance row.
  old=dict(report)
  if report.get('status')=='PASS_CURRENT606_KSM2_COPY_PROTOCOL_REQUIRES_RETAINED_REPLAY':old['status']='PASS_NATIVE606_DNS2_SYSCTL2_COMPOSITION'
  self.X.prepare_export(out,old);report['tools606_scope']=old['tools606_scope'];report['scope']='CURRENT606_KSM2_CLOSED_OWNED_SOURCE_AND_COPY_ONLY';report['native_acceptance']='NOT_GRANTED'
 def export_names(self,out):
  names=self.X.export_names(out)
  names+=['container/bridge-capture.json','plan/bridge-selection.json']  # Small source-bound DATA only; original64MiB cap remains.
  for prefix in('ksm-inputs','bridge-output'):
   p=out/prefix
   if p.exists():names.extend(f.relative_to(out).as_posix()for f in sorted(p.rglob('*'))if f.is_file()and not f.relative_to(out).as_posix().startswith('welcome-inputs/sources/'))
  return names

def main(argv=None):
 argv=list(sys.argv[1:]if argv is None else argv)
 if argv==['--source-preflight']:
  fact=O.verify();P,A,X,C=source_context(O.ROOT);P.verify(bound=False);owner_program(A.owner(P.ROOT));capture_program((P.HERE/'tools606.py').read_text());print(json.dumps(fact,sort_keys=True));return 0
 if argv==['--require-selection']:O.authorize(O.read(O.HERE/'input-policy.json'));return 0
 if len(argv)==3 and argv[:2]==['--native-inputs','--ksm-packet']:
  O.verify();policy=O.authorize(O.read(O.HERE/'input-policy.json'));builds.public_checkout(Path(argv[2]).absolute(),policy);return 0
 O.verify();policy=O.authorize(O.read(O.HERE/'input-policy.json'));P,A,X,C=source_context(O.ROOT);P.verify()
 O.need(argv.count('--ksm-packet')==1,'one actual public Apps packet checkout required');at=argv.index('--ksm-packet');O.need(at+1<len(argv),'Apps packet operand missing');packet=Path(argv[at+1]).absolute();argv=argv[:at]+argv[at+2:]
 Y=Integration(O.ROOT,X,C,policy,packet);raw=owner_program(A.owner(P.ROOT))
 m=types.ModuleType('_closed606_welcome_owner');m.__file__=str(P.ROOT/'held604'/P.OLD/'run.py');m.X=Y;m.Y=Y;m.time=time
 prior=sys.modules.get('contract');sys.modules['contract']=C
 try:exec(compile(raw,m.__file__,'exec'),m.__dict__);return m.main(argv)
 finally:
  if prior is None:sys.modules.pop('contract',None)
  else:sys.modules['contract']=prior
if __name__=='__main__':raise SystemExit(main())
