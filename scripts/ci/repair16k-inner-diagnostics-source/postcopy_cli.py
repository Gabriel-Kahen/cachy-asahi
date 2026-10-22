#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit fixed planned-CLI failure capture; no actors or changed clocks."""
import argparse,ast,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import correctness9000 as C
F=C.F;NAME='postcopy-cli210';GUEST=F.BRIDGE+'/guest.py'
PROFILE={'bytes': 82543, 'sha256': '8df0827a9c74f379b1f91531458108d9615d30d77f89e715832a68c1b0cb391a'}
INSERT='''  elif _vm_cli_role(argv,seconds,expected)is not None and len(captured)==1:
   try:
    role=_vm_cli_role(argv,seconds,expected);note=_vm_cli_note(role,*captured[0]);complete=_vm_cli_complete(role,*captured[0])
    if complete is not None:error.add_note(complete)
    error.add_note(note)
   except Exception:pass # Preserve the original CLI failure if capture cannot fit.
'''
PROMOTE=''' try:
  lines=[line for line in err.splitlines()if line.startswith(b'APPS574_CLI_FAILURE ')]
  if len(lines)==1 and len(lines[0])<=1900:
   capture=C.decode(lines[0][len(b'APPS574_CLI_FAILURE '):])
   candidate=dict(value,schema_version=3,cli_failure=capture)
   if len(C.encoded(candidate))<=12288:value=candidate
 except (ValueError,TypeError,KeyError,UnicodeError):pass
 # Planned CLI diagnostics use a separate finite role; no prepare-copy claim.
 try:
  lines=[line for line in err.splitlines()if line.startswith(b'APPS574_CLI_COMPLETE ')]
  if len(lines)==1 and len(lines[0])<=10240:
   capture=C.decode(lines[0][len(b'APPS574_CLI_COMPLETE '):])
   candidate=dict(value,schema_version=3,cli_complete=capture)
   if len(C.encoded(candidate))<=12288:value=candidate
 except (ValueError,TypeError,KeyError,UnicodeError):pass
'''
ALLOW_BEFORE="{'_vm_backend','_vm_backend_note','_vm_backend_call','_vm_capacity_wrap','_vm_backend_complete'}"
ALLOW_AFTER="{'_vm_backend','_vm_backend_note','_vm_backend_call','_vm_capacity_wrap','_vm_backend_complete','_vm_cli_role','_vm_cli_note','_vm_cli_complete'}"
def inputs():
 raw=F.read(HERE/'postcopy-cli-profile.json');F.need(F.pin(raw)==PROFILE,'whole postcopy CLI profile pin');p=json.loads(raw);F.need(p['profile']==NAME and len(p['before'])==len(p['after'])==210 and set(p['before'])==set(p['after'])and set(p['changed'])=={F.ADAPTER,GUEST,F.TEST,F.BM,F.MF,*F.WORKFLOWS},'finite seven-change exact210 profile')
 F.need(p['helper']=={n:F.pin(F.read(HERE/n))for n in('cost210.py','correctness9000.py')},'whole existing physical helper pins');F.need(p['before']==C.inputs()['after'],'complete existing correctness9000 output unchanged');bodies={}
 F.need(set(p['support'])=={'postcopy_cli_capture.py.in','postcopy_cli_tests.py.in'},'two used emitted support templates')
 for n,want in p['support'].items():bodies[n]=F.read(HERE/n);F.need(F.pin(bodies[n])==want,'whole source template pin: '+n)
 F.need(p['actual']is None and p['run_ids']==dict.fromkeys(('repair-bytes','repair-missing'))and p['clocks']=='UNCHANGED'and p['old4800_fit']=='FAILED'and p['old6000_fit']=='FAILED'and p['correctness9000_result']=='FAILED_POSTCOPY_CLI_CAUSE_UNEXPORTED'and p['performance']=='NOT_CLAIMED','no inherited fit/unknown cause or positive credit');return p,bodies

def derive(name,raw,bodies):
 text=raw.decode()
 if name==F.ADAPTER:
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='BACKEND_NOTE'for t in n.targets));old=ast.literal_eval(node.value);helper=bodies['postcopy_cli_capture.py.in'].decode();value=F.once(old,'_vm_original_call=H.Calls.call\n',helper+'_vm_original_call=H.Calls.call\n');value=F.once(value,'  raise\n finally:self.api=original',INSERT+'  raise\n finally:self.api=original');F.need(value.replace(helper,'',1).replace(INSERT,'',1)==old,'whole original backend note inverse');text=F.once(text,ast.get_source_segment(text,node),'BACKEND_NOTE = '+repr(value));text=F.once(text,ALLOW_BEFORE,ALLOW_AFTER)
 elif name==GUEST:
  text=F.once(text," raw=C.encoded(value);C.need(len(raw)<=12288,'bounded inner lifecycle diagnostic frame')",PROMOTE+" raw=C.encoded(value);C.need(len(raw)<=12288,'bounded inner lifecycle diagnostic frame')")
 else:
  F.need(name==F.TEST,'only adapter/guest/source-test bodies');text=F.once(text,"if __name__=='__main__':unittest.main()",bodies['postcopy_cli_tests.py.in'].decode()+"if __name__=='__main__':unittest.main()")
 compile(text,name,'exec');return text.encode()

def prepare(base,output,profile=None):
 F.need(profile==NAME,'explicit --profile postcopy-cli210 required; no diagnostic default');p,bodies=inputs();base=F.path(base);output=F.path(output);F.need(not output.exists()and output.parent.is_dir()and not output.is_relative_to(base)and not base.is_relative_to(output),'fresh separate source-only output');F.need(F.files(base)==p['before'],'whole exact published6402 source210 required');planned={n:F.read(base/F.relative(n))for n in p['before']};F.need({n:F.pin(v)for n,v in planned.items()}==p['before'],'all original210 physical bytes')
 for name in(F.ADAPTER,GUEST,F.TEST):planned[name]=derive(name,planned[name],bodies)
 bridge=json.loads(planned[F.BM])
 for name in(F.ADAPTER,GUEST,F.TEST):F.need(bridge['files'][name]==p['before'][name],'original bridge source stamp');bridge['files'][name]=F.pin(planned[name])
 planned[F.BM]=F.enc(bridge);manifest=json.loads(planned[F.MF])
 for name in(F.ADAPTER,GUEST,F.TEST,F.BM):F.need(manifest['files'][name]==p['before'][name],'original closed source stamp');manifest['files'][name]=F.pin(planned[name])
 planned[F.MF]=F.enc(manifest);before=p['before'][F.MF]['sha256'].encode();after=F.pin(planned[F.MF])['sha256'].encode()
 for name in F.WORKFLOWS:F.need(planned[name].count(before)==1,'one held workflow source stamp');planned[name]=planned[name].replace(before,after,1)
 F.need({n:F.pin(v)for n,v in planned.items()}==p['after'],'whole exact publishedc44 source210 emission');actual=json.loads(planned[F.BRIDGE+'/source-pins.json']);F.need(actual['actual_source']is actual['actual_ref']is None and all(v is None for v in actual['actual_runs'].values()),'all emitted actualsNULL');F.need(F.files(base)==p['before'],'full physical input reread before output')
 output.mkdir(mode=0o700)
 for name,raw in planned.items():
  target=output/F.relative(name);target.parent.mkdir(parents=True,exist_ok=True)
  with target.open('xb')as stream:stream.write(raw)
  target.chmod(0o644)
 F.need(F.files(output)==p['after']and F.files(base)==p['before'],'whole output and unchanged source-after equality');return dict(status='SOURCE_ONLY_EXACT210_POSTCOPY_CLI_FAILURE_CAPTURE',profile=NAME,files=p['after'],expected_fixture_source=p['source_after'],source=None,ref=None,run_ids=p['run_ids'],clocks='UNCHANGED',correctness9000_result=p['correctness9000_result'],actual_CLI_error='UNEXPORTED_UNKNOWN',native_fit='UNKNOWN',performance='NOT_CLAIMED',hardware='NOT_RUN',release='NOT_ADMITTED')
if __name__=='__main__':
 q=argparse.ArgumentParser(description=__doc__);q.add_argument('--profile',choices=(NAME,),required=True);q.add_argument('--base-root',type=Path,required=True);q.add_argument('--output',type=Path,required=True);q.add_argument('--authorization',type=Path,required=True);a=q.parse_args();authorization=F.path(a.authorization.absolute());output=a.output.absolute();F.need(not authorization.exists()and authorization.parent.is_dir()and not authorization.is_relative_to(output),'fresh separate authorization');value=prepare(a.base_root.absolute(),output,a.profile)
 with authorization.open('xb')as stream:stream.write(F.enc(value))
 print(json.dumps({k:value[k]for k in('status','profile','source','ref','run_ids')},sort_keys=True))
