#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit16K child; default4K constructor emits the unchanged parent360."""
import argparse,ast,json,os,re,sys,types
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import custody as Q
Q.verify()
sys.path.insert(0,str(ROOT/'parent360/implementation'))
import common as C,authority,runtime,source_guard
import selected

def without(args,*names):
 out=list(args)
 for name in names:
  if name in out:
   i=out.index(name);Q.need(out.count(name)==1 and i+1<len(out),'one explicit '+name);del out[i:i+2]
 return out

def authenticate(held,source,workflow,case):
 Q.verify();Q.verify_dependencies(held,'held')
 Q.need(case in C.CASES and source==workflow and re.fullmatch('[0-9a-f]{40}',source or''),'explicit current source/workflow/case')
 host=os.uname();Q.need(host.sysname=='Linux'and host.machine=='aarch64'and os.sysconf('SC_PAGE_SIZE')==4096 and os.getuid()==os.geteuid()>0 and not sys.flags.optimize,'ordinary native4K host owns a separate16K VM, not a projected16K host')
 e=os.environ;Q.need(e.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'and e.get('GITHUB_SHA')==source and e.get('GITHUB_EVENT_NAME')=='workflow_dispatch'and e.get('GITHUB_RUN_ATTEMPT')=='1'and re.fullmatch('[1-9][0-9]*',e.get('GITHUB_RUN_ID',''))and e.get('GITHUB_REF','').startswith('refs/heads/codex/'),'current first-attempt source-bound dispatch')
 Q.need(e.get('GITHUB_WORKFLOW')=='native-arm-latest607-updater-generic16k'and e.get('GITHUB_WORKFLOW_REF')=='Gabriel-Kahen/cachy-asahi/.github/workflows/native-arm-build.yml@'+e['GITHUB_REF'],'exact registered current16K option workflow')
 import subprocess
 git=lambda root,*args:subprocess.check_output(['git','-C',str(root),*args],timeout=15,text=True).strip()
 Q.need(git(ROOT,'rev-parse','HEAD')==source and git(held,'rev-parse','HEAD')==Q.profile()['dependencies']['held']['source'],'current child and held source revisions')
 Q.need(git(ROOT,'show',source+':.github/workflows/native-arm-build.yml').encode()+b'\n'==Q.read(ROOT/'.github/workflows/native-arm-build.yml'),'current workflow bytes')
 subprocess.run(['git','-C',str(ROOT),'diff','--exit-code','HEAD','--','.'],check=True,capture_output=True,timeout=15)
 current=dict(source=source,run=e['GITHUB_RUN_ID'],attempt=e['GITHUB_RUN_ATTEMPT'],ref=e['GITHUB_REF'],page_profile='generic16k')
 return dict(status='HOST4K_CURRENT607_GENERIC16K_VM_CUSTODY_NOT_ACCEPTANCE',source=source,ref=e['GITHUB_REF'],run=int(e['GITHUB_RUN_ID']),attempt=1,case=case,page_size=4096,expected_guest_page_size=16384,architecture='aarch64',current607=current,held_library_source=Q.profile()['dependencies']['held']['source'],hardware='NOT_RUN')

def parent(held):
 Q.verify();Q.verify_dependencies(held,'held');base=C.load('_current607_parent_entry',C.HERE/'entry.py');proxy=base.context(held);proxy.HERE=ROOT;proxy.authenticate=authenticate
 module=C.load('_current607_complete_parent_owner',C.ROOT/'parent4k/entry.py',{'case':proxy,'runtime':runtime})
 raw=Q.read(C.ROOT/'parent4k/entry.py')
 for name,edits in (
  ('parent',[("scope='NATIVE_ARM4K_NOT_16K_NOT_HARDWARE'","scope='HOST4K_GENERIC16K_VM_NOT_HARDWARE'")]),
  ('worker',[("rc=runtime.execute(a.implementation,forwarded)","rc=selected.execute(a.implementation,forwarded,proof['current607'],Q.verify_dependencies)"),("status='NATIVE4K_WRAPPER_RETURNED_NOT_ACCEPTANCE'","status='HOST4K_GENERIC16K_VM_WRAPPER_RETURNED_NOT_ACCEPTANCE'")])):
  node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name==name);body=ast.get_source_segment(raw.decode(),node).encode();out,_=selected.derive(body,edits)
  module.__dict__.update(selected=selected,Q=Q);exec(compile(out,'<whole-parent-'+name+'>','exec'),vars(module))
 return module,proxy

def main(argv=None):
 args=list(sys.argv[1:]if argv is None else argv)
 if args==['--source-preflight']:
  print(json.dumps(Q.verify(),sort_keys=True));return 0
 p=argparse.ArgumentParser(add_help=False);p.add_argument('mode',choices=('preflight','decisions','inputs','run','worker'));p.add_argument('--page-profile',choices=('generic16k',),required=True);p.add_argument('--implementation',type=Path,required=True);p.add_argument('--source',required=True);p.add_argument('--workflow-sha',required=True);p.add_argument('--case',choices=C.CASES,required=True);p.add_argument('--output',type=Path);p.add_argument('--updater-decisions',type=Path);p.add_argument('--kernel-input',type=Path);p.add_argument('--fresh16k-source',type=Path)
 a,_=p.parse_known_args(args);a.implementation=Q.safe(a.implementation);a.output=Q.safe(a.output)if a.output else None;proof=authenticate(a.implementation,a.source,a.workflow_sha,a.case)
 module,proxy=parent(a.implementation)
 if a.mode in('run','worker'):
  Q.need(a.kernel_input is not None and a.fresh16k_source is not None,'explicit current16K kernel and complete accepted-source inputs')
  Q.verify_dependencies(a.fresh16k_source,'fresh16k');selected.kernel_data.verify(a.kernel_input,Q.profile()['kernel_descriptor'])
  Q.need(a.updater_decisions is not None,'all original updater prerequisites mandatory')
  contract,W,A=proxy.apis(a.implementation);old,policy,binding=W.authorize(a.implementation,proxy.HELD,proxy.HELD,a.case);contract.accepted(old,a.updater_decisions.absolute(),binding)
  forward=args[1:]if a.mode=='run'else without(args[1:],'--page-profile')
  return(module.parent if a.mode=='run'else module.worker)(forward,a,proof)
 stripped=without(args[1:],'--page-profile','--kernel-input','--fresh16k-source')
 if a.mode=='inputs':
  Q.need(a.kernel_input is not None and a.fresh16k_source is not None,'current16K input gates precede secrets')
  Q.verify_dependencies(a.fresh16k_source,'fresh16k');selected.kernel_data.verify(a.kernel_input,Q.profile()['kernel_descriptor'])
 base=C.load('_current607_full_parent_entry_gate',C.HERE/'entry.py');return base.wrapper(a.implementation).prerequisites(a.implementation,a.mode,stripped)

if __name__=='__main__':raise SystemExit(main())
