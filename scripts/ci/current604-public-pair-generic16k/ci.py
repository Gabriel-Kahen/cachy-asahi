#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Same owned producer/VM/cleanup orchestration, one mandatory selected profile."""
import sys
import contract as C
import adapter
KP=C.module('_profile604_ci_keyboard',C.NEW+'/keyboard_profile.py')
context604=C.module('_profile604_held_context',C.NEW+'/context604.py')

def derive(text):
 text=C.one(text,'import context604\n','import context604\nimport KP\n')
 text=C.one(text,"profile,receipt,image,config=R.kernel(SimpleNamespace(kernel_work=args.kernel_work,kernel_receipt=args.kernel_receipt,source=args.implementation))","profile,receipt,image,config=KP.kernel(R,SimpleNamespace(kernel_work=args.kernel_work,kernel_receipt=args.kernel_receipt,source=args.implementation))")
 text=C.one(text,"p.add_argument('--implementation-revision',required=True);return p","p.add_argument('--implementation-revision',required=True);p.add_argument('--profile',choices=C.PROFILES,required=True);return p")
 text=C.one(text,'adapter.prepare(args.implementation,runner,assets,ready604)','adapter.prepare(args.implementation,runner,assets,ready604,args.profile)')
 text=C.one(text,"shutil.copyfile(C.HERE/'context604.py',runner/'context604.py')","shutil.copyfile(args.implementation/C.OLD/'context604.py',runner/'context604.py')")
 text=C.one(text,"report=dict(status='FAIL',scope=C.SCOPE","report=dict(status='FAIL',profile=args.profile,scope=C.SCOPE")
 text=C.one(text,"dict(purpose=C.SCOPE,output=str(output)","dict(purpose=C.SCOPE,profile=args.profile,output=str(output)")
 text=C.one(text,"dict(status='DERIVED_SOURCE_ONLY',files=source_rows,native='NOT_RUN',hardware='NOT_RUN')","dict(status='DERIVED_SOURCE_ONLY',profile=args.profile,scope='ONE_PROFILE_NOT_FULL60416K_ACCEPTANCE',files=source_rows,native='NOT_RUN',hardware='NOT_RUN')")
 text=C.one(text,"raw['status']==C.PASS and raw['runtime_package_count']==604","raw['status']==C.PASS and raw.get('profile')==args.profile and raw['runtime_package_count']==604")
 text=C.one(text,"CARRIERS=('legacy_source','eight_source','seven_source','management_source','setup_source','welcome_source')","CARRIERS=('legacy_source','eight_source','seven_source','management_source','setup_source','welcome_source','apps6_source','apps6_authority_source')")
 text=C.one(text,"DECISIONS=('fresh600_decisions','native604_decisions','gui_decisions')","DECISIONS=('fresh600_decisions','native604_decisions','fresh604_decisions','gui_decisions')")
 text=C.one(text,'C.decisions(args.native604_decisions,args.gui_decisions,value)','C.decisions(args.native604_decisions,args.fresh604_decisions,args.gui_decisions,value)')
 text=C.one(text,'accepted=C.decisions(args.native604_decisions,args.fresh604_decisions,args.gui_decisions,value)',"accepted=C.decisions(args.native604_decisions,args.fresh604_decisions,args.gui_decisions,value)\n    C.need(C.sha(C.read(args.implementation/'scripts/ci/expanded604-apps6-public-pair-installer/source-manifest.json'))==value['fresh604']['source_manifest_sha256'],'same accepted fresh source closure required')")
 text=C.one(text,'scripts/ci/expanded604-current-management-installer/contract.py','scripts/ci/expanded604-apps6-public-pair-installer/contract.py')
 text=C.one(text,'scripts/ci/expanded604-current-management/materializer.py','scripts/ci/expanded604-apps6-public-pairs/materializer.py')
 text=C.one(text,'args.welcome_source,args.implementation)','args.welcome_source,args.implementation,args.apps6_source,args.apps6_authority_source)')
 text=C.one(text,"args.implementation/C.OLD/'context604.py'","args.implementation/C.NEW/'context604.py'")
 text=C.one(text,"assets=C.assets(args.gui_decisions,value['welcome4_gui'])","C.authorize_assets(args,value);assets=None")
 text=C.one(text,"        original=SimpleNamespace(**{n:getattr(args,n) for n in PRODUCER_PATHS}","        assets=C.prepare_assets(args,value,output,report)\n        original=SimpleNamespace(**{n:getattr(args,n) for n in PRODUCER_PATHS}")
 text=C.one(text,"retain=C.load(args.implementation,C.PREFIX+'retain.py');retain.retain(output,producer_output,runtime,runner,args.kernel_work,args.implementation)","if started:\n                    retain=C.load(args.implementation,C.PREFIX+'retain.py');retain.retain(output,producer_output,runtime,runner,args.kernel_work,args.implementation)\n                else:report.update(runtime_status='NOT_STARTED',cleanup='PRODUCER_RETIRED_NO_RUNTIME_KERNEL_DISPOSAL_NOT_ESTABLISHED')")
 # Preserve the fixed bounded original offline build log even when retirement
 # is uncertain; diagnostic bytes grant no GUI/runtime or cleanup acceptance.
 text=C.one(text,"(runtime/'runtime.json','runtime/runtime.json',16*1024**2)","(runtime/'runtime.json','runtime/runtime.json',16*1024**2),(runtime/'runtime-image.log','runtime/runtime-image.log',16*1024**2)")
 text=C.one(text,"len(report.get('cleanup',[]))==14","len(report.get('cleanup',[]))==15 and context604.launcher_retired(report,C.ROOT)")
 text=C.one(text,'all original14 consumer cleanup records required','all original14 plus owned QEMU image consumer cleanup records required')
 text=C.one(text,"(runtime/'runtime-image.log','runtime/runtime-image.log',16*1024**2)","(runtime/'runtime-image.log','runtime/runtime-image.log',16*1024**2),(runtime/'qemu-tooling-image.log','runtime/qemu-tooling-image.log',16*1024**2)")
 text=C.one(text,"ready=producer.prepare(original);ready604=output/'ready604'","ready=producer.prepare(original);ready604=output/'ready604'\n        context604.preserve_producer_image(producer_output,report)")
 text=C.one(text,"        C.need(retired(raw,controller),","        context604.require_producer_image_preserved(raw,report['producer_image_preservation'])\n        C.need(retired(raw,controller),")
 text=C.one(text,"try:report['producer_cleanup']=producer.cleanup(producer_output)","try:\n                report['producer_cleanup']=producer.cleanup(producer_output)\n                if 'producer_image_preservation' in report:\n                    report['producer_image_retirement']=context604.producer_image_retired(report.get('producer_image_preservation'),report['producer_cleanup'])")
 return text.replace('expanded604-current-management-managed16k-runner','current604-public-pair-generic16k-runner').replace('expanded604-current-management-managed16k-runtime','current604-public-pair-generic16k-runtime')
_BASE=C.module('_profile604_owned_ci',C.OLD+'/ci.py',{'contract':C,'adapter':adapter,'context604':context604,'KP':KP},derive)
parser,retired,preflight,main=_BASE.parser,_BASE.retired,_BASE.preflight,_BASE.main
PRODUCER_PATHS,CARRIERS,DECISIONS=_BASE.PRODUCER_PATHS,_BASE.CARRIERS,_BASE.DECISIONS
if __name__=='__main__':raise SystemExit(main())
