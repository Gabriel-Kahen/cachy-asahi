#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Same owned producer/VM/cleanup orchestration, one mandatory selected profile."""
import sys
import contract as C
import adapter
context604=C.module('_profile604_held_context',C.NEW+'/context604.py')

def derive(text):
 text=C.one(text,"p.add_argument('--implementation-revision',required=True);return p","p.add_argument('--implementation-revision',required=True);p.add_argument('--profile',choices=C.PROFILES,required=True);return p")
 text=C.one(text,'adapter.prepare(args.implementation,runner,assets,ready604)','adapter.prepare(args.implementation,runner,assets,ready604,args.profile)')
 text=C.one(text,"shutil.copyfile(C.HERE/'context604.py',runner/'context604.py')","shutil.copyfile(args.implementation/C.OLD/'context604.py',runner/'context604.py')")
 text=C.one(text,"report=dict(status='FAIL',scope=C.SCOPE","report=dict(status='FAIL',profile=args.profile,scope=C.SCOPE")
 text=C.one(text,"dict(purpose=C.SCOPE,output=str(output)","dict(purpose=C.SCOPE,profile=args.profile,output=str(output)")
 text=C.one(text,"dict(status='DERIVED_SOURCE_ONLY',files=source_rows,native='NOT_RUN',hardware='NOT_RUN')","dict(status='DERIVED_SOURCE_ONLY',profile=args.profile,scope='ONE_PROFILE_NOT_FULL60416K_ACCEPTANCE',files=source_rows,native='NOT_RUN',hardware='NOT_RUN')")
 text=C.one(text,"raw['status']==C.PASS and raw['runtime_package_count']==604","raw['status']==C.PASS and raw.get('profile')==args.profile and raw['runtime_package_count']==604")
 text=C.one(text,"CARRIERS=('legacy_source','eight_source','seven_source','management_source','setup_source','welcome_source')","CARRIERS=('legacy_source','eight_source','seven_source','management_source','setup_source','welcome_source','apps6_source','apps6_native_source')")
 text=C.one(text,"DECISIONS=('fresh600_decisions','native604_decisions','gui_decisions')","DECISIONS=('fresh600_decisions','native604_decisions','fresh604_decisions','gui_decisions')")
 text=C.one(text,'C.decisions(args.native604_decisions,args.gui_decisions,value)','C.decisions(args.native604_decisions,args.fresh604_decisions,args.gui_decisions,value)')
 text=C.one(text,'accepted=C.decisions(args.native604_decisions,args.fresh604_decisions,args.gui_decisions,value)',"accepted=C.decisions(args.native604_decisions,args.fresh604_decisions,args.gui_decisions,value)\n    C.need(C.sha(C.read(args.implementation/'scripts/ci/expanded604-apps6-installer/source-manifest.json'))==value['fresh604']['source_manifest_sha256'],'same accepted fresh source closure required')")
 text=C.one(text,'scripts/ci/expanded604-current-management-installer/contract.py','scripts/ci/expanded604-apps6-installer/contract.py')
 text=C.one(text,'scripts/ci/expanded604-current-management/materializer.py','scripts/ci/expanded604-apps6/materializer.py')
 text=C.one(text,'args.welcome_source,args.implementation)','args.welcome_source,args.implementation,args.apps6_source,args.apps6_native_source)')
 text=C.one(text,"args.implementation/C.OLD/'context604.py'","args.implementation/C.NEW/'context604.py'")
 return text.replace('expanded604-current-management-managed16k-runner','current604-apps6-generic16k-runner').replace('expanded604-current-management-managed16k-runtime','current604-apps6-generic16k-runtime')
_BASE=C.module('_profile604_owned_ci',C.OLD+'/ci.py',{'contract':C,'adapter':adapter,'context604':context604},derive)
parser,retired,preflight,main=_BASE.parser,_BASE.retired,_BASE.preflight,_BASE.main
PRODUCER_PATHS,CARRIERS,DECISIONS=_BASE.PRODUCER_PATHS,_BASE.CARRIERS,_BASE.DECISIONS
if __name__=='__main__':raise SystemExit(main())
