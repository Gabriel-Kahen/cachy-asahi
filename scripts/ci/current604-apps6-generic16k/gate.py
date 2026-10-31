#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""New native+fresh604 and unchanged fullGUI authority before secrets or actors."""
import os
import contract as C
import ci

def main(argv=None):
 p=ci.parser();p.add_argument('--workflow-sha',required=True);p.add_argument('--preflight',action='store_true');p.add_argument('--decisions-only',action='store_true')
 for a in p._actions:
  if a.dest not in ('implementation','implementation_revision','workflow_sha','profile','help'):a.required=False
 args=p.parse_args(argv);v=C.policy()
 C.need(args.implementation_revision==args.workflow_sha==C.revision(args.implementation),'source/workflow revision must agree');C.check_source(args.implementation)
 C.need(C.sha(C.read(args.implementation/'scripts/ci/expanded604-apps6-installer/source-manifest.json'))==v['fresh604']['source_manifest_sha256'],'same accepted fresh source closure required')
 base=C.load(args.implementation,'scripts/ci/expanded604-apps6-installer/contract.py');bound=base.policy();composition=base.COMPOSITION.policy()
 C.need(v['native604']['carrier_source']==bound['native604']['carrier_source'] and v['native604']['decision']==bound['native604']['decision'],'same exact new native604 authority in both policies')
 if args.preflight:
  outputs=dict(eight_source=composition['eight_pair_source'],management_source=composition['management']['packet_source'],setup_source=composition['setup']['source'],welcome_source=composition['welcome']['carrier_source'],apps6_source=composition['apps6']['carrier_source'],apps6_native_source=composition['apps6']['native_source'],fresh600_decisions=bound['fresh600']['carrier_source'],native604_decisions=bound['native604']['carrier_source'],fresh604_decisions=v['fresh604']['carrier_source'],gui_decisions=v['welcome4_gui']['carrier_source'])
  if os.environ.get('GITHUB_OUTPUT'):
   with open(os.environ['GITHUB_OUTPUT'],'a') as stream:
    for k,value in outputs.items():stream.write(k+'='+value+'\n')
 elif args.decisions_only:
  C.need(all(getattr(args,n) is not None for n in ci.DECISIONS),'all original/new actual Root decisions required')
  accepted=C.decisions(args.native604_decisions,args.fresh604_decisions,args.gui_decisions,v);C.assets(args.gui_decisions,v['welcome4_gui'])
  original=base.decisions(args.fresh600_decisions,args.native604_decisions,bound);C.need(original['native604']==accepted['native604'],'same native604 decision at both gates')
 else:
  for name in (*ci.CARRIERS,*ci.DECISIONS,'audio_inputs'):C.need(getattr(args,name) is not None,'all exact public carriers required')
  ci.preflight(args)
 print('APPS6_PROFILE_SOURCE_AND_DECISIONS_PASS ACTORS_NOT_RUN');return 0
if __name__=='__main__':raise SystemExit(main())
