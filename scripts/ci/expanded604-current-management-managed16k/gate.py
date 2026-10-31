#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Refuse UNBOUND decisions before native tools, credentials or actors are reached."""
import argparse
import os
from pathlib import Path
import contract as C
import ci

def main(argv=None):
    p=ci.parser();p.add_argument('--workflow-sha',required=True);p.add_argument('--preflight',action='store_true');p.add_argument('--decisions-only',action='store_true')
    # Preflight needs only the implementation/source identity; all actor arguments stay absent.
    for a in p._actions:
        if a.dest not in ('implementation','implementation_revision','workflow_sha','help'):a.required=False
    args=p.parse_args(argv);v=C.policy()
    C.need(args.implementation_revision==args.workflow_sha==C.revision(args.implementation),'source/workflow revision must agree')
    C.check_source(args.implementation)
    if args.preflight:
        base=C.load(args.implementation,'scripts/ci/expanded604-current-management-installer/contract.py');bound=base.policy();composition=base.COMPOSITION.policy()
        C.need(v['native604']['carrier_source']==bound['native604']['carrier_source'] and v['native604']['decision']==bound['native604']['decision'],'same actual native604 carrier/receipt in both policies')
        outputs=dict(eight_source=composition['eight_pair_source'],management_source=composition['management']['packet_source'],setup_source=composition['setup']['source'],welcome_source=composition['welcome']['carrier_source'],fresh600_decisions=bound['fresh600']['carrier_source'],native604_decisions=bound['native604']['carrier_source'],gui_decisions=v['welcome4_gui']['carrier_source'])
        if os.environ.get('GITHUB_OUTPUT'):
            with Path(os.environ['GITHUB_OUTPUT']).open('a') as stream:
                for k,value in outputs.items():stream.write(k+'='+value+'\n')
    elif args.decisions_only:
        C.need(args.native604_decisions is not None and args.gui_decisions is not None and args.fresh600_decisions is not None,'all actual Root decisions required')
        C.decisions(args.native604_decisions,args.gui_decisions,v);C.assets(args.gui_decisions,v['welcome4_gui'])
        base=C.load(args.implementation,'scripts/ci/expanded604-current-management-installer/contract.py')
        base.decisions(args.fresh600_decisions,args.native604_decisions,base.policy())
    else:
        for name in (*ci.CARRIERS,*ci.DECISIONS,'audio_inputs'):C.need(getattr(args,name) is not None,'all exact carriers required')
        ci.preflight(args)
    print('SOURCE_AND_DECISIONS_PASS ACTORS_NOT_RUN');return 0
if __name__=='__main__':raise SystemExit(main())
