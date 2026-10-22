#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root native604 acceptance first; actual carriers before secrets or native work."""
import argparse
import os
from pathlib import Path
import re
import contract as C


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--implementation',type=Path,required=True)
    parser.add_argument('--source',required=True);parser.add_argument('--workflow-sha',required=True)
    parser.add_argument('--preflight',action='store_true')
    for name in (*C.CARRIERS,*C.DECISIONS,'audio_inputs'):parser.add_argument('--'+name.replace('_','-'),type=Path)
    args=parser.parse_args(argv);policy=C.policy()
    C.need(re.fullmatch('[0-9a-f]{40}',args.source) and args.source==args.workflow_sha,'exact workflow/source identity required')
    args.implementation=C.safe(args.implementation.absolute())
    C.need(C.revision(args.implementation)==args.source,'implementation revision differs')
    C.verify_source(args.implementation)
    if args.preflight:
        composition=C.COMPOSITION.policy()
        outputs=dict(legacy_source=composition['legacy_source'],eight_source=composition['eight_pair_source'],
             seven_source=composition['retained_seven_source'],management_source=composition['management']['packet_source'],
             setup_source=composition['setup']['source'],welcome_source=composition['welcome']['carrier_source'],
             fresh600_decisions=policy['fresh600']['carrier_source'],native604_decisions=policy['native604']['carrier_source'])
        C.need(all(re.fullmatch('[0-9a-f]{40}',v or '') for v in outputs.values()),'exact public carrier revisions required')
        if os.environ.get('GITHUB_OUTPUT'):
            with Path(os.environ['GITHUB_OUTPUT']).open('a') as stream:
                for name,value in outputs.items():stream.write(name+'='+value+'\n')
        print('FRESH604_POLICY_AND_SOURCE=PASS native=NOT_RUN');return 0
    for name in (*C.CARRIERS,*C.DECISIONS,'audio_inputs'):
        C.need(getattr(args,name) is not None,'all fixed public carriers and six audio inputs required')
        setattr(args,name,C.safe(getattr(args,name).absolute()))
    args.code=args.implementation;C.legacy(args.legacy_source);C.inputs(args,policy)
    print('FRESH604_ACTUAL_INPUTS_AND_ROOT_DECISIONS=PASS native=NOT_RUN');return 0


if __name__=='__main__':raise SystemExit(main())
