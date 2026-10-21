#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Require Root inputs and exact workflow/source before secrets or actors."""
import argparse
import os
from pathlib import Path
import re
import contract as C

CARRIERS=('legacy_source','eight_source','seven_source','management_source','setup_source','welcome_source','apps6_source','apps6_authority_source')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--code',type=Path,required=True)
    parser.add_argument('--source',required=True);parser.add_argument('--workflow-sha',required=True)
    parser.add_argument('--preflight',action='store_true')
    for name in CARRIERS:parser.add_argument('--'+name.replace('_','-'),type=Path)
    parser.add_argument('--audio-inputs',type=Path)
    args=parser.parse_args(argv)
    policy=C.policy()  # UNBOUND Welcome immediately refuses, including preflight.
    C.need(re.fullmatch('[0-9a-f]{40}',args.source) and args.source==args.workflow_sha,
        'exact manual workflow/source identity required')
    code=C.safe(args.code.absolute());C.need(C.revision(code)==args.source,'implementation checkout identity differs')
    C.verify_source(code)
    if args.preflight:
        outputs=dict(legacy_source=policy['legacy_source'],eight_source=policy['eight_pair_source'],
            seven_source=policy['retained_seven_source'],management_source=policy['management']['packet_source'],
            setup_source=policy['setup']['source'],welcome_source=policy['welcome']['carrier_source'],
            apps6_source=policy['apps6']['carrier_source'],apps6_authority_source=policy['apps6']['authority_source'])
        C.need(all(re.fullmatch('[0-9a-f]{40}',value or '') for value in outputs.values()),'fixed carrier revisions required')
        destination=os.environ.get('GITHUB_OUTPUT')
        if destination:
            with Path(destination).open('a') as stream:
                for name,value in outputs.items():stream.write(name+'='+value+'\n')
        print('EXPANDED604_POLICY_AND_SOURCE=PASS native=NOT_RUN');return 0
    C.need(all(getattr(args,name) is not None for name in CARRIERS),'complete fixed public input checkouts required')
    for name in CARRIERS:setattr(args,name,C.safe(getattr(args,name).absolute()))
    C.need(args.apps6_authority_source is not None,'exact public byte-case authority required');args.apps6_authority_source=C.safe(args.apps6_authority_source.absolute())
    C.need(args.audio_inputs is not None,'all six held audio inputs required')
    args.audio_inputs=C.safe(args.audio_inputs.absolute())
    C.inputs(args,policy)
    print('EXPANDED604_PASSIVE_INPUT_GATE=PASS native=NOT_RUN');return 0


if __name__=='__main__':raise SystemExit(main())
