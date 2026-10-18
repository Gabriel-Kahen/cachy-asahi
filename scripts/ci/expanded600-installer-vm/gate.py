#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pending acceptance always stops before caches, secrets or native actors."""
import argparse
import os
from pathlib import Path
import re
import contract as C
import ci
import materializer


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--implementation',type=Path,required=True)
    parser.add_argument('--source',required=True);parser.add_argument('--workflow-sha',required=True)
    parser.add_argument('--preflight',action='store_true')
    for name in ('legacy-source','seven-pairs','eight-pairs'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args();policy=C.policy()
    C.need(re.fullmatch('[0-9a-f]{40}',args.source) and args.source==args.workflow_sha,
           'exact manual workflow/source identity required')
    ci.own_source(C.safe(args.implementation.absolute()),args.source)
    if args.preflight:
        destination=os.environ.get('GITHUB_OUTPUT')
        if destination:
            with Path(destination).open('a') as stream:stream.write('eight_source='+policy['eight_pair_source']+'\n')
        print('EXPANDED600_INSTALLER_POLICY_BOUND=PASS actual_native_execution=NOT_RUN');return 0
    C.need(all(getattr(args,n) is not None for n in ('legacy_source','seven_pairs','eight_pairs')),'complete immutable input checkouts required')
    C.legacy(args.legacy_source)
    C.need(C.revision(args.seven_pairs)==C.SEVEN and C.revision(args.eight_pairs)==policy['eight_pair_source'],
           'immutable seven/eight-pair checkout revisions differ')
    C.prerequisites(args.eight_pairs,policy)
    materializer.accepted_pairs(args.eight_pairs,args.seven_pairs,args.legacy_source,policy)
    print('EXPANDED600_INSTALLER_BOUND_INPUTS=PASS actual_native_execution=NOT_RUN');return 0


if __name__=='__main__':raise SystemExit(main())
