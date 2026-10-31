#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Passive manual-dispatch proof, before secrets or native actors."""
import argparse
from pathlib import Path
import re
import subprocess
import contract as C
import inputs
import bang


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('code','script-source','module-source'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--source',required=True);parser.add_argument('--workflow-sha',required=True)
    args=parser.parse_args();code=C.safe(args.code.absolute());policy=C.policy()
    C.need(re.fullmatch('[0-9a-f]{40}',args.source) and args.source==args.workflow_sha and
           subprocess.check_output(['git','-C',str(code),'rev-parse','HEAD'],text=True,timeout=15).strip()==args.source,
           'manual source must equal this exact workflow commit')
    C.source(code);C.verify_self(code)
    for directory,expected in ((args.script_source,policy['script_source']),(args.module_source,policy['bang_source'])):
        C.need(subprocess.check_output(['git','-C',str(directory),'rev-parse','HEAD'],text=True,timeout=15).strip()==expected,
               'fixed input revision differs')
    bundle=args.script_source
    inputs.retained(bundle,C.read(C.checked(bundle,policy['script_index'])),code)
    inputs.combined(args.module_source,policy)
    bang.recipe(args.module_source,policy,inputs.tools(code)[0])
    print('EXPANDED600_PASSIVE_DISPATCH_GATE=PASS native=NOT_RUN')
    return 0


if __name__=='__main__':raise SystemExit(main())
