#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Prefill exact original574 DATA before the unchanged producer, inside its2300s cap."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

CARRIER='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'


def helper(source):
    directory=source/'scripts/ci/retained-build-inputs'
    sys.path.insert(0,str(directory))
    # Never collide with the lane constructor's already-imported prepare module.
    spec=importlib.util.spec_from_file_location('_maintenance_exact_retained_prepare',directory/'prepare.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def run(source,carrier,output,token,*,loader=helper,execute=os.execv,clock=time.monotonic):
    source,carrier,output=(C.safe(Path(p).absolute()) for p in (source,carrier,output))
    C.need(re.fullmatch('[0-9a-f]{16}',token),'original explicit producer token required')
    C.verify_source(source)
    policy=json.loads((source/C.LANE/'input-policy.json').read_bytes())
    C.need(re.fullmatch('[0-9a-f]{40}',policy.get('candidate_source') or '') and
           policy['candidate_files']==C.frozen_files(),'Root-bound frozen package source required before preparation')
    deadline=clock()+2300
    module=loader(source)
    value=module.prepare(carrier,output/'context/deps','desktop574',
        source/'scripts/ci/maintained-desktop574-inputs.json',deadline,carrier/'.git')
    C.need(value['status']=='EXACT_RETAINED_INPUT_PREPARATION_DATA_ONLY' and value['source']==CARRIER and
           value['mode']=='desktop574' and value['actual'] is None and
           value['receipt']['actual_authority'] is False and
           value['receipt']['cache']['all_previous_inode_metadata_bytes_unchanged'] is True,
           'complete retained574 DATA-only preparation and previous cache preservation required')
    C.need(clock()<deadline,'original producer budget exhausted during retained preparation')
    path=output/'maintenance-retained-inputs.json'
    with path.open('x') as stream:json.dump(value,stream,sort_keys=True,indent=2);stream.write('\n')
    command=[sys.executable,'-I','-B',str(source/'scripts/ci/maintained_desktop574.py'),'build',
        '--inputs',str(source/'scripts/ci/maintained-desktop574-inputs.json'),'--output',str(output),'--job-token',token]
    execute(sys.executable,command)
    raise RuntimeError('original producer exec unexpectedly returned')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','carrier','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--job-token',required=True);args=parser.parse_args()
    run(args.source,args.carrier,args.output,args.job_token)
