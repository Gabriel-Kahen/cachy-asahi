#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Seed exact retained574 DATA before the unchanged original2300s producer."""
import argparse,importlib.util,json,os,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C


def load_helper(root):
    helpers=root/'scripts/ci/setup6-retained-helpers';sys.path.insert(0,str(helpers))
    spec=importlib.util.spec_from_file_location('_doctor2_retained574_prepare',helpers/'prepare.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','carrier','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--job-token',required=True);args=parser.parse_args(argv);root=args.source.absolute()
    C.verify_source(root) # Every helper/profile is bound before it can access the carrier.
    helper=load_helper(root);deadline=time.monotonic()+2300
    value=helper.prepare(args.carrier.absolute(),args.output.absolute()/'context/deps','desktop574',
                         root/'scripts/ci/maintained-desktop574-inputs.json',deadline,args.carrier.absolute()/'.git')
    C.validate_retained_inputs(value)
    raw=json.dumps(value,indent=2,sort_keys=True)+'\n';C.need(len(raw.encode())<=512*1024,'retained DATA receipt cap')
    with (args.output/'doctor2-retained-inputs.json').open('x') as stream:stream.write(raw)
    os.execv(sys.executable,[sys.executable,'-I','-B',str(root/'scripts/ci/maintained_desktop574.py'),'build',
                            '--inputs',str(root/'scripts/ci/maintained-desktop574-inputs.json'),
                            '--output',str(args.output.absolute()),'--job-token',args.job_token])


if __name__=='__main__':main()
