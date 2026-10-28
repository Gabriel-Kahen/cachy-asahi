#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact source, pair and Tools-owned cache helper proof before native actors/secrets."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as c


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,required=True);parser.add_argument('--pair-root',type=Path,required=True)
    parser.add_argument('--source',required=True);parser.add_argument('--manifest',required=True);args=parser.parse_args()
    root=c.safe(args.source_root);policy=c.bindings()
    c.need(re.fullmatch('[0-9a-f]{40}',args.source) and os.environ['GITHUB_WORKFLOW_SHA']==args.source and
           subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True,timeout=15).strip()==args.source,
           'exact manual source/workflow required')
    raw=c.read(c.HERE/'source-manifest.json');c.need(c.sha(raw)==args.manifest,'Root frozen source manifest differs')
    value=c.decode(raw);c.need(value['schema_version']==1 and 1<=len(value['files'])<=192,'finite original source manifest bounds')
    pins=value['files']
    for name,row in pins.items():c.checked(root,name,row,2*1024**2)
    own=str((c.HERE/'source-manifest.json').relative_to(root))
    subprocess.run(['git','-C',str(root),'diff','--exit-code','HEAD','--',*pins,own],check=True,capture_output=True,timeout=20)
    c.check_source(root);c.pair(args.pair_root)
    c.need(subprocess.check_output(['git','-C',str(args.pair_root),'rev-parse','HEAD'],text=True,timeout=15).strip()==policy['binding']['source'],
           'exact accepted pair checkout required')
    token=c.sha(('glibc-system16k:'+os.environ['GITHUB_RUN_ID']+':'+os.environ['GITHUB_RUN_ATTEMPT']+':'+args.source).encode())[:16]
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as stream:stream.write('job_token='+token+'\n')
    print('SYSTEM16K_BOUND_PROVIDER_PROBES_CACHE_GATE=PASS execution=NOT_RUN');return 0


if __name__=='__main__':raise SystemExit(main())
