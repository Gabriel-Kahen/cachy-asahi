#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import argparse
from pathlib import Path
import adapter as A
import contract as C

def execute(source,base_dir,out,token):
 C.policy();C.verify_source(source) # Before derived imports, output, signing or actors.
 return A.module(source,'run.py').execute(source,base_dir,out,token)

if __name__=='__main__':
 p=argparse.ArgumentParser(description='Separate native Apps6 pairs and signed owned-copy repair; no host installation.')
 for name in ('source','base-dir','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--consumer-token',required=True);a=p.parse_args();raise SystemExit(execute(a.source.absolute(),a.base_dir.absolute(),a.output.absolute(),a.consumer_token))
