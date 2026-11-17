#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Pure read-only Root/source preflight before the workflow submits a scope."""
import argparse
import importlib.util
import os
from pathlib import Path
import sys
import time

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('libgit2_preflight_data',HERE/'data.py');D=importlib.util.module_from_spec(s);s.loader.exec_module(D)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True)
    for n in ('source-map-sha256','admission-sha256','runtime-sha256'):p.add_argument('--'+n,required=True)
    a=p.parse_args();D.need(sys.flags.isolated and __debug__,'isolated nonoptimized read-only admission preflight')
    D.admission(a.root,a.source_map_sha256,os.environ.get('ROOT_LIBGIT2_REFERENCE_ADMISSION_JSON','').encode(),os.environ.get('ROOT_LIBGIT2_REFERENCE_RUNTIME_JSON','').encode(),a.admission_sha256,a.runtime_sha256,os.environ,int(time.time()))
    print('LIBGIT2_REFERENCE_ROOT_SOURCE_PREFLIGHT_ONLY; native pair NOT RUN')

if __name__=='__main__':main()
