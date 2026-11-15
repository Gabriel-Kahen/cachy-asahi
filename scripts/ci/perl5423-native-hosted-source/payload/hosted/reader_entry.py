#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Future separately Root-admitted passive Reader; never called by native job."""
import argparse
import importlib.util
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
spec=importlib.util.spec_from_file_location('hosted_reader_data',HERE/'common.py');common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)


def run(args):
    common.need(sys.version_info>=(3,14),'qualified Python3.14 zstd Reader required')
    raw=common.read(args.binding);common.need(common.pin(raw)['sha256']==args.binding_sha256,'external authenticated Root binding hash')
    binding=common.decode(raw);common.verify_source(ROOT,binding['source_map_sha256'])
    reader=common.load('hosted_independent_perl_reader',HERE/'reader.py')
    return reader.validate(Path(args.evidence),ROOT,binding)


if __name__=='__main__':
    common.need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized Root Reader')
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('binding','binding-sha256','evidence'):p.add_argument('--'+name,required=True)
    print(common.encode(run(p.parse_args())).decode(),end='')
