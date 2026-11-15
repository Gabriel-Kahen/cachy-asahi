#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Future Root-only passive Reader entry; not invoked during source development."""
import argparse
import importlib.util
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('perl_reader_bootstrap',ROOT/'common.py')
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)


def run(args):
    ar=common.read(args.admission);qr=common.read(args.qualification)
    common.need(common.pin(ar)['sha256']==args.admission_sha256 and common.pin(qr)['sha256']==args.qualification_sha256,'independently Root-qualified operands')
    a,q=common.decode(ar),common.decode(qr);c=common.decode(common.read(ROOT/'contract.json'))
    common.need(common.encode(a)==ar and common.encode(q)==qr and a['qualification_sha256']==args.qualification_sha256,'canonical Root operand join')
    common.admission(a,q,c);common.source(ROOT,a['source_map_sha256'])
    # Root must have qualified this entire local Source/Reader before invoking
    # this entry. No code is imported from the evidence/capsule.
    reader=common.load('perl_independent_reader',ROOT/'reader.py')
    return reader.validate_pair(Path(args.evidence),c,a,q)


if __name__=='__main__':
    common.need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized Root Reader entry')
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('admission','admission-sha256','qualification','qualification-sha256','evidence'):parser.add_argument('--'+name,required=True)
    print(common.encode(run(parser.parse_args())).decode(),end='')
