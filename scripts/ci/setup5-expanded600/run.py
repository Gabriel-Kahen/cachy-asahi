#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Wrap the held original full600 runner with one separate accepted-Setup5 consumer."""
import argparse
from pathlib import Path
import sys
import policy as P
import host


def main():
    p=argparse.ArgumentParser(description=__doc__,add_help=False)
    for name in ('implementation','probe-source','setup5-inputs'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--implementation-source',required=True);a,original_args=p.parse_known_args()
    bound=P.policy();implementation=P.safe(a.implementation.absolute());P.source(implementation)
    P.need(P.revision(implementation)==a.implementation_source and P.revision(a.probe_source)==P.PROBE,
        'held implementation/probe source differs')
    P.need(original_args.count('--code')==original_args.count('--code-revision')==1,'explicit original runner source required')
    code=P.safe(Path(original_args[original_args.index('--code')+1]).absolute())
    P.need(P.revision(code)==bound['baseline_source']==original_args[original_args.index('--code-revision')+1],
        'Root accepted original600 source required')
    host.CONTEXT=dict(implementation=implementation,probe=P.safe(a.probe_source.absolute()),
        setup5=P.safe(a.setup5_inputs.absolute()),source=a.implementation_source)
    namespace,_=host.original_namespace(code)
    P.need(P.sha(host.CONTEXT['setup5']/'index.json')==P.INDEX,'exact staged Setup5 packet required')
    before=host.packet_snapshot(host.CONTEXT['setup5'])
    with_args=sys.argv
    try:
        sys.argv=[str(code/'scripts/ci/expanded-development-composition/run.py'),*original_args]
        result=namespace['main']()
    finally:sys.argv=with_args
    P.need(host.packet_snapshot(host.CONTEXT['setup5'])==before,'borrowed Setup5 packet bytes/metadata changed')
    return result


if __name__=='__main__':raise SystemExit(main())
