#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise exact current606 public ingress, with no package or guest actor."""

import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch


def reject(call, message):
    try:
        call()
    except ValueError:
        return
    raise AssertionError(message)


def main(args):
    sys.path.insert(0,str(args.source))
    import native
    f = native.fresh()
    data = native.fresh_data()
    packet = args.source/'fresh-test/public'
    bodies = f.operand_paths(args.held,args.project,data)
    receipt = f.verify_live(data,packet,bodies)
    f.recorded(data,receipt)
    assert all(b'/home/' not in path.read_bytes() for path in packet.rglob('*') if path.is_file())
    assert len(list(p for p in packet.rglob('*') if p.is_file())) == 11
    assert not (packet/'provenance.json').exists()
    f.recorded(data,receipt,run_start=receipt['verified'],run_end=receipt['verified'])
    bad = copy.deepcopy(receipt)
    bad['detached']['dns2']['signature_pin'] = bad['detached']['doctor']['signature_pin']
    reject(lambda:f.recorded(data,bad),'foreign detached role was accepted')
    reject(lambda:f.recorded(data,receipt,run_start=data['window']['start'],run_end=data['window']['end']), 'expired same-run acceptance')
    with patch.object(f,'time',SimpleNamespace(time=lambda:data['window']['end'])):
        reject(lambda:f.current(data,full_launch=False),'expired certificate window entered the actor')
    with tempfile.TemporaryDirectory(prefix='fresh606-actor-fenced-') as td:
        work=Path(td)
        replaced=work/'wrong.body'
        replaced.write_bytes(bodies['doctor'].read_bytes()+b'changed')
        reject(lambda:f.data_only(data,packet,dict(bodies,doctor=replaced)),'changed original package body accepted')
        f.prepare_assets(args.source/'original',args.held,args.project,work/'assets',packet,native.original().assets)
        factory=native.factory()
        cases={}
        with patch('subprocess.Popen',side_effect=AssertionError('actor forbidden')),patch('subprocess.run',side_effect=AssertionError('actor forbidden')):
            for profile in ('minimal','overlay'):
                for mode,pages in (('generic4k',4096),('generic16k',16384)):
                    label=profile+'-'+mode
                    out=work/label
                    p,changes=factory.prepare_code(args.source/'original',work/'assets',out,profile,mode)
                    result=factory.seal(out,profile,mode,p,changes,False)
                    assert result['page_size']==pages and result['packages']==606 and result['actual_run'] is None
                    assert 'installed606_progress' in result['derivatives']
                    assert (out/'candidates/test-signature-renewal.json').read_bytes()==(work/'assets'/f.INDEX).read_bytes()
                    assert result['status']=='UNBOUND_CURRENT606_GUI_CODE_ONLY_RUNTIME_REFUSES'
                    cases[label]=pages
    return dict(status='PASS_ACTUAL_PUBLIC_TEST_AND_FOUR_SOURCE_ONLY_CASES',cases=cases, roles=sorted(receipt['detached']),actual=None)


if __name__=='__main__':
    cli=argparse.ArgumentParser(description=__doc__)
    for field in ('source','held','project'):
        cli.add_argument('--'+field,required=True,type=lambda p:Path(p).absolute())
    print(json.dumps(main(cli.parse_args()),sort_keys=True))
