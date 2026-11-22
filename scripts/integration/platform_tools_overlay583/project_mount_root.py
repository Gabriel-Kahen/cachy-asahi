#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Project only the reviewed Platform Tools Overlay583 mount-root source leaves."""

import argparse
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from project_reader import HANDOFF, decode, encoded, need, ordinary, pin, read, unchanged

GUEST = 'scripts/integration/first_login_overlay583/guest.py'
TARGET = 'scripts/integration/first_login_overlay583/target.py'
READER = 'readback.py'
ORIGINAL = {
    GUEST: '181c62d10cfd48a78ed256771a4f188c168823ccd7f9c1ce12ee02edfc2755ce',
    TARGET: 'e136944d16d885467e0e8586a8d00362032265383793d21f6d380bc66cf81932',
    READER: 'a4dcdc53ff4ac8aa2fc56afdc84042caef412eb5244b25d27a0d5a484e07b57c',
}
EXPECTED = {
    GUEST: 'dd29c9336f956d845cd1d8d0728c84cb137634f77655da2b3de78df65d76851e',
    TARGET: 'acc80de85d585b66d7295ecc1cb3c17789fb58aaadada1f660887da2db7dd659',
    READER: 'b7eb08733d0d758891a7e2e18d7bf9f07242e1c4aeb4923f4a62f15c66b10e90',
}

OLD_JOURNEY = '''        'first-login-installed-journey': [*chroot,'/usr/bin/runuser','-u',ACCOUNT,'--','/usr/bin/env','-i',
                                      'PATH=/usr/bin:/bin','LC_ALL=C','TZ=UTC','HOME='+str(user),
                                      '/usr/bin/python3','-I','-B',str(TARGET_WORK/'target.py'),nonce],'''
MOUNT_JOURNEY = '''        JOURNEY: ['/usr/bin/env','-i','PATH=/usr/bin:/bin','LC_ALL=C','TZ=UTC',
                  'LD_LIBRARY_PATH=/trial-media/runtime/usr/lib',STOCK_PYTHON,'-I','-B',
                  str(SUPPLEMENT/'guest.py'),JOURNEY_ROOT_FLAG,nonce],'''
GUEST_INGRESS = '''

if __name__=='__main__':
    if len(sys.argv)!=3 or sys.argv[1]!=JOURNEY_ROOT_FLAG:
        raise SystemExit('exact private installed journey required')
    enter_private_root(sys.argv[2])
'''

OLD_RETIREMENT = '''        if label=='namespace' and result['exit']!=code:
            print(json.dumps(dict(status='HOLD_ORDINARY_GUEST_NAMESPACE',exit=result['exit'],
                                  timeout=result['timeout'],ownership=result['ownership'])),file=sys.stderr)
        need(result['reaped'] is result['output_complete'] is True
             and result['ownership']=='REAPED' and result['group_census']=='EMPTY_TWICE'
             and result['timeout'] is False and result['signals']==[] and result['error'] is None
             and result['exit']==code,'exact process exit and owned group retirement for '+label)'''
CHECKED_RETIREMENT = '''        if label=='namespace' and result['exit']!=code:
            diagnostic = namespace_hold(body,result)
            if diagnostic is not None:
                print(NAMESPACE_HOLD_MARKER+json.dumps(diagnostic,sort_keys=True,separators=(',',':')),
                      file=sys.stderr,flush=True)
        need(clean_retirement(result) and result['exit']==code,
             'exact process exit and owned group retirement for '+label)'''

READER_LOADER = '''    from types import ModuleType
    name="scripts/integration/first_login_overlay583/guest.py"
    source=file(DATA/"source"/name,128*1024,data["source"][name])
    checker=ModuleType("independent_platform_tools_guest");checker.__file__=str(DATA/"source"/name)
    exec(compile(source,name,"exec"),checker.__dict__)
'''
READER_JOIN = '''    if checker.JOURNEY in outputs:
        row=next(row for row in attempted["commands"] if row["role"]==checker.JOURNEY)
        result["installed_journey_data"]=checker.journey_observations(*outputs[checker.JOURNEY],nonce,row["exit"])
'''


def swap(body, old, new):
    need(body.count(old) == 1, 'Expected one exact mount-root source seam')
    return body.replace(old, new, 1)


def fragment(name, marker):
    body = read(HERE/name, cap=24*1024).decode('utf-8')
    need(body.count(marker) == 1, 'Expected one reviewed source fragment')
    return body.split(marker, 1)[1]


def guest_source(body):
    body = swap(body, 'import stat\nimport time', 'import stat\nimport sys\nimport time')
    seam = 'MAX_ALPM_LOG = 16*1024\n'
    body = swap(body, seam, seam+'\n'+fragment('mount_root.py', '# BEGIN GUEST SOURCE\n'))
    body = swap(body, OLD_JOURNEY, MOUNT_JOURNEY)
    seam = "        output[role]=stdout\n    if value['result'] is None:"
    return swap(body, seam, "        output[role]=stdout\n        if role==JOURNEY:\n"
                "            journey_observations(stdout,stderr,nonce,row['exit'])\n"
                "    if value['result'] is None:")+GUEST_INGRESS


def target_source(body):
    seam = '\n\ndef main(nonce):'
    body = swap(body, seam, '\n\n'+fragment('namespace_failure.py', '# BEGIN TARGET SOURCE\n')+seam)
    return swap(body, OLD_RETIREMENT, CHECKED_RETIREMENT)


def reader_source(body):
    body = swap(body, READER_LOADER, '')
    seam = '    outputs=addon_outputs(attempted,expected,held=held)\n'
    return swap(body, seam, seam+READER_LOADER+READER_JOIN)


def project(stage, handoff_sha256):
    stage = ordinary(stage)
    observed = {}
    raw = read(stage/'HANDOFF.DATA.json', cap=128*1024, observed=observed)
    stage_data = decode(raw)
    need(pin(raw)['sha256'] == handoff_sha256 and raw == encoded(stage_data)
         and stage_data['kind'] == HANDOFF, 'Exact sealed Platform Tools handoff required')
    outputs = {}
    for name, render in ((GUEST, guest_source), (TARGET, target_source), (READER, reader_source)):
        path = stage/name if name == READER else stage/'source'/name
        selected = stage_data['source'][name] if name != READER else None
        old = read(path, selected, cap=128*1024, observed=observed)
        need(pin(old)['sha256'] == ORIGINAL[name], 'Unexpected predecessor source: '+name)
        projected = render(old.decode('utf-8')).encode('utf-8')
        need(pin(projected)['sha256'] == EXPECTED[name], 'Unexpected emitted mount-root source: '+name)
        compile(projected, name, 'exec')
        outputs[path.relative_to(stage)] = projected
    unchanged(observed)
    return outputs


def main():
    cli = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    cli.add_argument('--stage', type=Path, required=True)
    cli.add_argument('--handoff-sha256', required=True)
    cli.add_argument('--output', type=Path, required=True)
    args = cli.parse_args()
    output = ordinary(args.output)
    need(not output.is_relative_to(ordinary(args.stage)), 'Output must be outside the sealed stage')
    files = project(args.stage, args.handoff_sha256)
    os.umask(0o077)
    output.mkdir(mode=0o700)
    for name, body in files.items():
        path = output/name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(body)
            os.fchmod(stream.fileno(), 0o400)
    print(encoded(dict(files={str(name): pin(body) for name, body in files.items()}, authority=None)).decode(), end='')


if __name__ == '__main__':
    main()
