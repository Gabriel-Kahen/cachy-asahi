#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the unchanged installed journey inside the verified disposable target."""

from base64 import b64encode
from functools import partial
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import time

WORK = Path('/run/caa-first-login-overlay583')
ACCOUNT = 'caa-first-login-guest'
UID = 29083
DIAGNOSTIC_BYTES = 4096


def load(path, name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_installed(journey, home, command, uid, gid):
    profile='fish0.1.0-1-zsh0.1.0-1'
    paths=dict(first_login='/usr/bin/cachy-asahi-first-login', setup='/usr/bin/cachy-asahi-setup',
               fish='/usr/bin/fish', zsh='/usr/bin/zsh', python3='/usr/bin/python3',
               template_root='/usr/share/cachy-asahi', template_profile=profile,
               template_sha256=journey.TEMPLATE_HASHES[profile], user=ACCOUNT)
    return journey.run(paths, home, command, uid, gid, label='first-login-overlay583')


def checked_command(process, end, records, step, argv, expected=0, cwd=None):
    cap=min(20,end-time.monotonic())
    if cap<=1:
        raise TimeoutError('installed first-login bounded window exhausted')
    child=subprocess.Popen(argv,cwd=cwd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT,start_new_session=True,
                           env={'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8','TZ':'UTC'})
    receipt=process.supervise(child,cap=cap,retirement=1,max_output=256*1024)
    output=receipt.pop('output')
    records.append(dict(step=step,expected=expected,receipt=receipt))
    if (receipt['reaped'] is not True or receipt['ownership']!='REAPED'
            or receipt['output_complete'] is not True or receipt['group_census']!='EMPTY_TWICE'
            or receipt['timeout'] or receipt['signals'] or receipt['error'] is not None):
        raise ValueError('installed first-login command failed owned retirement: '+step)
    if receipt['exit']!=expected:
        # Outer guest evidence retains this stderr independently of the journey JSON.
        print(json.dumps(dict(kind='first-login-command-output', step=step, expected=expected,
                              exit=receipt['exit'], bytes=len(output),
                              stdout_stderr_b64=b64encode(output[:DIAGNOSTIC_BYTES]).decode('ascii'))),
              file=sys.stderr,flush=True)
        raise ValueError(f'installed first-login command exited {receipt["exit"]}, expected {expected}: {step}')
    return output


def main(nonce):
    if (not sys.flags.isolated or not sys.dont_write_bytecode or os.getuid()!=0
            or os.uname().machine!='aarch64' or os.sysconf('SC_PAGE_SIZE')!=16384
            or Path(__file__).parent.resolve()!=WORK or not re.fullmatch('[0-9a-f]{32}',nonce)
            or Path('/proc/cmdline').read_text().split().count('cachy_overlay583_nonce='+nonce)!=1):
        raise ValueError('exact admitted ARM16K target driver required')
    owner=pwd.getpwnam(ACCOUNT)
    home=WORK/'home'
    if owner.pw_uid!=UID or owner.pw_gid<=0 or owner.pw_dir!=str(home):
        raise ValueError('exact disposable ordinary-user account required')
    home.mkdir(mode=0o700)
    os.chown(home,owner.pw_uid,owner.pw_gid)
    process=load(WORK/'owned_process.py','first_login_target_owned_process')
    journey=load(WORK/'journey.py','first_login_installed_journey')
    process.prepare()
    records=[]
    command=partial(checked_command,process,time.monotonic()+190,records)

    try:
        result=run_installed(journey,home,command,owner.pw_uid,owner.pw_gid)
    except Exception as error:
        result=getattr(error,'first_login_result',dict(status='FAIL',error=type(error).__name__))
    result['actor_commands']=records
    print(json.dumps(result,sort_keys=True))
    return 0 if result['status']=='PASS' else 2


if __name__=='__main__':
    if len(sys.argv)!=2:
        raise SystemExit('expected exact admitted guest nonce')
    raise SystemExit(main(sys.argv[1]))
