# SPDX-License-Identifier: MIT
"""Ordinary-user First Login v3 regression through the existing held callback."""
import hashlib
import json
import os
import re
from pathlib import Path
import shlex
import stat

LABEL = 'first-login-overlay583-v3-'
FIRST = '/usr/bin/cachy-asahi-first-login'
HELPER = '/usr/bin/cachy-asahi-setup'
PYTHON = '/usr/bin/python3'
BACKEND = '/usr/lib/cachy-asahi/first-login/first_login.py'
TEMPLATES = '/usr/share/cachy-asahi'
TEST_HOME = 'v3 isolation home'


class IsolationRefusal(ValueError):
    """Fixed reason values only, for bounded fixture diagnostics."""


def fixture_home(nonce):
    if not re.fullmatch('[a-f0-9]{32}', nonce):
        raise IsolationRefusal('FIXTURE_NONCE_REFUSED')
    return Path('/var/tmp')/('caa-first-login-v3-fixture-'+nonce)/TEST_HOME
PREEXISTING = {'config with spaces/fish/config.fish': b'# existing Fish configuration before ALPM',
               'zsh with spaces/.zshrc': b'# existing Zsh configuration before ALPM\n'}
STEPS = ('inspect', 'preview', 'apply')
POISON_PYTHON = b'#!/bin/sh\nprintf "unexpected ambient interpreter\\n" >&2\nexit 97\n'
POISON_MODULE = b'raise RuntimeError("unexpected ambient Python module")\n'
SEED = '''from pathlib import Path
import sys
home=Path(sys.argv[1])
for i in range(2,6,2):
    path=home/sys.argv[i]
    path.parent.mkdir(mode=0o700,parents=True)
    path.write_bytes(bytes.fromhex(sys.argv[i+1]))
poison=home/'poison imports'
poison.mkdir(mode=0o700)
for name in ('argparse.py','json.py','sitecustomize.py'):
    (poison/name).write_bytes(bytes.fromhex(sys.argv[6]))
exe=poison/'python3';exe.write_bytes(bytes.fromhex(sys.argv[7]));exe.chmod(0o700)
'''


def need(ok, message):
    if not ok:
        raise ValueError(message)


def pins(values):
    return {name: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) for name, raw in values.items()}


def configs(home):
    leaves={}
    for name in PREEXISTING:
        path=home/name
        row=path.lstat()
        need(path.resolve()==path and stat.S_ISREG(row.st_mode) and row.st_nlink==1
             and 0<row.st_size<=64*1024, 'ordinary bounded disposable user configuration')
        leaves[name]=path.read_bytes()
    return leaves


def check_poison(home):
    poison=home/'poison imports'
    executable=poison/'python3'
    if executable.read_bytes()!=POISON_PYTHON or any((poison/name).read_bytes()!=POISON_MODULE
            for name in ('argparse.py','json.py','sitecustomize.py')):
        raise IsolationRefusal('POISON_FIXTURE_BYTES_REFUSED')
    if not os.access(executable,os.X_OK):
        raise IsolationRefusal('POISON_EXECUTION_ACCESS_REFUSED')
    return poison


def settings(home):
    return dict(HOME=str(home), XDG_CONFIG_HOME=str(home/'config with spaces'), ZDOTDIR=str(home/'zsh with spaces'),
                XDG_STATE_HOME=str(home/'state with spaces'))


def isolated_argv(home, apply):
    env = settings(home)
    return [PYTHON, '-I', '-B', BACKEND, 'activate', '--setup-helper', HELPER,
            '--components', 'fish', 'zsh', '--home', env['HOME'], '--template-root', TEMPLATES,
            '--config-home', env['XDG_CONFIG_HOME'], '--zdotdir', env['ZDOTDIR'],
            '--state-dir', str(Path(env['XDG_STATE_HOME'])/'cachy-asahi/setup'),
            *(['--apply'] if apply else [])]


def runuser(user, env, argv):
    return ['/usr/bin/runuser', '-u', user, '--', '/usr/bin/env', '-i',
            *(key+'='+value for key,value in env.items()), *map(str,argv)]


def seed(home, user, call):
    """Run in the owned target before pacman installs the candidate."""
    need(home.is_absolute() and home.resolve()==home and not any(home.iterdir()), 'fresh disposable fixture home')
    args = [PYTHON, '-I', '-B', '-c', SEED, home]
    for name, raw in PREEXISTING.items():
        args.extend([name, raw.hex()])
    args.extend([POISON_MODULE.hex(), POISON_PYTHON.hex()])
    call(LABEL+'seed', runuser(user, {'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8','HOME':str(home)}, args), cwd=home)
    if configs(home)!=PREEXISTING:
        raise IsolationRefusal('SEED_CONFIG_BYTES_REFUSED')
    check_poison(home)
    return pins(PREEXISTING)


def run(home, user, uid, gid, call, snapshot):
    """Exercise the selected installed launcher and exact printed argv after install."""
    row=home.lstat()
    need(stat.S_ISDIR(row.st_mode) and row.st_uid==uid>0 and row.st_gid==gid>0
         and stat.S_IMODE(row.st_mode)==0o700 and configs(home)==PREEXISTING,
         'pre-existing ordinary-user configuration survived ALPM install')
    poison=check_poison(home)
    foreign=home/'foreign replay home'
    poisoned=dict(PATH=str(poison)+':/usr/bin:/bin', LC_ALL='C.UTF-8',
                  PYTHONPATH=str(poison), PYTHONHOME=str(poison), PYTHONUSERBASE=str(poison))
    before=snapshot(home,uid,gid)

    def run_case(step, argv, env):
        raw=call(LABEL+step,runuser(user,env|poisoned,argv),cwd=poison)
        need(type(raw) is bytes and len(raw)<=256*1024,'bounded real installed report')
        return json.loads(raw)

    def emitted(report, apply):
        next_commands=report['next']
        need(type(next_commands) is list and len(next_commands)==1,'one exact First Login follow-up')
        result=shlex.split(next_commands[0])
        need(result==isolated_argv(home,apply),'emitted follow-up must retain isolated interpreter and frozen roots')
        return result

    inspect=run_case('inspect',[FIRST,'inspect'],settings(home))
    need(inspect['operation']=='inspect' and inspect['status']=='ready-to-select'
         and inspect['setup_status']['operation']=='status' and inspect['setup_status']['mode']=='read-only',
         'installed Setup8 status must finish through the poisoned caller environment')
    preview_argv=emitted(inspect,False)
    need(snapshot(home,uid,gid)==before,'isolated inspect changed the seeded home')
    preview=run_case('preview',preview_argv,settings(foreign))
    need(preview['status']=='activation-preview' and preview['setup_result']['mode']=='preview'
         and snapshot(home,uid,gid)==before,'printed preview changed the frozen or ambient home')
    apply_argv=emitted(preview,True)
    result=run_case('apply',apply_argv,settings(foreign))
    after=configs(home)
    state=home/'state with spaces/cachy-asahi/setup/state.json'
    need(result['status']=='activation-applied' and result['setup_result']['mode']=='applied'
         and all(after[name].startswith(raw) and len(after[name])>len(raw) for name,raw in PREEXISTING.items())
         and state.is_file() and not foreign.exists()
         and not any((home/name).exists() for name in ('.config','.zshrc','.local/state')),
         'printed apply must update only the frozen roots and preserve both pre-existing lines')
    return dict(status='PASS_V3_INSTALLED_ISOLATION', initial=pins(PREEXISTING), after_apply=pins(after),
                setup_state=pins({'state.json':state.read_bytes()})['state.json'],
                preview_argv=preview_argv, apply_argv=apply_argv)


def verify(home, initial, result, removed):
    """Independent contract for the original seed, journey and post-pacman evidence."""
    need(initial==result['initial']==pins(PREEXISTING) and result['status']=='PASS_V3_INSTALLED_ISOLATION'
         and result['preview_argv']==isolated_argv(home,False) and result['apply_argv']==isolated_argv(home,True)
         and removed==result['after_apply'] and set(removed)==set(PREEXISTING)
         and all(row['bytes']>initial[name]['bytes'] and row['sha256']!=initial[name]['sha256']
                 and len(row['sha256'])==64 for name,row in removed.items())
         and result['setup_state']['bytes']>0 and len(result['setup_state']['sha256'])==64,
         'exact frozen-root journey and byte preservation across ALPM removal required')
    return removed
