# SPDX-License-Identifier: MIT
"""One guest-only extension to the verified Overlay583 installed target."""

from base64 import b64decode, b64encode
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import time

SUPPLEMENT = Path('/trial-code/first-login')
TARGET_WORK = Path('/run/caa-first-login-overlay583')
PKG = 'cachy-asahi-first-login'
ACCOUNT = 'caa-first-login-guest'
UID = 29083
ARCHIVE = 'cachy-asahi-first-login-0.1.0-2-any.pkg.tar.zst'
SIGNER = '18E721CE9D7928221AD3163BA91B1AFC7142F94E'
SIGNATURE = ARCHIVE+'.sig'
PUBLIC = 'rehearsal-TEST-public.gpg'
PASS = 'PASS_ARM16K_OVERLAY583_FIRST_LOGIN_INSTALLED_LIFECYCLE'
MAX_LOG = 256*1024
MAX_EVIDENCE = 2*1024**2
PROGRAMS = {
    'usr/bin/cachy-asahi-first-login': 'LAUNCHER_SHA',
    'usr/lib/cachy-asahi/first-login/first_login.py': 'BACKEND_SHA',
}


def command_plan(work, target, config, nonce):
    trust = work/'trust'
    pacman = ['/usr/bin/pacman', '--config', str(config), '--root', str(target),
              '--dbpath', str(target/'var/lib/pacman'), '--gpgdir', str(trust),
              '--cachedir',str(work/'cache'),'--logfile',str(work/'first-login-addon-pacman.log')]
    gpg = ['/usr/bin/gpg', '--batch', '--no-options', '--homedir', str(trust)]
    package = str(SUPPLEMENT/ARCHIVE)
    chroot = ['/usr/bin/chroot', str(target)]
    query = [*pacman,'--query']
    check = [*pacman,'--database','--check']
    user = TARGET_WORK/'home'
    return {
        'first-login-base': query,
        'first-login-base-deps': check,
        'first-login-import-public': [*gpg,'--import'],
        'first-login-verify-signature': [*gpg,'--status-fd','1','--verify',package+'.sig',package],
        'first-login-trust-fixture': [*gpg,'--import-ownertrust'],
        'first-login-install': [*pacman,'--upgrade','--noconfirm','--',package],
        'first-login-installed': query,
        'first-login-installed-deps': check,
        'first-login-create-fixture-user': [*chroot,'/usr/bin/useradd','--no-create-home','--user-group','--uid',str(UID),
                                           '--home-dir',str(user),'--shell','/usr/bin/nologin',ACCOUNT],
        'first-login-installed-journey': [*chroot,'/usr/bin/python3','-I','-B',str(TARGET_WORK/'target.py'),nonce],
        'first-login-uninstall': [*pacman,'--remove','--noconfirm','--',PKG],
        'first-login-removed': query,
        'first-login-removed-deps': check,
        'first-login-remove-fixture-user': [*chroot,'/usr/bin/userdel',ACCOUNT],
    }


ROLES = tuple(command_plan(Path('/trial-work'),Path('/trial-work/target'),Path('/trial-work/pacman.conf'),'').keys())


def good_signature(status, fingerprint, *, historical=False):
    records = [line.split() for line in status.decode('ascii').splitlines() if line.startswith('[GNUPG:] ')]
    kinds = {row[1] for row in records}
    valid = [row for row in records if row[1]=='VALIDSIG']
    bad = {'BADSIG','ERRSIG','REVKEYSIG','NO_PUBKEY','EXPSIG','SIGEXPIRED'}
    if not historical:
        bad.update(('EXPKEYSIG','KEYEXPIRED'))
    return (len(valid)==1 and len(valid[0])>=12 and valid[0][2]==valid[0][-1]==fingerprint
            and not kinds&bad and ('GOODSIG' in kinds or historical and 'EXPKEYSIG' in kinds))


def run(trial, *, supplement_sha256, nonce, env, command):
    """Call in the admitted guest after Overlay583 install and before trust retirement.

    command(step, argv, seconds, contents=None) returns stdout bytes on a checked
    natural exit. Its separate evidence namespace belongs to the existing actor.
    """
    need = trial.need
    need(os.getuid() == os.geteuid() == 0 and os.uname().machine == 'aarch64'
         and os.sysconf('SC_PAGE_SIZE') == 16384 and re.fullmatch('[0-9a-f]{32}', nonce or '')
         and Path('/proc/cmdline').read_text().split().count('cachy_overlay583_nonce='+nonce) == 1,
         'exact admitted generic ARM16K guest required')
    mounts = Path('/proc/self/mountinfo').read_text().splitlines()
    trial.mount_mode(SUPPLEMENT.parent, 'ro', mounts)
    trial.mount_mode(trial.IN, 'ro', mounts)
    trial.mount_mode(trial.WORK, 'rw', mounts)
    target = trial.ordinary(trial.TARGET)
    need(target.parent == trial.WORK and target.stat().st_dev == trial.WORK.stat().st_dev != Path('/').stat().st_dev
         and {path.name for path in Path('/sys/class/net').iterdir()} <= {'lo'}, 'owned offline scratch target required')
    raw = trial.read(SUPPLEMENT/'supplement.json', cap=64*1024)
    need(trial.pin(raw)['sha256'] == supplement_sha256, 'separately pinned exact supplement')
    packet = trial.decode(raw)
    need(raw == trial.encoded(packet) and packet['Root_authority'] is None and packet['installation'] == 'NOT RUN',
         'finite staging DATA only')
    need({path.name for path in SUPPLEMENT.iterdir()}==set(packet['files'])|{'supplement.json'},
         'exact read-only supplement leaf set')
    stage = load_stage(trial, packet)
    rehearsal = packet['rehearsal']
    need(packet['kind']==stage.KIND and stage.valid_rehearsal(rehearsal)
         and rehearsal['created']<=time.time()<rehearsal['expires'],
         'Current guest clock must accept the bounded TEST signing key')
    files = {name: trial.read(SUPPLEMENT/name, pin, cap=128*1024) for name, pin in packet['files'].items()}
    before = trial.read(trial.IN/'target.lock', stage.TARGET, cap=256*1024)
    need(packet['overlay_before'] == stage.TARGET and packet['preflight']['sha256'] == stage.PREFLIGHT_SHA
         and packet['provenance'] == stage.PROVENANCE and packet['template_profile'] == 'fish0.1.0-1-zsh0.1.0-1',
         'exact authenticated Overlay583 and supplemental package provenance')
    after = trial.sorted_rows(before+b'cachy-asahi-first-login 0.1.0-2\n')
    need(packet['overlay_after'] == trial.pin(after), 'exact single-package installed inventory')
    trial.canonical_lock(before, 583)
    trial.canonical_lock(after, 584)
    return exercise(trial,stage,target,before,after,files,nonce,env,command,rehearsal)


def exercise(trial, stage, target, before, after, files, nonce, env, command, rehearsal):
    need=trial.need
    trust = trial.ordinary(trial.WORK/'trust')
    need(env.get('GNUPGHOME') == str(trust) and trust.is_dir(), 'existing guest-only private trust directory')
    config = trial.read(trial.CONFIG, cap=4096).decode('ascii')
    need('SigLevel = Required TrustedOnly' in config.splitlines()
         and 'LocalFileSigLevel = Required TrustedOnly' in config.splitlines(), 'existing required signature policy')
    need(stage.ARCHIVE==ARCHIVE and stage.SIGNER==SIGNER and stage.PUBLIC==PUBLIC,
         'exact first-login archive and retained original TEST signer')
    signer = rehearsal['fingerprint']
    argv = command_plan(trial.WORK,target,trial.CONFIG,nonce)
    user = TARGET_WORK/'home'

    def call(step, seconds, contents=None):
        return command(step,argv[step],seconds,contents)

    def checked_inventory(step, expected):
        observed = trial.sorted_rows(call(step,45))
        need(observed == expected, 'complete installed inventory differs: '+step)
        call(step+'-deps',45)
        return trial.pin(observed)

    initial = checked_inventory('first-login-base', before)
    call('first-login-import-public',25,files[PUBLIC])
    verified = call('first-login-verify-signature',25)
    need(good_signature(verified,signer), 'exact selected TEST detached package signature required')
    call('first-login-trust-fixture',25,(signer+':6:\n').encode())

    with ExitStack() as stack:
        trial.target_api_mounts(target, env, stack)
        target_work = target/TARGET_WORK.relative_to('/')
        target_work.mkdir(mode=0o755)
        for name in ('journey.py','target.py','owned_process.py'):
            (target_work/name).write_bytes(files[name])
        call('first-login-install',90)
        installed = checked_inventory('first-login-installed',after)
        need(all(trial.pin(trial.read(target/relative,cap=128*1024))['sha256'] == getattr(stage, attr)
                 for relative,attr in PROGRAMS.items()), 'exact installed FirstLogin launcher and backend')
        call('first-login-create-fixture-user',20)
        journey = json.loads(call('first-login-installed-journey',210))
        need(journey['status'] == 'PASS' and journey['command_count'] == 27 and journey['shell_startups'] == 10
             and journey['recovery_confirmed'] and journey['final_components_deactivated'],
             'complete actual installed first-login and real Setup8 shell/recovery journey')
        call('first-login-uninstall',90)
        removed = checked_inventory('first-login-removed',before)
        need(all(not (target/relative).exists() and not (target/relative).is_symlink() for relative in PROGRAMS),
             'installed FirstLogin program files survived removal')
        home = target/user.relative_to('/')
        preserved = journey['user_edit_preservation']
        need(set(preserved) == {'.config/fish/config.fish','.zshrc'}
             and all(trial.pin(trial.read(home/name,cap=1024**2))['sha256'] == digest for name,digest in preserved.items()),
             'first-login removal must preserve the exact user edits')
        call('first-login-remove-fixture-user',20)

    return dict(status=PASS, before=initial, installed=installed,
                after_removal=removed, journey=journey, provenance=stage.PROVENANCE, rehearsal=rehearsal,
                native_arm_build='NOT RUN', M2='NOT RUN', Root_acceptance=None)


def load_stage(trial, packet):
    """Load only fixed selected read-only setup metadata from the mounted supplement."""
    from types import ModuleType

    files = packet['files']
    path = SUPPLEMENT/'stage.py'
    raw = trial.read(path, files['stage.py'], cap=64*1024)
    stage = ModuleType('first_login_overlay_stage_pins')
    stage.__file__ = str(path)
    exec(compile(raw,str(path),'exec'),stage.__dict__)
    trial.need(set(files) == {'stage.py','guest.py','target.py','journey.py','owned_process.py',SIGNATURE,PUBLIC}
               | set(stage.MATERIALS)
               and all(files[name] == pin for name,pin in stage.MATERIALS.items())
               and files['journey.py']['sha256'] == stage.JOURNEY_SHA
               and files['owned_process.py']['sha256'] == stage.PROCESS_SHA, 'exact signed archive and unchanged helper pins')
    return stage


def evidence(trial, directory, ledger, result):
    rows = []
    for row in ledger:
        entry = dict(row)
        for stream in ('stdout','stderr'):
            path = directory/(row['role']+'.'+stream)
            entry[stream] = b64encode(trial.read(path,cap=MAX_LOG)).decode('ascii')
        rows.append(entry)
    raw = trial.encoded(dict(result=result,commands=rows))
    trial.need(len(raw)<=MAX_EVIDENCE,'bounded first-login command evidence')
    return raw


def readback(raw, *, nonce, base, supplement, held, pin, need):
    """Join exact argv, byte inventories, signer and original in-target evidence."""
    value = json.loads(raw)
    need(set(value)=={'result','commands'} and type(value['commands']) is list,'exact first-login evidence schema')
    commands = value['commands']
    home = Path('/trial-work')
    expected = command_plan(home,home/'target',home/'pacman.conf',nonce)
    roles = [row['role'] for row in commands]
    need(roles==list(expected)[:len(roles)] and (held or roles==list(expected)), 'exact first-login command ledger')
    output = {}
    for index,row in enumerate(commands):
        role=row['role']
        need(set(row)=={'role','argv','exit','stdout','stderr'} and row['argv']==expected[role]
             and type(row['exit']) is int and (row['exit']==0 or held and index==len(commands)-1),
             'first-login original command or exit differs: '+role)
        stdout,stderr=(b64decode(row[stream],validate=True) for stream in ('stdout','stderr'))
        need(len(stdout)<=MAX_LOG and len(stderr)<=MAX_LOG,'first-login command output cap')
        output[role]=stdout
    if value['result'] is None:
        need(held,'missing successful first-login completion')
        return None
    need(roles==list(expected) and all(row['exit']==0 for row in commands),
         'complete natural first-login operation required')
    installed=b''.join(sorted((base+b'cachy-asahi-first-login 0.1.0-2\n').splitlines(keepends=True)))
    for role,wanted in (('first-login-base',base),('first-login-installed',installed),('first-login-removed',base)):
        need(b''.join(sorted(output[role].splitlines(keepends=True)))==wanted,'physical first-login inventory differs: '+role)
    need(good_signature(output['first-login-verify-signature'],supplement['rehearsal']['fingerprint']),'retained first-login TEST signature differs')
    result=value['result']
    journey=json.loads(output['first-login-installed-journey'])
    steps=journey['actor_commands']
    need(journey==result['journey'] and journey['status']=='PASS'
         and journey['command_count']==len(steps)==27 and journey['shell_startups']==10
         and [row['step'] for row in steps]==journey['ordered_steps']
         and journey['recovery_confirmed'] is True and journey['final_components_deactivated'] is True
         and journey['template_and_program_preservation'] is True
         and journey['template_profile']=='fish0.1.0-1-zsh0.1.0-1'
         and journey['uid']==UID and journey['user']==ACCOUNT
         and journey['pty']=='NOT RUN' and journey['graphical_login']=='NOT RUN'
         and set(journey['user_edit_preservation'])=={'.config/fish/config.fish','.zshrc'},
         'first-login installed journey, user edits or semantic acceptance differ')
    for row in steps:
        receipt=row['receipt']
        expected_exit=75 if row['step'].endswith('-interrupted-setup') else 2 if row['step'].endswith(
            ('-pending-inspect','-pending-new-selection-refused','-recover-preview')) else 0
        need(row['expected']==receipt['exit']==expected_exit and receipt['reaped'] is True
             and receipt['ownership']=='REAPED' and receipt['group_census']=='EMPTY_TWICE'
             and receipt['output_complete'] is True and receipt['timeout'] is False
             and receipt['signals']==[] and receipt['error'] is None,
             'first-login held user command custody differs')
    need(result['status']==PASS and result['before']==result['after_removal']==pin(base)
         and result['installed']==pin(installed)==supplement['after']
         and result['native_arm_build']==result['M2']=='NOT RUN' and result['Root_acceptance'] is None
         and result['provenance']['package_arch']=='any' and result['provenance']['host_build']=='x86_64'
         and result['provenance']['native_arm_build']=='NOT RUN' and result['provenance']['original_test_signer']==SIGNER
         and result['rehearsal']==supplement['rehearsal'],
         'first-login result is not the exact permitted artifact and transition')
    return result
