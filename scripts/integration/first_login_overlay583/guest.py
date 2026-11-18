# SPDX-License-Identifier: MIT
"""One guest-only extension to the verified Overlay583 installed target."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import re

SUPPLEMENT = Path('/trial-code/first-login')
TARGET_WORK = Path('/run/caa-first-login-overlay583')
PKG = 'cachy-asahi-first-login'
ACCOUNT = 'caa-first-login-guest'
UID = 29083
PROGRAMS = {
    'usr/bin/cachy-asahi-first-login': 'LAUNCHER_SHA',
    'usr/lib/cachy-asahi/first-login/first_login.py': 'BACKEND_SHA',
}


def good_signature(status, fingerprint):
    valid = [line.split() for line in status.decode('ascii').splitlines()
             if line.startswith('[GNUPG:] VALIDSIG ')]
    return len(valid) == 1 and valid[0][2] == valid[0][-1] == fingerprint


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
    need(raw == trial.encoded(packet) and packet['kind'] == 'FIRST_LOGIN_OVERLAY583_SUPPLEMENT_V1'
         and packet['Root_authority'] is None and packet['installation'] == 'NOT RUN', 'finite staging DATA only')
    need({path.name for path in SUPPLEMENT.iterdir()}==set(packet['files'])|{'supplement.json'},
         'exact read-only supplement leaf set')
    stage = load_stage(trial, packet)
    files = {name: trial.read(SUPPLEMENT/name, pin, cap=128*1024) for name, pin in packet['files'].items()}
    before = trial.read(trial.IN/'target.lock', stage.TARGET, cap=256*1024)
    need(packet['overlay_before'] == stage.TARGET and packet['preflight']['sha256'] == stage.PREFLIGHT_SHA
         and packet['provenance'] == stage.PROVENANCE and packet['template_profile'] == 'fish0.1.0-1-zsh0.1.0-1',
         'exact authenticated Overlay583 and supplemental package provenance')
    after = trial.sorted_rows(before+b'cachy-asahi-first-login 0.1.0-2\n')
    need(packet['overlay_after'] == trial.pin(after), 'exact single-package installed inventory')
    trial.canonical_lock(before, 583)
    trial.canonical_lock(after, 584)
    return exercise(trial,stage,target,before,after,files,nonce,env,command)


def exercise(trial, stage, target, before, after, files, nonce, env, command):
    need=trial.need
    trust = trial.ordinary(trial.WORK/'trust')
    need(env.get('GNUPGHOME') == str(trust) and trust.is_dir(), 'existing guest-only private trust directory')
    config = trial.read(trial.CONFIG, cap=4096).decode('ascii')
    need('SigLevel = Required TrustedOnly' in config.splitlines()
         and 'LocalFileSigLevel = Required TrustedOnly' in config.splitlines(), 'existing required signature policy')
    package = SUPPLEMENT/stage.ARCHIVE
    pacman = ['/usr/bin/pacman', '--config', str(trial.CONFIG), '--root', str(target),
              '--dbpath', str(target/'var/lib/pacman'), '--gpgdir', str(trust),
              '--cachedir',str(trial.WORK/'cache'),'--logfile',str(trial.WORK/'first-login-addon-pacman.log')]
    gpg = ['/usr/bin/gpg', '--batch', '--no-options', '--homedir', str(trust)]
    chroot = ['/usr/bin/chroot', str(target)]
    user = TARGET_WORK/'home'

    def checked_inventory(step, expected):
        observed = trial.sorted_rows(command(step, [*pacman,'--query'], 45))
        need(observed == expected, 'complete installed inventory differs: '+step)
        command(step+'-deps', [*pacman, '--database', '--check'], 45)
        return trial.pin(observed)

    initial = checked_inventory('first-login-base', before)
    command('first-login-import-public', [*gpg,'--import'], 25, files['project-public.gpg'])
    verified = command('first-login-verify-signature', [*gpg,'--status-fd','1','--verify',str(package)+'.sig',str(package)], 25)
    need(good_signature(verified,stage.SIGNER), 'exact selected TEST detached package signature required')
    command('first-login-trust-fixture', [*gpg,'--import-ownertrust'], 25, (stage.SIGNER+':6:\n').encode())

    with ExitStack() as stack:
        trial.target_api_mounts(target, env, stack)
        target_work = target/TARGET_WORK.relative_to('/')
        target_work.mkdir(mode=0o755)
        for name in ('journey.py','target.py','owned_process.py'):
            (target_work/name).write_bytes(files[name])
        install = [*pacman,'--upgrade','--noconfirm','--',str(package)]
        command('first-login-install', install, 90)
        installed = checked_inventory('first-login-installed',after)
        need(all(trial.pin(trial.read(target/relative,cap=128*1024))['sha256'] == getattr(stage, attr)
                 for relative,attr in PROGRAMS.items()), 'exact installed FirstLogin launcher and backend')
        command('first-login-create-fixture-user',
                [*chroot,'/usr/bin/useradd','--no-create-home','--user-group','--uid',str(UID),
                 '--home-dir',str(user),'--shell','/usr/bin/nologin',ACCOUNT], 20)
        journey = json.loads(command('first-login-installed-journey',
                                     [*chroot,'/usr/bin/python3','-I','-B',str(TARGET_WORK/'target.py'),nonce], 210))
        need(journey['status'] == 'PASS' and journey['command_count'] == 27 and journey['shell_startups'] == 10
             and journey['recovery_confirmed'] and journey['final_components_deactivated'],
             'complete actual installed first-login and real Setup8 shell/recovery journey')
        command('first-login-uninstall',[*pacman,'--remove','--noconfirm','--',PKG],90)
        removed = checked_inventory('first-login-removed',before)
        need(all(not (target/relative).exists() and not (target/relative).is_symlink() for relative in PROGRAMS),
             'installed FirstLogin program files survived removal')
        home = target/user.relative_to('/')
        preserved = journey['user_edit_preservation']
        need(set(preserved) == {'.config/fish/config.fish','.zshrc'}
             and all(trial.pin(trial.read(home/name,cap=1024**2))['sha256'] == digest for name,digest in preserved.items()),
             'first-login removal must preserve the exact user edits')
        command('first-login-remove-fixture-user',[*chroot,'/usr/bin/userdel',ACCOUNT],20)

    return dict(status='PASS_ARM16K_OVERLAY583_FIRST_LOGIN_INSTALLED_LIFECYCLE', before=initial, installed=installed,
                after_removal=removed, journey=journey, provenance=stage.PROVENANCE,
                native_arm_build='NOT RUN', M2='NOT RUN', Root_acceptance=None)


def load_stage(trial, packet):
    """Load only fixed selected read-only setup metadata from the mounted supplement."""
    from types import ModuleType

    files = packet['files']
    trial.need(set(files) == {'stage.py','guest.py','target.py','journey.py','owned_process.py',
                              'cachy-asahi-first-login-0.1.0-2-any.pkg.tar.zst',
                              'cachy-asahi-first-login-0.1.0-2-any.pkg.tar.zst.sig','project-public.gpg'},
               'closed supplement file set')
    path = SUPPLEMENT/'stage.py'
    raw = trial.read(path, files['stage.py'], cap=64*1024)
    stage = ModuleType('first_login_overlay_stage_pins')
    stage.__file__ = str(path)
    exec(compile(raw,str(path),'exec'),stage.__dict__)
    trial.need(all(files[name] == pin for name,pin in stage.MATERIALS.items())
               and files['journey.py']['sha256'] == stage.JOURNEY_SHA
               and files['owned_process.py']['sha256'] == stage.PROCESS_SHA, 'exact signed archive and unchanged helper pins')
    return stage
