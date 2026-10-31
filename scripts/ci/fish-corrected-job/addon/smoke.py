#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SOURCE ONLY, NOT RUN: future selected container lifecycle and private Fish probe.

No actors run on import. CLI lifecycle is root-only; all Fish cases run as alarm.
The caller supplies an absolute monotonic deadline, nonce, repo and TEST signer.
"""
import argparse
import errno
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import pty
import re
import select
import shlex
import signal
import stat
import struct
import subprocess
import sys
import termios
import time
from urllib.parse import unquote

ROOT = Path('/home/alarm/fish-history-sentinel')
WRAPPER = '/usr/share/cachy-asahi/fish-bang-bang/opt-in.fish'
HELPER = '/fish-original-config.fish'
HELPER_SHA = '223df59fe83948e1d83676f4571cd2d4ce186862adf1cc23da6d5bbd28370a1c'
PACKAGE = 'cachy-asahi-fish-bang-bang'
PHASES = ('installed-v1', 'upgraded-v2', 'removed', 'reinstalled-v2', 'removed-final')
VERSIONS = ('0.1.0-1', '0.1.0-2', None, '0.1.0-2', None)
CAP = 256 * 1024
PINS = {
 'usr/share/cachy-asahi/fish-bang-bang/__history_previous_command.fish': (170, 'd34b75125a34199775eaa74dd47ae37488c4e67f95f40f71b101b6a8f6f32e50'),
 'usr/share/cachy-asahi/fish-bang-bang/__history_previous_command_arguments.fish': (198, '4e72dcce435d0fe1cf332fb339ed9608f10b29295b28f85ed6e7411ef8c05b64'),
 'usr/share/cachy-asahi/fish-bang-bang/opt-in.fish': (2599, 'd4dbd9dc123ebb31f821afd78c4b55554b4f17929d214baff35e405436e4cce7'),
 'usr/share/cachy-asahi/fish-bang-bang/README.md': (2810, '37a52ff036984a5beb4f42b8837a78f3de3391081240b470177ecc0b03aa6890'),
 'usr/share/licenses/cachy-asahi-fish-bang-bang/NOTICE': (811, '0704c1ff8bcd8c94ad40888b35c5e25468ea9152b5781e7722ff0d04fb8aa879'),
 'usr/share/licenses/cachy-asahi-fish-bang-bang/LICENSE.upstream': (1108, '14c6826a7e33a6c74194ece88b26b5f5aee8473474001946a73d0f298b69fce0'),
 'usr/share/licenses/cachy-asahi-fish-bang-bang/LICENSE.project': (1081, '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7')}

class Refused(ValueError):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def live(end):
    need(type(end) in (int, float) and math.isfinite(end) and time.monotonic() < end, 'deadline')
    return end - time.monotonic()

def decode(raw):
    need(type(raw) is bytes and len(raw) <= 1024 * 1024, 'json-bound')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'json-duplicate')
            result[key] = value
        return result
    def finite(value):
        if type(value) is float:
            need(math.isfinite(value), 'json-nonfinite')
        elif type(value) is dict:
            for child in value.values(): finite(child)
        elif type(value) is list:
            for child in value: finite(child)
    try:
        result = json.loads(raw, object_pairs_hook=pairs,
                            parse_constant=lambda _: need(False, 'json-nonfinite'))
        finite(result)
        return result
    except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise Refused('json-structure') from error

def q(text):
    return "'" + str(text).replace('\\', '\\\\').replace("'", "\\'") + "'"

def regular(path, cap=CAP):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= cap, 'regular-file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        need(stat.S_ISREG(opened.st_mode) and (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), 'file-drift')
        raw = bytearray()
        while block := os.read(fd, min(65536, cap + 1 - len(raw))):
            raw.extend(block)
            need(len(raw) <= cap, 'file-bound')
        after = path.lstat()
        fields = ('st_dev','st_ino','st_size','st_mode','st_mtime_ns','st_ctime_ns','st_nlink')
        need(all(getattr(before,k) == getattr(s,k) for s in (opened, os.fstat(fd), after) for k in fields), 'file-drift')
        return bytes(raw), before
    finally:
        os.close(fd)

def snapshot(root):
    result = {}
    for name in ('config/fish/config.fish', 'config/fish/functions/__history_previous_command.fish',
                 'config/fish/functions/fish_user_key_bindings.fish', 'data/fish/protected_history', 'user-opt-in.fish'):
        raw, s = regular(root / name)
        result[name] = dict(sha256=sha(raw), bytes=len(raw), mode=stat.S_IMODE(s.st_mode),
                            mtime_ns=s.st_mtime_ns, nlink=s.st_nlink, uid=s.st_uid, gid=s.st_gid)
    return result

def save(path, value):
    raw = (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode()
    need(len(raw) <= 1024 * 1024, 'journal-bound')
    temporary = path.with_name(path.name + '.new')
    with temporary.open('xb') as stream:
        os.chmod(temporary, 0o600)
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)

class Journal:
    def __init__(self, path, value):
        self.path, self.value = path, value
        self.persist()
    def persist(self):
        save(self.path, self.value)
    def fail(self, code):
        if self.value['first_failure'] is None:
            self.value['first_failure'] = code
        self.value['status'] = 'FAIL'
        self.persist()

def dispose(actions, primary=None):
    first = None
    for action in actions:
        try: action()
        except BaseException as error:
            if first is None: first = error
            if primary is not None and isinstance(error,KeyboardInterrupt):
                primary.fish_cleanup_cancelled = True
    if primary is None and first is not None: raise first

def command(argv, end, env=None, require_zero=True):
    """Natural return is recorded; bounded output, no shell argument evaluation."""
    live(end)
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, start_new_session=True)
    raw = bytearray(); natural = False; primary = None
    try:
        fd = process.stdout.fileno()
        while True:
            live(end)
            if select.select([fd], [], [], min(0.1, live(end)))[0]:
                block = os.read(fd, 65536)
                if not block: break
                raw.extend(block); need(len(raw) <= CAP, 'command-output-bound')
        code = process.wait(timeout=live(end)); natural = True
        need(type(code) is int and (not require_zero or code == 0), 'command-return')
        return bytes(raw) if require_zero else (bytes(raw),code)
    except BaseException as error:
        primary = error
        raise
    finally:
        dispose((lambda: os.killpg(process.pid, signal.SIGKILL) if process.poll() is None else None,
                 lambda: process.wait(timeout=max(0, min(2, end - time.monotonic()))),
                 process.stdout.close), primary)
        if primary is None: need(natural, 'command-interrupted')

def environment(root, name):
    base = root / 'cases' / name
    for leaf in ('config', 'data', 'cache', 'runtime', 'config-dirs'):
        (base / leaf).mkdir(mode=0o700, parents=True, exist_ok=True)
    env = os.environ.copy()
    for key in ('fish_function_path', 'fish_complete_path', 'FISH_DEBUG', 'FISH_DEBUG_OUTPUT'):
        env.pop(key, None)
    for key, leaf in (('XDG_CONFIG_HOME','config'), ('XDG_DATA_HOME','data'), ('XDG_CACHE_HOME','cache'),
                      ('XDG_RUNTIME_DIR','runtime'), ('XDG_CONFIG_DIRS','config-dirs')):
        env[key] = str(base / leaf)
    env.update(fish_history=name, TERM='xterm-256color')
    need(env.get('HOME') == os.environ.get('HOME'), 'home-changed')
    return env

GUARDED = 'if test -r ' + q(WRAPPER) + '; source ' + q(WRAPPER) + '; end; '
NONE = 'not functions -q caa_history_bang; and not functions -q caa_history_argument'

def cases(installed):
    cli = {
      'guarded-user-line': 'source ' + q(ROOT / 'user-opt-in.fish') + '; ' + ('functions -q caa_history_bang caa_history_argument' if installed else NONE),
      'original-helpers': 'source ' + q(HELPER) + '; set -l before (functions caa_ll caa_mcd | string collect); ' + GUARDED * 2 + 'test "$before" = "$(functions caa_ll caa_mcd | string collect)"',
      'user-module': 'set -p fish_function_path ' + q(ROOT / 'config/fish/functions') + '; functions -q __history_previous_command; set -l before (functions __history_previous_command | string collect); ' + GUARDED * 2 + 'test "$before" = "$(functions __history_previous_command | string collect)"; and ' + NONE,
      'user-key-module': 'set -p fish_function_path ' + q(ROOT / 'config/fish/functions') + '; fish_user_key_bindings; set -l before (bind --user --mode default | string collect); ' + GUARDED * 2 + 'test "$before" = "$(bind --user --mode default | string collect)"; and ' + NONE,
      'noninteractive': GUARDED + NONE,
      'generic-user-binding': 'bind --user --mode default \"\" self-insert; ' + GUARDED + NONE,
      'existing-function': 'function caa_history_bang; printf OWNED; end; set -l before (functions caa_history_bang | string collect); ' + GUARDED * 2 + 'test \"$before\" = \"$(functions caa_history_bang | string collect)\"',
      'guarded-repeat': GUARDED + 'set -l before (bind --user --mode default | string collect); ' + GUARDED + 'test "$before" = "$(bind --user --mode default | string collect)"',
    }
    for name, keys in (('existing-bang','!'), ('existing-dollar','$'), ('prefix-bang','!,a'), ('prefix-dollar','$,a')):
        cli[name] = 'bind --user --mode default ' + q(keys) + ' self-insert; set -l before (bind --user --mode default | string collect); ' + GUARDED * 2 + 'test "$before" = "$(bind --user --mode default | string collect)"; and ' + NONE
    pty_cases = [('bang', '!!', 'echo CONTROLLED_PREVIOUS', 'echo CONTROLLED_PREVIOUS'),
                 ('argument', '!$', '"two words"', 'printf "%s\\n" "two words"'),
                 ('argument-prefix', 'echo !$', 'echo "two words"', 'printf "%s\\n" "two words"'),
                 ('literal-dollar', 'echo $', 'echo $', 'echo PREVIOUS'),
                 ('quoted-literal', 'echo "!$"', 'echo "!$"', 'echo PREVIOUS'),
                 ('protected-history', '!!', 'echo PROTECTED_HISTORY', None),
                 ('empty-bang', '!!', '!!', None), ('empty-argument', '!$', '!$', None),
                 ('vi-insert', '!!', 'echo VI_PREVIOUS', 'echo VI_PREVIOUS'),
                 ('hybrid-insert', '!!', 'echo HYBRID_PREVIOUS', 'echo HYBRID_PREVIOUS'),
                 ('cancel-line', '!!', 'echo CANCEL_PREVIOUS', 'echo CANCEL_PREVIOUS')]
    if not installed:
        pty_cases = [('removed-bang', '!!', '!!', 'echo CONTROLLED_PREVIOUS'),
                     ('removed-argument', '!$', '!$', 'echo CONTROLLED_PREVIOUS')]
    return cli, pty_cases

def child_setup():
    os.setsid(); fcntl.ioctl(0, termios.TIOCSCTTY, 0)

def terminal(root, name, typed, expected, previous, end):
    need('\n' not in typed and '\r' not in typed, 'expanded-enter-forbidden')
    master = slave = None; process = None; raw = bytearray(); natural = False; primary = None
    try:
        live(end); master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH',24,120,0,0))
        keyset = 'fish_vi_key_bindings' if name == 'vi-insert' else 'fish_hybrid_key_bindings' if name == 'hybrid-insert' else 'fish_default_key_bindings'
        setup = 'set -g fish_key_bindings ' + keyset + '; ' + keyset + '; ' + ('set -g fish_bind_mode insert; ' if keyset != 'fish_default_key_bindings' else '') + 'function fish_greeting; end; function fish_prompt; printf "__READY__>"; end; function fish_right_prompt; end; '
        setup += 'function __capture; printf "\\n__BUFFER__%s__END__\\n" (string escape --style=url -- "$(commandline -b)"); commandline -r ""; end; bind --user --mode default ctrl-g __capture; bind --user --mode insert ctrl-g __capture; '
        setup += GUARDED
        if previous is not None: setup += 'builtin history append -- ' + q(previous) + '; '
        env = environment(root, name)
        if name == 'protected-history':
            env['XDG_DATA_HOME'] = str(root / 'data'); env['fish_history'] = 'protected'
        process = subprocess.Popen(['/usr/bin/fish','--no-config','--private','--interactive','--init-command',setup], stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=child_setup)
        os.close(slave); slave = None
        def until(pattern):
            while not re.search(pattern, raw, re.S):
                live(end)
                if select.select([master],[],[],min(0.1,live(end)))[0]:
                    block = os.read(master,65536)
                    need(block, 'pty-eof'); raw.extend(block); need(len(raw) <= CAP,'pty-bound')
                    if b'\x1b[0c' in block: os.write(master,b'\x1b[?1;2c')
        until(b'__READY__>'); os.write(master, typed.encode() + b'\x07'); until(b'__BUFFER__(.*?)__END__')
        matches = re.findall(b'__BUFFER__(.*?)__END__', raw, re.S)
        need(len(matches) == 1, 'pty-buffer-count')
        actual = unquote(matches[0].decode('ascii'))
        need(actual == expected and b'USER_CONFIG_MUST_NOT_RUN' not in raw, 'pty-value')
        if name == 'cancel-line':
            os.write(master,b'CONTROLLED_CANCEL\x03\x07')
            until(b'__BUFFER__.*?__END__.*?__BUFFER__(.*?)__END__')
            matches = re.findall(b'__BUFFER__(.*?)__END__', raw, re.S)
            need(len(matches)==2 and unquote(matches[-1].decode('ascii'))=='' and process.poll() is None,'pty-cancel')
        # The capture function cleared the buffer. Only builtin exit receives Enter.
        os.write(master,b'\x03exit\n'); code = process.wait(timeout=live(end))
        need(type(code) is int and code == 0,'pty-return'); natural = True
        return dict(name=name, kind='pty', status='PASS', output_sha256=sha(raw),
                    natural_return_zero=True, cleanup=True, expanded_enter=False)
    except BaseException as error:
        primary = error
        raise
    finally:
        actions=[]
        if process is not None:
            actions.extend((lambda: os.killpg(process.pid,signal.SIGKILL) if process.poll() is None else None,
                            lambda: process.wait(timeout=max(0,min(2,end-time.monotonic())))))
        if slave is not None: actions.append(lambda: os.close(slave))
        if master is not None: actions.append(lambda: os.close(master))
        dispose(actions, primary)
        if primary is None: need(natural, 'pty-interrupted')

def prepare(root, end):
    live(end); need(not root.exists() and not root.is_symlink(), 'fixture-exists')
    root.mkdir(mode=0o700)
    for leaf in ('config/fish/functions','data/fish','cache','runtime','config-dirs','evidence'):
        (root / leaf).mkdir(mode=0o700, parents=True, exist_ok=True)
    files = {
      'config/fish/config.fish': 'printf USER_CONFIG_MUST_NOT_RUN\n',
      'config/fish/functions/__history_previous_command.fish': 'function __history_previous_command; printf OWNED_AUTOLOAD; end\n',
      'config/fish/functions/fish_user_key_bindings.fish': 'function fish_user_key_bindings; bind --user --mode default \\! self-insert; end\n',
      'data/fish/protected_history': '- cmd: echo PROTECTED_HISTORY\n  when: 1\n',
      'user-opt-in.fish': GUARDED + '\n'}
    for name, text in files.items():
        with (root / name).open('x') as stream: stream.write(text)
        (root / name).chmod(0o600)
    save(root / 'evidence/baseline.json', snapshot(root))

def probe(root, phase, end):
    live(end); need(root == ROOT and os.getuid() == 1000 and platform.machine() == 'aarch64', 'probe-context')
    if phase == 'prepare': prepare(root,end)
    baseline = decode(regular(root / 'evidence/baseline.json')[0])
    report = dict(schema_version=1, phase=phase, status='STARTED', first_failure=None,
                  protected_before=snapshot(root), protected_after=None, cases=[], payload=None,
                  HOME_overridden=False, expanded_commands_executed=False, cancelled=False)
    journal = Journal(root / ('evidence/' + phase + '.json'), report)
    try:
        need(report['protected_before'] == baseline, 'protected-before')
        helper, _ = regular(Path(HELPER)); need(sha(helper) == HELPER_SHA, 'original-helper-pin')
        if phase in PHASES:
            installed = VERSIONS[PHASES.index(phase)] is not None
            payload = {}
            for name,(size,digest) in PINS.items():
                path=Path('/') / name
                if installed:
                    raw,s=regular(path)
                    need(len(raw)==size and sha(raw)==digest and stat.S_IMODE(s.st_mode)==0o644 and s.st_uid==s.st_gid==0,'payload-pin')
                else: need(not path.exists() and not path.is_symlink(),'payload-remains')
                payload[name] = 'PINNED' if installed else 'ABSENT'
            report['payload']=payload; journal.persist()
            cli, terminal_cases = cases(installed)
            for name, predicate in cli.items():
                live(end)
                report['cases'].append(dict(name=name,kind='cli',status='STARTED')); journal.persist()
                need(snapshot(root)==baseline,'protected-case-before')
                setup='fish_default_key_bindings; '+predicate+'; or exit 41; printf "\\n__CASE_PASS__\\n"'
                argv=['/usr/bin/fish','--no-config','--private']+([] if name=='noninteractive' else ['--interactive'])+['--command',setup]
                raw=command(argv,end,environment(root,name))
                need(snapshot(root)==baseline,'protected-case-after')
                need(raw.count(b'__CASE_PASS__')==1 and b'USER_CONFIG_MUST_NOT_RUN' not in raw,'cli-marker')
                report['cases'][-1].update(dict(name=name,kind='cli',status='PASS',output_sha256=sha(raw),natural_return_zero=True,cleanup=True,expanded_enter=False)); journal.persist()
            for name,typed,expected,previous in terminal_cases:
                report['cases'].append(dict(name=name,kind='pty',status='STARTED')); journal.persist()
                need(snapshot(root)==baseline,'protected-case-before')
                report['cases'][-1] = terminal(root,name,typed,expected,previous,end)
                need(snapshot(root)==baseline,'protected-case-after'); journal.persist()
        report['protected_after']=snapshot(root)
        need(report['protected_after']==baseline,'protected-after')
        live(end); report['status']='PASS'; journal.persist()
        return report
    except BaseException as error:
        report['cancelled']=isinstance(error,KeyboardInterrupt) or getattr(error,'fish_cleanup_cancelled',False) is True
        journal.fail(error.args[0] if type(error) is Refused else 'probe-error')
        return report

def validate_lifecycle(value):
    """Closed admission schema. Pure; safe for the selected engine to embed."""
    def require(test):
        if not test: raise ValueError('fish-lifecycle-evidence')
    def pin(text):
        require(type(text) is str and len(text)==64 and all(c in '0123456789abcdef' for c in text))
    require(type(value) is dict and set(value)=={'schema_version','scope','status','nonce','deadline','fingerprint','phases','inventory_before_sha256','inventory_after_sha256','inventory_restored','ownership','first_failure','cancelled','cleanup','hardware','progress'})
    require(type(value['schema_version']) is int and value['schema_version']==1 and value['scope']=='fish-history-lifecycle' and value['status']=='PASS')
    require(type(value['nonce']) is str and len(value['nonce'])==32 and all(c in '0123456789abcdef' for c in value['nonce']))
    require(type(value['deadline']) in (int,float) and value['deadline']>0 and value['deadline']<float('inf'))
    require(type(value['fingerprint']) is str and len(value['fingerprint'])==40 and all(c in '0123456789ABCDEF' for c in value['fingerprint']))
    require(value['first_failure'] is None and value['cancelled'] is False and value['cleanup'] is True and value['inventory_restored'] is True and value['hardware']=='NOT_RUN')
    pin(value['inventory_before_sha256']); pin(value['inventory_after_sha256'])
    require(value['inventory_before_sha256']==value['inventory_after_sha256'])
    phases=('prepare','installed-v1','upgraded-v2','removed','reinstalled-v2','removed-final','baseline')
    require(type(value['phases']) is list and len(value['phases'])==7)
    baseline=None
    for phase,row in zip(phases,value['phases']):
        require(type(row) is dict and set(row)=={'schema_version','phase','status','first_failure','protected_before','protected_after','cases','payload','HOME_overridden','expanded_commands_executed','cancelled'})
        require(type(row['schema_version']) is int and row['schema_version']==1 and row['phase']==phase and row['status']=='PASS' and row['first_failure'] is None and row['HOME_overridden'] is False and row['expanded_commands_executed'] is False and row['cancelled'] is False)
        names={'config/fish/config.fish','config/fish/functions/__history_previous_command.fish','config/fish/functions/fish_user_key_bindings.fish','data/fish/protected_history','user-opt-in.fish'}
        for field in ('protected_before','protected_after'):
            records=row[field]; require(type(records) is dict and set(records)==names)
            for record in records.values():
                require(type(record) is dict and set(record)=={'sha256','bytes','mode','mtime_ns','nlink','uid','gid'})
                pin(record['sha256'])
                require(type(record['bytes']) is int and 0<record['bytes']<=262144 and type(record['mode']) is int and record['mode']==384 and type(record['mtime_ns']) is int and record['mtime_ns']>=0 and type(record['nlink']) is int and record['nlink']==1 and type(record['uid']) is int and record['uid']==1000 and type(record['gid']) is int and record['gid']==1000)
            if baseline is None: baseline=records
            require(records==baseline)
        cli={'guarded-user-line','original-helpers','user-module','user-key-module','guarded-repeat','noninteractive','generic-user-binding','existing-function','existing-bang','existing-dollar','prefix-bang','prefix-dollar'}
        installed=phase in ('installed-v1','upgraded-v2','reinstalled-v2')
        expected=cli|({'bang','argument','argument-prefix','literal-dollar','quoted-literal','protected-history','empty-bang','empty-argument','vi-insert','hybrid-insert','cancel-line'} if installed else {'removed-bang','removed-argument'}) if phase not in ('prepare','baseline') else set()
        require(type(row['cases']) is list and len(row['cases'])==len(expected))
        require(all(type(r) is dict and type(r.get('name')) is str for r in row['cases']))
        require({r['name'] for r in row['cases']}==expected)
        for record in row['cases']:
            require(type(record) is dict and set(record)=={'name','kind','status','output_sha256','natural_return_zero','cleanup','expanded_enter'})
            require(record['kind']==('cli' if record['name'] in cli else 'pty') and record['status']=='PASS' and record['natural_return_zero'] is True and record['cleanup'] is True and record['expanded_enter'] is False); pin(record['output_sha256'])
        owned={'usr/share/cachy-asahi/fish-bang-bang/'+n for n in ('__history_previous_command.fish','__history_previous_command_arguments.fish','opt-in.fish','README.md')}|{'usr/share/licenses/cachy-asahi-fish-bang-bang/'+n for n in ('NOTICE','LICENSE.upstream','LICENSE.project')}
        if phase in ('prepare','baseline'): require(row['payload'] is None)
        else: require(type(row['payload']) is dict and set(row['payload'])==owned and all(type(v) is str for v in row['payload'].values()) and set(row['payload'].values())=={'PINNED' if installed else 'ABSENT'})
    require(type(value['ownership']) is list and len(value['ownership'])==5)
    for phase,version,row in zip(phases[1:6],('0.1.0-1','0.1.0-2',None,'0.1.0-2',None),value['ownership']):
        require(type(row) is dict and set(row)=={'phase','version','paths','owners','integrity_zero'})
        require(row['phase']==phase and row['version']==version and type(row['paths']) is list and row['paths']==sorted(owned) and type(row['owners']) is dict and set(row['owners'])==owned and all(type(v) is str for v in row['owners'].values()) and set(row['owners'].values())=={'cachy-asahi-fish-bang-bang' if version else 'ABSENT'} and row['integrity_zero'] is True)
    expected=['inventory-before','probe-prepare','certificate','import-test-certificate','local-sign-test-certificate']
    for phase in phases[1:6]:
        if phase in ('installed-v1','upgraded-v2','reinstalled-v2'):
            expected += [phase+'.install',phase+'.version',phase+'.integrity',phase+'.paths']+[phase+'.owner']*7
        else: expected += [phase+'.remove']
        expected += ['probe-'+phase]
    expected += ['probe-baseline','inventory-after']
    require(type(value['progress']) is list and len(value['progress'])==len(expected))
    for operation,row in zip(expected,value['progress']):
        require(type(row) is dict and set(row)=={'operation','status','output_sha256','natural_return_zero'})
        require(row['operation']==operation and row['status']=='PASS' and row['natural_return_zero'] is True)
        pin(row['output_sha256'])
    return value

def inventory(raw):
    need(type(raw) is bytes and raw.endswith(b'\n') and len(raw)<=CAP,'inventory-format')
    rows=raw.splitlines(); names=[]
    for row in rows:
        parts=row.split(b' ')
        need(len(parts)==2 and all(parts) and all(32<c<127 for part in parts for c in part),'inventory-format')
        names.append(parts[0])
    need(len(names)==len(set(names)),'inventory-duplicate')
    return b'\n'.join(sorted(rows))+b'\n'

def certificate(raw, fingerprint):
    primary=[]; active=False
    for line in raw.decode('ascii').splitlines():
        fields=line.split(':')
        if fields[0]=='pub': active=True
        elif fields[0]=='sub': active=False
        elif fields[0]=='fpr' and active:
            need(len(fields)>9,'certificate-format'); primary.append(fields[9]); active=False
    need(primary==[fingerprint],'certificate-fingerprint')

def lifecycle(end, nonce):
    live(end)
    fp=os.environ.get('FISH_SIGNER_FP','')
    need(os.getuid()==0 and platform.machine()=='aarch64' and os.environ.get('CACHY_ASAHI_CONTAINER')=='1' and Path('/.dockerenv').is_file(),'lifecycle-context')
    need(re.fullmatch('[A-F0-9]{40}',fp) and re.fullmatch('[a-f0-9]{32}',nonce),'lifecycle-binding')
    need(not ROOT.exists() and not ROOT.is_symlink(),'fixture-exists')
    work=Path('/tmp')/('fish-history-lifecycle-'+nonce); work.mkdir(mode=0o700)
    record=dict(schema_version=1,scope='fish-history-lifecycle',status='STARTED',nonce=nonce,deadline=end,fingerprint=fp,phases=[],inventory_before_sha256=None,inventory_after_sha256=None,inventory_restored=False,ownership=[],first_failure=None,cancelled=False,cleanup=False,hardware='NOT_RUN',progress=[])
    journal=Journal(work/'receipt.json',record)
    def fail(code): journal.fail(code)
    def started(operation):
        row=dict(operation=operation,status='STARTED',output_sha256=None,natural_return_zero=None)
        record['progress'].append(row); journal.persist(); return row
    def run(argv,operation):
        row=started(operation)
        try:
            raw=command(argv,end)
            row.update(status='PASS',output_sha256=sha(raw),natural_return_zero=True); journal.persist()
            return raw
        except BaseException as error:
            fail(error.args[0] if type(error) is Refused else 'lifecycle-command'); raise
    def user(phase):
        argv=['/usr/bin/python3','-I','-B','/fish-history-probe.py','--phase',phase,'--root',str(ROOT),'--deadline',str(end)]
        row=started('probe-'+phase)
        raw,code=command(['/usr/bin/su','-m','alarm','-s','/bin/sh','-c',shlex.join(argv)],end,require_zero=False)
        result=decode(raw); record['phases'].append(result)
        if type(result) is dict and result.get('cancelled') is True: record['cancelled']=True
        journal.persist()
        need(type(code) is int and code==0 and result.get('status')=='PASS','probe-failed')
        row.update(status='PASS',output_sha256=sha(raw),natural_return_zero=True); journal.persist()
    before=None; installed=False
    try:
        before=inventory(run(['/usr/bin/pacman','-Q'],'inventory-before')); record['inventory_before_sha256']=sha(before)
        need(not any(line.split()[0]==PACKAGE.encode() for line in before.splitlines()),'package-baseline')
        user('prepare')
        certificate(run(['/usr/bin/gpg','--no-autostart','--batch','--no-options','--homedir','/etc/pacman.d/gnupg','--no-auto-key-retrieve','--with-colons','--show-keys','/repo/public-key.asc'],'certificate'),fp)
        run(['/usr/bin/pacman-key','--add','/repo/public-key.asc'],'import-test-certificate')
        # The selected engine has already bound the exact TEST certificate and keyring.
        run(['/usr/bin/pacman-key','--lsign-key',fp],'local-sign-test-certificate')
        config=work/'pacman.conf'
        for phase,version in zip(PHASES,VERSIONS):
            live(end)
            if version:
                variant='v1' if version=='0.1.0-1' else 'v2'
                config.write_text('[options]\nArchitecture = aarch64\nHookDir = /builder-disabled-hooks\nSigLevel = Required DatabaseRequired\nLocalFileSigLevel = Required\n[fish-history]\nServer = file:///repo/'+variant+'\n'); config.chmod(0o600)
                installed=True  # Cleanup also covers a partially failed transaction.
                run(['/usr/bin/pacman','--config',str(config),'--cachedir',str(work/'cache'),'--noconfirm','-Sy',PACKAGE],phase+'.install')
                need(run(['/usr/bin/pacman','-Q',PACKAGE],phase+'.version').decode().strip()==PACKAGE+' '+version,'package-version')
                run(['/usr/bin/pacman','-Qkk',PACKAGE],phase+'.integrity')
                paths=sorted(line.lstrip('/') for line in run(['/usr/bin/pacman','-Qlq',PACKAGE],phase+'.paths').decode().splitlines() if not line.endswith('/'))
                need(paths==sorted(PINS),'package-paths')
                owners={name:run(['/usr/bin/pacman','-Qqo','/'+name],phase+'.owner').decode().strip() for name in paths}
                need(set(owners.values())=={PACKAGE},'package-owners')
            else:
                run(['/usr/bin/pacman','--config',str(config),'--noconfirm','-R',PACKAGE],phase+'.remove'); installed=False
                paths=sorted(PINS); owners={name:'ABSENT' for name in paths}
                need(all(not (Path('/')/name).exists() and not (Path('/')/name).is_symlink() for name in paths),'removed-paths')
            record['ownership'].append(dict(phase=phase,version=version,paths=paths,owners=owners,integrity_zero=True)); journal.persist(); user(phase)
        user('baseline')
    except BaseException as error:
        fail(error.args[0] if type(error) is Refused else 'lifecycle-error')
        record['cancelled']=record['cancelled'] or isinstance(error,KeyboardInterrupt) or getattr(error,'fish_cleanup_cancelled',False) is True
    finally:
        try:
            if installed: run(['/usr/bin/pacman','--config',str(config),'--noconfirm','-R',PACKAGE],'cleanup-remove')
            if before is not None:
                after=inventory(run(['/usr/bin/pacman','-Q'],'inventory-after')); record['inventory_after_sha256']=sha(after)
                record['inventory_restored']=before==after
                need(record['inventory_restored'],'inventory-drift')
            record['cleanup']=not installed or record['inventory_restored']
        except BaseException as error:
            record['cancelled']=record['cancelled'] or isinstance(error,KeyboardInterrupt) or getattr(error,'fish_cleanup_cancelled',False) is True
            fail('lifecycle-cleanup')
        if record['first_failure'] is None:
            record['status']='PASS'
            try: validate_lifecycle(record)
            except (ValueError,TypeError,KeyError): fail('lifecycle-evidence')
        journal.persist()
    return record

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase',choices=('prepare','baseline','lifecycle')+PHASES,required=True)
    parser.add_argument('--root',default=str(ROOT))
    parser.add_argument('--deadline',type=float,required=True)
    parser.add_argument('--nonce',default='')
    args=parser.parse_args()
    def interrupted(signum, frame):
        raise KeyboardInterrupt()
    for signum in (signal.SIGINT, signal.SIGTERM): signal.signal(signum, interrupted)
    try:
        live(args.deadline)
        need(Path(args.root)==ROOT,'fixture-root')
        result=lifecycle(args.deadline,args.nonce) if args.phase=='lifecycle' else probe(ROOT,args.phase,args.deadline)
    except BaseException:
        result={'schema_version':1,'status':'FAIL','first_failure':'preflight'}
    print(json.dumps(result,sort_keys=True,allow_nan=False))
    return 0 if result['status']=='PASS' else 1

if __name__=='__main__':
    raise SystemExit(main())
