#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Freeze side-by-side ARM-C01 packages; execute only in a disposable native job.

prepare and audit never install packages. native-job is an explicit disposable
container entrypoint, not a host installer or performance benchmark.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import shutil
import shlex
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zlib

SOURCE_SHA = 'bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16'
PACKAGES_SHA = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
EPOCH = '1791748800'
VARIANTS = ('baseline', 'lto')
FILES = ('PKGBUILD', 'probe.c', 'strict-gzip.c', 'LICENSE.project')
PACKAGE_ROOT = 'packages/experiments'
HELPER = 'scripts/experiments/package_variants.py'
BASE_FLAGS = '-O2 -g -march=armv8-a -mtune=generic -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -frandom-seed=$@'
LINK_FLAGS = '-pie -Wl,-z,relro,-z,now,-z,max-page-size=65536,-z,common-page-size=16384'
WORK = Path('/tmp/cachy-asahi-zlib-package-build')
META = {'.PKGINFO', '.BUILDINFO', '.MTREE'}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, limit=16 * 1024**2):
    path = Path(path)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_size <= limit and
         not any(p.is_symlink() for p in path.parents), 'bounded regular file required: ' + str(path))
    return path.read_bytes()


def save(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def name(variant):
    need(variant in VARIANTS, 'unknown variant')
    return 'cachy-asahi-zlib-' + variant


def prefix(variant):
    return Path('/usr/lib/cachy-asahi/experiments/zlib-' + variant)


def flags(variant):
    name(variant)
    return (BASE_FLAGS + (' -fno-lto' if variant == 'baseline' else ' -flto=2 -Werror=lto-type-mismatch'),
            LINK_FLAGS + (' -fno-lto' if variant == 'baseline' else ' -flto=2'))



def configured_flags(data, variant):
    values = {}
    for key in ('CC', 'AR', 'RANLIB', 'CFLAGS', 'LDFLAGS', 'prefix'):
        found = re.findall(r'^' + key + r'[ \t]*=[ \t]*([^\n]*)$', data.decode(), re.M)
        need(len(found) == 1, 'one configured assignment required: ' + key)
        values[key] = found[0].strip()
    cflags, ldflags = flags(variant)
    expected, actual = shlex.split(cflags), shlex.split(values['CFLAGS'])
    suffix = actual[len(expected):]
    features = {'-fPIC', '-D_LARGEFILE64_SOURCE=1', '-DNO_FSEEKO', '-DNO_STRERROR', '-DHAVE_HIDDEN',
                '-DHAS_vsnprintf_void', '-DNO_vsnprintf', '-DHAS_vsprintf_void', '-DHAS_snprintf_void',
                '-DNO_snprintf', '-DHAS_sprintf_void'}
    need(actual[:len(expected)] == expected and suffix and suffix[0] == '-fPIC'
         and len(suffix) == len(set(suffix)) and set(suffix) <= features
         and values['LDFLAGS'] == ldflags and values['prefix'] == str(prefix(variant))
         and values['CC'] == 'gcc' and values['AR'] == 'gcc-ar' and values['RANLIB'] == 'gcc-ranlib',
         'effective configured flags/tools/prefix differ')
    return values

def source_material(data):
    need(len(data) == 1502830 and sha(data) == SOURCE_SHA, 'upstream source pin differs')
    seen, total, result = set(), 0, {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            need(path.parts and path.parts[0] == 'zlib-1.3.2' and not path.is_absolute()
                 and '..' not in path.parts and path.as_posix() not in seen
                 and len(seen) < 2048 and (member.isfile() or member.isdir()), 'unsafe upstream archive')
            seen.add(path.as_posix()); total += member.size
            need(0 <= member.size <= 8 * 1024**2 and total <= 16 * 1024**2, 'upstream archive bound')
            if path.as_posix() in ('zlib-1.3.2/LICENSE', 'zlib-1.3.2/README'):
                result[path.name] = archive.extractfile(member).read()
    need(set(result) == {'LICENSE', 'README'}, 'upstream notice/README missing')
    return result


def audit(root):
    """Check static source/flag correspondence; no recipe evaluation or mutation."""
    root = Path(root)
    rows = {}
    for variant in VARIANTS:
        directory = root / PACKAGE_ROOT / name(variant)
        files = {f: read(directory / f) for f in FILES}
        text = files['PKGBUILD'].decode()
        cflags, ldflags = flags(variant)
        pins = [SOURCE_SHA] + [sha(files[f]) for f in FILES[1:]]
        found = re.search(r'sha256sums=\((.*?)\)', text, re.S)
        need(found and re.findall(r"'([0-9a-f]{64})'", found[1]) == pins, 'recipe source pins differ')
        need(f'pkgname={name(variant)}\n' in text and 'pkgver=1.3.2\npkgrel=1\n' in text
             and f'_variant={variant}\n_prefix={prefix(variant)}\n' in text
             and f"export CFLAGS='{cflags}'\n" in text
             and f"export LDFLAGS='{ldflags}'\n" in text, 'package identity/flags differ')
        need("source=('https://zlib.net/zlib-1.3.2.tar.gz' 'probe.c' 'strict-gzip.c' 'LICENSE.project')" in text
             and "arch=('aarch64')" in text and "depends=('glibc')" in text
             and "options=('staticlibs' '!buildflags' '!strip' '!debug' '!lto')" in text,
             'reviewed source/dependencies/options differ')
        need(not re.search(r'^(provides|conflicts|replaces|install|backup)=', text, re.M)
             and 'make install' not in text and 'pacman ' not in text, 'system mutation/replacement refused')
        rows[variant] = {f: sha(data) for f, data in files.items()}
    need(read(root / PACKAGE_ROOT / name('baseline') / 'probe.c') ==
         read(root / PACKAGE_ROOT / name('lto') / 'probe.c'), 'probe source is another variable')
    need(rows['baseline']['strict-gzip.c'] == rows['lto']['strict-gzip.c'] ==
         '369e4e0e3f7c79b5d892edf7476ade41d6647332fb78f95ad7de7d8449bbaca9',
         'strict decoder differs from accepted C01 driver')
    return rows


def prepare(root, source, packages, output, base_commit):
    root, output = Path(root).resolve(), Path(output).absolute()
    need(re.fullmatch('[0-9a-f]{40}', base_commit or ''), 'exact source-base commit required')
    need(not output.exists() and not output.is_symlink() and
         not any(p.is_symlink() for p in output.parents) and
         not output.is_relative_to(root) and not root.is_relative_to(output), 'new disjoint context required')
    rows = audit(root)
    upstream = read(source); source_material(upstream)
    inventory = read(packages)
    need(sha(inventory) == PACKAGES_SHA, 'accepted complete 341-package inventory required')
    material = {HELPER: read(root / HELPER), 'packages.lock': inventory}
    for variant in VARIANTS:
        for f in FILES:
            relative = PACKAGE_ROOT + '/' + name(variant) + '/' + f
            material[relative] = read(root / relative)
        material[PACKAGE_ROOT + '/' + name(variant) + '/zlib-1.3.2.tar.gz'] = upstream
    output.mkdir(mode=0o755)
    for path, data in material.items():
        target = output / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
    contract = {'schema_version': 1, 'purpose': 'ARM-C01-installable-private-prefix',
                'base_commit': base_commit, 'source_sha256': SOURCE_SHA,
                'packages_sha256': PACKAGES_SHA, 'source_date_epoch': EPOCH,
                'files': {p: sha(data) for p, data in material.items()}, 'recipes': rows,
                'native_build': 'NOT RUN', 'installed_behavior': 'NOT RUN',
                'generic16k_execution': 'NOT RUN', 'hardware_validation': 'NOT RUN',
                'performance_acceptance': 'NOT RUN', 'selected_for_release': False}
    save(output / 'context.json', contract)
    return contract


def verify_context(context, pin):
    context = Path(context)
    data = read(context / 'context.json')
    need(re.fullmatch('[0-9a-f]{64}', pin or '') and sha(data) == pin, 'context pin differs')
    contract = json.loads(data)
    expected = {HELPER, 'packages.lock'} | {
        PACKAGE_ROOT + '/' + name(v) + '/' + f for v in VARIANTS for f in (*FILES, 'zlib-1.3.2.tar.gz')}
    need(contract['schema_version'] == 1 and contract['purpose'] == 'ARM-C01-installable-private-prefix'
         and set(contract['files']) == expected and contract['source_sha256'] == SOURCE_SHA
         and contract['packages_sha256'] == PACKAGES_SHA and contract['selected_for_release'] is False
         and contract['source_date_epoch'] == EPOCH
         and re.fullmatch('[0-9a-f]{40}', contract.get('base_commit', '')),
         'finite development context required')
    for relative, pin in contract['files'].items():
        need(sha(read(context / relative)) == pin, 'frozen context drift: ' + relative)
    need(sha(read(context / 'packages.lock')) == PACKAGES_SHA and audit(context) == contract['recipes'],
         'context recipe/inventory mismatch')
    need(sha(read(__file__)) == contract['files'][HELPER], 'executing helper differs from freeze')
    for v in VARIANTS:
        source_material(read(context / PACKAGE_ROOT / name(v) / 'zlib-1.3.2.tar.gz'))
    return contract


def package_members(data, variant):
    """Read a finite .pkg.tar.xz; only exact private payload/metadata is allowed."""
    own = prefix(variant).relative_to('/').as_posix()
    license_dir = 'usr/share/licenses/' + name(variant)
    required = {own + '/' + f for f in ('bin/minigzip', 'bin/probe', 'bin/strict-gzip', 'lib/libz.a',
                'include/zlib.h', 'include/zconf.h', 'build/Makefile', 'source/zlib-1.3.2.tar.gz',
                'source/probe.c', 'source/strict-gzip.c', 'source/LICENSE.project', 'source/PKGBUILD')}
    required |= {license_dir + '/LICENSE.zlib', license_dir + '/LICENSE.project'} | META
    ancestors = {str(parent) for f in required for parent in PurePosixPath(f).parents if str(parent) != '.'}
    rows, total, seen = {}, 0, set()
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:xz') as archive:
        for m in archive:
            p = PurePosixPath(m.name)
            path = p.as_posix()
            need(path not in seen and not p.is_absolute() and '..' not in p.parts and
                 len(seen) < 128 and (m.isfile() or m.isdir()) and m.uid == m.gid == 0,
                 'unsafe package member')
            seen.add(path); total += m.size
            need(total <= 32 * 1024**2 and m.size <= 16 * 1024**2, 'package byte bound')
            if m.isdir():
                need(path in ancestors and m.mode & 0o7777 == 0o755, 'unapproved directory')
            else:
                need(path in required and m.mode & 0o7777 == (0o755 if '/bin/' in path else 0o644),
                     'unapproved payload/mode')
                rows[path] = archive.extractfile(m).read()
    need(set(rows) == required, 'incomplete package payload')
    info = rows['.PKGINFO'].decode()
    fields = {}
    for line in info.splitlines():
        if line and not line.startswith('#'):
            key, value = line.split(' = ', 1); fields.setdefault(key, []).append(value)
    need(fields.get('pkgname') == [name(variant)] and fields.get('arch') == ['aarch64']
         and fields.get('pkgver') in (['1.3.2-1'], ['1.3.2-2']) and fields.get('depend') == ['glibc']
         and not set(fields) & {'provides', 'conflict', 'replaces', 'backup'}, 'unsafe package metadata')
    source_material(rows[own + '/source/zlib-1.3.2.tar.gz'])
    return rows



def live_group(pgid):
    """Read only this still-held leader's session/group; zombies need no signal."""
    members = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / 'stat').read_text().rpartition(') ')[2].split()
            if len(fields) < 4 or int(fields[2]) != pgid or int(fields[3]) != pgid or fields[0] in ('Z', 'X'):
                continue
            uid = next(line.split()[1] for line in (entry / 'status').read_text().splitlines() if line.startswith('Uid:'))
            members.append({'pid': int(entry.name), 'uid': int(uid)})
        except (FileNotFoundError, ProcessLookupError):
            continue
    return members


# BEGIN EXACT OWNED_CHILD MODULE
# SPDX-License-Identifier: MIT
"""Single-threaded owned children: WNOWAIT reservation, then direct final reap.

Ownership loss is terminal. Popen wait/poll/communicate status is never evidence.
"""
import contextlib
import errno
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import threading
import time


class OwnershipLost(subprocess.SubprocessError):
    pass


class ChildPolicyError(subprocess.SubprocessError):
    pass


def _owned_policy(normalize=False):
    if threading.current_thread() is not threading.main_thread() or threading.active_count()!=1:
        raise ChildPolicyError('owned children require one main Python thread')
    if signal.getsignal(signal.SIGCHLD)!=signal.SIG_DFL:
        raise ChildPolicyError('SIGCHLD must use the default disposition')
    if not all(hasattr(os,n)for n in('waitid','WNOWAIT','waitpid')) or not hasattr(signal,'pthread_sigmask'):
        raise ChildPolicyError('Linux owned wait and signal-mask APIs required')
    if normalize:
        signal.signal(signal.SIGCHLD,signal.SIG_DFL)
        saved=signal.pthread_sigmask(signal.SIG_BLOCK,set())
        signal.pthread_sigmask(signal.SIG_SETMASK,saved)


class _OwnedState:
    def __init__(self,process,lifecycle,allowed_uids):
        self.process=process;self.pid=process.pid;self.row=lifecycle;self.reaped=False;self.lost=False
        self.allowed_uids={os.geteuid()}if allowed_uids is None else set(allowed_uids)
        self.row.update(pid=self.pid,exit=None,natural_exit=False,group_absent=False,
            leader_held_until_group_inspection=False,exit_observed_via_waitpid=False,
            ownership_lost=False,retirement='UNKNOWN',forced_cleanup=False,cleanup_member_uids=[])

    def lose(self,why):
        self.lost=True;self.row.update(exit=None,exit_observed_via_waitpid=False,
            ownership_lost=True,retirement='UNKNOWN',group_absent=False,ownership_error=str(why))
        # Private destructor-detachment marker, never a public observed status.
        self.process.returncode=-9999
        return OwnershipLost(str(why))

    def witness(self):
        if self.lost or self.reaped:raise OwnershipLost('no unreaped child ownership reservation')
        try:
            _owned_policy()
            value=os.waitid(os.P_PID,self.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
        except ChildProcessError as error:raise self.lose('ECHILD: child ownership lost')from error
        except OSError as error:
            if error.errno==errno.ECHILD:raise self.lose('ECHILD: child ownership lost')from error
            raise
        except ChildPolicyError as error:raise self.lose('child policy changed: '+str(error))from error
        if value is not None and value.si_pid!=self.pid:raise self.lose('witness identifies another child')
        return value

    def members(self):
        self.witness();members=[]
        for entry in Path('/proc').iterdir():
            if not entry.name.isdecimal():continue
            try:
                self.witness();fields=(entry/'stat').read_text().rpartition(') ')[2].split()
                if len(fields)<4 or int(fields[2])!=self.pid or int(fields[3])!=self.pid or fields[0]in('Z','X'):continue
                self.witness()
                uid=int(next(line.split()[1]for line in(entry/'status').read_text().splitlines()if line.startswith('Uid:')))
                members.append((int(entry.name),uid))
            except(FileNotFoundError,ProcessLookupError):continue
        return members

    def signal_group(self):
        self.witness()
        try:os.killpg(self.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        self.row['forced_cleanup']=True

    def reap(self):
        if self.witness()is None:raise ChildPolicyError('cannot final-reap a running leader')
        prior=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM,signal.SIGCHLD})
        try:
            # There is no numeric process operation after this final waitpid.
            try:pid,status=os.waitpid(self.pid,0)
            except ChildProcessError as error:raise self.lose('ECHILD during final direct reap')from error
            except OSError as error:
                if error.errno==errno.ECHILD:raise self.lose('ECHILD during final direct reap')from error
                raise
            self.reaped=True
            if pid!=self.pid:raise self.lose('final reap returned another child')
            code=os.waitstatus_to_exitcode(status);self.process.returncode=code
            self.row.update(exit=code,exit_observed_via_waitpid=True,
                retirement='REAPED'if self.row['group_absent']else'UNKNOWN')
        finally:signal.pthread_sigmask(signal.SIG_SETMASK,prior)

    def retire(self,force=False):
        if self.lost or self.reaped:return
        self.witness();members=self.members();uids=sorted({uid for _,uid in members});self.row['cleanup_member_uids']=uids
        if not set(uids)<=self.allowed_uids:
            self.row['cleanup_error']='unexpected live group credentials; no group signal issued'
            if self.witness()is not None:self.reap()
            raise ChildPolicyError(self.row['cleanup_error'])
        if force or members:self.signal_group()
        end=time.monotonic()+2
        while True:
            state=self.witness();members=self.members()
            if state is not None and not members:break
            if time.monotonic()>=end:raise ChildPolicyError('owned group did not retire within cleanup budget')
            time.sleep(.01)
        self.row.update(group_absent=True,leader_held_until_group_inspection=True)
        self.reap()


def run(argv,*,timeout=None,input=None,stdin=None,stdout=None,stderr=None,capture_output=False,
        text=False,encoding=None,errors=None,check=False,cwd=None,env=None,lifecycle=None,
        on_tick=None,allowed_uids=None,stdout_limit=None,stderr_limit=16*1024**2,**options):
    """Bounded subprocess.run subset, without Popen's reaping/status methods."""
    if options.get('shell',False)or options.get('start_new_session',True)is not True:
        raise ChildPolicyError('shell and borrowed sessions are forbidden')
    if set(options)-{'shell','start_new_session'}:raise TypeError('unsupported owned-run options: '+str(sorted(options)))
    _owned_policy(normalize=True)
    timeout=120 if timeout is None else timeout
    if type(timeout)not in(int,float)or not 0<timeout<=3600:raise ValueError('bounded positive owned timeout')
    if input is not None and stdin is not None:raise ValueError('input and stdin are exclusive')
    if capture_output:
        if stdout is not None or stderr is not None:raise ValueError('capture_output conflicts with explicit streams')
        stdout=stderr=subprocess.PIPE
    allowed_uids={os.geteuid()}if allowed_uids is None else set(allowed_uids)
    if not allowed_uids or any(type(uid)is not int or uid<0 for uid in allowed_uids):
        raise ChildPolicyError('concrete permitted child credentials required before launch')
    stdout_limit=(16*1024**2 if stderr==subprocess.STDOUT else 8*1024**2)if stdout_limit is None else stdout_limit
    if any(type(v)is not int or not 0<v<=512*1024**2 for v in(stdout_limit,stderr_limit)):
        raise ValueError('bounded explicit owned output limits')
    row={}if lifecycle is None else lifecycle
    started=time.monotonic();process=None;owned=None;pending=None;result_stdout=result_stderr=None
    with contextlib.ExitStack()as resources:
        def output_stream(value,cap):
            if value==subprocess.DEVNULL:return subprocess.DEVNULL,None,False
            if value in(None,subprocess.PIPE):
                stream=resources.enter_context(tempfile.TemporaryFile());return stream,(stream,cap),True
            if not hasattr(value,'fileno'):raise TypeError('owned output must be a file or PIPE/DEVNULL')
            return value,(value,cap),False
        out,out_watch,out_temp=output_stream(stdout,stdout_limit)
        if stderr==subprocess.STDOUT:err=subprocess.STDOUT;err_watch=None;err_temp=False
        else:err,err_watch,err_temp=output_stream(stderr,stderr_limit)
        source=stdin if stdin is not None else subprocess.DEVNULL
        if input is not None:
            source=resources.enter_context(tempfile.TemporaryFile())
            payload=input.encode(encoding or'utf-8',errors or'strict')if isinstance(input,str)else input
            if not isinstance(payload,bytes)or len(payload)>32*1024**2:raise ValueError('bounded byte input required')
            source.write(payload);source.seek(0)
        def sizes():
            for item in(out_watch,err_watch):
                if item is not None and os.fstat(item[0].fileno()).st_size>item[1]:raise ValueError('owned child output bound')
        try:
            process=subprocess.Popen(argv,stdin=source,stdout=out,stderr=err,cwd=cwd,env=env,start_new_session=True)
            owned=_OwnedState(process,row,allowed_uids)
            while True:
                state=owned.witness();sizes()
                if state is not None:row['natural_exit']=True;break
                if time.monotonic()-started>=timeout:raise subprocess.TimeoutExpired(argv,timeout)
                if on_tick is not None:on_tick()
                time.sleep(.01)
        except BaseException as error:pending=error
        finally:
            if owned is not None:
                try:owned.retire(force=pending is not None)
                except BaseException as error:
                    row['cleanup_error']=type(error).__name__+': '+str(error)
                    if pending is None or isinstance(error,OwnershipLost):pending=error
            row['elapsed_seconds']=time.monotonic()-started
            if process is not None and not(owned and owned.reaped):process.returncode=-9999
        try:sizes()
        except BaseException as error:
            if pending is None:pending=error
        if out_temp:
            out.seek(0);body=out.read(stdout_limit+1)
            if stdout==subprocess.PIPE:result_stdout=body
            elif stdout is None and body:os.write(1,body)
        if err_temp:
            err.seek(0);body=err.read(stderr_limit+1)
            if stderr==subprocess.PIPE:result_stderr=body
            elif stderr is None and body:os.write(2,body)
        if pending is not None:raise pending
        if not row.get('exit_observed_via_waitpid')or row.get('ownership_lost'):
            raise OwnershipLost('no directly observed owned exit status')
        if text or encoding is not None:
            result_stdout=result_stdout.decode(encoding or'utf-8',errors or'strict')if result_stdout is not None else None
            result_stderr=result_stderr.decode(encoding or'utf-8',errors or'strict')if result_stderr is not None else None
        result=subprocess.CompletedProcess(argv,row['exit'],result_stdout,result_stderr)
        if check:result.check_returncode()
        return result
# END EXACT OWNED_CHILD MODULE

class Commands:
    """Finite groups; hold the leader until same-credential descendant cleanup."""
    def __init__(self, output, seconds=1200, builder_uid=None):
        self.output = Path(output); self.deadline = time.monotonic() + seconds
        self.rows = []; self.active = None; self.cancelled = False
        self.builder_uid = builder_uid

    def cancel(self, *_):
        self.cancelled = True
        raise KeyboardInterrupt()

    def stop(self, process, row):
        # Retirement belongs entirely to owned run. Never inspect a borrowed handle.
        need(row.get('exit_observed_via_waitpid') is True and row.get('ownership_lost') is False
             and row.get('retirement') == 'REAPED' and row.get('natural_exit') is True
             and row.get('group_absent') is True and row.get('leader_held_until_group_inspection') is True
             and row.get('forced_cleanup') is False and type(row.get('exit')) is int,
             'directly observed natural owned-child retirement required')

    def run(self, label, argv, *, cwd=None, env=None, data=None, expected=0, timeout=180):
        need(not self.cancelled and time.monotonic() < self.deadline, 'job cancelled/deadline reached')
        budget = min(timeout, self.deadline - time.monotonic())
        row = {'label': label, 'argv': list(map(str, argv)), 'status': 'FAIL', 'exit': None}
        log = self.output / (f'{len(self.rows):04d}-' + label + '.log')
        row['log'] = log.name; self.rows.append(row)
        started = time.monotonic()
        lifecycle = dict(exit=None, natural_exit=False, group_absent=False,
                         leader_held_until_group_inspection=False, exit_observed_via_waitpid=False,
                         ownership_lost=False, retirement='UNKNOWN', forced_cleanup=False, cleanup_member_uids=[])
        self.active = lifecycle
        try:
            allowed_uids = {os.geteuid()}
            if os.getuid() == 0 and self.builder_uid is not None:
                need(type(self.builder_uid) is int and self.builder_uid > 0, 'ordinary builder UID required')
                allowed_uids.add(self.builder_uid)
            with log.open('wb') as diagnostic, tempfile.TemporaryFile() as input_stream, tempfile.TemporaryFile() as output_stream:
                if data is not None:
                    input_stream.write(data); input_stream.seek(0)
                def bounds():
                    need(not self.cancelled and os.fstat(output_stream.fileno()).st_size <= 8 * 1024**2
                         and log.stat().st_size <= 16 * 1024**2, 'command output bound or cancellation')
                run(row['argv'], cwd=cwd, env=env, stdin=input_stream if data is not None else subprocess.DEVNULL,
                    stdout=output_stream, stderr=diagnostic, timeout=budget, check=False,
                    lifecycle=lifecycle, on_tick=bounds, allowed_uids=allowed_uids)
                row.update(lifecycle); self.stop(None, row); bounds()
                output_stream.seek(0); stdout = output_stream.read(8 * 1024**2 + 1)
                need(len(stdout) <= 8 * 1024**2, 'command stdout bound')
                row.update(stdout_sha256=sha(stdout), stdout_bytes=len(stdout))
                if label.startswith(('build-', 'pacman-', 'tool-', 'elf-', 'sections-')):
                    diagnostic.write(stdout); diagnostic.flush()
                need(log.stat().st_size <= 16 * 1024**2, 'combined command diagnostic bound')
                need(row['exit'] == expected, 'command failed: ' + label)
                row['status'] = 'PASS'
                return stdout
        except BaseException as error:
            row.update(status='FAIL', error_type=type(error).__name__, error=str(error)[:2048])
            raise
        finally:
            row.update(lifecycle)
            if row.get('ownership_lost'):
                row.update(status='FAIL', exit=None, retirement='UNKNOWN', group_absent=False)
            self.active = None
            row['elapsed_seconds'] = time.monotonic() - started
            save(self.output / 'commands.json', self.rows)


def workload(runner, variants, phase, *, roots=None, installed=True):
    """Finite roundtrip/cross-decoder and strict-negative checks, never timing."""
    roots = roots or {v: prefix(v) for v in variants}
    corpus = [b'', b'x', b'cachy-asahi public workload\n' * 4096, bytes(range(256)) * 1024]
    corpus += [bytes((i * 13 + i // 257) & 255 for i in range(n)) for n in (16383, 16384, 16385)]
    result = {'probe': {}, 'encodes': 0, 'cross_decodes': 0, 'strict_rejections': 0,
              'inputs': [{'bytes': len(d), 'sha256': sha(d)} for d in corpus]}
    for v in variants:
        report = json.loads(runner.run(phase + '-probe-' + v, [str(roots[v] / 'bin/probe'),
                              '--installed-check' if installed else '--build-check'], timeout=15))
        need(report == {'status': 'PASS', 'variant': v, 'prefix': str(prefix(v)), 'zlib': '1.3.2',
                        'source_sha256': SOURCE_SHA, 'roundtrips': 21, 'negative_checks': 42}, 'probe identity/check count differs')
        result['probe'][v] = report
    for producer in variants:
        for i, original in enumerate(corpus):
            for level in (1, 6, 9):
                label = f'{phase}-{producer}-{i}-{level}'
                packed = runner.run(label + '-encode', [str(roots[producer] / 'bin/minigzip'), '-' + str(level)], data=original, timeout=10)
                result['encodes'] += 1
                # Python is an independent decoder, in addition to all installed variants.
                decoder = zlib.decompressobj(31)
                need(decoder.decompress(packed) == original and decoder.eof and not decoder.unused_data, 'independent decode differs')
                for consumer in variants:
                    decoded = runner.run(label + '-decode-' + consumer, [str(roots[consumer] / 'bin/strict-gzip')], data=packed, timeout=10)
                    need(decoded == original, 'cross-variant decode differs'); result['cross_decodes'] += 1
    reference = gzip.compress(corpus[2], mtime=0)
    corrupt = bytearray(reference); corrupt[-8] ^= 1
    for v in variants:
        for i, invalid in enumerate((bytes(corrupt), reference[:-8], reference + b'garbage')):
            runner.run(phase + '-reject-' + v + '-' + str(i), [str(roots[v] / 'bin/strict-gzip')], data=invalid, expected=2, timeout=10)
            result['strict_rejections'] += 1
    return result


def inventory(runner, label):
    data = runner.run(label, ['pacman', '-Q'], timeout=20)
    rows = {}
    for line in data.decode().splitlines():
        fields = line.split()
        need(len(fields) == 2 and fields[0] not in rows, 'invalid inventory')
        rows[fields[0]] = fields[1]
    return rows


def native_job(context, pin, output):
    """Root only inside a new no-network disposable container; never called by prepare."""
    need(platform.system() == 'Linux' and platform.machine() == 'aarch64' and os.getuid() == os.geteuid() == 0
         and Path('/.dockerenv').is_file() and os.environ.get('CACHY_ASAHI_DISPOSABLE_ZLIB') == '1',
         'explicit disposable native ARM root container required')
    context, output = Path(context), Path(output)
    need(context == Path('/inputs') and output == Path('/out') and output.is_dir() and not any(output.iterdir())
         and not WORK.exists() and not WORK.is_symlink(), 'fixed clean mounts/build path required')
    contract = verify_context(context, pin)
    user = pwd.getpwnam('alarm')
    need(user.pw_uid > 0 and user.pw_gid > 0, 'ordinary alarm builder required')
    runner = Commands(output, builder_uid=user.pw_uid)
    report = {'status': 'FAIL', 'base_commit': contract['base_commit'], 'context_sha256': pin,
              'source_sha256': SOURCE_SHA, 'native_build': 'NOT RUN', 'installed_behavior': 'NOT RUN',
              'generic16k_execution': 'NOT RUN', 'hardware_validation': 'NOT RUN',
              'performance_acceptance': 'NOT RUN', 'selected_for_release': False,
              'rebuilds': {}, 'phases': []}
    previous = {sig: signal.signal(sig, runner.cancel) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        initial = inventory(runner, 'initial-inventory')
        need((''.join(k + ' ' + v + '\n' for k, v in sorted(initial.items()))).encode() == read(context / 'packages.lock'),
             'full accepted inventory required before building')
        need(not any(prefix(v).exists() or prefix(v).is_symlink() or name(v) in initial for v in VARIANTS), 'experiment already installed')
        sentinel_paths = [Path(p).resolve() for p in ('/usr/lib/libz.so.1', '/usr/lib/libc.so.6', '/usr/bin/pacman', '/etc/pacman.conf')]
        sentinels = {str(p): sha(read(p)) for p in sentinel_paths}
        report['system_sentinels'] = sentinels
        report.update(kernel=platform.release(), machine=platform.machine(), pagesize=os.sysconf('SC_PAGE_SIZE'),
                      inventory_sha256=PACKAGES_SHA, tools={})
        for tool in ('gcc', 'ld', 'gcc-ar', 'gcc-ranlib', 'make', 'makepkg', 'pacman'):
            report['tools'][tool] = runner.run('tool-' + tool, [tool, '--version'], timeout=10).decode()[:4096]
        artifacts = {}
        for variant in VARIANTS:
            previous_payload = previous_archive = None
            for release, attempt in ((1, 1), (1, 2), (2, 1)):
                WORK.mkdir(mode=0o755)
                try:
                    recipe = context / PACKAGE_ROOT / name(variant)
                    for f in (*FILES, 'zlib-1.3.2.tar.gz'):
                        shutil.copyfile(recipe / f, WORK / f)
                    if release == 2:
                        text = (WORK / 'PKGBUILD').read_text()
                        need(text.count('pkgrel=1\n') == 1, 'one explicit metadata upgrade required')
                        (WORK / 'PKGBUILD').write_text(text.replace('pkgrel=1\n', 'pkgrel=2\n'))
                    for p in (WORK, *WORK.iterdir()):
                        os.chown(p, user.pw_uid, user.pw_gid)
                    label = f'{variant}-r{release}-{attempt}'
                    build_env = {'PATH': '/usr/bin:/bin', 'HOME': str(WORK), 'LC_ALL': 'C', 'LANG': 'C', 'TZ': 'UTC',
                                 'SOURCE_DATE_EPOCH': EPOCH, 'PACKAGER': 'cachy-asahi experimental job',
                                 'PKGEXT': '.pkg.tar.xz'}
                    # Override moving local makepkg defaults explicitly, including archive codec/checks.
                    (WORK / 'makepkg.conf').write_text(
                        'source /etc/makepkg.conf\nPKGEXT=\".pkg.tar.xz\"\n'
                        'COMPRESSXZ=(xz -c -z -T2 -)\n'
                        'BUILDENV=(!distcc !color !ccache check !sign)\nOPTIONS+=(!autodeps)\n'
                        f'BUILDDIR=\"{WORK}\"\nSRCDEST=\"{WORK}\"\nPKGDEST=\"{WORK}\"\n'
                        f'SRCPKGDEST=\"{WORK}\"\nLOGDEST=\"{WORK}\"\n')
                    # Full clean makepkg run, checks mandatory, no dependency install/download.
                    argv = ['runuser', '-u', 'alarm', '--', 'env', '-i']
                    argv += [k + '=' + v for k, v in build_env.items()]
                    argv += ['makepkg', '--config', str(WORK / 'makepkg.conf'), '--cleanbuild', '--noconfirm', '--nodeps', '--nocolor']
                    runner.run('build-' + label, argv, cwd=WORK, timeout=180)
                    packages = list(WORK.glob('*.pkg.tar.*'))
                    need(len(packages) == 1 and packages[0].name == name(variant) + f'-1.3.2-{release}-aarch64.pkg.tar.xz', 'one exact xz package required')
                    archive = read(packages[0]); members = package_members(archive, variant)
                    # Bind packaged licenses and corresponding project/upstream source.
                    own = prefix(variant).relative_to('/').as_posix()
                    material = source_material(members[own + '/source/zlib-1.3.2.tar.gz'])
                    need(members['usr/share/licenses/' + name(variant) + '/LICENSE.zlib'] == material['LICENSE'], 'license differs')
                    for f in FILES:
                        need(members[own + '/source/' + f] == read(WORK / f), 'packaged corresponding source differs')
                    effective = configured_flags(members[own + '/build/Makefile'], variant)
                    for f in ('Makefile', 'configure.log'):
                        shutil.copyfile(WORK / 'src/zlib-1.3.2' / f, output / (label + '-' + f))
                    for program in ('minigzip', 'probe', 'strict-gzip'):
                        path = WORK / 'src/zlib-1.3.2' / program
                        elf = runner.run('elf-' + label + '-' + program, ['readelf', '-h', '-lW', '-dW', str(path)])
                        need(b'AArch64' in elf and b'libz.so' not in elf and b'libc.so' in elf, 'local-static zlib/AArch64 link differs')
                        loads = re.findall(rb'^\s*LOAD\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+.*\s+(0x[0-9a-f]+)\s*$', elf, re.M)
                        need(loads and all(int(a, 16) >= 16384 and (int(o, 16) - int(v, 16)) % 16384 == 0
                                           for o, v, a in loads), '16K ELF layout differs; execution still separately gated')
                    sections = runner.run('sections-' + label, ['readelf', '-SW', str(WORK / 'src/zlib-1.3.2/libz.a')])
                    need((b'.gnu.lto_' in sections) == (variant == 'lto'), 'archive LTO selection differs')
                    # configure.log is retained outside the package because of timestamps.
                    payload = {k: sha(v) for k, v in members.items() if k not in META}
                    row = {'package_sha256': sha(archive), 'bytes': len(archive), 'payload': payload, 'configured_flags': effective}
                    if release == 1 and attempt == 2:
                        need(payload == previous_payload, 'clean rebuild payload differs')
                        row['archive_bytes_equal'] = archive == previous_archive
                        # Metadata differences fail this job too, rather than being silently ignored.
                        need(row['archive_bytes_equal'], 'clean rebuild archive bytes differ')
                    if release == 1:
                        previous_payload, previous_archive = payload, archive
                    dest = output / (label + '.pkg.tar.xz'); dest.write_bytes(archive)
                    artifacts[(variant, release)] = dest
                    report['rebuilds'][label] = row
                finally:
                    shutil.rmtree(WORK)
        report['native_build'] = 'PASS'
        # Root/pacman act only in this disposable job; no signature or release admission.
        config = output / 'pacman-local.conf'
        need(Path('/builder-disabled-hooks').is_dir(), 'accepted masked-hook builder required')
        config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Never\nLocalFileSigLevel = Never\n'
                          'HookDir = /builder-disabled-hooks\n')
        def phase(label, versions, transaction=None):
            if transaction:
                runner.run('pacman-' + label, ['pacman', '--config', str(config), '--noconfirm', '--noscriptlet', *transaction], timeout=30)
            expected = {**initial, **{name(v): '1.3.2-' + str(rel) for v, rel in versions.items()}}
            need(inventory(runner, label + '-inventory') == expected, 'full base inventory changed')
            need({str(p): sha(read(p)) for p in sentinel_paths} == sentinels, 'system library/pacman sentinel changed')
            for v in VARIANTS:
                need(prefix(v).exists() == (v in versions), 'prefix removal/installation differs')
                if v not in versions:
                    need(not Path('/usr/share/licenses', name(v)).exists(), 'package license directory remains')
            row = {'phase': label, 'versions': versions}
            if versions:
                row['workload'] = workload(runner, tuple(versions), label)
                for v, release in versions.items():
                    members = package_members(read(artifacts[(v, release)]), v)
                    for path, data in members.items():
                        if path not in META:
                            need(read('/' + path) == data, 'installed payload differs: ' + path)
            report['phases'].append(row)
            save(output / 'result.json', report)
        phase('install-baseline', {'baseline': 1}, ['-U', str(artifacts[('baseline', 1)])])
        phase('coexist', {'baseline': 1, 'lto': 1}, ['-U', str(artifacts[('lto', 1)])])
        phase('upgrade', {'baseline': 2, 'lto': 2}, ['-U', *[str(artifacts[(v, 2)]) for v in VARIANTS]])
        phase('repeat', {'baseline': 2, 'lto': 2}, ['-U', *[str(artifacts[(v, 2)]) for v in VARIANTS]])
        phase('remove-baseline', {'lto': 2}, ['-R', name('baseline')])
        phase('remove-lto', {}, ['-R', name('lto')])
        phase('reinstall', {'baseline': 2, 'lto': 2}, ['-U', *[str(artifacts[(v, 2)]) for v in VARIANTS]])
        phase('final-remove', {}, ['-R', *[name(v) for v in VARIANTS]])
        report.update(status='PASS', installed_behavior='PASS')
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, tarfile.TarError, zlib.error, KeyboardInterrupt) as error:
        report.update(error_kind=type(error).__name__, error=str(error)[:2048], cancelled=runner.cancelled)
    finally:
        # A failed lifecycle is not rolled back on the host; the caller removes its owned container.
        for sig in previous:
            signal.signal(sig, lambda *_: setattr(runner, 'cancelled', True))
        if runner.cancelled:
            report.update(status='FAIL', cancelled=True)
        report['container_cleanup'] = 'CALLER MUST REMOVE AND VERIFY OWNED CONTAINER'
        report['job_elapsed_limit_seconds'] = 1200
        save(output / 'result.json', report)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return 0 if report['status'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    check = sub.add_parser('audit'); check.add_argument('--root', type=Path, required=True)
    stage = sub.add_parser('prepare')
    for arg in ('root', 'source', 'packages', 'output'):
        stage.add_argument('--' + arg, type=Path, required=True)
    stage.add_argument('--base-commit', required=True)
    job = sub.add_parser('native-job')
    job.add_argument('--context', type=Path, required=True)
    job.add_argument('--context-sha256', required=True)
    job.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.mode == 'audit':
            print(json.dumps(audit(args.root), indent=2, sort_keys=True)); return 0
        if args.mode == 'prepare':
            prepare(args.root, args.source, args.packages, args.output, args.base_commit)
            print(sha(read(args.output / 'context.json'))); return 0
        return native_job(args.context, args.context_sha256, args.output)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, tarfile.TarError, zlib.error) as error:
        print(str(error), file=sys.stderr); return 1


if __name__ == '__main__':
    sys.exit(main())
