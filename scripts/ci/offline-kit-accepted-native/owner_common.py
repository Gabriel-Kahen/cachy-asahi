# SPDX-License-Identifier: MIT
import argparse
import ctypes
import math
import threading
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
DOCKER=('docker','--host=unix:///var/run/docker.sock')
LABEL='org.cachy-asahi.offline-kit-accepted-owner'
def need(ok, message):
    if not ok:
        raise ValueError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def read(path, limit=16 * 1024**2):
    path = Path(path)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit
         and not any(p.is_symlink() for p in path.parents), 'bounded ordinary file: ' + str(path))
    return path.read_bytes()

def load(path):
    return json.loads(read(path))

def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

def safe_path(path):
    path = Path(path).absolute()
    need(not path.is_symlink() and not any(p.is_symlink() for p in path.parents), 'symlink ancestry refused')
    return path

def fresh(path):
    path = safe_path(path)
    need(not path.exists(), 'fresh owned path required: ' + str(path))
    path.mkdir(mode=0o755)
    return path

def group_members(pgid, leader):
    members = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal() or int(entry.name) == leader:
            continue
        try:
            fields = (entry / 'stat').read_text().rpartition(') ')[2].split()
        except FileNotFoundError:
            continue
        if len(fields) >= 3 and int(fields[2]) == pgid:
            members.append(int(entry.name))
    return members

def reaping_policy():
    need(threading.current_thread() is threading.main_thread() and threading.active_count() == 1
         and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'incompatible child reaping policy')
    # Clear inherited SA_NOCLDWAIT while keeping the default disposition.
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    libc = ctypes.CDLL(None, use_errno=True)
    need(libc.prctl(36, 1, 0, 0, 0) == 0, 'child subreaper setup failed')


class ReservationLost(ValueError):
    pass


class Actors:
    """Retain the leader until all group operations finish; reap it exactly once."""
    def __init__(self, directory, seconds):
        need(type(seconds) in (int, float) and math.isfinite(seconds) and 0 < seconds <= 20760,
             'finite owner deadline')
        self.directory = fresh(directory)
        self.deadline = time.monotonic() + seconds
        self.rows = []

    def run(self, argv, log=None, timeout=60, *, allowed=(0,)):
        reaping_policy()
        need(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 20760,
             'finite actor timeout')
        need(time.monotonic() < self.deadline, 'owner deadline reached')
        argv = list(map(str, argv))
        log = Path(log) if log is not None else self.directory / (f'{len(self.rows):04d}.log')
        need(log.parent.is_dir() and not log.exists(), 'fresh actor log')
        row = {'argv': argv, 'log': str(log), 'status': 'FAIL', 'exit': None,
               'natural_exit': False, 'group_absent': None, 'leader_reaped': False,
               'leader_held_until_group_inspection': False, 'reservation': 'NOT_LAUNCHED',
               'forced_retirement': False}
        self.rows.append(row)
        process = None
        authority = False
        failure = None
        ready = False

        def observe():
            nonlocal authority
            if not authority:
                raise ReservationLost('child reservation unavailable')
            try:
                need(threading.current_thread() is threading.main_thread() and threading.active_count() == 1
                     and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'child reaping policy changed')
                need(process.returncode is None, 'Popen leader was already reaped')
                state = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                need(state is None or state.si_pid == process.pid, 'unexpected owned child observation')
                return state
            except (OSError, ValueError) as error:
                authority = False
                row.update(exit=None, group_absent=None, reservation='LOST_OR_UNVERIFIED',
                           reservation_error=type(error).__name__ + ': ' + str(error))
                # Suppress Popen.__del__ poll and its ECHILD-to-zero fallback.
                process._child_created = False
                raise ReservationLost('owned child reservation lost or unverified') from error

        def members():
            observe()  # Immediately before each numeric group census.
            return group_members(process.pid, process.pid)

        def send(number):
            observe()  # No reap occurs between this observation and signal.
            try:
                os.killpg(process.pid, number)
            except ProcessLookupError:
                pass

        def reap_adopted(pids):
            nonlocal authority
            # Reap only direct adopted children in the still-reserved group.
            for pid in pids:
                observe()
                try:
                    values = (Path('/proc') / str(pid) / 'stat').read_text().rpartition(') ')[2].split()
                except FileNotFoundError:
                    continue
                if len(values) < 3 or int(values[1]) != os.getpid():
                    continue
                try:
                    actual, status = os.waitpid(pid, os.WNOHANG)
                    need(actual in (0, pid), 'unexpected adopted child reap')
                except (OSError, ValueError) as error:
                    authority = False
                    row.update(exit=None, group_absent=None, reservation='LOST_OR_UNVERIFIED',
                               reservation_error=type(error).__name__ + ': ' + str(error))
                    process._child_created = False
                    raise ReservationLost('adopted child reservation lost or unverified') from error

        def retire():
            nonlocal authority
            state = observe()
            remaining = members()
            if not row['natural_exit'] or remaining:
                row['status'] = 'FAIL'
                row['forced_retirement'] = True
                send(signal.SIGTERM)
                term_end = time.monotonic() + 2
                while True:
                    state = observe()
                    remaining = members()
                    reap_adopted(remaining)
                    if state is not None and not members():
                        break
                    if time.monotonic() >= term_end:
                        send(signal.SIGKILL)
                        break
                    time.sleep(.02)
            cleanup_end = time.monotonic() + 1
            while True:
                state = observe()
                remaining = members()
                reap_adopted(remaining)
                remaining = members()
                if state is not None and not remaining:
                    row.update(group_absent=True, leader_held_until_group_inspection=True)
                    break
                if time.monotonic() >= cleanup_end:
                    row['group_absent'] = False
                    raise ValueError('owned group retirement incomplete')
                time.sleep(.01)
            # All numeric group census/signalling is permanently finished now.
            state = observe()
            need(state is not None, 'final leader exit not reserved')
            expected_code = state.si_status if state.si_code == os.CLD_EXITED else -state.si_status
            while True:
                try:
                    pid, status = os.waitpid(process.pid, os.WNOHANG)
                except OSError as error:
                    authority = False
                    row.update(exit=None, group_absent=None, reservation='LOST_OR_UNVERIFIED',
                               reservation_error=type(error).__name__ + ': ' + str(error))
                    process._child_created = False
                    raise ReservationLost('final owned leader status unavailable') from error
                if pid == process.pid:
                    row['exit'] = process.returncode = os.waitstatus_to_exitcode(status)
                    row.update(leader_reaped=True, reservation='REAPED')
                    authority = False
                    need(row['exit'] == expected_code, 'final child status differs from WNOWAIT observation')
                    return
                need(pid == 0, 'unexpected final leader reap')
                if time.monotonic() >= cleanup_end:
                    raise ValueError('final owned leader reap incomplete')
                time.sleep(.01)

        try:
            with log.open('wb') as stream:
                mask = signal.pthread_sigmask(signal.SIG_BLOCK, (signal.SIGINT, signal.SIGTERM))
                try:
                    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stream,
                                               stderr=subprocess.STDOUT, start_new_session=True,
                                               preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, mask))
                    row.update(pid=process.pid, reservation='OWNED_UNREAPED')
                    authority = True
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, mask)
                end = min(self.deadline, time.monotonic() + timeout)
                while True:
                    state = observe()
                    if state is not None:
                        row['natural_exit'] = True
                        code = state.si_status if state.si_code == os.CLD_EXITED else -state.si_status
                        need(code in allowed, 'actor exit: ' + str(code))
                        break
                    if time.monotonic() >= end:
                        raise subprocess.TimeoutExpired(argv, timeout)
                    time.sleep(.05)
            need(log.stat().st_size <= 16 * 1024**2, 'bounded actor log')
            ready = True
        except BaseException as error:
            failure = error
        finally:
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, (signal.SIGINT, signal.SIGTERM))
            try:
                if process is not None and authority:
                    try:
                        retire()
                    except BaseException as error:
                        row['cleanup_error'] = type(error).__name__ + ': ' + str(error)
                        failure = failure or error
                if process is not None and not row['leader_reaped']:
                    # Unknown retirement must never trigger implicit poll/wait.
                    process._child_created = False
                queued = set(signal.sigpending()) & ({signal.SIGINT, signal.SIGTERM} - set(mask))
                if queued:
                    row['cancellation_pending'] = sorted(map(int, queued))
                    failure = failure or InterruptedError('actor cancellation pending')
                if (failure is None and ready and not row['forced_retirement'] and row['natural_exit'] and row['group_absent'] is True
                        and row['leader_reaped'] and row['exit'] in allowed):
                    row['status'] = 'PASS'
                save(self.directory / 'actors.json', self.rows)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        if failure is not None:
            raise failure
        need(row['status'] == 'PASS', 'natural actor group absence and actual exit required')
        return read(log).decode().strip()

    def docker(self, *argv, **kwargs):
        return self.run([*DOCKER, *argv], **kwargs)

def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

def trial_inspection(row, own, image, mounts):
    host = row['HostConfig']
    need(row['Name'] == '/' + own['consumer'] and row['Image'] == image
         and row['Config']['Labels'].get(LABEL) == own['token']
         and row['Config']['User'] == f'{os.getuid()}:{os.getgid()}', 'owned finite native trial consumer')
    need(host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] and not host['Privileged']
         and not host['AutoRemove'] and host['PidsLimit'] == 128 and host['Memory'] == 1024**3
         and host['NanoCpus'] == 2_000_000_000 and set(host['CapDrop']) == {'ALL'}
         and not host.get('CapAdd') and host['SecurityOpt'] == ['no-new-privileges']
         and not host.get('Devices') and not host.get('DeviceRequests') and not host.get('VolumesFrom'),
         'finite native trial isolation')
    actual={(m['Destination'],m['Source'],m['RW']) for m in row['Mounts'] if m['Type']=='bind'}
    need(actual == set(mounts) and all(m['Type']=='bind' or
         (m['Type']=='tmpfs' and m['Destination']=='/tmp') for m in row['Mounts'])
         and set(host['Tmpfs']) == {'/tmp'}
         and set(host['Tmpfs']['/tmp'].split(',')) == {'rw','nosuid','nodev','exec','size=256m'},
         'trial exact bind namespace')

def trial_actor(actor, own, image, work, phase, mounts):
    need(not actor.docker('ps','-aq','--no-trunc','--filter','name=^/'+own['consumer']+'$'), 'fresh trial consumer name')
    command=['create','--name',own['consumer'],'--label',LABEL+'='+own['token'],'--pull=never',
        '--platform','linux/arm64','--user',f'{os.getuid()}:{os.getgid()}', '--cap-drop=ALL',
        '--security-opt=no-new-privileges','--read-only','--pids-limit','128','--memory','1g','--cpus','2',
        '--network','none','--tmpfs','/tmp:rw,nosuid,nodev,exec,size=256m',
        '--env','HOME=/tmp/kit-home','--env','LANG=C.UTF-8','--env','LC_ALL=C.UTF-8','--env','TZ=UTC',
        '--env','PYTHONDONTWRITEBYTECODE=1','--env','FEATURE_CODE_SHA='+own['feature_code_sha'],
        '--env','CONTEXT_SOURCE_SHA='+own['source_sha'], '--env','ACCEPTED_TOOL='+own['accepted_tool']]
    for dst,src,rw in mounts:
        need(',' not in src and '\n' not in src,'simple finite mount path')
        command += ['--mount','type=bind,src='+src+',dst='+dst+('' if rw else ',readonly')]
    if phase=='candidate':
        command += ['--env','CACHY_ASAHI_INSTALL_NONCE='+own['candidate_nonce'],
                    '--env','CACHY_ASAHI_INSTALL_IMAGE='+image,
                    '--env','CANDIDATE_SELECTION_SHA='+own['candidate_selection_sha']]
    command += ['--entrypoint','/usr/bin/python',image,'-I','-B','/trial-code/trial.py',phase]
    cid=actor.docker(*command,timeout=30)
    row=json.loads(actor.docker('inspect',cid))[0]
    trial_inspection(row,own,image,mounts)
    save(work/('trial-'+phase+'-inspection.json'),row)
    actor.docker('start','--attach',cid,timeout=1500 if phase=='candidate' else 300)
    stopped=json.loads(actor.docker('inspect',cid))[0]
    need(stopped['State']['Status']=='exited' and stopped['State']['ExitCode']==0 and not stopped['State']['OOMKilled'],
         'natural complete native trial actor')
    save(work/('trial-'+phase+'-stopped.json'),stopped)
    actor.docker('rm',cid)
    need(not actor.docker('ps','-aq','--no-trunc','--filter','name=^/'+own['consumer']+'$'), 'trial consumer retired')
    save(work/('trial-'+phase+'-absence.json'),dict(container_id=cid,observed_absent=True))
