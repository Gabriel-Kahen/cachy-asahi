#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One guarded mount-propagation observation; never a kit/ALPM admission."""
import argparse
import base64
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

HERE = Path('/trial-code/namespace_diagnostic.py')
OUT = Path('/out')
RUNTIME = Path('/source/runtime.py')
RUNTIME_SHA = 'd889340eef78ba3755ea8751ff4e97dc35889c1604567ce24e0d8effc323ed9a'
UNSHARE_BYTES = 133560
UNSHARE_SHA = '4b36ec42b72b23f75e7eb4fec2fca4af93837e714135c6779d11d6087a806247'
PROFILE_SHA = '92342499a72bfde278975c12d33e97165d51ddeb0fd8094ad8bd4d3f0eb6c741'
PURPOSE = 'ONE_PRIVATE_PROPAGATION_MOUNT_DIAGNOSTIC_ONLY'
NAMES = ('user', 'mnt', 'pid', 'net')
STATUS_FIELDS = ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp', 'Seccomp_filters')
MOUNT = dict(source='none', target='/', filesystem=None, flags=278528, data=None)
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
UNSHARE = ['/usr/bin/unshare', '--user', '--map-root-user', '--mount', '--pid', '--net', '--fork', '--kill-child=SIGKILL', '--propagation', 'unchanged', '--']


def need(value, message):
    if not value: raise ValueError(message)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def encoded(value): return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode()


def decode(raw):
    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON key'); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: need(False, 'nonfinite JSON'))


def ordinary(path, limit):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary fixed path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit, 'bounded ordinary file required')
        raw = stream.read(limit + 1); after = os.fstat(stream.fileno())
    key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(key(before) == key(after) == key(path.lstat()) and len(raw) == before.st_size, 'file changed while reading')
    return raw


def save(name, value):
    need(name in {'namespace-parent.json', 'namespace-child.json', 'namespace-status.json'}, 'fixed report name required')
    need(OUT.is_dir() and not any(p.is_symlink() for p in (OUT, *OUT.parents)) and OUT.stat().st_uid == os.getuid(), 'owned ordinary output required')
    raw = encoded(value); need(len(raw) <= 512*1024, 'bounded diagnostic JSON required')
    path = OUT / name
    with path.open('xb') as stream: stream.write(raw)
    path.chmod(0o600)


def observed(path, limit):
    try:
        with open(path, 'rb', buffering=0) as stream: raw = stream.read(limit + 1)
        if len(raw) > limit: return dict(state='OVERSIZE', limit=limit)
        return dict(state='OK', bytes=len(raw), sha256=sha(raw), base64=base64.b64encode(raw).decode(), text=raw.decode(errors='replace'))
    except OSError as error:
        state = 'DENIED' if error.errno in (1, 13) else 'ABSENT' if error.errno == 2 else 'UNAVAILABLE'
        return dict(state=state, errno=error.errno, error_type=type(error).__name__)


def capture():
    namespaces = {}
    for name in NAMES:
        try:
            info = os.stat('/proc/self/ns/' + name)
            namespaces[name] = dict(state='OK', device=info.st_dev, inode=info.st_ino)
        except OSError as error: namespaces[name] = dict(state='DENIED' if error.errno in (1,13) else 'UNAVAILABLE', errno=error.errno)
    status = observed('/proc/self/status', 65536)
    scalars = dict(state=status['state'], values={key: None for key in STATUS_FIELDS})
    if status['state'] == 'OK':
        for line in status['text'].splitlines():
            key, sep, value = line.partition(':')
            if sep and key in scalars['values']: scalars['values'][key] = value.strip()[:64]
    root = observed('/proc/self/mountinfo', 1024*1024)
    root_view = dict(state=root['state'])
    if root['state'] == 'OK':
        rows = [line.split() for line in root['text'].splitlines() if len(line.split()) >= 10 and line.split()[4] == '/']
        if len(rows) == 1 and '-' in rows[0]:
            fields = rows[0]; split = fields.index('-')
            root_view = dict(state='OK', mount_id=fields[0], parent_id=fields[1], device=fields[2], root=fields[3], target='/',
                options=fields[5], propagation=[v for v in fields[6:split] if re.fullmatch(r'(shared|master|propagate_from):[0-9]+|unbindable', v)], filesystem=fields[split+1])
        else: root_view = dict(state='UNAVAILABLE', reason='root mount row not unique')
    return dict(schema_version=1, pid=os.getpid(), ppid=os.getppid(), uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), egid=os.getegid(),
        namespaces=namespaces, uid_map=observed('/proc/self/uid_map', 4096), gid_map=observed('/proc/self/gid_map', 4096), status=scalars,
        lsm={name: observed(path, 1024) for name,path in [('current','/proc/self/attr/current'),('apparmor','/proc/self/attr/apparmor/current'),('selinux','/proc/self/attr/selinux/current')]}, root_mount=root_view)


def context_check(context, helper_sha):
    keys = {'schema_version','purpose','source_sha','feature_code_sha','run_id','image','token','nonce','helper_sha256','map_sha256','no_kit_transactions'}
    need(type(context) is dict and set(context) == keys and type(context['schema_version']) is int and context['schema_version'] == 1 and context['purpose'] == PURPOSE and context['no_kit_transactions'] is True, 'closed diagnostic context required')
    need(type(context['source_sha']) is str and re.fullmatch('[a-f0-9]{40}', context['source_sha']) and context['source_sha'] == context['feature_code_sha'], 'exact source/feature binding required')
    for name, width in [('helper_sha256',64),('map_sha256',64),('token',16),('nonce',32)]: need(type(context[name]) is str and re.fullmatch('[a-f0-9]{'+str(width)+'}', context[name]), 'literal context pin required')
    need(context['helper_sha256'] == helper_sha and type(context['run_id']) is str and re.fullmatch('[1-9][0-9]{0,19}', context['run_id']) and type(context['image']) is str and re.fullmatch('sha256:[a-f0-9]{64}', context['image']), 'helper/run/image context binding required')


def frame_check(frame, helper_sha):
    need(type(frame) is dict and set(frame) == {'schema_version','purpose','context_sha256','helper_sha256','context_raw_base64','context','parent'} and type(frame['schema_version']) is int and frame['schema_version'] == 1 and frame['purpose'] == PURPOSE and frame['helper_sha256'] == helper_sha, 'closed immutable parent frame required')
    context_raw = base64.b64decode(frame['context_raw_base64'], validate=True)
    need(len(context_raw) <= 8192 and sha(context_raw) == frame['context_sha256'] and encoded(decode(context_raw)) == encoded(frame['context']), 'exact original context bytes required')
    context_check(frame['context'], helper_sha)


def unshare_pin_check(value):
    need(type(value) is dict and set(value) == {'bytes','sha256'} and type(value['bytes']) is int and value['bytes'] == UNSHARE_BYTES and value['sha256'] == UNSHARE_SHA, 'exact reviewed unshare binary required')


def unshare_preflight():
    profile_raw = ordinary(Path('/source/profile.json'),65536)
    need(sha(profile_raw) == PROFILE_SHA, 'held native tool profile required')
    profile = decode(profile_raw); roles = [row for row in profile['files'] if row['path'] == '/usr/bin/unshare']
    need(len(roles) == 1, 'one reviewed unshare profile role required')
    unshare_pin_check(dict(bytes=roles[0]['size'],sha256=roles[0]['sha256']))
    raw = ordinary(Path('/usr/bin/unshare'),UNSHARE_BYTES); value = dict(bytes=len(raw),sha256=sha(raw)); unshare_pin_check(value)
    return value


def parent_guard(parent):
    unshare_pin_check(parent['unshare_binary'])
    need(all(type(parent.get(k)) is int for k in ('pid','uid','euid','gid','egid')) and parent['pid'] > 0 and 0 < parent['uid'] == parent['euid'] < 2**32 and 0 < parent['gid'] == parent['egid'] < 2**32, 'ordinary parent identity required')
    need(parent['status']['state'] == 'OK' and parent['status']['values']['NoNewPrivs'] == '1', 'parent no-new-privileges required')
    need(all(re.fullmatch('[a-fA-F0-9]{1,16}', parent['status']['values'][key] or '') and int(parent['status']['values'][key],16) == 0 for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')), 'parent zero capabilities required')
    for name in NAMES:
        row = parent['namespaces'][name]
        need(row['state'] == 'OK' and type(row['device']) is int and type(row['inode']) is int and row['inode'] > 0, 'complete parent namespace identities required')


def child_guard(parent, child):
    parent_guard(parent)
    need(all(type(child.get(k)) is int for k in ('pid','uid','euid','gid','egid')) and child['pid'] == 1 and child['uid'] == child['euid'] == child['gid'] == child['egid'] == 0, 'mapped root PID1 child required')
    for name in NAMES:
        before, after = parent['namespaces'][name], child['namespaces'][name]
        need(after['state'] == 'OK' and type(after['device']) is int and type(after['inode']) is int and after['inode'] > 0 and (before['device'],before['inode']) != (after['device'],after['inode']), 'new '+name+' namespace required')
    for name, host in [('uid_map',parent['uid']),('gid_map',parent['gid'])]:
        row = child[name]
        need(row['state'] == 'OK' and row['text'].split() == ['0',str(host),'1'], 'exact single child '+name+' required')
    need(child['status']['state'] == 'OK' and child['status']['values']['NoNewPrivs'] == '1', 'child no-new-privileges required')


def probe(frame, parent_pin, sampler, mounter):
    frame_check(frame, frame['helper_sha256'])
    result = dict(schema_version=1, purpose=PURPOSE, context_sha256=frame['context_sha256'], helper_sha256=frame['helper_sha256'], parent_snapshot_sha256=parent_pin,
        acceptance=False, native_admission=False, no_kit_transactions=True, mount=dict(called=False, tuple=MOUNT), before=None, after=None, status='GUARD_REFUSED')
    try:
        result['before'] = sampler(); child_guard(frame['parent'], result['before'])
    except BaseException as error:
        result['guard_error'] = dict(type=type(error).__name__, reason=str(error)[:1024]); return result
    result['mount']['called'] = True
    try:
        value = mounter()
        need(type(value) is dict and set(value) == {'return','errno','error_text'} and type(value['return']) is int and type(value['errno']) is int and type(value['error_text']) is str, 'literal syscall observation required')
        result['mount'].update(value); result['status'] = 'MOUNT_OBSERVED'
    except BaseException as error:
        result['mount']['error'] = dict(type=type(error).__name__, reason=str(error)[:1024]); result['status'] = 'MOUNT_CALL_ERROR'
    try: result['after'] = sampler()
    except BaseException as error: result['after'] = dict(state='UNAVAILABLE', error_type=type(error).__name__)
    return result


def mount_once():
    libc = ctypes.CDLL(None, use_errno=True); function = libc.mount
    function.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p); function.restype = ctypes.c_int
    ctypes.set_errno(0)
    code = function(b'none', b'/', None, ctypes.c_ulong(278528), None)
    error = ctypes.get_errno()
    return {'return':int(code),'errno':int(error),'error_text':os.strerror(error)}


def fd_check(info, seals, expected, owner):
    need(all(type(expected.get(k)) is int and expected[k] >= 0 for k in ('device','inode','bytes')) and type(owner) is int and owner >= 0, 'literal snapshot descriptor required')
    need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o400 and info.st_nlink == 0 and info.st_uid == owner and seals & SEALS == SEALS, 'immutable owned memfd required')
    need((info.st_dev,info.st_ino,info.st_size) == (expected['device'],expected['inode'],expected['bytes']) and 0 < info.st_size <= 65536, 'exact memfd identity required')


def read_frame(fd, expected, helper_sha, owner):
    fd_check(os.fstat(fd), fcntl.fcntl(fd, fcntl.F_GET_SEALS), expected, owner)
    os.lseek(fd,0,os.SEEK_SET); raw = os.read(fd,65537)
    need(len(raw) == expected['bytes'] and sha(raw) == expected['sha256'], 'immutable parent snapshot bytes required')
    frame = decode(raw); frame_check(frame, helper_sha); return frame


def trusted_runtime():
    raw = ordinary(RUNTIME, 32768); need(sha(raw) == RUNTIME_SHA, 'held runtime bytes required')
    spec = importlib.util.spec_from_file_location('_namespace_held_runtime',RUNTIME); value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    need(sha(ordinary(RUNTIME,32768)) == RUNTIME_SHA, 'runtime source changed')
    return value


def relay_command(frame, descriptor):
    fields = ['--snapshot-fd',str(descriptor['fd']),'--snapshot-device',str(descriptor['device']),'--snapshot-inode',str(descriptor['inode']),'--snapshot-bytes',str(descriptor['bytes']),'--snapshot-sha256',descriptor['sha256'],'--self-sha256',frame['helper_sha256']]
    return ['/usr/bin/python3','-I','-B',str(HERE),'relay','--parent-pid',str(frame['parent']['pid']),*fields]


def supervise_observation(frame, descriptor, actor, child_reader):
    command = relay_command(frame,descriptor); error = None; code = None
    try: code = actor(command)
    except BaseException as problem: error = dict(type=type(problem).__name__, reason=str(problem)[:1024])
    child = None; report_error = None
    try:
        child = child_reader()
        if child is not None:
            need(child['context_sha256'] == frame['context_sha256'] and child['helper_sha256'] == frame['helper_sha256'] and child['parent_snapshot_sha256'] == descriptor['sha256'] and child['acceptance'] is False and child['native_admission'] is False and child['no_kit_transactions'] is True, 'child report immutable binding required')
    except BaseException as problem:
        report_error = dict(type=type(problem).__name__, reason=str(problem)[:1024]); child = None
    complete = error is None and report_error is None and type(code) is int and (code != 0 or child is not None)
    return dict(schema_version=1,status='CAPTURED_NAMESPACE_DIAGNOSTIC_ONLY' if complete else 'INCOMPLETE_NAMESPACE_DIAGNOSTIC', context_sha256=frame['context_sha256'],helper_sha256=frame['helper_sha256'],parent_snapshot_sha256=descriptor['sha256'],acceptance=False,native_admission=False,no_kit_transactions=True,
        child_status=child['status'] if child is not None else 'UNSHARE_OR_CHILD_DID_NOT_REPORT',supervision='HELD_RUNTIME_RETURNED' if error is None else 'HELD_RUNTIME_RAISED',returncode=code,runtime_error=error,child_report_error=report_error,command_argv=command)


def parent():
    need(os.environ.get('CACHY_NAMESPACE_DIAGNOSTIC') == '1' and os.uname().sysname == 'Linux' and os.uname().machine in ('aarch64','arm64'), 'explicit native diagnostic environment required')
    raw = ordinary(OUT/'namespace-context.json',8192); context = decode(raw); self_sha = sha(ordinary(HERE,65536))
    need(sha(raw) == os.environ['CACHY_NAMESPACE_DIAGNOSTIC_CONTEXT_SHA'], 'independent diagnostic context SHA required'); context_check(context,self_sha)
    unshare_binary = unshare_preflight()
    before = capture(); before['unshare_binary'] = unshare_binary; parent_guard(before)
    frame = dict(schema_version=1,purpose=PURPOSE,context_sha256=sha(raw),helper_sha256=self_sha,context_raw_base64=base64.b64encode(raw).decode(),context=context,parent=before)
    body = encoded(frame); need(len(body) <= 65536,'bounded parent snapshot required'); save('namespace-parent.json',frame)
    fd = os.memfd_create('namespace-diagnostic-parent',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(body)
        while view:
            written = os.write(fd,view); need(written > 0,'snapshot write made no progress'); view = view[written:]
        os.fchmod(fd,0o400); fcntl.fcntl(fd,fcntl.F_ADD_SEALS,SEALS); info = os.fstat(fd)
        descriptor = dict(fd=fd,device=info.st_dev,inode=info.st_ino,bytes=len(body),sha256=sha(body))
        fd_check(info,fcntl.fcntl(fd,fcntl.F_GET_SEALS),descriptor,os.getuid())
        runtime = trusted_runtime(); env = dict(PATH='/usr/bin:/bin',HOME='/tmp/kit-home',LANG='C.UTF-8',LC_ALL='C.UTF-8',TZ='UTC',PYTHONDONTWRITEBYTECODE='1')
        runner = runtime.Runner(45,env,OUT/'namespace-supervisor')
        def actor(command):
            with runtime.cancellation_handlers():return runner.run(command,timeout=30,limit=65536,log='command.log').returncode
        def child_reader():
            path = OUT/'namespace-child.json'
            return decode(ordinary(path,512*1024)) if os.path.lexists(path) else None
        status = supervise_observation(frame,descriptor,actor,child_reader)
        pins = {}
        for name in ('namespace-parent.json','namespace-child.json','namespace-supervisor/command.log'):
            path = OUT/name
            if os.path.lexists(path):
                data = ordinary(path,512*1024); pins[name] = dict(bytes=len(data),sha256=sha(data))
        status['report_pins'] = pins; save('namespace-status.json',status)
        return int(status['status'] != 'CAPTURED_NAMESPACE_DIAGNOSTIC_ONLY')
    finally: os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('mode',choices=('parent','relay','child')); parser.add_argument('--execute',action='store_true')
    parser.add_argument('--parent-pid',type=int)
    for name in ('snapshot-fd','snapshot-device','snapshot-inode','snapshot-bytes'):parser.add_argument('--'+name,type=int)
    parser.add_argument('--snapshot-sha256'); parser.add_argument('--self-sha256'); args = parser.parse_args()
    if args.mode == 'parent':
        need(args.execute,'explicit parent execute required'); return parent()
    need(not args.execute and re.fullmatch('[a-f0-9]{64}',args.self_sha256 or '') and sha(ordinary(HERE,65536)) == args.self_sha256,'exact helper source pin required')
    expected = dict(device=args.snapshot_device,inode=args.snapshot_inode,bytes=args.snapshot_bytes,sha256=args.snapshot_sha256)
    need(all(type(v)is int and v>=0 for v in (args.snapshot_fd,args.snapshot_device,args.snapshot_inode,args.snapshot_bytes)) and args.snapshot_fd>=3 and re.fullmatch('[a-f0-9]{64}',args.snapshot_sha256 or ''),'complete inherited snapshot descriptor required')
    if args.mode == 'relay':
        need(type(args.parent_pid)is int and args.parent_pid == os.getppid(),'live exact parent required')
        fd = os.open('/proc/'+str(args.parent_pid)+'/fd/'+str(args.snapshot_fd),os.O_RDONLY|os.O_CLOEXEC)
        try:
            frame = read_frame(fd,expected,args.self_sha256,os.getuid()); need(frame['parent']['pid'] == args.parent_pid,'snapshot parent identity required')
            os.set_inheritable(fd,True)
            child = ['/usr/bin/python3','-I','-B',str(HERE),'child','--snapshot-fd',str(fd),'--snapshot-device',str(args.snapshot_device),'--snapshot-inode',str(args.snapshot_inode),'--snapshot-bytes',str(args.snapshot_bytes),'--snapshot-sha256',args.snapshot_sha256,'--self-sha256',args.self_sha256]
            os.execve(UNSHARE[0],[*UNSHARE,*child],dict(os.environ))
        finally:os.close(fd)
    frame = read_frame(args.snapshot_fd,expected,args.self_sha256,0)
    report = probe(frame,args.snapshot_sha256,capture,mount_once); save('namespace-child.json',report)
    print(json.dumps(dict(status=report['status'],acceptance=False),sort_keys=True),flush=True); return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as error:
        print('namespace diagnostic refused: '+type(error).__name__+': '+str(error)[:1024],file=sys.stderr);raise SystemExit(1)
