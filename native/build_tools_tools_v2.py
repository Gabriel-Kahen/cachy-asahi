# SPDX-License-Identifier: MIT
"""Fixed namespace observations. Import is inert; every exec has a held owner."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

OPERATION = 'native-build-namespace-preflight-v1'
PREFIX = Path('/opt/native-' + OPERATION)
SOURCE = PREFIX / 'source'
STORE = PREFIX / 'evidence'
CASES = ('bwrap-user-mount-net', 'unshare-mapped-root')
FRAME = b'NATIVE_BUILD_NAMESPACE_V1 '


def need(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def data_pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def ordinary(path, cap=65536):
    path = Path(path)
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary canonical input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= cap, 'bounded ordinary input')
        raw = os.read(fd, cap + 1)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == before.st_size <= cap and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), 'stable whole input')
        return raw
    finally:
        os.close(fd)


def selected_proc(path, cap=4096):
    try:
        with open(path, 'rb', buffering=0) as stream:
            raw = stream.read(cap + 1)
        need(len(raw) <= cap, 'proc cap')
        return raw.decode('ascii')
    except (OSError, UnicodeError, ValueError):
        return None


def context():
    namespaces = {}
    for name in ('user', 'mnt', 'net', 'pid'):
        try:
            value = os.readlink('/proc/self/ns/' + name)
            namespaces[name] = value if re.fullmatch(name + r':\[[1-9][0-9]{0,19}\]', value) else None
        except OSError:
            namespaces[name] = None
    maps = {}
    for name in ('uid_map', 'gid_map'):
        raw = selected_proc('/proc/self/' + name)
        rows = None
        if raw is not None:
            parsed = [line.split() for line in raw.splitlines()]
            if 0 < len(parsed) <= 8 and all(len(r) == 3 and all(re.fullmatch('[0-9]{1,10}', v) for v in r) for r in parsed):
                rows = [[int(v) for v in r] for r in parsed]
        maps[name] = rows
    raw = selected_proc('/proc/self/status', 16384)
    fields = {}
    for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp', 'Seccomp_filters'):
        rows = [] if raw is None else [line.split(':', 1)[1].strip() for line in raw.splitlines() if line.startswith(name + ':')]
        fields[name] = rows[0] if len(rows) == 1 and re.fullmatch('[0-9a-f]{1,16}', rows[0]) else None
    groups = os.getgroups()
    return dict(uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), egid=os.getegid(),
                groups=groups[:32], group_count=len(groups), groups_complete=len(groups) <= 32,
                namespaces=namespaces, maps=maps, status=fields, cwd=os.getcwd(),
                architecture=os.uname().machine, page_bytes=os.sysconf('SC_PAGE_SIZE'))


def binary(path):
    try:
        raw = ordinary(path, 4 * 1024**2); info = Path(path).stat()
        return dict(**data_pin(raw), mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid)
    except (OSError, ValueError):
        return None


def arguments(case, map_hash, token):
    need(case in CASES and re.fullmatch('[0-9a-f]{64}', map_hash or '') and re.fullmatch('[0-9a-f]{24}', token or ''), 'fixed bound namespace request')
    inner = ['/usr/bin/python3', '-I', '-B', str(SOURCE / 'native/build_tools_tools_v2.py'),
             '--inner', '--case', case, '--map-sha256', map_hash, '--token', token]
    if case == CASES[0]:
        return ['/usr/bin/bwrap', '--die-with-parent', '--unshare-net', '--ro-bind', '/', '/',
                '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/home', '--tmpfs', '/var/lib/pacman',
                '--chdir', '/tmp', '--', *inner]
    return ['/usr/bin/unshare', '--user', '--map-root-user', '--', *inner]


def wrapper(case, map_hash, token):
    return ['/usr/bin/python3', '-I', '-B', str(SOURCE / 'native/build_tools_tools_v2.py'),
            '--exec-probe', '--case', case, '--map-sha256', map_hash, '--token', token]


def emit(value):
    raw = FRAME + encoded(value)
    need(len(raw) <= 16384, 'bounded same-process observation frame')
    sys.stdout.buffer.write(raw); sys.stdout.buffer.flush()


def execute(case, map_hash, token, inner):
    from common import verify_source
    verify_source(SOURCE, map_hash)
    argv = arguments(case, map_hash, token)
    value = dict(schema=1, phase='inner' if inner else 'exec', operation=OPERATION,
                 case=case, source_map_sha256=map_hash, token=token, context=context())
    if inner:
        emit(value)
        return
    need(os.getuid() == os.geteuid() != 0 and os.getcwd() == '/tmp', 'unprivileged actual image RUN child')
    value.update(argv=argv, executable=binary(argv[0]))
    emit(value)
    try:
        os.execve(argv[0], argv, dict(PATH='/usr/bin:/bin', HOME='/tmp', TMPDIR='/tmp', LC_ALL='C', TZ='UTC', PYTHONDONTWRITEBYTECODE='1'))
    except OSError as error:
        emit(dict(schema=1, phase='exec-error', case=case, source_map_sha256=map_hash, token=token, errno=error.errno))
        raise SystemExit(126)


def namespace_context(value):
    names = {'uid','euid','gid','egid','groups','group_count','groups_complete','namespaces','maps','status','cwd','architecture','page_bytes'}
    need(type(value) is dict and set(value) == names, 'closed namespace context fields')
    for key in ('uid','euid','gid','egid','group_count','page_bytes'):
        need(type(value[key]) is int and 0 <= value[key] < 2**32, 'typed bounded process identity')
    need(type(value['groups']) is list and len(value['groups']) <= 32 and all(type(x) is int and 0 <= x < 2**32 for x in value['groups']) and
         type(value['groups_complete']) is bool and len(value['groups']) == min(value['group_count'],32) and
         value['groups_complete'] is (value['group_count'] <= 32), 'bounded complete group observation')
    need(value['cwd'] == '/tmp' and value['architecture'] == 'aarch64' and value['page_bytes'] in (4096,16384,65536), 'actual fixed native image probe cwd/architecture')
    need(type(value['namespaces']) is dict and set(value['namespaces']) == {'user','mnt','net','pid'}, 'closed namespace observations')
    for name, observed in value['namespaces'].items():
        need(observed is None or type(observed) is str and re.fullmatch(name + r':\[[1-9][0-9]{0,19}\]', observed), 'typed namespace link or UNKNOWN')
    need(type(value['maps']) is dict and set(value['maps']) == {'uid_map','gid_map'}, 'closed mapping observations')
    for rows in value['maps'].values():
        need(rows is None or type(rows) is list and 0 < len(rows) <= 8 and all(type(row) is list and len(row) == 3 and
             all(type(x) is int and 0 <= x < 2**32 for x in row) and row[2] > 0 for row in rows), 'finite map rows or UNKNOWN')
    fields = {'CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs','Seccomp','Seccomp_filters'}
    need(type(value['status']) is dict and set(value['status']) == fields and all(x is None or type(x) is str and re.fullmatch('[0-9a-f]{1,16}',x) for x in value['status'].values()), 'finite proc status or UNKNOWN')
    return value


def namespace_outcome(raw, code, case, map_hash, token):
    need(type(raw) is bytes and len(raw) <= 65536 and type(code) is int and 0 <= code <= 255 and case in CASES, 'bounded actual namespace output/code')
    lines = raw.splitlines(keepends=True);frames = []; tail = []
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate observation key')
            result[key] = value
        return result
    for index,line in enumerate(lines):
        if line.startswith(FRAME):
            body = line[len(FRAME):]
            need(len(line) <= 16384 and line.endswith(b'\n'), 'one complete bounded observation frame')
            value = json.loads(body, object_pairs_hook=pairs)
            need(encoded(value) == body and type(value) is dict and value.get('schema') == 1 and type(value.get('schema')) is int and
                 value.get('case') == case and value.get('source_map_sha256') == map_hash and value.get('token') == token,
                 'canonical same-source same-run namespace frame')
            frames.append(value)
        else:
            tail.append(line)
    result = dict(outcome='UNKNOWN', reason='MISSING_SAME_PROCESS_CONTEXT', exit=code, output=data_pin(raw),
                  namespace_errno='UNKNOWN', policy_cause='UNKNOWN', before=None, inside=None, executable=None)
    if not frames:
        return result
    first = frames[0]
    need(lines[0].startswith(FRAME) and first.get('phase') == 'exec' and
         set(first) == {'schema','phase','operation','case','source_map_sha256','token','context','argv','executable'} and
         first['operation'] == OPERATION and first['argv'] == arguments(case,map_hash,token), 'first exact exec frame and fixed argv')
    before = namespace_context(first['context']); result['before'] = before; result['executable'] = first['executable']
    executable = first['executable']
    if executable is not None:
        need(type(executable) is dict and set(executable) == {'bytes','sha256','mode','uid','gid'} and
             type(executable['bytes']) is int and 0 < executable['bytes'] <= 4*1024**2 and
             type(executable['sha256']) is str and re.fullmatch('[0-9a-f]{64}',executable['sha256']) and
             all(type(executable[k]) is int for k in ('mode','uid','gid')), 'typed actual probe binary identity')
    result['reason'] = 'UNVERIFIED_OUTER_IDENTITY_OR_BINARY'
    if not (before['uid'] == before['euid'] == before['gid'] == before['egid'] == 1000 and before['groups_complete'] and
            executable is not None and executable['mode'] == 0o755 and executable['uid'] == executable['gid'] == 0):
        return result
    if len(frames) == 2 and frames[1].get('phase') == 'exec-error':
        need(set(frames[1]) == {'schema','phase','case','source_map_sha256','token','errno'} and
             type(frames[1]['errno']) is int and 0 < frames[1]['errno'] < 4096 and code == 126, 'bounded actual exec failure')
        result['reason'] = 'EXEC_FAILED_NOT_NAMESPACE_RESULT'
        return result
    if len(frames) == 1 and code > 0:
        denied = (b'No permissions to create a new namespace' in b''.join(tail) or
                  b'unshare failed: Operation not permitted' in b''.join(tail) or
                  b'Creating new namespace failed: Operation not permitted' in b''.join(tail))
        result.update(outcome='DENIED' if denied else 'UNKNOWN', reason='TOOL_REPORTED_NAMESPACE_DENIAL_NO_CAUSE_OR_ERRNO' if denied else 'NONZERO_TOOL_RESULT_NO_CAUSE_OR_ERRNO')
        return result
    result['reason'] = 'NO_COMPLETE_SUCCESSFUL_INNER_OBSERVATION'
    if not (len(frames) == 2 and frames[1].get('phase') == 'inner' and code == 0 and not tail):
        return result
    inner = frames[1]
    need(set(inner) == {'schema','phase','operation','case','source_map_sha256','token','context'} and inner['operation'] == OPERATION, 'closed same-process inner frame')
    after = namespace_context(inner['context']); result['inside'] = after
    ns0,ns1 = before['namespaces'],after['namespaces']
    result['reason'] = 'INCOMPLETE_NAMESPACE_METADATA'
    if not all(x is not None for x in [*ns0.values(),*ns1.values(),*before['maps'].values(),*after['maps'].values()]):
        return result
    common = ns0['user'] != ns1['user'] and ns0['pid'] == ns1['pid'] and after['groups_complete']
    if case == CASES[0]:
        supported = common and ns0['mnt'] != ns1['mnt'] and ns0['net'] != ns1['net'] and after['uid'] == after['euid'] == after['gid'] == after['egid'] == 1000
    else:
        supported = common and ns0['mnt'] == ns1['mnt'] and ns0['net'] == ns1['net'] and after['uid'] == after['euid'] == after['gid'] == after['egid'] == 0 and after['maps'] == dict(uid_map=[[0,1000,1]],gid_map=[[0,1000,1]])
    result.update(outcome='SUPPORTED' if supported else 'UNKNOWN', reason='EXACT_OBSERVED_NAMESPACE_EFFECTS' if supported else 'INNER_EFFECTS_DO_NOT_ESTABLISH_REQUEST')
    return result


if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--exec-probe', action='store_true'); mode.add_argument('--inner', action='store_true')
    parser.add_argument('--case', choices=CASES, required=True)
    parser.add_argument('--map-sha256', required=True); parser.add_argument('--token', required=True)
    args = parser.parse_args()
    execute(args.case, args.map_sha256, args.token, args.inner)
