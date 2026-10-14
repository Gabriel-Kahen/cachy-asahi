#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One fixed FD input, one terminal receipt; no command-line selection surface."""
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import signal
import stat
import sys
import time

INPUT_FD, RECEIPT_FD = 3, 4
CLI = 'scripts/ci/private-library-cli/'
LIMIT = 1024**2


def need(value, reason):
    if not value:
        raise ValueError(reason)


def decode(raw):
    def pairs(rows):
        value = {}
        for name, item in rows:
            need(name not in value, 'DUPLICATE_INPUT_KEY')
            value[name] = item
        return value
    def invalid(_):
        raise ValueError('NONFINITE_INPUT')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def node(info):
    return tuple(getattr(info,name) for name in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid',
                                               'st_size','st_mtime_ns','st_ctime_ns'))


def capsule_inventory(root, files):
    expected_dirs = {''}
    for name in files:
        relative = PurePosixPath(name)
        need(type(name) is str and 0 < len(name) <= 512 and not relative.is_absolute() and
             '..' not in relative.parts and relative.as_posix() == name and name != '.' and '\\' not in name and
             '__pycache__' not in relative.parts and not name.endswith(('.pyc','.pyo')), 'CAPSULE_RELATIVE_PATH')
        expected_dirs.update(str(parent) for parent in relative.parents if str(parent) != '.')
    leaves, directories, pending, count = set(), set(), [root], 0
    while pending:
        parent = pending.pop()
        directories.add('' if parent == root else parent.relative_to(root).as_posix())
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) in (0o500,0o555), 'READONLY_CAPSULE_DIRECTORY')
        with os.scandir(parent) as entries:
            for entry in entries:
                count += 1
                need(count <= 4096, 'CAPSULE_ENTRY_LIMIT')
                name = Path(entry.path).relative_to(root).as_posix()
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    need(name in expected_dirs and entry.name != '__pycache__', 'UNSELECTED_CAPSULE_DIRECTORY')
                    pending.append(Path(entry.path))
                else:
                    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and name in files and
                         not name.endswith(('.pyc','.pyo')) and stat.S_IMODE(info.st_mode) == files[name]['mode'],
                         'UNSELECTED_CAPSULE_LEAF')
                    leaves.add(name)
    need(leaves == set(files) and directories == expected_dirs, 'CAPSULE_INVENTORY_MISMATCH')


def bootstrap():
    """Authenticate project bodies before their first import, not afterwards."""
    need(len(sys.argv) == 1 and sys.flags.isolated and sys.flags.dont_write_bytecode and sys.flags.no_site,
         'FIXED_ISOLATED_INVOCATION_REQUIRED')
    need(fcntl.fcntl(INPUT_FD, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY, 'READ_ONLY_INPUT_FD_REQUIRED')
    required = fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL
    need(fcntl.fcntl(INPUT_FD, fcntl.F_GET_SEALS) & required == required, 'SEALED_INPUT_FD_REQUIRED')
    input_info = os.fstat(INPUT_FD)
    need(stat.S_ISREG(input_info.st_mode) and 0 < input_info.st_size <= LIMIT, 'BOUNDED_INPUT_FD_REQUIRED')
    raw = os.pread(INPUT_FD, LIMIT+1, 0)
    need(len(raw) == input_info.st_size and node(os.fstat(INPUT_FD)) == node(input_info), 'INPUT_FD_CHANGED')
    record = decode(raw)
    source = record['sources']
    root = Path(source['root'])
    need(root.is_absolute() and '..' not in root.parts and
         all(not path.is_symlink() for path in (root,*root.parents)), 'SOURCE_ROOT_REQUIRED')
    files = source['files']
    need(type(files) is dict and 8 <= len(files) <= 512 and
         all(CLI+name+'.py' in files for name in ('entry','parent_bridge','boundary','operations','owned_build','baseline_bridge','evidence','consumer_adapter')),
         'SELECTED_EIGHT_BODIES_REQUIRED')
    canonical = (json.dumps(files,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    need(hashlib.sha256(canonical).hexdigest() == source['manifest_sha256'], 'SOURCE_MANIFEST_PIN')
    capsule_inventory(root,files)
    total = 0
    for name, row in files.items():
        relative = PurePosixPath(name)
        need(type(name) is str and 0 < len(name) <= 512 and not relative.is_absolute() and
             '..' not in relative.parts and relative.as_posix() == name and '\\' not in name, 'SOURCE_PATH')
        path = root/name
        need(all(not part.is_symlink() for part in (path,*path.parents)), 'SOURCE_SYMLINK')
        for parent in (path.parent,*path.parent.parents):
            if parent == root.parent:
                break
            need(not stat.S_IMODE(parent.lstat().st_mode) & 0o222, 'WRITABLE_IMPORT_DIRECTORY')
        fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        first = None
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= 8*1024**2 and
                 stat.S_IMODE(before.st_mode) in (0o444,0o555) and stat.S_IMODE(before.st_mode) == row['mode'] and
                 before.st_size == row['bytes'], 'READONLY_SELECTED_BODY_REQUIRED')
            body = os.pread(fd, before.st_size+1, 0)
            need(len(body) == before.st_size and hashlib.sha256(body).hexdigest() == row['sha256'] and
                 node(os.fstat(fd)) == node(before) and node(path.lstat()) == node(before), 'SELECTED_BODY_CHANGED')
            total += len(body)
            need(total <= 64*1024**2, 'SOURCE_TOTAL_LIMIT')
        except BaseException as error:
            first = error
            raise
        finally:
            try:
                os.close(fd)
            except BaseException as error:
                if first is None:
                    raise
                first.add_note('SOURCE_BODY_FD_CLOSE_UNCERTAIN:'+type(error).__name__)
    need(Path(__file__).absolute() == root/CLI/'entry.py', 'SELECTED_INITIAL_BODY_PATH')
    # -I -S selects the ordinary trusted interpreter's runtime paths. Project
    # bodies remain capsule-selected; no universal stdlib executed-byte claim.
    trusted_runtime = [value for value in sys.path if value and Path(value).is_absolute()]
    sys.path[:] = [str(root/CLI), *trusted_runtime]
    return record


def write_receipt(value, bridge, state):
    need(stat.S_ISFIFO(os.fstat(RECEIPT_FD).st_mode) and
         fcntl.fcntl(RECEIPT_FD,fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY, 'RECEIPT_PIPE_REQUIRED')
    raw = bridge.receipt_frame(value)
    position = 0
    while position < len(raw):
        state.check(cleanup=True)
        try:
            count = os.write(RECEIPT_FD,raw[position:])
        except BlockingIOError:
            time.sleep(0.01)
            continue
        need(count > 0, 'SHORT_RECEIPT_WRITE')
        position += count
        state.check(cleanup=True)


def main():
    record = bootstrap()
    import boundary
    import parent_bridge as bridge
    import operations
    observed = bridge.clock_domain()
    record = boundary.validate_input(record,observed_domain=observed)
    need(dict(os.environ) == record['environment'], 'FIXED_ENVIRONMENT_REQUIRED')
    need(record['budget']['commands'] == 3, 'CHILD_INHERITED_PREFLIGHT_BUDGET_REQUIRED')
    state = boundary.Boundary(record,observed_domain=observed,clock=time.monotonic)
    custody = bridge.Custody(record,state)
    previous = {}
    value = None
    def cancelled(number, frame):
        bridge.remember(state,KeyboardInterrupt('CHILD_CANCELLED'),cancel=True)
    try:
        for number in (signal.SIGINT,signal.SIGTERM):
            state.check()
            previous[number] = signal.getsignal(number)
            signal.signal(number,cancelled)
        custody.authenticate()
        custody.check_modules()
        # Root's selected adapter currently hard-refuses production scheduling.
        value = operations.run_cli(record,bridge.OwnedRunner(record,state,custody),state,custody)
        boundary.validate_terminal(value,record)
    except BaseException as error:
        bridge.remember(state,error,cancel=isinstance(error,KeyboardInterrupt))
    finally:
        for number, handler in previous.items():
            try:
                state.check(cleanup=True)
                signal.signal(number,handler)
            except BaseException as error:
                bridge.remember(state,error,cleanup=True)
        custody.close()
    if value is None:
        value = state.terminal(status='INCOMPLETE')
    elif state.first_cause is not None or state.cleanup_errors or state.cancelled:
        value['status'] = 'FAIL'
        value['first_cause'] = boundary.failure_record(state.first_cause) if state.first_cause else None
        value['cleanup_errors'] = [boundary.failure_record(error) for error in state.cleanup_errors]
        value['cancelled'] = state.cancelled
        value['budget'] = state.snapshot()
    boundary.validate_terminal(value,record)
    write_receipt(value,bridge,state)
    return 0 if value['status'] == 'CHILD_COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
