#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite adapter for a Root-qualified ordinary container; no nested sandbox."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

INPUTS = Path('/inputs')
CANDIDATE = INPUTS / 'packages/port/llvm23-source-reference'
WORK = Path('/work')
OUT = WORK / 'output'
PREFIX = Path('/opt/cachy-asahi/llvm23-source-reference')
MODE = 'ROOTFUL_CONTAINER_NO_BWRAP_V1'
OPERATION = 'llvm23-source-reference-native-v1'
EXPECTED349 = '579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'
ARCHIVE_SHA = 'ebe9be46fe8756d58c5b198ffad0fa2a766257add81a4dc52179bfacc7888ee6'
ARCHIVE_BYTES = 179168672
PACKAGE = 'cachy-asahi-llvm23-source-reference-23.1.1-1-aarch64.pkg.tar.zst'
MIB = 1024**2
LOG_LIMIT = 64*MIB
ACTOR_SECONDS = 14400
MAKEPKG_SECONDS = 13800
STAGES = {'probe': 60, 'tools': 10800, 'runtimes': 1800, 'check': 600}
ORIGINAL_CALL = '  python -I "$startdir/reference.py" "$1" --work "$srcdir" "${@:2}"'
CONTAINER_CALL = '  python -I -B /inputs/actor/container_mode.py "$1" --work "$srcdir" "${@:2}"'


def need(ok, why):
    if not ok:
        raise ValueError(why)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def is_digest(value, width=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(width)+'}', value) is not None


def read(path, cap=4*MIB):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap, 'ordinary bounded DATA required: '+str(path))
        data = bytearray()
        while block := os.read(fd, min(65536, cap+1-len(data))):
            data.extend(block)
            need(len(data) <= cap, 'DATA cap exceeded')
        key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(data) == before.st_size and key(before) == key(os.fstat(fd)) == key(Path(path).lstat()), 'DATA changed during read')
        return bytes(data)
    finally:
        os.close(fd)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def digest(path):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode), 'ordinary hashed file required')
    with path.open('rb') as stream:
        value = hashlib.file_digest(stream, 'sha256').hexdigest()
    key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(key(info) == key(path.lstat()), 'hashed file changed')
    return value


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('nonfinite JSON')
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    need(type(value) is dict, 'JSON object required')
    return value


def descriptor(path, expected, cap=4*MIB):
    raw = read(path, cap)
    need(dict(**pin(raw), mode=stat.S_IMODE(path.stat().st_mode)) == expected, 'pinned input differs: '+str(path))
    return raw


def context():
    raw = read(INPUTS/'admission.json')
    need(is_digest(os.environ.get('ADMISSION_SHA256')) and pin(raw)['sha256'] == os.environ['ADMISSION_SHA256'], 'explicit Root admission hash required')
    a = decode(raw)
    need(encode(a) == raw and a['schema'] == 1 and a['mode'] == MODE and a['operation'] == OPERATION and a['holds_preserved'] is True, 'canonical same-operation Root input admission required')
    need(set(a['source']) == {'sha', 'ref'} and is_digest(a['source']['sha'], 40) and re.fullmatch(r'codex/[A-Za-z0-9._/-]+', a['source']['ref'] or ''), 'actual Source SHA/ref required')
    need(all(type(a[k]) is str and re.fullmatch('[1-9][0-9]{0,19}', a[k]) for k in ('run', 'job')), 'actual run/job required')
    need(re.fullmatch(r'sha256:[0-9a-f]{64}', a['image'] or '') and all(is_digest(a[k]) for k in ('approval', 'source_map_sha256', 'contract_sha256', 'source_tree_sha256', 'input_signature_audit_sha256')), 'external Root material bindings required')
    need(a['expected349_sha256'] == EXPECTED349, 'different signed349 baseline')
    c_raw = read(INPUTS/'contract.json')
    need(pin(c_raw)['sha256'] == a['contract_sha256'], 'Root contract differs')
    c = decode(c_raw)
    need(c['schema'] == 1 and c['mode'] == MODE and c['operation'] == OPERATION and c['package_name'] == PACKAGE, 'fixed container-mode contract required')
    need(c['source'] == {'bytes': ARCHIVE_BYTES, 'sha256': ARCHIVE_SHA}, 'fixed LLVM source declaration required')
    for group, root in (('candidate_files', CANDIDATE), ('actor_files', INPUTS/'actor')):
        need(type(c[group]) is dict and 1 <= len(c[group]) <= 32, 'finite input map required')
        for name, expected in c[group].items():
            need(re.fullmatch('[A-Za-z0-9._+-]+', name) and name not in ('.', '..'), 'literal input leaf required')
            descriptor(root/name, expected)
    need({'PKGBUILD', 'reference.py', 'build.sh', 'inputs.json', 'LICENSE.packaging'} <= set(c['candidate_files']), 'complete candidate runtime input pins required')
    need({'entry.py', 'entry.sh', 'runtime.py', 'container_mode.py'} <= set(c['actor_files']), 'complete actor pins required')
    descriptor(INPUTS/'helpers/owned_child.py', c['owned_child'])
    uids = next(line.split()[1:] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('Uid:'))
    need(uids == ['1001']*4 and os.uname().machine == 'aarch64', 'actual kernel alarm1001 AArch64 required')
    return c, a


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


def pure_candidate():
    # The complete pinned module has definitions/stdimports only at top level.
    # Only these three data-check functions are called; its preflight/sandbox
    # and helper-loading/operational entry points are never entered.
    return module('llvm23_pinned_candidate_data', CANDIDATE/'reference.py')


def environment():
    return dict(PATH='/usr/bin:/bin', HOME='/work/home', XDG_CONFIG_HOME='/work/home/.config', TMPDIR='/work/tmp', LC_ALL='C', TZ='UTC', MAKEFLAGS='-j2', CMAKE_BUILD_PARALLEL_LEVEL='2', SOURCE_DATE_EPOCH='1791748800', CACHY_ASAHI_LLVM23_BUILD='1', ADMISSION_SHA256=os.environ['ADMISSION_SHA256'], PKGDEST='/work/output', LOGDEST='/work/output', PYTHONDONTWRITEBYTECODE='1')


def natural(row, code=0):
    return row.get('natural_exit') is True and row.get('forced_cleanup') is False and row.get('group_absent') is True and row.get('retirement') == 'REAPED' and row.get('ownership_lost') is False and row.get('leader_held_until_group_inspection') is True and row.get('exit_observed_via_waitpid') is True and row.get('exit') == code and not row.get('cleanup_error')


def remaining():
    state = decode(read(WORK/'actor-clock.json'))
    deadline = state['deadline_monotonic']
    need(type(deadline) in (int, float) and math.isfinite(deadline) and 0 < deadline-time.monotonic() <= ACTOR_SECONDS, 'finite actor deadline required')
    return deadline-time.monotonic()


def command(argv, name, seconds):
    need(re.fullmatch('[a-z0-9-]+', name), 'fixed command log name')
    row = dict(argv=argv, log=name+'.log', log_pin=None, requested_seconds=seconds, timeout_seconds=None, lifecycle={}, returncode=None, success=False)
    timeout = min(seconds, remaining()-60)
    need(timeout > 2, 'actor metadata/retirement reserve exhausted')
    row['timeout_seconds'] = timeout
    owned = module('llvm23_owned_child', INPUTS/'helpers/owned_child.py')
    def tick():
        need(not (WORK/'cancelled').exists() and remaining() > 60, 'actor cancelled or deadline reserve exhausted')
    try:
        tick()
        with (OUT/row['log']).open('xb') as stream:
            result = owned.run(argv, timeout=timeout, cwd=WORK/'recipe', env=environment(), stdout=stream, stderr=subprocess.STDOUT, lifecycle=row['lifecycle'], stdout_limit=LOG_LIMIT, allowed_uids={1001}, on_tick=tick)
        row['returncode'] = result.returncode
        tick()
        need(result.returncode == 0 and natural(row['lifecycle']), 'command failed or natural retirement unproven: '+name)
        row['success'] = True
    finally:
        log = OUT/row['log']
        if log.is_file() and log.stat().st_size <= LOG_LIMIT:
            row['log_pin'] = dict(bytes=log.stat().st_size, sha256=digest(log))
        path = OUT/(name+'.json')
        need(not path.exists(), 'command receipt collision')
        path.write_bytes(encode(row))
    return row


def transform_recipe(raw):
    need(raw.count(ORIGINAL_CALL.encode()) == 1 and CONTAINER_CALL.encode() not in raw, 'exact one candidate _reference call required')
    effective = raw.replace(ORIGINAL_CALL.encode(), CONTAINER_CALL.encode())
    need(effective.replace(CONTAINER_CALL.encode(), ORIGINAL_CALL.encode()) == raw, 'whole recipe literal inverse failed')
    return effective


def receipt_binding(a):
    return {'admission_sha256': os.environ['ADMISSION_SHA256'], 'source_tree_sha256': a['source_tree_sha256']}


def prepared(a):
    value = decode(read(WORK/'prepared.json'))
    need(value == receipt_binding(a), 'prepared binding differs')
    return value


def action(operation, work, destination=None):
    need(work == Path('/work/recipe/src'), 'fixed makepkg srcdir required')
    c, a = context()
    need(operation == 'package' or os.geteuid() == os.getuid() == 1001, 'ordinary alarm1001 build required')
    candidate = pure_candidate()
    if operation == 'prepare':
        need(not (WORK/'prepared.json').exists() and not any((WORK/n).exists() for n in ('tools', 'runtimes', 'built.json', 'checked.json')), 'fresh build required')
        need(candidate.tree_digest(Path('/source')) == a['source_tree_sha256'], 'Root source inventory differs')
        for name, expected in decode(read(CANDIDATE/'inputs.json'))['notices'].items():
            need(digest(Path('/source')/name/'LICENSE.TXT') == expected, 'source notice differs')
        (WORK/'prepared.json').write_bytes(encode(receipt_binding(a)))
        command(['/usr/bin/bash', str(CANDIDATE/'build.sh'), 'probe'], 'probe', STAGES['probe'])
    elif operation == 'build':
        binding = prepared(a)
        need(not any((WORK/n).exists() for n in ('tools', 'runtimes', 'built.json', 'checked.json')), 'single fresh build only')
        for stage in ('tools', 'runtimes'):
            command(['/usr/bin/bash', str(CANDIDATE/'build.sh'), stage], stage, STAGES[stage])
        candidate.check_stage(WORK/'dest')
        (WORK/'built.json').write_bytes(encode(dict(**binding, staged_tree_sha256=candidate.tree_digest(WORK/'dest'))))
    elif operation in ('check', 'package'):
        binding = prepared(a)
        value = decode(read(WORK/('built.json' if operation == 'check' else 'checked.json')))
        need(all(value.get(k) == v for k, v in binding.items()) and value['staged_tree_sha256'] == candidate.tree_digest(WORK/'dest'), 'built/checked stage changed')
        candidate.check_stage(WORK/'dest')
        if operation == 'check':
            need(not (WORK/'checked.json').exists(), 'single check only')
            command(['/usr/bin/bash', str(CANDIDATE/'build.sh'), 'check'], 'check', STAGES['check'])
            (WORK/'checked.json').write_bytes(encode(value))
        else:
            need(destination == Path('/work/recipe/pkg/cachy-asahi-llvm23-source-reference') and destination.is_dir() and not destination.is_symlink() and not list(destination.iterdir()), 'fixed empty makepkg staging required')
            shutil.copytree(WORK/'dest', destination, symlinks=True, dirs_exist_ok=True)
            notices = destination/PREFIX.relative_to('/')/'share/licenses/llvm23-source-reference'
            notices.mkdir(parents=True, exist_ok=True)
            for component in ('llvm', 'clang', 'lld', 'compiler-rt', 'libunwind'):
                shutil.copy2(Path('/source')/component/'LICENSE.TXT', notices/(component+'-LICENSE.TXT'))
            for name in ('LICENSE.packaging', 'inputs.json', 'build.sh'):
                shutil.copy2(CANDIDATE/name, notices/name)
            candidate.check_stage(destination)
    else:
        raise ValueError('fixed makepkg action required')


def main():
    need(sys.flags.isolated and not sys.flags.optimize, 'isolated unoptimized adapter required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'build', 'check', 'package'))
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--destination', type=Path)
    args = parser.parse_args()
    action(args.operation, args.work, args.destination)


if __name__ == '__main__':
    main()
