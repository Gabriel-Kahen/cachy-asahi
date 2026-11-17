#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Actor-free CI over a pinned published Source and the unchanged TEST controls."""
import argparse
import ctypes
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import resource
import stat
import subprocess
import sys
import tarfile
import traceback
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SOURCE = '8fb13c028cf043119f8324eb089c51d74e3891ee'
PARENT = dict(files=367, bytes=43757093, tree='f846369139e03239d500cb737092b5eeb358c260',
              map_sha256='189430cae42422e8f50d8de38a41976d87a8b4a0fcec527a3949d6031eccc2f6')
LIMIT = 512 * 1024**2
SUITES = {
    'admission': ('project_test_provider_v1/test_admission.py', 12),
    'archive': ('project_test_provider_v1/test_archive.py', 8),
    'native': ('project_test_provider_v1/test_native.py', 10),
    'image': ('project_test_provider_v1/test_image.py', 8),
    'v19-source': ('successor_v19/test_source.py', 10),
    'v19-delta': ('successor_v19/test_delta.py', 10),
    'v19-bridge': ('successor_v19/test_bridge.py', 7),
}


def need(value, why):
    if not value:
        raise ValueError(why)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def filesystem():
    path = HERE.parent / 'filesystem.py'
    need(pin(path.read_bytes())['sha256'] == '7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7',
         'immutable bounded filesystem helper')
    fs = module('project_ci_filesystem', path); fs.MAX_FILES = 512
    return fs


def identity(files, fs):
    return dict(files=len(files), bytes=sum(len(raw) for raw, mode in files.values()),
                tree=fs.tree(files), map_sha256=pin(files['source-map.json'][0])['sha256'])


def extract_source(archive_path, commit_raw_path, output):
    """Read Git DATA only. Never import or run any program from the Source."""
    fs = filesystem(); raw, mode = fs.read(fs.absolute(commit_raw_path), 4096)
    headers = raw.split(b'\n\n', 1)[0].splitlines()
    need(mode == 0o644 and fs.oid(b'commit', raw).hex() == SOURCE
         and headers[0] == ('tree ' + PARENT['tree']).encode()
         and not any(row.startswith(b'parent ') for row in headers), 'exact published zero-parent Source367 commit')
    archive, mode = fs.read(fs.absolute(archive_path))
    need(mode == 0o644 and len(archive) % 512 == 0, 'ordinary finite uncompressed Git archive')
    files = {}; directories = set(); total = 0; end = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as stream:
        for index, member in enumerate(stream):
            need(index < 2048 and member.sparse is None, 'finite ordinary published Source archive')
            name = member.name.rstrip('/') if member.isdir() else member.name; fs.relative(name)
            end = member.offset_data + ((member.size + 511) // 512) * 512
            if member.isdir():
                need(member.size == 0 and member.mode == 0o755 and name not in directories
                     and member.name in (name, name + '/'), 'unique ordinary Source directory')
                directories.add(name); continue
            need(member.isfile() and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                 and name not in files and len(files) < fs.MAX_FILES and member.mode in (0o644, 0o755)
                 and 0 < member.size <= fs.MAX_FILE, 'unique regular Source file; no aliases/special files')
            with stream.extractfile(member) as source: body = source.read(member.size + 1)
            total += len(body)
            need(len(body) == member.size and total <= fs.MAX_TOTAL, 'complete bounded Source file bytes')
            files[name] = body, member.mode
            stream.members.clear()
    need(len(archive) - end >= 1024 and not any(archive[end:]), 'complete zero-padded Git tar ending')
    need(directories == {str(p) for n in files for p in PurePosixPath(n).parents if str(p) != '.'},
         'complete exact Source directory census; no extra or empty directories')
    need(identity(files, fs) == PARENT, 'complete genuine Source367 bytes/modes/tree/map')
    mapping = fs.decode(files['source-map.json'][0])
    need(mapping['files'] == fs.descriptors({n: row for n, row in files.items() if n != 'source-map.json'}),
         'whole published Source367 census')
    fs.publish(files, fs.absolute(output))
    return PARENT.copy()


def require_result(result, actor_attempts, expected_count):
    need(result.wasSuccessful() and result.testsRun == expected_count and not result.skipped
         and not result.expectedFailures and not result.unexpectedSuccesses and not actor_attempts,
         'all exact controls pass without skips, expected failures or caught actor attempts')
    return dict(status='PASS_ACTOR_FREE_DATA_ONLY', tests=result.testsRun, skips=0, actor_attempts=0)


def worker(name, parent, receipt):
    resource.setrlimit(resource.RLIMIT_AS, (LIMIT,) * 2)
    attempts = []

    def deny(event, args):
        forbidden = event.startswith(('subprocess.', 'socket.', 'os.exec', 'os.spawn', 'os.fork', 'os.posix_spawn'))
        forbidden |= event in ('os.system', 'fcntl.flock')
        forbidden |= event == 'ctypes.dlopen' and args[0] is not None
        forbidden |= event in ('ctypes.dlsym', 'ctypes.dlsym/handle') and args[1] != 'renameat2'
        if forbidden:
            attempts.append(event)
            raise PermissionError('PROJECT_CI_ACTOR_DENIED: ' + event)

    sys.addaudithook(deny)
    os.environ['RUST199_V19_PARENT'] = str(Path(parent).resolve())
    relative, expected = SUITES[name]
    value = module('project_ci_' + name.replace('-', '_'), HERE.parent / relative)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(value))
    report = require_result(result, attempts, expected)
    report.update(suite=name, native='NOT RUN', signing='NOT RUN', Root_grants=None, Source_issued=False)
    with Path(receipt).open('xb') as stream: stream.write(encode(report))
    return report


def run(archive_path, commit_raw_path, output):
    fs = filesystem(); output = fs.absolute(output)
    sources = tuple(map(fs.absolute, (archive_path, commit_raw_path)))
    need(not output.is_relative_to(ROOT) and not any(
        output == p or p.is_relative_to(output) or output.is_relative_to(p) for p in sources),
        'fresh evidence outside the checkout and Source input domains')
    parent = fs.directory(output.parent)
    try:
        info = os.fstat(parent)
        need(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o022, 'private owned evidence parent')
        os.mkdir(output.name, 0o700, dir_fd=parent)
    finally:
        os.close(parent)
    report = dict(schema=1, status='FAIL', source=SOURCE, Source_issued=False, parent=PARENT,
                  tests=0, suites=[], errors=[], native='NOT RUN', signing='NOT RUN',
                  Root_grants=None, provider_tuples='UNBOUND', RLIMIT_AS=LIMIT)
    try:
        source = output / 'Source367'; extract_source(*sources, source)
        tmp = output / 'tmp'; tmp.mkdir(mode=0o700)
        env = dict(PATH=os.environ.get('PATH', '/usr/bin:/bin'), LC_ALL='C', TZ='UTC', TMPDIR=str(tmp),
                   RUST199_V19_PARENT=str(source))
        for name, (relative, expected) in SUITES.items():
            log = output / (name + '.rawlog'); receipt = output / (name + '.DATA.json')
            argv = [sys.executable, '-I', '-B', '-Werror::ResourceWarning', str(Path(__file__).resolve()),
                    '--worker', name, '--parent', str(source), '--receipt', str(receipt)]
            with log.open('xb') as stream:
                done = subprocess.run(argv, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                      stdout=stream, stderr=subprocess.STDOUT, timeout=180, check=False)
            raw, mode = fs.read(log, 2 * 1024**2)
            print(raw.decode('utf-8', errors='replace'), end='', flush=True)
            need(done.returncode == 0 and receipt.is_file(), 'complete successful actor-free suite: ' + name)
            result = json.loads(fs.read(receipt, 65536)[0])
            need(result == dict(status='PASS_ACTOR_FREE_DATA_ONLY', tests=expected, skips=0, actor_attempts=0,
                suite=name, native='NOT RUN', signing='NOT RUN', Root_grants=None, Source_issued=False),
                'exact worker result and held authority')
            report['suites'].append(dict(name=name, argv=argv, returncode=done.returncode,
                tests=expected, rawlog=pin(raw), receipt=pin(encode(result))))
            report['tests'] += expected
        need(report['tests'] == 65, '38 interface plus 27 v19 controls, without double counting')
        report['status'] = 'PASS_ACTOR_FREE_DATA_ONLY'
    except BaseException as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error)); raise
    finally:
        with (output / 'result.DATA.json').open('xb') as stream: stream.write(encode(report))
    return report


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_AS, (LIMIT,) * 2)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', choices=tuple(SUITES))
    for key in ('parent', 'receipt', 'source-archive', 'source-commit', 'output'):
        parser.add_argument('--' + key, type=Path)
    args = parser.parse_args()
    try:
        if args.worker:
            need(args.parent is not None and args.receipt is not None, 'explicit worker operands')
            value = worker(args.worker, args.parent, args.receipt)
        else:
            need(all(p is not None for p in (args.source_archive, args.source_commit, args.output)), 'explicit published Git DATA and fresh evidence required')
            value = run(args.source_archive, args.source_commit, args.output)
        print(encode(value).decode(), end='')
    except BaseException:
        traceback.print_exc(); raise SystemExit(1)
