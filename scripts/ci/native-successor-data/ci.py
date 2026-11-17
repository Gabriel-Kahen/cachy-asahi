#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite source-only CI; public DATA and MODEL tests confer no Root authority."""
import argparse
import ast
import ctypes
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import resource
import runpy
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
LIMIT = 512 * 1024**2
FS_PIN = '7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7'
SUITES = {
    'audio': ('scripts/ci/bankstown-qt3-source79-adoption-data/test_adopt.py', 26),
    'native-source': ('scripts/ci/llhttp-reference-native-source/successor_v2/test_data.py', 7),
    'libgit2': ('scripts/ci/libgit2-reference-native-source/test_data.py', 23),
    'libgit2-interop': ('scripts/ci/libgit2-reference-native-source/test_interop.py', 1),
    'libgit2-va': ('scripts/ci/libgit2-reference-native-source/successor_v2/test_data.py', 7),
    'fish-v5': ('scripts/ci/fish-config02-native-source/successor_v5/test_data.py', 8),
    'ci-guards': ('scripts/ci/native-successor-data/test_ci.py', 8),
    'source85': ('scripts/ci/llhttp-reference-native-source/successor_v4/test_data.py', 7),
    'filebackend': ('scripts/integration/arm16k_perl_ldcache_file_backend/test_chain.py', 10),
    'semantic': ('scripts/integration/arm16k_perl_ldcache_semantic_transition/test_semantics.py', 16),
}


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def filesystem():
    path = ROOT / 'scripts/ci/rust199-source-reference-native/filesystem.py'
    need(pin(path.read_bytes())['sha256'] == FS_PIN, 'immutable filesystem helper')
    return load(path, 'successor_ci_filesystem')


def checked_file(path, expected, fs):
    raw, mode = fs.read(fs.absolute(path), 32 * 1024**2)
    need(pin(raw) == {k: expected[k] for k in ('bytes', 'sha256')} and mode == expected.get('mode', 0o644),
         'whole pinned ordinary DATA file: ' + str(path))
    return raw


def tar_files(raw, fs):
    need(type(raw) is bytes and 0 < len(raw) <= 32 * 1024**2 and len(raw) % 512 == 0, 'finite Git tar')
    files = {}; directories = set(); total = end = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as stream:
        for index, member in enumerate(stream):
            need(index < 1024 and member.sparse is None, 'bounded ordinary Git tar census')
            name = member.name.rstrip('/') if member.isdir() else member.name; fs.relative(name)
            end = member.offset_data + ((member.size + 511) // 512) * 512
            if member.isdir():
                need(name not in directories and member.size == 0 and member.mode == 0o755, 'unique ordinary directory')
                directories.add(name); continue
            need(member.isfile() and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                 and name not in files and member.mode in (0o644, 0o755)
                 and 0 < member.size <= 16 * 1024**2, 'unique bounded regular Git file')
            with stream.extractfile(member) as source: body = source.read(member.size + 1)
            total += len(body); need(len(body) == member.size and total <= 32 * 1024**2, 'complete bounded DATA bytes')
            files[name] = body, member.mode
            stream.members.clear()
    need(len(raw) - end >= 1024 and not any(raw[end:]), 'complete zero-padded tar ending')
    need(directories == {str(p) for n in files for p in PurePosixPath(n).parents if str(p) != '.'},
         'complete exact directory census; no extra or empty directories')
    return files


def identity(files, fs):
    return dict(files=len(files), bytes=sum(len(raw) for raw, mode in files.values()), tree=fs.tree(files),
                source_map=pin(files['source-map.json'][0]))


def extract_source(inputs, name, expected, output, fs):
    commit, mode = fs.read(inputs / (name + '.commit'), 4096)
    headers = commit.split(b'\n\n', 1)[0].splitlines()
    need(mode == 0o644 and fs.oid(b'commit', commit).hex() == expected['commit']
         and headers[0] == ('tree ' + expected['tree']).encode()
         and not any(row.startswith(b'parent ') for row in headers), 'exact published zero-parent commit')
    raw, mode = fs.read(inputs / (name + '.tar'), 32 * 1024**2); need(mode == 0o644, 'ordinary Git tar mode')
    files = tar_files(raw, fs)
    wanted = {k: expected[k] for k in ('files', 'bytes', 'tree')}
    wanted['source_map'] = {k: expected['source_map'][k] for k in ('bytes', 'sha256')}
    need(identity(files, fs) == wanted, 'exact complete published Source tuple')
    mapping = fs.decode(files['source-map.json'][0])
    need(mapping['files'] == fs.descriptors({n: row for n, row in files.items() if n != 'source-map.json'}),
         'whole Source member pins and modes')
    fs.publish(files, output)
    return wanted


def prepare(inputs, output):
    fs = filesystem(); native = fs.decode((HERE / 'native-fish-inputs.lock.json').read_bytes())
    lib = fs.decode((HERE / 'libgit2-inputs.lock.json').read_bytes())
    sources = {name: extract_source(inputs, name, spec, output / name, fs) for name, spec in native['sources'].items()}
    raw, mode = fs.read(inputs / 'recipes.tar', 32 * 1024**2); need(mode == 0o644, 'ordinary recipe tar')
    commit, mode = fs.read(inputs / 'recipes.commit', 4096)
    need(mode == 0o644 and fs.oid(b'commit', commit).hex() == lib['recipe_checkout']['commit']
         and commit.splitlines()[0] == ('tree ' + lib['recipe_checkout']['tree']).encode(), 'exact original recipe commit/tree')
    recipes = tar_files(raw, fs); expected_recipes = {}
    for recipe in lib['recipe_checkout']['recipes'].values():
        for leaf, spec in recipe['files'].items():
            name = recipe['path'] + '/' + leaf
            need(name in recipes and pin(recipes[name][0]) == {k: spec[k] for k in ('bytes', 'sha256')}
                 and recipes[name][1] == spec['mode']
                 and fs.oid(b'blob', recipes[name][0]).hex() == spec['git_blob'], 'exact original recipe leaf')
            expected_recipes[name] = spec
    need(set(recipes) == set(expected_recipes), 'exact complete two-recipe namespace')
    fs.publish(recipes, output / 'recipes')
    for name, spec in lib['consumer']['files'].items(): checked_file(ROOT / name, spec, fs)
    for spec in lib['author_descriptors'].values(): checked_file(ROOT / spec['path'], spec, fs)
    for name, spec in lib['upstream_archives'].items(): checked_file(inputs / spec['filename'], spec, fs)
    for name, spec in native['fish50']['constructor_operands'].items(): checked_file(ROOT / name, spec, fs)
    constructor = load(ROOT / native['fish50']['constructor'], 'successor_ci_fish_constructor')
    constructor.construct(output / 'fish48', output / 'fish50')
    files = fs.snapshot(output / 'fish50')
    need(identity(files, fs) == native['fish50']['expected'], 'exact unissued reconstructed Source50')
    diagnostic = fs.decode((HERE / 'diagnostic-cache-inputs.lock.json').read_bytes())
    for name, spec in diagnostic['constructors'].items(): checked_file(ROOT / name, spec, fs)
    for selection in diagnostic['suites'].values(): checked_file(ROOT / selection['path'], selection['whole_test_pin'], fs)
    family = ROOT / 'scripts/ci/llhttp-reference-native-source'
    load(family / 'successor_v2/prepare.py', 'ci_source68').construct(output / 'llhttp62', output / 'llhttp68')
    load(family / 'successor_v3/prepare.py', 'ci_source76').construct(output / 'llhttp68', output / 'llhttp76')
    source76 = identity(fs.snapshot(output / 'llhttp76'), fs)
    need(source76 == diagnostic['source76_expected'], 'whole exact reconstructed Source76 tuple')
    load(family / 'successor_v4/prepare.py', 'ci_source85_parent').parent_bodies(output / 'llhttp76')
    return dict(published_sources=sources, fish50=identity(files, fs), recipes=len(recipes), consumer_files=7,
                reconstructed_source76=source76, source76_publication_checked_here=False,
                cache_baseline='HOLD_MISSING_ACTUAL_BASELINE_BODY', Root_authority=None)


def temporary_parent(value, target):
    return target if value is not None and os.fspath(value) in ('/home/gabe', '/home/gabe/.cache') else value


def require_result(result, attempts, expected):
    need(result.wasSuccessful() and result.testsRun == expected and not result.skipped
         and not result.expectedFailures and not result.unexpectedSuccesses and not attempts,
         'exact control count, zero skips/failures/expected failures/actor attempts required')
    return dict(tests=result.testsRun, skips=0, actor_attempts=0)


def native_members(raw, selection):
    tree = ast.parse(raw)
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Controls']
    need(len(classes) == 1, 'one native author Controls class')
    declared = {node.name for node in classes[0].body if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')}
    registered, blocked = set(selection['registered_methods']), set(selection['blocked_methods'])
    need(len(declared) == selection['original_count'] and len(registered) == selection['registered_count']
         and not registered & blocked and registered | blocked == declared,
         'every native author control must be registered or explicitly blocked; no hidden selection drift')


def actor_forbidden(event, args):
    return (event.startswith(('subprocess.', 'socket.', 'os.exec', 'os.spawn', 'os.fork', 'os.posix_spawn'))
            or event in ('os.system', 'os.kill', 'os.killpg', 'os.pidfd_open', 'fcntl.flock', 'resource.setrlimit')
            or event == 'ctypes.dlopen' and args[0] is not None
            or event in ('ctypes.dlsym', 'ctypes.dlsym/handle') and args[1] != 'renameat2')


def install_fence():
    attempts = []
    def deny(event, args):
        if actor_forbidden(event, args):
            attempts.append(event); raise PermissionError('SUCCESSOR_CI_NO_ACTOR: ' + event)
    sys.addaudithook(deny)
    return attempts


def limits():
    resource.setrlimit(resource.RLIMIT_AS, (LIMIT,) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024**2,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (120,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (256,) * 2)


def worker(name, inputs, data, receipt):
    limits()
    attempts = install_fence()
    fs = filesystem(); native = fs.decode((HERE / 'native-fish-inputs.lock.json').read_bytes())
    lib = fs.decode((HERE / 'libgit2-inputs.lock.json').read_bytes())
    os.environ.update(LLHTTP_VA_PARENT=str(data / 'llhttp62'), LLHTTP_V4_PARENT=str(data / 'llhttp76'),
                      LIBGIT2_CONSUMER_ROOT=str(ROOT),
                      LIBGIT2_DATA_RECIPE_ROOT=str(data / 'recipes'),
                      LIBGIT2_DATA_ARCHIVE=str(inputs / lib['upstream_archives']['libgit2']['filename']),
                      LLHTTP_DATA_ARCHIVE=str(inputs / lib['upstream_archives']['llhttp']['filename']))
    # Only temporary test-parent literals change. No operand/Path/read/authority API is replaced.
    original_temp = tempfile.mkdtemp
    target = data / ('tmp-' + name); target.mkdir(mode=0o700)
    def portable_temp(suffix=None, prefix=None, dir=None):
        return original_temp(suffix, prefix, temporary_parent(dir, target))
    tempfile.mkdtemp = portable_temp
    results = []; original_main = unittest.main
    def observed_main(*args, **kwargs):
        kwargs['exit'] = False
        value = original_main(*args, **kwargs); results.append(value.result); return value
    unittest.main = observed_main
    script, expected = SUITES[name]; sys.argv = [str(ROOT / script)]
    if name == 'native-source':
        selection = native['native_source_controls']; native_members((ROOT / script).read_bytes(), selection)
        sys.argv += ['Controls.' + method for method in selection['registered_methods']]
    if name in ('source85', 'filebackend', 'semantic'):
        diagnostic = fs.decode((HERE / 'diagnostic-cache-inputs.lock.json').read_bytes())
        selection = diagnostic['suites'][name]
        need(selection['path'] == script and selection['registered_count'] == expected, 'exact new suite binding')
        checked_file(ROOT / script, selection['whole_test_pin'], fs)
        native_members((ROOT / script).read_bytes(), selection)
        if selection['blocked_methods']:
            sys.argv += ['Controls.' + method for method in selection['registered_methods']]
    if name == 'fish-v5':
        os.environ['TMPDIR'] = '/tmp'  # The unchanged author CLI explicitly requires /tmp or /dev/shm.
        sys.argv += ['--base', str(data / 'fish50')]
    # Retain this output FD before Fish installs its stricter fixture-only open fence.
    # No author fence is changed; no post-fence path open is needed for the receipt.
    with receipt.open('xb') as stream:
        runpy.run_path(str(ROOT / script), run_name='__main__')
        need(len(results) == 1, 'one unchanged author CLI unittest result')
        report = dict(status='PASS_SOURCE_DATA_ONLY', suite=name, **require_result(results[0], attempts, expected),
                      temporary_parent_remap='test temporary directories only', native='NOT RUN', Root_authority=None)
        stream.write(encode(report))
    return report


def run(inputs, output):
    fs = filesystem(); inputs, output = fs.absolute(inputs), fs.absolute(output)
    need(not output.is_relative_to(ROOT) and output != inputs and not output.is_relative_to(inputs)
         and not inputs.is_relative_to(output), 'fresh evidence outside code and input domains')
    fd = fs.directory(output.parent)
    try:
        info = os.fstat(fd); need(info.st_uid == os.getuid() and not info.st_mode & 0o022, 'owned output parent')
        os.mkdir(output.name, 0o700, dir_fd=fd)
    finally: os.close(fd)
    report = dict(status='FAIL', tests=0, author_controls=105, existing_controls=80, added_controls=33, CI_guards=8, suites=[], errors=[],
                  blocked_native_controls=12, blocked_source85_actual87=1, blocked_semantic_model_shell=2,
                  cache_baseline='HOLD_MISSING_ACTUAL_BASELINE_BODY', Root_authority=None, native='NOT RUN', M2='NOT RUN')
    try:
        # Setup imports only pinned pure constructors under the same actor boundary in its own worker.
        setup_log = output / 'prepare.rawlog'
        env = dict(PATH=os.environ.get('PATH', '/usr/bin:/bin'), LC_ALL='C', TZ='UTC', TMPDIR=str(output))
        command = [sys.executable, '-I', '-B', '-Werror::ResourceWarning', str(HERE / 'ci.py')]
        with setup_log.open('xb') as stream:
            done = subprocess.run(command + ['--prepare', '--inputs', str(inputs), '--output', str(output)],
                                  env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=120)
        need(done.returncode == 0 and setup_log.stat().st_size < 4 * 1024**2, 'pinned DATA preparation failed; see rawlog')
        report['inputs'] = fs.decode((output / 'inputs.DATA.json').read_bytes())
        for name in SUITES:
            log = output / (name + '.rawlog'); receipt = output / (name + '.DATA.json')
            with log.open('xb') as stream:
                done = subprocess.run(command + ['--worker', name, '--inputs', str(inputs), '--output', str(output),
                                                '--receipt', str(receipt)], env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=180)
            need(done.returncode == 0 and log.stat().st_size < 4 * 1024**2, 'suite failed: ' + name + '; see rawlog')
            row = fs.decode(receipt.read_bytes()); need(row['tests'] == SUITES[name][1] and row['skips'] == row['actor_attempts'] == 0, 'exact worker result')
            report['suites'].append(row); report['tests'] += row['tests']
        need(report['tests'] == 113, 'all existing80 and new33 controls; zero skipped or model phase acceptance')
        report['status'] = 'PASS_SOURCE_DATA_ONLY'
    except Exception as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
        for path in sorted(output.glob('*.rawlog')):
            print(path.name + ':\n' + path.read_bytes()[-8192:].decode('utf-8', 'replace'), file=sys.stderr)
    (output / 'result.DATA.json').write_bytes(encode(report))
    print(json.dumps(report, sort_keys=True)); return report['status'] == 'PASS_SOURCE_DATA_ONLY'


if __name__ == '__main__':
    need(__debug__ and sys.flags.isolated and sys.dont_write_bytecode, 'use unoptimized Python -I -B')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--worker', choices=SUITES); parser.add_argument('--receipt', type=Path)
    parser.add_argument('--prepare', action='store_true'); args = parser.parse_args()
    if args.prepare:
        limits(); attempts = install_fence()
        result = prepare(args.inputs, args.output); need(not attempts, 'preparation actor attempted')
        (args.output / 'inputs.DATA.json').write_bytes(encode(result))
    elif args.worker: worker(args.worker, args.inputs, args.output, args.receipt)
    else: sys.exit(0 if run(args.inputs, args.output) else 1)
