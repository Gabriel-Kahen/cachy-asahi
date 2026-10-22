#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce exact public Core800 or explicit historical failed lifecycle source; no actors or acceptance."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import shutil
import tempfile
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PROFILE_SHA256 = 'ca147eb320a88d6e848b8acef0f64ee37b4e190573de626a0b1384a3174c3aee'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def read(path, cap=32 * 1024**2):
    path = Path(path).absolute()
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary source ancestry')
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= cap, 'bounded ordinary single-link source')
        chunks, size = [], 0
        while block := os.read(descriptor, 1024**2):
            size += len(block)
            need(size <= cap, 'whole source byte cap')
            chunks.append(block)
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        need(size == before.st_size and identity(before) == identity(os.fstat(descriptor))
             == identity(path.lstat()), 'stable source identity and bytes; atime excluded')
        return b''.join(chunks)
    finally:
        os.close(descriptor)


def files(root, *, checkout=False):
    root = Path(root).absolute()
    need(root.is_dir() and not any(p.is_symlink() for p in (root, *root.parents)),
         'explicit ordinary source directory')
    result = {}
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root)
        if checkout and relative.parts[0] == '.git':
            continue  # Checkout metadata is not a source leaf.
        need(not path.is_symlink() and (path.is_file() or path.is_dir()),
             'ordinary complete source namespace')
        if path.is_file():
            result[relative.as_posix()] = pin(read(path))
    return result


def profile():
    raw = read(HERE / 'profile.json', 1024**2)
    need(pin(raw)['sha256'] == PROFILE_SHA256, 'whole fixed Core796 factory profile')
    value = json.loads(raw)
    fixed = value['baseline_scriptlet']
    baseline = read(HERE / fixed['path'], 1024**2)
    need(pin(baseline) == {k: fixed[k] for k in ('bytes', 'sha256')}, 'whole fixed baseline800 profile')
    value['baseline_scriptlet'] = json.loads(baseline)
    need(value['schema'] == 1
         and value['purpose'] == 'MAINTAINED_FINITE_CORE800_AND_HISTORICAL_FAILED_SOURCES_ONLY'
         and len(value['parent']['files']) == 745 and len(value['payload']) == 49
         and len(value['expected']['files']) == len(value['workflow_launch']['files']) == 796
         and value['actual'] is value['workflow_launch']['actual'] is None
         and value['old_target261'] == 'UNCHANGED_UNACCEPTED'
         and len(value['evidence_transport']['files']) == 796
         and value['evidence_transport']['actual'] is None
         and len(value['auth_import']['files']) == 797
         and value['auth_import']['actual'] is None
         and len(value['baseline_scriptlet']['files']) == 800
         and value['baseline_scriptlet']['actual'] is None
         and value['default_mode'] == 'baseline-scriptlet', 'fixed source-only scope')
    return value


@contextmanager
def modules(root):
    """Bind sibling imports to this one payload, then restore the caller exactly."""
    saved_modules, saved_path = dict(sys.modules), sys.path[:]
    try:
        sys.path.insert(0, str(root))
        for path in root.glob('*.py'):
            sys.modules.pop(path.stem, None)
        yield
    finally:
        sys.path[:] = saved_path
        for name in set(sys.modules) - set(saved_modules):
            sys.modules.pop(name, None)
        sys.modules.update(saved_modules)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def assemble(runtime, output, mode='baseline-scriptlet'):
    runtime, output = Path(runtime).absolute(), Path(output).absolute()
    value = profile()
    need(mode in ('original796', 'workflow-launch', 'evidence-transport', 'auth-import', 'baseline-scriptlet'), 'explicit fixed source mode')
    expected = {'original796': value['expected'], 'workflow-launch': value['workflow_launch'],
                'evidence-transport': value['evidence_transport'], 'auth-import': value['auth_import'], 'baseline-scriptlet': value['baseline_scriptlet']}[mode]
    payload = HERE / 'payload'
    need(files(payload) == value['payload'], 'whole exact49 maintained payload')
    need(files(runtime, checkout=True) == value['parent']['files'], 'whole exact public745 predecessor')
    need(not output.exists() and output.parent.is_dir()
         and not any(p.is_symlink() for p in (output, *output.parents))
         and all(not output.is_relative_to(root) and not root.is_relative_to(output)
                 for root in (runtime, HERE)), 'fresh disjoint output before emission')
    def emit(factory_root):
        with modules(factory_root):
            factory = load(factory_root / 'prepare.py', '_fixed_core796_payload_factory')
            return factory.emit(runtime, output)  # The frozen source-contained emitter.
    if mode == 'original796':
        receipt = emit(payload)
    elif mode in ('evidence-transport', 'auth-import', 'baseline-scriptlet'):
        replacements = expected['replacements']
        need(set(replacements) == ({'owner.py', 'entry.py', 'workflow.yml.in', 'assemble.py'}
                                   if mode == 'auth-import' else {'owner.py', 'entry.py', 'workflow.yml.in', 'assemble.py', 'contract.py', 'container.py'}
                                   if mode == 'baseline-scriptlet' else {'owner.py', 'entry.py', 'workflow.yml.in'}),
             'exact three source-owned evidence transport bodies')
        bodies = {}
        for name, row in replacements.items():
            raw = read(HERE / row['path'])
            need(pin(raw) == {key: row[key] for key in ('bytes', 'sha256')}
                 and pin(read(payload / name)) == row['before'],
                 'whole fixed transport replacement and original body')
            bodies[name] = raw
        additions = expected.get('additions', {})
        need(set(additions) == ({'core-tools/package_checks.py'} if mode == 'auth-import' else {'core-tools/package_checks.py', 'fixture.py', 'audio_aux.py', 'test_fixture.py'}
                                    if mode == 'baseline-scriptlet' else set()),
             'exact original package_checks dependency only')
        for name, row in additions.items():
            raw = read(HERE / row['path'])
            need(pin(raw) == {key: row[key] for key in ('bytes', 'sha256')}
                 and not (payload / name).exists(), 'whole original added dependency')
            bodies[name] = raw
        with tempfile.TemporaryDirectory(prefix='core796-evidence-factory-') as temporary:
            factory_root = Path(temporary) / 'factory'
            shutil.copytree(payload, factory_root)
            for name, raw in bodies.items():
                (factory_root / name).write_bytes(raw)
            receipt = emit(factory_root)
    else:
        template = read(HERE / expected['template']['path'])
        need(pin(template) == {key: expected['template'][key] for key in ('bytes', 'sha256')},
             'whole fixed workflow-launch template')
        before = read(payload / 'workflow.yml.in')
        old, new = expected['before'].encode(), expected['proposed'].encode()
        need(before.count(old) == template.count(new) == 1
             and template.replace(new, old, 1) == before, 'exact single job.env literal inverse')
        with tempfile.TemporaryDirectory(prefix='core796-launch-factory-') as temporary:
            factory_root = Path(temporary) / 'factory'
            shutil.copytree(payload, factory_root)
            (factory_root / 'workflow.yml.in').write_bytes(template)
            receipt = emit(factory_root)
    need(files(output) == expected['files'] and receipt['held'] == 744,
         'whole exact selected public source and original744 held bodies')
    with modules(output / 'scripts/ci/core-native-lifecycle'):
        entry = load(output / 'scripts/ci/core-native-lifecycle/entry.py',
                     '_fixed_core796_emitted_entry')
        entry.source(output)
    return {'status': ('EMITTED_EXACT_PUBLIC_CORE800_SOURCE_ONLY' if mode == 'baseline-scriptlet'
                       else 'EMITTED_EXACT_PUBLIC_CORE797_SOURCE_ONLY' if mode == 'auth-import'
                       else 'EMITTED_EXACT_PUBLIC_CORE796_SOURCE_ONLY'), 'files': len(expected['files']),
            'parent_source': value['parent']['source'], 'expected_source': expected['source'], 'source_mode': mode,
            'payload_files': 49, 'held_parent_files': 744, 'bounds': value['bounds'],
            'actual': None, 'GPG': 'NOT_RUN', 'native_lifecycle': 'NOT_RUN_BY_FACTORY',
            'dispatch': ('HISTORICAL_HTTP422_NO_RUN_DO_NOT_DISPATCH' if mode == 'original796'
                         else 'HISTORICAL_NATIVE_FAILURE_ZERO_ARTIFACTS_DO_NOT_DISPATCH'
                         if mode == 'workflow-launch'
                         else 'HISTORICAL_NATIVE_AUTH_IMPORT_FAILURE_DO_NOT_DISPATCH'
                         if mode == 'evidence-transport'
                         else 'HISTORICAL_SCRIPTLET_ACCOUNT_CACHE_REFUSAL_DO_NOT_DISPATCH'
                         if mode == 'auth-import'
                         else 'SEPARATE_ROOT_NATIVE_DISPATCH_AND_ACCEPTANCE_REQUIRED'),
            'M2': 'NOT_RUN', 'old_target261': 'UNCHANGED_UNACCEPTED', 'release': 'NOT_ADMITTED'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True,
                        help='Complete exact public d268745 source checkout; never fetched here')
    parser.add_argument('--output', type=Path, required=True, help='Fresh disjoint source directory')
    parser.add_argument('--mode', choices=('original796', 'workflow-launch', 'evidence-transport', 'auth-import', 'baseline-scriptlet'), default='baseline-scriptlet',
                        help='Core800 by default; all previous modes reproduce failed or undispatched source only')
    args = parser.parse_args()
    print(json.dumps(assemble(args.runtime, args.output, args.mode), sort_keys=True, indent=2))
