#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the exact generated observer and guest drain without a VM or signer."""

import argparse
import ast
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import installed606_progress as progress


ARCHIVES = ['archlinuxarm-keyring-20240419-2-any', 'hyprland-guiutils-0.2.2-4-aarch64',
            'thunar-4.20.10-1-aarch64', 'waybar-0.15.0-3-aarch64',
            'xdg-desktop-portal-hyprland-1.4.1-2-aarch64']
CARRIER = 'ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'


def module(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def controls(generated, directory):
    raw = progress.guest(generated.read_text())
    tree = ast.parse(raw)
    nodes = [node for node in tree.body if getattr(node, 'name', None) in ('Logged', 'Installed606ProgressForward')
             or isinstance(node, ast.Assign) and any(getattr(target, 'id', '').startswith('INSTALLED606_') for target in node.targets)]
    namespace = {'json': json, 'SHARE': directory, 'emit': Mock(),
                 'subprocess': SimpleNamespace(DEVNULL=None, PIPE=None,
                                               Popen=Mock(return_value=SimpleNamespace(stdout=None, stderr=None))),
                 'threading': SimpleNamespace(Thread=Mock())}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(generated), 'exec'), namespace)
    argv = ['/usr/bin/python3', '-I', '-B', str(directory / 'installed606.py'), 'verify', '/',
            str(directory / 'alpm_reader.py'), str(directory / 'expected.lock'), str(directory / 'installed606.json')]
    construct = namespace['Logged']
    assert construct(argv, 'installed606-preserved', directory, {}).forward is not None
    assert construct(argv, 'foreign', directory, {}).forward is None
    assert construct(argv[:4] + ['capture'] + argv[5:], 'installed606-preserved', directory, {}).forward is None
    rows = []
    forward = namespace['Installed606ProgressForward'](lambda event, **row: rows.append((event, row)))
    prefix = namespace['INSTALLED606_PREFIX']
    data = dict(schema=1, phase='inventory_begin', ordinal=1, elapsed_ns=123, nodes=0, payload_bytes=0, package_ordinal=0)

    def framed(**extra):
        return prefix + json.dumps(dict(data, **extra), separators=(',', ':'), sort_keys=True).encode() + b'\n'

    first = framed()
    invalid = framed(ordinal=2, nodes=True) + framed(ordinal=3, elapsed_ns=-1)
    stderr = directory / 'selected.stderr'
    logged = namespace['Logged'].__new__(namespace['Logged'])
    logged.forward = forward
    logged.paths = [directory / 'selected.stdout', stderr]
    logged.errors = []
    logged.overflow = False
    namespace['MAX_LOG'] = 65536
    segments = [b'foreign\n' + first[:28], first[28:] + invalid + b'x'*500, b'\n' + framed(ordinal=4, phase='payload_begin', elapsed_ns=456)]

    class Pipe(io.BytesIO):
        def read1(self, _):
            if not segments:
                assert len(rows) == 2, 'valid diagnostics must forward before the child pipe closes'
                return b''
            return segments.pop(0)

    logged.drain(Pipe(), stderr)
    assert not logged.errors and not logged.overflow
    assert [row['observer_stage'] for _, row in rows] == ['inventory_begin', 'payload_begin']
    assert all(event == 'installed606_observer_DATA' and row['status'] == 'DIAGNOSTIC_ONLY_NOT_ACCEPTANCE' for event, row in rows)
    assert stderr.read_bytes() == b'foreign\n' + first + invalid + b'x'*500 + b'\n' + framed(ordinal=4, phase='payload_begin', elapsed_ns=456)
    assert raw.count('timeout=600') == generated.read_text().count('timeout=600')


def corpus(repo, source, root):
    expected = dict(line.split() for line in (source / 'factory/expected606.lock').read_text().splitlines())
    pins = json.loads((source / 'factory/retained-helpers/carrier-profile.json').read_text())['files']
    pins_used = {}
    ownership = {}
    git_env = dict(PATH=os.defpath, GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_NO_LAZY_FETCH='1', GIT_NO_REPLACE_OBJECTS='1')
    for archive_name in ARCHIVES:
        leaf = 'packages/' + archive_name + '.pkg.tar.xz'
        meta = pins[leaf]
        assert meta['bytes'] < 2 * 1024**2
        raw = subprocess.run(['/usr/bin/git', '-C', str(repo), '-c', 'protocol.allow=never', 'cat-file', 'blob', CARRIER + ':' + leaf],
                             env=git_env, capture_output=True, check=True, timeout=10).stdout
        assert (len(raw), hashlib.sha256(raw).hexdigest()) == (meta['bytes'], meta['sha256'])
        pins_used[leaf] = meta
        package = archive_name.rsplit('-', 3)[0]
        assert package in expected
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:xz') as stream:
            members = [member for member in stream if not member.name.startswith('.')]
            assert all(member.name.startswith(('usr/', 'etc/')) or member.name in ('usr', 'etc') for member in members)
            stream.extractall(root, members=members, filter='data')
        ownership[package] = [member.name for member in members if not member.isdir()]

    db = root / 'var/lib/pacman/local'
    db.mkdir(parents=True)
    (db / 'ALPM_DB_VERSION').write_bytes(b'9\n')
    for name, version in sorted(expected.items()):
        package = db / (name + '-' + version)
        package.mkdir()
        (package / 'desc').write_text(f'%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%ARCH%\naarch64\n')
        names = ownership.get(name, [])
        (package / 'files').write_text('%FILES%\n' + '\n'.join(names) + '\n' if names else '')
    return expected, pins_used


def run(args):
    with tempfile.TemporaryDirectory(prefix='actual-package-fixture-') as tmp:
        directory = Path(tmp)
        controls(args.generated_guest, directory)
        root = directory / 'root'
        root.mkdir()
        expected, pins = corpus(args.repo, args.source, root)
        support = args.source / 'factory/support'
        before = (support / 'installed604.py').read_text().replace('604', '606')
        after = progress.observer(before)
        for name in ('alpm_reader.py', 'file_capabilities.py'):
            (directory / name).write_bytes((support / name).read_bytes())
        helper = module(directory / 'alpm_reader.py')
        original_path, updated_path = (directory / name for name in ('before.py', 'after.py'))
        original_path.write_text(before)
        updated_path.write_text(after)
        original, updated = module(original_path), module(updated_path)
        control = original.observe(root, helper, expected)
        rows = []
        observed = updated.observe(root, helper, expected, report=lambda *row: rows.append(row))
        assert control == observed and original.encoded(control) == updated.encoded(observed)
        assert rows[0] == ('inventory_begin',) and rows[-1][0] == 'recheck_end'
        assert rows[-1][1:] == (len(control['nodes']), control['payload_bytes'], 606)
        assert all(row[0] != 'payload_progress' for row in rows), 'small authentic payload corpus stays below one progress bucket'
        times = [[], []]
        for pair in range(7):
            for choice in (pair % 2, 1 - pair % 2):
                start = time.monotonic()
                result = (updated.observe(root, helper, expected, report=lambda *_: None) if choice
                          else original.observe(root, helper, expected))
                times[choice].append(time.monotonic() - start)
                assert result == control
        # Cross a fixed bucket with an isolated ALPM fixture and verify live ordinals.
        extra = root / 'usr/share/progress-test'
        extra.mkdir()
        names = []
        for index in range(2048):
            entry = extra / str(index)
            entry.write_bytes(b'fixture')
            names.append(entry.relative_to(root).as_posix())
        record = root / 'var/lib/pacman/local' / ('zstd-' + expected['zstd']) / 'files'
        previous = record.read_bytes()
        assert previous == b''
        record.write_text('%FILES%\n' + '\n'.join(names) + '\n')
        rows = []
        updated.observe(root, helper, expected, report=lambda *row: rows.append(row))
        bucket = [row for row in rows if row[0] == 'payload_progress']
        assert len(bucket) == 1 and bucket[0][1] == 2048 and bucket[0][3] == sorted(expected).index('zstd') + 1
        record.write_bytes(previous)
        # Run both original safety failures through the unchanged ALPM and observer gates.
        path = next(name for name, row in control['nodes'].items() if row['type'] == 'file')
        for implementation in (original, updated):
            target = root / path
            os.setxattr(target, 'user.progress-test', b'foreign')
            try:
                implementation.observe(root, helper, expected)
            except ValueError as error:
                assert str(error) == 'unknown xattr/ACL metadata refused'
            else:
                raise AssertionError('unallowlisted xattr must refuse')
            finally:
                os.removexattr(target, 'user.progress-test')
        # A mutated body remains distinguishable even when the locked archive name is unchanged.
        target.write_bytes(target.read_bytes() + b'drift')
        for implementation in (original, updated):
            changed = implementation.observe(root, helper, expected)
            try:
                implementation.verify(changed, control)
            except ValueError as error:
                assert 'preservation differs' in str(error)
            else:
                raise AssertionError('changed payload must refuse')
        return dict(status='PASS_EXACT_SELECTED_ARCHIVE_PAYLOAD_AND_DRAIN_CONTROLS', fixture='actual frozen archive bodies plus synthetic ALPM descriptors',
                    pins=pins, nodes=len(control['nodes']), payload_bytes=control['payload_bytes'], equal=True, paired_seconds=times,
                    baseline_median=statistics.median(times[0]), instrumented_median=statistics.median(times[1]), VM_performance='NOT_MEASURED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-controls-only', action='store_true')
    parser.add_argument('--repo', type=Path)
    for flag in ('source', 'generated-guest'):
        parser.add_argument('--' + flag, required=True, type=Path)
    args = parser.parse_args()
    if args.source_controls_only:
        before = (args.source / 'factory/support/installed604.py').read_text().replace('604', '606')
        compile(progress.observer(before), 'installed606.py', 'exec')
        with tempfile.TemporaryDirectory(prefix='installed606-source-controls-') as directory:
            controls(args.generated_guest, Path(directory))
        print('PASS_EXACT_OBSERVER_DRAIN_SOURCE_CONTROLS')
        raise SystemExit(0)
    if args.repo is None:
        parser.error('--repo is required for retained package controls')
    real_popen = subprocess.Popen

    def git_only(argv, *args, **kwargs):
        assert argv[0] == '/usr/bin/git' and argv[-3:-1] == ['cat-file', 'blob']
        return real_popen(argv, *args, **kwargs)

    with patch('subprocess.Popen', side_effect=git_only):
        result = run(args)
    print(json.dumps(result, sort_keys=True, indent=2))
