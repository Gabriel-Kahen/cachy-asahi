#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One opt-in native ARM kernel build and generic TCG trial on disposable CI."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
PACKAGES = ('build-essential', 'bc', 'clang', 'lld', 'llvm', 'flex', 'bison',
            'libssl-dev', 'libelf-dev', 'python3', 'qemu-system-arm', 'ca-certificates')
PUBLIC_LIMIT = 256 * 1024
DIAGNOSTIC_PUBLIC_LIMIT = 2 * 1024**2


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def check_source(root, expected):
    need(re.fullmatch('[0-9a-f]{64}', expected) is not None, 'manifest SHA required')
    manifest = HERE / 'ci-files.json'
    raw = manifest.read_bytes()
    need(len(raw) <= 65536 and digest(raw) == expected, 'manifest differs')
    value = json.loads(raw)
    need(value.get('schema') == 1 and 1 <= len(value['files']) <= 32, 'manifest shape')
    for name, row in value['files'].items():
        need(not name.startswith('/') and all(x not in ('', '.', '..') for x in name.split('/')), 'source path')
        path = root / name
        need(not path.is_symlink() and path.resolve().is_relative_to(root), 'source link')
        data = path.read_bytes()
        need(len(data) == row['bytes'] <= 262144 and digest(data) == row['sha256'], 'source differs: ' + name)
    return digest(raw)


def command(argv, log, seconds, env):
    """Bound output and retire the owned child, allowing its nested-group cleanup."""
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, env=env, start_new_session=True)
    poll = selectors.DefaultSelector()
    poll.register(child.stdout, selectors.EVENT_READ)
    data = bytearray()
    deadline = time.monotonic() + seconds
    try:
        while poll.get_map():
            need(time.monotonic() < deadline, 'command deadline')
            for key, _ in poll.select(.2):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    poll.unregister(key.fileobj)
                else:
                    data.extend(block)
                    need(len(data) <= 1024**2, 'command output limit')
        code = child.wait(timeout=max(.01, deadline - time.monotonic()))
        need(code == 0, 'command failed with exit ' + str(code))
        return {'argv': argv, 'returncode': code, 'output_sha256': digest(data), 'output_bytes': len(data)}
    finally:
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
                child.wait(timeout=12)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
        # Direct-child normal exit does not exempt any remaining same-group descendants.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.stdout.close()
        poll.close()
        log.write_bytes(data[:1024**2])


def publish(run):
    public = run / 'public'
    index = json.loads((public / 'index.json').read_text())
    diagnostics = False
    if (public / 'caller.json').is_file():
        diagnostics = json.loads((public / 'caller.json').read_text()).get('boot_diagnostics', False)
    need(type(diagnostics) is bool, 'diagnostic selection')
    limit = DIAGNOSTIC_PUBLIC_LIMIT if diagnostics else PUBLIC_LIMIT
    rows, total = [], 0
    need(len(index) <= 32, 'public count')
    for row in index:
        name = row['name']
        need(re.fullmatch('[A-Za-z0-9_.-]+', name) is not None, 'public path')
        path = public / name
        need(path.is_file() and not path.is_symlink(), 'public regular file')
        data = path.read_bytes()
        total += len(data)
        need(len(data) == row['bytes'] and digest(data) == row['sha256'] and total <= limit, 'public binding')
        rows.append(dict(row, base64=base64.b64encode(data).decode('ascii')))
    print('GENERIC16K_PUBLIC_BEGIN')
    print(json.dumps({'schema': 1, 'files': rows}, sort_keys=True, separators=(',', ':')))
    print('GENERIC16K_PUBLIC_END')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--run-name', required=True)
    parser.add_argument('--publish', action='store_true')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--boot-diagnostics', action='store_true')
    args = parser.parse_args()
    root = args.source_root.resolve(strict=True)
    check_source(root, args.manifest_sha256)
    need(re.fullmatch('ci-[0-9]{1,20}-[0-9]{1,10}', args.run_name) is not None, 'run name')
    run = HERE / args.run_name
    if args.publish:
        publish(run)
        return
    need(args.execute and os.environ.get('GITHUB_ACTIONS') == 'true' and
         os.environ.get('RUNNER_OS') == 'Linux' and os.environ.get('RUNNER_ARCH') == 'ARM64' and
         platform.system() == 'Linux' and platform.machine().lower() in ('aarch64', 'arm64') and
         os.getuid() == os.geteuid() != 0, 'disposable native ARM CI opt-in required')
    run.mkdir(mode=0o700)
    public = run / 'public'
    public.mkdir(mode=0o700)
    build = HERE / (args.run_name + '-kernel')
    need(not build.exists() and not build.is_symlink(), 'fresh build output required')
    report = {'status': 'FAIL', 'scope': 'generic ARM64 16KiB software smoke only',
              'boot_diagnostics': args.boot_diagnostics,
              'source_commit': os.environ.get('GITHUB_SHA'), 'manifest_sha256': args.manifest_sha256,
              'uname': list(os.uname()), 'commands': [], 'cleanup': [], 'hardware': 'NOT RUN',
              'performance': 'NOT RUN', 'source_license_records': 'public source COPYING, GPL-2.0 and syscall note'}
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(run), 'TMPDIR': str(run), 'LC_ALL': 'C',
           'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1'}
    selected = {}
    diagnostic_args = ['--boot-diagnostics'] if args.boot_diagnostics else []
    def call(argv, log, seconds):
        row = {'argv': argv, 'status': 'STARTED', 'log': log.name}
        report['commands'].append(row)
        try:
            row.update(command(argv, log, seconds, env), status='PASS')
        except BaseException:
            row['status'] = 'FAIL'
            raise
    def select(name, path, limit=65536, tail=False):
        if path.is_file() and not path.is_symlink():
            with path.open('rb') as stream:
                size = path.stat().st_size
                need(tail or size <= limit, 'public receipt too large: ' + name)
                if tail:
                    stream.seek(max(0, size - limit))
                selected[name] = stream.read(limit)
    try:
        for name, argv in (
            ('package-versions', ['/usr/bin/dpkg-query', '-W', '-f=${Package}=${Version}\n', *PACKAGES]),
            ('clang-version', ['/usr/bin/clang', '--version']),
            ('qemu-version', ['/usr/bin/qemu-system-aarch64', '--version'])):
            call(argv, run / (name + '.log'), 10)
            select(name + '.txt', run / (name + '.log'), 8192)
        for name, argv, seconds in (
            ('fetch', [sys.executable, '-B', str(HERE/'fetch_inputs.py'), '--fetch', '--out', str(run/'inputs')], 320),
            ('kernel', [sys.executable, '-B', str(HERE/'build_kernel.py'), '--archive', str(run/'inputs/kernel.tar.gz'),
                        '--output', str(build), '--build', *diagnostic_args], 3700)):
            call(argv, run / (name + '.log'), seconds)
        receipt = json.loads((build/'build-receipt.json').read_text())
        argv = [sys.executable, '-B', str(HERE/'fixture.py'), '--kernel', str(build/'build/arch/arm64/boot/Image'),
                '--kernel-config', str(build/'build/.config'), '--kernel-receipt', str(build/'build-receipt.json'),
                '--kernel-release', receipt['kernel_release'], '--rootfs-tar', str(run/'inputs/rootfs.tar.gz'),
                '--rootfs-sha256', '42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319',
                '--out', str(run/'vm'), '--execute-in-owned-fixture', *diagnostic_args]
        call(argv, run/'fixture.log', 300)
        result = json.loads((run/'vm/fixture-result.json').read_text())
        need(result['status'] == 'PASS' and result.get('natural_exit') is True and result.get('qemu_exit') == 0,
             'actual fixture did not pass')
        report['status'] = 'PASS_GENERIC_16K_SOFTWARE_ONLY'
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        try:
            if args.boot_diagnostics:
                select('uart.full.log', run/'vm/uart.log', 1024**2)
                select('diagnostic.fragment', build/'diagnostic.fragment')
            for name, path in (
                ('input-manifest.json', HERE/'inputs.json'), ('candidate-files.json', HERE/'ci-files.json'),
                ('kernel.fragment', HERE/'kernel.fragment'),
                ('fetch.json', run/'inputs/fetch-result.json'), ('build.json', build/'build-receipt.json'),
                ('kernel.config', build/'build/.config'), ('fixture.json', run/'vm/fixture-result.json'),
                ('COPYING', build/'linux-asahi-7.1.13-3/COPYING'),
                ('GPL-2.0', build/'linux-asahi-7.1.13-3/LICENSES/preferred/GPL-2.0'),
                ('license-rules.rst', build/'linux-asahi-7.1.13-3/Documentation/process/license-rules.rst'),
                ('Linux-syscall-note', build/'linux-asahi-7.1.13-3/LICENSES/exceptions/Linux-syscall-note')):
                select(name, path)
            for name, path in (('fetch', run/'fetch.log'), ('kernel', run/'kernel.log'),
                               ('configure', build/'configure.log'), ('build', build/'build.log'),
                               ('fixture', run/'fixture.log'), ('compile', run/'vm/compile.log'), ('uart', run/'vm/uart.log')):
                select(name + '.tail.txt', path, 8192, tail=True)
        except BaseException as error:
            report.update(status='FAIL', export_error=type(error).__name__)
        for path in (run/'inputs', run/'vm', build):
            if path.exists() and not path.is_symlink():
                try:
                    argv = [sys.executable, '-c', 'import shutil,sys;shutil.rmtree(sys.argv[1])', str(path)]
                    command(argv, run/(path.name + '-cleanup.log'), 60, env)
                    need(not path.exists(), 'owned directory remains')
                    report['cleanup'].append({'name': path.name, 'status': 'ABSENT'})
                except BaseException as error:
                    report.update(status='FAIL', cleanup_error=type(error).__name__)
                    report['cleanup'].append({'name': path.name, 'status': 'FAIL'})
        selected['caller.json'] = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
        limit = DIAGNOSTIC_PUBLIC_LIMIT if args.boot_diagnostics else PUBLIC_LIMIT
        need(sum(map(len, selected.values())) <= limit, 'public total limit')
        index = []
        for name, data in sorted(selected.items()):
            (public/name).write_bytes(data)
            index.append({'name': name, 'bytes': len(data), 'sha256': digest(data)})
        save(public/'index.json', index)
        need(report['status'] == 'PASS_GENERIC_16K_SOFTWARE_ONLY', 'build, guest, export or cleanup failed')


if __name__ == '__main__':
    def interrupt(signum, frame):
        raise KeyboardInterrupt('caller interrupted')
    signal.signal(signal.SIGTERM, interrupt)
    main()
