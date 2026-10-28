#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Opt-in same-job native574 host capture, then a disposable 16KiB QEMU trial."""
import argparse
import json
import os
from pathlib import Path
import signal
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import deps as d
import payload_vm


def native_command(root, image, name, bundles, output, lock, product, archives):
    rust = d.load(root, 'scripts/ci/asahi-rust-lv2-offline/run.py')
    held = d.load(root, 'scripts/ci/asahi-lsp-offline/run.py')
    argv = rust.runtime_command(held, image, name, bundles, output, lock, product)
    original = 'type=bind,src=' + str(rust.s.HERE) + ',dst=/source,readonly'
    d.need(argv.count(original) == 1, 'held source mount differs')
    argv[argv.index(original)] = 'type=bind,src=' + str(d.HERE) + ',dst=/source,readonly'
    index = argv.index('--entrypoint=/usr/bin/python3')
    argv[index:index] = ['--mount', 'type=bind,src=' + str(root) + ',dst=/repo,readonly',
                         '--mount', 'type=bind,src=' + str(archives) + ',dst=/accepted-archives,readonly']
    d.need(argv[-1] == '/source/container.py', 'held entrypoint differs')
    argv[-1:] = ['/source/native_capture.py', '--source-root', '/repo', '--image-id', image]
    return argv


def run(args):
    root = args.source_root.resolve(strict=True)
    for name in d.POLICY['dependencies']:
        d.source(root, name)
    if not args.execute:
        return {'status': 'SOURCE_VALIDATED_NOT_RUN', 'compiled_host': 'NOT RUN', 'QEMU': 'NOT RUN'}
    held = d.load(root, 'scripts/ci/asahi-lsp-offline/run.py')
    rust = d.load(root, 'scripts/ci/asahi-rust-lv2-offline/run.py')
    generic = d.load(root, 'scripts/virtual/generic16k/fixture.py')
    api = held.pair_api()
    image, lock = api.preflight(args)  # Exact existing immutable574 preparation and local daemon contract.
    api.ordinary(args.archives)
    d.need(args.archives.is_dir() and args.archives.stat().st_uid == os.getuid() and
           not args.archives.stat().st_mode & 0o022, 'owned accepted archives required')
    os.umask(0o077)
    args.private.mkdir(mode=0o700); args.output.mkdir(mode=0o700)
    result = {'status': 'FAIL', 'scope': 'generic ARM64 16KiB existing Rust LV2 software properties',
              'image_id': image, 'Rust_package_rebuilds': 0, 'fresh_C_host_compilations': 'NOT OBSERVED',
              'historical_host_reproduction': 'NOT CLAIMED', 'hardware': 'NOT RUN',
              'audio_devices': 'NOT USED', 'performance': 'NOT RUN', 'cancelled': False}
    try:
        checks = api.module(args.product/'scripts/checks/package_checks.py')
        result['accepted_packages'] = rust.bundles(args.archives, args.private/'bundles', checks,
                                                  root/'scripts/ci/full-development-composition')
        capture = args.private/'capture'; capture.mkdir(mode=0o700)
        name = 'cachy-asahi-lsp-offline-' + uuid.uuid4().hex[:16]
        query = ['docker', 'container', 'ls', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}']
        d.need(api.capture(query) == '', 'fresh owned container name required')
        (args.private/'runtime-container.json').write_text(json.dumps({'name': name}))
        argv = native_command(root, image, name, args.private/'bundles', capture, lock, args.product, args.archives)
        result['native_capture_command'] = argv
        code, _ = generic.supervise(argv, args.private/'capture.log', 480, 1024**2)
        d.need(code == 0, 'native host capture failed')
        raw = (capture/'native.json').read_bytes()
        d.need(len(raw) <= 128*1024, 'native receipt too large')
        receipt = json.loads(raw)
        d.need(receipt['image_id'] == image, 'native receipt image differs')
        result.update(fresh_C_host_compilations=1, native_host_sha256=receipt['host_sha256'],
                      native_receipt_sha256=d.sha(raw))
        (args.output/'native.json').write_bytes(raw)
        kernel_raw = args.kernel_receipt.read_bytes()
        d.need(len(kernel_raw) <= 65536, 'kernel receipt too large')
        kernel = json.loads(kernel_raw)
        vm = payload_vm.run(root, capture/'payload.tar', receipt, kernel, args.private/'vm')
        (args.output/'vm.json').write_text(json.dumps(vm, sort_keys=True, indent=2) + '\n')
        result.update(status='PASS_GENERIC_16K_AUDIO_SOFTWARE_ONLY', cases=60, instances=120,
                      kernel_receipt_sha256=d.sha(kernel_raw))
    except BaseException as error:
        result.update(error=type(error).__name__ + ': ' + str(error), cancelled=isinstance(error, KeyboardInterrupt))
        raise
    finally:
        try:
            for name, path, limit in (
                ('vm.json', args.private/'vm/vm.json', 128*1024),
                ('uart.tail.txt', args.private/'vm/uart.log', 8192),
                ('native-compile.tail.txt', args.private/'capture/compile.stderr', 8192),
                ('capture.tail.txt', args.private/'capture.log', 8192)):
                if path.is_file():
                    size = path.stat().st_size
                    if name.endswith('.json'):
                        d.need(size <= limit, 'public JSON bound')
                    with path.open('rb') as stream:
                        stream.seek(max(0, size-limit)); (args.output/name).write_bytes(stream.read(limit))
        except BaseException as error:
            result.update(status='FAIL', export_error=type(error).__name__)
        previous = signal.getsignal(signal.SIGALRM)
        def expired(signum, frame):
            raise TimeoutError('owned cleanup deadline')
        signal.signal(signal.SIGALRM, expired); signal.setitimer(signal.ITIMER_REAL, 60)
        try:
            result['cleanup'] = held.cleanup(args.private, [])
            d.need(result['cleanup']['status'] == 'PASS' and result['cleanup']['private_removed'] and
                   result['cleanup']['runtime']['absence_verified'], 'owned cleanup failed')
        except BaseException as error:
            result.update(status='FAIL', cleanup_error=type(error).__name__)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0); signal.signal(signal.SIGALRM, previous)
        (args.output/'result.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
        d.need(sum(p.stat().st_size for p in args.output.iterdir()) <= 512*1024, 'public total bound')
        d.need(result['status'] == 'PASS_GENERIC_16K_AUDIO_SOFTWARE_ONLY', 'audio16K trial failed')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source-root', 'product', 'desktop', 'builder', 'private', 'output', 'archives', 'kernel-receipt'):
        parser.add_argument('--'+name, required=True, type=Path)
    parser.add_argument('--execute', action='store_true')
    def interrupt(signum, frame):
        raise KeyboardInterrupt('audio16K interrupted')
    signal.signal(signal.SIGTERM, interrupt)
    print(json.dumps(run(parser.parse_args()), sort_keys=True))
