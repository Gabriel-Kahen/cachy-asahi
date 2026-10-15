#!/usr/bin/env python3
"""Two exact accepted bundles, zero rebuilds, one private Rust LV2 trial."""
import argparse
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
import sys
import tarfile
from types import SimpleNamespace
import uuid

spec = importlib.util.spec_from_file_location('rust_support', Path(__file__).with_name('support.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


def payload(report):
    # Same narrow regular-file projection consumed by the frozen audio inspector.
    return [{'path': '/' + name, 'type': 'file', 'mode': row['mode'], 'sha256': row['sha256']}
            for name, row in report['members'].items() if not name.startswith('.') and row['type'] == '0']


def bundles(archives, target, checks, full):
    pins = s.inputs()
    s.need(s.sha(full / 'audio-inputs.json') == pins['audio_policy_sha256'], 'audio-policy-differs')
    inspector = s.load('rust_audio_inspector', full / 'audio_inputs.py', pins['audio_inputs_helper_sha256'])
    policy = json.loads((full / 'audio-inputs.json').read_text())
    target.mkdir(mode=0o700); observations = []
    for row in pins['packages']:
        s.need(next(x for x in policy if x['name'] == row['name']) == row, 'accepted-package-policy-differs')
        archive = archives / row['filename']
        s.need(archive.is_file() and not archive.is_symlink() and archive.stat().st_size == row['size'] and
               s.sha(archive) == row['sha256'], 'accepted-package-bytes-differ')
        report = checks.package(archive)
        inspector.inspect(row, report, SimpleNamespace(payload=payload))
        library = Path(row['elf_paths'][0]); prefix = str(library.parent) + '/'
        members = {x['path'].removeprefix('/'): x for x in row['payload'] if x['path'].startswith('/' + prefix)}
        s.need(set(members) == {str(library), prefix + 'manifest.ttl', prefix + row['name'].removesuffix('-lv2') + '.ttl'},
               'closed-bundle-set-differs')
        bundle = target / library.parent.name; bundle.mkdir(mode=0o700); copied = set()
        with tarfile.open(archive, 'r:xz') as stream:
            for entry in stream:
                name = str(PurePosixPath(entry.name))
                if name not in members: continue
                leaf = name[len(prefix):]
                s.need(entry.isfile() and name not in copied and '/' not in leaf and leaf not in ('', '.', '..') and
                       0 < entry.size <= 4 * 1024 * 1024, 'unsafe-bundle-member')
                path = bundle / leaf
                with path.open('xb') as out: shutil.copyfileobj(stream.extractfile(entry), out, 1024 * 1024)
                s.need(s.sha(path) == members[name]['sha256'], 'bundle-copy-differs')
                path.chmod(members[name]['mode']); copied.add(name)
        s.need(copied == set(members), 'bundle-copy-incomplete')
        observations.append({'name': row['name'], 'version': row['version'], 'archive_bytes': row['size'],
                             'archive_sha256': row['sha256'], 'library_sha256': members[str(library)]['sha256']})
    return observations


def runtime_command(held, image, name, bundle, output, lock, product):
    argv = held.runtime_command(image, name, bundle, output, lock, product)
    mount = 'type=bind,src=' + str(held.HERE) + ',dst=/source,readonly'
    s.need(argv.count(mount) == 1, 'held-runtime-command-differs')
    argv[argv.index(mount)] = 'type=bind,src=' + str(s.HERE) + ',dst=/source,readonly'
    index = argv.index('--entrypoint=/usr/bin/python3')
    return argv[:index] + ['--mount', 'type=bind,src=' + str(held.HERE) + ',dst=/held,readonly'] + argv[index:]


def runtime_report(path, held, allow_failure=False):
    s.need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 2 * 1024 * 1024,
           'runtime-report-bounds')
    common = s.held('container')
    value = common.json_document(path.read_bytes())
    held.no_private_values(value)
    contract = s.load('rust_runtime_contract', s.HERE / 'container.py')
    contract.common = lambda: common  # Pure schema checking on the host; no actors.
    allowed = {'schema_version', 'status', 'failure_class', 'stage', 'inventory', 'headers',
               'candidates', 'host', 'elf', 'loader', 'processing'}
    s.need(type(value) is dict and set(value) <= allowed and value.get('schema_version') == 1 and
           value.get('stage') in contract.STAGES, 'runtime-schema-differs')
    if allow_failure and value.get('status') == 'FAIL':
        s.need(value.get('failure_class') in contract.failure_codes(), 'runtime-failure-invalid')
        failed = {key: value[key] for key in ('schema_version', 'status', 'failure_class', 'stage')}
        inventory = value.get('inventory')
        if inventory is not None:
            s.need(set(inventory) == {'count', 'before_sha256', 'after_sha256', 'unchanged'} and
                   inventory['count'] == 574 and type(inventory['unchanged']) is bool and
                   inventory['before_sha256'] == s.LOCK and
                   (inventory['after_sha256'] is None or re.fullmatch('[0-9a-f]{64}', inventory['after_sha256'])) and
                   (not inventory['unchanged'] or inventory['after_sha256'] == s.LOCK), 'failed-inventory-invalid')
            failed['inventory'] = inventory
        return failed
    s.need(set(value) == allowed and value['status'] == 'PASS' and value['stage'] == 'complete' and
           value['failure_class'] is None, 'runtime-not-passed')
    s.need(value['inventory'] == {'count': 574, 'before_sha256': s.LOCK, 'after_sha256': s.LOCK, 'unchanged': True},
           'runtime-inventory-differs')
    expected = {row['name']: next(x['sha256'] for x in row['payload'] if x['path'] == '/' + row['elf_paths'][0])
                for row in s.inputs()['packages']}
    s.need(value['candidates'] == expected and set(value['loader']) == set(expected) and
           set(value['elf']) == set(expected) | {'host'}, 'runtime-candidates-differ')
    s.need(value['headers'] == {key: row[1] for key, row in common.HEADERS.items()}, 'runtime-headers-differ')
    for name, uri in zip(expected, s.URIS):
        loader = value['loader'][name]
        s.need(set(loader) == {'status', 'selected_uris', 'descriptor_count', 'loaded_libraries'} and
               loader['status'] == 'PASS' and loader['selected_uris'] == [uri] and loader['descriptor_count'] == 1,
               'runtime-loader-differs')
        libraries = loader['loaded_libraries']
        s.need(type(libraries) is list and 0 < len(libraries) <= 128 and
               len({row['identity'] for row in libraries}) == len(libraries), 'runtime-loader-differs')
        candidate_identity = 'candidate/' + ('bankstown.lv2/bankstown.so' if uri == s.BANK else 'triforce.lv2/triforce.so')
        s.need(any(row.get('identity') == candidate_identity and row.get('sha256') == expected[name]
                   for row in libraries), 'runtime-loader-candidate-differs')
        for row in libraries:
            s.need(set(row) == {'identity', 'sha256'} and row['identity'].startswith(('candidate/', 'system/', 'virtual/', 'host/')) and
                   (row['sha256'] is None if row['identity'] == 'virtual/linux-vdso.so.1' else
                    re.fullmatch('[0-9a-f]{64}', row['sha256'])), 'runtime-loader-differs')
    host = value['host']
    s.need(set(host) == {'sha256', 'source_sha256', 'compile_flags', 'compiler_sha256', 'pkg_config_sha256',
                         'readelf_sha256', 'lilv_pc_sha256'}, 'runtime-host-differs')
    s.need(all(type(host[key]) is str and re.fullmatch('[0-9a-f]{64}', host[key])
               for key in host if key != 'compile_flags'), 'runtime-host-differs')
    flags = host['compile_flags']
    s.need(type(flags) is list and flags[:len(common.FLAGS)] == common.FLAGS and flags[-2:] == ['-ldl', '-lm'],
           'runtime-flags-differ')
    common.pkg_flags(' '.join(flags[len(common.FLAGS):-2]).encode('ascii'))
    s.need(host['source_sha256'] == s.sha(s.HERE / 'host.c'), 'runtime-host-source-differs')
    for name, elf in value['elf'].items():
        s.need(set(elf) == {'class', 'machine', 'needed', 'path_tags', 'version_requirements', 'sha256',
                            'load_segments', 'structural_16k', 'hardware_status'} and
               elf['class'] == 'ELF64' and elf['machine'] == 'AArch64' and
               type(elf['load_segments']) is int and 0 < elf['load_segments'] <= 128 and
               elf['structural_16k'] == 'PASS' and elf['hardware_status'] == 'NOT RUN' and
               elf['path_tags'] == [] and elf['sha256'] == (host['sha256'] if name == 'host' else expected[name]),
               'runtime-elf-differs')
        for key in ('needed', 'version_requirements'):
            s.need(type(elf[key]) is list and len(elf[key]) <= 128 and
                   all(type(x) is str and common.NAME.fullmatch(x) for x in elf[key]), 'runtime-elf-differs')
    contract.project_processing(json.dumps(value['processing'], allow_nan=False).encode())
    return value


def run(args):
    held = s.held('run'); common = s.held('container'); api = held.pair_api(); image, lock = api.preflight(args)
    api.ordinary(s.HERE)
    archives = args.private.parent / 'incoming/audio-archives'; api.ordinary(archives)
    s.need(archives.is_dir() and archives.stat().st_uid == os.getuid() and not archives.stat().st_mode & 0o022,
           'owned-inputs-required')
    os.umask(0o077); args.private.mkdir(mode=0o700); args.output.mkdir(mode=0o700)
    result = {'status': 'FAIL', 'scope': 'PRIVATE-ASAHI-RUST-LV2-PROPERTIES', 'native_rebuilds': 0,
              'package_pair_repeated': False, 'lsp_processing': 'NOT RUN', 'installation': 'NOT RUN',
              'target_audio': 'NOT RUN', 'hardware': 'NOT RUN', 'selected_for_release': False,
              'image_id': image, 'expected_packages_sha256': s.LOCK, 'cancelled': False}
    previous = {sig: signal.signal(sig, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
                for sig in (signal.SIGINT, signal.SIGTERM)}
    stage = 'accepted-inputs'
    try:
        checks = api.module(args.product / 'scripts/checks/package_checks.py')
        result['accepted_inputs'] = bundles(archives, args.private / 'bundles', checks,
                                           s.HERE.parent / 'full-development-composition')
        stage = 'runtime'; raw = args.private / 'runtime'; raw.mkdir(mode=0o700)
        name = 'cachy-asahi-lsp-offline-' + uuid.uuid4().hex[:16]  # Existing exact owner namespace.
        s.save(args.private / 'runtime-container.json', {'name': name})
        try:
            api.command(runtime_command(held, image, name, args.private / 'bundles', raw, lock, args.product),
                        args.private / 'runtime.log', 420)
        except api.CommandFailure:
            try:
                failed = runtime_report(raw / 'observations.json', held, allow_failure=True)
                s.need(failed['status'] == 'FAIL', 'runtime-exit-status-differs')
                s.save(args.output / 'runtime.json', failed)
                result['runtime_failure'] = {key: failed[key] for key in ('stage', 'failure_class')}
            except (OSError, ValueError, KeyError, TypeError, common.Failure):
                result['runtime_failure'] = {'stage': 'controller', 'failure_class': 'unavailable-or-invalid-report'}
            raise
        runtime = runtime_report(raw / 'observations.json', held)
        runtime['controller_inputs'] = {p.name: s.sha(p) for p in sorted(s.HERE.iterdir())
                                        if p.is_file() and p.suffix in ('.c', '.py', '.json')}
        s.save(args.output / 'runtime.json', runtime)
        result.update(status='PASS', offline_properties='PASS', cases=60, instances=120)
    except (KeyboardInterrupt, OSError, ValueError, KeyError, TypeError, AssertionError, common.Failure, subprocess.SubprocessError) as error:
        result.update(failed_stage=stage, error_kind=type(error).__name__, cancelled=isinstance(error, KeyboardInterrupt))
        if isinstance(error, api.CommandFailure): result['child_exit_code'] = error.code
        if isinstance(error, common.Failure):
            contract = s.load('rust_failed_contract', s.HERE / 'container.py'); contract.common = lambda: common
            result['runtime_failure'] = {'stage': 'projection', 'failure_class':
                error.code if error.code in contract.failure_codes() else 'unavailable-or-invalid-report'}
        result['private_logs'] = {p.name: {'bytes': p.stat().st_size, 'sha256': s.sha(p)} for p in args.private.glob('*.log')}
    finally:
        interrupted = []
        for sig in previous: signal.signal(sig, lambda signum, _: interrupted.append(signum))
        try:
            try: result['cleanup'] = held.cleanup(args.private, [])
            except (OSError, ValueError, subprocess.SubprocessError): result['cleanup'] = {'status': 'FAIL', 'private_removed': False}
            if result['cleanup']['status'] != 'PASS': result['status'] = 'FAIL'
            if interrupted: result.update(status='FAIL', cancelled=True)
            s.save(args.output / 'result.json', result)
            if interrupted: result.update(status='FAIL', cancelled=True); s.save(args.output / 'result.json', result)
        finally:
            for sig, handler in previous.items(): signal.signal(sig, handler)
    if interrupted: result.update(status='FAIL', cancelled=True); s.save(args.output / 'result.json', result)
    return int(result['status'] != 'PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('product', 'desktop', 'builder', 'private', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    return run(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
