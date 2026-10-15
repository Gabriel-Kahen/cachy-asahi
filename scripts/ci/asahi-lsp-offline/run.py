#!/usr/bin/env python3
"""One exact LSP rebuild, then an isolated fixed offline LV2 property trial."""
import argparse
import functools
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import uuid

HERE = Path(__file__).resolve().parent
PAIR = HERE.parent / 'asahi-lsp-build'
PAIR_RUN = '514fb0697ba473cf73f7d6c94be383f7d3f582dfbe3a22e531364f729fb393a2'
ARCHIVE = '8fbd603732c505a36cf57be2163cb96b5bd0a13171d64c6104ea6a6c8b1a8791'
LIBRARY = 'b11bb9851ac3153ffe8b423d591133d4f48bd12cb9508c8c7080f93b6a906a84'
LIB_PATH = 'usr/lib/lv2/lsp-plugins.lv2/lsp-plugins-lv2.so'
PUBLIC = {'result.json', 'build-1.json', 'runtime.json'}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


@functools.lru_cache(maxsize=1)
def pair_api():
    need(sha(PAIR / 'run.py') == PAIR_RUN, 'held-pair-caller-differs')
    return module('offline_held_pair', PAIR / 'run.py')


def extract_bundle(archive, report, target):
    need(report['artifact_sha256'] == ARCHIVE and sha(archive) == ARCHIVE, 'accepted-package-differs')
    need(report['members'][LIB_PATH]['sha256'] == LIBRARY, 'accepted-library-differs')
    target.mkdir(mode=0o700)
    prefix = 'usr/lib/lv2/lsp-plugins.lv2/'
    expected = {name for name, row in report['members'].items()
                if name.startswith(prefix) and row['type'] == '0'}
    need(len(expected) == 200 and sum(name.endswith('.ttl') for name in expected) == 199,
         'closed-bundle-set-differs')
    copied = set()
    with tarfile.open(archive, 'r:xz') as stream:
        for entry in stream:
            name = str(PurePosixPath(entry.name))
            if name not in expected:
                continue
            relative = name[len(prefix):]
            need(entry.isfile() and '/' not in relative and relative not in ('', '.', '..') and
                 name not in copied and entry.size == report['members'][name]['size'], 'unsafe-bundle-member')
            path = target / relative
            content = stream.extractfile(entry)
            with path.open('xb') as output:
                shutil.copyfileobj(content, output, 1024 * 1024)
            need(sha(path) == report['members'][name]['sha256'], 'bundle-copy-differs')
            path.chmod(0o755 if name == LIB_PATH else 0o644)
            copied.add(name)
    need(copied == expected and sha(target / 'lsp-plugins-lv2.so') == LIBRARY, 'bundle-copy-incomplete')


def runtime_command(image, name, bundle, output, lock, product):
    return ['docker', 'run', '--rm', '--name', name, '--pull=never', '--platform=linux/arm64',
            '--user', f'{os.getuid()}:{os.getgid()}', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--read-only', '--network=none',
            '--pids-limit=128', '--memory=1g', '--cpus=2',
            '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=512m',
            '--env', 'CACHY_ASAHI_OFFLINE=1', '--env', 'PYTHONDONTWRITEBYTECODE=1',
            '--mount', f'type=bind,src={HERE},dst=/source,readonly',
            '--mount', f'type=bind,src={bundle},dst=/candidate,readonly',
            '--mount', f'type=bind,src={lock},dst=/expected.lock,readonly',
            '--mount', f'type=bind,src={product / "scripts/checks/package_checks.py"},dst=/checks.py,readonly',
            '--mount', f'type=bind,src={output},dst=/out',
            '--entrypoint=/usr/bin/python3', image, '-I', '-B', '/source/container.py']


def no_private_values(value):
    if isinstance(value, dict):
        need(len(value) <= 2048, 'runtime-metadata-oversized')
        for key, child in value.items():
            need(isinstance(key, str) and len(key) <= 256 and not key.startswith('/'), 'runtime-key-invalid')
            no_private_values(child)
    elif isinstance(value, list):
        need(len(value) <= 2048, 'runtime-list-oversized')
        for child in value:
            no_private_values(child)
    elif isinstance(value, str):
        need(len(value) <= 2048 and not value.startswith('/') and '\n' not in value and '\r' not in value,
             'runtime-private-text-refused')
    elif isinstance(value, float):
        need(math.isfinite(value), 'runtime-nonfinite-metadata')
    else:
        need(value is None or isinstance(value, (bool, int)), 'runtime-type-invalid')


def runtime_report(path, allow_failure=False):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 2 * 1024 * 1024,
         'runtime-report-missing-or-oversized')
    value = json.loads(path.read_text())
    allowed = {'schema_version', 'status', 'failure_class', 'stage', 'inventory', 'headers', 'host',
               'elf', 'loader', 'processing', 'candidate_sha256'}
    need(set(value) <= allowed and value.get('schema_version') == 1, 'runtime-schema-differs')
    no_private_values(value)
    contract = module('offline_runtime_contract', HERE / 'container.py')
    need(value.get('stage') in contract.STAGES, 'runtime-stage-invalid')
    if allow_failure and value.get('status') == 'FAIL':
        need(value.get('failure_class') in contract.FAILURE_CODES, 'runtime-failure-class-invalid')
        # Completed detailed sections stay private on failure; project only the closed
        # reason and verified-shape inventory state, never arbitrary partial payloads.
        failure = {key: value[key] for key in ('schema_version', 'status', 'failure_class', 'stage')}
        inventory = value.get('inventory')
        if inventory is not None:
            need(set(inventory) == {'count', 'before_sha256', 'after_sha256', 'unchanged'} and
                 type(inventory['count']) is int and inventory['count'] == 574 and
                 type(inventory['unchanged']) is bool and
                 inventory['before_sha256'] == pair_api().LOCK and
                 (inventory['after_sha256'] is None or re.fullmatch('[0-9a-f]{64}', inventory['after_sha256'])),
                 'runtime-failed-inventory-invalid')
            need(not inventory['unchanged'] or inventory['after_sha256'] == inventory['before_sha256'],
                 'runtime-failed-inventory-invalid')
            failure['inventory'] = inventory
        return failure
    need(value['status'] == 'PASS' and value['candidate_sha256'] == LIBRARY, 'offline-runtime-failed')
    need(value['inventory']['count'] == 574 and value['inventory']['unchanged'] and
         value['inventory']['before_sha256'] == value['inventory']['after_sha256'] == pair_api().LOCK,
         'runtime-inventory-differs')
    need(value['loader']['status'] == 'PASS' and value['processing']['status'] == 'PASS' and
         value['processing']['case_count'] == 48 and value['processing']['instance_count'] == 96,
         'offline-case-matrix-incomplete')
    return value


def cleanup(private, builds):
    api = pair_api()
    handle = private / 'runtime-container.json'
    runtime = {'status': 'NOT CREATED', 'absence_verified': True}
    if handle.exists():
        try:
            name = json.loads(handle.read_text())['name']
            need(re.fullmatch(r'cachy-asahi-lsp-offline-[0-9a-f]{16}', name), 'unknown-runtime-container')
            query = ['docker', 'container', 'ls', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}']
            before = api.capture(query)
            need(before in ('', name), 'ambiguous-runtime-container')
            if before:
                subprocess.run(['docker', 'rm', '-f', name], check=True, capture_output=True, timeout=20)
            need(api.capture(query) == '', 'runtime-container-remains')
            runtime = {'status': 'PASS', 'name': name, 'absence_verified': True}
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            return {'status': 'FAIL', 'runtime': {'absence_verified': False}, 'private_removed': False}
    result = api.cleanup(private, builds)
    result['runtime'] = runtime
    return result


def run(args):
    api = pair_api()
    image, lock = api.preflight(args)
    api.ordinary(HERE)
    os.umask(0o077)
    args.private.mkdir(mode=0o700)
    args.output.mkdir(mode=0o700)
    result = {'status': 'FAIL', 'scope': 'PRIVATE-OFFLINE-LV2-DSP-PROPERTIES', 'cancelled': False,
              'source_sha256': api.SOURCE_SHA, 'accepted_package_sha256': ARCHIVE,
              'accepted_library_sha256': LIBRARY, 'product_api_source': api.PRODUCT,
              'desktop_builder_source': api.DESKTOP, 'image_id': image, 'expected_packages_sha256': api.LOCK,
              'native_rebuilds': 0, 'package_pair_repeated': False, 'target_audio': 'NOT RUN',
              'installation': 'NOT RUN', 'hardware': 'NOT RUN', 'selected_for_release': False,
              'active_algorithm_reference': 'NOT ESTABLISHED'}
    stage = 'source'
    builds = []
    def cancel(*_):
        raise KeyboardInterrupt()
    previous = {sig: signal.signal(sig, cancel) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        recipe = args.private / 'recipe'
        shutil.copytree(PAIR / 'recipe', recipe)
        api.source(recipe / api.SOURCE_NAME, args.archive)
        checks = api.module(args.product / 'scripts/checks/package_checks.py')
        reviewed = checks.recipe(recipe / 'PKGBUILD')
        need(not reviewed['errors'], 'held-recipe-static-failed')
        pins = args.private / 'reviewed-inputs.json'
        save(pins, reviewed['input_sha256'])
        stage = 'build-1'
        build = args.private / stage
        builds.append(build)
        result['native_rebuilds'] = 1
        api.command([sys.executable, '-I', '-B', args.product / 'scripts/build/build.py', recipe,
                     '--image', image, '--mode', 'native', '--network', 'none',
                     '--source-date-epoch', str(api.EPOCH), '--expected-packages', lock,
                     '--reviewed-inputs', pins, '--timeout', '2400', '--output', build],
                    args.private / 'build-1.log', 2460)
        row = api.observations(build, checks)
        need(row['image_id'] == image and row['expected_packages_sha256'] == api.LOCK and
             row['artifact_sha256'] == ARCHIVE and row['members'][LIB_PATH]['sha256'] == LIBRARY,
             'accepted-rebuild-differs')
        save(args.output / 'build-1.json', row)
        archive, = (build / 'artifacts').glob('*.pkg.tar.xz')
        stage = 'private-bundle'
        bundle = args.private / 'bundle'
        extract_bundle(archive, row, bundle)
        stage = 'offline-runtime'
        raw = args.private / 'runtime'
        raw.mkdir(mode=0o700)
        name = 'cachy-asahi-lsp-offline-' + uuid.uuid4().hex[:16]
        save(args.private / 'runtime-container.json', {'name': name})
        try:
            api.command(runtime_command(image, name, bundle, raw, build / 'expected-packages.lock', args.product),
                        args.private / 'runtime.log', 360)
        except api.CommandFailure:
            # A nonzero trial is still FAIL; retain only its validated fixed reason.
            try:
                failed_runtime = runtime_report(raw / 'observations.json', allow_failure=True)
                need(failed_runtime['status'] == 'FAIL', 'runtime-exit-status-differs')
                save(args.output / 'runtime.json', failed_runtime)
                result['runtime_failure'] = {key: failed_runtime[key] for key in ('stage', 'failure_class')}
            except (OSError, ValueError, KeyError, TypeError):
                result['runtime_failure'] = {'stage': 'controller', 'failure_class': 'unavailable-or-invalid-report'}
            raise
        runtime = runtime_report(raw / 'observations.json')
        runtime['controller_inputs'] = {f.name: sha(f) for f in sorted(HERE.iterdir())
                                        if f.is_file() and f.suffix in ('.c', '.py', '.json')}
        save(args.output / 'runtime.json', runtime)
        result.update(status='PASS', offline_loader='PASS', offline_dsp_properties='PASS', cases=48, instances=96)
    except (KeyboardInterrupt, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result.update(failed_stage=stage, error_kind=type(error).__name__, cancelled=isinstance(error, KeyboardInterrupt))
        if isinstance(error, api.CommandFailure):
            result['child_exit_code'] = error.code
        result['private_logs'] = {p.name: {'bytes': p.stat().st_size, 'sha256': sha(p)}
                                  for p in args.private.glob('*.log') if p.is_file()}
    finally:
        interrupted = []
        for sig in previous:
            signal.signal(sig, lambda signum, _: interrupted.append(signum))
        try:
            try:
                result['diagnostics'] = api.diagnostics(args.private)
            except (OSError, ValueError):
                result.update(status='FAIL', diagnostics_status='FAIL')
            try:
                result['cleanup'] = cleanup(args.private, builds)
            except (OSError, ValueError, subprocess.SubprocessError):
                result['cleanup'] = {'status': 'FAIL', 'private_removed': False}
            if result['cleanup']['status'] != 'PASS':
                result['status'] = 'FAIL'
            if interrupted:
                result.update(status='FAIL', cancelled=True)
            save(args.output / 'result.json', result)
            if interrupted:
                result.update(status='FAIL', cancelled=True)
                save(args.output / 'result.json', result)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    if interrupted:
        result.update(status='FAIL', cancelled=True)
        save(args.output / 'result.json', result)
    return int(result['status'] != 'PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('product', 'desktop', 'builder', 'private', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--archive', type=Path)
    return run(parser.parse_args())


if __name__ == '__main__':
    sys.exit(main())
