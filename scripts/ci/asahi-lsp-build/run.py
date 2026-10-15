#!/usr/bin/env python3
"""Private, build-only LSP pair using the unchanged reviewed native builder."""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.request

HERE = Path(__file__).resolve().parent
PRODUCT = 'db1010de321cc056a01672f006e6cc25d3c8a8b7'
DESKTOP = '8d8e2f5d5a94ab3ebee2d8b1cc20aecf98e435e2'
LOCK = 'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
INPUTS = 'b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9'
HELPER = '6ca8813aa7a704251d842e1d7e05404aa56e4029067ccacb57b0a7a3c8af80e5'
SOURCE_NAME = 'lsp-plugins-src-1.2.35.tar.gz'
SOURCE_URL = 'https://github.com/lsp-plugins/lsp-plugins/releases/download/1.2.35/' + SOURCE_NAME
SOURCE_SHA = '2c95ec7bb219d561ea3db36051b6c732133bcd76426fb836b1dd850dc4b5bb6c'
SOURCE_SIZE = 78369996
EPOCH = 1787491172  # Retained release published_at, 2026-08-23T13:19:32Z.
API = {
    'scripts/build/build.py': 'e520b37e5dfc285914203cfab99daecc80543505fef7ded6704b3fb06f001d45',
    'scripts/build/compare.py': '4198864c264642b196a090a67b36185e5c194e38edc4cb928d08eb65b9f710cd',
    'scripts/build/container-entry.sh': '89723f0a0b2ef80391160f451e877f15fb1e0c4d9a4fec6dbbb8e0d66d8d0f24',
    'scripts/checks/package_checks.py': 'e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8',
}
RECIPE_FILES = {'.SRCINFO': '5293a92f63bff2542ea985a4fe9984b446cc3ebb1ac47d03fa049a29525b3969',
 'PKGBUILD': '8d78f75f57e3d54a00de8d074e5b31c050db11097890adea03a6d134ce4eac64',
 'README.md': 'e2acab64a43c45e5b1c9fb16abdf1208f6a6744abb72bc5d0fff8e0396a65b58',
 'lsp-native-build.sh': '0bb4024d0eb02f4e8ced77a68fce80a730877a2b9cb190cae2aae650ecab1e0e'}
CONFIG_KEYS = ('BUILD_FEATURES', 'CFLAGS', 'CXXFLAGS', 'HOST_CFLAGS', 'HOST_CXXFLAGS', 'SO_FLAGS', 'HOST_SO_FLAGS')


class CommandFailure(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__('child-failed')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def ordinary(path):
    need(path.is_absolute() and '..' not in path.parts and
         not any(c in str(path) for c in ',\r\n') and
         not any(p.is_symlink() for p in (path, *path.parents)), 'unsafe-path')


def capture(argv):
    return subprocess.check_output(argv, text=True, stderr=subprocess.DEVNULL, timeout=20).strip()


def command(argv, log, timeout):
    with log.open('wb') as stream:
        proc = subprocess.Popen(list(map(str, argv)), stdout=stream, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            code = proc.wait(timeout=timeout)
            if code:
                raise CommandFailure(code)
        finally:
            if proc.poll() is None:
                for sig, seconds in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
                    try:
                        os.killpg(proc.pid, sig)
                    except ProcessLookupError:
                        pass
                    try:
                        proc.wait(timeout=seconds)
                        break
                    except subprocess.TimeoutExpired:
                        continue


def source(target, retained=None):
    if retained is not None:
        ordinary(retained)
        need(retained.is_file() and retained.stat().st_size == SOURCE_SIZE and
             sha(retained) == SOURCE_SHA, 'retained-source-differs')
        shutil.copyfile(retained, target)
    else:
        deadline = time.monotonic() + 300
        with urllib.request.urlopen(SOURCE_URL, timeout=30) as response, target.open('xb') as stream:
            need(response.url.startswith('https://'), 'source-redirect-not-https')
            count = 0
            while True:
                need(time.monotonic() < deadline, 'source-fetch-deadline')
                block = response.read1(1024 * 1024)
                if not block:
                    break
                count += len(block)
                need(count <= SOURCE_SIZE, 'source-fetch-oversized')
                stream.write(block)
    need(target.stat().st_size == SOURCE_SIZE and sha(target) == SOURCE_SHA, 'source-hash-differs')


def module(path):
    spec = importlib.util.spec_from_file_location('lsp_existing_checks', path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def preflight(args):
    need(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64') and
         os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid(), 'native-ordinary-host-required')
    need(not any(k.startswith('DOCKER_') for k in os.environ), 'docker-overrides-refused')
    paths = [args.product, args.desktop, args.builder, args.private, args.output]
    for path in paths:
        ordinary(path)
    need(all(not a.is_relative_to(b) and not b.is_relative_to(a)
             for i, a in enumerate(paths) for b in paths[i + 1:]), 'paths-must-be-separate')
    need(not args.private.exists() and not args.output.exists(), 'fresh-output-required')
    for path, pin in ((args.product, PRODUCT), (args.desktop, DESKTOP)):
        need(capture(['git', '-C', str(path), 'rev-parse', 'HEAD']) == pin, 'checkout-pin-differs')
    for name, pin in API.items():
        need(sha(args.product / name) == pin, 'builder-api-differs')
    need(sha(args.desktop / 'scripts/ci/maintained_desktop574.py') == HELPER and
         sha(args.desktop / 'scripts/ci/maintained-desktop574-inputs.json') == INPUTS, 'desktop-input-differs')
    constants = {}
    tree = ast.parse((args.desktop / 'scripts/ci/maintained_desktop574.py').read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in ('DOCKERFILE', 'PACMAN'):
                    constants[target.id] = ast.literal_eval(node.value)
    need((args.builder / 'context/Dockerfile').read_text() == constants['DOCKERFILE'] and
         (args.builder / 'context/pacman.conf').read_text() == constants['PACMAN'], '574-config-differs')
    selected = json.loads((args.desktop / 'scripts/ci/maintained-desktop574-inputs.json').read_text())
    hooks = ''.join(name + '\n' for name in sorted(set(selected['bootstrap_hook_masks'])))
    need((args.builder / 'context/disabled-hooks.txt').read_text() == hooks, '574-hook-masks-differ')
    lock = args.builder / 'installed-packages.lock'
    need(sha(lock) == LOCK and len(lock.read_text().splitlines()) == 574, '574-lock-differs')
    image = (args.builder / 'image-id').read_text().strip()
    need(re.fullmatch(r'sha256:[0-9a-f]{64}', image), 'immutable-image-required')
    report = json.loads((args.builder / 'report.json').read_text())
    need(report['status'] == 'PASS_NATIVE_OFFLINE_574_TRANSACTION' and report['image'] == image and
         report['native_build'] == 'PASS' and report['packages'] == 574 and report['acquired'] == 1153 and
         report['build_returncode'] == 0 and report['failures'] == [] and
         report['host_arch'] in ('aarch64', 'arm64') and report['daemon_arch'] in ('aarch64', 'arm64'),
         '574-builder-handoff-failed')
    need(sha(args.builder / 'context/expected-packages.lock') == LOCK, '574-context-differs')
    need(capture(['docker', 'context', 'show']) == 'default', 'local-default-docker-required')
    context = json.loads(capture(['docker', 'context', 'inspect', 'default']))[0]
    need(context['Endpoints']['docker']['Host'] == 'unix:///var/run/docker.sock', 'local-docker-required')
    need(capture(['docker', 'info', '--format', '{{.Architecture}}']) in ('aarch64', 'arm64'),
         'native-daemon-required')
    actual = json.loads(capture(['docker', 'image', 'inspect', image]))[0]
    need(actual['Architecture'] == 'arm64' and actual['Os'] == 'linux' and actual['Id'] == image,
         '574-image-differs')
    need(RECIPE_FILES and {p.name for p in (HERE / 'recipe').iterdir()} == set(RECIPE_FILES),
         'recipe-file-set-differs')
    for name, pin in RECIPE_FILES.items():
        path = HERE / 'recipe' / name
        need(path.is_file() and not path.is_symlink() and sha(path) == pin, 'recipe-differs')
    return image, lock


def observations(build, checks):
    record = json.loads((build / 'provenance.json').read_text())
    need(record['status'] == 'built-package-static-pass', 'build-not-passed')
    artifacts = list((build / 'artifacts').glob('*.pkg.tar.*'))
    need(len(artifacts) == 1, 'one-package-required')
    report = checks.package(artifacts[0])
    need(not report['errors'], 'package-checks-failed')
    members = report['members']
    need(len(members) <= 8192, 'payload-count-exceeded')
    library = 'usr/lib/lv2/lsp-plugins.lv2/lsp-plugins-lv2.so'
    license_prefix = 'usr/share/licenses/lsp-plugins-lv2-headless-development/'
    files = {name: row for name, row in members.items() if row['type'] != '5' and name not in checks.PACKAGE_METADATA}
    need(library in files and set(report['elf']) == {library}, 'unexpected-elf-set')
    for name, row in files.items():
        need(row['type'] == '0' and (name == library or name.startswith(license_prefix) or
             (name.startswith('usr/lib/lv2/lsp-plugins.lv2/') and name.endswith('.ttl'))), 'unexpected-payload')
    need(any(name.endswith('/manifest.ttl') for name in files) and
         {license_prefix + name for name in ('COPYING', 'COPYING.LESSER', 'LV2-COPYING',
                                             'Ardour-inline-display-NOTICE', 'SOURCE-NOTICE')} <= set(files),
         'required-metadata-notices-missing')
    return {'artifact_sha256': report['sha256'], 'artifact_bytes': artifacts[0].stat().st_size,
            'metadata': report['metadata'], 'members': members, 'elf': report['elf'],
            'effective_configuration': configuration(build / 'build.log'),
            'recipe_inputs': record['recipe_inputs'], 'image_id': record['image_id'],
            'expected_packages_sha256': record['expected_packages_sha256'],
            'build_log': {'bytes': (build / 'build.log').stat().st_size, 'sha256': sha(build / 'build.log')},
            'configuration_hashes': {p.name: sha(p) for p in (build / 'artifacts').iterdir()
                                     if p.name in ('makepkg.conf', 'pacman.conf', 'generated.SRCINFO', 'config.sha256')}}


def log_lines(path):
    need(path.stat().st_size <= 128 * 1024 * 1024, 'diagnostic-log-oversized')
    with path.open('r', encoding='ascii', errors='replace') as stream:
        for line in stream:
            yield line.rstrip('\n')


def configuration(path):
    result = {}
    for line in log_lines(path):
        if not line.startswith('LSP_CONFIG '):
            continue
        fields = line.split(' ', 2)
        need(len(fields) == 3, 'config-record-invalid')
        _, key, value = fields
        need(key in CONFIG_KEYS and key not in result and len(value) <= 2048, 'config-record-invalid')
        tokens = value.split()
        if key == 'BUILD_FEATURES':
            need(tokens == ['lv2'], 'headless-features-differ')
        else:
            need(tokens and all(re.fullmatch(r'-[A-Za-z0-9_.,=+:/-]+', token) for token in tokens),
                 'config-token-invalid')
            need(not any('-flto' in token or token.startswith('-mcpu=') or
                 (token.startswith('-march=') and token != '-march=armv8-a') or
                 (token.startswith('-mtune=') and token != '-mtune=generic') for token in tokens),
                 'generic-flags-differ')
            if key in CONFIG_KEYS[1:5]:
                need('-march=armv8-a' in tokens and '-mtune=generic' in tokens, 'generic-flags-missing')
        result[key] = ' '.join(tokens)
    need(set(result) == set(CONFIG_KEYS), 'config-records-missing')
    return result


def diagnostics(private):
    rows = []
    for path in sorted(private.glob('build-*/build.log')):
        for line in log_lines(path):
            if re.fullmatch(r'LSP_(?:STAGE|PROBE) [a-z][a-z0-9-]{0,31} (?:START|PASS|FAIL)', line):
                rows.append({'build': path.parent.name, 'marker': line})
    need(len(rows) <= 256, 'diagnostic-count-exceeded')
    return rows


def cleanup(private, builds):
    result = {'status': 'PASS', 'containers': [], 'private_removed': False, 'builder_image': 'BORROWED-PRESERVED'}
    for build in builds:
        path = build / 'provenance.json'
        if not path.exists():
            continue  # Existing builder writes this before its sole docker run.
        try:
            record = json.loads(path.read_text())
            name = record.get('clean_environment_id')
            if name is None:
                continue
            need(re.fullmatch(r'cachy-asahi-[0-9a-f]{16}', name), 'unknown-container')
            query = ['docker', 'container', 'ls', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}']
            before = capture(query)
            need(before in ('', name), 'ambiguous-container')
            if before:
                subprocess.run(['docker', 'rm', '-f', name], check=True, capture_output=True, timeout=20)
            need(capture(query) == '', 'container-remains')
            result['containers'].append({'name': name, 'absence_verified': True})
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            result['status'] = 'FAIL'
    if result['status'] == 'PASS':
        shutil.rmtree(private)
        result['private_removed'] = not private.exists()
        if not result['private_removed']:
            result['status'] = 'FAIL'
    return result


def run(args):
    image, lock = preflight(args)
    os.umask(0o077)
    args.private.mkdir(mode=0o700)
    args.output.mkdir(mode=0o700)
    result = {'status': 'FAIL', 'scope': 'PRIVATE-BUILD-ONLY', 'source_sha256': SOURCE_SHA,
              'product_api_source': PRODUCT, 'desktop_builder_source': DESKTOP, 'image_id': image,
              'expected_packages_sha256': LOCK, 'features': 'lv2', 'cancelled': False,
              'plugin_processing': 'NOT RUN', 'audio': 'NOT RUN', 'installation': 'NOT RUN',
              'hardware': 'NOT RUN', 'selected_for_release': False, 'builds': []}
    stage = 'source'
    builds = []
    def cancel(*_):
        raise KeyboardInterrupt()
    previous = {sig: signal.signal(sig, cancel) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        recipe = args.private / 'recipe'
        shutil.copytree(HERE / 'recipe', recipe)
        source(recipe / SOURCE_NAME, args.archive)
        checks = module(args.product / 'scripts/checks/package_checks.py')
        reviewed = checks.recipe(recipe / 'PKGBUILD')
        need(not reviewed['errors'], 'recipe-static-failed')
        pins = args.private / 'reviewed-inputs.json'
        save(pins, reviewed['input_sha256'])
        for attempt in (1, 2):
            stage = 'build-' + str(attempt)
            build = args.private / stage
            builds.append(build)
            command([sys.executable, '-I', '-B', args.product / 'scripts/build/build.py', recipe,
                     '--image', image, '--mode', 'native', '--network', 'none',
                     '--source-date-epoch', str(EPOCH), '--expected-packages', lock,
                     '--reviewed-inputs', pins, '--timeout', '2400', '--output', build],
                    args.private / (stage + '.log'), 2460)
            row = observations(build, checks)
            need(row['image_id'] == image and row['expected_packages_sha256'] == LOCK,
                 'build-selection-differs')
            save(args.output / (stage + '.json'), row)
            result['builds'].append({'attempt': attempt, 'status': 'PASS', 'artifact_sha256': row['artifact_sha256']})
        stage = 'compare'
        comparison = args.private / 'comparison.json'
        command([sys.executable, '-I', '-B', args.product / 'scripts/build/compare.py', *builds,
                 '--require-bytes'], comparison, 180)
        report = json.loads(comparison.read_text())
        need(not report['errors'] and all(row['bytes_equal'] and row['installed_contents_equal'] and
             row['pkginfo_equal'] for row in report['packages'].values()), 'pair-comparison-failed')
        save(args.output / 'comparison.json', report)
        result['status'] = 'PASS'
    except (KeyboardInterrupt, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result.update(failed_stage=stage, error_kind=type(error).__name__, cancelled=isinstance(error, KeyboardInterrupt))
        if isinstance(error, CommandFailure):
            result['child_exit_code'] = error.code
        # Raw diagnostics may contain source excerpts. Only their digest/size is public.
        result['private_logs'] = {p.name: {'bytes': p.stat().st_size, 'sha256': sha(p)}
                                  for p in args.private.glob('*.log') if p.is_file()}
    finally:
        interrupted = []
        for sig in previous:
            signal.signal(sig, lambda signum, _: interrupted.append(signum))
        try:
            try:
                result['diagnostics'] = diagnostics(args.private)
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
    parser.add_argument('--archive', type=Path, help='optional exact privately retained archive instead of host fetch')
    return run(parser.parse_args())


if __name__ == '__main__':
    sys.exit(main())
