#!/usr/bin/env python3
"""Audit frozen signed ALARM inputs or build them on a native, disposable ARM runner."""
import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/checks'))
from package_checks import recipe

RECIPES = ('cachy-asahi-hyprland-settings', 'cachy-asahi-fish-config',
           'cachy-asahi-zsh-config', 'cachy-asahi-setup')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def run(command, log=None, timeout=1800):
    if log is None:
        return subprocess.check_output(command, text=True, timeout=timeout).strip()
    with log.open('w') as stream:
        result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        raise ValueError(f'command failed ({result.returncode}); see {log}')


def check_pin(value):
    if not re.fullmatch(r'[0-9a-f]{64}', value or ''):
        raise ValueError('a reviewed full SHA-256 is required')
    return value


def load_pinned(path, expected):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != check_pin(expected):
        raise ValueError(f'reviewed input file changed: {path}')
    return json.loads(data)


class AcquisitionError(ValueError):
    def __init__(self, name, category, http_status=None):
        self.filename, self.category, self.http_status = name, category, http_status
        detail = f'HTTP {http_status}' if http_status is not None else category
        super().__init__(f'input acquisition failed: {name}: {detail}')


def input_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9._+@:~-]{1,255}', value) or value in ('.', '..'):
        raise ValueError('unsafe cache filename')
    return value


def fetch(item, cache):
    name = input_name(item['filename'])
    check_pin(item['sha256'])
    if not isinstance(item['size'], int) or not 0 <= item['size'] <= 2 * 1024**3:
        raise ValueError('invalid input size')
    target = cache / name
    if target.exists():
        if target.is_symlink() or not target.is_file() or target.stat().st_size != item['size'] or sha(target) != item['sha256']:
            raise ValueError(f'cached input differs from pin: {name}')
        return target
    if not item['url'].startswith('https://'):
        raise ValueError('downloads require verified HTTPS')
    descriptor, temporary = tempfile.mkstemp(prefix=name + '.', suffix='.partial', dir=cache)
    partial = Path(temporary)
    try:
        with os.fdopen(descriptor, 'wb') as stream, urllib.request.urlopen(item['url'], timeout=60) as response:
            if not response.url.startswith('https://'):
                raise ValueError('insecure redirect')
            size = 0
            while block := response.read(1024**2):
                size += len(block)
                if size > item['size']:
                    raise ValueError(f'download exceeds pinned size: {name}')
                stream.write(block)
        if partial.stat().st_size != item['size'] or sha(partial) != item['sha256']:
            raise ValueError(f'download checksum/size mismatch: {name}')
        partial.rename(target)
        return target
    except urllib.error.HTTPError as error:
        code = error.code if type(error.code) is int and 100 <= error.code <= 599 else None
        # Close the response body without retaining/printing it, including in
        # HTTPError's implicit-cleanup warning after the failed future is released.
        try:
            error.close()
        except OSError:
            pass
        raise AcquisitionError(name, 'HTTP failure', code) from None
    except (urllib.error.URLError, TimeoutError):
        raise AcquisitionError(name, 'HTTPS transport failure') from None
    finally:
        partial.unlink(missing_ok=True)


def acquire(items, cache, out):
    """Persist each transport/pin result before any signature authentication."""
    names = [input_name(item['filename']) for item in items]
    if len(names) != len(set(names)) or len(names) > 1024:
        raise ValueError('duplicate/oversized acquisition input set')
    records = {item['filename']: {'status': 'PENDING', 'expected_sha256': check_pin(item['sha256']),
                                 'expected_bytes': item['size']} for item in items}
    receipt = {'schema_version': 1, 'acquisition': 'IN_PROGRESS', 'signature_authentication': 'NOT RUN',
               'inputs': records, 'counts': {'total': len(items), 'pass': 0, 'fail': 0, 'pending': len(items)}}

    def persist():
        descriptor, name = tempfile.mkstemp(prefix='acquisition.', suffix='.partial', dir=out)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, 'w') as stream:
                json.dump(receipt, stream, sort_keys=True, indent=2); stream.write('\n')
                stream.flush(); os.fsync(stream.fileno())
            temporary.replace(out / 'acquisition.json')
        finally:
            temporary.unlink(missing_ok=True)

    persist()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(fetch, item, cache): item['filename'] for item in items}
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    future.result()
                    records[name]['status'] = 'PASS'
                    receipt['counts']['pass'] += 1
                except Exception as error:
                    records[name].update(status='FAIL', error_type=type(error).__name__,
                                         error='transport, cache or pinned-byte validation failed')
                    if isinstance(error, AcquisitionError):
                        records[name].update(error=error.category, http_status=error.http_status)
                    receipt['counts']['fail'] += 1
                receipt['counts']['pending'] -= 1
                persist()
        receipt['acquisition'] = 'FAIL' if receipt['counts']['fail'] else 'PASS'
    finally:
        persist()
    if receipt['counts']['fail']:
        failed = sorted(name for name, row in records.items() if row['status'] == 'FAIL')
        shown = [name + (f' (HTTP {records[name]["http_status"]})' if records[name].get('http_status') else '')
                 for name in failed[:20]]
        raise ValueError(f'{len(failed)} input acquisitions failed: ' + ', '.join(shown) +
                         '; complete per-input results in acquisition.json')
    return receipt


def signature_item(item):
    return {'filename': item['filename'] + '.sig', 'url': item['url'] + '.sig',
            'sha256': item['signature_sha256'], 'size': item['signature_size']}


def valid_signature(status, signer):
    records = [line.split()[1:] for line in status.splitlines() if line.startswith('[GNUPG:] ')]
    if any(row[0] in ('EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'BADSIG', 'ERRSIG', 'NO_PUBKEY') for row in records):
        raise ValueError('invalid, expired, revoked or unverified signature')
    valid = [row for row in records if row[0] == 'VALIDSIG']
    if len(valid) != 1 or len(valid[0]) != 11 or valid[0][1] != signer or valid[0][-1] != signer:
        raise ValueError('signature does not match the pinned primary fingerprint')


def pkginfo(text):
    result = {}
    for line in text.splitlines():
        if line and not line.startswith('#'):
            key, value = line.split(' = ', 1)
            result.setdefault(key, []).append(value)
    return result


def inspect_package(path, expected):
    found, buildinfo, hooks, paths, seen = None, None, {}, [], set()
    with tarfile.open(path, 'r|xz') as archive:
        for member in archive:
            name = member.name.removeprefix('./')
            if name.startswith('/') or '..' in Path(name).parts:
                raise ValueError(f'unsafe package path: {name}')
            if name in seen:
                raise ValueError(f'duplicate package member: {name}')
            seen.add(name)
            paths.append(name)
            if name.startswith(('usr/share/libalpm/hooks/', 'etc/pacman.d/hooks/')) and not member.isdir() and not member.isfile():
                raise ValueError('nonregular installed package hook')
            if name in ('.PKGINFO', '.BUILDINFO', '.INSTALL') or name.startswith(('usr/share/libalpm/hooks/', 'etc/pacman.d/hooks/')) and member.isfile():
                if not member.isfile() or member.size > 1024**2:
                    raise ValueError('invalid/oversized package metadata or hook')
                data = archive.extractfile(member).read().decode()
                if name == '.PKGINFO':
                    found = pkginfo(data)
                elif name == '.BUILDINFO':
                    buildinfo = pkginfo(data)
                else:
                    hooks[name] = data
    if found is None:
        raise ValueError('package has no .PKGINFO')
    for target, source in [('pkgname', 'name'), ('pkgver', 'version'), ('arch', 'arch'),
                           ('license', 'license'), ('depend', 'depends'), ('provides', 'provides'),
                           ('conflict', 'conflicts'), ('replaces', 'replaces')]:
        value = expected[source]
        if sorted(found.get(target, [])) != sorted(value if isinstance(value, list) else [value]):
            raise ValueError(f'signed package metadata differs from frozen database: {path.name} {target}')
    return {'metadata': found, 'buildinfo': buildinfo, 'hooks': hooks, 'installed_paths': paths}


def rootfs_inventory(path):
    rows = []
    with tarfile.open(path, 'r|gz') as archive:
        for member in archive:
            name = member.name.removeprefix('./')
            if member.isfile() and name.startswith('var/lib/pacman/local/') and name.endswith('/desc'):
                if member.size > 1024**2:
                    raise ValueError('oversized rootfs package metadata')
                fields = {}
                for chunk in archive.extractfile(member).read().decode().split('\n\n'):
                    lines = chunk.strip().splitlines()
                    if lines:
                        fields[lines[0].strip('%')] = lines[1:]
                rows.append({key.lower(): fields.get(key, [])
                             for key in ('NAME', 'VERSION', 'ARCH', 'LICENSE', 'DEPENDS', 'PROVIDES')})
    if not rows:
        raise ValueError('signed rootfs has no package inventory')
    return rows


def rootfs_hooks(path):
    names = set()
    with tarfile.open(path, 'r|gz') as archive:
        for member in archive:
            name = member.name.removeprefix('./')
            if name.startswith(('usr/share/libalpm/hooks/', 'etc/pacman.d/hooks/')) and name.endswith('.hook'):
                names.add(Path(name).name)
    return sorted(names)


def hook_masks(names):
    if any(not re.fullmatch(r'[A-Za-z0-9_.@+-]+\.hook', name) for name in names):
        raise ValueError('unsafe ALPM hook mask name')
    return ''.join(name + '\n' for name in sorted(set(names)))


def audit(inputs, cache, out):
    cache.mkdir(parents=True, exist_ok=True)
    items = inputs['keyring_files'] + [inputs['rootfs'], signature_item(inputs['rootfs'])]
    for package in inputs['packages']:
        if not package['filename'].endswith('.pkg.tar.xz'):
            raise ValueError('this audited snapshot requires original .pkg.tar.xz bytes')
        items += [package, signature_item(package)]
    names = [item['filename'] for item in items]
    if len(set(names)) != len(names):
        raise ValueError('duplicate download filename')
    acquire(items, cache, out)
    keyhome = out / 'gpg'
    keyhome.mkdir(mode=0o700)
    gpg = ['gpg', '--batch', '--no-options', '--homedir', str(keyhome), '--no-auto-key-retrieve']
    run(gpg + ['--import', str(cache / 'archlinuxarm.gpg')], out / 'key-import.log', 60)
    # HTTPS upstream source and independently published full fingerprint anchor ownership.
    # VALIDSIG authenticates each payload; no imported-key UID alone is trusted.
    signatures, package_audits = {}, {}
    for item in [inputs['rootfs']] + inputs['packages']:
        command = gpg + ['--status-fd', '1', '--verify', str(cache / (item['filename'] + '.sig')), str(cache / item['filename'])]
        result = subprocess.run(command, text=True, capture_output=True, timeout=60)
        signatures[item['filename']] = {'command': command, 'exit_code': result.returncode,
                                         'status': result.stdout, 'diagnostic': result.stderr}
        save(out / 'signatures.json', signatures)
        if result.returncode:
            raise ValueError(f'signature verification failed: {item["filename"]}')
        valid_signature(result.stdout, inputs['signer_fingerprint'])
    inventory = rootfs_inventory(cache / inputs['rootfs']['filename'])
    if inventory != inputs['rootfs_packages']:
        raise ValueError('rootfs inventory differs from frozen signed-rootfs metadata')
    save(out / 'rootfs-inventory.json', inventory)
    save(out / 'rootfs-hooks.json', rootfs_hooks(cache / inputs['rootfs']['filename']))
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        values = list(pool.map(lambda item: inspect_package(cache / item['filename'], item), inputs['packages']))
    package_audits = {item['filename']: value for item, value in zip(inputs['packages'], values)}
    save(out / 'package-audit.json', package_audits)
    save(out / 'cache-checksums.json', {item['filename']: item['sha256'] for item in items})
    return len(inputs['packages'])


def probe(out):
    record = {'kernel': platform.uname()._asdict(), 'page_size': os.sysconf('SC_PAGE_SIZE'),
              'docker_server_arch': run(['docker', 'info', '--format', '{{.Architecture}}'], timeout=60),
              'docker_version': run(['docker', 'version'], timeout=60),
              'cpu': run(['lscpu'], timeout=60), 'python': sys.version,
              'uid': os.getuid(), 'gid': os.getgid(), 'runner_arch': os.environ.get('RUNNER_ARCH'),
              'runner_os': os.environ.get('RUNNER_OS'), 'image_version': os.environ.get('ImageVersion'),
              'image_os': os.environ.get('ImageOS'), 'repository': os.environ.get('GITHUB_REPOSITORY'),
              'commit': os.environ.get('GITHUB_SHA'), 'run_id': os.environ.get('GITHUB_RUN_ID'),
              'bootstrap_script_sha256': sha(Path(__file__)),
              'native_build': 'NOT RUN', 'hardware_validation': 'NOT RUN'}
    save(out / 'runner.json', record)
    if platform.system() != 'Linux' or platform.machine() not in ('aarch64', 'arm64') or record['docker_server_arch'] not in ('aarch64', 'arm64'):
        raise ValueError('native Linux ARM host and native local ARM Docker daemon required')
    if os.getuid() == 0:
        raise ValueError('the native build coordinator must be non-root')
    context = json.loads(run(['docker', 'context', 'inspect'], timeout=60))[0]
    endpoint = context['Endpoints']['docker']['Host']
    local = ('unix:///var/run/docker.sock', 'unix:///run/docker.sock')
    if endpoint not in local or os.environ.get('DOCKER_HOST', endpoint) not in local:
        raise ValueError('the default local Docker socket is required; remote contexts are forbidden')
    record['docker_endpoint'] = endpoint
    save(out / 'runner.json', record)
    return record


def setup_sync():
    base = ROOT / 'packages/settings/cachy-asahi-setup'
    data = json.loads((base / 'source-provenance.json').read_bytes())
    if data['canonical_path'] != 'scripts/setup/setup.py' or data['packaged_source'] != 'cachy-asahi-setup':
        raise ValueError('unexpected setup canonical/source provenance paths')
    for path, expected in [(ROOT / data['canonical_path'], data['sha256']),
                           (base / data['packaged_source'], data['sha256']),
                           (ROOT / 'LICENSE', data['license_sha256']),
                           (base / 'LICENSE', data['license_sha256'])]:
        if path.is_symlink() or not path.resolve().is_relative_to(ROOT.resolve()) or sha(path) != check_pin(expected):
            raise ValueError('canonical/package setup source or license differs from pinned provenance')


def freeze_recipes(output):
    reports = [recipe(path) for directory in ('desktop', 'shells', 'settings')
               for path in (ROOT / 'packages' / directory).rglob('PKGBUILD')]
    if any(report['errors'] for report in reports):
        raise ValueError('recipe inspection failed')
    if sorted(report['metadata']['pkgname'][0] for report in reports) != sorted(RECIPES):
        raise ValueError('all four original recipes must exist before freezing the reviewed set')
    setup_sync()
    save(output, {str(Path(report['recipe']).parent.relative_to(ROOT)): report['input_sha256'] for report in reports})


def build(inputs, cache, out, reviews):
    # This narrow scratch bootstrap preserves original xz package signatures.
    # provision.py requires a preexisting registry digest; this base starts as a signed rootfs.
    context = out / 'context'
    context.mkdir()
    shutil.copyfile(cache / inputs['rootfs']['filename'], context / 'rootfs.tar.gz')
    deps = context / 'deps'
    deps.mkdir()
    for item in inputs['packages']:
        for name in (item['filename'], item['filename'] + '.sig'):
            shutil.copyfile(cache / name, deps / name)
    keys = context / 'keys'
    keys.mkdir()
    for item in inputs['keyring_files']:
        shutil.copyfile(cache / item['filename'], keys / item['filename'])
    # Bind the exact bytes verified above to the Docker context before execution.
    copied = [(context / 'rootfs.tar.gz', inputs['rootfs']['sha256'])]
    for item in inputs['packages']:
        copied += [(deps / item['filename'], item['sha256']),
                   (deps / (item['filename'] + '.sig'), item['signature_sha256'])]
    copied += [(keys / item['filename'], item['sha256']) for item in inputs['keyring_files']]
    if any(path.is_symlink() or sha(path) != digest for path, digest in copied):
        raise ValueError('audited input changed during Docker context copy')
    names = json.loads((out / 'rootfs-hooks.json').read_text())
    for report in json.loads((out / 'package-audit.json').read_text()).values():
        names += [Path(name).name for name in report['installed_paths']
                  if name.startswith(('usr/share/libalpm/hooks/', 'etc/pacman.d/hooks/')) and name.endswith('.hook')]
    (context / 'disabled-hooks.txt').write_text(hook_masks(names))
    (context / 'pacman.conf').write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nHookDir = /builder-disabled-hooks\n')
    dockerfile = ('FROM scratch\nADD rootfs.tar.gz /\nCOPY keys/ /usr/share/pacman/keyrings/\n'
                  'COPY deps/ /tmp/deps/\nCOPY pacman.conf /etc/pacman.conf\n'
                  'COPY disabled-hooks.txt /tmp/disabled-hooks.txt\n'
                  'RUN mkdir -p /builder-disabled-hooks '
                  '&& while IFS= read -r hook; do ln -s /dev/null "/builder-disabled-hooks/$hook"; done < /tmp/disabled-hooks.txt '
                  '&& pacman-key --init && pacman-key --populate archlinuxarm '
                  '&& pacman -U --noconfirm --noscriptlet /tmp/deps/*.pkg.tar.xz '
                  '&& ldconfig && rm -rf /tmp/deps /var/cache/pacman/pkg/* '
                  f'&& groupmod -g {os.getgid()} alarm && usermod -u {os.getuid()} -g alarm alarm '
                  '&& pacman -Q | LC_ALL=C sort > /builder-packages.lock\n'
                  'USER alarm\nWORKDIR /tmp\n')
    (context / 'Dockerfile').write_text(dockerfile)
    command = ['docker', 'build', '--network=none', '--pull=false', '--platform=linux/arm64',
               '--iidfile', str(out / 'image-id'), str(context)]
    save(out / 'bootstrap.json', {'command': command, 'dockerfile_sha256': sha(context / 'Dockerfile'),
                                 'inputs_sha256': sha(out / 'inputs.lock.json'),
                                 'hook_policy': 'ALPM hooks masked with /dev/null overrides, package scriptlets disabled; explicit in-container ldconfig',
                                 'status': 'bootstrap-starting'})
    try:
        run(command, out / 'bootstrap.log', 1800)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        save(out / 'bootstrap.json', {'command': command, 'status': 'failed', 'error': str(error),
                                     'dockerfile_sha256': sha(context / 'Dockerfile')})
        raise
    image = (out / 'image-id').read_text().strip()
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise ValueError('bootstrap produced no immutable image ID')
    inspect = json.loads(run(['docker', 'image', 'inspect', image], timeout=60))[0]
    if inspect['Architecture'] != 'arm64' or inspect['Os'] != 'linux':
        raise ValueError('bootstrap image architecture differs from native ARM contract')
    lock = run(['docker', 'run', '--rm', '--pull=never', '--network=none', '--cap-drop=ALL',
                '--security-opt=no-new-privileges', '--read-only', '--entrypoint=/bin/cat', image,
                '/builder-packages.lock'], timeout=60) + '\n'
    (out / 'packages.lock').write_text(lock)
    expected = {row['name'][0]: row['version'][0] for row in inputs['rootfs_packages']}
    expected.update({item['name']: item['version'] for item in inputs['packages']})
    if lock != ''.join(f'{name} {version}\n' for name, version in sorted(expected.items())):
        raise ValueError('offline transaction changed the frozen package set; review packages.lock')
    save(out / 'bootstrap.json', {'command': command, 'dockerfile_sha256': sha(context / 'Dockerfile'),
                                 'inputs_sha256': sha(out / 'inputs.lock.json'), 'image_id': image,
                                 'packages_lock_sha256': sha(out / 'packages.lock'),
                                 'hook_policy': 'ALPM hooks masked with /dev/null overrides, package scriptlets disabled; explicit in-container ldconfig',
                                 'status': 'image-provisioned'})
    for path, hashes in reviews.items():
        reviewed = out / (Path(path).name + '-review.json')
        save(reviewed, hashes)
        for attempt in (1, 2):
            run([sys.executable, str(ROOT / 'scripts/build/build.py'), str(ROOT / path), '--image', image,
                 '--mode', 'native', '--source-date-epoch', str(inputs['source_date_epoch']),
                 '--expected-packages', str(out / 'packages.lock'), '--reviewed-inputs', str(reviewed),
                 '--timeout', '300', '--output', str(out / (Path(path).name + f'-{attempt}'))],
                out / (Path(path).name + f'-{attempt}-driver.log'), 360)
        run([sys.executable, str(ROOT / 'scripts/build/compare.py'), str(out / (Path(path).name + '-1')),
             str(out / (Path(path).name + '-2')), '--require-bytes'], out / (Path(path).name + '-compare.json'), 120)
    return image


def main(argv=None, integration_consumers=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('probe', 'audit', 'build', 'integration', 'freeze-recipes'))
    parser.add_argument('--inputs', type=Path, default=ROOT / 'scripts/ci/inputs.lock.json')
    parser.add_argument('--inputs-sha256')
    parser.add_argument('--recipes', type=Path, default=ROOT / 'scripts/ci/recipes.lock.json')
    parser.add_argument('--recipes-sha256')
    parser.add_argument('--integration', type=Path, default=ROOT / 'scripts/ci/integration.lock.json')
    parser.add_argument('--integration-sha256')
    parser.add_argument('--integration-output', type=Path)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.mode == 'freeze-recipes':
        freeze_recipes(args.output)
        return 0
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    record = {'status': 'failed', 'mode': args.mode, 'native_build': 'NOT RUN', 'hardware_validation': 'NOT RUN',
              'reviewed_inputs_sha256': args.inputs_sha256, 'reviewed_recipes_sha256': args.recipes_sha256,
              'bootstrap_script_sha256': sha(Path(__file__))}
    try:
        if args.mode == 'probe':
            probe(out)
            record['status'] = 'native-runner-probe-pass'
        else:
            inputs = load_pinned(args.inputs, args.inputs_sha256)
            save(out / 'inputs.lock.json', inputs)
            reviews = None
            integration_lock = None
            if args.mode in ('build', 'integration'):
                probe(out)
                reviews = load_pinned(args.recipes, args.recipes_sha256)
                expected_names = sorted(RECIPES)
                if sorted(Path(path).name for path in reviews) != expected_names:
                    raise ValueError('reviewed recipe set must include all four originals')
                for path, hashes in reviews.items():
                    if path not in [str(p.parent.relative_to(ROOT)) for directory in ('desktop', 'shells', 'settings')
                                    for p in (ROOT / 'packages' / directory).rglob('PKGBUILD')]:
                        raise ValueError('reviewed recipe is outside allowed package paths')
                    report = recipe(ROOT / path / 'PKGBUILD')
                    if report['errors'] or report['input_sha256'] != hashes:
                        raise ValueError('current recipes differ from the reviewed set')
                setup_sync()
                if args.mode == 'integration':
                    import integration
                    if args.integration_output is None:
                        raise ValueError('separate new integration output required')
                    integration.output_boundaries(ROOT, out, args.cache, args.integration_output)
                    integration_lock = integration.preflight(ROOT, args.integration, args.integration_sha256,
                                                             args.recipes_sha256, inputs['source_date_epoch'])
                    accepted_commit = os.environ.get('GITHUB_SHA', '')
                    if not re.fullmatch(r'[0-9a-f]{40}', accepted_commit) or run(['git', 'rev-parse', 'HEAD']) != accepted_commit:
                        raise ValueError('accepted workflow checkout commit must match GITHUB_SHA')
            record['verified_signed_packages'] = audit(inputs, args.cache.resolve(), out)
            record['status'] = 'signed-input-audit-pass'
            if args.mode in ('build', 'integration'):
                record['status'] = 'building'
                image = build(inputs, args.cache.resolve(), out, reviews)
                record.update(status='native-builds-and-byte-comparison-pass', native_build='PASS')
                save(out / 'result.json', record)
                if args.mode == 'integration':
                    controller = integration.Controller(image, out, args.integration_output.resolve(), integration_lock, accepted_commit)
                    if not controller.run(consumers=integration_consumers):
                        raise ValueError('native virtual integration failed; inspect separate sanitized stage evidence')
                    record.update(status='native-builds-and-virtual-integration-pass', virtual_integration='PASS',
                                  integration_sha256=args.integration_sha256)
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, tarfile.TarError) as error:
        record.update(status='failed', error=str(error))
        print(str(error), file=sys.stderr)
        return 1
    finally:
        save(out / 'result.json', record)
        print(json.dumps(record, sort_keys=True))


if __name__ == '__main__':
    sys.exit(main())
