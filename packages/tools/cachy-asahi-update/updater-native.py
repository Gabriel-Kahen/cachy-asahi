#!/usr/bin/env python3
"""Freeze updater inputs or build them in a separate authenticated native worker.

Freeze/plan only read data. Build requires a native nonroot ARM coordinator and
local ARM Docker; all installation/compiler execution stays inside containers.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import posixpath
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[2]
PINS = {
    'scripts/ci/inputs.lock.json': '3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650',
    'scripts/port/updater-extension/builder-extension.lock.json': '988a74e39f5d3b74cee18dcd53e78733c38872fe2143ccf4e2f4e95d5a5f8776',
    'scripts/port/updater-extension/extension-receipt.json': 'f48c3fa41de8df649260e3c16fa3361f0c4b65e28c70e431baee8d887bcf4490',
    'scripts/port/updater-extension/expected-packages.lock': 'd5e2b02a4af36b763c24c0eded8d4b7326874448996f94126fbfc3f787946271',
    # Runtime pin awaits a coordinator-reviewed checkpoint; tests use retained data.
    'scripts/ci/native_arm.py': 'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898',
}
TOOLS = ('cargo', 'rustc', 'rustdoc', 'pacman', 'gcc', 'cc', 'ld', 'pkg-config',
         'make', 'scdoc', 'git', 'python', 'bash', 'makepkg', 'readelf')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class BuildCancelled(KeyboardInterrupt):
    def __init__(self, signum):
        self.signum = signum
        super().__init__('cancelled by ' + signal.Signals(signum).name)


def cancel(signum, _frame):
    raise BuildCancelled(signum)


def public_error(error):
    """Bound diagnostics; never serialize subprocess output, argv or environment."""
    if isinstance(error, BuildCancelled):
        return str(error)
    if isinstance(error, KeyboardInterrupt):
        return 'cancelled by keyboard interrupt'
    if isinstance(error, subprocess.TimeoutExpired):
        return 'external command timed out; see retained logs'
    if isinstance(error, subprocess.CalledProcessError):
        return 'external command failed (exit ' + str(error.returncode) + '); see retained logs'
    if isinstance(error, OSError):
        return 'filesystem/process error (errno ' + str(error.errno) + ')'
    if isinstance(error, ValueError):
        return str(error).replace('\n', ' ')[:1024]
    return 'operation failed; see retained logs'


def failure(record, error):
    record.update(error_type=type(error).__name__, error=public_error(error),
                  cancelled=isinstance(error, KeyboardInterrupt))
    if isinstance(error, BuildCancelled):
        record['cancel_signal'] = signal.Signals(error.signum).name


def save(path, value):
    """Atomic, fsynced status; cancellation cannot interrupt its replacement."""
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix='.' + path.name + '-',
                                         delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(value, indent=2, sort_keys=True) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def final_status(path, record, field):
    """A cancellation delivered after an atomic write must supersede PASS."""
    try:
        save(path, record)
    except KeyboardInterrupt as error:
        if record[field].startswith('PASS'):
            record[field] = 'FAIL'
            failure(record, error)
        else:
            record['finalization_cancelled'] = True
        # Defer further signals until the FAIL replacement is durable. Pending
        # signals may propagate afterwards, but cannot leave a PASS status.
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
        try:
            save(path, record)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        raise


def regular(path):
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink input refused')
    need(path.is_file() and path.stat().st_nlink == 1, 'singly-linked regular input required')
    return path


def pinned(path, expected):
    need(re.fullmatch('[0-9a-f]{64}', expected or ''), 'full SHA-256 required')
    need(sha(regular(path)) == expected, 'frozen input changed: ' + str(path))
    return path.read_bytes()


def inventory(inputs):
    result = {p['name'][0]: p['version'][0] for p in inputs['rootfs_packages']}
    result.update({p['name']: p['version'] for p in inputs['packages']})
    return result


def inventory_bytes(records):
    return ''.join(name + ' ' + version + '\n' for name, version in sorted(records.items())).encode()


def merge(base, extension, receipt, expected):
    need(extension['base_inputs_lock_sha256'] == PINS['scripts/ci/inputs.lock.json'], 'extension baseline pin differs')
    initial = inventory(base)
    need(len(initial) == 341 and hashlib.sha256(inventory_bytes(initial)).hexdigest() == extension['base_inventory_sha256'], 'current 341-package baseline differs')
    need(base['signer_fingerprint'] == extension['signer_fingerprint'] and base['keyring_files'] == extension['keyring_files'], 'extension trust inputs differ')
    additions = extension['packages']
    need(len(additions) == 13 and len({p['name'] for p in additions}) == 13, 'finite 13-package extension required')
    need(not any(p['name'] in initial for p in additions), 'baseline replacement refused')
    merged = copy.deepcopy(base)
    merged['packages'] += copy.deepcopy(additions)
    final = inventory(merged)
    need(len(final) == 354 and inventory_bytes(final) == expected and hashlib.sha256(expected).hexdigest() == extension['expected_inventory_sha256'], 'exact 354-package inventory differs')
    need(receipt['extension_lock_sha256'] == PINS['scripts/port/updater-extension/builder-extension.lock.json']
         and receipt['expected_inventory_sha256'] == extension['expected_inventory_sha256']
         and receipt['base_inputs_lock_sha256'] == extension['base_inputs_lock_sha256'], 'authenticated receipt binding differs')
    need(not any(receipt[k] for k in ('baseline_changes', 'conflicts', 'removals', 'failures', 'unsatisfied', 'deptest_missing'))
         and receipt['deptest_exit'] == 0 and receipt['verified_count'] == 13, 'extension has unresolved transaction evidence')
    # Historical first-successful builder is distinct from this refreshed baseline.
    merged['status'] = 'private-updater-extension; separate from original four-package builder'
    return merged


def plan():
    data = {name: pinned(ROOT / name, pin) for name, pin in PINS.items()}
    merged = merge(json.loads(data['scripts/ci/inputs.lock.json']),
                   json.loads(data['scripts/port/updater-extension/builder-extension.lock.json']),
                   json.loads(data['scripts/port/updater-extension/extension-receipt.json']),
                   data['scripts/port/updater-extension/expected-packages.lock'])
    return merged, data['scripts/port/updater-extension/expected-packages.lock']


def tree_hashes(root):
    files = {}
    for path in sorted(root.rglob('*')):
        need(not path.is_symlink(), 'snapshot symlink refused')
        if path.is_file():
            files[path.relative_to(root).as_posix()] = sha(regular(path))
        else:
            need(path.is_dir(), 'snapshot special file refused')
    return files


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def freeze(source, vendor, output):
    plan()  # Refuse drift before creating an input snapshot.
    need(not output.exists() and not output.is_symlink(), 'new private freeze directory required')
    output.mkdir(mode=0o700, parents=True)
    stage = output / 'recipe'
    stage.mkdir(mode=0o700)
    # Byte inputs only; omit transient interpreter caches and previous receipts.
    for path in BASE.rglob('*'):
        relative = path.relative_to(BASE)
        if '__pycache__' in relative.parts or path.suffix == '.pyc':
            continue
        need(not path.is_symlink(), 'recipe symlink refused')
        if path.is_file():
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(regular(path), target)
    checks = load_module('updater_checks', ROOT / 'scripts/checks/package_checks.py')
    data = checks.metadata((stage / '.SRCINFO').read_text())
    for external, source_index in ((source, 0), (vendor, 1)):
        name, pin = data['source'][source_index], data['sha256sums'][source_index]
        need('/' not in name and name.endswith('.tar.gz'), 'expected two local archive inputs')
        pinned(external, pin)
        shutil.copyfile(external, stage / name)
    report = checks.recipe(stage / 'PKGBUILD')
    need(not report['errors'], 'static recipe input inspection failed: ' + '; '.join(report['errors']))
    candidate = {'schema_version': 1, 'scope': 'private native Linux compile trial; publication unaccepted',
                 'recipe_path': str(stage.resolve()), 'recipe_input_sha256': report['input_sha256'],
                 'adapter_sha256': sha(Path(__file__)), 'entry_script_sha256': sha(BASE / 'native-entry.py'),
                 'immutable_inputs': PINS, 'native_compilation': 'NOT RUN', 'hardware': 'NOT RUN'}
    save(output / 'candidate.json', candidate)
    return output / 'candidate.json'


def tool_pins(inputs, cache):
    """Derive tool file/alias hashes from authenticated archives, without execution."""
    records = {}
    for item in [inputs['rootfs']] + inputs['packages']:
        archive_path = cache / item['filename']
        pinned(archive_path, item['sha256'])
        with tarfile.open(archive_path, 'r|*') as archive:
            count = 0
            for member in archive:
                count += 1
                need(count <= 200000, 'archive member bound')
                name = member.name.removeprefix('./').rstrip('/')
                need(not name.startswith('/') and '..' not in PurePosixPath(name).parts, 'unsafe authenticated archive path')
                if not name.startswith(('usr/bin/', 'bin/', 'usr/lib/')) or member.isdir():
                    continue
                if member.isfile():
                    records['/' + name] = {'archive': str(archive_path), 'member': member.name}
                    if name.startswith(('usr/bin/', 'bin/')):
                        need(member.size <= 512 * 1024**2, 'oversized tool input')
                        records['/' + name]['sha256'] = hashlib.file_digest(archive.extractfile(member), 'sha256').hexdigest()
                elif member.issym() or member.islnk():
                    target = member.linkname
                    if member.islnk():
                        target = '/' + target.removeprefix('./').lstrip('/')
                    elif not target.startswith('/'):
                        target = posixpath.join(posixpath.dirname('/' + name), target)
                    records['/' + name] = {'link': posixpath.normpath(target)}
    tools = {}
    for tool in TOOLS:
        path = '/usr/bin/' + tool
        target, seen = path, set()
        while 'link' in records.get(target, {}):
            need(target not in seen and len(seen) < 16, 'tool alias cycle')
            seen.add(target)
            target = records[target]['link']
        need('archive' in records.get(target, {}), 'authenticated regular tool target missing: ' + path)
        if 'sha256' not in records[target]:
            record = records[target]
            with tarfile.open(record['archive'], 'r|*') as archive:
                for member in archive:
                    if member.name == record['member']:
                        need(member.isfile() and member.size <= 512 * 1024**2, 'bounded regular tool target required')
                        record['sha256'] = hashlib.file_digest(archive.extractfile(member), 'sha256').hexdigest()
                        break
            need('sha256' in record, 'authenticated tool target disappeared')
        tools[path] = {'resolved_path': target, 'sha256': records[target]['sha256']}
    return {'schema_version': 1, 'builder_inventory_sha256': PINS['scripts/port/updater-extension/expected-packages.lock'], 'tools': tools}


def launch(image, recipe_path, expected_lock, tools, entry, output, checks, metadata, expected_recipe, expected_entry, timeout=1800):
    need(not output.exists(), 'fresh worker output required')
    output.mkdir(mode=0o700)
    provenance = {'schema_version': 1, 'image_id': image, 'native_compilation': 'STARTING',
                  'publication': 'NOT ACCEPTED', 'hardware': 'NOT RUN', 'stage': 'input-snapshot',
                  'worker_launch_attempted': False, 'container_cleanup_attempted': False,
                  'container_removal_succeeded': False, 'container_absence_verified': False,
                  'container_cleanup_complete': False}
    name, launched = None, False
    cleanup_error = None
    try:
        save(output / 'provenance.json', provenance)
        inputs = output / 'inputs'
        inputs.mkdir(mode=0o700)
        need(tree_hashes(recipe_path) == expected_recipe, 'reviewed recipe changed before snapshot')
        pinned(entry, expected_entry)
        shutil.copytree(recipe_path, inputs / 'recipe')
        need(tree_hashes(inputs / 'recipe') == expected_recipe, 'reviewed recipe changed during snapshot')
        entry_copy = output / 'native-entry.py'
        shutil.copyfile(entry, entry_copy)
        pinned(entry_copy, expected_entry)
        entry = entry_copy
        nonce = os.urandom(16).hex()
        tool_digest = hashlib.sha256(canonical(tools)).hexdigest()
        controller = {'schema_version': 1, 'image_id': image, 'nonce': nonce,
                      'builder_inventory_sha256': sha(expected_lock), 'tool_pins': tools,
                      'tool_pins_sha256': tool_digest, 'recipe_input_sha256': expected_recipe,
                      'entry_script_sha256': sha(entry)}
        save(inputs / 'controller-input.json', controller)
        artifacts = output / 'artifacts'
        artifacts.mkdir(mode=0o700)
        name = 'cachy-asahi-updater-' + nonce
        command = ['docker', 'run', '--name', name, '--pull=never', '--platform=linux/arm64',
                   '--user', f'{os.getuid()}:{os.getgid()}', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                   '--read-only', '--pids-limit=512', '--memory=4g', '--cpus=4', '--network=none',
                   '--tmpfs=/tmp:rw,nosuid,nodev,exec,size=4g',
                   '--env=CACHY_ASAHI_CONTAINER=1', '--env=CACHY_ASAHI_IMAGE_ID=' + image,
                   '--env=CACHY_ASAHI_UPDATE_BUILD_NONCE=' + nonce,
                   '--env=CACHY_ASAHI_CONTROLLER_SHA256=' + sha(inputs / 'controller-input.json'),
                   '--env=SOURCE_DATE_EPOCH=1789753605',
                   '--mount', f'type=bind,src={inputs.resolve()},dst=/inputs,readonly',
                   '--mount', f'type=bind,src={artifacts.resolve()},dst=/out',
                   '--mount', f'type=bind,src={entry.resolve()},dst=/builder-entry.sh,readonly',
                   '--mount', f'type=bind,src={expected_lock.resolve()},dst=/expected-packages.lock,readonly',
                   '--entrypoint=/usr/bin/python', image, '/builder-entry.sh']
        need(all(',' not in str(p) and '\n' not in str(p) for p in (inputs, artifacts, entry, expected_lock)), 'unsafe mount path')
        provenance.update(command=command, controller_sha256=sha(inputs / 'controller-input.json'),
                          entry_script_sha256=sha(entry), stage='worker-launch')
        save(output / 'provenance.json', provenance)
        launched = True
        provenance['worker_launch_attempted'] = True
        with (output / 'build.log').open('wb') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        provenance['stage'] = 'worker-inspection'
        inspection = subprocess.check_output(['docker', 'inspect', name], timeout=60)
        (output / 'container-inspect.json').write_bytes(inspection)
        need(result.returncode == 0, 'worker exited ' + str(result.returncode) + '; see build.log')
        need((artifacts / 'packages.lock').read_bytes() == expected_lock.read_bytes(), 'actual worker inventory differs')
        need(not any(p.is_symlink() for p in artifacts.rglob('*')), 'worker output symlink refused')
        provenance['stage'] = 'package-inspection'
        checks_build = load_module('updater_build_checks', ROOT / 'scripts/build/build.py')
        generated = checks.metadata((artifacts / 'generated.SRCINFO').read_text())
        checks_build.bind_generated(metadata, generated)
        packages = sorted(artifacts.glob('*.pkg.tar.*'))
        need(len(packages) == 1, 'exactly one package required')
        report = checks.package(packages[0])
        errors = report['errors'] + checks_build.bind_artifact(metadata, report, controller['recipe_input_sha256']['PKGBUILD'])
        save(output / 'package-validation.json', {'artifacts': [report], 'errors': errors})
        need(not errors, '; '.join(errors))
        provenance.update(native_compilation='PASS-private-native-package-static-checks', package_sha256=sha(packages[0]),
                          outputs_sha256=tree_hashes(artifacts), publication='NOT ACCEPTED', M2='NOT RUN')
    except BaseException as error:
        provenance['native_compilation'] = 'FAIL'
        provenance['failed_stage'] = provenance['stage']
        failure(provenance, error)
        raise
    finally:
        if launched:
            provenance['container_cleanup_attempted'] = True
            try:
                subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=60, check=True)
                provenance['container_removal_succeeded'] = True
            except BaseException as error:
                cleanup_error = error
                provenance['container_cleanup_error'] = type(error).__name__ + ': ' + public_error(error)
                provenance['container_cleanup_error_type'] = type(error).__name__
            try:
                remaining = subprocess.check_output(['docker', 'ps', '--all',
                    '--filter=name=^/' + name + '$', '--format={{.ID}}'], timeout=60)
                need(not remaining.strip(), 'named worker remains after cleanup')
                provenance['container_absence_verified'] = True
            except BaseException as error:
                provenance['container_absence_verified'] = False
                provenance['container_absence_error_type'] = type(error).__name__
                provenance['container_absence_error'] = public_error(error)
                if cleanup_error is None:
                    cleanup_error = error
                    provenance['container_cleanup_error'] = type(error).__name__ + ': ' + public_error(error)
                    provenance['container_cleanup_error_type'] = type(error).__name__
            provenance['container_cleanup_complete'] = (provenance['container_removal_succeeded']
                                                        and provenance['container_absence_verified'])
        if cleanup_error is not None and provenance['native_compilation'].startswith('PASS'):
            provenance['native_compilation'] = 'FAIL-container-cleanup'
            provenance['failed_stage'] = 'container-cleanup'
            failure(provenance, cleanup_error)
        provenance['stage'] = 'finalized'
        final_status(output / 'provenance.json', provenance, 'native_compilation')
        if cleanup_error is not None and provenance['native_compilation'] == 'FAIL-container-cleanup':
            if isinstance(cleanup_error, KeyboardInterrupt):
                raise cleanup_error
            raise ValueError('worker cleanup failed; see provenance.json') from cleanup_error


def compare_pair(first, second, checks):
    need(first.resolve() != second.resolve(), 'distinct clean workers required')
    records, packages, controllers = [], [], []
    for directory in (first, second):
        record = json.loads((directory / 'provenance.json').read_bytes())
        need(record.get('native_compilation') == 'PASS-private-native-package-static-checks', 'both private builds must pass')
        need(tree_hashes(directory / 'artifacts') == record['outputs_sha256'], 'build output changed')
        controller = json.loads(pinned(directory / 'inputs/controller-input.json', record['controller_sha256']))
        need(tree_hashes(directory / 'inputs/recipe') == controller['recipe_input_sha256'], 'build source snapshot changed')
        paths = sorted((directory / 'artifacts').glob('*.pkg.tar.*'))
        need(len(paths) == 1 and sha(paths[0]) == record['package_sha256'], 'package byte binding differs')
        report = checks.package(paths[0])
        need(not report['errors'], 'artifact inspection failed')
        records.append(record);packages.append(report);controllers.append(controller)
    need(controllers[0]['nonce'] != controllers[1]['nonce'], 'distinct worker nonces required')
    need(all(controllers[0][k] == controllers[1][k] for k in ('image_id', 'builder_inventory_sha256', 'tool_pins', 'recipe_input_sha256', 'entry_script_sha256')), 'pair input mismatch')
    trees = [{k: v for k, v in p['members'].items() if k not in checks.PACKAGE_METADATA} for p in packages]
    same_tree = trees[0] == trees[1]
    same_info = packages[0]['metadata']['.PKGINFO'] == packages[1]['metadata']['.PKGINFO']
    same_bytes = packages[0]['sha256'] == packages[1]['sha256']
    errors = []
    if not same_tree or not same_info: errors.append('installed tree or package metadata differs')
    if not same_bytes: errors.append('package bytes differ; byte reproducibility not established')
    return {'scope': 'private native Linux package pair', 'installed_contents_equal': same_tree,
            'pkginfo_equal': same_info, 'bytes_equal': same_bytes, 'errors': errors,
            'publication': 'NOT ACCEPTED', 'hardware': 'NOT RUN',
            'independence_limit': 'two clean container launches on one authenticated image/daemon'}


def build(candidate_path, candidate_sha, cache, output):
    need(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64')
         and os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid() > 0,
         'native nonroot Linux ARM coordinator required; host compiler execution refused')
    need(not output.exists(), 'new native evidence directory required')
    output.mkdir(mode=0o700, parents=True)
    result = {'schema_version': 1, 'scope': 'private native Linux trial', 'native_pair': 'STARTING',
              'publication': 'NOT ACCEPTED', 'hardware': 'NOT RUN', 'stage': 'input-validation'}
    try:
        save(output / 'result.json', result)
        candidate = json.loads(pinned(candidate_path, candidate_sha))
        need(candidate['adapter_sha256'] == sha(Path(__file__)) and candidate['immutable_inputs'] == PINS, 'candidate adapter/frozen inputs changed')
        recipe_path = Path(candidate['recipe_path'])
        need(tree_hashes(recipe_path) == candidate['recipe_input_sha256'], 'frozen recipe snapshot changed')
        entry = BASE / 'native-entry.py'
        pinned(entry, candidate['entry_script_sha256'])
        inputs, expected = plan()
        native = load_module('updater_native_bootstrap', ROOT / 'scripts/ci/native_arm.py')
        result['stage'] = 'native-probe'
        runner = native.probe(output)  # Requires local Unix socket and actual native ARM daemon.
        # Keep later bootstrap/launch commands on that inspected local daemon even
        # if another process changes the user's default Docker context.
        os.environ['DOCKER_HOST'] = runner['docker_endpoint']
        os.environ.pop('DOCKER_CONTEXT', None)
        cache.mkdir(mode=0o700, parents=True, exist_ok=True)
        need(not cache.is_symlink() and cache.stat().st_uid == os.getuid(), 'owned input cache required')
        save(output / 'inputs.lock.json', inputs)
        result['stage'] = 'input-authentication'
        native.audit(inputs, cache, output)  # Reauthenticate all baseline +13 archive signatures.
        tools = tool_pins(inputs, cache)
        save(output / 'tool-pins.json', tools)
        result['stage'] = 'image-bootstrap'
        image = native.build(inputs, cache, output, {})  # Separate bootstrap, no original recipes.
        need((output / 'packages.lock').read_bytes() == expected, 'actual immutable image inventory differs')
        checks = load_module('updater_checks_build', ROOT / 'scripts/checks/package_checks.py')
        report = checks.recipe(recipe_path / 'PKGBUILD')
        need(not report['errors'] and report['input_sha256'] == candidate['recipe_input_sha256'], 'frozen recipe changed during bootstrap')
        for attempt in (1, 2):
            result['stage'] = 'worker-' + str(attempt)
            launch(image, recipe_path, output / 'packages.lock', tools, entry, output / f'build-{attempt}', checks, report['metadata'],
                   candidate['recipe_input_sha256'], candidate['entry_script_sha256'])
        result['stage'] = 'pair-comparison'
        comparison = compare_pair(output / 'build-1', output / 'build-2', checks)
        save(output / 'comparison.json', comparison)
        need(not comparison['errors'], '; '.join(comparison['errors']))
        result.update(native_pair='PASS', image_id=image, inventory_sha256=sha(output / 'packages.lock'))
    except BaseException as error:
        result['native_pair'] = 'FAIL'
        failure(result, error)
        # A worker's cleanup failure is part of the pair's terminal public state.
        cleanup = []
        for attempt in (1, 2):
            path = output / ('build-' + str(attempt)) / 'provenance.json'
            if path.is_file() and not path.is_symlink():
                try:
                    record = json.loads(path.read_bytes())
                    if record.get('container_cleanup_error'):
                        cleanup.append({'worker': attempt, 'error_type': record.get('container_cleanup_error_type'),
                                        'error': record['container_cleanup_error'][:1024]})
                except (OSError, ValueError):
                    cleanup.append({'worker': attempt, 'error': 'worker cleanup receipt unreadable'})
        if cleanup:
            result['worker_cleanup_errors'] = cleanup
        raise
    finally:
        result['failed_stage'] = result['stage'] if result['native_pair'] != 'PASS' else None
        result['stage'] = 'finalized'
        final_status(output / 'result.json', result, 'native_pair')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, cancel)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('plan', 'freeze', 'build'))
    parser.add_argument('--source', type=Path)
    parser.add_argument('--vendor', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--candidate-sha256')
    parser.add_argument('--cache', type=Path)
    args = parser.parse_args()
    if args.mode == 'plan':
        inputs, expected = plan()
        print(json.dumps({'scope': 'private native proposal', 'packages': len(inventory(inputs)), 'inventory_sha256': hashlib.sha256(expected).hexdigest(), 'build': 'NOT RUN'}))
    elif args.mode == 'freeze':
        need(all((args.source, args.vendor, args.output)), 'freeze source/vendor/output required')
        path = freeze(args.source.absolute(), args.vendor.absolute(), args.output.absolute())
        print(json.dumps({'candidate': str(path), 'sha256': sha(path), 'native_compilation': 'NOT RUN'}))
    else:
        need(all((args.candidate, args.candidate_sha256, args.cache, args.output)), 'build candidate/pin/cache/output required')
        build(args.candidate.absolute(), args.candidate_sha256, args.cache.absolute(), args.output.absolute())
