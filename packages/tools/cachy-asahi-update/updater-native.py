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
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

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
    record.update(error_type='ValueError' if type(error) is WorkerObservationError else type(error).__name__, error=public_error(error),
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


WORKER_CHECKS=frozenset({'not-started','worker-run','container-inspection','worker-run-result',
                        'worker-diagnostic','worker-inventory','worker-artifact-shape','complete'})
WORKER_FAILURES=frozenset({'worker-run-launch-failed','worker-run-timeout','worker-run-cancelled','worker-run-failed',
    'worker-returncode-invalid','inspection-launch-failed','inspection-command-failed','inspection-timeout',
    'inspection-output-limit','inspection-json-invalid','inspection-schema-invalid','inspection-identity-mismatch',
    'inspection-id-drift','inspection-state-invalid','inspection-cancelled','inspection-io-failed',
    'inspection-cleanup-failed','worker-nonzero-returncode','worker-container-state-unaccepted','worker-diagnostic-incomplete',
    'worker-inventory-unavailable','worker-inventory-mismatch','worker-output-symlink',
    'worker-output-observation-failed','worker-observation-cancelled'})
CONTAINER_STATUSES=frozenset({'created','running','paused','restarting','removing','exited','dead'})
INSPECTION_LIMIT=1024**2


class WorkerObservationError(ValueError):
    def __init__(self,check,code):
        need(type(check) is str and check in WORKER_CHECKS and type(code) is str and code in WORKER_FAILURES,
             'invalid worker observation')
        self.check,self.code=check,code
        super().__init__(code)


def observation_need(value,code):
    if not value:raise WorkerObservationError('container-inspection',code)


def capture_inspection(name,deadline):
    """Bound stdout/time; the broker remains in the native helper's owned group."""
    process=selector=None;data=bytearray();error=None;cleanup_failed=False
    try:
        observation_need(time.monotonic()<deadline,'inspection-timeout')
        process=subprocess.Popen(['docker','inspect',name],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        selector=selectors.DefaultSelector();os.set_blocking(process.stdout.fileno(),False)
        selector.register(process.stdout,selectors.EVENT_READ)
        while selector.get_map():
            observation_need(time.monotonic()<deadline,'inspection-timeout')
            for key,_ in selector.select(min(.1,max(0,deadline-time.monotonic()))):
                chunk=os.read(key.fd,65536)
                if not chunk:selector.unregister(key.fileobj);continue
                observation_need(len(data)+len(chunk)<=INSPECTION_LIMIT,'inspection-output-limit');data.extend(chunk)
        observation_need(time.monotonic()<deadline,'inspection-timeout')
        process.wait(timeout=max(.01,deadline-time.monotonic()))
        observation_need(type(process.returncode) is int and process.returncode==0,'inspection-command-failed')
        return bytes(data)
    except subprocess.TimeoutExpired:
        error=WorkerObservationError('container-inspection','inspection-timeout');raise error from None
    except OSError:
        error=WorkerObservationError('container-inspection','inspection-launch-failed' if process is None else 'inspection-io-failed')
        raise error from None
    except BaseException as caught:
        error=caught;raise
    finally:
        mask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGTERM,signal.SIGINT})
        try:
            if process is not None:
                try:
                    if process.poll() is None:
                        process.terminate()
                        try:process.wait(timeout=1)
                        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=2)
                except BaseException:cleanup_failed=True
                if process.stdout is not None:
                    try:process.stdout.close()
                    except BaseException:cleanup_failed=True
            if selector is not None:
                try:selector.close()
                except BaseException:cleanup_failed=True
        finally:signal.pthread_sigmask(signal.SIG_SETMASK,mask)
        if cleanup_failed and error is None:raise WorkerObservationError('container-inspection','inspection-cleanup-failed')


def parse_worker_inspection(raw,name,image,nonce,controller_sha,expected_id=None):
    """Project known actual State fields only after the expected launch binding."""
    observation_need(type(raw) is bytes and len(raw)<=INSPECTION_LIMIT,'inspection-output-limit')
    observation_need(type(nonce) is str and type(name) is str and name=='cachy-asahi-updater-'+nonce and re.fullmatch('[0-9a-f]{32}',nonce) and type(image) is str and
        re.fullmatch('sha256:[0-9a-f]{64}',image) and type(controller_sha) is str and
        re.fullmatch('[0-9a-f]{64}',controller_sha),'inspection-identity-mismatch')
    def unique(rows):
        value={}
        for key,item in rows:
            observation_need(key not in value,'inspection-json-invalid');value[key]=item
        return value
    try:
        rows=json.loads(raw.decode('utf-8'),object_pairs_hook=unique,
                        parse_constant=lambda _:observation_need(False,'inspection-json-invalid'))
    except (UnicodeError,ValueError,RecursionError):
        raise WorkerObservationError('container-inspection','inspection-json-invalid') from None
    pending=[rows];count=0
    while pending:
        value=pending.pop();count+=1;observation_need(count<=8192,'inspection-schema-invalid')
        if type(value) is dict:pending.extend(value.values())
        elif type(value) is list:pending.extend(value)
    observation_need(type(rows) is list and len(rows)==1 and type(rows[0]) is dict,'inspection-schema-invalid')
    row=rows[0];identity=row.get('Id')
    observation_need(type(identity) is str and re.fullmatch('[0-9a-f]{64}',identity),'inspection-identity-mismatch')
    observation_need(expected_id is None or type(expected_id) is str and identity==expected_id,'inspection-id-drift')
    observation_need(type(row.get('Name')) is str and row['Name']=='/'+name and
                     type(row.get('Image')) is str and row['Image']==image,'inspection-identity-mismatch')
    config=row.get('Config');observation_need(type(config) is dict,'inspection-schema-invalid')
    env=config.get('Env');observation_need(type(env) is list and len(env)<=128 and
        all(type(item) is str for item in env),'inspection-schema-invalid')
    try:lengths=[len(item.encode('utf-8')) for item in env]
    except UnicodeError:raise WorkerObservationError('container-inspection','inspection-schema-invalid') from None
    observation_need(all(size<=8192 for size in lengths) and sum(lengths)<=65536,'inspection-schema-invalid')
    values={}
    for item in env:
        key,separator,value=item.partition('=')
        observation_need(bool(separator) and key not in values,'inspection-identity-mismatch');values[key]=value
    expected={'CACHY_ASAHI_CONTAINER':'1','CACHY_ASAHI_IMAGE_ID':image,'CACHY_ASAHI_UPDATE_BUILD_NONCE':nonce,
              'CACHY_ASAHI_CONTROLLER_SHA256':controller_sha,'SOURCE_DATE_EPOCH':'1789753605'}
    observation_need(all(values.get(key)==value for key,value in expected.items()),'inspection-identity-mismatch')
    state=row.get('State');observation_need(type(state) is dict,'inspection-state-invalid')
    status=state.get('Status');observation_need(type(status) is str and status in CONTAINER_STATUSES,'inspection-state-invalid')
    flags={'running':'Running','paused':'Paused','restarting':'Restarting','dead':'Dead','oom_killed':'OOMKilled'}
    observation_need(all(type(state.get(field)) is bool for field in flags.values()),'inspection-state-invalid')
    code=state.get('ExitCode');message=state.get('Error')
    observation_need(type(code) is int and 0<=code<=255 and type(message) is str,'inspection-state-invalid')
    try:message_size=len(message.encode('utf-8'))
    except UnicodeError:raise WorkerObservationError('container-inspection','inspection-state-invalid') from None
    observation_need(message_size<=8192,'inspection-state-invalid')
    return {'schema_version':1,'container_id':identity,'image_id':image,'controller_sha256':controller_sha,
            'name_sha256':hashlib.sha256(name.encode()).hexdigest(),'nonce_sha256':hashlib.sha256(nonce.encode()).hexdigest(),
            'status':status,**{key:state[field] for key,field in flags.items()},'exit_code':code,
            'state_error_present':bool(message)}


def inspect_worker(name,image,nonce,controller_sha,raw_path):
    # First expected name/image/nonce/controller observation anchors the ID;
    # a second independent query must still resolve to that immutable identity.
    deadline=time.monotonic()+60
    first=capture_inspection(name,deadline)
    observed=parse_worker_inspection(first,name,image,nonce,controller_sha)
    raw_path.write_bytes(first)
    second=capture_inspection(name,deadline)
    result=parse_worker_inspection(second,name,image,nonce,controller_sha,observed['container_id'])
    raw_path.write_bytes(second)
    return result


def worker_observation_failure(record,error):
    """Freeze the first finite parent failure; never parse exception text."""
    if record.get('worker_failure_code') is not None:return
    check=record.get('worker_check')
    if type(error) is WorkerObservationError:
        record.update(worker_check=error.check,worker_failure_code=error.code);return
    cancelled=isinstance(error,KeyboardInterrupt)
    if check=='worker-run':
        code='worker-run-cancelled' if cancelled else 'worker-run-timeout' if isinstance(error,subprocess.TimeoutExpired) else              'worker-run-launch-failed' if isinstance(error,OSError) else 'worker-run-failed'
    elif check=='container-inspection':code='inspection-cancelled' if cancelled else 'inspection-io-failed'
    elif check in ('worker-inventory','worker-artifact-shape'):
        code='worker-observation-cancelled' if cancelled else              'worker-inventory-unavailable' if check=='worker-inventory' else 'worker-output-observation-failed'
    else:return
    record['worker_failure_code']=code


def accepted_container_state(state):
    return state['status']=='exited' and state['exit_code']==0 and not any(state[key] for key in
        ('running','paused','restarting','dead','oom_killed','state_error_present'))



def diagnostic_bytes(root, name, limit, *, mode=None):
    """One nofollow, owned, stable capture under a retained private directory."""
    for path in (root, *root.parents):
        need(not path.is_symlink(), 'diagnostic namespace refused')
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
    fd = None
    try:
        parent = os.fstat(directory)
        need(parent.st_uid == os.getuid() and parent.st_gid == os.getgid()
             and not stat.S_IMODE(parent.st_mode) & 0o022, 'diagnostic owner refused')
        need(mode != 0o600 or stat.S_IMODE(parent.st_mode) == 0o700, 'diagnostic directory mode refused')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit
             and before.st_uid == os.getuid() and before.st_gid == os.getgid(), 'diagnostic file refused')
        need(mode is None or stat.S_IMODE(before.st_mode) == mode, 'diagnostic mode refused')
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk: break
            data.extend(chunk)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
                                info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        need(identity(before) == identity(os.fstat(fd)) == identity(os.stat(name, dir_fd=directory, follow_symlinks=False))
             and len(data) == before.st_size, 'diagnostic drift refused')
        named = root.lstat()
        need((parent.st_dev, parent.st_ino, parent.st_mode, parent.st_uid, parent.st_gid) ==
             (named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_gid), 'diagnostic parent drift refused')
        return bytes(data)
    finally:
        original = sys.exc_info()[1]
        close_error = None
        for owned in (fd, directory):
            if owned is not None:
                try: os.close(owned)
                except Exception as error:
                    if close_error is None: close_error = error
        if original is None and close_error is not None: raise close_error


def diagnostic_projector(recipe, expected_recipe):
    raw = diagnostic_bytes(recipe, 'public-evidence.py', 128 * 1024)
    need(hashlib.sha256(raw).hexdigest() == expected_recipe.get('public-evidence.py'), 'diagnostic projector source refused')
    audited = {name: sys.modules[name] for name in ('argparse', 'hashlib', 'json', 'os', 'pathlib', 're', 'stat')}
    def allowed_import(name, globals=None, locals=None, fromlist=(), level=0):
        need(level == 0 and name in audited and (not fromlist or name == 'pathlib' and tuple(fromlist) == ('Path',)),
             'diagnostic projector import refused')
        return audited[name]
    builtins = __builtins__ if type(__builtins__) is dict else vars(__builtins__)
    namespace = {'__name__': 'captured_worker_diagnostic_projector', '__file__': str(recipe / 'public-evidence.py'),
                 '__builtins__': dict(builtins, __import__=allowed_import)}
    exec(compile(raw, str(recipe / 'public-evidence.py'), 'exec'), namespace)
    need(all(callable(namespace.get(name)) for name in
             ('load', 'diagnostic', 'bound_worker_diagnostic', 'accepted_worker_diagnostic')),
         'diagnostic projector interface refused')
    return namespace


def capture_worker_diagnostic(artifacts, recipe, expected_recipe, provenance):
    """Failure evidence is a single capture; no later read can promote it."""
    fields = {'worker_diagnostic_status': 'UNKNOWN', 'worker_diagnostic_reason': 'source-invalid',
              'worker_diagnostic_sha256': None, 'worker_diagnostic': None}
    try:
        projector = diagnostic_projector(recipe, expected_recipe)
    except Exception:
        return fields, False
    try:
        raw = diagnostic_bytes(artifacts, 'worker-diagnostic.json', 4096, mode=0o600)
    except FileNotFoundError:
        fields['worker_diagnostic_reason'] = 'missing'; return fields, False
    except Exception:
        fields['worker_diagnostic_reason'] = 'unavailable'; return fields, False
    fields['worker_diagnostic_sha256'] = hashlib.sha256(raw).hexdigest()
    try:
        value = projector['diagnostic'](projector['load'](raw))
    except Exception:
        fields['worker_diagnostic_reason'] = 'invalid'; return fields, False
    try:
        value = projector['bound_worker_diagnostic'](value,
            controller_sha256=provenance['controller_sha256'], image_id=provenance['image_id'],
            entry_script_sha256=provenance['entry_script_sha256'], observed_state=provenance['worker_container_state'])
    except Exception:
        fields['worker_diagnostic_reason'] = 'unbound'; return fields, False
    fields.update(worker_diagnostic_status='BOUND', worker_diagnostic_reason='bound', worker_diagnostic=value)
    try:
        accepted = projector['accepted_worker_diagnostic'](value)
        need(type(accepted) is bool, 'diagnostic acceptance refused')
    except Exception:
        fields.update(worker_diagnostic_status='UNKNOWN', worker_diagnostic_reason='source-invalid', worker_diagnostic=None)
        return fields, False
    return fields, accepted

def launch(image, recipe_path, expected_lock, tools, entry, output, checks, metadata, expected_recipe, expected_entry, timeout=1800):
    need(not output.exists(), 'fresh worker output required')
    output.mkdir(mode=0o700)
    provenance = {'schema_version': 1, 'image_id': image, 'native_compilation': 'STARTING',
                  'publication': 'NOT ACCEPTED', 'hardware': 'NOT RUN', 'stage': 'input-snapshot',
                  'worker_launch_attempted': False, 'container_cleanup_attempted': False,
                  'container_removal_succeeded': False, 'container_absence_verified': False,
                  'container_cleanup_complete': False, 'worker_run_returncode':None, 'worker_check':'not-started',
                  'worker_failure_code':None,'worker_container_state':None,
                  'worker_diagnostic_status':'NOT OBSERVED','worker_diagnostic_reason':'not-started',
                  'worker_diagnostic_sha256':None,'worker_diagnostic':None}
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
        provenance['worker_check']='worker-run';save(output / 'provenance.json',provenance)
        with (output / 'build.log').open('wb') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        code=result.returncode
        valid_code=type(code) is int and -64<=code<=255
        provenance['worker_run_returncode']=code if valid_code else None
        save(output / 'provenance.json',provenance)
        if not valid_code:raise WorkerObservationError('worker-run','worker-returncode-invalid')
        provenance.update(stage='worker-inspection',worker_check='container-inspection')
        save(output / 'provenance.json',provenance)
        provenance['worker_container_state']=inspect_worker(name,image,nonce,provenance['controller_sha256'],
                                                           output / 'container-inspect.json')
        save(output / 'provenance.json',provenance)
        diagnostic_fields, diagnostic_ok = capture_worker_diagnostic(artifacts, inputs / 'recipe', expected_recipe, provenance)
        provenance.update(diagnostic_fields)
        provenance['worker_check']='worker-run-result';save(output / 'provenance.json',provenance)
        if code!=0:raise WorkerObservationError('worker-run-result','worker-nonzero-returncode')
        if not accepted_container_state(provenance['worker_container_state']):
            raise WorkerObservationError('worker-run-result','worker-container-state-unaccepted')
        provenance['worker_check']='worker-diagnostic';save(output / 'provenance.json',provenance)
        if not diagnostic_ok:
            raise WorkerObservationError('worker-diagnostic','worker-diagnostic-incomplete')
        provenance['worker_check']='worker-inventory';save(output / 'provenance.json',provenance)
        if (artifacts / 'packages.lock').read_bytes()!=expected_lock.read_bytes():
            raise WorkerObservationError('worker-inventory','worker-inventory-mismatch')
        provenance['worker_check']='worker-artifact-shape';save(output / 'provenance.json',provenance)
        if any(p.is_symlink() for p in artifacts.rglob('*')):
            raise WorkerObservationError('worker-artifact-shape','worker-output-symlink')
        provenance['worker_check']='complete';save(output / 'provenance.json',provenance)
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
        if launched and provenance['worker_diagnostic_status'] == 'NOT OBSERVED':
            provenance.update(worker_diagnostic_status='UNKNOWN', worker_diagnostic_reason=
                'unavailable' if provenance['worker_container_state'] is not None else 'state-unavailable')
        provenance['native_compilation'] = 'FAIL'
        provenance['failed_stage'] = provenance['stage']
        worker_observation_failure(provenance,error)
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
