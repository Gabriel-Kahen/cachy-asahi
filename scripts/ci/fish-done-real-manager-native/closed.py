# SPDX-License-Identifier: MIT
"""Closed hosted source, retained context and accepted infrastructure gates."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

HERE = Path(__file__).resolve().parent
SLICE = 'scripts/ci/fish-done-real-manager-native'
DATA = 'scripts/ci/fish-done-real-manager-data'
MANIFEST = SLICE+'/source-manifest.json'
TEMPLATE = SLICE+'/workflow.in'
WORKFLOWS = ('.github/workflows/native-arm-build.yml',
             '.github/workflows/native-arm-fish-done-real-manager.yml')
OLD18_SHA256 = '79a869d9adc6405a07ac647d01be905f99cc1e8dedd0821f38680fc504b919dd'


def need(ok, why):
    if not ok:
        raise ValueError(why)


def safe(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and not any(c in str(path) for c in ',\r\n') and
         not any(p.is_symlink() for p in (path, *path.parents)), 'explicit ordinary absolute path required')
    return path


def read(path, cap=16*1024**2):
    path = safe(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= cap,
         'bounded ordinary single-link file required: '+path.name)
    raw = path.read_bytes()
    after = path.lstat()
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
         len(raw) == before.st_size, 'file changed during read')
    return raw


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def digest(path):
    return pin(read(path))['sha256']


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n')


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def files(root):
    root = safe(root)
    result, directories = {}, set()
    for directory, dirs, names in os.walk(root):
        parent = Path(directory)
        if parent == root:
            for external in ('.git',):
                if external in dirs:
                    need(not (root/external).is_symlink(), 'external source ancestry differs')
                    dirs.remove(external)
        for name in dirs:
            need(not (parent/name).is_symlink(), 'source directory aliases refused')
            directories.add(str((parent/name).relative_to(root)))
        for name in names:
            path = parent/name
            result[str(path.relative_to(root))] = pin(read(path))
            need(len(result) <= 192, 'finite closed source set required')
    expected={str(parent) for name in result for parent in Path(name).parents if parent != Path('.')}
    need(directories == expected, 'whole source directory membership differs')
    return result


def verify(root, expected=None):
    root = safe(root)
    raw = read(root/MANIFEST)
    if expected is not None:
        need(pin(raw)['sha256'] == expected, 'externally reviewed manifest differs')
    meta = json.loads(raw)
    need(meta['schema_version'] == 1 and
         meta['actual_source'] is meta['actual_ref'] is meta['actual_run'] is None,
         'source-only NULL selectors required')
    actual = files(root)
    need(set(actual) == set(meta['files']) | set(WORKFLOWS) | {MANIFEST},
         'whole closed source membership differs')
    for name, row in meta['files'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts and actual[name] == row,
             'closed source leaf differs: '+name)
    template = read(root/TEMPLATE).decode()
    rendered = template.replace('@MANIFEST_SHA256@', pin(raw)['sha256']).replace(
        '@JOB_SHA256@', meta['files'][SLICE+'/job.py']['sha256'])
    need(all(read(root/name).decode() == rendered for name in WORKFLOWS), 'full workflow/alias drift')
    infra = json.loads(read(root/SLICE/'held-infrastructure.json'))
    need(all(actual[name] == row for name, row in infra.items()), 'accepted infrastructure changed')
    context = json.loads(read(root/DATA/'context.json'))
    need(context['status'] == 'PASS_DATA_ONLY_NATIVE_BUILD_CONTEXT' and len(context['files']) == 24 and
         context['build'] == context['native_runtime'] == context['installed_delivery'] == 'NOT_RUN' and
         digest(root/DATA/'context.json') == meta['context_sha256'], 'reserved-process24 context differs')
    need({n.removeprefix(DATA+'/') for n in actual if n.startswith(DATA+'/')} == set(context['files']) | {'context.json'},
         'whole held context membership differs')
    for name, row in context['files'].items():
        need(actual[DATA+'/'+name] == row, 'held context byte differs: '+name)
    association = json.loads(read(root/SLICE/'data-association.json'))
    need(association['actual'] is None and set(association['files']) == set(context['files']) | {'context.json'} and
         all(row['pin'] == actual[DATA+'/'+name] and row['actual_authority'] is False
             for name, row in association['files'].items()), 'complete DATA-only source/license association required')
    lock = json.loads(read(root/DATA/'build.lock.json'))
    ledger = json.loads(read(root/'scripts/ci/maintained-desktop574-inputs.json'))
    base = {r['name']: r for r in ledger['packages']}
    need(len(base) == 574 and all(base[name] == row for name, row in lock['required_packages'].items()) and
         len(lock['required_packages']) == 26, 'exact26 roots in complete574 dependency inventory required')
    inventory = ''.join(r['name']+' '+r['version']+'\n' for r in sorted(base.values(), key=lambda r:r['name'])).encode()
    need(pin(inventory)['sha256'] == lock['base']['inventory_sha256'] ==
         'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac' and
         read(root/DATA/'inventory574.lock') == inventory, 'known574 inventory changed')
    package_rows = json.loads(read(root/DATA/'delivery/done-lock.json'))
    need(digest(root/DATA/'done.pkg.tar.xz') == package_rows['sha256'] and package_rows['version'] == '0.1.0-2',
         'exact retained Done native archive required')
    need(digest(root/'packages/tools/cachy-asahi-fish-done/check-module.py') == OLD18_SHA256,
         'unchanged original18 driver required')
    return meta


def held_job(root):
    contract = load(root/'scripts/ci/setup8-native/contract.py', 'held_done_cleanup_contract')
    previous = sys.modules.get('contract')
    sys.modules['contract'] = contract
    try:
        return load(root/'scripts/ci/tools-native/job.py', 'held_done_cleanup')
    finally:
        if previous is None:
            sys.modules.pop('contract', None)
        else:
            sys.modules['contract'] = previous


def held_docker(root, image, name, output):
    contract = load(root/'scripts/ci/setup8-native/contract.py', 'held_done_docker_contract')
    previous = sys.modules.get('contract')
    sys.modules['contract'] = contract
    try:
        module = load(root/'scripts/ci/welcome-native/run.py', 'held_done_docker')
    finally:
        if previous is None:
            sys.modules.pop('contract', None)
        else:
            sys.modules['contract'] = previous
    return module.docker(image, name, output, root=True), contract.LABEL
