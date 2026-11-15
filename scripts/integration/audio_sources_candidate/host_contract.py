# SPDX-License-Identifier: MIT
"""Closed observed host Docker contract; no change to inherited native policy."""
import os
from pathlib import Path
import stat


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def engine(value, spec):
    expected = dict(spec['engine_host_config'], MaskedPaths=spec['engine_masked_paths'],
                    ReadonlyPaths=spec['engine_readonly_paths'])
    actual = {key: value.get(key) for key in expected}
    for key in ('MaskedPaths', 'ReadonlyPaths'):
        need(type(actual[key]) is list and len(actual[key]) == len(set(actual[key])), 'ENGINE_PATH_LIST')
        actual[key] = sorted(actual[key])
    need(actual == expected, 'EXACT_ENGINE_HOST_CONTRACT_REQUIRED')
    return actual


def binds(value, roots):
    need(value.get('Binds') in (None, []) and type(value.get('Mounts')) is list, 'EXPLICIT_BIND_CONTRACT')
    actual = {}
    for row in value['Mounts']:
        need(row.get('Type') == 'bind' and row.get('Target') not in actual, 'EXTRA_OR_DUPLICATE_BIND')
        actual[row['Target']] = (row.get('Source'), row.get('ReadOnly', False))
    need(actual == roots, 'EXACT_PRIVATE_BIND_SOURCES_REQUIRED')


def mount_record(row):
    need(set(row) == {'fs', 'options', 'root'} and isinstance(row['options'], set)
         and row['options'] & {'rw', 'ro'} in ({'rw'}, {'ro'})
         and not any(a in row['options'] and b in row['options'] for a, b in
                     (('nosuid', 'suid'), ('nodev', 'dev'), ('noexec', 'exec'))), 'HOST_MOUNT_RECORD')


def device(path, identity):
    node = Path(path).lstat()
    need(stat.S_ISCHR(node.st_mode) and (os.major(node.st_rdev), os.minor(node.st_rdev)) == tuple(identity),
         'HOST_CHARACTER_DEVICE_IDENTITY')


def mounts(repository, observed, declaration, spec):
    engine(declaration, spec)
    admitted = {}
    for path, identity in spec['standard_device_mounts'].items():
        if path not in observed:
            continue
        row = observed[path]; mount_record(row)
        need(row['fs'] in {'tmpfs', 'devtmpfs'} and 'nosuid' in row['options']
             and row['root'] in {path, '/' + Path(path).name}, 'STANDARD_DEVICE_MOUNT_IDENTITY')
        device(path, identity)
        admitted[path] = dict(kind='standard-character-device', major=identity[0], minor=identity[1])
    for path in spec['engine_masked_paths']:
        exists = Path(path).exists() or Path(path).is_symlink()
        need(not exists or path in observed, 'ENGINE_MASK_NOT_ACTUALLY_MOUNTED')
        if path not in observed or path not in spec['null_mask_paths']:
            continue
        need(path in declaration['MaskedPaths'], 'UNDECLARED_PROTECTED_MASK')
        row = observed[path]; mount_record(row)
        mask = spec['null_mask_identity']
        need(row['fs'] in mask['filesystems'] and row['root'] == mask['root']
             and set(mask['required_options']) <= row['options'], 'PROTECTED_NULL_MOUNT_IDENTITY')
        device(path, (1, 3))
        admitted[path] = dict(kind='engine-declared-null-mask', major=1, minor=3)
    path = spec['work_volume']['path']; row = observed.get(path, {})
    mount_record(row)
    work = spec['work_volume']
    need(row['fs'] == work['filesystem'] and row['root'] == work['root']
         and set(work['options_required']) <= row['options'] and 'noexec' not in row['options'],
         'EXECUTABLE_OWNED_ALPM_VOLUME_REQUIRED')
    admitted[path] = dict(kind='owned-bounded-executable-tmpfs')
    for path, data in spec['data_volumes'].items():
        row = observed.get(path, {}); mount_record(row)
        need(row['fs'] == 'tmpfs' and row['root'] == '/' and set(data['options_required']) <= row['options'],
             'PRIVATE_NOEXEC_DATA_VOLUME_REQUIRED')
    # Explicit new roles above are fully checked, never fabricated as old facts.
    # The unchanged native/common policy checks every remaining record.
    repository.validate_mounts({p: row for p, row in observed.items() if p not in admitted})
    return admitted


def volumes(spec, nonce, initial=False):
    roles = {spec['work_volume']['path']: spec['work_volume'], **spec['data_volumes']}
    devices = set()
    for name, role in roles.items():
        path = Path(name); info = path.lstat(); usage = os.statvfs(path)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
             and stat.S_IMODE(info.st_mode) == role['mode']
             and usage.f_frsize * usage.f_blocks == role['bytes'], 'EXACT_TMPFS_RESOURCE_IDENTITY')
        devices.add(info.st_dev)
        need(not initial or not any(path.iterdir()), 'PRIVATE_VOLUME_NOT_FRESH')
    need(len(devices) == len(roles), 'PRIVATE_TMPFS_VOLUMES_MUST_BE_DISTINCT')
    if not initial:
        owner = Path(spec['work_volume']['path']) / spec['work_volume']['owner_marker']
        info = owner.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 0
             and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 33,
             'EXECUTABLE_VOLUME_OWNER_NONCE')
        fd = os.open(owner, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            need(stream.read(34) == (nonce + '\n').encode(), 'EXECUTABLE_VOLUME_OWNER_NONCE')


def claim(spec, nonce):
    path = Path(spec['work_volume']['path']) / spec['work_volume']['owner_marker']
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write((nonce + '\n').encode())


def runtime_metadata(repository):
    for path in repository.RUNTIME_FILES:
        info = Path(path).lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022,
             'STANDARD_DOCKER_METADATA_IDENTITY')
