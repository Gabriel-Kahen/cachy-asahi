#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Recover one exact Qt detached signature from retained repository DATA, offline."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
FROZEN = {'bytes': 7326, 'sha256': 'cf66e1390dbe87b64c44a51f45ecd4fc786c26cdeabd8efa8ad560f7843d9d88'}
MAX_DATABASE = 16 * 1024**2


def need(ok, code):
    if not ok:
        raise ValueError(code)


def descriptor(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'CANONICAL_PATH_REQUIRED')
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ALIASED_PATH_REFUSED')
    return path


def stable(s):
    # A legitimate read can change atime; content/identity metadata must remain.
    return tuple(getattr(s, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_nlink',
        'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def pinned(path, expected):
    path = ordinary(path)
    need(0 < expected['bytes'] <= MAX_DATABASE, 'INPUT_BOUND')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             before.st_size == expected['bytes'], 'ORDINARY_EXACT_INPUT_REQUIRED')
        raw = stream.read(expected['bytes'] + 1)
        need(stable(before) == stable(os.fstat(stream.fileno())) == stable(path.lstat()),
             'INPUT_CHANGED')
    need(descriptor(raw) == expected, 'INPUT_PIN_DIFFERS')
    return raw


def frozen_record():
    value = json.loads(pinned(HERE / 'qt-frozen-inputs.json', FROZEN))
    row = value['packages']['qt6-base']
    need(row['filename'] == 'qt6-base-6.12.0-2-aarch64.pkg.tar.xz' and
         row['version'] == '6.12.0-2' and row['arch'] == 'aarch64', 'FIXED_QT_IDENTITY')
    return row


def signature_from_desc(raw, row):
    source = row['source']
    need(descriptor(raw) == dict(bytes=source['entry_bytes'], sha256=source['entry_sha256']),
         'DESC_PIN_DIFFERS')
    fields = {}
    for block in raw.decode('utf-8', errors='strict').strip().split('\n\n'):
        lines = block.splitlines()
        need(lines and lines[0].startswith('%') and lines[0].endswith('%') and
             lines[0] not in fields and len(lines) >= 2, 'DESC_FIELDS')
        fields[lines[0]] = lines[1:]
    for key, expected in {'%FILENAME%': row['filename'], '%NAME%': 'qt6-base',
        '%BASE%': 'qt6-base', '%VERSION%': row['version'], '%ARCH%': row['arch'],
        '%CSIZE%': str(row['archive']['bytes']), '%SHA256SUM%': row['archive']['sha256']}.items():
        need(fields.get(key) == [expected], 'DESC_ASSOCIATION_DIFFERS')
    need(fields.get('%LICENSE%') == row['licenses_declared'], 'DECLARED_LICENSES_DIFFER')
    need(len(fields.get('%PGPSIG%', [])) == 1, 'ONE_ENCODED_SIGNATURE_REQUIRED')
    signature = base64.b64decode(fields['%PGPSIG%'][0], validate=True)
    need(descriptor(signature) == row['signature'], 'SIGNATURE_PIN_DIFFERS')
    return signature


def database_signature(raw, row):
    need(descriptor(raw) == {k: row['source']['database'][k] for k in ('bytes', 'sha256')},
         'DATABASE_PIN_DIFFERS')
    found = []
    total = 0
    deadline = time.monotonic() + 30
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r|*') as archive:
        for count, member in enumerate(archive, 1):
            total += member.size
            need(count <= 50000 and 0 <= member.size <= 65536 and total <= 64 * 1024**2 and
                 time.monotonic() < deadline, 'DATABASE_MEMBER_BOUND')
            if member.name == row['source']['entry']:
                need(not found and member.isfile() and not member.issparse() and
                     member.size == row['source']['entry_bytes'], 'ONE_REGULAR_DESC_REQUIRED')
                with archive.extractfile(member) as stream:
                    found.append(stream.read(65537))
    need(len(found) == 1, 'EXACT_DESC_REQUIRED')
    return signature_from_desc(found[0], row)


def recover(database, output):
    database, output = ordinary(database), ordinary(output)
    need(not output.exists() and not database.is_relative_to(output), 'FRESH_SEPARATE_OUTPUT_REQUIRED')
    parent = output.parent.stat()
    need(stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode) == 0o700 and
         parent.st_uid == os.getuid(), 'OWNED_PRIVATE_PARENT_REQUIRED')
    row = frozen_record()
    raw = pinned(database, {k: row['source']['database'][k] for k in ('bytes', 'sha256')})
    signature = database_signature(raw, row)
    receipt = dict(schema=1, status='EXACT_QT_SIGNATURE_RECOVERED_ARCHIVE_STILL_REQUIRED',
        filename=row['filename'] + '.sig', signature=row['signature'], archive=row['archive'],
        source=row['source'], licenses_declared=row['licenses_declared'],
        signature_authentication='NOT_PERFORMED', archive_supplied_by_this_operation=False,
        archive_metadata='NOT_ACQUIRED_OR_INSPECTED', catalog_accepted=False,
        legal_acceptance=False, native_execution=False, root_authority=None)
    output.mkdir(mode=0o700)
    for name, body in ((receipt['filename'], signature), ('recovery.json',
        (json.dumps(receipt, sort_keys=True, indent=2, allow_nan=False) + '\n').encode())):
        with os.fdopen(os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
            stream.write(body)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        need(sys.flags.isolated and sys.dont_write_bytecode, 'ISOLATED_NO_BYTECODE_REQUIRED')
        result = recover(args.database, args.output)
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError):
        print('Exact offline Qt signature recovery refused', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
