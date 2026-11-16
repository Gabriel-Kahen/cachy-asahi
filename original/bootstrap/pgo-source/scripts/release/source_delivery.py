#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Associate opaque release source files. Review records are data, not approval.

Callers authenticate release signatures and bind callbacks to signed payload rows.
Input-relative paths are publisher inputs only; recipient reads use evidence IDs.
No archive is extracted and no source, subprocess or network operation executes.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

MAX_JSON = 4 * 1024**2
MAX_FILE, MAX_TOTAL, MAX_FILES = 512 * 1024**2, 2 * 1024**3, 4096
RECEIPT = 'source-delivery-receipt.json'
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')


class Error(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise Error(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fields(value, keys):
    need(type(value) is dict and set(value) == set(keys), 'unexpected source-delivery fields')


def name(value):
    need(type(value) is str and NAME.fullmatch(value) and value != RECEIPT, 'unsafe/reserved evidence ID')
    return value


def relative(value):
    need(type(value) is str and value and '\\' not in value and '\x00' not in value, 'unsafe source input path')
    path = PurePosixPath(value)
    need(not path.is_absolute() and path.parts and path.as_posix() == value and
         all(p not in ('.', '..') for p in path.parts), 'noncanonical source input path')
    return path.parts


def sha(value):
    need(type(value) is str and HEX.fullmatch(value), 'SHA-256 required')
    return value


def descriptor(row, material=False):
    fields(row, ('id', 'path', 'sha256', 'bytes') if material else ('id', 'path', 'sha256'))
    name(row['id']); relative(row['path']); sha(row['sha256'])
    if material:
        need(type(row['bytes']) is int and 0 < row['bytes'] <= MAX_FILE, 'material byte bound')
    return row


def decode(raw):
    need(type(raw) is bytes and len(raw) <= MAX_JSON, 'source JSON byte bound')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate source JSON key')
            result[key] = value
        return result
    def invalid(value):
        raise Error('source JSON float/nonfinite value')
    try:
        result = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Error('invalid source JSON') from error
    need(type(result) is dict, 'source JSON object required')
    return result


def identity(row):
    fields(row, ('name', 'version', 'arch', 'sha256'))
    name(row['name']); sha(row['sha256'])
    need(type(row['version']) is str and 0 < len(row['version']) <= 256 and
         not any(c.isspace() or c == '\x00' for c in row['version']), 'package version required')
    need(row['arch'] in ('any', 'aarch64'), 'source package architecture')
    return row


def materials(record):
    fields(record, ('package', 'bundle', 'notices', 'source_map', 'recipe', 'recipe_key', 'authorization', 'review_status'))
    identity(record['package']); relative(record['recipe_key'])
    need(type(record['review_status']) is str and bool(record['review_status'].strip()) and
         len(record['review_status']) <= 4096, 'retained review status required')
    need(type(record['notices']) is list and 0 < len(record['notices']) <= MAX_FILES, 'notices list required')
    result = [record['bundle'], *record['notices'], record['source_map'], record['recipe'], record['authorization']]
    for row in result:
        descriptor(row, True)
    need(len(result) <= MAX_FILES and len({r['id'] for r in result}) == len(result), 'duplicate material ID')
    need(sum(r['bytes'] for r in result) <= MAX_TOTAL, 'source material total byte bound')
    return result


def checked(row, read, limit=MAX_FILE):
    raw = read(row['id'], limit)
    need(type(raw) is bytes and len(raw) <= limit and digest(raw) == row['sha256'], 'source material checksum/bound mismatch')
    if 'bytes' in row:
        need(len(raw) == row['bytes'], 'source material length mismatch')
    return raw


def record_check(record, read, provenance=None):
    rows = materials(record)
    source_map = decode(checked(record['source_map'], read, MAX_JSON))
    need(0 < len(source_map) <= MAX_FILES, 'bounded source map required')
    for path, value in source_map.items():
        relative(path); sha(value)
    recipe_hash = digest(checked(record['recipe'], read))
    need(source_map.get(record['recipe_key']) == recipe_hash, 'recipe missing/different in source map')
    if provenance is not None:
        need(type(provenance) is dict and provenance.get('recipe_sha256') == recipe_hash, 'source/provenance recipe mismatch')
    # The existing reviewer artifact is opaque data. Neither its label nor its
    # contents grant permission, legal clearance or source-completeness approval.
    for row in rows:
        checked(row, read, MAX_JSON if row is record['source_map'] else MAX_FILE)


def associations(index, index_row, packages, selected, synthetic, read, read_provenance):
    fields(index, ('schema_version', 'purpose', 'synthetic', 'packages'))
    need(type(index['schema_version']) is int and index['schema_version'] == 1 and index['purpose'] == 'release-source-delivery'
         and type(synthetic) is bool and index['synthetic'] is synthetic, 'source index version/synthetic mismatch')
    need(type(packages) is list and 0 < len(packages) <= 256, 'bounded release packages required')
    available = {}
    for p in packages:
        value = identity({k: p.get(k) for k in ('name', 'version', 'arch', 'sha256')})
        need(value['name'] not in available, 'duplicate release package')
        available[value['name']] = p
    need(type(selected) is list and all(type(v) is str for v in selected) and
         len(set(selected)) == len(selected) and set(selected) == set(available),
         'selected release package set differs')
    records = index['packages']
    need(type(records) is list and len(records) == len(selected), 'source package coverage differs')
    rows = [index_row]; covered = set()
    for record in records:
        current = materials(record); value = record['package']; package_name = value['name']
        need(package_name in available and package_name not in covered and
             value == {k: available[package_name][k] for k in value}, 'source package identity mismatch')
        covered.add(package_name); rows.extend(current)
        need(len(rows) <= MAX_FILES and len({r['id'] for r in rows}) == len(rows), 'duplicate/too many source IDs')
    need(covered == set(selected) and sum(r.get('bytes', 0) for r in rows) <= MAX_TOTAL, 'source coverage/total bound')
    for record in records:
        provenance = read_provenance(available[record['package']['name']])
        need(type(provenance) is dict, 'source provenance record required')
        record_check(record, read, provenance)
    return rows


def _close(fd):
    primary = sys.exception()
    try:
        os.close(fd)
    except BaseException as error:
        if primary is None:
            raise
        primary.add_note('source-delivery close uncertainty: ' + type(error).__name__)


def directory(path):
    path = Path(path)
    need(path.is_absolute() and str(path) == str(path.absolute()) and '..' not in path.parts, 'absolute source directory required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            previous, fd = fd, child
            _close(previous)
        return fd
    except BaseException:
        _close(fd)
        raise


def local_read(base, rel, limit):
    parts = relative(rel); parent = directory(Path(base).absolute()); fd = None
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            previous, parent = parent, child
            _close(previous)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit, 'unsafe/oversized source input')
        blocks = []; count = 0
        while True:
            block = os.read(fd, min(65536, limit - count + 1))
            if not block:
                break
            count += len(block); need(count <= limit, 'source input bound'); blocks.append(block)
        after = os.fstat(fd)
        need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) ==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns), 'source input changed')
        return b''.join(blocks)
    finally:
        try:
            if fd is not None:
                _close(fd)
        finally:
            if parent is not None:
                _close(parent)


def assemble(base_dir, index_descriptor, packages, selected, synthetic, read_provenance):
    descriptor(index_descriptor)
    raw = local_read(base_dir, index_descriptor['path'], MAX_JSON)
    need(digest(raw) == index_descriptor['sha256'], 'source index checksum mismatch')
    index = decode(raw)
    rows_by_id = {index_descriptor['id']: index_descriptor}
    # Close the complete finite index before any callback reads a material.
    for record in index.get('packages', []):
        for row in materials(record):
            need(row['id'] not in rows_by_id and len(rows_by_id) < MAX_FILES, 'duplicate/too many source IDs')
            rows_by_id[row['id']] = row
    def read(eid, limit):
        return local_read(base_dir, rows_by_id[eid]['path'], limit)
    rows = associations(index, dict(index_descriptor, bytes=len(raw)), packages, selected, synthetic, read, read_provenance)
    need(sum(r['bytes'] for r in rows) <= MAX_TOTAL, 'source total bound including index')
    return [{k: row[k] for k in ('id', 'path', 'sha256')} for row in rows]


def read_file(path, limit=MAX_FILE):
    path = Path(path).absolute()
    need(type(limit) is int and 0 <= limit <= MAX_FILE, 'source read limit')
    return local_read(path.parent, path.name, limit)


def verify_associations(spec, packages, read_evidence, read_provenance):
    if 'source_delivery' not in spec:
        return None
    opt = spec['source_delivery']; fields(opt, ('schema_version', 'index'))
    need(type(opt['schema_version']) is int and opt['schema_version'] == 1, 'source delivery opt-in version')
    descriptor(opt['index'])
    evidence = spec.get('evidence')
    need(type(evidence) is list and len(evidence) <= MAX_FILES, 'bounded spec evidence required')
    registered = {}
    for row in evidence:
        descriptor(row); need(row['id'] not in registered, 'duplicate spec evidence ID'); registered[row['id']] = row
    row = opt['index']
    need(registered.get(row['id']) == row, 'source index missing/different in spec evidence')
    raw = checked(row, read_evidence, MAX_JSON); index = decode(raw)
    # Require every association descriptor before reading its bytes.
    for record in index.get('packages', []):
        for material in materials(record):
            need(registered.get(material['id']) == {k:material[k] for k in ('id','path','sha256')},
                 'source material missing/different in spec evidence')
    rows = associations(index, dict(row, bytes=len(raw)), packages, spec['policy']['selected_packages'],
                        spec.get('synthetic', False), read_evidence, read_provenance)
    for material in rows:
        need(registered.get(material['id']) == {k: material[k] for k in ('id', 'path', 'sha256')},
             'source material missing/different in spec evidence')
    return index


def export_package(record, read_evidence, output, release_sha256):
    sha(release_sha256); rows = materials(record)
    record_check(record, read_evidence)
    output = Path(output); target = output.name
    need(target not in ('', '.', '..') and str(output.absolute()) == str(output) and '\x00' not in target,
         'absolute fresh export directory required')
    parent = directory(output.parent); parent_info = os.fstat(parent)
    fd = None; created = False; files = []; info = None
    try:
        os.mkdir(target, 0o700, dir_fd=parent); created = True
        info = os.stat(target, dir_fd=parent, follow_symlinks=False)
        need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'private export directory required')
        def owned():
            current = os.stat(target, dir_fd=parent, follow_symlinks=False)
            need(stat.S_ISDIR(current.st_mode) and (current.st_dev,current.st_ino) ==
                 (info.st_dev,info.st_ino), 'export directory replaced')
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        need((os.fstat(fd).st_dev,os.fstat(fd).st_ino) == (info.st_dev,info.st_ino), 'export directory open changed')
        receipt = dict(schema_version=1,purpose='release-source-delivery-export',release_sha256=release_sha256,
                       package=record['package'],review_status=record['review_status'],
                       source_completeness_accepted=False,legal_acceptance=False,
                       files=[{k:r[k] for k in ('id','sha256','bytes')} for r in rows])
        def write(eid, raw):
            owned()
            leaf = os.open(eid, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            files.append(eid)
            try:
                position = 0
                while position < len(raw):
                    count = os.write(leaf, raw[position:]); need(count > 0, 'source export short write'); position += count
                need(stat.S_IMODE(os.fstat(leaf).st_mode) == 0o600 and os.fstat(leaf).st_nlink == 1, 'private export file required')
            finally:
                _close(leaf)
        for material in rows:
            write(material['id'], checked(material, read_evidence))
        write(RECEIPT, (json.dumps(receipt, sort_keys=True, indent=2) + '\n').encode())
        owned()
        _close(fd); fd = None
        _close(parent); parent = None
        return receipt
    except BaseException as error:
        # Never interpret a missing dir_fd as CWD. Reopen only the exact owned
        # parent/directory identities; uncertainty retains output rather than
        # deleting through a guessed path or a stale descriptor.
        cleanup_parent = cleanup_fd = None
        if created:
            try:
                need(info is not None, 'export directory ownership unavailable')
                cleanup_parent = directory(output.parent)
                current = os.fstat(cleanup_parent)
                need((current.st_dev,current.st_ino) == (parent_info.st_dev,parent_info.st_ino),
                     'export parent replaced during cleanup')
                cleanup_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=cleanup_parent)
                current = os.fstat(cleanup_fd)
                need((current.st_dev,current.st_ino) == (info.st_dev,info.st_ino), 'export directory replaced during cleanup')
                for eid in reversed(files):
                    os.unlink(eid, dir_fd=cleanup_fd)
                current = os.stat(target, dir_fd=cleanup_parent, follow_symlinks=False)
                need((current.st_dev,current.st_ino) == (info.st_dev,info.st_ino), 'export cleanup path changed')
                os.rmdir(target, dir_fd=cleanup_parent)
            except BaseException as failure:
                error.add_note('source export retained; cleanup uncertainty: ' + type(failure).__name__)
            finally:
                for held in (cleanup_fd, cleanup_parent):
                    if held is not None:
                        try:
                            os.close(held)
                        except BaseException as failure:
                            error.add_note('source export cleanup close uncertainty: ' + type(failure).__name__)
        raise
    finally:
        try:
            if fd is not None:
                _close(fd)
        finally:
            if parent is not None:
                _close(parent)
