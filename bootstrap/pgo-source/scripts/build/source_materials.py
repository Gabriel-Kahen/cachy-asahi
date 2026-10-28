#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind reviewed HTTPS archives to a recipe and stage private offline SRCDEST."""
import hashlib
import os
from pathlib import Path
import stat
import sys
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'maintenance'))
import source_cache as cache

sd = cache.sd
need = sd.need


def prepare(report, plan_path, plan_sha256, catalog_path, cache_path):
    """Read/verify only. No download, Docker, extraction or source execution."""
    sd.sha(plan_sha256)
    raw = sd.read_file(plan_path, sd.MAX_JSON)
    need(sd.digest(raw) == plan_sha256, 'source plan checksum mismatch')
    plan = sd.decode(raw)
    sd.fields(plan, ('schema_version', 'purpose', 'recipe_inputs', 'catalog_sha256', 'sources'))
    need(type(plan['schema_version']) is int and plan['schema_version'] == 1 and
         plan['purpose'] == 'offline-build-sources', 'source plan version/purpose')
    need(not report['errors'] and plan['recipe_inputs'] == report['input_sha256'],
         'source plan recipe inputs mismatch')
    bindings = plan['sources']
    need(type(bindings) is list and 0 < len(bindings) <= 128, 'bounded source bindings required')
    for row in bindings:
        sd.fields(row, ('source', 'id', 'revision'))
        sd.name(row['id']); cache.text(row['revision'])
        need(type(row['source']) is str, 'recipe source string required')
    ids = [row['id'] for row in bindings]
    rows = cache.inputs(catalog_path, plan['catalog_sha256'], ids, sd.MAX_TOTAL)
    data = report['metadata']
    sources = data.get('source', []) + data.get('source_aarch64', [])
    sums = data.get('sha256sums', []) + data.get('sha256sums_aarch64', [])
    need(len(sources) == len(sums), 'recipe source/checksum count mismatch')
    selected = []; names = set(); remote = []; local_names = set()
    for source, checksum in zip(sources, sums):
        url = source.split('::', 1)[-1]
        if '://' not in url:
            local_names.add(source.split('::', 1)[0] if '::' in source else url.rsplit('/', 1)[-1])
            continue
        cache.https(url)  # VCS sources require a separate design; never treated as archives.
        remote.append((source, checksum))
    need([source for source, _ in remote] == [row['source'] for row in bindings],
         'source plan must cover every remote source in recipe order')
    for (source, checksum), binding, row in zip(remote, bindings, rows):
        url = source.split('::', 1)[-1]
        filename = source.split('::', 1)[0] if '::' in source else urllib.parse.urlsplit(url).path.rsplit('/', 1)[-1]
        sd.name(filename)
        need(filename not in names and filename not in local_names and filename not in report['input_sha256'],
             'source filename collision with source/recipe input')
        names.add(filename)
        need(url == row['url'] and binding['revision'] == row['revision'] and
             checksum == row['material']['sha256'], 'recipe/catalog URL, revision or checksum mismatch')
        selected.append(dict(filename=filename, source=source, record=row))
    cache.run(cache_path, catalog_path, plan['catalog_sha256'], ids, offline=True)
    catalog = sd.read_file(catalog_path, sd.MAX_JSON)
    need(sd.digest(catalog) == plan['catalog_sha256'], 'catalog changed during verification')
    notices = {}
    for row in rows:
        for notice in row['license_evidence']:
            content = sd.local_read(Path(catalog_path).absolute().parent, notice['path'], sd.MAX_JSON)
            need((len(content), sd.digest(content)) == (notice['bytes'], notice['sha256']),
                 'license evidence changed during verification')
            notices[notice['sha256']] = content
    return dict(plan=plan, plan_raw=raw, catalog_raw=catalog, cache_path=Path(cache_path),
                selected=selected, notices=notices)


def copy_object(parent, material, destination):
    """Stream from a held, private cache directory; rehash the actual staged bytes."""
    fd = os.open(material['sha256'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        before = cache.private(fd)
        need(before.st_size == material['bytes'], 'cached source size changed before staging')
        count = 0; hashed = hashlib.sha256()
        with destination.open('xb') as output:
            os.chmod(destination, 0o600)
            while True:
                block = os.read(fd, min(cache.CHUNK, material['bytes'] - count + 1))
                if not block:
                    break
                count += len(block)
                need(count <= material['bytes'], 'cached source grew during staging')
                hashed.update(block); output.write(block)
        after = os.fstat(fd)
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
             'cached source changed during staging')
        need((count, hashed.hexdigest()) == (material['bytes'], material['sha256']),
             'staged source byte pin mismatch')
        os.chmod(destination, 0o400)
    finally:
        os.close(fd)


def stage(prepared, destination):
    """Create a fresh owned tree; only srcdest/ is mounted into the container."""
    destination = Path(destination)
    parent = sd.directory(destination.parent)
    try:
        info = os.fstat(parent)
        need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
             'private owned staging parent required')
        os.mkdir(destination.name, 0o700, dir_fd=parent)
    finally:
        os.close(parent)
    srcdest = destination / 'srcdest'
    srcdest.mkdir(mode=0o700)
    receipts = destination / 'receipts'; receipts.mkdir(mode=0o700)
    notices = destination / 'notices'; notices.mkdir(mode=0o700)
    held = []
    try:
        root = sd.directory(prepared['cache_path']); held.append(root); cache.private(root, True)
        objects = cache.open_dir('objects', root); held.append(objects)
        original_receipts = cache.open_dir('receipts', root); held.append(original_receipts)
        for item in prepared['selected']:
            row = item['record']; material = row['material']
            receipt = cache.encoded(dict(schema_version=1, purpose='source-cache-receipt',
                inputs_sha256=prepared['plan']['catalog_sha256'], source=row,
                object_path='objects/' + material['sha256'], legal_acceptance=False,
                source_completeness_accepted=False))
            key = prepared['plan']['catalog_sha256'] + '-' + material['id'] + '.json'
            need(cache.read_entry(original_receipts, key, sd.MAX_JSON) == (len(receipt), sd.digest(receipt)),
                 'cache receipt changed before staging')
            copy_object(objects, material, srcdest / item['filename'])
            (receipts / (material['id'] + '.json')).write_bytes(receipt)
        (destination / 'source-plan.json').write_bytes(prepared['plan_raw'])
        (destination / 'source-catalog.json').write_bytes(prepared['catalog_raw'])
        for checksum, content in prepared['notices'].items():
            (notices / checksum).write_bytes(content)
        result = dict(schema_version=1, purpose='offline-build-sources',
            plan_sha256=sd.digest(prepared['plan_raw']), catalog_sha256=prepared['plan']['catalog_sha256'],
            recipe_inputs=prepared['plan']['recipe_inputs'], sources=prepared['selected'],
            legal_acceptance=False, source_completeness_accepted=False)
        (destination / 'selection.json').write_bytes(cache.encoded(result))
        for path in destination.rglob('*'):
            if path.is_file():
                path.chmod(0o400)
        return result
    finally:
        for fd in reversed(held):
            os.close(fd)
