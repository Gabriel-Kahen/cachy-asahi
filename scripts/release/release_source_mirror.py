#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Export exact retained release sources; verify portable mirrors without imports.

Export imports only the installed project helpers. Verify uses the standard
library and treats every retained file, including Python and PKGBUILD, as data.
Caller-authenticated SHA-256 pins are required at both boundaries.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile

sys.dont_write_bytecode = True
MAX_JSON = 4 * 1024**2
MAX_OBJECT = 64 * 1024**2
MAX_TOTAL = 512 * 1024**2
MAX_MIRROR = MAX_TOTAL + 32 * 1024**2
MAX_FILES = 16384
HERE = Path(__file__).absolute().parent


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def sha(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'SHA-256 required')
    return value


def relative(value):
    need(type(value) is str and value and '\\' not in value and '\x00' not in value, 'unsafe relative path')
    path = PurePosixPath(value)
    need(not path.is_absolute() and path.as_posix() == value and
         all(part not in ('.', '..') for part in path.parts), 'noncanonical relative path')
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def decode(raw):
    need(len(raw) <= MAX_JSON, 'JSON byte bound')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('float/nonfinite JSON refused')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    need(type(value) is dict, 'JSON object required')
    return value


def read_file(path, limit=MAX_MIRROR):
    """No symlink ancestors, hardlinks, special files or changing snapshots."""
    need(not str(path).startswith('//'), 'path alias refused')
    path = Path(path).absolute()
    need('..' not in path.parts, 'parent path refused')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    fd = None
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent); parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit,
             'unsafe/oversized mirror input')
        chunks = []; size = 0
        while block := os.read(fd, min(65536, limit - size + 1)):
            size += len(block); need(size <= limit, 'input byte bound'); chunks.append(block)
        after = os.fstat(fd)
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'input changed')
        return b''.join(chunks)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def dependencies(directory=HERE):
    sbom = module('mirror_sbom', Path(directory) / 'release_sbom.py')
    return sbom, sbom.dependencies(directory)


def tar_bytes(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for key, raw in sorted(files.items()):
            node = tarfile.TarInfo(relative(key))
            node.size, node.mode, node.mtime, node.uid, node.gid = len(raw), 0o644, 0, 0, 0
            archive.addfile(node, io.BytesIO(raw))
    return output.getvalue()


def source_bodies(raw, sbom, s, stream):
    # The shared reader bounds decoded bytes/physical headers first. Sources
    # must be regular files; neither source links nor retained code is followed.
    compressed = raw.startswith((b'\x1f\x8b', b'\xfd7zXZ\x00', b'\x28\xb5\x2f\xfd'))
    nodes = sbom.tar_entries(raw, s, stream, compressed)
    need(all(row['type'] in ('file', 'directory') for row in nodes.values()), 'source links refused')
    # Shared reviewed recipe bundles are USTAR; remote-input bundles use USTAR
    # too, avoiding another decompressor/extractor in this exporter.
    need(not compressed, 'source bundle must be retained uncompressed USTAR')
    result = source_tar(raw)
    need(all(digest(body) == nodes[key]['sha256'] for key, body in result.items()), 'source snapshot mismatch')
    return result


def source_tar(raw):
    """Bounded USTAR data reader shared with the standalone verifier."""
    need(0 < len(raw) <= MAX_OBJECT and len(raw) % 512 == 0, 'source USTAR byte bound/alignment')
    files = {}; seen = set(); offset = 0
    while offset + 512 <= len(raw) and any(raw[offset:offset + 512]):
        node = tarfile.TarInfo.frombuf(raw[offset:offset + 512], 'utf-8', 'strict')
        key = node.name.removeprefix('./').rstrip('/')
        if key not in ('', '.'):
            relative(key)
        need(node.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE) and
             key not in seen and len(seen) < MAX_FILES and 0 <= node.size <= MAX_OBJECT,
             'unsafe/duplicate source USTAR member')
        seen.add(key)
        start = offset + 512; end = start + node.size
        need(end <= len(raw) and (node.isfile() or node.size == 0), 'truncated/nonregular source member')
        if node.isfile():
            relative(key); files[key] = raw[start:end]
        offset = start + ((node.size + 511) // 512) * 512
    need(offset + 1024 <= len(raw) and not any(raw[offset:]), 'source USTAR end/trailing bytes')
    return files


def supplement(path, checksum, root, s):
    if path is None:
        need(checksum is None and root is None, 'retained input options must be supplied together')
        return None, {}
    need(checksum is not None and root is not None, 'retained input options must be supplied together')
    need(Path(root).absolute().anchor == '/' and '..' not in Path(root).parts, 'retained root path alias refused')
    raw = read_file(path, MAX_JSON)
    need(digest(raw) == sha(checksum), 'retained inputs checksum mismatch')
    data = decode(raw)
    s.fields(data, ('schema_version', 'purpose', 'packages'))
    need(type(data['schema_version']) is int and data['schema_version'] == 1 and
         data['purpose'] == 'release-source-mirror-inputs', 'retained input schema')
    need(type(data['packages']) is list and len(data['packages']) <= 256, 'retained package bound')
    packages = {}
    for row in data['packages']:
        s.fields(row, ('package', 'plan', 'catalog', 'cache'))
        s.identity(row['package']); relative(row['cache'])
        for key in ('plan', 'catalog'):
            s.descriptor(row[key], True)
        name = row['package']['name']
        need(name not in packages, 'duplicate retained package')
        packages[name] = row
    return raw, packages


def remote_sources(row, root, bodies, package, provenance, recipe, directory):
    """Reuse source_materials.prepare, with a report built only from held bytes."""
    need(row['package'] == package, 'retained package identity mismatch')
    sm = module('mirror_source_materials', Path(directory).parent / 'build/source_materials.py')
    s = sm.sd
    paths = {}
    for key in ('plan', 'catalog'):
        desc = row[key]
        raw = s.local_read(Path(root).absolute(), desc['path'], MAX_JSON)
        need((len(raw), digest(raw)) == (desc['bytes'], desc['sha256']), 'retained ' + key + ' mismatch')
        paths[key] = Path(root).absolute() / desc['path']
    info = recipe.metadata(bodies['.SRCINFO'])
    version = info.get('pkgver', []) + info.get('pkgrel', [])
    need(len(info.get('pkgver', [])) == len(info.get('pkgrel', [])) == 1 and
         info.get('pkgbase', [package['name']]) == [package['name']] and
         not info.get('epoch') and info.get('pkgname') == [package['name']] and
         '-'.join(version) == package['version'] and info.get('arch') == [package['arch']], 'SRCINFO package identity mismatch')
    need(info.get('license') == provenance.get('licenses') and info.get('license'), 'SRCINFO license mismatch')
    sources = info.get('source', []) + info.get('source_aarch64', [])
    sums = info.get('sha256sums', []) + info.get('sha256sums_aarch64', [])
    need(all(len(info.get('source' + suffix, [])) == len(info.get('sha256sums' + suffix, []))
             for suffix in ('', '_aarch64')), 'SRCINFO source/checksum group mismatch')
    need(0 < len(sources) == len(sums) <= 128 and len(set(sources)) == len(sources), 'SRCINFO source count/duplicates')
    for source, checksum in zip(sources, sums):
        sha(checksum)
        url = source.split('::', 1)[-1]
        if '://' not in url:
            relative(url)
            need('::' not in source and url in bodies and digest(bodies[url]) == checksum, 'local recipe source missing/mismatch')
    for hook in info.get('install', []):
        relative(hook); need(hook in bodies, 'retained install hook missing')
    report = dict(errors=[], metadata=info, input_sha256={key: digest(raw) for key, raw in bodies.items()})
    prepared = sm.prepare(report, paths['plan'], row['plan']['sha256'], paths['catalog'],
                          Path(root).absolute() / row['cache'])
    need(prepared['catalog_raw'] == read_file(paths['catalog'], MAX_JSON) and
         digest(prepared['catalog_raw']) == row['catalog']['sha256'], 'retained catalog pin mismatch')
    results = []
    for item in prepared['selected']:
        record = item['record']; material = record['material']
        raw = s.local_read(prepared['cache_path'], 'objects/' + material['sha256'], MAX_OBJECT)
        need((len(raw), digest(raw)) == (material['bytes'], material['sha256']), 'cached source changed')
        receipt_key = prepared['plan']['catalog_sha256'] + '-' + material['id'] + '.json'
        receipt = s.local_read(prepared['cache_path'], 'receipts/' + receipt_key, MAX_JSON)
        expected = sm.cache.encoded(dict(schema_version=1, purpose='source-cache-receipt',
            inputs_sha256=prepared['plan']['catalog_sha256'], source=record,
            object_path='objects/' + material['sha256'], legal_acceptance=False, source_completeness_accepted=False))
        need(receipt == expected, 'cache receipt changed')
        matches = [p for p in provenance['sources'] if p.get('url') == record['url'] and
                   p.get('sha256') == material['sha256'] and p.get('commit') is None]
        need(len(matches) == 1, 'remote source/provenance mismatch')
        results.append((item, raw, receipt))
    need(results, 'HTTPS retained inputs must contain remote sources')
    return prepared, results


def build(root, release_sha256, deps, inputs=None, inputs_sha256=None, retained_root=None, directory=HERE):
    sbom, shared = deps
    s, recipe, stream = shared
    root = Path(root).absolute()
    need(root.anchor == '/', 'release path alias refused')
    document, coverage = sbom.export(root, release_sha256, shared)
    release = sbom.Release(root, release_sha256, s)
    manifest_raw = s.local_read(root, 'release.json', MAX_JSON)
    need(digest(manifest_raw) == release_sha256, 'release changed')
    index = s.verify_associations(release.spec, release.manifest['packages'], release.evidence_read,
                                  lambda p: s.decode(release.read(p['provenance'], MAX_JSON)))
    need(index is not None, 'complete source delivery index required')
    extra_raw, extras = supplement(inputs, inputs_sha256, retained_root, s)
    need(set(extras) <= {p['name'] for p in release.manifest['packages']}, 'foreign retained package')
    objects, files, packages = {}, {}, []
    total = 0
    def add(raw):
        nonlocal total
        need(type(raw) is bytes and len(raw) <= MAX_OBJECT, 'object byte bound')
        checksum = digest(raw)
        if checksum not in objects:
            total += len(raw)
            need(total <= MAX_TOTAL and len(objects) < MAX_FILES, 'mirror aggregate bound')
            objects[checksum] = raw
        return dict(sha256=checksum, bytes=len(raw))
    files['release.json'] = add(manifest_raw)
    # Re-read the SBOM's complete read set and compare its exact byte snapshots.
    for ref in coverage['input_files']:
        raw = release.read(ref['path'])
        need((len(raw), digest(raw)) == (ref['bytes'], ref['sha256']), 'release changed after SBOM')
        files[ref['path']] = add(raw)
    records = {record['package']['name']: record for record in index['packages']}
    rows = {row['package']['name']: row for row in coverage['packages']}
    for package in sorted(release.manifest['packages'], key=lambda p: p['name']):
        name = package['name']; record = records[name]; row = rows[name]
        retained = row['retained_source']
        need(retained is not None and row['buildinfo'] is not None and row['buildinfo']['installed'], 'source/BUILDINFO required')
        archive = sbom.tar_entries(release.read('repo/' + package['filename']), s, stream)
        need(sbom.metadata(archive['.BUILDINFO']['raw'], s).get('format') == ['2'], 'BUILDINFO format 2 required')
        need(row['bundled_license_evidence'] and retained['matched_license_sha256'], 'matching source/package license text required')
        allowed = {'MISSING_OR_UNSUPPORTED_OR_AMBIGUOUS_LICENSE_DECLARATION'}
        if name in extras:
            allowed.add('UNRESOLVED_UNRECOGNIZED_BUNDLE_PROFILE')
        need(set(row['unresolved']) <= allowed, 'required source evidence unresolved: ' + name + ': ' + ','.join(row['unresolved']))
        raw = release.evidence_read(record['bundle']['id'], MAX_OBJECT)
        bodies = source_bodies(raw, sbom, s, stream)
        source_map = s.decode(release.evidence_read(record['source_map']['id'], MAX_JSON))
        need(set(bodies) == set(source_map) | ({'bundle.json'} if 'bundle.json' in bodies else set()),
             'source map must cover every retained source file')
        need(all(digest(bodies[key]) == checksum for key, checksum in source_map.items()), 'source map bytes differ')
        need(record['recipe_key'] == 'PKGBUILD' and 'PKGBUILD' in bodies and
             bodies['PKGBUILD'] == release.evidence_read(record['recipe']['id'], MAX_OBJECT), 'retained PKGBUILD bytes differ')
        remote = []; plan = catalog = None; notices = {}
        if name in extras:
            need(retained['profile'] == 'UNRESOLVED_UNRECOGNIZED_BUNDLE_PROFILE' and '.SRCINFO' in bodies,
                 'supplement requires literal SRCINFO source profile')
            prov = s.decode(release.read(package['provenance'], MAX_JSON))
            prepared, selected = remote_sources(extras[name], retained_root, bodies, record['package'], prov, recipe, directory)
            plan, catalog = add(prepared['plan_raw']), add(prepared['catalog_raw'])
            for item, content, receipt in selected:
                remote.append(dict(filename=item['filename'], source=item['source'], record=item['record'],
                                   object=add(content), receipt=add(receipt)))
            notices = {checksum: add(content) for checksum, content in sorted(prepared['notices'].items())}
            expected_urls = {item['record']['url'] for item, _, _ in selected}
            need({p['url'] for p in prov['sources']} == expected_urls, 'provenance sources must match retained HTTPS set')
        else:
            need(retained['profile'] == 'REVIEWED_ORIGINAL_RECIPE_PROFILE', 'reviewed original source profile required')
            saved, exact = recipe.unpacked(raw, digest(raw))
            need(all(p['status'] == 'RESOLVED_TO_RETAINED_RECIPE_PROFILE' for p in row['pinned_source_references']),
                 'additional remote source has no retained input')
            need(saved['package'] == {key: package[key] for key in ('name', 'version', 'arch')}, 'reviewed source identity mismatch')
        packages.append(dict(package=record['package'], profile=retained['profile'],
            source_files={key: add(content) for key, content in sorted(bodies.items())},
            remote_sources=remote, plan=plan, catalog=catalog, remote_notices=notices,
            recipe_sha256=row['recipe_sha256'], archive=row['archive'], provenance=row['provenance'],
            license_texts=row['bundled_license_evidence'], declared_license=row['declared_license'],
            buildinfo=row['buildinfo'], source_delivery=record))
    verifier = read_file(Path(__file__).absolute(), MAX_JSON)
    result = dict(schema_version=1, purpose='release-source-mirror', release_sha256=release_sha256,
        release_id=release.manifest['release_id'], synthetic=release.spec.get('synthetic', False),
        files=files, packages=packages, objects={key: len(raw) for key, raw in sorted(objects.items())},
        sbom=add(encoded(document)), coverage=add(encoded(coverage)),
        retained_inputs=add(extra_raw) if extra_raw is not None else None,
        verifier_sha256=digest(verifier), legal_acceptance=False, corresponding_source_completeness='NOT_ASSERTED',
        native_build_validation='NOT_PERFORMED', hardware_validation='NOT_RUN', release_acceptance='NOT_ADMITTED')
    # add() above also retains reports and caller-pinned supplemental descriptors.
    result['objects'] = {key: len(raw) for key, raw in sorted(objects.items())}
    bundle = tar_bytes({'mirror.json': encoded(result), 'verify.py': verifier,
                        **{'objects/' + key: raw for key, raw in objects.items()}})
    need(len(bundle) <= MAX_MIRROR, 'mirror tar byte bound')
    verify(bundle, digest(bundle), release_sha256)
    return bundle, result, verifier


def canonical_files(raw, checksum):
    """Authenticate canonical portable TAR bytes without executing its files."""
    need(0 < len(raw) <= MAX_MIRROR and digest(raw) == sha(checksum), 'mirror checksum/bound mismatch')
    need(len(raw) % 512 == 0, 'mirror tar alignment')
    files = {}; offset = 0
    while offset + 512 <= len(raw) and any(raw[offset:offset + 512]):
        node = tarfile.TarInfo.frombuf(raw[offset:offset + 512], 'utf-8', 'strict')
        relative(node.name)
        need(node.isfile() and node.type == tarfile.REGTYPE and not node.pax_headers and
             node.name not in files and len(files) < MAX_FILES + 2 and
             0 <= node.size <= MAX_OBJECT and node.mode == 0o644 and node.uid == node.gid == node.mtime == 0 and
             not node.linkname and not node.uname and not node.gname, 'noncanonical/unsafe mirror member')
        start = offset + 512; end = start + node.size
        need(end <= len(raw), 'truncated mirror member')
        files[node.name] = raw[start:end]
        offset = start + ((node.size + 511) // 512) * 512
        need(not any(raw[end:offset]), 'nonzero tar padding')
    need(offset + 1024 <= len(raw) and not any(raw[offset:]), 'mirror tar end/trailing bytes')
    need(tar_bytes(files) == raw, 'noncanonical mirror tar')
    return files


def verify(raw, checksum, release_sha256):
    """Authenticate the entire tar before reading its inert object graph."""
    mirror_checksum = checksum
    sha(release_sha256)
    files = canonical_files(raw, checksum)
    need('mirror.json' in files and 'verify.py' in files, 'mirror metadata/verifier missing')
    mirror = decode(files['mirror.json'])
    need(mirror.get('schema_version') == 1 and type(mirror['schema_version']) is int and
         mirror.get('purpose') == 'release-source-mirror' and mirror.get('release_sha256') == release_sha256,
         'mirror/release identity mismatch')
    need(mirror.get('legal_acceptance') is False and mirror.get('corresponding_source_completeness') == 'NOT_ASSERTED' and
         mirror.get('native_build_validation') == 'NOT_PERFORMED' and mirror.get('hardware_validation') == 'NOT_RUN' and
         mirror.get('release_acceptance') == 'NOT_ADMITTED', 'mirror evidence boundary changed')
    need(digest(files['verify.py']) == mirror['verifier_sha256'], 'verifier checksum mismatch')
    objects = mirror['objects']; used = set()
    need(type(objects) is dict and 0 < len(objects) <= MAX_FILES and
         set(files) == {'mirror.json', 'verify.py'} | {'objects/' + sha(key) for key in objects}, 'object set mismatch')
    need(all(type(size) is int and 0 <= size <= MAX_OBJECT and len(files['objects/' + key]) == size and
             digest(files['objects/' + key]) == key for key, size in objects.items()) and
         sum(objects.values()) <= MAX_TOTAL, 'object size/checksum/total mismatch')
    def get(ref):
        need(type(ref) is dict and set(ref) == {'sha256', 'bytes'}, 'object descriptor fields')
        key = sha(ref['sha256']); need(key in objects and type(ref['bytes']) is int and objects[key] == ref['bytes'], 'object descriptor mismatch')
        used.add(key)
        return files['objects/' + key]
    logical = mirror['files']
    need(type(logical) is dict and 0 < len(logical) <= MAX_FILES, 'release file bound')
    for path, ref in logical.items():
        relative(path); get(ref)
    release_raw = get(logical['release.json'])
    need(digest(release_raw) == release_sha256, 'retained release checksum mismatch')
    release = decode(release_raw); spec = decode(get(logical['spec.json']))
    need(release['release_id'] == spec['release_id'] == mirror['release_id'] and
         mirror['synthetic'] is spec.get('synthetic', False), 'release/spec identity mismatch')
    need(all(path == 'release.json' or release['files'].get(path) == ref['sha256'] for path, ref in logical.items()),
         'release file binding mismatch')
    report = decode(get(mirror['coverage'])); document = decode(get(mirror['sbom']))
    need(report['release_sha256'] == release_sha256 and report['spdx_sha256'] == digest(encoded(document)), 'report binding mismatch')
    need(set(logical) == {'release.json'} | {ref['path'] for ref in report['input_files']} and
         all(logical[ref['path']] == {key: ref[key] for key in ('sha256', 'bytes')} for ref in report['input_files']),
         'coverage input set mismatch')
    def evidence(ref):
        relative(ref['id']); relative(ref['path'])
        registered = [row for row in spec['evidence'] if row['id'] == ref['id']]
        need(registered == [{key: ref[key] for key in ('id', 'path', 'sha256')}], 'source evidence registration mismatch')
        raw = get(logical['evidence/' + ref['id']])
        need(digest(raw) == ref['sha256'] and ('bytes' not in ref or len(raw) == ref['bytes']), 'source evidence binding mismatch')
        return raw
    index = decode(evidence(spec['source_delivery']['index']))
    need(index.get('schema_version') == 1 and index.get('purpose') == 'release-source-delivery' and
         index.get('synthetic') is mirror['synthetic'], 'source index schema mismatch')
    records = index['packages']
    expected = [{key: row[key] for key in ('name', 'version', 'arch', 'sha256')}
                for row in sorted(release['packages'], key=lambda p: p['name'])]
    need(type(mirror['packages']) is list and [row['package'] for row in mirror['packages']] == expected and
         len(expected) == len({p['name'] for p in expected}) == report['package_count'] and
         len(spec['policy']['selected_packages']) == len(expected) and
         set(spec['policy']['selected_packages']) == {p['name'] for p in expected} and
         len(records) == len(expected) == len(spec['packages']) == len(report['packages']), 'exact package set mismatch')
    extras = decode(get(mirror['retained_inputs']))['packages'] if mirror['retained_inputs'] is not None else []
    need(len(extras) == len({row['package']['name'] for row in extras}) and
         {row['package']['name'] for row in extras} <= {row['name'] for row in expected}, 'retained package set mismatch')
    for row, package in zip(mirror['packages'], sorted(release['packages'], key=lambda p: p['name'])):
        bodies = {relative(path): get(ref) for path, ref in row['source_files'].items()}
        record = row['source_delivery']; key = record['recipe_key']
        need([r for r in records if r['package']['name'] == package['name']] == [record] and
             record['package'] == row['package'] and key == 'PKGBUILD', 'source association identity mismatch')
        source_map = decode(evidence(record['source_map']))
        retained_bodies = source_tar(evidence(record['bundle']))
        need(bodies == retained_bodies and set(bodies) == set(source_map) | ({'bundle.json'} if 'bundle.json' in bodies else set()) and
             all(digest(bodies[path]) == sha(checksum) for path, checksum in source_map.items()), 'source map/bundle/file mismatch')
        need(bodies[key] == evidence(record['recipe']) and
             digest(bodies[key]) == row['recipe_sha256'] == record['recipe']['sha256'], 'recipe identity mismatch')
        notices = [evidence(ref) for ref in record['notices']]
        evidence(record['authorization'])
        need(notices and all(raw in bodies.values() for raw in notices) and row['license_texts'] and
             any(ref['sha256'] in {digest(raw) for raw in notices} for ref in row['license_texts']), 'source/license text mismatch')
        for role in ('archive', 'provenance'):
            ref = row[role]
            path = 'repo/' + package['filename'] if role == 'archive' else package['provenance']
            need(ref['path'] == path and logical[path] == {key: ref[key] for key in ('sha256', 'bytes')}, 'package input binding mismatch')
        provenance = decode(get(logical[package['provenance']]))
        need(provenance['package'] == {key: package[key] for key in ('name', 'version', 'arch')} and
             provenance['artifact_sha256'] == package['sha256'] == row['archive']['sha256'] and
             provenance['recipe_sha256'] == row['recipe_sha256'] and provenance['source_commit'] == spec['source_commit'],
             'package provenance mismatch')
        spec_rows = [p for p in spec['packages'] if Path(p['artifact']['path']).name == package['filename']]
        need(len(spec_rows) == 1 and spec_rows[0]['artifact']['sha256'] == package['sha256'] and
             spec_rows[0]['provenance']['sha256'] == row['provenance']['sha256'], 'spec package binding mismatch')
        report_rows = [p for p in report['packages'] if p['package'] == row['package']]
        need(len(report_rows) == 1 and all(row[key] == report_rows[0][key] for key in
             ('archive', 'provenance', 'recipe_sha256', 'buildinfo', 'declared_license')) and
             row['license_texts'] == report_rows[0]['bundled_license_evidence'], 'package coverage mismatch')
        if row['remote_sources']:
            need(row['profile'] == 'UNRESOLVED_UNRECOGNIZED_BUNDLE_PROFILE', 'remote source profile mismatch')
            extra = [r for r in extras if r['package'] == row['package']]
            need(len(extra) == 1, 'remote supplemental binding missing')
            plan_raw, catalog_raw = get(row['plan']), get(row['catalog'])
            need(all((len(raw), digest(raw)) == (extra[0][key]['bytes'], extra[0][key]['sha256'])
                     for key, raw in (('plan', plan_raw), ('catalog', catalog_raw))), 'remote plan/catalog pin mismatch')
            plan, catalog = decode(plan_raw), decode(catalog_raw)
            need(plan['recipe_inputs'] == {path: digest(raw) for path, raw in bodies.items()} and
                 plan['catalog_sha256'] == digest(catalog_raw), 'remote recipe plan mismatch')
            need(len(row['remote_sources']) == len(plan['sources']) and
                 [r['source'] for r in row['remote_sources']] == [r['source'] for r in plan['sources']], 'remote source coverage mismatch')
        else:
            need(row['profile'] == 'REVIEWED_ORIGINAL_RECIPE_PROFILE' and row['plan'] is row['catalog'] is None and
                 not row['remote_notices'] and not any(r['package'] == row['package'] for r in extras), 'original source profile mismatch')
        for remote in row['remote_sources']:
            content = get(remote['object']); receipt = decode(get(remote['receipt'])); source = remote['record']
            need(remote['object'] == {key: source['material'][key] for key in ('sha256', 'bytes')} and
                 source in catalog['sources'] and
                 [p for p in plan['sources'] if p['source'] == remote['source']] == [dict(
                     source=remote['source'], id=source['material']['id'], revision=source['revision'])], 'remote material binding mismatch')
            need(receipt == dict(schema_version=1, purpose='source-cache-receipt', inputs_sha256=digest(catalog_raw),
                 source=source, object_path='objects/' + source['material']['sha256'], legal_acceptance=False,
                 source_completeness_accepted=False), 'remote receipt binding mismatch')
            need(len([p for p in provenance['sources'] if p.get('url') == source['url'] and
                      p.get('sha256') == digest(content) and p.get('commit') is None]) == 1, 'remote provenance binding mismatch')
            for notice in source['license_evidence']:
                raw = get(row['remote_notices'][notice['sha256']])
                need(len(raw) == notice['bytes'] and digest(raw) == notice['sha256'], 'remote notice binding mismatch')
        for checksum, ref in row['remote_notices'].items():
            need(digest(get(ref)) == checksum, 'remote notice checksum mismatch')
    need(used == set(objects), 'unreferenced mirror objects')
    return dict(status='VERIFIED_OFFLINE_SOURCE_MIRROR', release_sha256=release_sha256,
        mirror_sha256=mirror_checksum, packages=len(expected), unique_objects=len(objects),
        legal_acceptance=False, native_build_validation='NOT_PERFORMED', hardware_validation='NOT_RUN', release_acceptance='NOT_ADMITTED')


def history_stats(manifests):
    prior = set().union(*(set(row['objects']) for row in manifests[:-1]))
    old_head, head = set(manifests[-2]['objects']), set(manifests[-1]['objects'])
    return dict(new_objects=len(head - prior), reused_objects=len(head & prior),
        retired_objects=len(old_head - head), retained_recovery_objects=len(prior - head), pruned_objects=0)


def history_parts(files, history):
    """Validate the union and reconstruct bounded, complete per-release mirrors."""
    need(set(history) == {'schema_version', 'purpose', 'head_release_sha256', 'previous_mirror_sha256',
         'releases', 'objects', 'stats', 'verifier_sha256', 'legal_acceptance',
         'corresponding_source_completeness', 'native_build_validation', 'hardware_validation', 'release_acceptance'},
         'history fields mismatch')
    need(type(history['schema_version']) is int and history['schema_version'] == 1 and
         history['purpose'] == 'release-source-mirror-history', 'history schema mismatch')
    need(history['legal_acceptance'] is False and history['corresponding_source_completeness'] == 'NOT_ASSERTED' and
         history['native_build_validation'] == 'NOT_PERFORMED' and history['hardware_validation'] == 'NOT_RUN' and
         history['release_acceptance'] == 'NOT_ADMITTED', 'history evidence boundary changed')
    sha(history['previous_mirror_sha256']); sha(history['head_release_sha256'])
    need(digest(files['verify.py']) == history['verifier_sha256'], 'history verifier checksum mismatch')
    objects = history['objects']
    need(type(objects) is dict and 0 < len(objects) <= MAX_FILES and
         set(files) == {'history.json', 'verify.py'} | {'objects/' + sha(key) for key in objects}, 'history object set mismatch')
    need(all(type(size) is int and 0 <= size <= MAX_OBJECT and len(files['objects/' + key]) == size and
         digest(files['objects/' + key]) == key for key, size in objects.items()) and
         sum(objects.values()) <= MAX_TOTAL, 'history object size/checksum/total mismatch')
    used = set()
    def get(ref):
        need(type(ref) is dict and set(ref) == {'sha256', 'bytes'}, 'history descriptor fields')
        key = sha(ref['sha256'])
        need(type(ref['bytes']) is int and objects.get(key) == ref['bytes'], 'history descriptor mismatch')
        used.add(key)
        return files['objects/' + key]
    rows = history['releases']
    need(type(rows) is list and 2 <= len(rows) <= 256 and all(type(row) is dict for row in rows) and
         len({row['release_sha256'] for row in rows}) == len(rows) == len({row['release_id'] for row in rows}) and
         history['head_release_sha256'] == rows[-1]['release_sha256'], 'retained release set mismatch')
    manifests, bundles = [], []
    references = expanded = 0
    for row in rows:
        need(type(row) is dict and set(row) == {'release_sha256', 'release_id', 'mirror_sha256', 'manifest', 'verifier'},
             'retained release fields mismatch')
        sha(row['release_sha256']); sha(row['mirror_sha256'])
        manifest_raw, verifier = get(row['manifest']), get(row['verifier'])
        manifest = decode(manifest_raw)
        need(type(manifest.get('objects')) is dict, 'retained release objects required')
        need(manifest['release_sha256'] == row['release_sha256'] and manifest['release_id'] == row['release_id'] and
             manifest['verifier_sha256'] == digest(verifier), 'retained release descriptor mismatch')
        references += len(manifest['objects']); expanded += sum(manifest['objects'].values())
        need(references <= MAX_FILES and expanded <= MAX_TOTAL, 'retained release aggregate reference/byte bound')
        payload = {'mirror.json': manifest_raw, 'verify.py': verifier}
        for key, size in manifest['objects'].items():
            payload['objects/' + sha(key)] = get(dict(sha256=key, bytes=size))
        bundle = tar_bytes(payload)
        need(len(bundle) <= MAX_MIRROR, 'retained mirror tar byte bound')
        bundles.append(bundle); manifests.append(manifest)
    need(used == set(objects), 'unreferenced history objects')
    need(type(history['stats']) is dict and all(type(value) is int for value in history['stats'].values()) and
         history['stats'] == history_stats(manifests), 'history object counts mismatch')
    return manifests, bundles


def verify_any(raw, checksum, release_sha256):
    """Verify every recovery release; the requested pin must be retained."""
    files = canonical_files(raw, checksum)
    if 'mirror.json' in files:
        return verify(raw, checksum, release_sha256)
    need('history.json' in files and 'verify.py' in files, 'history metadata/verifier missing')
    history = decode(files['history.json'])
    manifests, bundles = history_parts(files, history)
    for row, bundle in zip(history['releases'], bundles):
        verify(bundle, row['mirror_sha256'], row['release_sha256'])
    releases = [row['release_sha256'] for row in history['releases']]
    need(sha(release_sha256) in releases, 'requested release is not retained')
    return dict(status='VERIFIED_OFFLINE_SOURCE_MIRROR_HISTORY', mirror_sha256=checksum,
        release_sha256=release_sha256, head_release_sha256=history['head_release_sha256'],
        retained_releases=releases, unique_objects=len(history['objects']), stats=history['stats'],
        legal_acceptance=False, native_build_validation='NOT_PERFORMED', hardware_validation='NOT_RUN', release_acceptance='NOT_ADMITTED')


def update(previous_raw, previous_sha256, previous_head_release_sha256, root, release_sha256, deps,
           inputs=None, inputs_sha256=None, retained_root=None, directory=HERE):
    """Reuse only verified predecessor objects; append without pruning recovery."""
    proof = verify_any(previous_raw, previous_sha256, previous_head_release_sha256)
    files = canonical_files(previous_raw, previous_sha256)
    if 'mirror.json' in files:
        previous = decode(files['mirror.json'])
        rows = [dict(release_sha256=previous['release_sha256'], release_id=previous['release_id'],
            mirror_sha256=previous_sha256, manifest=None, verifier=None)]
        retained = [(files['mirror.json'], files['verify.py'])]
        manifests = [previous]
    else:
        need(proof['head_release_sha256'] == previous_head_release_sha256, 'previous head release pin mismatch')
        previous = decode(files['history.json']); rows = list(previous['releases'])
        manifests, _ = history_parts(files, previous)
        retained = [(files['objects/' + row['manifest']['sha256']], files['objects/' + row['verifier']['sha256']]) for row in rows]
    need(release_sha256 not in {row['release_sha256'] for row in rows}, 'next release is already retained')
    # Validate complete pinned next inputs independently; predecessor data is
    # reused for portable object storage, never to excuse a missing next input.
    next_raw, next_manifest, verifier = build(root, release_sha256, deps, inputs, inputs_sha256, retained_root, directory)
    need(next_manifest['release_id'] not in {row['release_id'] for row in rows}, 'conflicting retained release ID')
    need(len(rows) < 256, 'retained release count bound')
    next_files = canonical_files(next_raw, digest(next_raw))
    objects = {key[8:]: value for key, value in files.items() if key.startswith('objects/')}
    def add(raw):
        key = digest(raw)
        need(len(raw) <= MAX_OBJECT, 'history object byte bound')
        if key in objects:
            need(objects[key] == raw, 'reused object bytes differ')
        else:
            objects[key] = raw
        need(len(objects) <= MAX_FILES and sum(map(len, objects.values())) <= MAX_TOTAL, 'history aggregate object bound')
        return dict(sha256=key, bytes=len(raw))
    # Old rows are rebuilt from their verified raw metadata. Their original
    # individual mirror digests remain replayable without executing verifiers.
    rows = [dict(row, manifest=add(manifest), verifier=add(tool))
            for row, (manifest, tool) in zip(rows, retained)]
    for key, body in next_files.items():
        if key.startswith('objects/'):
            add(body)
    rows.append(dict(release_sha256=release_sha256, release_id=next_manifest['release_id'],
        mirror_sha256=digest(next_raw), manifest=add(next_files['mirror.json']), verifier=add(verifier)))
    manifests.append(next_manifest)
    history = dict(schema_version=1, purpose='release-source-mirror-history',
        head_release_sha256=release_sha256, previous_mirror_sha256=previous_sha256,
        releases=rows, objects={key: len(body) for key, body in sorted(objects.items())},
        stats=history_stats(manifests), verifier_sha256=digest(verifier), legal_acceptance=False,
        corresponding_source_completeness='NOT_ASSERTED', native_build_validation='NOT_PERFORMED',
        hardware_validation='NOT_RUN', release_acceptance='NOT_ADMITTED')
    raw = tar_bytes({'history.json': encoded(history), 'verify.py': verifier,
                     **{'objects/' + key: body for key, body in objects.items()}})
    verify_any(raw, digest(raw), release_sha256)
    return raw, history, verifier


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    export = commands.add_parser('export')
    export.add_argument('--release-dir', type=Path, required=True)
    export.add_argument('--release-sha256', required=True)
    export.add_argument('--output', type=Path, required=True, help='Fresh directory')
    export.add_argument('--retained-inputs', type=Path)
    export.add_argument('--inputs-sha256')
    export.add_argument('--retained-root', type=Path)
    successor = commands.add_parser('update')
    successor.add_argument('--previous-bundle', type=Path, required=True)
    successor.add_argument('--previous-sha256', required=True)
    successor.add_argument('--previous-release-sha256', required=True, help='Authenticated previous head release digest')
    successor.add_argument('--release-dir', type=Path, required=True)
    successor.add_argument('--release-sha256', required=True)
    successor.add_argument('--output', type=Path, required=True, help='Fresh directory')
    successor.add_argument('--retained-inputs', type=Path)
    successor.add_argument('--inputs-sha256')
    successor.add_argument('--retained-root', type=Path)
    check = commands.add_parser('verify')
    check.add_argument('--bundle', type=Path, required=True)
    check.add_argument('--sha256', required=True)
    check.add_argument('--release-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'verify':
            result = verify_any(read_file(args.bundle), args.sha256, args.release_sha256)
        else:
            deps = dependencies()
            need(args.output.absolute().anchor == '/' and '..' not in args.output.parts, 'output path alias refused')
            if args.command == 'update':
                bundle, manifest, verifier = update(read_file(args.previous_bundle), args.previous_sha256,
                    args.previous_release_sha256, args.release_dir, args.release_sha256, deps,
                    args.retained_inputs, args.inputs_sha256, args.retained_root)
            else:
                bundle, manifest, verifier = build(args.release_dir, args.release_sha256, deps,
                    args.retained_inputs, args.inputs_sha256, args.retained_root)
            head = manifest if args.command == 'export' else decode(canonical_files(bundle, digest(bundle))[
                'objects/' + manifest['releases'][-1]['manifest']['sha256']])
            result = dict(status='UPDATED_SOURCE_MIRROR' if args.command == 'update' else 'EXPORTED_SOURCE_MIRROR', release_sha256=args.release_sha256,
                mirror_sha256=digest(bundle), packages=len(head['packages']), unique_objects=len(manifest['objects']),
                verifier_sha256=digest(verifier),
                bytes=len(bundle), legal_acceptance=False, hardware_validation='NOT_RUN', release_acceptance='NOT_ADMITTED')
            if args.command == 'update':
                result.update(retained_releases=[row['release_sha256'] for row in manifest['releases']], stats=manifest['stats'])
            deps[1][1].write_fresh(args.output, {'mirror.tar': bundle, 'verify.py': verifier,
                                               'mirror-receipt.json': encoded(result)})
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, tarfile.TarError, EOFError, RecursionError) as error:
        print(json.dumps(dict(status='REFUSED', reason=str(error)), sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
