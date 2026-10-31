#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Offline SPDX 2.3 inventory of an existing release.json exact package set.

No extraction, network, subprocess, signing, package selection or legal decision.
Integrity/identity errors refuse export; absent evidence remains unresolved.
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import tarfile
import time
from urllib.parse import urlsplit

HERE = Path(__file__).absolute().parent
MAX_ARCHIVE = 64 * 1024**2
MAX_TAR = 128 * 1024**2
MAX_TOTAL = 512 * 1024**2
MAX_MEMBER = 32 * 1024**2
MAX_MEMBERS = 32768
# Conservative supported SPDX identifiers. Unknown/legacy/free-text declarations
# are preserved verbatim in coverage, never converted to a legal conclusion.
LICENSE_IDS = frozenset(('MIT Apache-2.0 BSD-2-Clause BSD-3-Clause ISC Zlib 0BSD '
    'CC0-1.0 GPL-2.0-only GPL-2.0-or-later GPL-3.0-only GPL-3.0-or-later '
    'LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0-only LGPL-3.0-or-later '
    'MPL-2.0 BSL-1.0 Unlicense').split())


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


def dependencies(directory=HERE):
    """Canonical layout; packet tests pass the unchanged checkout directory."""
    directory = Path(directory)
    return (module('sbom_source_delivery', directory / 'source_delivery.py'),
            module('sbom_recipe_source_delivery', directory / 'recipe_source_delivery.py'),
            module('sbom_archive_stream', directory.parent / 'update/archive_stream.py'))


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + '\n').encode()


def text(value, reason):
    if not (type(value) is str and 0 < len(value) <= 4096 and
            all(ord(c) >= 32 and ord(c) != 127 for c in value)):
        raise ValueError(reason)
    return value


def metadata(raw, s):
    result = {}
    for line in raw.decode('utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        s.need(' = ' in line, 'malformed package metadata')
        key, value = line.split(' = ', 1)
        s.need(re.fullmatch('[a-zA-Z0-9_]+', key), 'metadata key')
        text(value, 'metadata value'); result.setdefault(key, []).append(value)
    return result


def tar_entries(raw, s, stream, compressed=True):
    """Bound expansion and physical headers before tarfile parses extensions.

    Retain only metadata/license bytes; hash other regular members. Links remain
    opaque and are never followed. No member is written to the filesystem.
    """
    s.need(0 < len(raw) <= MAX_ARCHIVE, 'archive compressed size bound')
    if compressed:
        limits = stream.Limits(MAX_ARCHIVE, MAX_ARCHIVE, MAX_TAR, MAX_MEMBERS,
                               MAX_MEMBER, 64 * 1024**2, time.monotonic() + 30)
        decoder = stream.Decoded(io.BytesIO(raw), limits, 0)
        chunks = []
        try:
            while block := decoder.read(65536):
                chunks.append(block)
        except stream.DECODER_ERRORS as error:
            raise ValueError('invalid compressed archive: ' + type(error).__name__) from error
        s.need(decoder.done, 'incomplete compressed archive')
        raw = b''.join(chunks)
    s.need(len(raw) <= MAX_TAR and len(raw) % 512 == 0, 'tar byte bound/alignment')
    offset, count = 0, 0
    while offset + 512 <= len(raw) and any(raw[offset:offset + 512]):
        header = tarfile.TarInfo.frombuf(raw[offset:offset + 512], 'utf-8', 'strict')
        count += 1
        s.need(count <= MAX_MEMBERS and 0 <= header.size <= MAX_MEMBER, 'tar header/member bound')
        if header.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
            s.need(header.size <= 65536, 'tar extended header bound')
        s.need(header.type != tarfile.GNUTYPE_SPARSE, 'sparse tar refused')
        offset += 512 + ((header.size + 511) // 512) * 512
    s.need(offset + 1024 <= len(raw) and not any(raw[offset:]), 'tar end/trailing data')
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            key = member.name.removeprefix('./').rstrip('/')
            # bsdtar may include a root directory entry.
            if key in ('', '.') and member.isdir():
                continue
            s.relative(key)
            s.need(key not in result and len(result) < MAX_MEMBERS, 'duplicate/too many archive paths')
            s.need(not member.sparse and not any(k.startswith('GNU.sparse') for k in member.pax_headers),
                   'sparse tar refused')
            s.need(0 <= member.size <= MAX_MEMBER, 'effective member byte bound')
            row = dict(type='other', bytes=member.size, mode=member.mode & 0o7777)
            if member.isfile():
                with archive.extractfile(member) as source:
                    body = source.read(MAX_MEMBER + 1)
                s.need(len(body) == member.size, 'truncated archive member')
                row.update(type='file', sha256=s.digest(body))
                if key in ('.PKGINFO', '.BUILDINFO', 'bundle.json') or key.startswith('usr/share/licenses/'):
                    s.need(len(body) <= s.MAX_JSON, 'metadata/license byte bound')
                    row['raw'] = body
            elif member.isdir():
                row['type'] = 'directory'
            elif member.issym() or member.islnk():
                text(member.linkname, 'archive link target')
                row.update(type='link', target=member.linkname)
            else:
                raise ValueError('archive special member refused')
            result[key] = row
    return result


class Release:
    def __init__(self, root, release_sha256, s):
        self.root, self.s, self.reads, self.total = Path(root).absolute(), s, {}, 0
        raw = s.local_read(self.root, 'release.json', s.MAX_JSON)
        s.sha(release_sha256); s.need(s.digest(raw) == release_sha256, 'release manifest checksum mismatch')
        self.release_hash = release_sha256
        self.manifest = s.decode(raw)
        s.need(type(self.manifest.get('schema_version')) is int and self.manifest['schema_version'] == 1, 'release schema')
        self.files = self.manifest.get('files')
        s.need(type(self.files) is dict and 0 < len(self.files) <= s.MAX_FILES, 'release file map bound')
        for path, checksum in self.files.items():
            s.relative(path); s.sha(checksum)
        self.spec = s.decode(self.read('spec.json', s.MAX_JSON))
        s.need(type(self.spec.get('schema_version')) is int and self.spec['schema_version'] == 1 and
               self.spec.get('release_id') == self.manifest.get('release_id'),
               'release/spec identity mismatch')
        revision = self.spec.get('source_commit')
        s.need(type(revision) is str and re.fullmatch('[0-9a-f]{40}', revision), 'full release source commit required')
        s.need(type(self.spec.get('synthetic', False)) is bool, 'release synthetic flag must be boolean')
        s.name(self.manifest['release_id'])
        self.evidence = {}
        rows = self.spec.get('evidence', [])
        s.need(type(rows) is list and len(rows) <= s.MAX_FILES, 'evidence list bound')
        for row in rows:
            s.descriptor(row); eid = row['id']
            s.need(eid not in self.evidence, 'duplicate evidence ID')
            s.need(self.files.get('evidence/' + eid) == row['sha256'], 'evidence manifest binding mismatch')
            self.evidence[eid] = row

    def read(self, path, limit=MAX_ARCHIVE):
        self.s.relative(path)
        self.s.need(path in self.files, 'unregistered release input: ' + path)
        if path in self.reads:
            raw = self.reads[path]
            self.s.need(len(raw) <= limit, 'cached input byte bound')
            return raw
        raw = self.s.local_read(self.root, path, limit)
        self.s.need(self.s.digest(raw) == self.files[path], 'release input checksum mismatch: ' + path)
        self.total += len(raw)
        self.s.need(self.total <= MAX_TOTAL, 'aggregate release input byte bound')
        self.reads[path] = raw
        return raw

    def evidence_read(self, eid, limit):
        self.s.need(eid in self.evidence, 'unregistered evidence ID')
        return self.read('evidence/' + eid, min(limit, MAX_ARCHIVE))

    def ref(self, path):
        return dict(path=path, sha256=self.files[path], bytes=len(self.reads[path]))


def source_urls(provenance, s):
    rows = provenance.get('sources', [])
    s.need(type(rows) is list and len(rows) <= 4096, 'provenance sources bound')
    result, seen = [], set()
    for row in rows:
        s.need(type(row) is dict, 'source record object required')
        uri = text(row.get('url'), 'source URL required')
        s.need(uri not in seen, 'duplicate/conflicting source URL'); seen.add(uri)
        checksum, revision = row.get('sha256'), row.get('commit')
        if checksum is not None:
            s.sha(checksum)
        if revision is not None:
            s.need(type(revision) is str and re.fullmatch('[0-9a-f]{40}', revision), 'source commit must be full Git SHA-1')
        parsed = urlsplit(uri)
        s.need(not parsed.username and not parsed.password, 'credential-bearing source URL refused')
        retrievable = (parsed.scheme in ('https', 'git+https') and bool(parsed.hostname) and
                       not parsed.username and not parsed.password and not parsed.query and
                       (not parsed.fragment or parsed.fragment == 'commit=' + str(revision)))
        reason = None
        if not (checksum or revision):
            reason = 'NO_CONTENT_HASH_OR_FULL_COMMIT'
        elif parsed.scheme not in ('https', 'git+https'):
            reason = 'RETRIEVAL_SCHEME_NOT_SUPPORTED_OR_INTERNAL_CONTEXT_NOT_BOUND'
        elif not parsed.hostname:
            reason = 'SOURCE_HOST_MISSING'
        elif not retrievable:
            reason = 'SOURCE_URL_QUERY_OR_UNBOUND_FRAGMENT'
        result.append(dict(url=uri, sha256=checksum, commit=revision,
                           status='PINNED_REMOTE_REFERENCE_NOT_FETCHED' if retrievable and (checksum or revision)
                                  else 'UNRESOLVED_SOURCE_REFERENCE',
                           unresolved_reason=reason,
                           remote_retrievability='NOT_CHECKED_OFFLINE'))
    return sorted(result, key=lambda row: row['url'])


def source_record(release, record, package, provenance, archive, s, recipe, stream):
    """Validate the existing association plus bundle/map/archive correspondence."""
    s.record_check(record, release.evidence_read, provenance)
    source_map = s.decode(release.evidence_read(record['source_map']['id'], s.MAX_JSON))
    bundle = release.evidence_read(record['bundle']['id'], MAX_ARCHIVE)
    # Existing delivery permits opaque formats. Unknown formats stay unresolved;
    # no filename/URL is promoted to complete corresponding-source delivery.
    if not bundle.startswith((b'\x1f\x8b', b'\xfd7zXZ\x00', b'\x28\xb5\x2f\xfd')):
        compressed = False
    else:
        compressed = True
    opaque = False
    if not compressed:
        try:
            tarfile.TarInfo.frombuf(bundle[:512], 'utf-8', 'strict')
        except (tarfile.TarError, ValueError):
            opaque = True
    if opaque:
        return dict(bundle=release.ref('evidence/' + record['bundle']['id']),
                    recipe=release.ref('evidence/' + record['recipe']['id']),
                    source_map=release.ref('evidence/' + record['source_map']['id']),
                    notices=[release.ref('evidence/' + row['id']) for row in record['notices']],
                    review_status=record['review_status'], profile='UNRESOLVED_OPAQUE_BUNDLE_FORMAT',
                    matched_license_sha256=[], source_file_count=len(source_map),
                    corresponding_source_completeness='NOT_ASSERTED', issues=['UNRESOLVED_OPAQUE_BUNDLE_FORMAT'])
    nodes = tar_entries(bundle, s, stream, compressed)
    s.need(all(nodes.get(key, {}).get('sha256') == checksum for key, checksum in source_map.items()),
           'source bundle/map mismatch')
    notices = []
    for row in record['notices']:
        raw = release.evidence_read(row['id'], s.MAX_JSON)
        matches = sorted(key for key, node in nodes.items() if node.get('sha256') == s.digest(raw))
        s.need(matches, 'notice absent from source bundle')
        notices.append(dict(release.ref('evidence/' + row['id']), bundle_members=matches))
    issues = []
    saved = s.decode(nodes['bundle.json']['raw']) if 'bundle.json' in nodes else None
    profile = 'UNRESOLVED_UNRECOGNIZED_BUNDLE_PROFILE'
    if saved is not None:
        if 'package' in saved:
            s.need(saved['package'] == {k: package[k] for k in ('name', 'version', 'arch')}, 'source bundle package identity mismatch')
        if 'recipe_sha256' in saved:
            s.need(saved['recipe_sha256'] == provenance['recipe_sha256'], 'bundle/provenance recipe mismatch')
        binding = saved.get('archive_binding')
        if binding:
            s.need(binding.get('archive_sha256') == package['sha256'] and
                   binding.get('archive_bytes') == package['archive_bytes'] and
                   binding.get('pkgbuild_sha256') == provenance['recipe_sha256'], 'source bundle/archive binding mismatch')
        if saved.get('purpose') == 'reviewed-original-recipe-source' and (package['name'] in recipe.PROFILES and
                (package['version'] == recipe.PROFILES[package['name']]['version'] or
                 (package['name'], package['version']) in recipe.LEGACY_PROFILES)):
            # Profiles are existing authority, including legacy recipe versions.
            verified, _ = recipe.unpacked(bundle, s.digest(bundle))
            s.need(verified == saved, 'reviewed bundle manifest mismatch')
            profile = 'REVIEWED_ORIGINAL_RECIPE_PROFILE'
            wanted = recipe.payload(package['name'], package['version'])
            s.need({key for key, node in archive.items() if node['type'] != 'directory'} ==
                   set(wanted) | {'.PKGINFO', '.BUILDINFO', '.MTREE'}, 'archive/source payload set mismatch')
            if binding:
                actual_metadata = {key: metadata(archive[key]['raw'], s) for key in ('.PKGINFO', '.BUILDINFO')}
                s.need(binding.get('metadata_sha256') == s.digest(recipe.encoded(actual_metadata)),
                       'source bundle/archive metadata mismatch')
            for path, (source, mode) in wanted.items():
                s.need(archive.get(path, {}).get('sha256') == nodes[source]['sha256'] and
                       archive[path]['mode'] == mode, 'archive/source payload mismatch: ' + path)
    if profile.startswith('UNRESOLVED'):
        issues.append(profile)
    archive_licenses = {key: node['sha256'] for key, node in archive.items()
                        if key.startswith('usr/share/licenses/') and node['type'] == 'file'}
    matched = sorted(set(archive_licenses.values()) & {row['sha256'] for row in notices})
    if not matched:
        issues.append('SOURCE_NOTICES_NOT_MATCHED_TO_BUNDLED_PACKAGE_LICENSE_FILES')
    return dict(bundle=release.ref('evidence/' + record['bundle']['id']),
                recipe=release.ref('evidence/' + record['recipe']['id']),
                source_map=release.ref('evidence/' + record['source_map']['id']),
                notices=notices, review_status=record['review_status'], profile=profile,
                declared_license=saved.get('license') if saved else None,
                matched_license_sha256=matched, source_file_count=len(source_map),
                corresponding_source_completeness='NOT_ASSERTED', issues=issues)


def export(root, release_sha256, deps):
    s, recipe, stream = deps
    release = Release(root, release_sha256, s)
    manifest, spec = release.manifest, release.spec
    packages = manifest.get('packages')
    s.need(type(packages) is list and 0 < len(packages) <= 256, 'exact nonempty release package set required')
    by_name, filenames, checksums = {}, set(), set()
    for package in packages:
        s.need(type(package) is dict, 'package object required')
        s.identity({k: package.get(k) for k in ('name', 'version', 'arch', 'sha256')})
        s.need(package['name'] not in by_name, 'duplicate/conflicting package identity')
        filename = text(package.get('filename'), 'package filename required')
        s.need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+:-]*\.pkg\.tar\.(gz|xz|zst)', filename), 'unsafe package filename')
        s.relative(package.get('provenance'))
        s.need(package['filename'] not in filenames and package['sha256'] not in checksums, 'duplicate package archive')
        filenames.add(package['filename']); checksums.add(package['sha256']); by_name[package['name']] = package
        s.need(release.files.get('repo/' + package['filename']) == package['sha256'], 'package/file-map checksum mismatch')
    selected = spec.get('policy', {}).get('selected_packages')
    s.need(type(selected) is list and len(selected) == len(by_name) and set(selected) == set(by_name), 'selected package set mismatch')
    spec_packages = spec.get('packages')
    s.need(type(spec_packages) is list and len(spec_packages) == len(packages), 'spec package set mismatch')
    provenance_by_name = {}
    for package in packages:
        raw = release.read(package['provenance'], s.MAX_JSON)
        provenance = s.decode(raw)
        s.need(provenance.get('schema_version') == 1 and provenance.get('artifact_sha256') == package['sha256'] and
               provenance.get('package') == {k: package[k] for k in ('name', 'version', 'arch')}, 'provenance/archive identity mismatch')
        s.sha(provenance.get('recipe_sha256'))
        s.need(provenance.get('source_commit') == spec.get('source_commit'), 'provenance source commit mismatch')
        inputs = [p for p in spec_packages if type(p) is dict and type(p.get('artifact')) is dict and
                  Path(p['artifact'].get('path', '')).name == package['filename']]
        s.need(len(inputs) == 1 and inputs[0]['artifact'].get('sha256') == package['sha256'] and
               inputs[0].get('provenance', {}).get('sha256') == s.digest(raw), 'spec/archive/provenance mismatch')
        provenance_by_name[package['name']] = provenance
    # Preserve partial source indexes for the report; use the canonical full
    # association validator on the present subset, refusing foreign identities.
    records = {}
    if 'source_delivery' in spec:
        option = spec['source_delivery']; s.fields(option, ('schema_version', 'index'))
        s.need(type(option['schema_version']) is int and option['schema_version'] == 1, 'source option schema')
        s.descriptor(option['index']); index_ref = option['index']
        s.need(release.evidence.get(index_ref['id']) == index_ref, 'source index registration mismatch')
        raw = release.evidence_read(index_ref['id'], s.MAX_JSON); index = s.decode(raw)
        s.fields(index, ('schema_version', 'purpose', 'synthetic', 'packages'))
        s.need(type(index['packages']) is list and len(index['packages']) <= len(packages), 'source index package bound')
        ids = {index_ref['id']}
        for record in index['packages']:
            rows = s.materials(record); identity = record['package']; name = identity['name']
            s.need(name in by_name and name not in records and identity == {k: by_name[name][k] for k in identity},
                   'source package identity mismatch')
            for row in rows:
                s.need(row['id'] not in ids and release.evidence.get(row['id']) ==
                       {k: row[k] for k in ('id', 'path', 'sha256')}, 'duplicate/unregistered source material')
                ids.add(row['id'])
            records[name] = record
        if records:
            subset = [by_name[name] for name in sorted(records)]
            s.associations(index, dict(index_ref, bytes=len(raw)), subset, sorted(records), spec.get('synthetic', False),
                           release.evidence_read, lambda p: provenance_by_name[p['name']])
        else:
            s.need(index['schema_version'] == 1 and index['purpose'] == 'release-source-delivery' and
                   type(index['synthetic']) is bool and index['synthetic'] is spec.get('synthetic', False), 'empty source index schema')
    spdx_packages, coverage = [], []
    for name in sorted(by_name):
        package, provenance = dict(by_name[name]), provenance_by_name[name]
        issues = []
        raw = release.read('repo/' + package['filename'])
        package['archive_bytes'] = len(raw)
        archive = tar_entries(raw, s, stream)
        s.need(archive.get('.PKGINFO', {}).get('type') == 'file', 'missing/nonregular .PKGINFO')
        info = metadata(archive['.PKGINFO']['raw'], s)
        s.need(all(info.get(k) == [package[v]] for k, v in (('pkgname', 'name'), ('pkgver', 'version'), ('arch', 'arch'))),
               'archive .PKGINFO identity mismatch')
        licenses = info.get('license', [])
        declared = licenses[0] if len(licenses) == 1 and licenses[0] in LICENSE_IDS else 'NOASSERTION'
        if declared == 'NOASSERTION':
            issues.append('MISSING_OR_UNSUPPORTED_OR_AMBIGUOUS_LICENSE_DECLARATION')
        if package.get('license', []) != licenses or provenance.get('licenses', []) != licenses:
            declared = 'NOASSERTION'; issues.append('LICENSE_DECLARATIONS_DIFFER')
        buildinfo, installed = None, []
        if archive.get('.BUILDINFO', {}).get('type') == 'file':
            buildinfo = metadata(archive['.BUILDINFO']['raw'], s)
            s.need(buildinfo.get('pkgbuild_sha256sum') == [provenance['recipe_sha256']], 'BUILDINFO/provenance recipe mismatch')
            for key, expected in (('pkgname', name), ('pkgver', package['version']), ('pkgarch', package['arch'])):
                s.need(buildinfo.get(key) == [expected], 'BUILDINFO package identity mismatch')
            installed = buildinfo.get('installed', [])
            s.need(len(installed) == len(set(installed)), 'duplicate BUILDINFO installed lock entry')
            installed_names = set()
            for entry in installed:
                parts = entry.rsplit('-', 3)
                s.need(len(parts) == 4 and all(parts), 'malformed BUILDINFO installed lock entry')
                s.name(parts[0])
                s.need(parts[0] not in installed_names, 'conflicting BUILDINFO installed package versions')
                installed_names.add(parts[0])
            if not installed:
                issues.append('BUILDINFO_INSTALLED_LOCK_MISSING')
        else:
            issues.append('BUILDINFO_MISSING')
        urls = source_urls(provenance, s)
        if not urls:
            issues.append('PROVENANCE_SOURCES_MISSING')
        if any(row['status'].startswith('UNRESOLVED') for row in urls):
            issues.append('PROVENANCE_SOURCE_REFERENCE_UNRESOLVED')
        license_files = [dict(path=key, sha256=node['sha256'], bytes=node['bytes']) for key, node in sorted(archive.items())
                         if key.startswith('usr/share/licenses/') and node['type'] == 'file']
        if not license_files:
            issues.append('BUNDLED_LICENSE_TEXT_MISSING')
        source = None
        if name in records:
            source = source_record(release, records[name], package, provenance, archive, s, recipe, stream)
            issues.extend(source['issues'])
            if source.get('declared_license') is not None and source['declared_license'] != declared:
                declared = 'NOASSERTION'; issues.append('SOURCE_LICENSE_DECLARATION_DIFFERS')
        else:
            issues.append('RETAINED_SOURCE_ASSOCIATION_MISSING')
        # Only the exact retained recipe can resolve its internal context URL.
        # A matching profile says nothing about any additional source reference.
        if source and source['profile'] == 'REVIEWED_ORIGINAL_RECIPE_PROFILE':
            prefix = 'context-source:' + str(spec.get('source_commit')) + '/'
            for row in urls:
                if row['status'] == 'UNRESOLVED_SOURCE_REFERENCE' and row['url'].startswith(prefix):
                    path = row['url'][len(prefix):]
                    s.relative(path)
                    if (path.endswith('/' + name) and row['sha256'] == provenance['recipe_sha256'] and
                            row['commit'] in (None, spec.get('source_commit'))):
                        row.update(status='RESOLVED_TO_RETAINED_RECIPE_PROFILE',
                                   resolved_by_bundle_sha256=source['bundle']['sha256'], unresolved_reason=None)
            if not any(row['status'].startswith('UNRESOLVED') for row in urls):
                issues = [issue for issue in issues if issue != 'PROVENANCE_SOURCE_REFERENCE_UNRESOLVED']
        sid = 'SPDXRef-Package-' + s.digest(encoded({k: package[k] for k in ('name', 'version', 'arch', 'sha256')}))
        build_record = None
        if 'actual_native_build_record' in provenance:
            path = provenance['actual_native_build_record']
            native = s.decode(release.read(path, s.MAX_JSON))
            if 'archive_binding' in native:
                binding = native['archive_binding']
                s.need(binding.get('archive_sha256') == package['sha256'] and
                       binding.get('archive_bytes') == len(raw) and
                       binding.get('pkgbuild_sha256') == provenance['recipe_sha256'], 'native record/archive binding mismatch')
            if 'artifacts' in native:
                s.need(native['artifacts'].get(package['filename']) == package['sha256'] and
                       native.get('recipe_inputs', {}).get('PKGBUILD') == provenance['recipe_sha256'], 'raw native build/archive mismatch')
            build_record = dict(release.ref(path), reported_status=native.get('status'), execution_revalidated=False)
        coverage.append(dict(package={k: package[k] for k in ('name', 'version', 'arch', 'sha256')}, spdx_id=sid,
            archive=release.ref('repo/' + package['filename']), provenance=release.ref(package['provenance']),
            recipe_sha256=provenance['recipe_sha256'], declared_license=declared, raw_license_declarations=dict(
                pkginfo=licenses, release=package.get('license', []), provenance=provenance.get('licenses', [])),
            bundled_license_evidence=license_files, pinned_source_references=urls, retained_source=source,
            build_context=provenance.get('build'), retained_build_record=build_record,
            buildinfo=dict(sha256=archive['.BUILDINFO']['sha256'], installed=installed,
                           installed_lock_sha256=s.digest(('\n'.join(installed) + '\n').encode())) if buildinfo else None,
            status='UNRESOLVED' if issues else 'EVIDENCE_LINKED', unresolved=sorted(set(issues))))
        spdx_packages.append(dict(SPDXID=sid, name=name, versionInfo=package['version'],
            packageFileName=package['filename'], downloadLocation='NOASSERTION', filesAnalyzed=False,
            checksums=[dict(algorithm='SHA256', checksumValue=package['sha256'])],
            licenseConcluded='NOASSERTION', licenseDeclared=declared, copyrightText='NOASSERTION',
            licenseComments='Publisher declarations only; exact text hashes and unresolved evidence are in coverage.json.',
            sourceInfo=json.dumps(dict(architecture=package['arch'], provenance=package['provenance'],
                retained_source_bundle=source['bundle'] if source else None, references=urls), sort_keys=True)))
    # The namespace incorporates the entire output basis, including tool behavior
    # and coverage. Wall clock and absolute paths never enter generated documents.
    created = text(manifest.get('created_utc'), 'release creation timestamp required')
    moment = datetime.fromisoformat(created.replace('Z', '+00:00'))
    s.need(moment.tzinfo is not None, 'release timestamp timezone required')
    created = moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    report = dict(schema_version=1, purpose='release-sbom-coverage', release_id=manifest['release_id'],
        release_sha256=release_sha256, synthetic=spec.get('synthetic', False), package_count=len(coverage), packages=coverage,
        unresolved_package_count=sum(row['status'] == 'UNRESOLVED' for row in coverage),
        input_files=[release.ref(path) for path in sorted(release.reads)],
        signature_verification='NOT_PERFORMED_CALLER_MUST_AUTHENTICATE_RELEASE_DIGEST',
        corresponding_source_completeness='NOT_ASSERTED', legal_acceptance=False,
        native_build_validation='NOT_PERFORMED', hardware_validation='NOT_RUN', release_acceptance='NOT_ADMITTED')
    token = s.digest(encoded(dict(report=report, packages=spdx_packages)))
    document = dict(spdxVersion='SPDX-2.3', dataLicense='CC0-1.0', SPDXID='SPDXRef-DOCUMENT',
        name='cachy-asahi-' + manifest['release_id'],
        documentNamespace='https://spdx.org/spdxdocs/cachy-asahi-' + token,
        creationInfo=dict(created=created, creators=['Tool: cachy-asahi-release-sbom-1'],
                          comment='Creation time inherited from release.json for deterministic export.'),
        packages=spdx_packages, relationships=[dict(spdxElementId='SPDXRef-DOCUMENT',
            relationshipType='DESCRIBES', relatedSpdxElement=p['SPDXID']) for p in spdx_packages])
    report['spdx_sha256'] = s.digest(encoded(document))
    return document, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-dir', type=Path, required=True)
    parser.add_argument('--release-sha256', required=True, help='Caller-authenticated release.json SHA-256')
    parser.add_argument('--output', type=Path, required=True, help='Fresh directory; never replace an export')
    args = parser.parse_args()
    try:
        deps = dependencies()
        document, report = export(args.release_dir, args.release_sha256, deps)
        # Verify all inputs before creating the output. Exclusive mkdir/open make
        # concurrent runs refuse overwrite.
        deps[1].write_fresh(args.output, {'sbom.spdx.json': encoded(document), 'coverage.json': encoded(report)})
        print(json.dumps(dict(status='EXPORTED', packages=report['package_count'],
            unresolved_packages=report['unresolved_package_count'], spdx_sha256=report['spdx_sha256']), sort_keys=True))
        return 0
    except (ValueError, OSError, tarfile.TarError, EOFError, KeyError, TypeError, RecursionError) as error:
        print(json.dumps(dict(status='REFUSED', reason=str(error)), sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
